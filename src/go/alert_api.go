package main

import (
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "net/http"
    "path"
    "net"
    "strconv"
    "strings"
    "sync"
    "time"

    "etracee/internal/api/middleware"
    httpapi "etracee/internal/api/http"
    "etracee/internal/common/config"
    "etracee/internal/web"

    "github.com/gorilla/websocket"
)

// AlertAPI 告警API服务器
type AlertAPI struct {
	alertManager *AlertManager
	server       *http.Server
	storage      Storage
	eventContext *EventContext

	// WebSocket
	wsUpgrader  websocket.Upgrader
	wsClients   map[*WSClient]struct{}
	wsMutex     sync.Mutex
	wsQueueSize int

	// Security & CORS
	allowedOrigins map[string]struct{}
	apiToken       string
	bindAddr       string
	requireAuth    bool
}

// NewAlertAPI 创建告警API服务器
func NewAlertAPI(alertManager *AlertManager, port int, storage Storage, eventContext *EventContext) *AlertAPI {
	api := &AlertAPI{
		alertManager: alertManager,
		storage:      storage,
		eventContext: eventContext,
	}

	mux := http.NewServeMux()

    httpapi.Register(mux, api)
    mux.Handle("/", web.Handler())

    api.allowedOrigins = config.AllowedOriginsFromEnv()
    api.apiToken = config.APITokenFromEnv()
    api.requireAuth = api.apiToken != ""
    api.bindAddr = config.BindAddrFromEnv()
    if api.bindAddr == "" {
        api.bindAddr = "0.0.0.0"
        log.Printf("[*] 未设置 ETRACEE_BIND_ADDR，默认绑定到 %s", api.bindAddr)
    }

	mw := middleware.NewCORSMiddleware(api.allowedOrigins, api.apiToken)
    api.wsUpgrader = websocket.Upgrader{CheckOrigin: mw.CheckOrigin}
    if api.requireAuth {
        api.wsUpgrader.Subprotocols = []string{api.apiToken, "Bearer " + api.apiToken}
    }
	api.wsClients = make(map[*WSClient]struct{})
    // 队列大小可通过环境变量配置
    api.wsQueueSize = config.WSQueueSizeFromEnv(1024)

	addr := fmt.Sprintf(":%d", port)
	if api.bindAddr != "" {
		if strings.Contains(api.bindAddr, ":") {
			// ETRACEE_BIND_ADDR 已包含端口，则直接使用
			addr = api.bindAddr
		} else {
			addr = fmt.Sprintf("%s:%d", api.bindAddr, port)
		}
	}
    base := mw.Wrap(mux)
    normalizer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        p := r.URL.Path
        for strings.Contains(p, "//") { p = strings.ReplaceAll(p, "//", "/") }
        p = path.Clean(p)
        if p == "." { p = "/" }
        r2 := r.Clone(r.Context())
        r2.URL.Path = p
        base.ServeHTTP(w, r2)
    })
    api.server = &http.Server{Addr: addr, Handler: normalizer}

	return api
}

// WSClient 表示一个带发送队列的 WebSocket 客户端（用于反压）
type WSClient struct {
	Conn      *websocket.Conn
	Send      chan []byte
	closeOnce sync.Once
}

func (api *AlertAPI) addWSClient(conn *websocket.Conn) *WSClient {
	client := &WSClient{
		Conn: conn,
		Send: make(chan []byte, api.wsQueueSize),
	}
	api.wsMutex.Lock()
	api.wsClients[client] = struct{}{}
	api.wsMutex.Unlock()
	go api.wsWritePump(client)
	return client
}

func (api *AlertAPI) removeWSClient(client *WSClient) {
	api.wsMutex.Lock()
	delete(api.wsClients, client)
	api.wsMutex.Unlock()
	// 幂等关闭：一次性关闭发送队列与连接
	client.closeOnce.Do(func() {
		close(client.Send)
		_ = client.Conn.Close()
	})
}

func (api *AlertAPI) wsWritePump(client *WSClient) {
    pingTicker := time.NewTicker(30 * time.Second)
    defer pingTicker.Stop()
    for {
        select {
        case msg, ok := <-client.Send:
            if !ok { return }
            _ = client.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
            if err := client.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
                if !(errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(strings.ToLower(err.Error()), "broken pipe")) {
                    log.Printf("WebSocket 写入失败，移除客户端: %v", err)
                }
                api.removeWSClient(client)
                return
            }
        case <-pingTicker.C:
            _ = client.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
            if err := client.Conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
                api.removeWSClient(client)
                return
            }
        }
    }
}

func (api *AlertAPI) wsReadPump(client *WSClient) {
    _ = client.Conn.SetReadDeadline(time.Now().Add(90 * time.Second))
    client.Conn.SetPongHandler(func(string) error { _ = client.Conn.SetReadDeadline(time.Now().Add(90 * time.Second)); return nil })
    for {
        if _, _, err := client.Conn.ReadMessage(); err != nil {
            api.removeWSClient(client)
            return
        }
    }
}

// Start 启动API服务器
func (api *AlertAPI) Start() error {
	log.Printf("告警管理API服务器启动: %s", api.server.Addr)
	return api.server.ListenAndServe()
}

// Stop 停止API服务器
func (api *AlertAPI) Stop() error { return api.server.Close() }

 

// 处理告警列表请求
func (api *AlertAPI) handleAlerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		api.getAlerts(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 获取告警列表
func (api *AlertAPI) getAlerts(w http.ResponseWriter, r *http.Request) {
	// 解析查询参数
	filters := make(map[string]interface{})
	if severity := r.URL.Query().Get("severity"); severity != "" {
		filters["severity"] = severity
	}
	if category := r.URL.Query().Get("category"); category != "" {
		filters["category"] = category
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filters["status"] = status
	}
	if ruleName := r.URL.Query().Get("rule_name"); ruleName != "" {
		filters["rule_name"] = ruleName
	}

	page := 1
	pageSize := 50
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 1000 {
			pageSize = parsed
		}
	}

	var alerts []*ManagedAlert
	total := 0
	if api.storage != nil {
		res, cnt, err := api.storage.QueryAlerts(filters, page, pageSize)
		if err != nil {
			log.Printf("查询存储告警失败: %v", err)
			alerts = api.alertManager.GetActiveAlerts(filters)
			total = len(api.alertManager.GetActiveAlerts(nil))
		} else {
			alerts = res
			total = cnt
		}
	} else {
		alerts = api.alertManager.GetActiveAlerts(filters)
		total = len(api.alertManager.GetActiveAlerts(nil))
	}

	response := map[string]interface{}{
		"alerts":    alerts,
		"page":      page,
		"page_size": pageSize,
		"total":     total,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// 处理事件查询
func (api *AlertAPI) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if api.storage == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}
	filters := make(map[string]interface{})
	if et := r.URL.Query().Get("event_type"); et != "" {
		filters["event_type"] = et
	}
	if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
		if v, err := strconv.Atoi(pidStr); err == nil {
			filters["pid"] = v
		}
	}
	if uidStr := r.URL.Query().Get("uid"); uidStr != "" {
		if v, err := strconv.Atoi(uidStr); err == nil {
			filters["uid"] = v
		}
	}
	if since := r.URL.Query().Get("since"); since != "" {
		filters["since"] = since
	}
	if until := r.URL.Query().Get("until"); until != "" {
		filters["until"] = until
	}

	page := 1
	pageSize := 50
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 1000 {
			pageSize = parsed
		}
	}

	events, total, err := api.storage.QueryEvents(filters, page, pageSize)
	if err != nil {
		http.Error(w, fmt.Sprintf("query events failed: %v", err), http.StatusInternalServerError)
		return
	}
	response := map[string]interface{}{
		"events":    events,
		"page":      page,
		"page_size": pageSize,
		"total":     total,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// 处理图谱子图查询
func (api *AlertAPI) handleGraphSubgraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析查询参数
	pidStr := r.URL.Query().Get("pid")
	chainID := r.URL.Query().Get("chain_id")
	maxNodes := 200
	if v := strings.TrimSpace(r.URL.Query().Get("max_nodes")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			maxNodes = n
		}
	}
	var sincePtr, untilPtr *time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		if ts, err := time.Parse(time.RFC3339, v); err == nil {
			sincePtr = &ts
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if ts, err := time.Parse(time.RFC3339, v); err == nil {
			untilPtr = &ts
		}
	}

	opts := SubgraphOptions{Since: sincePtr, Until: untilPtr, MaxNodes: maxNodes}
	var g *Subgraph
	if pidStr != "" {
		if pid, err := strconv.Atoi(pidStr); err == nil && pid >= 0 {
			g = BuildSubgraphByPID(api.eventContext, uint32(pid), opts)
		}
	}
	if g == nil && chainID != "" {
		g = BuildSubgraphByChainID(api.eventContext, chainID, opts)
	}
	if g == nil {
		g = &Subgraph{Nodes: []GraphNode{}, Edges: []GraphEdge{}}
		g.finalize()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"graph":     g,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// 处理告警详情请求
func (api *AlertAPI) handleAlertDetail(w http.ResponseWriter, r *http.Request) {
	// 提取告警ID
	path := strings.TrimPrefix(r.URL.Path, "/api/alerts/")
	alertID := strings.Split(path, "/")[0]

	if alertID == "" {
		http.Error(w, "Alert ID is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		api.getAlertDetail(w, r, alertID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 获取告警详情
func (api *AlertAPI) getAlertDetail(w http.ResponseWriter, r *http.Request, alertID string) {
	api.alertManager.mutex.RLock()
	alert, exists := api.alertManager.activeAlerts[alertID]
	api.alertManager.mutex.RUnlock()

	if !exists {
		http.Error(w, "Alert not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alert)
}

// 处理告警统计请求
func (api *AlertAPI) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 仅使用存储进行统计，避免与内存统计混用造成不一致
	var stats AlertStats
	if api.storage != nil {
		// 活跃告警：new、acknowledged、in_progress
		activeStatuses := []string{string(AlertStatusNew), string(AlertStatusAcknowledged), string(AlertStatusInProgress)}
		activeTotal := 0
		for _, st := range activeStatuses {
			_, cnt, err := api.storage.QueryAlerts(map[string]interface{}{"status": st}, 1, 1)
			if err != nil {
				log.Printf("统计活跃告警失败(status=%s): %v", st, err)
				continue
			}
			activeTotal += cnt
		}
		stats.ActiveAlerts = uint64(activeTotal)

		// 已解决与误报
		if _, cnt, err := api.storage.QueryAlerts(map[string]interface{}{"status": string(AlertStatusResolved)}, 1, 1); err == nil {
			stats.ResolvedAlerts = uint64(cnt)
		} else {
			log.Printf("统计已解决告警失败: %v", err)
		}
		if _, cnt, err := api.storage.QueryAlerts(map[string]interface{}{"status": string(AlertStatusFalsePositive)}, 1, 1); err == nil {
			stats.FalsePositives = uint64(cnt)
		} else {
			log.Printf("统计误报告警失败: %v", err)
		}

		// 总告警数
		if _, totalCnt, err := api.storage.QueryAlerts(map[string]interface{}{}, 1, 1); err == nil {
			stats.TotalAlerts = uint64(totalCnt)
		} else {
			log.Printf("统计总告警失败: %v", err)
		}

		// 分布与平均解决时间（SQLite下）
		if sqlite, ok := api.storage.(*SQLiteStorage); ok && sqlite.DB != nil {
			// 严重级别分布
			rows, err := sqlite.DB.Query("SELECT severity, COUNT(1) FROM alerts GROUP BY severity")
			if err == nil {
				defer rows.Close()
				stats.SeverityDistribution = map[string]uint64{}
				for rows.Next() {
					var sev string
					var cnt int
					if err := rows.Scan(&sev, &cnt); err == nil {
						stats.SeverityDistribution[sev] = uint64(cnt)
					}
				}
			} else {
				log.Printf("统计严重级别分布失败: %v", err)
			}

			// 类别分布
			rows2, err := sqlite.DB.Query("SELECT category, COUNT(1) FROM alerts GROUP BY category")
			if err == nil {
				defer rows2.Close()
				stats.CategoryDistribution = map[string]uint64{}
				for rows2.Next() {
					var cat string
					var cnt int
					if err := rows2.Scan(&cat, &cnt); err == nil {
						stats.CategoryDistribution[cat] = uint64(cnt)
					}
				}
			} else {
				log.Printf("统计类别分布失败: %v", err)
			}

			// 平均解决时间（updated_at - created_at 近似）
			rows3, err := sqlite.DB.Query("SELECT created_at, updated_at FROM alerts WHERE status = ?", string(AlertStatusResolved))
			if err == nil {
				defer rows3.Close()
				var totalDur time.Duration
				var count int
				for rows3.Next() {
					var createdStr, updatedStr string
					if err := rows3.Scan(&createdStr, &updatedStr); err == nil {
						created, err1 := time.Parse(time.RFC3339, createdStr)
						updated, err2 := time.Parse(time.RFC3339, updatedStr)
						if err1 == nil && err2 == nil && updated.After(created) {
							totalDur += updated.Sub(created)
							count++
						}
					}
				}
				if count > 0 {
					stats.AverageResolutionTime = totalDur / time.Duration(count)
				}
			} else {
				log.Printf("统计平均解决时间失败: %v", err)
			}
		}
	} else {
		// 无存储时，回退到内存统计，但不混用
		m := api.alertManager.GetAlertStats()
		if m != nil {
			stats = *m
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// computeAlertStats 统一基于存储计算统计信息（用于WebSocket推送）
func (api *AlertAPI) computeAlertStats() *AlertStats {
	var stats AlertStats
	if api.storage != nil {
		// 活跃告警：new、acknowledged、in_progress
		activeStatuses := []string{string(AlertStatusNew), string(AlertStatusAcknowledged), string(AlertStatusInProgress)}
		activeTotal := 0
		for _, st := range activeStatuses {
			_, cnt, err := api.storage.QueryAlerts(map[string]interface{}{"status": st}, 1, 1)
			if err != nil {
				log.Printf("统计活跃告警失败(status=%s): %v", st, err)
				continue
			}
			activeTotal += cnt
		}
		stats.ActiveAlerts = uint64(activeTotal)

		// 已解决与误报
		if _, cnt, err := api.storage.QueryAlerts(map[string]interface{}{"status": string(AlertStatusResolved)}, 1, 1); err == nil {
			stats.ResolvedAlerts = uint64(cnt)
		} else {
			log.Printf("统计已解决告警失败: %v", err)
		}
		if _, cnt, err := api.storage.QueryAlerts(map[string]interface{}{"status": string(AlertStatusFalsePositive)}, 1, 1); err == nil {
			stats.FalsePositives = uint64(cnt)
		} else {
			log.Printf("统计误报告警失败: %v", err)
		}

		// 总告警数
		if _, totalCnt, err := api.storage.QueryAlerts(map[string]interface{}{}, 1, 1); err == nil {
			stats.TotalAlerts = uint64(totalCnt)
		} else {
			log.Printf("统计总告警失败: %v", err)
		}

		// 分布与平均解决时间（SQLite下）
		if sqlite, ok := api.storage.(*SQLiteStorage); ok && sqlite.DB != nil {
			// 严重级别分布
			rows, err := sqlite.DB.Query("SELECT severity, COUNT(1) FROM alerts GROUP BY severity")
			if err == nil {
				defer rows.Close()
				stats.SeverityDistribution = map[string]uint64{}
				for rows.Next() {
					var sev string
					var cnt int
					if err := rows.Scan(&sev, &cnt); err == nil {
						stats.SeverityDistribution[sev] = uint64(cnt)
					}
				}
			} else {
				log.Printf("统计严重级别分布失败: %v", err)
			}

			// 类别分布
			rows2, err := sqlite.DB.Query("SELECT category, COUNT(1) FROM alerts GROUP BY category")
			if err == nil {
				defer rows2.Close()
				stats.CategoryDistribution = map[string]uint64{}
				for rows2.Next() {
					var cat string
					var cnt int
					if err := rows2.Scan(&cat, &cnt); err == nil {
						stats.CategoryDistribution[cat] = uint64(cnt)
					}
				}
			} else {
				log.Printf("统计类别分布失败: %v", err)
			}

			// 平均解决时间（updated_at - created_at 近似）
			rows3, err := sqlite.DB.Query("SELECT created_at, updated_at FROM alerts WHERE status = ?", string(AlertStatusResolved))
			if err == nil {
				defer rows3.Close()
				var totalDur time.Duration
				var count int
				for rows3.Next() {
					var createdStr, updatedStr string
					if err := rows3.Scan(&createdStr, &updatedStr); err == nil {
						created, err1 := time.Parse(time.RFC3339, createdStr)
						updated, err2 := time.Parse(time.RFC3339, updatedStr)
						if err1 == nil && err2 == nil && updated.After(created) {
							totalDur += updated.Sub(created)
							count++
						}
					}
				}
				if count > 0 {
					stats.AverageResolutionTime = totalDur / time.Duration(count)
				}
			} else {
				log.Printf("统计平均解决时间失败: %v", err)
			}
		}
		return &stats
	}

	// 无存储时，回退到内存统计
	if m := api.alertManager.GetAlertStats(); m != nil {
		stats = *m
		return &stats
	}
	return &AlertStats{}
}

// broadcast 将payload广播到所有WebSocket客户端（带反压：队列满时丢弃最旧消息以保障实时性）
func (api *AlertAPI) broadcast(payload interface{}) {
    data := mustJSON(payload)
    api.wsMutex.Lock()
    for client := range api.wsClients {
        api.enqueueNonBlocking(client, data)
    }
    api.wsMutex.Unlock()
}

// BroadcastAlert 推送新告警并同时推送最新统计
func (api *AlertAPI) BroadcastAlert(alert *ManagedAlert) {
	if alert == nil {
		return
	}
	now := time.Now().Format(time.RFC3339)
	api.broadcast(map[string]interface{}{"type": "alert", "ts": now, "data": alert})
	if stats := api.computeAlertStats(); stats != nil {
		api.broadcast(map[string]interface{}{"type": "stats", "ts": now, "data": stats})
	}
}

// BroadcastEvent 推送原始事件（用于前端展示与实时数据流）
func (api *AlertAPI) BroadcastEvent(event *EventJSON) {
	if event == nil {
		return
	}
	api.broadcast(map[string]interface{}{"type": "event", "ts": time.Now().Format(time.RFC3339), "data": event})
}

// BroadcastGraphUpdate 推送图谱增量（用于前端 D3 可视化实时更新）
func (api *AlertAPI) BroadcastGraphUpdate(update *GraphUpdate) {
	if update == nil {
		return
	}
	api.broadcast(map[string]interface{}{"type": "graph_update", "ts": time.Now().Format(time.RFC3339), "data": update})
}

func (api *AlertAPI) writeWS(conn *websocket.Conn, payload interface{}) error {
    data := mustJSON(payload)
    _ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
    return conn.WriteMessage(websocket.TextMessage, data)
}

// handleWebSocket 客户端连接与初始化数据推送
func (api *AlertAPI) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    conn, err := api.wsUpgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket升级失败: %v", err)
        return
    }
    client := api.addWSClient(conn)
    go api.wsReadPump(client)

	// 初始推送统计与最近告警（仅发给当前客户端）
    if stats := api.computeAlertStats(); stats != nil {
        api.enqueueNonBlocking(client, mustJSON(map[string]interface{}{"type": "stats", "ts": time.Now().Format(time.RFC3339), "data": stats}))
    }
	if api.storage != nil {
		if alerts, _, err := api.storage.QueryAlerts(map[string]interface{}{"status": string(AlertStatusNew)}, 1, 10); err == nil {
            for _, a := range alerts {
                api.enqueueNonBlocking(client, mustJSON(map[string]interface{}{"type": "alert", "ts": time.Now().Format(time.RFC3339), "data": a}))
            }
		}
	} else {
        for _, a := range api.alertManager.GetActiveAlerts(map[string]interface{}{}) {
            api.enqueueNonBlocking(client, mustJSON(map[string]interface{}{"type": "alert", "ts": time.Now().Format(time.RFC3339), "data": a}))
        }
	}

	// 读取循环仅用于保持连接与处理关闭
	conn.SetReadLimit(1024)
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
	api.removeWSClient(client)
}

// mustJSON 辅助：序列化为 JSON 文本；失败返回空字节切片
func mustJSON(v interface{}) []byte {
    b, err := json.Marshal(v)
    if err != nil {
        return []byte{}
    }
    return b
}

func (api *AlertAPI) enqueueNonBlocking(client *WSClient, data []byte) {
    select {
    case client.Send <- data:
        return
    default:
        select {
        case <-client.Send:
        default:
        }
        select {
        case client.Send <- data:
        default:
        }
    }
}

func (api *AlertAPI) HandleAlerts(w http.ResponseWriter, r *http.Request) { api.handleAlerts(w, r) }
func (api *AlertAPI) HandleAlertDetail(w http.ResponseWriter, r *http.Request) { api.handleAlertDetail(w, r) }
func (api *AlertAPI) HandleAlertStats(w http.ResponseWriter, r *http.Request) { api.handleAlertStats(w, r) }
func (api *AlertAPI) HandleAttackChains(w http.ResponseWriter, r *http.Request) { api.handleAttackChains(w, r) }
func (api *AlertAPI) HandleEvents(w http.ResponseWriter, r *http.Request) { api.handleEvents(w, r) }
func (api *AlertAPI) HandleGraphSubgraph(w http.ResponseWriter, r *http.Request) { api.handleGraphSubgraph(w, r) }
func (api *AlertAPI) HandleWebSocket(w http.ResponseWriter, r *http.Request) { api.handleWebSocket(w, r) }

// 处理攻击链请求
func (api *AlertAPI) handleAttackChains(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取攻击链处理器
	var attackChainProcessor *AttackChainProcessor
	if processor, exists := api.alertManager.processors["attack_chain"]; exists {
		if acp, ok := processor.(*AttackChainProcessor); ok {
			attackChainProcessor = acp
		}
	}

	if attackChainProcessor == nil {
		http.Error(w, "Attack chain processor not found", http.StatusNotFound)
		return
	}

	chains := attackChainProcessor.GetAttackChains()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chains)
}
