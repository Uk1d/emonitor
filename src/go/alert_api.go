package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"

	"github.com/gorilla/websocket"
)

// AlertAPI 告警API服务器
type AlertAPI struct {
    alertManager *AlertManager
    server       *http.Server
    storage      Storage

    // WebSocket
    wsUpgrader websocket.Upgrader
    wsClients  map[*WSClient]struct{}
    wsMutex    sync.Mutex
    wsQueueSize int
}

// NewAlertAPI 创建告警API服务器
func NewAlertAPI(alertManager *AlertManager, port int, storage Storage) *AlertAPI {
    api := &AlertAPI{
        alertManager: alertManager,
        storage:      storage,
    }

	mux := http.NewServeMux()

	// 注册API路由
	mux.HandleFunc("/api/alerts", api.handleAlerts)
	mux.HandleFunc("/api/alerts/", api.handleAlertDetail)
	mux.HandleFunc("/api/alerts/stats", api.handleAlertStats)
	mux.HandleFunc("/api/attack-chains", api.handleAttackChains)
	mux.HandleFunc("/api/events", api.handleEvents)
	// WebSocket实时推送
	mux.HandleFunc("/ws", api.handleWebSocket)

	// 静态文件服务（用于Web界面）
	mux.HandleFunc("/", api.handleWebInterface)

    // 初始化WebSocket
    api.wsUpgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
    api.wsClients = make(map[*WSClient]struct{})
    // 队列大小可通过环境变量配置
    api.wsQueueSize = 256
    if v := strings.TrimSpace(os.Getenv("ETRACEE_WS_QUEUE_SIZE")); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 8192 {
            api.wsQueueSize = n
        }
    }

	api.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: api.corsMiddleware(mux),
	}

	return api
}

// WSClient 表示一个带发送队列的 WebSocket 客户端（用于反压）
type WSClient struct {
    Conn *websocket.Conn
    Send chan []byte
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
    // 专用写循环，读取队列并写入到连接；写失败则移除客户端
    for msg := range client.Send {
        _ = client.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
        if err := client.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
            log.Printf("WebSocket 写入失败，移除客户端: %v", err)
            api.removeWSClient(client)
            return
        }
    }
}

// Start 启动API服务器
func (api *AlertAPI) Start() error {
	log.Printf("告警管理API服务器启动在端口: %s", api.server.Addr)
	return api.server.ListenAndServe()
}

// Stop 停止API服务器
func (api *AlertAPI) Stop() error {
	return api.server.Close()
}

// CORS中间件
func (api *AlertAPI) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

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
    data, err := json.Marshal(payload)
    if err != nil {
        log.Printf("WebSocket 负载序列化失败: %v", err)
        return
    }
    api.wsMutex.Lock()
    for client := range api.wsClients {
        select {
        case client.Send <- data:
            // 正常入队
        default:
            // 队列已满，丢弃最旧的一条并重试入队
            select {
            case <-client.Send:
                // 移除一个旧消息
            default:
                // 无法移除（极端情况），本次直接丢弃以保护服务
            }
            select {
            case client.Send <- data:
            default:
                // 若仍阻塞，则忽略该客户端本次消息
                log.Printf("WebSocket 客户端队列饱和，已丢弃一条消息")
            }
        }
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

func (api *AlertAPI) writeWS(conn *websocket.Conn, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
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

    // 初始推送统计与最近告警（仅发给当前客户端）
    if stats := api.computeAlertStats(); stats != nil {
        select {
        case client.Send <- mustJSON(map[string]interface{}{"type": "stats", "ts": time.Now().Format(time.RFC3339), "data": stats}):
        default:
            select { case <-client.Send: default: }
            select { case client.Send <- mustJSON(map[string]interface{}{"type": "stats", "ts": time.Now().Format(time.RFC3339), "data": stats}): default: }
        }
    }
    if api.storage != nil {
        if alerts, _, err := api.storage.QueryAlerts(map[string]interface{}{"status": string(AlertStatusNew)}, 1, 10); err == nil {
            for _, a := range alerts {
                select {
                case client.Send <- mustJSON(map[string]interface{}{"type": "alert", "ts": time.Now().Format(time.RFC3339), "data": a}):
                default:
                    // 队列饱和时丢弃最旧消息
                    select { case <-client.Send: default: }
                    select { case client.Send <- mustJSON(map[string]interface{}{"type": "alert", "ts": time.Now().Format(time.RFC3339), "data": a}): default: }
                }
            }
        }
    } else {
        for _, a := range api.alertManager.GetActiveAlerts(map[string]interface{}{}) {
            select {
            case client.Send <- mustJSON(map[string]interface{}{"type": "alert", "ts": time.Now().Format(time.RFC3339), "data": a}):
            default:
                select { case <-client.Send: default: }
                select { case client.Send <- mustJSON(map[string]interface{}{"type": "alert", "ts": time.Now().Format(time.RFC3339), "data": a}): default: }
            }
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

// 处理Web界面请求
func (api *AlertAPI) handleWebInterface(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		// 设置正确的Content-Type响应头，指定UTF-8编码
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// 返回简单的HTML界面
		html := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>eTracee 告警中心</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; }
        h1, h2 { color: #333; }
        .container { display: flex; flex-wrap: wrap; gap: 20px; }
        .stats-card { background-color: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); flex: 1; min-width: 200px; }
        .alerts-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .alerts-table th, .alerts-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .alerts-table th { background-color: #f2f2f2; }
        .status-new { color: blue; }
        .status-acknowledged { color: orange; }
        .status-resolved { color: green; }
        .status-false_positive { color: grey; }
        #ws-status { margin-top: 10px; font-weight: bold; }
    </style>
</head>
<body>
    <h1>eTracee 告警中心</h1>
    <div id="ws-status">连接中...</div>
    <h2>告警统计</h2>
    <div class="container">
        <div class="stats-card">总告警数: <span id="total-alerts">0</span></div>
        <div class="stats-card">活跃告警: <span id="active-alerts">0</span></div>
        <div class="stats-card">已解决: <span id="resolved-alerts">0</span></div>
        <div class="stats-card">误报: <span id="false-positive-alerts">0</span></div>
    </div>
    <h2>最新告警</h2>
    <table class="alerts-table">
        <thead>
            <tr>
                <th>ID</th>
                <th>规则名称</th>
                <th>严重性</th>
                <th>状态</th>
                <th>时间</th>
            </tr>
        </thead>
        <tbody id="alerts-tbody">
        </tbody>
    </table>

    <h2>最新事件流</h2>
    <table class="alerts-table">
        <thead>
            <tr>
                <th>时间</th>
                <th>类型</th>
                <th>PID</th>
                <th>Comm</th>
                <th>文件</th>
                <th>源地址</th>
                <th>目标地址</th>
            </tr>
        </thead>
        <tbody id="events-tbody">
        </tbody>
    </table>

    <script>
        const wsStatus = document.getElementById('ws-status');
        const totalAlertsSpan = document.getElementById('total-alerts');
        const activeAlertsSpan = document.getElementById('active-alerts');
        const resolvedAlertsSpan = document.getElementById('resolved-alerts');
        const falsePositiveAlertsSpan = document.getElementById('false-positive-alerts');
        const alertsTbody = document.getElementById('alerts-tbody');
        const eventsTbody = document.getElementById('events-tbody');

        function connect() {
            const ws = new WebSocket("ws://" + window.location.host + "/ws");

            ws.onopen = function() {
                wsStatus.textContent = "WebSocket 已连接";
                wsStatus.style.color = "green";
            };

            ws.onmessage = function(event) {
                const message = JSON.parse(event.data);
                if (message.type === 'stats') {
                    updateStats(message.data);
                } else if (message.type === 'alert') {
                    addAlert(message.data);
                } else if (message.type === 'event') {
                    addEvent(message.data);
                }
            };

            ws.onclose = function() {
                wsStatus.textContent = "WebSocket 已断开，尝试重连...";
                wsStatus.style.color = "red";
                setTimeout(connect, 3000); // 3秒后重连
            };

            ws.onerror = function(err) {
                console.error('WebSocket 错误: ', err);
                ws.close();
            };
        }

        function updateStats(stats) {
            totalAlertsSpan.textContent = stats.total_alerts || 0;
            activeAlertsSpan.textContent = stats.active_alerts || 0;
            resolvedAlertsSpan.textContent = stats.resolved_alerts || 0;
            falsePositiveAlertsSpan.textContent = stats.false_positive_alerts || 0;
        }

        function addAlert(alert) {
            const row = document.createElement('tr');
            row.innerHTML = '<td>' + alert.ID + '</td>' +
                '<td>' + alert.RuleName + '</td>' +
                '<td>' + alert.Severity + '</td>' +
                '<td class="status-' + alert.Status.toLowerCase() + '">' + alert.Status + '</td>' +
                '<td>' + new Date(alert.CreatedAt).toLocaleString() + '</td>';
            alertsTbody.insertBefore(row, alertsTbody.firstChild);
            // 限制告警表行数，避免页面无限增长
            if (alertsTbody.children.length > 200) {
                alertsTbody.removeChild(alertsTbody.lastChild);
            }
        }

        function addEvent(event) {
            const row = document.createElement('tr');
            const src = event.src_addr ? (event.src_addr.ip + ':' + (event.src_addr.port || '')) : '';
            const dst = event.dst_addr ? (event.dst_addr.ip + ':' + (event.dst_addr.port || '')) : '';
            row.innerHTML = '<td>' + (event.timestamp || '') + '</td>' +
                '<td>' + (event.event_type || '') + '</td>' +
                '<td>' + (event.pid || '') + '</td>' +
                '<td>' + (event.comm || '') + '</td>' +
                '<td>' + (event.filename || '') + '</td>' +
                '<td>' + src + '</td>' +
                '<td>' + dst + '</td>';
            eventsTbody.insertBefore(row, eventsTbody.firstChild);
            // 限制事件表行数，避免页面无限增长
            if (eventsTbody.children.length > 500) {
                eventsTbody.removeChild(eventsTbody.lastChild);
            }
        }

        connect();
    </script>
</body>
</html>
`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}
}
