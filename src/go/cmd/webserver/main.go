// Package main 提供 Web 服务独立入口
// 该服务可运行在普通用户权限下，通过 WebSocket 连接监控程序获取数据
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"etracee/internal/api/middleware"
	"etracee/internal/auth"
	"etracee/internal/common/config"
	"etracee/internal/dbconfig"
	"etracee/internal/web"

	"github.com/gorilla/websocket"
	_ "github.com/go-sql-driver/mysql"
)

// WebServer Web 服务结构
type WebServer struct {
	server       *http.Server
	authService  *auth.AuthService
	storage      WebStorage
	mux          *http.ServeMux

	// WebSocket 连接到监控程序
	monitorConn      *websocket.Conn
	monitorURL       string
	reconnectDelay   time.Duration

	// WebSocket 客户端（浏览器）
	wsUpgrader       websocket.Upgrader
	wsClients        map[*WSClient]struct{}
	wsMutex          sync.Mutex
	wsQueueSize      int

	// 事件缓存
	eventMu          sync.RWMutex
	eventTotal       uint64
	eventHistory     []*EventInfo
	eventWindowLimit int
	startTime        time.Time
	alertHistory     []*AlertInfo

	// 安全配置
	allowedOrigins map[string]struct{}
	apiToken       string
	bindAddr       string
	requireAuth    bool

	// 认证启用标志
	authEnabled bool

	// 中间件
	corsMiddleware *middleware.CORSMiddleware
}

// EventInfo 事件信息（简化版）
type EventInfo struct {
	Timestamp string `json:"timestamp"`
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	EventType string `json:"event_type"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename,omitempty"`
	SrcAddr   string `json:"src_addr,omitempty"`
	DstAddr   string `json:"dst_addr,omitempty"`
	Severity  string `json:"severity,omitempty"`
}

// AlertInfo 告警信息
type AlertInfo struct {
	ID          string                 `json:"id"`
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Timestamp   string                 `json:"timestamp"`
	Status      string                 `json:"status"`
	Event       *EventInfo             `json:"event,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// WebStorage Web 服务存储接口
type WebStorage interface {
	GetAlerts(limit, offset int) ([]*AlertInfo, error)
	GetAlertByID(id string) (*AlertInfo, error)
	GetEventCount() (uint64, error)
	GetAlertStats() (map[string]interface{}, error)
}

// MySQLStorage MySQL 存储实现
type MySQLStorage struct {
	db *sql.DB
}

// NewWebServer 创建 Web 服务
func NewWebServer(port int, monitorURL string) *WebServer {
	srv := &WebServer{
		monitorURL:       monitorURL,
		reconnectDelay:   5 * time.Second,
		wsClients:        make(map[*WSClient]struct{}),
		wsQueueSize:      1024,
		eventWindowLimit: 100000,
		startTime:        time.Now(),
		eventHistory:     make([]*EventInfo, 0),
		alertHistory:     make([]*AlertInfo, 0),
		mux:              http.NewServeMux(),
	}

	// 从环境变量获取配置
	srv.allowedOrigins = config.AllowedOriginsFromEnv()
	srv.apiToken = config.APITokenFromEnv()
	srv.requireAuth = srv.apiToken != ""
	srv.bindAddr = config.BindAddrFromEnv()
	if srv.bindAddr == "" {
		srv.bindAddr = "0.0.0.0"
	}

	// 设置 CORS 中间件
	srv.corsMiddleware = middleware.NewCORSMiddleware(srv.allowedOrigins, srv.apiToken)
	srv.corsMiddleware.RequireAuth = srv.requireAuth
	srv.wsUpgrader = websocket.Upgrader{CheckOrigin: srv.corsMiddleware.CheckOrigin}

	// 注册路由（不应用认证中间件）
	srv.registerRoutes()

	// 构建处理器链
	handler := srv.buildHandler()

	addr := fmt.Sprintf("%s:%d", srv.bindAddr, port)
	srv.server = &http.Server{Addr: addr, Handler: handler}

	return srv
}

// registerRoutes 注册所有路由
func (s *WebServer) registerRoutes() {
	// 认证相关路由（无需认证）
	s.mux.HandleFunc("/api/login", s.handleLogin)
	s.mux.HandleFunc("/api/logout", s.handleLogout)
	s.mux.HandleFunc("/api/check-auth", s.handleCheckAuth)
	s.mux.Handle("/login", web.LoginHandler())

	// API 路由（需要认证）
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/events", s.handleEvents)
	s.mux.HandleFunc("/api/alerts", s.handleAlerts)
	s.mux.HandleFunc("/api/stats", s.handleStats)
	s.mux.HandleFunc("/api/ws", s.handleWebSocket)

	// 静态资源
	s.mux.Handle("/", web.Handler())
}

// buildHandler 构建处理器链
func (s *WebServer) buildHandler() http.Handler {
	// 构建基础处理器链：mux -> auth -> cors
	var baseHandler http.Handler = s.mux

	// 如果认证服务已启用，应用认证中间件
	if s.authService != nil {
		baseHandler = s.authService.Middleware(baseHandler)
	}

	// 应用 CORS 中间件
	baseHandler = s.corsMiddleware.Wrap(baseHandler)

	// 应用路径规范化（必须在最外层，且直接调用 baseHandler）
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		for strings.Contains(p, "//") {
			p = strings.ReplaceAll(p, "//", "/")
		}
		p = path.Clean(p)
		if p == "." {
			p = "/"
		}

		// 如果路径被修改，创建新请求
		if p != r.URL.Path {
			r2 := r.Clone(r.Context())
			r2.URL.Path = p
			baseHandler.ServeHTTP(w, r2)
			return
		}

		// 直接调用基础处理器链，避免闭包递归
		baseHandler.ServeHTTP(w, r)
	})
}

// SetAuthService 设置认证服务并重建处理器链
func (s *WebServer) SetAuthService(authService *auth.AuthService) {
	s.authService = authService
	s.authEnabled = authService != nil
	// 重建处理器链以应用认证中间件
	s.server.Handler = s.buildHandler()
}

// SetStorage 设置存储
func (s *WebServer) SetStorage(storage WebStorage) {
	s.storage = storage
}

// Start 启动服务
func (s *WebServer) Start() error {
	// 启动监控程序连接
	go s.connectToMonitor()

	log.Printf("[+] Web 服务启动在 %s", s.server.Addr)
	log.Printf("    Web 界面: http://%s", s.server.Addr)
	log.Printf("    监控程序地址: %s", s.monitorURL)
	if s.authEnabled {
		log.Printf("    认证服务: 已启用 (数据库: etracee_web)")
	} else {
		log.Printf("    认证服务: 未启用")
	}

	return s.server.ListenAndServe()
}

// Stop 停止服务
func (s *WebServer) Stop() error {
	if s.monitorConn != nil {
		s.monitorConn.Close()
	}
	return s.server.Close()
}

// connectToMonitor 连接到监控程序
func (s *WebServer) connectToMonitor() {
	for {
		conn, _, err := websocket.DefaultDialer.Dial(s.monitorURL, nil)
		if err != nil {
			log.Printf("[!] 连接监控程序失败: %v, %s 后重试...", err, s.reconnectDelay)
			time.Sleep(s.reconnectDelay)
			continue
		}

		s.monitorConn = conn
		log.Printf("[+] 已连接到监控程序: %s", s.monitorURL)

		// 读取消息
		s.readFromMonitor()

		// 连接断开后重连
		log.Printf("[!] 监控程序连接断开, %s 后重连...", s.reconnectDelay)
		time.Sleep(s.reconnectDelay)
	}
}

// readFromMonitor 从监控程序读取消息
func (s *WebServer) readFromMonitor() {
	for {
		_, msg, err := s.monitorConn.ReadMessage()
		if err != nil {
			return
		}

		// 解析消息并处理
		var data map[string]interface{}
		if err := json.Unmarshal(msg, &data); err != nil {
			continue
		}

		msgType, _ := data["type"].(string)
		switch msgType {
		case "event":
			s.handleMonitorEvent(data)
		case "alert":
			s.handleMonitorAlert(data)
		case "stats":
			s.handleMonitorStats(data)
		}

		// 广播给所有客户端
		s.broadcast(msg)
	}
}

// handleMonitorEvent 处理监控程序事件
func (s *WebServer) handleMonitorEvent(data map[string]interface{}) {
	s.eventMu.Lock()
	s.eventTotal++
	s.eventMu.Unlock()
}

// handleMonitorAlert 处理监控程序告警
func (s *WebServer) handleMonitorAlert(data map[string]interface{}) {
	// 解析告警并存储
	alertData, _ := data["data"].(map[string]interface{})
	if alertData == nil {
		return
	}

	alert := &AlertInfo{
		ID:          fmt.Sprintf("%v", alertData["id"]),
		RuleName:    fmt.Sprintf("%v", alertData["rule_name"]),
		Severity:    fmt.Sprintf("%v", alertData["severity"]),
		Description: fmt.Sprintf("%v", alertData["description"]),
		Timestamp:   fmt.Sprintf("%v", alertData["timestamp"]),
		Status:      "new",
	}

	s.eventMu.Lock()
	s.alertHistory = append(s.alertHistory, alert)
	if len(s.alertHistory) > 1000 {
		s.alertHistory = s.alertHistory[len(s.alertHistory)-1000:]
	}
	s.eventMu.Unlock()
}

// handleMonitorStats 处理监控程序统计
func (s *WebServer) handleMonitorStats(data map[string]interface{}) {
	// 更新本地统计
}

// broadcast 广播消息给所有客户端
func (s *WebServer) broadcast(msg []byte) {
	s.wsMutex.Lock()
	clients := make([]*WSClient, 0, len(s.wsClients))
	for c := range s.wsClients {
		clients = append(clients, c)
	}
	s.wsMutex.Unlock()

	for _, c := range clients {
		select {
		case c.Send <- msg:
		default:
			s.removeWSClient(c)
		}
	}
}

// WSClient WebSocket 客户端
type WSClient struct {
	Conn      *websocket.Conn
	Send      chan []byte
	closeOnce sync.Once
}

func (s *WebServer) addWSClient(conn *websocket.Conn) *WSClient {
	client := &WSClient{
		Conn: conn,
		Send: make(chan []byte, s.wsQueueSize),
	}
	s.wsMutex.Lock()
	s.wsClients[client] = struct{}{}
	s.wsMutex.Unlock()
	go s.wsWritePump(client)
	return client
}

func (s *WebServer) removeWSClient(client *WSClient) {
	s.wsMutex.Lock()
	delete(s.wsClients, client)
	s.wsMutex.Unlock()
	client.closeOnce.Do(func() {
		close(client.Send)
		_ = client.Conn.Close()
	})
}

func (s *WebServer) wsWritePump(client *WSClient) {
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()
	for {
		select {
		case msg, ok := <-client.Send:
			if !ok {
				return
			}
			_ = client.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := client.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				s.removeWSClient(client)
				return
			}
		case <-pingTicker.C:
			_ = client.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := client.Conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(30*time.Second)); err != nil {
				s.removeWSClient(client)
				return
			}
		}
	}
}

func (s *WebServer) wsReadPump(client *WSClient) {
	client.Conn.SetReadLimit(1024)
	_ = client.Conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	client.Conn.SetPongHandler(func(string) error {
		_ = client.Conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		return nil
	})
	for {
		if _, _, err := client.Conn.ReadMessage(); err != nil {
			s.removeWSClient(client)
			return
		}
	}
}

// HTTP handlers

func (s *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.authService == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "认证服务未启用，请配置 MySQL 连接",
		})
		return
	}
	s.authService.HandleLogin(w, r)
}

func (s *WebServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.authService == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	s.authService.HandleLogout(w, r)
}

func (s *WebServer) handleCheckAuth(w http.ResponseWriter, r *http.Request) {
	if s.authService == nil {
		w.Header().Set("Content-Type", "application/json")
		// 当认证服务未启用时，根据配置返回相应状态
		if s.authEnabled {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"authenticated": false,
				"message":       "认证服务初始化失败",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"authenticated": false,
				"message":       "认证服务未启用，请配置 MySQL 连接",
			})
		}
		return
	}
	s.authService.HandleCheckAuth(w, r)
}

func (s *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.eventMu.RLock()
	total := s.eventTotal
	alertCount := len(s.alertHistory)
	s.eventMu.RUnlock()

	connected := s.monitorConn != nil

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"connected":      connected,
		"monitor_url":    s.monitorURL,
		"event_total":    total,
		"alert_count":    alertCount,
		"uptime_seconds": time.Since(s.startTime).Seconds(),
		"auth_enabled":   s.authEnabled,
	})
}

func (s *WebServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	s.eventMu.RLock()
	events := make([]*EventInfo, len(s.eventHistory))
	copy(events, s.eventHistory)
	s.eventMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"total":  len(events),
	})
}

func (s *WebServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	s.eventMu.RLock()
	alerts := make([]*AlertInfo, len(s.alertHistory))
	copy(alerts, s.alertHistory)
	s.eventMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"alerts": alerts,
		"total":  len(alerts),
	})
}

func (s *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	s.eventMu.RLock()
	total := s.eventTotal
	alertCount := len(s.alertHistory)
	s.eventMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events_total":   total,
		"alerts_total":   alertCount,
		"uptime_seconds": time.Since(s.startTime).Seconds(),
		"start_time":     s.startTime.Format(time.RFC3339),
		"auth_enabled":   s.authEnabled,
	})
}

func (s *WebServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := s.addWSClient(conn)
	go s.wsReadPump(client)
}

func main() {
	// 命令行参数
	port := 8888
	monitorURL := "ws://localhost:8889/ws"

	if p := os.Getenv("WEB_PORT"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	if u := os.Getenv("MONITOR_URL"); u != "" {
		monitorURL = u
	}

	log.Println("[*] Web 服务正在初始化...")
	log.Printf("    端口: %d", port)
	log.Printf("    监控程序地址: %s", monitorURL)

	// 加载配置文件
	appCfg, err := dbconfig.LoadAppConfig()
	if err != nil {
		log.Fatalf("[!] 加载配置文件失败: %v", err)
	}

	// 初始化认证服务（使用 Web 数据库）
	webDB := appCfg.GetWebDBConfig()
	authCfg := &auth.Config{
		MySQLHost:     webDB.Host,
		MySQLPort:     webDB.Port,
		MySQLUser:     webDB.User,
		MySQLPassword: webDB.Password,
		MySQLDatabase: webDB.Database,
		AdminUsername: appCfg.Admin.Username,
		AdminPassword: appCfg.Admin.Password,
		JWTSecret:     appCfg.JWT.Secret,
		TokenExpiry:   time.Duration(appCfg.JWT.ExpiryHours) * time.Hour,
	}

	log.Printf("[*] 认证服务配置: MySQL %s@%s:%d/%s",
		authCfg.MySQLUser, authCfg.MySQLHost, authCfg.MySQLPort, authCfg.MySQLDatabase)

	authService, authErr := auth.InitAuth(authCfg)
	if authErr != nil {
		log.Printf("[!] 认证服务初始化失败: %v", authErr)
		log.Printf("[!] Web 服务将以无认证模式运行")
		log.Printf("[!] 请检查 MySQL 连接配置: config/database.yaml")
	} else {
		log.Println("[+] 认证服务初始化成功")
		log.Printf("[+] 管理员账户: %s (请及时修改密码)", authCfg.AdminUsername)
	}

	// 创建 Web 服务
	srv := NewWebServer(port, monitorURL)
	if authService != nil {
		srv.SetAuthService(authService)
	}

	// 信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("[*] 收到退出信号，正在关闭...")
		srv.Stop()
		os.Exit(0)
	}()

	// 启动服务
	if err := srv.Start(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Web 服务错误: %v", err)
	}
}
