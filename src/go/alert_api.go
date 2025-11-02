package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AlertAPI 告警API服务器
type AlertAPI struct {
	alertManager *AlertManager
	server       *http.Server
}

// NewAlertAPI 创建告警API服务器
func NewAlertAPI(alertManager *AlertManager, port int) *AlertAPI {
	api := &AlertAPI{
		alertManager: alertManager,
	}

	mux := http.NewServeMux()
	
	// 注册API路由
	mux.HandleFunc("/api/alerts", api.handleAlerts)
	mux.HandleFunc("/api/alerts/", api.handleAlertDetail)
	mux.HandleFunc("/api/alerts/stats", api.handleAlertStats)
	mux.HandleFunc("/api/alerts/acknowledge", api.handleAcknowledgeAlert)
	mux.HandleFunc("/api/alerts/resolve", api.handleResolveAlert)
	mux.HandleFunc("/api/attack-chains", api.handleAttackChains)
	
	// 静态文件服务（用于Web界面）
	mux.HandleFunc("/", api.handleWebInterface)

	api.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: api.corsMiddleware(mux),
	}

	return api
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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
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

	// 获取告警列表
	alerts := api.alertManager.GetActiveAlerts(filters)
	
	// 分页处理
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
	
	start := (page - 1) * pageSize
	end := start + pageSize
	
	if start >= len(alerts) {
		alerts = []*ManagedAlert{}
	} else {
		if end > len(alerts) {
			end = len(alerts)
		}
		alerts = alerts[start:end]
	}

	// 构建响应
	response := map[string]interface{}{
		"alerts":     alerts,
		"page":       page,
		"page_size":  pageSize,
		"total":      len(api.alertManager.GetActiveAlerts(nil)),
		"timestamp":  time.Now().Format(time.RFC3339),
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

	stats := api.alertManager.GetAlertStats()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// 处理确认告警请求
func (api *AlertAPI) handleAcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		AlertID        string `json:"alert_id"`
		AcknowledgedBy string `json:"acknowledged_by"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if request.AlertID == "" || request.AcknowledgedBy == "" {
		http.Error(w, "alert_id and acknowledged_by are required", http.StatusBadRequest)
		return
	}

	if err := api.alertManager.AcknowledgeAlert(request.AlertID, request.AcknowledgedBy); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Alert acknowledged successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// 处理解决告警请求
func (api *AlertAPI) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		AlertID    string `json:"alert_id"`
		ResolvedBy string `json:"resolved_by"`
		Notes      string `json:"notes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if request.AlertID == "" || request.ResolvedBy == "" {
		http.Error(w, "alert_id and resolved_by are required", http.StatusBadRequest)
		return
	}

	if err := api.alertManager.ResolveAlert(request.AlertID, request.ResolvedBy, request.Notes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Alert resolved successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
		// 返回简单的HTML界面
		html := `
<!DOCTYPE html>
<html>
<head>
    <title>eTracee 告警管理系统</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-card { background: #ecf0f1; padding: 15px; border-radius: 5px; flex: 1; }
        .alerts { margin: 20px 0; }
        .alert { background: #fff; border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .alert.critical { border-left: 5px solid #e74c3c; }
        .alert.high { border-left: 5px solid #f39c12; }
        .alert.medium { border-left: 5px solid #f1c40f; }
        .alert.low { border-left: 5px solid #27ae60; }
        .api-docs { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 eTracee 告警管理系统</h1>
        <p>实时安全事件监控与告警管理平台</p>
    </div>

    <div class="stats" id="stats">
        <div class="stat-card">
            <h3>活跃告警</h3>
            <p id="active-alerts">加载中...</p>
        </div>
        <div class="stat-card">
            <h3>已解决告警</h3>
            <p id="resolved-alerts">加载中...</p>
        </div>
        <div class="stat-card">
            <h3>误报告警</h3>
            <p id="false-positives">加载中...</p>
        </div>
    </div>

    <div class="alerts">
        <h2>最新告警</h2>
        <div id="alerts-list">加载中...</div>
    </div>

    <div class="api-docs">
        <h2>API 文档</h2>
        <ul>
            <li><strong>GET /api/alerts</strong> - 获取告警列表</li>
            <li><strong>GET /api/alerts/{id}</strong> - 获取告警详情</li>
            <li><strong>GET /api/alerts/stats</strong> - 获取告警统计</li>
            <li><strong>POST /api/alerts/acknowledge</strong> - 确认告警</li>
            <li><strong>POST /api/alerts/resolve</strong> - 解决告警</li>
            <li><strong>GET /api/attack-chains</strong> - 获取攻击链信息</li>
        </ul>
    </div>

    <script>
        // 加载统计信息
        fetch('/api/alerts/stats')
            .then(response => response.json())
            .then(data => {
                document.getElementById('active-alerts').textContent = data.active_alerts;
                document.getElementById('resolved-alerts').textContent = data.resolved_alerts;
                document.getElementById('false-positives').textContent = data.false_positives;
            })
            .catch(error => {
                console.error('Error loading stats:', error);
            });

        // 加载告警列表
        fetch('/api/alerts?page_size=10')
            .then(response => response.json())
            .then(data => {
                const alertsList = document.getElementById('alerts-list');
                if (data.alerts && data.alerts.length > 0) {
                    alertsList.innerHTML = data.alerts.map(alert => 
                        '<div class="alert ' + alert.severity + '">' +
                        '<h4>' + alert.rule_name + ' (' + alert.severity + ')</h4>' +
                        '<p>' + alert.description + '</p>' +
                        '<small>PID: ' + alert.event.pid + ', UID: ' + alert.event.uid + 
                        ', 时间: ' + new Date(alert.created_at).toLocaleString() + '</small>' +
                        '</div>'
                    ).join('');
                } else {
                    alertsList.innerHTML = '<p>暂无活跃告警</p>';
                }
            })
            .catch(error => {
                console.error('Error loading alerts:', error);
                document.getElementById('alerts-list').innerHTML = '<p>加载告警失败</p>';
            });

        // 每30秒刷新一次
        setInterval(() => {
            location.reload();
        }, 30000);
    </script>
</body>
</html>
`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	} else {
		http.NotFound(w, r)
	}
}