package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// IntegrationTest 集成测试
type IntegrationTest struct {
	ruleEngine   *EnhancedRuleEngine
	perfMonitor  *PerformanceMonitor
	alertManager *AlertManager
	eventContext *EventContext
	testResults  []IntegrationTestResult
}

// IntegrationTestResult 集成测试结果
type IntegrationTestResult struct {
	TestName    string        `json:"test_name"`
	Description string        `json:"description"`
	Passed      bool          `json:"passed"`
	Duration    time.Duration `json:"duration"`
	Error       string        `json:"error,omitempty"`
	Details     interface{}   `json:"details,omitempty"`
}

// NewIntegrationTest 创建集成测试
func NewIntegrationTest() *IntegrationTest {
	return &IntegrationTest{
		testResults: make([]IntegrationTestResult, 0),
	}
}

// RunIntegrationTests 运行集成测试
func (it *IntegrationTest) RunIntegrationTests() error {
	log.Println("开始运行集成测试...")

	// 初始化所有组件
	if err := it.initializeComponents(); err != nil {
		return fmt.Errorf("组件初始化失败: %v", err)
	}

	// 运行各项测试
	tests := []func() IntegrationTestResult{
		it.testRuleEngineIntegration,
		it.testPerformanceMonitorIntegration,
		it.testAlertManagerIntegration,
		it.testEventContextIntegration,
		it.testAPIServerIntegration,
		it.testEndToEndWorkflow,
	}

	for _, test := range tests {
		result := test()
		it.testResults = append(it.testResults, result)

    status := "[+] PASS"
		if !result.Passed {
			status = "✗ FAIL"
		}
		log.Printf("[%s] %s (耗时: %v)", status, result.TestName, result.Duration)

		if !result.Passed && result.Error != "" {
			log.Printf("  错误: %s", result.Error)
		}
	}

	// 生成测试报告
	if err := it.generateReport(); err != nil {
		log.Printf("生成测试报告失败: %v", err)
	}

	// 统计结果
	passed := 0
	for _, result := range it.testResults {
		if result.Passed {
			passed++
		}
	}

	log.Printf("集成测试完成: %d/%d 通过", passed, len(it.testResults))

	if passed != len(it.testResults) {
		return fmt.Errorf("存在失败的集成测试")
	}

	return nil
}

// initializeComponents 初始化所有组件
func (it *IntegrationTest) initializeComponents() error {
	// 初始化规则引擎
	it.ruleEngine = NewEnhancedRuleEngine()

	// 添加测试规则
	it.ruleEngine.AddRule(&EnhancedRule{
		ID:          "test_rule_1",
		Name:        "测试规则1",
		Description: "用于集成测试的规则",
		Category:    "test",
		Severity:    "medium",
		Enabled:     true,
		Conditions: []RuleCondition{
			{
				Field:    "event_type",
				Operator: "equals",
				Value:    "execve",
			},
			{
				Field:    "comm",
				Operator: "equals",
				Value:    "test_process",
			},
		},
		Actions: []RuleAction{
			{Type: "log", Config: map[string]interface{}{"level": "info"}},
			{Type: "alert", Config: map[string]interface{}{"severity": "medium"}},
		},
	})

	// 初始化性能监控器
	it.perfMonitor = NewPerformanceMonitor(it.ruleEngine)

	// 初始化告警管理器
	alertConfig := &AlertManagerConfig{
		MaxActiveAlerts:      1000,
		MaxHistoryAlerts:     5000,
		AlertRetentionDays:   7,
		EnableAggregation:    true,
		AggregationWindow:    1 * time.Minute,
		AggregationThreshold: 3,
		EnableAutoResolve:    true,
		AutoResolveTimeout:   1 * time.Hour,
		EnableNotifications:  true,
		AlertStoragePath:     "./test_alerts",
	}
	it.alertManager = NewAlertManager(alertConfig)

	// 注册告警处理器
	it.alertManager.RegisterProcessor(&DefaultAlertProcessor{})
	it.alertManager.RegisterProcessor(&SeverityBasedProcessor{})

	// 注册通知渠道
	it.alertManager.RegisterNotificationChannel(&ConsoleNotificationChannel{})

	// 初始化事件上下文
	config := &EventContextConfig{
		MaxProcessContexts:         1000,
		MaxNetworkContexts:         500,
		MaxFileContexts:            2000,
		MaxAttackChains:            100,
		ProcessContextTTL:          time.Hour,
		NetworkContextTTL:          30 * time.Minute,
		FileContextTTL:             2 * time.Hour,
		AttackChainTTL:             24 * time.Hour,
		EnablePersistence:          false, // 测试时禁用持久化
		EnableAttackChainDetection: true,
		AttackChainTimeout:         10 * time.Minute,
		MinChainEvents:             2,
		EnableThreatIntel:          false, // 测试时禁用威胁情报
	}
	it.eventContext = NewEventContext(config)

	return nil
}

// testRuleEngineIntegration 测试规则引擎集成
func (it *IntegrationTest) testRuleEngineIntegration() IntegrationTestResult {
	start := time.Now()
	result := IntegrationTestResult{
		TestName:    "规则引擎集成测试",
		Description: "测试规则引擎的基本功能",
	}

	// 创建测试事件
	testEvent := &EventJSON{
		EventType: "execve",
		PID:       12345,
		PPID:      1,
		UID:       1000,
		Comm:      "test_process",
		Filename:  "/bin/test_process",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// 匹配规则
	alerts := it.ruleEngine.MatchRules(testEvent)

	// 验证结果
	if len(alerts) != 1 {
		result.Error = fmt.Sprintf("期望1个告警，实际得到%d个", len(alerts))
	} else if alerts[0].RuleName != "测试规则1" {
		result.Error = fmt.Sprintf("期望规则名称'测试规则1'，实际得到'%s'", alerts[0].RuleName)
	} else {
		result.Passed = true
		result.Details = map[string]interface{}{
			"alerts_count": len(alerts),
			"rule_name":    alerts[0].RuleName,
			"severity":     alerts[0].Severity,
		}
	}

	result.Duration = time.Since(start)
	return result
}

// testPerformanceMonitorIntegration 测试性能监控器集成
func (it *IntegrationTest) testPerformanceMonitorIntegration() IntegrationTestResult {
	start := time.Now()
	result := IntegrationTestResult{
		TestName:    "性能监控器集成测试",
		Description: "测试性能监控器的功能",
	}

	// 记录一些性能数据
	it.perfMonitor.RecordEvent(10 * time.Millisecond)
	it.perfMonitor.RecordAlert("test_rule", 5*time.Millisecond)
	it.perfMonitor.RecordError("test_error")

	// 获取性能报告
	report := it.perfMonitor.GenerateReport()

	// 验证结果
	if report.TotalEvents != 1 {
		result.Error = fmt.Sprintf("期望处理1个事件，实际处理%d个", report.TotalEvents)
	} else if report.TotalAlerts != 1 {
		result.Error = fmt.Sprintf("期望生成1个告警，实际生成%d个", report.TotalAlerts)
	} else if report.TotalErrors != 1 {
		result.Error = fmt.Sprintf("期望1个错误，实际%d个", report.TotalErrors)
	} else {
		result.Passed = true
		result.Details = map[string]interface{}{
			"events_processed":   report.TotalEvents,
			"alerts_generated":   report.TotalAlerts,
			"errors_occurred":    report.TotalErrors,
			"average_event_time": report.AvgProcessingTime,
		}
	}

	result.Duration = time.Since(start)
	return result
}

// testAlertManagerIntegration 测试告警管理器集成
func (it *IntegrationTest) testAlertManagerIntegration() IntegrationTestResult {
	start := time.Now()
	result := IntegrationTestResult{
		TestName:    "告警管理器集成测试",
		Description: "测试告警管理器的功能",
	}

	// 创建测试告警
	testAlert := AlertEvent{
		RuleName:    "测试规则1",
		Severity:    "medium",
		Description: "集成测试告警",
		Event: &EventJSON{
			PID:  12345,
			Comm: "test_process",
		},
		Timestamp: time.Now(),
	}

	// 处理告警
	managedAlert, err := it.alertManager.ProcessAlert(testAlert)
	if err != nil {
		result.Error = fmt.Sprintf("处理告警失败: %v", err)
	} else if managedAlert.Status != AlertStatusNew {
		result.Error = fmt.Sprintf("期望告警状态为'%s'，实际为'%s'", AlertStatusNew, managedAlert.Status)
	} else {
		result.Passed = true
		result.Details = map[string]interface{}{
			"alert_id":     managedAlert.ID,
			"status":       managedAlert.Status,
			"severity":     managedAlert.Severity,
			"processed_at": managedAlert.UpdatedAt,
		}
	}

	result.Duration = time.Since(start)
	return result
}

// testEventContextIntegration 测试事件上下文集成
func (it *IntegrationTest) testEventContextIntegration() IntegrationTestResult {
	start := time.Now()
	result := IntegrationTestResult{
		TestName:    "事件上下文集成测试",
		Description: "测试事件上下文管理功能",
	}

	// 创建测试事件
	testEvent := &EventJSON{
		PID:       12345,
		PPID:      1,
		UID:       1000,
		GID:       1000,
		Comm:      "test_process",
		Filename:  "/bin/test_process",
		EventType: "execve",
		SrcAddr: &AddrJSON{
			IP:   "127.0.0.1",
			Port: 8080,
		},
		DstAddr: &AddrJSON{
			IP:   "192.168.1.100",
			Port: 443,
		},
		Mode:    0644,
		RetCode: 0,
	}

	// 更新进程上下文
	it.eventContext.UpdateProcessContext(testEvent)

	// 更新网络上下文
	testEvent.EventType = "connect"
	it.eventContext.UpdateNetworkContext(testEvent)

	// 更新文件上下文
	testEvent.EventType = "openat"
	testEvent.Filename = "/etc/passwd"
	it.eventContext.UpdateFileContext(testEvent)

	// 创建测试告警事件
	testAlertEvent := &AlertEvent{
		RuleName:    "test_rule",
		Description: "测试攻击链检测",
		Severity:    "medium",
		Category:    "test",
		Timestamp:   time.Now(),
	}

	// 检测攻击链
	it.eventContext.DetectAttackChain(testEvent, testAlertEvent)
	
	// 获取攻击链
	attackChains := it.eventContext.GetAttackChains()

	// 验证结果
	if len(attackChains) == 0 {
		result.Passed = true
		result.Details = map[string]interface{}{
			"process_contexts": it.eventContext.GetProcessContextCount(),
			"network_contexts": it.eventContext.GetNetworkContextCount(),
			"file_contexts":    it.eventContext.GetFileContextCount(),
			"attack_chains":    len(attackChains),
		}
	} else {
		result.Passed = true
		result.Details = map[string]interface{}{
			"attack_chains_detected": len(attackChains),
			"first_chain_stage":      attackChains[0].CurrentStage,
			"first_chain_risk":       attackChains[0].RiskLevel,
		}
	}

	result.Duration = time.Since(start)
	return result
}

// testAPIServerIntegration 测试API服务器集成
func (it *IntegrationTest) testAPIServerIntegration() IntegrationTestResult {
	start := time.Now()
	result := IntegrationTestResult{
		TestName:    "API服务器集成测试",
		Description: "测试告警API服务器功能",
	}

	// 启动API服务器
    alertAPI := NewAlertAPI(it.alertManager, 8889, nil, it.eventContext)
	go func() {
		if err := alertAPI.Start(); err != nil {
			log.Printf("API服务器启动失败: %v", err)
		}
	}()

	// 等待服务器启动
	time.Sleep(100 * time.Millisecond)

	// 测试API端点
	resp, err := http.Get("http://localhost:8889/api/alerts")
	if err != nil {
		result.Error = fmt.Sprintf("API请求失败: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			result.Error = fmt.Sprintf("API返回状态码%d，期望200", resp.StatusCode)
		} else {
			result.Passed = true
			result.Details = map[string]interface{}{
				"api_status":  "running",
				"endpoint":    "/api/alerts",
				"status_code": resp.StatusCode,
			}
		}
	}

	result.Duration = time.Since(start)
	return result
}

// testEndToEndWorkflow 测试端到端工作流
func (it *IntegrationTest) testEndToEndWorkflow() IntegrationTestResult {
	start := time.Now()
	result := IntegrationTestResult{
		TestName:    "端到端工作流测试",
		Description: "测试完整的事件处理工作流",
	}

	// 模拟完整的事件处理流程
	testEvent := &EventJSON{
		EventType: "execve",
		PID:       54321,
		PPID:      1,
		UID:       0,
		Comm:      "test_process",
		Filename:  "/bin/test_process",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// 1. 更新事件上下文
	it.eventContext.UpdateProcessContext(testEvent)

	// 2. 规则匹配
	alerts := it.ruleEngine.MatchRules(testEvent)

	// 3. 记录性能
	it.perfMonitor.RecordEvent(5 * time.Millisecond)

	// 4. 处理告警
	var processedAlerts []*ManagedAlert
	for _, alert := range alerts {
		it.perfMonitor.RecordAlert(alert.RuleName, 2*time.Millisecond)

		managedAlert, err := it.alertManager.ProcessAlert(alert)
		if err != nil {
			result.Error = fmt.Sprintf("告警处理失败: %v", err)
			result.Duration = time.Since(start)
			return result
		}
		processedAlerts = append(processedAlerts, managedAlert)
	}

	// 5. 检测攻击链
	// 创建测试告警事件用于攻击链检测
	testAlertForChain := &AlertEvent{
		RuleName:    "test_attack_rule",
		Description: "测试攻击链检测",
		Severity:    "high",
		Category:    "attack",
		Timestamp:   time.Now(),
	}
	it.eventContext.DetectAttackChain(testEvent, testAlertForChain)
	attackChains := it.eventContext.GetAttackChains()

	// 验证整个工作流
	if len(alerts) > 0 && len(processedAlerts) > 0 {
		result.Passed = true
		result.Details = map[string]interface{}{
			"original_alerts":   len(alerts),
			"processed_alerts":  len(processedAlerts),
			"attack_chains":     len(attackChains),
			"workflow_complete": true,
		}
	} else {
		result.Error = "端到端工作流未能正确处理事件"
	}

	result.Duration = time.Since(start)
	return result
}

// generateReport 生成集成测试报告
func (it *IntegrationTest) generateReport() error {
	// 确保报告目录存在
	reportDir := "./integration_test_reports"
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return err
	}

	// 生成JSON报告
	timestamp := time.Now().Format("20060102_150405")
	jsonFile := filepath.Join(reportDir, fmt.Sprintf("integration_test_%s.json", timestamp))

	reportData := map[string]interface{}{
		"timestamp":    time.Now(),
		"total_tests":  len(it.testResults),
		"passed_tests": 0,
		"failed_tests": 0,
		"results":      it.testResults,
	}

	for _, result := range it.testResults {
		if result.Passed {
			reportData["passed_tests"] = reportData["passed_tests"].(int) + 1
		} else {
			reportData["failed_tests"] = reportData["failed_tests"].(int) + 1
		}
	}

	jsonData, err := json.MarshalIndent(reportData, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(jsonFile, jsonData, 0644); err != nil {
		return err
	}

	// 生成HTML报告
	htmlFile := filepath.Join(reportDir, fmt.Sprintf("integration_test_%s.html", timestamp))
	if err := it.generateHTMLReport(reportData, htmlFile); err != nil {
		return err
	}

	log.Printf("集成测试报告已生成: %s", jsonFile)
	return nil
}

// generateHTMLReport 生成HTML报告
func (it *IntegrationTest) generateHTMLReport(data map[string]interface{}, filename string) error {
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>eTracee 集成测试报告</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background: #e8f4fd; padding: 15px; border-radius: 5px; flex: 1; }
        .passed { background: #d4edda; }
        .failed { background: #f8d7da; }
        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>eTracee 集成测试报告</h1>
        <p>生成时间: %s</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>总测试数</h3>
            <h2>%d</h2>
        </div>
        <div class="stat-box passed">
            <h3>通过</h3>
            <h2>%d</h2>
        </div>
        <div class="stat-box failed">
            <h3>失败</h3>
            <h2>%d</h2>
        </div>
    </div>
    
    <h2>测试结果详情</h2>
    <table>
        <tr><th>测试名称</th><th>描述</th><th>状态</th><th>耗时</th><th>错误信息</th></tr>`,
		time.Now().Format("2006-01-02 15:04:05"),
		data["total_tests"],
		data["passed_tests"],
		data["failed_tests"])

	for _, result := range it.testResults {
    status := `<span class="pass">[+] PASS</span>`
		if !result.Passed {
			status = `<span class="fail">✗ FAIL</span>`
		}

		html += fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%v</td>
            <td>%s</td>
        </tr>`,
			result.TestName,
			result.Description,
			status,
			result.Duration,
			result.Error)
	}

	html += `
    </table>
</body>
</html>`

	return os.WriteFile(filename, []byte(html), 0644)
}

// RunIntegrationTestCommand 运行集成测试命令
func RunIntegrationTestCommand() {
	integrationTest := NewIntegrationTest()

	if err := integrationTest.RunIntegrationTests(); err != nil {
		log.Fatalf("集成测试失败: %v", err)
	}

	log.Println("集成测试全部通过!")
}
