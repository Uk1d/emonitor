package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TestCase 表示一个测试用例
type TestCase struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Event       *EventJSON   `json:"event"`
	Expected    TestExpected `json:"expected"`
	Category    string       `json:"category"`
	Severity    string       `json:"severity"`
}

// TestExpected 表示期望的测试结果
type TestExpected struct {
	ShouldTrigger bool     `json:"should_trigger"`
	RuleNames     []string `json:"rule_names"`
	Severity      string   `json:"severity"`
	AlertCount    int      `json:"alert_count"`
}

// TestResult 表示测试结果
type TestResult struct {
	TestCase      *TestCase     `json:"test_case"`
	Passed        bool          `json:"passed"`
	ActualAlerts  []*AlertEvent `json:"actual_alerts"`
	ExecutionTime time.Duration `json:"execution_time"`
	ErrorMessage  string        `json:"error_message,omitempty"`
}

// TestSuite 表示测试套件
type TestSuite struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	TestCases   []*TestCase `json:"test_cases"`
}

// RuleTestFramework 规则测试框架
type RuleTestFramework struct {
	ruleEngine *EnhancedRuleEngine
	testSuites []*TestSuite
	results    []*TestResult
	mutex      sync.RWMutex
	config     *TestFrameworkConfig
}

// TestFrameworkConfig 测试框架配置
type TestFrameworkConfig struct {
	TestDataPath    string        `json:"test_data_path"`
	ReportPath      string        `json:"report_path"`
	Timeout         time.Duration `json:"timeout"`
	ParallelTests   int           `json:"parallel_tests"`
	EnableBenchmark bool          `json:"enable_benchmark"`
	BenchmarkRounds int           `json:"benchmark_rounds"`
}

// TestReport 测试报告
type TestReport struct {
	Timestamp      time.Time                `json:"timestamp"`
	TotalTests     int                      `json:"total_tests"`
	PassedTests    int                      `json:"passed_tests"`
	FailedTests    int                      `json:"failed_tests"`
	PassRate       float64                  `json:"pass_rate"`
	TotalTime      time.Duration            `json:"total_time"`
	AverageTime    time.Duration            `json:"average_time"`
	CategoryStats  map[string]*CategoryStat `json:"category_stats"`
	FailedCases    []*TestResult            `json:"failed_cases"`
	BenchmarkStats *BenchmarkStats          `json:"benchmark_stats,omitempty"`
}

// CategoryStat 分类统计
type CategoryStat struct {
	Total    int     `json:"total"`
	Passed   int     `json:"passed"`
	Failed   int     `json:"failed"`
	PassRate float64 `json:"pass_rate"`
}

// BenchmarkStats 性能测试统计
type BenchmarkStats struct {
	MinTime    time.Duration `json:"min_time"`
	MaxTime    time.Duration `json:"max_time"`
	AvgTime    time.Duration `json:"avg_time"`
	MedianTime time.Duration `json:"median_time"`
	TotalOps   int           `json:"total_ops"`
	OpsPerSec  float64       `json:"ops_per_sec"`
}

// NewRuleTestFramework 创建新的规则测试框架
func NewRuleTestFramework(ruleEngine *EnhancedRuleEngine) *RuleTestFramework {
	config := &TestFrameworkConfig{
		TestDataPath:    "./test_data",
		ReportPath:      "./test_reports",
		Timeout:         30 * time.Second,
		ParallelTests:   4,
		EnableBenchmark: true,
		BenchmarkRounds: 1000,
	}

	return &RuleTestFramework{
		ruleEngine: ruleEngine,
		testSuites: make([]*TestSuite, 0),
		results:    make([]*TestResult, 0),
		config:     config,
	}
}

// LoadTestSuites 加载测试套件
func (rtf *RuleTestFramework) LoadTestSuites() error {
	rtf.mutex.Lock()
	defer rtf.mutex.Unlock()

	// 确保测试数据目录存在
	if err := os.MkdirAll(rtf.config.TestDataPath, 0755); err != nil {
		return fmt.Errorf("创建测试数据目录失败: %v", err)
	}

	// 创建默认测试套件
	if err := rtf.createDefaultTestSuites(); err != nil {
		return fmt.Errorf("创建默认测试套件失败: %v", err)
	}

	// 扫描测试数据目录
	return filepath.Walk(rtf.config.TestDataPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("读取测试文件失败 %s: %v", path, err)
			return nil
		}

		var suite TestSuite
		if err := json.Unmarshal(data, &suite); err != nil {
			log.Printf("解析测试文件失败 %s: %v", path, err)
			return nil
		}

		rtf.testSuites = append(rtf.testSuites, &suite)
		log.Printf("加载测试套件: %s (%d个测试用例)", suite.Name, len(suite.TestCases))
		return nil
	})
}

// createDefaultTestSuites 创建默认测试套件
func (rtf *RuleTestFramework) createDefaultTestSuites() error {
	// 进程执行测试套件
	processTestSuite := &TestSuite{
		Name:        "进程执行检测测试",
		Description: "测试进程执行相关的安全规则",
		TestCases: []*TestCase{
			{
				ID:          "proc_001",
				Name:        "可疑进程执行",
				Description: "检测可疑进程执行",
				Event: &EventJSON{
					EventType: "execve",
					PID:       1234,
					PPID:      1,
					UID:       0,
					Comm:      "nc",
					Filename:  "/bin/nc",
				},
				Expected: TestExpected{
					ShouldTrigger: true,
					RuleNames:     []string{"suspicious_process"},
					Severity:      "high",
					AlertCount:    1,
				},
				Category: "process",
				Severity: "high",
			},
			{
				ID:          "proc_002",
				Name:        "正常进程执行",
				Description: "测试正常进程不应触发告警",
				Event: &EventJSON{
					EventType: "execve",
					PID:       1235,
					PPID:      1000,
					UID:       1000,
					Comm:      "ls",
					Filename:  "/bin/ls",
				},
				Expected: TestExpected{
					ShouldTrigger: false,
					RuleNames:     []string{},
					AlertCount:    0,
				},
				Category: "process",
				Severity: "low",
			},
		},
	}

	// 网络连接测试套件
	networkTestSuite := &TestSuite{
		Name:        "网络连接检测测试",
		Description: "测试网络连接相关的安全规则",
		TestCases: []*TestCase{
			{
				ID:          "net_001",
				Name:        "可疑外连",
				Description: "检测可疑的外部连接",
				Event: &EventJSON{
					EventType: "connect",
					PID:       1236,
					UID:       0,
					Comm:      "malware",
					DstAddr: &AddrJSON{
						IP:   "192.168.1.100",
						Port: 4444,
					},
				},
				Expected: TestExpected{
					ShouldTrigger: true,
					RuleNames:     []string{"suspicious_network"},
					Severity:      "critical",
					AlertCount:    1,
				},
				Category: "network",
				Severity: "critical",
			},
		},
	}

	// 文件操作测试套件
	fileTestSuite := &TestSuite{
		Name:        "文件操作检测测试",
		Description: "测试文件操作相关的安全规则",
		TestCases: []*TestCase{
			{
				ID:          "file_001",
				Name:        "敏感文件访问",
				Description: "检测对敏感文件的访问",
				Event: &EventJSON{
					EventType: "openat",
					PID:       1237,
					UID:       1000,
					Comm:      "cat",
					Filename:  "/etc/passwd",
				},
				Expected: TestExpected{
					ShouldTrigger: true,
					RuleNames:     []string{"sensitive_file_access"},
					Severity:      "medium",
					AlertCount:    1,
				},
				Category: "file",
				Severity: "medium",
			},
		},
	}

	// 保存测试套件到文件
	testSuites := []*TestSuite{processTestSuite, networkTestSuite, fileTestSuite}
	for _, suite := range testSuites {
		data, err := json.MarshalIndent(suite, "", "  ")
		if err != nil {
			return err
		}

		filename := filepath.Join(rtf.config.TestDataPath, fmt.Sprintf("%s.json",
			strings.ReplaceAll(strings.ToLower(suite.Name), " ", "_")))
		if err := os.WriteFile(filename, data, 0644); err != nil {
			return err
		}
	}

	return nil
}

// RunTests 运行所有测试
func (rtf *RuleTestFramework) RunTests() (*TestReport, error) {
	rtf.mutex.Lock()
	defer rtf.mutex.Unlock()

	startTime := time.Now()
	rtf.results = make([]*TestResult, 0)

	log.Println("开始运行规则测试...")

	// 收集所有测试用例
	var allTestCases []*TestCase
	for _, suite := range rtf.testSuites {
		allTestCases = append(allTestCases, suite.TestCases...)
	}

	// 并行运行测试
	testChan := make(chan *TestCase, len(allTestCases))
	resultChan := make(chan *TestResult, len(allTestCases))

	// 启动工作协程
	for i := 0; i < rtf.config.ParallelTests; i++ {
		go rtf.testWorker(testChan, resultChan)
	}

	// 发送测试用例
	for _, testCase := range allTestCases {
		testChan <- testCase
	}
	close(testChan)

	// 收集结果
	for i := 0; i < len(allTestCases); i++ {
		result := <-resultChan
		rtf.results = append(rtf.results, result)
	}

	totalTime := time.Since(startTime)

	// 生成报告
	report := rtf.generateReport(totalTime)

	// 运行性能测试
	if rtf.config.EnableBenchmark {
		benchmarkStats, err := rtf.runBenchmark()
		if err != nil {
			log.Printf("性能测试失败: %v", err)
		} else {
			report.BenchmarkStats = benchmarkStats
		}
	}

	// 保存报告
	if err := rtf.saveReport(report); err != nil {
		log.Printf("保存测试报告失败: %v", err)
	}

	log.Printf("测试完成: %d/%d 通过 (%.2f%%), 耗时: %v",
		report.PassedTests, report.TotalTests, report.PassRate, report.TotalTime)

	return report, nil
}

// testWorker 测试工作协程
func (rtf *RuleTestFramework) testWorker(testChan <-chan *TestCase, resultChan chan<- *TestResult) {
	for testCase := range testChan {
		result := rtf.runSingleTest(testCase)
		resultChan <- result
	}
}

// runSingleTest 运行单个测试
func (rtf *RuleTestFramework) runSingleTest(testCase *TestCase) *TestResult {
	startTime := time.Now()

	result := &TestResult{
		TestCase:      testCase,
		ActualAlerts:  make([]*AlertEvent, 0),
		ExecutionTime: 0,
	}

	// 设置超时
	done := make(chan bool, 1)
	go func() {
		// 运行规则匹配
		alerts := rtf.ruleEngine.MatchRules(testCase.Event)
		
		// 转换 []AlertEvent 到 []*AlertEvent
		alertPointers := make([]*AlertEvent, len(alerts))
		for i := range alerts {
			alertPointers[i] = &alerts[i]
		}
		
		result.ActualAlerts = alertPointers
		result.ExecutionTime = time.Since(startTime)

		// 验证结果
		result.Passed = rtf.validateResult(testCase, alertPointers)
		done <- true
	}()

	select {
	case <-done:
		// 测试完成
	case <-time.After(rtf.config.Timeout):
		result.ErrorMessage = "测试超时"
		result.Passed = false
		result.ExecutionTime = rtf.config.Timeout
	}

	return result
}

// validateResult 验证测试结果
func (rtf *RuleTestFramework) validateResult(testCase *TestCase, actualAlerts []*AlertEvent) bool {
	expected := testCase.Expected

	// 检查是否应该触发告警
	if expected.ShouldTrigger && len(actualAlerts) == 0 {
		return false
	}
	if !expected.ShouldTrigger && len(actualAlerts) > 0 {
		return false
	}

	// 检查告警数量
	if expected.AlertCount > 0 && len(actualAlerts) != expected.AlertCount {
		return false
	}

	// 检查规则名称
	if len(expected.RuleNames) > 0 {
		actualRuleNames := make(map[string]bool)
		for _, alert := range actualAlerts {
			actualRuleNames[alert.RuleName] = true
		}

		for _, expectedRule := range expected.RuleNames {
			if !actualRuleNames[expectedRule] {
				return false
			}
		}
	}

	// 检查严重级别
	if expected.Severity != "" && len(actualAlerts) > 0 {
		for _, alert := range actualAlerts {
			if alert.Severity != expected.Severity {
				return false
			}
		}
	}

	return true
}

// runBenchmark 运行性能测试
func (rtf *RuleTestFramework) runBenchmark() (*BenchmarkStats, error) {
	if len(rtf.testSuites) == 0 {
		return nil, fmt.Errorf("没有可用的测试套件")
	}

	log.Println("开始性能测试...")

	// 选择第一个测试用例进行性能测试
	var testEvent *EventJSON
	for _, suite := range rtf.testSuites {
		if len(suite.TestCases) > 0 {
			testEvent = suite.TestCases[0].Event
			break
		}
	}

	if testEvent == nil {
		return nil, fmt.Errorf("没有可用的测试事件")
	}

	times := make([]time.Duration, rtf.config.BenchmarkRounds)
	startTime := time.Now()

	for i := 0; i < rtf.config.BenchmarkRounds; i++ {
		roundStart := time.Now()
		rtf.ruleEngine.MatchRules(testEvent)
		times[i] = time.Since(roundStart)
	}

	totalTime := time.Since(startTime)

	// 计算统计信息
	stats := &BenchmarkStats{
		TotalOps:  rtf.config.BenchmarkRounds,
		OpsPerSec: float64(rtf.config.BenchmarkRounds) / totalTime.Seconds(),
	}

	// 计算最小、最大、平均时间
	stats.MinTime = times[0]
	stats.MaxTime = times[0]
	var totalDuration time.Duration

	for _, t := range times {
		if t < stats.MinTime {
			stats.MinTime = t
		}
		if t > stats.MaxTime {
			stats.MaxTime = t
		}
		totalDuration += t
	}

	stats.AvgTime = totalDuration / time.Duration(len(times))

	log.Printf("性能测试完成: %d次操作, 平均耗时: %v, QPS: %.2f",
		stats.TotalOps, stats.AvgTime, stats.OpsPerSec)

	return stats, nil
}

// generateReport 生成测试报告
func (rtf *RuleTestFramework) generateReport(totalTime time.Duration) *TestReport {
	report := &TestReport{
		Timestamp:     time.Now(),
		TotalTests:    len(rtf.results),
		PassedTests:   0,
		FailedTests:   0,
		TotalTime:     totalTime,
		CategoryStats: make(map[string]*CategoryStat),
		FailedCases:   make([]*TestResult, 0),
	}

	// 统计结果
	for _, result := range rtf.results {
		if result.Passed {
			report.PassedTests++
		} else {
			report.FailedTests++
			report.FailedCases = append(report.FailedCases, result)
		}

		// 分类统计
		category := result.TestCase.Category
		if report.CategoryStats[category] == nil {
			report.CategoryStats[category] = &CategoryStat{}
		}
		report.CategoryStats[category].Total++
		if result.Passed {
			report.CategoryStats[category].Passed++
		} else {
			report.CategoryStats[category].Failed++
		}
	}

	// 计算通过率
	if report.TotalTests > 0 {
		report.PassRate = float64(report.PassedTests) / float64(report.TotalTests) * 100
		report.AverageTime = totalTime / time.Duration(report.TotalTests)
	}

	// 计算分类通过率
	for _, stat := range report.CategoryStats {
		if stat.Total > 0 {
			stat.PassRate = float64(stat.Passed) / float64(stat.Total) * 100
		}
	}

	return report
}

// saveReport 保存测试报告
func (rtf *RuleTestFramework) saveReport(report *TestReport) error {
	// 确保报告目录存在
	if err := os.MkdirAll(rtf.config.ReportPath, 0755); err != nil {
		return err
	}

	// 生成报告文件名
	timestamp := report.Timestamp.Format("20060102_150405")
	filename := filepath.Join(rtf.config.ReportPath, fmt.Sprintf("test_report_%s.json", timestamp))

	// 保存JSON报告
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return err
	}

	// 生成HTML报告
	htmlFilename := filepath.Join(rtf.config.ReportPath, fmt.Sprintf("test_report_%s.html", timestamp))
	if err := rtf.generateHTMLReport(report, htmlFilename); err != nil {
		log.Printf("生成HTML报告失败: %v", err)
	}

	log.Printf("测试报告已保存: %s", filename)
	return nil
}

// generateHTMLReport 生成HTML测试报告
func (rtf *RuleTestFramework) generateHTMLReport(report *TestReport, filename string) error {
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>规则引擎测试报告</title>
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
        .pass { color: green; }
        .fail { color: red; }
    </style>
</head>
<body>
    <div class="header">
        <h1>规则引擎测试报告</h1>
        <p>生成时间: %s</p>
        <p>总耗时: %v</p>
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
        <div class="stat-box">
            <h3>通过率</h3>
            <h2>%.2f%%</h2>
        </div>
    </div>
    
    <h2>分类统计</h2>
    <table>
        <tr><th>分类</th><th>总数</th><th>通过</th><th>失败</th><th>通过率</th></tr>`,
		report.Timestamp.Format("2006-01-02 15:04:05"),
		report.TotalTime,
		report.TotalTests,
		report.PassedTests,
		report.FailedTests,
		report.PassRate)

	for category, stat := range report.CategoryStats {
		html += fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td>%d</td>
            <td>%d</td>
            <td>%d</td>
            <td>%.2f%%</td>
        </tr>`, category, stat.Total, stat.Passed, stat.Failed, stat.PassRate)
	}

	html += `
    </table>
    
    <h2>失败的测试用例</h2>
    <table>
        <tr><th>ID</th><th>名称</th><th>分类</th><th>错误信息</th><th>执行时间</th></tr>`

	for _, failedCase := range report.FailedCases {
		html += fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%v</td>
        </tr>`,
			failedCase.TestCase.ID,
			failedCase.TestCase.Name,
			failedCase.TestCase.Category,
			failedCase.ErrorMessage,
			failedCase.ExecutionTime)
	}

	if report.BenchmarkStats != nil {
		html += fmt.Sprintf(`
    </table>
    
    <h2>性能测试结果</h2>
    <div class="stats">
        <div class="stat-box">
            <h3>平均耗时</h3>
            <h2>%v</h2>
        </div>
        <div class="stat-box">
            <h3>最小耗时</h3>
            <h2>%v</h2>
        </div>
        <div class="stat-box">
            <h3>最大耗时</h3>
            <h2>%v</h2>
        </div>
        <div class="stat-box">
            <h3>QPS</h3>
            <h2>%.2f</h2>
        </div>
    </div>`,
			report.BenchmarkStats.AvgTime,
			report.BenchmarkStats.MinTime,
			report.BenchmarkStats.MaxTime,
			report.BenchmarkStats.OpsPerSec)
	}

	html += `
</body>
</html>`

	return os.WriteFile(filename, []byte(html), 0644)
}

// PrintSummary 打印测试摘要
func (rtf *RuleTestFramework) PrintSummary(report *TestReport) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("规则引擎测试报告摘要")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("测试时间: %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("总测试数: %d\n", report.TotalTests)
	fmt.Printf("通过: %d\n", report.PassedTests)
	fmt.Printf("失败: %d\n", report.FailedTests)
	fmt.Printf("通过率: %.2f%%\n", report.PassRate)
	fmt.Printf("总耗时: %v\n", report.TotalTime)
	fmt.Printf("平均耗时: %v\n", report.AverageTime)

	if len(report.CategoryStats) > 0 {
		fmt.Println("\n分类统计:")
		for category, stat := range report.CategoryStats {
			fmt.Printf("  %s: %d/%d (%.2f%%)\n",
				category, stat.Passed, stat.Total, stat.PassRate)
		}
	}

	if report.BenchmarkStats != nil {
		fmt.Println("\n性能测试:")
		fmt.Printf("  平均耗时: %v\n", report.BenchmarkStats.AvgTime)
		fmt.Printf("  QPS: %.2f\n", report.BenchmarkStats.OpsPerSec)
	}

	if len(report.FailedCases) > 0 {
		fmt.Printf("\n失败的测试用例 (%d个):\n", len(report.FailedCases))
		for _, failedCase := range report.FailedCases {
			fmt.Printf("  - %s: %s\n", failedCase.TestCase.ID, failedCase.TestCase.Name)
			if failedCase.ErrorMessage != "" {
				fmt.Printf("    错误: %s\n", failedCase.ErrorMessage)
			}
		}
	}

	fmt.Println(strings.Repeat("=", 60))
}
