package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

// TestRunner 测试运行器
type TestRunner struct {
	framework    *RuleTestFramework
	ruleEngine   *EnhancedRuleEngine
	configPath   string
	testDataPath string
	reportPath   string
	verbose      bool
	benchmark    bool
}

// NewTestRunner 创建新的测试运行器
func NewTestRunner() *TestRunner {
	return &TestRunner{
		configPath:   "./config/enhanced_security_config.yaml",
		testDataPath: "./test_data",
		reportPath:   "./test_reports",
		verbose:      false,
		benchmark:    true,
	}
}

// ParseFlags 解析命令行参数
func (tr *TestRunner) ParseFlags() {
	flag.StringVar(&tr.configPath, "config", tr.configPath, "规则配置文件路径")
	flag.StringVar(&tr.testDataPath, "test-data", tr.testDataPath, "测试数据目录路径")
	flag.StringVar(&tr.reportPath, "report", tr.reportPath, "测试报告输出目录")
	flag.BoolVar(&tr.verbose, "verbose", tr.verbose, "详细输出模式")
	flag.BoolVar(&tr.benchmark, "benchmark", tr.benchmark, "启用性能测试")

	// 添加帮助信息
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "eTracee 规则测试工具\n\n")
		fmt.Fprintf(os.Stderr, "用法: %s [选项]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "选项:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n示例:\n")
		fmt.Fprintf(os.Stderr, "  %s -config ./config/rules.yaml -test-data ./tests\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -verbose -benchmark=false\n", os.Args[0])
	}

	flag.Parse()
}

// Initialize 初始化测试运行器
func (tr *TestRunner) Initialize() error {
	log.Println("初始化规则测试框架...")

	// 创建规则引擎
	tr.ruleEngine = NewEnhancedRuleEngine()

	// 加载规则配置
	if _, err := os.Stat(tr.configPath); err == nil {
		if err := loadEnhancedSecurityConfig(tr.configPath, tr.ruleEngine); err != nil {
			log.Printf("加载规则配置失败，使用默认配置: %v", err)
			tr.loadDefaultRules()
		} else {
			log.Printf("已加载规则配置: %s", tr.configPath)
		}
	} else {
		log.Println("配置文件不存在，使用默认规则配置")
		tr.loadDefaultRules()
	}

	// 创建测试框架
	tr.framework = NewRuleTestFramework(tr.ruleEngine)
	tr.framework.config.TestDataPath = tr.testDataPath
	tr.framework.config.ReportPath = tr.reportPath
	tr.framework.config.EnableBenchmark = tr.benchmark

	// 加载测试套件
	if err := tr.framework.LoadTestSuites(); err != nil {
		return fmt.Errorf("加载测试套件失败: %v", err)
	}

	return nil
}

// loadDefaultRules 加载默认规则
func (tr *TestRunner) loadDefaultRules() {
	// 添加一些基本的测试规则
	tr.ruleEngine.AddRule(&EnhancedRule{
		ID:          "suspicious_process",
		Name:        "可疑进程检测",
		Description: "检测可疑的进程执行",
		Category:    "process",
		Severity:    "high",
		Enabled:     true,
		Conditions: []RuleCondition{
			{
				Field:    "event_type",
				Operator: "equals",
				Value:    "execve",
			},
			{
				Field:    "comm",
				Operator: "in",
				Value:    []string{"nc", "netcat", "ncat", "socat", "telnet"},
			},
		},
		Actions: []RuleAction{
			{Type: "log", Config: map[string]interface{}{"level": "warn"}},
			{Type: "alert", Config: map[string]interface{}{"severity": "high"}},
		},
		Metadata: map[string]interface{}{
			"mitre_attack": []string{"T1059"},
			"references":   []string{"https://attack.mitre.org/techniques/T1059/"},
		},
	})

	tr.ruleEngine.AddRule(&EnhancedRule{
		ID:          "suspicious_network",
		Name:        "可疑网络连接",
		Description: "检测可疑的网络连接",
		Category:    "network",
		Severity:    "critical",
		Enabled:     true,
		Conditions: []RuleCondition{
			{
				Field:    "event_type",
				Operator: "equals",
				Value:    "connect",
			},
			{
				Field:    "dst_addr.port",
				Operator: "in",
				Value:    []int{4444, 4445, 1234, 31337},
			},
		},
		Actions: []RuleAction{
			{Type: "log", Config: map[string]interface{}{"level": "error"}},
			{Type: "alert", Config: map[string]interface{}{"severity": "critical"}},
			{Type: "block", Config: map[string]interface{}{"duration": 3600}},
		},
		Metadata: map[string]interface{}{
			"mitre_attack": []string{"T1071"},
			"references":   []string{"https://attack.mitre.org/techniques/T1071/"},
		},
	})

	tr.ruleEngine.AddRule(&EnhancedRule{
		ID:          "sensitive_file_access",
		Name:        "敏感文件访问",
		Description: "检测对敏感文件的访问",
		Category:    "file",
		Severity:    "medium",
		Enabled:     true,
		Conditions: []RuleCondition{
			{
				Field:    "event_type",
				Operator: "equals",
				Value:    "openat",
			},
			{
				Field:    "filename",
				Operator: "contains",
				Value:    []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers"},
			},
		},
		Actions: []RuleAction{
			{Type: "log", Config: map[string]interface{}{"level": "warn"}},
			{Type: "alert", Config: map[string]interface{}{"severity": "medium"}},
		},
		Metadata: map[string]interface{}{
			"mitre_attack": []string{"T1005"},
			"references":   []string{"https://attack.mitre.org/techniques/T1005/"},
		},
	})

	log.Printf("已加载 %d 个默认规则", len(tr.ruleEngine.Rules))
}

// Run 运行测试
func (tr *TestRunner) Run() error {
	log.Println("开始运行规则引擎测试...")

	// 运行测试
	report, err := tr.framework.RunTests()
	if err != nil {
		return fmt.Errorf("运行测试失败: %v", err)
	}

	// 打印摘要
	tr.framework.PrintSummary(report)

	// 详细输出
	if tr.verbose {
		tr.printDetailedResults(report)
	}

	// 检查测试结果
	if report.FailedTests > 0 {
		log.Printf("警告: %d 个测试失败", report.FailedTests)
		return fmt.Errorf("存在失败的测试用例")
	}

	log.Println("所有测试通过!")
	return nil
}

// printDetailedResults 打印详细结果
func (tr *TestRunner) printDetailedResults(report *TestReport) {
	fmt.Println("\n详细测试结果:")
	fmt.Println(strings.Repeat("-", 80))

	for _, result := range tr.framework.results {
    status := "[+] PASS"
		if !result.Passed {
			status = "✗ FAIL"
		}

		fmt.Printf("[%s] %s - %s (耗时: %v)\n",
			status, result.TestCase.ID, result.TestCase.Name, result.ExecutionTime)

		if tr.verbose && !result.Passed {
			fmt.Printf("  期望: 触发=%v, 规则=%v, 严重级别=%s\n",
				result.TestCase.Expected.ShouldTrigger,
				result.TestCase.Expected.RuleNames,
				result.TestCase.Expected.Severity)

			fmt.Printf("  实际: 告警数=%d\n", len(result.ActualAlerts))
			for _, alert := range result.ActualAlerts {
				fmt.Printf("    - 规则: %s, 严重级别: %s\n", alert.RuleName, alert.Severity)
			}

			if result.ErrorMessage != "" {
				fmt.Printf("  错误: %s\n", result.ErrorMessage)
			}
		}
	}
}

// RunTestCommand 运行测试命令
func RunTestCommand() {
	runner := NewTestRunner()
	runner.ParseFlags()

	if err := runner.Initialize(); err != nil {
		log.Fatalf("初始化失败: %v", err)
	}

	if err := runner.Run(); err != nil {
		log.Fatalf("测试失败: %v", err)
	}
}

// 如果直接运行此文件，则执行测试
func init() {
	// 检查是否直接运行测试
	if len(os.Args) > 1 && os.Args[1] == "test" {
		// 移除 "test" 参数
		os.Args = append(os.Args[:1], os.Args[2:]...)
		RunTestCommand()
		os.Exit(0)
	}
}
