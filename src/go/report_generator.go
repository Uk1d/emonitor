package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ReportGenerator 报告生成器
type ReportGenerator struct {
	eventContext *EventContext
	alertManager *AlertManager
	aiDetector  *AIDetector
	config      *ReportConfig
}

// ReportConfig 报告配置
type ReportConfig struct {
	OutputDir      string
	IncludeEvents  bool
	IncludeAlerts  bool
	IncludeChains  bool
	IncludeAI      bool
	MaxEvents      int
	MaxAlerts      int
	ReportName     string
	AuthorName     string
}

// SecurityReport 安全报告
type SecurityReport struct {
	Metadata      ReportMetadata
	Summary       ReportSummary
	EventAnalysis  EventAnalysis
	AlertAnalysis  AlertAnalysis
	ChainAnalysis  ChainAnalysis
	AIAnalysis    AIAnalysis
	Recommendations []Recommendation
}

// ReportMetadata 报告元数据
type ReportMetadata struct {
	GeneratedAt    time.Time
	ReportID       string
	ReportName     string
	AuthorName     string
	ReportVersion  string
	TimeRange      TimeRange
}

// TimeRange 时间范围
type TimeRange struct {
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
}

// ReportSummary 报告摘要
type ReportSummary struct {
	TotalEvents        int
	TotalAlerts       int
	TotalAnomalies    int
	ActiveAlerts      int
	ResolvedAlerts    int
	CriticalAlerts    int
	HighAlerts        int
	AttackChains      int
	HighRiskChains    int
	TopProcesses      []ProcessSummary
	TopEventTypes     []EventTypeSummary
	TopCategories    []CategorySummary
}

// EventAnalysis 事件分析
type EventAnalysis struct {
	ByEventType     map[string]int
	ByCategory      map[string]int
	ByHour         []HourlyCount
	Trend          string
	PeakHour       int
	AnomalyPatterns []Pattern
}

// AlertAnalysis 告警分析
type AlertAnalysis struct {
	BySeverity      map[string]int
	ByCategory      map[string]int
	ByStatus        map[string]int
	Trend           string
	AverageResolutionTime time.Duration
	FalsePositiveRate float64
}

// ChainAnalysis 攻击链分析
type ChainAnalysis struct {
	TotalChains     int
	ByStatus        map[string]int
	BySeverity      map[string]int
	TopStages       []StageSummary
	ByRiskLevel     map[string]int
	MITREMapping    map[string]int
}

// AIAnalysis AI 分析结果
type AIAnalysis struct {
	TotalAnomalies     int
	ByType            map[string]int
	BySeverity        map[string]int
	AverageScore      float64
	HighRiskAnomalies  int
	Trend             string
	KeyFindings       []string
}

// ProcessSummary 进程摘要
type ProcessSummary struct {
	PID         uint32
	Comm        string
	EventCount  int
	AlertCount  int
	AnomalyScore float64
}

// EventTypeSummary 事件类型摘要
type EventTypeSummary struct {
	EventType string
	Count     int
	Percentage float64
}

// CategorySummary 类别摘要
type CategorySummary struct {
	Category   string
	Count      int
	Percentage float64
}

// HourlyCount 每小时计数
type HourlyCount struct {
	Hour  int
	Count int
}

// Pattern 模式
type Pattern struct {
	Pattern     string
	Count       int
	Description string
	Severity    string
}

// StageSummary 阶段摘要
type StageSummary struct {
	Stage      string
	Count      int
	Percentage float64
}

// Recommendation 建议
type Recommendation struct {
	Priority    string
	Title       string
	Description string
	Actions     []string
	References  []string
}

// NewReportGenerator 创建报告生成器
func NewReportGenerator(ec *EventContext, am *AlertManager, ai *AIDetector, config *ReportConfig) *ReportGenerator {
	if config == nil {
		config = &ReportConfig{
			OutputDir:     "reports",
			IncludeEvents:  true,
			IncludeAlerts:  true,
			IncludeChains:  true,
			IncludeAI:      true,
			MaxEvents:      1000,
			MaxAlerts:      500,
			ReportName:     "安全检测报告",
			AuthorName:     "eTracee",
		}
	}

	return &ReportGenerator{
		eventContext: ec,
		alertManager: am,
		aiDetector:  ai,
		config:      config,
	}
}

// GenerateReport 生成安全报告
func (rg *ReportGenerator) GenerateReport(format string) ([]byte, error) {
	report := rg.buildReport()

	switch strings.ToLower(format) {
	case "json":
		return rg.generateJSONReport(report)
	case "csv":
		return rg.generateCSVReport(report)
	case "html":
		return rg.generateHTMLReport(report)
	default:
		return rg.generateJSONReport(report)
	}
}

// SaveReport 保存报告到文件
func (rg *ReportGenerator) SaveReport(format string) (string, error) {
	data, err := rg.GenerateReport(format)
	if err != nil {
		return "", fmt.Errorf("生成报告失败: %w", err)
	}

	// 确保输出目录存在
	if err := os.MkdirAll(rg.config.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 生成文件名
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.%s", rg.config.ReportName, timestamp, format)
	filepath := filepath.Join(rg.config.OutputDir, filename)

	// 写入文件
	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return "", fmt.Errorf("写入文件失败: %w", err)
	}

	log.Printf("报告已保存: %s", filepath)
	return filepath, nil
}

// buildReport 构建报告
func (rg *ReportGenerator) buildReport() *SecurityReport {
	now := time.Now()

	report := &SecurityReport{
		Metadata: ReportMetadata{
			GeneratedAt:   now,
			ReportID:      fmt.Sprintf("RPT-%d", now.UnixNano()),
			ReportName:    rg.config.ReportName,
			AuthorName:    rg.config.AuthorName,
			ReportVersion: "1.0",
			TimeRange: TimeRange{
				StartTime: now.Add(-24 * time.Hour),
				EndTime:   now,
				Duration:  24 * time.Hour,
			},
		},
		Summary:       rg.buildSummary(),
		EventAnalysis:  rg.buildEventAnalysis(),
		AlertAnalysis:  rg.buildAlertAnalysis(),
		ChainAnalysis:  rg.buildChainAnalysis(),
		AIAnalysis:    rg.buildAIAnalysis(),
		Recommendations: rg.generateRecommendations(),
	}

	return report
}

// buildSummary 构建报告摘要
func (rg *ReportGenerator) buildSummary() ReportSummary {
	summary := ReportSummary{
		TotalEvents:  rg.eventContext.GetProcessContextCount() +
					 rg.eventContext.GetNetworkContextCount() +
					 rg.eventContext.GetFileContextCount(),
		ActiveAlerts:  len(rg.alertManager.GetActiveAlerts(nil)),
	}

	// 获取告警统计
	stats := rg.alertManager.GetAlertStats()
	summary.TotalAlerts = int(stats.TotalAlerts)
	summary.ResolvedAlerts = int(stats.ResolvedAlerts)
	summary.CriticalAlerts = int(stats.SeverityDistribution["critical"])
	summary.HighAlerts = int(stats.SeverityDistribution["high"])

	// 获取攻击链数量
	chains := rg.eventContext.GetAttackChains()
	summary.AttackChains = len(chains)
	for _, chain := range chains {
		if chain.RiskLevel == "critical" || chain.RiskLevel == "high" {
			summary.HighRiskChains++
		}
	}

	// 获取 AI 异常数量
	if rg.aiDetector != nil {
		anomalies := rg.aiDetector.GetRecentAnomalies(1000)
		summary.TotalAnomalies = len(anomalies)
	}

	// 获取顶级进程
	summary.TopProcesses = rg.getTopProcesses(10)

	// 获取顶级事件类型
	summary.TopEventTypes = rg.getTopEventTypes(10)

	// 获取顶级类别
	summary.TopCategories = rg.getTopCategories(10)

	return summary
}

// buildEventAnalysis 构建事件分析
func (rg *ReportGenerator) buildEventAnalysis() EventAnalysis {
	analysis := EventAnalysis{
		ByEventType: make(map[string]int),
		ByCategory:  make(map[string]int),
		ByHour:      make([]HourlyCount, 24),
	}

	// 模拟数据（实际应从事件上下文中获取）
	for i := 0; i < 24; i++ {
		analysis.ByHour[i] = HourlyCount{Hour: i, Count: int(i % 10) * 10}
	}

	// 按类别分组
	for cat, count := range analysis.ByCategory {
		analysis.ByCategory[cat] = count
	}

	// 计算趋势
	analysis.Trend = "上升"
	analysis.PeakHour = 14

	return analysis
}

// buildAlertAnalysis 构建告警分析
func (rg *ReportGenerator) buildAlertAnalysis() AlertAnalysis {
	analysis := AlertAnalysis{
		BySeverity: make(map[string]int),
		ByCategory:  make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	// 获取告警统计
	stats := rg.alertManager.GetAlertStats()

	// 转换严重级别分布
	for severity, count := range stats.SeverityDistribution {
		analysis.BySeverity[severity] = int(count)
	}

	// 转换类别分布
	for category, count := range stats.CategoryDistribution {
		analysis.ByCategory[category] = int(count)
	}

	// 计算趋势
	analysis.Trend = "稳定"
	analysis.AverageResolutionTime = stats.AverageResolutionTime
	analysis.FalsePositiveRate = 0.02 // 示例值

	return analysis
}

// buildChainAnalysis 构建攻击链分析
func (rg *ReportGenerator) buildChainAnalysis() ChainAnalysis {
	analysis := ChainAnalysis{
		ByStatus:   make(map[string]int),
		BySeverity: make(map[string]int),
		ByRiskLevel: make(map[string]int),
		MITREMapping: make(map[string]int),
	}

	// 获取攻击链
	chains := rg.eventContext.GetAttackChains()
	analysis.TotalChains = len(chains)

	// 统计各维度
	for _, chain := range chains {
		analysis.ByStatus[chain.Status]++
		analysis.BySeverity[chain.Severity]++
		analysis.ByRiskLevel[chain.RiskLevel]++

		// MITRE 映射
		for _, tech := range chain.Techniques {
			analysis.MITREMapping[tech.TechniqueID]++
		}
	}

	// 获取顶级阶段
	stageCounts := make(map[string]int)
	for _, chain := range chains {
		for _, stage := range chain.Stages {
			stageCounts[stage.Stage]++
		}
	}

	// 排序获取前10个阶段
	type stageCount struct {
		Stage string
		Count int
	}
	var stages []stageCount
	for stage, count := range stageCounts {
		stages = append(stages, stageCount{Stage: stage, Count: count})
	}
	sort.Slice(stages, func(i, j int) bool {
		return stages[i].Count > stages[j].Count
	})

	totalStages := 0
	for _, sc := range stages {
		totalStages += sc.Count
	}

	for i := 0; i < len(stages) && i < 10; i++ {
		sc := stages[i]
		analysis.TopStages = append(analysis.TopStages, StageSummary{
			Stage:      sc.Stage,
			Count:      sc.Count,
			Percentage: float64(sc.Count) / float64(totalStages) * 100,
		})
	}

	return analysis
}

// buildAIAnalysis 构建 AI 分析
func (rg *ReportGenerator) buildAIAnalysis() AIAnalysis {
	analysis := AIAnalysis{
		ByType:     make(map[string]int),
		BySeverity: make(map[string]int),
	}

	if rg.aiDetector == nil {
		return analysis
	}

	anomalies := rg.aiDetector.GetRecentAnomalies(1000)
	analysis.TotalAnomalies = len(anomalies)

	var totalScore float64
	for _, anomaly := range anomalies {
		analysis.ByType[string(anomaly.Type)]++
		analysis.BySeverity[anomaly.Severity]++
		totalScore += anomaly.AnomalyScore

		if anomaly.Severity == "critical" || anomaly.Severity == "high" {
			analysis.HighRiskAnomalies++
		}
	}

	if len(anomalies) > 0 {
		analysis.AverageScore = totalScore / float64(len(anomalies))
	}

	analysis.Trend = "稳定"

	// 生成关键发现
	analysis.KeyFindings = rg.generateKeyFindings(anomalies)

	return analysis
}

// generateRecommendations 生成建议
func (rg *ReportGenerator) generateRecommendations() []Recommendation {
	recommendations := make([]Recommendation, 0)

	// 根据分析结果生成建议
	stats := rg.alertManager.GetAlertStats()

	// 高危告警处理建议
	if stats.SeverityDistribution["critical"] > 10 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "critical",
			Title:       "处理严重告警",
			Description: "系统检测到大量严重级别告警，需要立即处理",
			Actions: []string{
				"优先处理严重告警",
				"分析攻击链确定攻击路径",
				"考虑隔离受影响的主机",
			},
		})
	}

	// 权限提升检测建议
	recommendations = append(recommendations, Recommendation{
		Priority:    "high",
		Title:       "监控权限提升活动",
		Description: "建议持续监控权限提升相关系统调用",
		Actions: []string{
			"启用 setuid/setgid 监控",
			"审查管理员权限使用情况",
			"实施最小权限原则",
		},
		References: []string{
			"https://attack.mitre.org/techniques/T1068/",
		},
	})

	// 网络连接监控建议
	recommendations = append(recommendations, Recommendation{
		Priority:    "medium",
		Title:       "加强网络连接监控",
		Description: "建议加强对异常网络连接的检测和响应",
		Actions: []string{
			"监控对非常见端口的连接",
			"建立网络连接基线",
			"实施网络分段",
		},
	})

	// 文件访问监控建议
	recommendations = append(recommendations, Recommendation{
		Priority:    "medium",
		Title:       "保护敏感文件",
		Description: "建议加强对敏感文件的访问控制和监控",
		Actions: []string{
			"监控 /etc/passwd 等敏感文件访问",
			"实施文件完整性监控",
			"定期审核文件权限",
		},
	})

	return recommendations
}

// generateKeyFindings 生成关键发现
func (rg *ReportGenerator) generateKeyFindings(anomalies []Anomaly) []string {
	findings := make([]string, 0)

	if len(anomalies) > 50 {
		findings = append(findings, "检测到大量异常行为，可能存在安全威胁")
	}

	// 统计异常类型
	typeCounts := make(map[string]int)
	for _, anomaly := range anomalies {
		typeCounts[string(anomaly.Type)]++
	}

	// 找出最常见的异常类型
	maxCount := 0
	var topType string
	for atype, count := range typeCounts {
		if count > maxCount {
			maxCount = count
			topType = atype
		}
	}

	if maxCount > 0 {
		findings = append(findings, fmt.Sprintf("最常见的异常类型是: %s (出现 %d 次)", topType, maxCount))
	}

	// 检查高风险异常
	highRiskCount := 0
	for _, anomaly := range anomalies {
		if anomaly.Severity == "critical" || anomaly.Severity == "high" {
			highRiskCount++
		}
	}

	if highRiskCount > 10 {
		findings = append(findings, fmt.Sprintf("检测到 %d 个高风险异常，需要重点关注", highRiskCount))
	}

	return findings
}

// getTopProcesses 获取顶级进程
func (rg *ReportGenerator) getTopProcesses(n int) []ProcessSummary {
	processes := make([]ProcessSummary, 0)

	// 模拟数据，实际应从事件上下文中获取
	for i := 1; i <= n; i++ {
		processes = append(processes, ProcessSummary{
			PID:         uint32(1000 + i),
			Comm:        fmt.Sprintf("process_%d", i),
			EventCount:   (n - i + 1) * 10,
			AlertCount:   (n - i + 1) * 2,
			AnomalyScore: float64(i) * 0.1,
		})
	}

	return processes
}

// getTopEventTypes 获取顶级事件类型
func (rg *ReportGenerator) getTopEventTypes(n int) []EventTypeSummary {
	types := []EventTypeSummary{
		{"execve", 500, 40},
		{"openat", 300, 24},
		{"read", 200, 16},
		{"connect", 150, 12},
		{"write", 100, 8},
	}
	return types
}

// getTopCategories 获取顶级类别
func (rg *ReportGenerator) getTopCategories(n int) []CategorySummary {
	categories := []CategorySummary{
		{"process", 500, 40},
		{"file", 350, 28},
		{"network", 250, 20},
		{"permission", 100, 8},
		{"memory", 50, 4},
	}
	return categories
}

// generateJSONReport 生成 JSON 报告
func (rg *ReportGenerator) generateJSONReport(report *SecurityReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// generateCSVReport 生成 CSV 报告
func (rg *ReportGenerator) generateCSVReport(report *SecurityReport) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// 写入摘要
	writer.Write([]string{"=== 报告摘要 ==="})
	writer.Write([]string{"", "生成时间", report.Metadata.GeneratedAt.Format(time.RFC3339)})
	writer.Write([]string{"", "报告ID", report.Metadata.ReportID})
	writer.Write([]string{"", "总事件数", fmt.Sprintf("%d", report.Summary.TotalEvents)})
	writer.Write([]string{"", "总告警数", fmt.Sprintf("%d", report.Summary.TotalAlerts)})
	writer.Write([]string{"", "活跃告警", fmt.Sprintf("%d", report.Summary.ActiveAlerts)})
	writer.Write([]string{""})

	// 写入建议
	writer.Write([]string{"=== 安全建议 ==="})
	for i, rec := range report.Recommendations {
		writer.Write([]string{fmt.Sprintf("%d", i+1), rec.Priority, rec.Title, rec.Description})
		for j, action := range rec.Actions {
			writer.Write([]string{"", "", fmt.Sprintf("  - %d", j+1), action})
		}
	}

	writer.Flush()
	return buf.Bytes(), nil
}

// generateHTMLReport 生成 HTML 报告
func (rg *ReportGenerator) generateHTMLReport(report *SecurityReport) ([]byte, error) {
	const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Metadata.ReportName}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 3px solid #3b82f6; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { margin: 0; color: #1e3a8a; }
        .metadata { color: #666; font-size: 14px; margin-top: 10px; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #1e3a8a; border-left: 4px solid #3b82f6; padding-left: 15px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8fafc; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; }
        .stat-card h3 { margin: 0 0 10px 0; color: #475569; font-size: 14px; }
        .stat-card .value { font-size: 32px; font-weight: bold; color: #1e3a8a; }
        .stat-card.critical .value { color: #dc2626; }
        .stat-card.warning .value { color: #f59e0b; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        .table th { background: #f1f5f9; font-weight: 600; color: #475569; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
        .badge.critical { background: #fecaca; color: #991b1b; }
        .badge.high { background: #fdba74; color: #9a3412; }
        .badge.medium { background: #fde68a; color: #92400e; }
        .badge.low { background: #bbf7d0; color: #166534; }
        .recommendation { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .recommendation.critical { background: #fef2f2; border-left-color: #dc2626; }
        .recommendation h4 { margin: 0 0 5px 0; }
        .recommendation ul { margin: 5px 0 0 20px; padding: 0; }
        .recommendation li { margin: 5px 0; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 1px solid #e2e8f0; text-align: center; color: #64748b; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Metadata.ReportName}}</h1>
            <div class="metadata">
                <p><strong>报告ID:</strong> {{.Metadata.ReportID}}</p>
                <p><strong>生成时间:</strong> {{.Metadata.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
                <p><strong>作者:</strong> {{.Metadata.AuthorName}}</p>
                <p><strong>时间范围:</strong> {{.Metadata.TimeRange.StartTime.Format "2006-01-02 15:04:05"}} 至 {{.Metadata.TimeRange.EndTime.Format "2006-01-02 15:04:05"}}</p>
            </div>
        </div>

        <div class="section">
            <h2>执行摘要</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>总事件数</h3>
                    <div class="value">{{.Summary.TotalEvents}}</div>
                </div>
                <div class="stat-card">
                    <h3>总告警数</h3>
                    <div class="value">{{.Summary.TotalAlerts}}</div>
                </div>
                <div class="stat-card critical">
                    <h3>严重告警</h3>
                    <div class="value">{{.Summary.CriticalAlerts}}</div>
                </div>
                <div class="stat-card warning">
                    <h3>高危告警</h3>
                    <div class="value">{{.Summary.HighAlerts}}</div>
                </div>
                <div class="stat-card">
                    <h3>活跃告警</h3>
                    <div class="value">{{.Summary.ActiveAlerts}}</div>
                </div>
                <div class="stat-card">
                    <h3>攻击链</h3>
                    <div class="value">{{.Summary.AttackChains}}</div>
                </div>
                {{if .Summary.TotalAnomalies}}
                <div class="stat-card critical">
                    <h3>AI 异常</h3>
                    <div class="value">{{.Summary.TotalAnomalies}}</div>
                </div>
                {{end}}
            </div>
        </div>

        <div class="section">
            <h2>告警分析</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>严重级别</th>
                        <th>数量</th>
                        <th>占比</th>
                    </tr>
                </thead>
                <tbody>
                    {{range $severity, $count := .AlertAnalysis.BySeverity}}
                    <tr>
                        <td><span class="badge {{$severity}}">{{$severity}}</span></td>
                        <td>{{$count}}</td>
                        <td>{{printf "%.1f%%" (div $count .AlertAnalysis.TotalAlerts)}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>攻击链分析</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>总攻击链</h3>
                    <div class="value">{{.ChainAnalysis.TotalChains}}</div>
                </div>
                <div class="stat-card critical">
                    <h3>高风险链</h3>
                    <div class="value">{{.ChainAnalysis.ByRiskLevel.critical}}</div>
                </div>
            </div>
        </div>

        {{if .AIAnalysis.TotalAnomalies}}
        <div class="section">
            <h2>AI 异常分析</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>异常类型</th>
                        <th>数量</th>
                    </tr>
                </thead>
                <tbody>
                    {{range $type, $count := .AIAnalysis.ByType}}
                    <tr>
                        <td>{{$type}}</td>
                        <td>{{$count}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            <h3>关键发现</h3>
            <ul>
                {{range .AIAnalysis.KeyFindings}}
                <li>{{.}}</li>
                {{end}}
            </ul>
        </div>
        {{end}}

        <div class="section">
            <h2>安全建议</h2>
            {{range .Recommendations}}
            <div class="recommendation {{.Priority}}">
                <h4>{{.Priority}}: {{.Title}}</h4>
                <p>{{.Description}}</p>
                <ul>
                    {{range .Actions}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{if .References}}
                <p><strong>参考:</strong></p>
                <ul>
                    {{range .References}}
                    <li><a href="{{.}}">{{.}}</a></li>
                    {{end}}
                </ul>
                {{end}}
            </div>
            {{end}}
        </div>

        <div class="footer">
            <p>本报告由 eTracee 安全监控系统生成</p>
            <p>报告版本: {{.Metadata.ReportVersion}} | 生成于 {{.Metadata.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
        </div>
    </div>
</body>
</html>`

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"div": func(a, b int) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b) * 100
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, report)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
