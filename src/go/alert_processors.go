package main

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// DefaultAlertProcessor 默认告警处理器
type DefaultAlertProcessor struct{}

func (p *DefaultAlertProcessor) ProcessAlert(alert *ManagedAlert) error {
	// 基本验证和标准化
	if alert.Severity == "" {
		alert.Severity = "medium"
	}

	if alert.Category == "" {
		alert.Category = "security"
	}

	// 添加处理时间戳
	note := fmt.Sprintf("[%s] 默认处理器: 告警已标准化处理",
		time.Now().Format("2006-01-02 15:04:05"))
	alert.ProcessingNotes = append(alert.ProcessingNotes, note)

	return nil
}

func (p *DefaultAlertProcessor) GetProcessorName() string {
	return "default"
}

// SeverityBasedProcessor 基于严重级别的处理器
type SeverityBasedProcessor struct{}

func (p *SeverityBasedProcessor) ProcessAlert(alert *ManagedAlert) error {
	switch alert.Severity {
	case "critical":
		// 关键告警立即升级
		alert.Status = AlertStatusInProgress
		note := fmt.Sprintf("[%s] 严重级别处理器: 关键告警已升级处理",
			time.Now().Format("2006-01-02 15:04:05"))
		alert.ProcessingNotes = append(alert.ProcessingNotes, note)

		// 记录关键事件
		log.Printf("[!] 关键安全告警: %s - %s", alert.RuleName, alert.Description)

	case "high":
		// 高危告警需要关注
		note := fmt.Sprintf("[%s] 严重级别处理器: 高危告警需要及时处理",
			time.Now().Format("2006-01-02 15:04:05"))
		alert.ProcessingNotes = append(alert.ProcessingNotes, note)

		log.Printf("[!] 高危安全告警: %s - %s", alert.RuleName, alert.Description)

	case "medium":
		// 中等告警常规处理
		note := fmt.Sprintf("[%s] 严重级别处理器: 中等告警常规监控",
			time.Now().Format("2006-01-02 15:04:05"))
		alert.ProcessingNotes = append(alert.ProcessingNotes, note)

	case "low":
		// 低危告警可能自动解决
		if p.shouldAutoResolve(alert) {
			now := time.Now()
			alert.Status = AlertStatusResolved
			alert.ResolvedAt = &now
			alert.UpdatedAt = now

			note := fmt.Sprintf("[%s] 严重级别处理器: 低危告警自动解决",
				time.Now().Format("2006-01-02 15:04:05"))
			alert.ProcessingNotes = append(alert.ProcessingNotes, note)
		}
	}

	return nil
}

func (p *SeverityBasedProcessor) shouldAutoResolve(alert *ManagedAlert) bool {
	// 检查是否为已知的低风险模式
	lowRiskPatterns := []string{
		"system_process",
		"known_good_binary",
		"whitelisted_user",
	}

	for _, pattern := range lowRiskPatterns {
		if strings.Contains(strings.ToLower(alert.Description), pattern) {
			return true
		}
	}

	return false
}

func (p *SeverityBasedProcessor) GetProcessorName() string {
	return "severity_based"
}

// ThreatIntelProcessor 威胁情报处理器
type ThreatIntelProcessor struct {
	iocDatabase map[string]ThreatIndicator
}

func NewThreatIntelProcessor() *ThreatIntelProcessor {
	processor := &ThreatIntelProcessor{
		iocDatabase: make(map[string]ThreatIndicator),
	}

	// 加载一些示例IOC
	processor.loadSampleIOCs()

	return processor
}

func (p *ThreatIntelProcessor) ProcessAlert(alert *ManagedAlert) error {
	if alert.Event == nil {
		return nil
	}
	event := alert.Event
	// 检查文件哈希
	if event.Filename != "" {
		if indicator, found := p.iocDatabase[event.Filename]; found {
			alert.Severity = indicator.Severity
			note := fmt.Sprintf("[%s] 威胁情报处理器: 检测到已知威胁指标 - %s (%s)",
				time.Now().Format("2006-01-02 15:04:05"), indicator.Description, indicator.Source)
			alert.ProcessingNotes = append(alert.ProcessingNotes, note)

			log.Printf("[*] 威胁情报匹配: %s - %s", event.Filename, indicator.Description)
		}
	}

	// 检查进程名
	if event.Comm != "" {
		if indicator, found := p.iocDatabase[event.Comm]; found {
			alert.Severity = indicator.Severity
			note := fmt.Sprintf("[%s] 威胁情报处理器: 检测到可疑进程 - %s (%s)",
				time.Now().Format("2006-01-02 15:04:05"), indicator.Description, indicator.Source)
			alert.ProcessingNotes = append(alert.ProcessingNotes, note)
		}
	}

	return nil
}

func (p *ThreatIntelProcessor) loadSampleIOCs() {
	sampleIOCs := []ThreatIndicator{
		{
			Value:       "nc",
			Type:        "process",
			Severity:    "high",
			Source:      "internal",
			Description: "Netcat - 常用于反向Shell",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Confidence:  0.8,
		},
		{
			Value:       "bash",
			Type:        "process",
			Severity:    "medium",
			Source:      "internal",
			Description: "Bash Shell - 可能用于命令执行",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Confidence:  0.6,
		},
		{
			Value:       "/tmp/malware",
			Type:        "file",
			Severity:    "critical",
			Source:      "threat_feed",
			Description: "已知恶意软件路径",
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Confidence:  0.9,
		},
	}

	for _, ioc := range sampleIOCs {
		p.iocDatabase[ioc.Value] = ioc
	}
}

func (p *ThreatIntelProcessor) GetProcessorName() string {
	return "threat_intel"
}

// AddThreatIndicator 添加威胁指标
func (p *ThreatIntelProcessor) AddThreatIndicator(indicator ThreatIndicator) {
	p.iocDatabase[indicator.Value] = indicator
}

// RemoveThreatIndicator 移除威胁指标
func (p *ThreatIntelProcessor) RemoveThreatIndicator(value string) {
	delete(p.iocDatabase, value)
}
