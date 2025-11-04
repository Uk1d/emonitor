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

// AttackChainProcessor 攻击链处理器
type AttackChainProcessor struct {
	attackChains map[string]*AttackChain
}

func NewAttackChainProcessor() *AttackChainProcessor {
	return &AttackChainProcessor{
		attackChains: make(map[string]*AttackChain),
	}
}

func (p *AttackChainProcessor) ProcessAlert(alert *ManagedAlert) error {
	// 分析是否属于攻击链
	chainID := p.identifyAttackChain(alert)
	if chainID != "" {
		alert.AttackChainID = chainID
		p.updateAttackChain(chainID, alert)
		
		note := fmt.Sprintf("[%s] 攻击链处理器: 告警已关联到攻击链 %s", 
			time.Now().Format("2006-01-02 15:04:05"), chainID)
		alert.ProcessingNotes = append(alert.ProcessingNotes, note)
		
		// 检查攻击链是否需要升级
		if chain := p.attackChains[chainID]; chain != nil && len(chain.Alerts) >= 3 {
			alert.Severity = "high"
    log.Printf("[*] 攻击链检测: %s 包含 %d 个相关告警", chainID, len(chain.Alerts))
		}
	}
	
	return nil
}

func (p *AttackChainProcessor) identifyAttackChain(alert *ManagedAlert) string {
	// 基于时间窗口和相关性识别攻击链
	timeWindow := 10 * time.Minute
	cutoffTime := time.Now().Add(-timeWindow)
	
	// 检查现有攻击链
	for chainID, chain := range p.attackChains {
		if chain.LastUpdate.Before(cutoffTime) {
			continue
		}
		
		// 检查是否相关（相同用户、相同主机、相关技术）
		if p.isRelatedToChain(alert, chain) {
			return chainID
		}
	}
	
	// 创建新攻击链
	if p.shouldCreateNewChain(alert) {
		chainID := fmt.Sprintf("chain_%d_%d", alert.Event.UID, time.Now().Unix())
		p.attackChains[chainID] = &AttackChain{
			ChainID:    chainID,
			ID:         chainID,
			StartTime:  time.Now(),
			LastUpdate: time.Now(),
			Alerts:     []string{},
			Techniques: []MITRETechnique{},
			Severity:   alert.Severity,
			Status:     "active",
		}
		return chainID
	}
	
	return ""
}

func (p *AttackChainProcessor) isRelatedToChain(alert *ManagedAlert, chain *AttackChain) bool {
	// 检查MITRE ATT&CK技术相关性
	if alert.MitreAttack != nil {
		for _, technique := range chain.Techniques {
			if alert.MitreAttack.TechniqueID == technique.TechniqueID {
				return true
			}
			
			// 检查相关技术（同一战术）
			if p.isRelatedTechnique(alert.MitreAttack.TechniqueID, technique.TechniqueID) {
				return true
			}
		}
	}
	
	// 检查进程关系
	// 这里可以添加更复杂的进程关系分析
	
	return false
}

func (p *AttackChainProcessor) isRelatedTechnique(tech1, tech2 string) bool {
	// 简化的技术关联检查
	relatedTechniques := map[string][]string{
		"T1059": {"T1055", "T1106", "T1140"}, // Command and Scripting Interpreter
		"T1055": {"T1059", "T1106", "T1134"}, // Process Injection
		"T1106": {"T1055", "T1059", "T1543"}, // Native API
	}
	
	if related, exists := relatedTechniques[tech1]; exists {
		for _, relatedTech := range related {
			if relatedTech == tech2 {
				return true
			}
		}
	}
	
	return false
}

func (p *AttackChainProcessor) shouldCreateNewChain(alert *ManagedAlert) bool {
	// 高危告警或包含MITRE ATT&CK信息的告警应该创建攻击链
	return alert.Severity == "high" || alert.Severity == "critical" || alert.MitreAttack != nil
}

func (p *AttackChainProcessor) updateAttackChain(chainID string, alert *ManagedAlert) {
	chain := p.attackChains[chainID]
	if chain == nil {
		return
	}
	
	chain.LastUpdate = time.Now()
	chain.Alerts = append(chain.Alerts, alert.ID)
	
	if alert.MitreAttack != nil {
		// 添加新技术
		found := false
		for _, tech := range chain.Techniques {
			if tech.TechniqueID == alert.MitreAttack.TechniqueID {
				found = true
				break
			}
		}
		if !found {
			chain.Techniques = append(chain.Techniques, *alert.MitreAttack)
		}
	}
	
	// 更新攻击链严重级别
	if alert.Severity == "critical" || (alert.Severity == "high" && chain.Severity != "critical") {
		chain.Severity = alert.Severity
	}
}

func (p *AttackChainProcessor) GetProcessorName() string {
	return "attack_chain"
}

// GetAttackChains 获取攻击链信息
func (p *AttackChainProcessor) GetAttackChains() map[string]*AttackChain {
	return p.attackChains
}

// CleanupExpiredChains 清理过期攻击链
func (p *AttackChainProcessor) CleanupExpiredChains() {
	cutoffTime := time.Now().Add(-1 * time.Hour)
	
	for chainID, chain := range p.attackChains {
		if chain.LastUpdate.Before(cutoffTime) {
			delete(p.attackChains, chainID)
		}
	}
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
	// 检查文件哈希
	if alert.Event.Filename != "" {
		if indicator, found := p.iocDatabase[alert.Event.Filename]; found {
			alert.Severity = indicator.Severity
			note := fmt.Sprintf("[%s] 威胁情报处理器: 检测到已知威胁指标 - %s (%s)", 
				time.Now().Format("2006-01-02 15:04:05"), indicator.Description, indicator.Source)
			alert.ProcessingNotes = append(alert.ProcessingNotes, note)
			
    log.Printf("[*] 威胁情报匹配: %s - %s", alert.Event.Filename, indicator.Description)
		}
	}
	
	// 检查进程名
	if alert.Event.Comm != "" {
		if indicator, found := p.iocDatabase[alert.Event.Comm]; found {
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