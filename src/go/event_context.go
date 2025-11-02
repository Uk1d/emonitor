package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// EventContext 事件上下文管理器
type EventContext struct {
	// 进程上下文存储
	processContexts map[uint32]*ProcessContext
	
	// 网络连接上下文
	networkContexts map[string]*NetworkContext
	
	// 文件操作上下文
	fileContexts    map[string]*FileContext
	
	// 攻击链上下文
	attackChains    map[string]*AttackChain
	
	// 配置
	config          *EventContextConfig
	
	// 同步控制
	mutex           sync.RWMutex
	
	// 持久化存储
	storage         *ContextStorage
}

// ProcessContext 进程上下文
type ProcessContext struct {
	PID             uint32                 `json:"pid"`
	PPID            uint32                 `json:"ppid"`
	UID             uint32                 `json:"uid"`
	GID             uint32                 `json:"gid"`
	Comm            string                 `json:"comm"`
	Cmdline         string                 `json:"cmdline"`
	StartTime       time.Time              `json:"start_time"`
	LastActivity    time.Time              `json:"last_activity"`
	
	// 进程行为特征
	FileOperations  []FileOperation        `json:"file_operations"`
	NetworkActivity []NetworkActivity      `json:"network_activity"`
	SystemCalls     []SystemCallInfo       `json:"system_calls"`
	ChildProcesses  []uint32               `json:"child_processes"`
	
	// 安全相关信息
	Privileges      []string               `json:"privileges"`
	SecurityEvents  []SecurityEvent        `json:"security_events"`
	RiskScore       float64                `json:"risk_score"`
	ThreatIndicators []ThreatIndicator     `json:"threat_indicators"`
	
	// 元数据
	Labels          map[string]string      `json:"labels"`
	Annotations     map[string]interface{} `json:"annotations"`
}

// NetworkContext 网络连接上下文
type NetworkContext struct {
	ConnectionID    string                 `json:"connection_id"`
	Protocol        string                 `json:"protocol"`
	LocalAddr       string                 `json:"local_addr"`
	RemoteAddr      string                 `json:"remote_addr"`
	LocalPort       uint16                 `json:"local_port"`
	RemotePort      uint16                 `json:"remote_port"`
	State           string                 `json:"state"`
	StartTime       time.Time              `json:"start_time"`
	LastActivity    time.Time              `json:"last_activity"`
	
	// 流量统计
	BytesSent       uint64                 `json:"bytes_sent"`
	BytesReceived   uint64                 `json:"bytes_received"`
	PacketsSent     uint64                 `json:"packets_sent"`
	PacketsReceived uint64                 `json:"packets_received"`
	
	// 关联进程
	ProcessPID      uint32                 `json:"process_pid"`
	ProcessComm     string                 `json:"process_comm"`
	
	// 安全信息
	ThreatLevel     string                 `json:"threat_level"`
	IOCMatches      []IOCMatch             `json:"ioc_matches"`
	GeoLocation     *GeoLocation           `json:"geo_location,omitempty"`
}

// FileContext 文件操作上下文
type FileContext struct {
	FilePath        string                 `json:"file_path"`
	FileType        string                 `json:"file_type"`
	FileSize        int64                  `json:"file_size"`
	Permissions     string                 `json:"permissions"`
	Owner           string                 `json:"owner"`
	Group           string                 `json:"group"`
	CreatedAt       time.Time              `json:"created_at"`
	ModifiedAt      time.Time              `json:"modified_at"`
	AccessedAt      time.Time              `json:"accessed_at"`
	
	// 操作历史
	Operations      []FileOperation        `json:"operations"`
	AccessPatterns  []AccessPattern        `json:"access_patterns"`
	
	// 安全信息
	HashValues      map[string]string      `json:"hash_values"`
	VirusScanResult *VirusScanResult       `json:"virus_scan_result,omitempty"`
	ThreatLevel     string                 `json:"threat_level"`
	Quarantined     bool                   `json:"quarantined"`
}

// AttackChain 攻击链
type AttackChain struct {
	ChainID         string                 `json:"chain_id"`
	ID              string                 `json:"id"`
	StartTime       time.Time              `json:"start_time"`
	LastUpdate      time.Time              `json:"last_update"`
	Status          string                 `json:"status"`
	Severity        string                 `json:"severity"`
	
	// 攻击阶段
	Stages          []AttackStage          `json:"stages"`
	CurrentStage    string                 `json:"current_stage"`
	
	// 关联实体
	InvolvedProcesses []uint32             `json:"involved_processes"`
	InvolvedFiles     []string             `json:"involved_files"`
	InvolvedNetworks  []string             `json:"involved_networks"`
	
	// MITRE ATT&CK 映射
	Techniques      []MITRETechnique       `json:"techniques"`
	Tactics         []string               `json:"tactics"`
	
	// 威胁情报
	ThreatActor     string                 `json:"threat_actor,omitempty"`
	Campaign        string                 `json:"campaign,omitempty"`
	IOCs            []IOCMatch             `json:"iocs"`
	
	// 影响评估
	ImpactScore     float64                `json:"impact_score"`
	ConfidenceScore float64                `json:"confidence_score"`
	RiskLevel       string                 `json:"risk_level"`
	
	// 关联的告警
	Alerts          []string               `json:"alerts"`
}

// 辅助数据结构
type FileOperation struct {
	Operation       string                 `json:"operation"`
	FilePath        string                 `json:"file_path"`
	Timestamp       time.Time              `json:"timestamp"`
	ProcessPID      uint32                 `json:"process_pid"`
	Result          string                 `json:"result"`
	Details         map[string]interface{} `json:"details"`
}

type NetworkActivity struct {
	Activity        string                 `json:"activity"`
	Protocol        string                 `json:"protocol"`
	RemoteAddr      string                 `json:"remote_addr"`
	RemotePort      uint16                 `json:"remote_port"`
	Timestamp       time.Time              `json:"timestamp"`
	DataSize        uint64                 `json:"data_size"`
	Direction       string                 `json:"direction"`
}

type SystemCallInfo struct {
	SyscallName     string                 `json:"syscall_name"`
	SyscallID       uint32                 `json:"syscall_id"`
	Arguments       []interface{}          `json:"arguments"`
	ReturnValue     int64                  `json:"return_value"`
	Timestamp       time.Time              `json:"timestamp"`
	Duration        time.Duration          `json:"duration"`
}

type SecurityEvent struct {
	EventType       string                 `json:"event_type"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	Timestamp       time.Time              `json:"timestamp"`
	RuleName        string                 `json:"rule_name"`
	Evidence        map[string]interface{} `json:"evidence"`
}

type ThreatIndicator struct {
	Type            string                 `json:"type"`
	Value           string                 `json:"value"`
	Confidence      float64                `json:"confidence"`
	Source          string                 `json:"source"`
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
}

type AccessPattern struct {
	Pattern         string                 `json:"pattern"`
	Frequency       int                    `json:"frequency"`
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
	ProcessPIDs     []uint32               `json:"process_pids"`
}

type VirusScanResult struct {
	Scanner         string                 `json:"scanner"`
	ScanTime        time.Time              `json:"scan_time"`
	Result          string                 `json:"result"`
	ThreatName      string                 `json:"threat_name,omitempty"`
	Confidence      float64                `json:"confidence"`
}

type AttackStage struct {
	Stage           string                 `json:"stage"`
	Technique       string                 `json:"technique"`
	Description     string                 `json:"description"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         *time.Time             `json:"end_time,omitempty"`
	Events          []string               `json:"events"`
	Indicators      []ThreatIndicator      `json:"indicators"`
}

type MITRETechnique struct {
	TechniqueID     string                 `json:"technique_id"`
	TechniqueName   string                 `json:"technique_name"`
	Tactic          string                 `json:"tactic"`
	Description     string                 `json:"description"`
	Confidence      float64                `json:"confidence"`
	Evidence        []string               `json:"evidence"`
}

type IOCMatch struct {
	IOCType         string                 `json:"ioc_type"`
	IOCValue        string                 `json:"ioc_value"`
	MatchType       string                 `json:"match_type"`
	Confidence      float64                `json:"confidence"`
	Source          string                 `json:"source"`
	Timestamp       time.Time              `json:"timestamp"`
}

type GeoLocation struct {
	Country         string                 `json:"country"`
	Region          string                 `json:"region"`
	City            string                 `json:"city"`
	Latitude        float64                `json:"latitude"`
	Longitude       float64                `json:"longitude"`
	ISP             string                 `json:"isp"`
	Organization    string                 `json:"organization"`
}

// EventContextConfig 事件上下文配置
type EventContextConfig struct {
	// 存储配置
	MaxProcessContexts    int           `yaml:"max_process_contexts"`
	MaxNetworkContexts    int           `yaml:"max_network_contexts"`
	MaxFileContexts       int           `yaml:"max_file_contexts"`
	MaxAttackChains       int           `yaml:"max_attack_chains"`
	
	// 保留时间
	ProcessContextTTL     time.Duration `yaml:"process_context_ttl"`
	NetworkContextTTL     time.Duration `yaml:"network_context_ttl"`
	FileContextTTL        time.Duration `yaml:"file_context_ttl"`
	AttackChainTTL        time.Duration `yaml:"attack_chain_ttl"`
	
	// 持久化配置
	EnablePersistence     bool          `yaml:"enable_persistence"`
	StoragePath           string        `yaml:"storage_path"`
	FlushInterval         time.Duration `yaml:"flush_interval"`
	
	// 分析配置
	EnableAttackChainDetection bool     `yaml:"enable_attack_chain_detection"`
	AttackChainTimeout        time.Duration `yaml:"attack_chain_timeout"`
	MinChainEvents            int       `yaml:"min_chain_events"`
	
	// 威胁情报配置
	EnableThreatIntel     bool          `yaml:"enable_threat_intel"`
	ThreatIntelSources    []string      `yaml:"threat_intel_sources"`
	IOCUpdateInterval     time.Duration `yaml:"ioc_update_interval"`
}

// ContextStorage 上下文存储
type ContextStorage struct {
	storagePath string
	mutex       sync.RWMutex
}

// NewEventContext 创建事件上下文管理器
func NewEventContext(config *EventContextConfig) *EventContext {
	if config == nil {
		config = &EventContextConfig{
			MaxProcessContexts:         10000,
			MaxNetworkContexts:         5000,
			MaxFileContexts:            20000,
			MaxAttackChains:            1000,
			ProcessContextTTL:          24 * time.Hour,
			NetworkContextTTL:          6 * time.Hour,
			FileContextTTL:             48 * time.Hour,
			AttackChainTTL:             7 * 24 * time.Hour,
			EnablePersistence:          true,
			StoragePath:                "data/context",
			FlushInterval:              5 * time.Minute,
			EnableAttackChainDetection: true,
			AttackChainTimeout:         30 * time.Minute,
			MinChainEvents:             3,
			EnableThreatIntel:          true,
			IOCUpdateInterval:          1 * time.Hour,
		}
	}

	ec := &EventContext{
		processContexts: make(map[uint32]*ProcessContext),
		networkContexts: make(map[string]*NetworkContext),
		fileContexts:    make(map[string]*FileContext),
		attackChains:    make(map[string]*AttackChain),
		config:          config,
	}

	// 初始化存储
	if config.EnablePersistence {
		ec.storage = &ContextStorage{
			storagePath: config.StoragePath,
		}
		
		// 确保存储目录存在
		if err := os.MkdirAll(config.StoragePath, 0755); err != nil {
			log.Printf("Warning: Failed to create context storage directory: %v", err)
		}
	}

	// 启动后台任务
	go ec.startBackgroundTasks()

	return ec
}

// UpdateProcessContext 更新进程上下文
func (ec *EventContext) UpdateProcessContext(event *EventJSON) {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	ctx, exists := ec.processContexts[event.PID]
	if !exists {
		ctx = &ProcessContext{
			PID:             event.PID,
			PPID:            event.PPID,
			UID:             event.UID,
			GID:             event.GID,
			Comm:            event.Comm,
			StartTime:       time.Now(),
			FileOperations:  make([]FileOperation, 0),
			NetworkActivity: make([]NetworkActivity, 0),
			SystemCalls:     make([]SystemCallInfo, 0),
			ChildProcesses:  make([]uint32, 0),
			Privileges:      make([]string, 0),
			SecurityEvents:  make([]SecurityEvent, 0),
			ThreatIndicators: make([]ThreatIndicator, 0),
			Labels:          make(map[string]string),
			Annotations:     make(map[string]interface{}),
		}
		ec.processContexts[event.PID] = ctx
	}

	ctx.LastActivity = time.Now()

	// 根据事件类型更新上下文
	switch event.EventType {
	case "execve":
		if event.Filename != "" {
			ctx.Cmdline = event.Filename
		}
	case "openat", "close", "read", "write", "unlink", "rename":
		if event.Filename != "" {
			fileOp := FileOperation{
				Operation:  event.EventType,
				FilePath:   event.Filename,
				Timestamp:  time.Now(),
				ProcessPID: event.PID,
				Result:     fmt.Sprintf("ret_code:%d", event.RetCode),
				Details:    make(map[string]interface{}),
			}
			ctx.FileOperations = append(ctx.FileOperations, fileOp)
		}
	case "connect", "bind", "listen", "accept":
		if event.DstAddr != nil {
			netActivity := NetworkActivity{
				Activity:   event.EventType,
				Protocol:   "tcp", // 假设为TCP
				RemoteAddr: event.DstAddr.IP,
				RemotePort: event.DstAddr.Port,
				Timestamp:  time.Now(),
				Direction:  "outbound",
			}
			ctx.NetworkActivity = append(ctx.NetworkActivity, netActivity)
		}
	}

	// 更新系统调用信息
	syscallInfo := SystemCallInfo{
		SyscallName: event.EventType,
		SyscallID:   event.SyscallID,
		ReturnValue: int64(event.RetCode),
		Timestamp:   time.Now(),
	}
	ctx.SystemCalls = append(ctx.SystemCalls, syscallInfo)

	// 限制历史记录长度
	if len(ctx.FileOperations) > 1000 {
		ctx.FileOperations = ctx.FileOperations[len(ctx.FileOperations)-500:]
	}
	if len(ctx.NetworkActivity) > 1000 {
		ctx.NetworkActivity = ctx.NetworkActivity[len(ctx.NetworkActivity)-500:]
	}
	if len(ctx.SystemCalls) > 2000 {
		ctx.SystemCalls = ctx.SystemCalls[len(ctx.SystemCalls)-1000:]
	}
}

// UpdateNetworkContext 更新网络连接上下文
func (ec *EventContext) UpdateNetworkContext(event *EventJSON) {
	if event.DstAddr == nil || event.SrcAddr == nil {
		return
	}

	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	connID := fmt.Sprintf("%s:%d->%s:%d", 
		event.SrcAddr.IP, event.SrcAddr.Port,
		event.DstAddr.IP, event.DstAddr.Port)

	ctx, exists := ec.networkContexts[connID]
	if !exists {
		ctx = &NetworkContext{
			ConnectionID:  connID,
			Protocol:      "tcp",
			LocalAddr:     event.SrcAddr.IP,
			RemoteAddr:    event.DstAddr.IP,
			LocalPort:     event.SrcAddr.Port,
			RemotePort:    event.DstAddr.Port,
			State:         "connecting",
			StartTime:     time.Now(),
			ProcessPID:    event.PID,
			ProcessComm:   event.Comm,
			ThreatLevel:   "unknown",
			IOCMatches:    make([]IOCMatch, 0),
		}
		ec.networkContexts[connID] = ctx
	}

	ctx.LastActivity = time.Now()

	// 更新连接状态
	switch event.EventType {
	case "connect":
		ctx.State = "connected"
	case "close":
		ctx.State = "closed"
	}
}

// UpdateFileContext 更新文件操作上下文
func (ec *EventContext) UpdateFileContext(event *EventJSON) {
	if event.Filename == "" {
		return
	}

	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	ctx, exists := ec.fileContexts[event.Filename]
	if !exists {
		ctx = &FileContext{
			FilePath:       event.Filename,
			FileType:       "unknown",
			Permissions:    fmt.Sprintf("%o", event.Mode),
			CreatedAt:      time.Now(),
			Operations:     make([]FileOperation, 0),
			AccessPatterns: make([]AccessPattern, 0),
			HashValues:     make(map[string]string),
			ThreatLevel:    "unknown",
		}
		ec.fileContexts[event.Filename] = ctx
	}

	// 更新访问时间
	switch event.EventType {
	case "openat", "read":
		ctx.AccessedAt = time.Now()
	case "write", "rename":
		ctx.ModifiedAt = time.Now()
	}

	// 添加操作记录
	fileOp := FileOperation{
		Operation:  event.EventType,
		FilePath:   event.Filename,
		Timestamp:  time.Now(),
		ProcessPID: event.PID,
		Result:     fmt.Sprintf("ret_code:%d", event.RetCode),
		Details:    make(map[string]interface{}),
	}
	ctx.Operations = append(ctx.Operations, fileOp)

	// 限制操作历史长度
	if len(ctx.Operations) > 500 {
		ctx.Operations = ctx.Operations[len(ctx.Operations)-250:]
	}
}

// DetectAttackChain 检测攻击链
func (ec *EventContext) DetectAttackChain(event *EventJSON, alert *AlertEvent) {
	if !ec.config.EnableAttackChainDetection {
		return
	}

	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	// 查找相关的攻击链
	var relatedChain *AttackChain
	for _, chain := range ec.attackChains {
		if ec.isEventRelatedToChain(event, chain) {
			relatedChain = chain
			break
		}
	}

	// 如果没有找到相关攻击链，创建新的
	if relatedChain == nil {
		chainID := fmt.Sprintf("chain_%d_%s", event.PID, time.Now().Format("20060102150405"))
		relatedChain = &AttackChain{
			ChainID:           chainID,
			StartTime:         time.Now(),
			LastUpdate:        time.Now(),
			Status:            "active",
			Severity:          alert.Severity,
			Stages:            make([]AttackStage, 0),
			CurrentStage:      "initial",
			InvolvedProcesses: []uint32{event.PID},
			InvolvedFiles:     make([]string, 0),
			InvolvedNetworks:  make([]string, 0),
			Techniques:        make([]MITRETechnique, 0),
			Tactics:           make([]string, 0),
			IOCs:              make([]IOCMatch, 0),
		}
		ec.attackChains[chainID] = relatedChain
	}

	// 更新攻击链
	relatedChain.LastUpdate = time.Now()
	
	// 添加涉及的资源
	if event.Filename != "" {
		for _, file := range relatedChain.InvolvedFiles {
			if file == event.Filename {
				goto skipFile
			}
		}
		relatedChain.InvolvedFiles = append(relatedChain.InvolvedFiles, event.Filename)
		skipFile:
	}

	if event.DstAddr != nil {
		networkID := fmt.Sprintf("%s:%d", event.DstAddr.IP, event.DstAddr.Port)
		for _, network := range relatedChain.InvolvedNetworks {
			if network == networkID {
				goto skipNetwork
			}
		}
		relatedChain.InvolvedNetworks = append(relatedChain.InvolvedNetworks, networkID)
		skipNetwork:
	}

	// 添加MITRE ATT&CK技术映射
	technique := ec.mapToMITRETechnique(event, alert)
	if technique != nil {
		relatedChain.Techniques = append(relatedChain.Techniques, *technique)
	}

	// 更新攻击阶段
	stage := ec.determineAttackStage(event, alert)
	if stage != relatedChain.CurrentStage {
		newStage := AttackStage{
			Stage:       stage,
			Technique:   alert.RuleName,
			Description: alert.Description,
			StartTime:   time.Now(),
			Events:      []string{fmt.Sprintf("%s_%d", event.EventType, event.PID)},
			Indicators:  make([]ThreatIndicator, 0),
		}
		relatedChain.Stages = append(relatedChain.Stages, newStage)
		relatedChain.CurrentStage = stage
	}

	// 计算影响和置信度分数
	relatedChain.ImpactScore = ec.calculateImpactScore(relatedChain)
	relatedChain.ConfidenceScore = ec.calculateConfidenceScore(relatedChain)
	relatedChain.RiskLevel = ec.determineRiskLevel(relatedChain.ImpactScore, relatedChain.ConfidenceScore)
}

// GetProcessContext 获取进程上下文
func (ec *EventContext) GetProcessContext(pid uint32) *ProcessContext {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()
	
	return ec.processContexts[pid]
}

// GetAttackChains 获取攻击链
func (ec *EventContext) GetAttackChains() []*AttackChain {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()
	
	chains := make([]*AttackChain, 0, len(ec.attackChains))
	for _, chain := range ec.attackChains {
		chains = append(chains, chain)
	}
	
	// 按最后更新时间排序
	sort.Slice(chains, func(i, j int) bool {
		return chains[i].LastUpdate.After(chains[j].LastUpdate)
	})
	
	return chains
}

// GetProcessContextCount 获取进程上下文数量
func (ec *EventContext) GetProcessContextCount() int {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()
	return len(ec.processContexts)
}

// GetNetworkContextCount 获取网络上下文数量
func (ec *EventContext) GetNetworkContextCount() int {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()
	return len(ec.networkContexts)
}

// GetFileContextCount 获取文件上下文数量
func (ec *EventContext) GetFileContextCount() int {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()
	return len(ec.fileContexts)
}

// 辅助方法
func (ec *EventContext) isEventRelatedToChain(event *EventJSON, chain *AttackChain) bool {
	// 检查进程关联
	for _, pid := range chain.InvolvedProcesses {
		if pid == event.PID || pid == event.PPID {
			return true
		}
	}
	
	// 检查文件关联
	if event.Filename != "" {
		for _, file := range chain.InvolvedFiles {
			if file == event.Filename {
				return true
			}
		}
	}
	
	// 检查网络关联
	if event.DstAddr != nil {
		networkID := fmt.Sprintf("%s:%d", event.DstAddr.IP, event.DstAddr.Port)
		for _, network := range chain.InvolvedNetworks {
			if network == networkID {
				return true
			}
		}
	}
	
	// 检查时间窗口
	if time.Since(chain.LastUpdate) > ec.config.AttackChainTimeout {
		return false
	}
	
	return false
}

func (ec *EventContext) mapToMITRETechnique(event *EventJSON, alert *AlertEvent) *MITRETechnique {
	// 简化的MITRE ATT&CK映射
	techniqueMap := map[string]MITRETechnique{
		"suspicious_execve": {
			TechniqueID:   "T1059",
			TechniqueName: "Command and Scripting Interpreter",
			Tactic:        "Execution",
			Description:   "Adversaries may abuse command and script interpreters",
			Confidence:    0.8,
		},
		"privilege_escalation": {
			TechniqueID:   "T1068",
			TechniqueName: "Exploitation for Privilege Escalation",
			Tactic:        "Privilege Escalation",
			Description:   "Adversaries may exploit software vulnerabilities",
			Confidence:    0.9,
		},
		"network_connection": {
			TechniqueID:   "T1071",
			TechniqueName: "Application Layer Protocol",
			Tactic:        "Command and Control",
			Description:   "Adversaries may communicate using application layer protocols",
			Confidence:    0.7,
		},
	}
	
	if technique, exists := techniqueMap[alert.Category]; exists {
		technique.Evidence = []string{fmt.Sprintf("Event: %s, PID: %d", event.EventType, event.PID)}
		return &technique
	}
	
	return nil
}

func (ec *EventContext) determineAttackStage(event *EventJSON, alert *AlertEvent) string {
	// 简化的攻击阶段判断
	switch alert.Category {
	case "reconnaissance":
		return "reconnaissance"
	case "initial_access":
		return "initial_access"
	case "execution":
		return "execution"
	case "persistence":
		return "persistence"
	case "privilege_escalation":
		return "privilege_escalation"
	case "defense_evasion":
		return "defense_evasion"
	case "credential_access":
		return "credential_access"
	case "discovery":
		return "discovery"
	case "lateral_movement":
		return "lateral_movement"
	case "collection":
		return "collection"
	case "command_and_control":
		return "command_and_control"
	case "exfiltration":
		return "exfiltration"
	case "impact":
		return "impact"
	default:
		return "unknown"
	}
}

func (ec *EventContext) calculateImpactScore(chain *AttackChain) float64 {
	score := 0.0
	
	// 基于涉及的进程数量
	score += float64(len(chain.InvolvedProcesses)) * 0.1
	
	// 基于涉及的文件数量
	score += float64(len(chain.InvolvedFiles)) * 0.05
	
	// 基于涉及的网络连接数量
	score += float64(len(chain.InvolvedNetworks)) * 0.15
	
	// 基于攻击阶段数量
	score += float64(len(chain.Stages)) * 0.2
	
	// 基于严重程度
	switch chain.Severity {
	case "critical":
		score += 1.0
	case "high":
		score += 0.8
	case "medium":
		score += 0.5
	case "low":
		score += 0.2
	}
	
	// 限制在0-10范围内
	if score > 10.0 {
		score = 10.0
	}
	
	return score
}

func (ec *EventContext) calculateConfidenceScore(chain *AttackChain) float64 {
	score := 0.0
	
	// 基于技术数量
	score += float64(len(chain.Techniques)) * 0.1
	
	// 基于IOC匹配数量
	score += float64(len(chain.IOCs)) * 0.2
	
	// 基于攻击链持续时间
	duration := time.Since(chain.StartTime)
	if duration > time.Hour {
		score += 0.3
	} else if duration > 10*time.Minute {
		score += 0.2
	} else {
		score += 0.1
	}
	
	// 基于事件数量
	totalEvents := 0
	for _, stage := range chain.Stages {
		totalEvents += len(stage.Events)
	}
	score += float64(totalEvents) * 0.05
	
	// 限制在0-1范围内
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

func (ec *EventContext) determineRiskLevel(impactScore, confidenceScore float64) string {
	combinedScore := impactScore * confidenceScore
	
	if combinedScore >= 7.0 {
		return "critical"
	} else if combinedScore >= 5.0 {
		return "high"
	} else if combinedScore >= 3.0 {
		return "medium"
	} else {
		return "low"
	}
}

// 后台任务
func (ec *EventContext) startBackgroundTasks() {
	// 定期清理过期上下文
	cleanupTicker := time.NewTicker(10 * time.Minute)
	defer cleanupTicker.Stop()
	
	// 定期持久化数据
	var persistTicker *time.Ticker
	if ec.config.EnablePersistence {
		persistTicker = time.NewTicker(ec.config.FlushInterval)
		defer persistTicker.Stop()
	}
	
	for {
		select {
		case <-cleanupTicker.C:
			ec.cleanupExpiredContexts()
		case <-persistTicker.C:
			if ec.config.EnablePersistence {
				ec.persistContexts()
			}
		}
	}
}

func (ec *EventContext) cleanupExpiredContexts() {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()
	
	now := time.Now()
	
	// 清理过期的进程上下文
	for pid, ctx := range ec.processContexts {
		if now.Sub(ctx.LastActivity) > ec.config.ProcessContextTTL {
			delete(ec.processContexts, pid)
		}
	}
	
	// 清理过期的网络上下文
	for connID, ctx := range ec.networkContexts {
		if now.Sub(ctx.LastActivity) > ec.config.NetworkContextTTL {
			delete(ec.networkContexts, connID)
		}
	}
	
	// 清理过期的文件上下文
	for filePath, ctx := range ec.fileContexts {
		if now.Sub(ctx.AccessedAt) > ec.config.FileContextTTL && 
		   now.Sub(ctx.ModifiedAt) > ec.config.FileContextTTL {
			delete(ec.fileContexts, filePath)
		}
	}
	
	// 清理过期的攻击链
	for chainID, chain := range ec.attackChains {
		if now.Sub(chain.LastUpdate) > ec.config.AttackChainTTL {
			delete(ec.attackChains, chainID)
		}
	}
}

func (ec *EventContext) persistContexts() {
	if ec.storage == nil {
		return
	}
	
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()
	
	// 持久化攻击链（最重要的数据）
	for chainID, chain := range ec.attackChains {
		data, err := json.Marshal(chain)
		if err != nil {
			log.Printf("Failed to marshal attack chain %s: %v", chainID, err)
			continue
		}
		
		filePath := filepath.Join(ec.config.StoragePath, fmt.Sprintf("chain_%s.json", chainID))
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			log.Printf("Failed to persist attack chain %s: %v", chainID, err)
		}
	}
}