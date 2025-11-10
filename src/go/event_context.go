package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "sort"
    "strconv"
    "strings"
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
	fileContexts map[string]*FileContext

	// 攻击链上下文
	attackChains map[string]*AttackChain

	// 配置
	config *EventContextConfig

	// 同步控制
	mutex sync.RWMutex

	// 持久化存储
	storage *ContextStorage
}

// ProcessContext 进程上下文
type ProcessContext struct {
	PID          uint32    `json:"pid"`
	PPID         uint32    `json:"ppid"`
	UID          uint32    `json:"uid"`
	GID          uint32    `json:"gid"`
	Comm         string    `json:"comm"`
	Cmdline      string    `json:"cmdline"`
	StartTime    time.Time `json:"start_time"`
	LastActivity time.Time `json:"last_activity"`

	// 进程行为特征
	FileOperations  []FileOperation   `json:"file_operations"`
	NetworkActivity []NetworkActivity `json:"network_activity"`
	SystemCalls     []SystemCallInfo  `json:"system_calls"`
	ChildProcesses  []uint32          `json:"child_processes"`

	// 安全相关信息
	Privileges       []string          `json:"privileges"`
	SecurityEvents   []SecurityEvent   `json:"security_events"`
	RiskScore        float64           `json:"risk_score"`
	ThreatIndicators []ThreatIndicator `json:"threat_indicators"`

	// 元数据
	Labels      map[string]string      `json:"labels"`
	Annotations map[string]interface{} `json:"annotations"`
}

// NetworkContext 网络连接上下文
type NetworkContext struct {
	ConnectionID string    `json:"connection_id"`
	Protocol     string    `json:"protocol"`
	LocalAddr    string    `json:"local_addr"`
	RemoteAddr   string    `json:"remote_addr"`
	LocalPort    uint16    `json:"local_port"`
	RemotePort   uint16    `json:"remote_port"`
	State        string    `json:"state"`
	StartTime    time.Time `json:"start_time"`
	LastActivity time.Time `json:"last_activity"`

	// 流量统计
	BytesSent       uint64 `json:"bytes_sent"`
	BytesReceived   uint64 `json:"bytes_received"`
	PacketsSent     uint64 `json:"packets_sent"`
	PacketsReceived uint64 `json:"packets_received"`

	// 关联进程
	ProcessPID  uint32 `json:"process_pid"`
	ProcessComm string `json:"process_comm"`

	// 安全信息
	ThreatLevel string       `json:"threat_level"`
	IOCMatches  []IOCMatch   `json:"ioc_matches"`
	GeoLocation *GeoLocation `json:"geo_location,omitempty"`
}

// FileContext 文件操作上下文
type FileContext struct {
	FilePath    string    `json:"file_path"`
	FileType    string    `json:"file_type"`
	FileSize    int64     `json:"file_size"`
	Permissions string    `json:"permissions"`
	Owner       string    `json:"owner"`
	Group       string    `json:"group"`
	CreatedAt   time.Time `json:"created_at"`
	ModifiedAt  time.Time `json:"modified_at"`
	AccessedAt  time.Time `json:"accessed_at"`

	// 操作历史
	Operations     []FileOperation `json:"operations"`
	AccessPatterns []AccessPattern `json:"access_patterns"`

	// 安全信息
	HashValues      map[string]string `json:"hash_values"`
	VirusScanResult *VirusScanResult  `json:"virus_scan_result,omitempty"`
	ThreatLevel     string            `json:"threat_level"`
	Quarantined     bool              `json:"quarantined"`
}

// AttackChain 攻击链
type AttackChain struct {
	ChainID    string    `json:"chain_id"`
	ID         string    `json:"id"`
	StartTime  time.Time `json:"start_time"`
	LastUpdate time.Time `json:"last_update"`
	Status     string    `json:"status"`
	Severity   string    `json:"severity"`

	// 攻击阶段
	Stages       []AttackStage `json:"stages"`
	CurrentStage string        `json:"current_stage"`

	// 关联实体
	InvolvedProcesses []uint32 `json:"involved_processes"`
	InvolvedFiles     []string `json:"involved_files"`
	InvolvedNetworks  []string `json:"involved_networks"`

	// MITRE ATT&CK 映射
	Techniques []MITRETechnique `json:"techniques"`
	Tactics    []string         `json:"tactics"`

	// 威胁情报
	ThreatActor string     `json:"threat_actor,omitempty"`
	Campaign    string     `json:"campaign,omitempty"`
	IOCs        []IOCMatch `json:"iocs"`

	// 影响评估
	ImpactScore     float64 `json:"impact_score"`
	ConfidenceScore float64 `json:"confidence_score"`
	RiskLevel       string  `json:"risk_level"`

	// 关联的告警
	Alerts []string `json:"alerts"`
}

// 辅助数据结构
type FileOperation struct {
	Operation  string                 `json:"operation"`
	FilePath   string                 `json:"file_path"`
	Timestamp  time.Time              `json:"timestamp"`
	ProcessPID uint32                 `json:"process_pid"`
	Result     string                 `json:"result"`
	Details    map[string]interface{} `json:"details"`
}

type NetworkActivity struct {
	Activity   string    `json:"activity"`
	Protocol   string    `json:"protocol"`
	RemoteAddr string    `json:"remote_addr"`
	RemotePort uint16    `json:"remote_port"`
	Timestamp  time.Time `json:"timestamp"`
	DataSize   uint64    `json:"data_size"`
	Direction  string    `json:"direction"`
}

type SystemCallInfo struct {
	SyscallName string        `json:"syscall_name"`
	SyscallID   uint32        `json:"syscall_id"`
	Arguments   []interface{} `json:"arguments"`
	ReturnValue int64         `json:"return_value"`
	Timestamp   time.Time     `json:"timestamp"`
	Duration    time.Duration `json:"duration"`
}

type SecurityEvent struct {
	EventType   string                 `json:"event_type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	RuleName    string                 `json:"rule_name"`
	Evidence    map[string]interface{} `json:"evidence"`
}

type ThreatIndicator struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Confidence  float64   `json:"confidence"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
}

type AccessPattern struct {
	Pattern     string    `json:"pattern"`
	Frequency   int       `json:"frequency"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ProcessPIDs []uint32  `json:"process_pids"`
}

type VirusScanResult struct {
	Scanner    string    `json:"scanner"`
	ScanTime   time.Time `json:"scan_time"`
	Result     string    `json:"result"`
	ThreatName string    `json:"threat_name,omitempty"`
	Confidence float64   `json:"confidence"`
}

type AttackStage struct {
	Stage       string            `json:"stage"`
	Technique   string            `json:"technique"`
	Description string            `json:"description"`
	StartTime   time.Time         `json:"start_time"`
	EndTime     *time.Time        `json:"end_time,omitempty"`
	Events      []string          `json:"events"`
	Indicators  []ThreatIndicator `json:"indicators"`
}

type MITRETechnique struct {
	TechniqueID   string   `json:"technique_id"`
	TechniqueName string   `json:"technique_name"`
	Tactic        string   `json:"tactic"`
	Description   string   `json:"description"`
	Confidence    float64  `json:"confidence"`
	Evidence      []string `json:"evidence"`
}

type IOCMatch struct {
	IOCType    string    `json:"ioc_type"`
	IOCValue   string    `json:"ioc_value"`
	MatchType  string    `json:"match_type"`
	Confidence float64   `json:"confidence"`
	Source     string    `json:"source"`
	Timestamp  time.Time `json:"timestamp"`
}

type GeoLocation struct {
	Country      string  `json:"country"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	ISP          string  `json:"isp"`
	Organization string  `json:"organization"`
}

// EventContextConfig 事件上下文配置
type EventContextConfig struct {
	// 存储配置
	MaxProcessContexts int `yaml:"max_process_contexts"`
	MaxNetworkContexts int `yaml:"max_network_contexts"`
	MaxFileContexts    int `yaml:"max_file_contexts"`
	MaxAttackChains    int `yaml:"max_attack_chains"`

	// 保留时间
	ProcessContextTTL time.Duration `yaml:"process_context_ttl"`
	NetworkContextTTL time.Duration `yaml:"network_context_ttl"`
	FileContextTTL    time.Duration `yaml:"file_context_ttl"`
	AttackChainTTL    time.Duration `yaml:"attack_chain_ttl"`

	// 持久化配置
	EnablePersistence bool          `yaml:"enable_persistence"`
	StoragePath       string        `yaml:"storage_path"`
	FlushInterval     time.Duration `yaml:"flush_interval"`

	// 分析配置
	EnableAttackChainDetection bool          `yaml:"enable_attack_chain_detection"`
	AttackChainTimeout         time.Duration `yaml:"attack_chain_timeout"`
	MinChainEvents             int           `yaml:"min_chain_events"`

	// 威胁情报配置
	EnableThreatIntel  bool          `yaml:"enable_threat_intel"`
	ThreatIntelSources []string      `yaml:"threat_intel_sources"`
	IOCUpdateInterval  time.Duration `yaml:"ioc_update_interval"`
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

// readPPIDFromProc 通过读取 /proc/<pid>/status 获取父进程 PPID（Linux 环境兜底）
// 若不在 Linux 或读取失败，返回 0 不影响正常流程
func readPPIDFromProc(pid uint32) (uint32, error) {
    // Windows/非 Linux 环境可能不存在 /proc；打开失败直接返回
    path := fmt.Sprintf("/proc/%d/status", pid)
    f, err := os.Open(path)
    if err != nil {
        return 0, err
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()
        if strings.HasPrefix(line, "PPid:") {
            fields := strings.Fields(line)
            if len(fields) >= 2 {
                v, err := strconv.Atoi(fields[1])
                if err == nil && v >= 0 {
                    return uint32(v), nil
                }
            }
            break
        }
    }
    if err := scanner.Err(); err != nil {
        return 0, err
    }
    return 0, fmt.Errorf("PPid not found in status")
}

// UpdateProcessContext 更新进程上下文
func (ec *EventContext) UpdateProcessContext(event *EventJSON) {
    ec.mutex.Lock()
    defer ec.mutex.Unlock()

	ctx, exists := ec.processContexts[event.PID]
	if !exists {
		ctx = &ProcessContext{
			PID:              event.PID,
			PPID:             event.PPID,
			UID:              event.UID,
			GID:              event.GID,
			Comm:             event.Comm,
			Cmdline:          event.Cmdline,
			StartTime:        time.Now(),
			FileOperations:   make([]FileOperation, 0),
			NetworkActivity:  make([]NetworkActivity, 0),
			SystemCalls:      make([]SystemCallInfo, 0),
			ChildProcesses:   make([]uint32, 0),
			Privileges:       make([]string, 0),
			SecurityEvents:   make([]SecurityEvent, 0),
			ThreatIndicators: make([]ThreatIndicator, 0),
			Labels:           make(map[string]string),
			Annotations:      make(map[string]interface{}),
		}
		ec.processContexts[event.PID] = ctx
    }

    ctx.LastActivity = time.Now()

    // 事件缺少命令行且上下文已有，进行回填，增强可读性
    if event.Cmdline == "" && ctx.Cmdline != "" {
        event.Cmdline = ctx.Cmdline
    }

    // PPID 兜底与回填逻辑：优先使用已有上下文，其次事件值，最后尝试从 /proc 读取
    if ctx.PPID == 0 || event.PPID == 0 {
        var candidate uint32
        // 优先已有上下文
        if ctx.PPID != 0 {
            candidate = ctx.PPID
        } else if event.PPID != 0 {
            candidate = event.PPID
        } else {
            if ppid, err := readPPIDFromProc(event.PID); err == nil && ppid != 0 {
                candidate = ppid
            }
        }
        if candidate != 0 {
            if ctx.PPID == 0 {
                ctx.PPID = candidate
            }
            if event.PPID == 0 {
                event.PPID = candidate
            }
        }
    }

    // 维护父子进程映射，增强链路关联能力
    if event.PPID != 0 {
        if parentCtx, ok := ec.processContexts[event.PPID]; ok {
            // 去重追加子进程
            found := false
            for _, child := range parentCtx.ChildProcesses {
                if child == event.PID {
                    found = true
                    break
                }
            }
            if !found {
                parentCtx.ChildProcesses = append(parentCtx.ChildProcesses, event.PID)
            }
            parentCtx.LastActivity = time.Now()
        }
    }

	// 根据事件类型更新上下文
	switch event.EventType {
	case "execve":
		// 优先使用事件中的 cmdline；若无，则回退到文件名
		if event.Cmdline != "" {
			ctx.Cmdline = event.Cmdline
		} else if event.Filename != "" {
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
    // 允许仅有Dst或仅有Src的典型事件（connect常见仅Dst；bind常见仅Src）
    if event.DstAddr == nil && event.SrcAddr == nil {
        return
    }

    ec.mutex.Lock()
    defer ec.mutex.Unlock()

    // 连接ID：尽量稳定，优先使用完整地址；缺失时以pid与问号占位避免冲突
    localIP := "?"
    localPort := uint16(0)
    remoteIP := "?"
    remotePort := uint16(0)
    if event.SrcAddr != nil {
        localIP = event.SrcAddr.IP
        localPort = event.SrcAddr.Port
    }
    if event.DstAddr != nil {
        remoteIP = event.DstAddr.IP
        remotePort = event.DstAddr.Port
    }
    connID := fmt.Sprintf("pid:%d %s:%d->%s:%d", event.PID, localIP, localPort, remoteIP, remotePort)

    ctx, exists := ec.networkContexts[connID]
    if !exists {
        ctx = &NetworkContext{
            ConnectionID: connID,
            Protocol:     "tcp",
            LocalAddr:    localIP,
            RemoteAddr:   remoteIP,
            LocalPort:    localPort,
            RemotePort:   remotePort,
            State:        "observed",
            StartTime:    time.Now(),
            ProcessPID:   event.PID,
            ProcessComm:  event.Comm,
            ThreatLevel:  "unknown",
            IOCMatches:   make([]IOCMatch, 0),
        }
        ec.networkContexts[connID] = ctx
    } else {
        // 回填可能缺失的地址
        if ctx.LocalAddr == "?" && event.SrcAddr != nil {
            ctx.LocalAddr = event.SrcAddr.IP
            ctx.LocalPort = event.SrcAddr.Port
        }
        if ctx.RemoteAddr == "?" && event.DstAddr != nil {
            ctx.RemoteAddr = event.DstAddr.IP
            ctx.RemotePort = event.DstAddr.Port
        }
    }

    ctx.LastActivity = time.Now()

    // 更新连接状态
    switch event.EventType {
    case "connect":
        ctx.State = "connected"
    case "bind":
        ctx.State = "bound"
    case "listen":
        ctx.State = "listening"
    case "accept":
        ctx.State = "accepted"
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

    // 如果没有找到相关攻击链：
    // - 有告警则创建新链；
    // - 无告警则仅返回，不创建新链（避免噪声事件泛滥生成链）。
    if relatedChain == nil {
        if alert == nil {
            return
        }
        chainID := fmt.Sprintf("chain_%d_%s", event.PID, time.Now().Format("20060102150405"))
        relatedChain = &AttackChain{
            ChainID: chainID,
            ID:      chainID,
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

    // 关联网络：同时考虑目标地址与本地地址
    if event.DstAddr != nil {
        networkID := fmt.Sprintf("%s:%d", event.DstAddr.IP, event.DstAddr.Port)
        for _, network := range relatedChain.InvolvedNetworks {
            if network == networkID {
                goto skipNetworkDst
            }
        }
        relatedChain.InvolvedNetworks = append(relatedChain.InvolvedNetworks, networkID)
    skipNetworkDst:
    }
    if event.SrcAddr != nil {
        networkID := fmt.Sprintf("%s:%d", event.SrcAddr.IP, event.SrcAddr.Port)
        for _, network := range relatedChain.InvolvedNetworks {
            if network == networkID {
                goto skipNetworkSrc
            }
        }
        relatedChain.InvolvedNetworks = append(relatedChain.InvolvedNetworks, networkID)
    skipNetworkSrc:
    }

    // 当无告警时不进行技术映射，以减少误报噪声
    if alert != nil {
        technique := ec.mapToMITRETechnique(event, alert)
        if technique != nil {
            relatedChain.Techniques = append(relatedChain.Techniques, *technique)
        }
    }

    // 更新攻击阶段
    stage := ec.determineAttackStage(event, alert)
    if stage != relatedChain.CurrentStage {
        // 无告警时，Technique/Description使用事件类型与通用描述
        tech := ""
        desc := ""
        if alert != nil {
            tech = alert.RuleName
            desc = alert.Description
        } else {
            tech = event.EventType
            desc = "事件观察"
        }
        newStage := AttackStage{
            Stage:       stage,
            Technique:   tech,
            Description: desc,
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

    // 检查网络关联（目标或本地）
    if event.DstAddr != nil {
        networkID := fmt.Sprintf("%s:%d", event.DstAddr.IP, event.DstAddr.Port)
        for _, network := range chain.InvolvedNetworks {
            if network == networkID {
                return true
            }
        }
    }
    if event.SrcAddr != nil {
        networkID := fmt.Sprintf("%s:%d", event.SrcAddr.IP, event.SrcAddr.Port)
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
    // 无告警时不做技术映射
    if alert == nil {
        return nil
    }
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
		// 类别同义词映射
		"network_monitoring": {
			TechniqueID:   "T1071",
			TechniqueName: "Application Layer Protocol",
			Tactic:        "Command and Control",
			Description:   "Network activity indicative of command and control",
			Confidence:    0.7,
		},
		"command_and_control": {
			TechniqueID:   "T1071",
			TechniqueName: "Application Layer Protocol",
			Tactic:        "Command and Control",
			Description:   "C2 communication detected",
			Confidence:    0.7,
		},
		"command_control": {
			TechniqueID:   "T1071",
			TechniqueName: "Application Layer Protocol",
			Tactic:        "Command and Control",
			Description:   "C2 communication (synonym)",
			Confidence:    0.7,
		},
		"execution_detection": {
			TechniqueID:   "T1059",
			TechniqueName: "Command and Scripting Interpreter",
			Tactic:        "Execution",
			Description:   "Execution behavior detected",
			Confidence:    0.8,
		},
		"process_monitoring": {
			TechniqueID:   "T1059",
			TechniqueName: "Command and Scripting Interpreter",
			Tactic:        "Execution",
			Description:   "Process-related execution behavior",
			Confidence:    0.7,
		},
		"file_monitoring": {
			TechniqueID:   "T1005",
			TechniqueName: "Data from Local System",
			Tactic:        "Collection",
			Description:   "Suspicious file activity indicative of collection",
			Confidence:    0.6,
		},
		"data_exfiltration": {
			TechniqueID:   "T1041",
			TechniqueName: "Exfiltration Over C2 Channel",
			Tactic:        "Exfiltration",
			Description:   "Potential data exfiltration detected",
			Confidence:    0.7,
		},
		"permission_changes": {
			TechniqueID:   "T1068",
			TechniqueName: "Exploitation for Privilege Escalation",
			Tactic:        "Privilege Escalation",
			Description:   "Permission changes related to privilege escalation",
			Confidence:    0.75,
		},
		"memory_protection": {
			TechniqueID:   "T1027",
			TechniqueName: "Obfuscated/Compressed Files and Information",
			Tactic:        "Defense Evasion",
			Description:   "Memory protection changes possibly used for evasion",
			Confidence:    0.6,
		},
		"code_injection": {
			TechniqueID:   "T1055",
			TechniqueName: "Process Injection",
			Tactic:        "Execution",
			Description:   "Potential code injection behavior",
			Confidence:    0.8,
		},
	}

	if technique, exists := techniqueMap[alert.Category]; exists {
		technique.Evidence = []string{fmt.Sprintf("Event: %s, PID: %d", event.EventType, event.PID)}
		return &technique
	}

	// 事件类型回退映射（当类别未覆盖或缺失时）
	var fallbackKey string
	switch event.EventType {
	case "connect", "accept", "sendto", "recvfrom":
		fallbackKey = "network_connection"
	case "execve":
		fallbackKey = "suspicious_execve"
	case "setuid", "setgid", "chmod", "chown":
		fallbackKey = "privilege_escalation"
	case "mmap", "mprotect":
		fallbackKey = "code_injection"
	case "openat", "read", "write", "unlink", "rename":
		fallbackKey = "file_monitoring"
	}

	if fallbackKey != "" {
		if technique, exists := techniqueMap[fallbackKey]; exists {
			technique.Evidence = []string{fmt.Sprintf("Event: %s, PID: %d", event.EventType, event.PID)}
			return &technique
		}
	}

	return nil
}

func (ec *EventContext) determineAttackStage(event *EventJSON, alert *AlertEvent) string {
    // 根据项目“事后取证与损失评估”的检测重点，使用更贴近的中文阶段
    // 优先使用规则类别，其次回退到事件类型判断
    if alert != nil {
        switch alert.Category {
        // 外联通信 / 指挥与控制
        case "command_and_control", "network_monitoring", "command_control":
            return "外联通信"
        // 执行行为（进程执行/脚本执行）
        case "execution", "execution_detection", "process_monitoring":
            return "执行行为"
        // 持久化（服务、定时任务、启动项、钥匙）
        case "persistence":
            return "持久化"
        // 权限变更（提权/所有权/权限位调整）
        case "privilege_escalation", "permission_changes":
            return "权限变更"
        // 防御规避（内存保护、混淆、关闭安全进程等）
        case "defense_evasion", "memory_protection":
            return "防御规避"
        // 凭据访问
        case "credential_access":
            return "凭据访问"
        // 探索/信息收集
        case "discovery":
            return "探索行为"
        // 横向移动
        case "lateral_movement":
            return "横向移动"
        // 数据收集/文件操作
        case "collection", "file_monitoring":
            return "文件操作"
        // 数据外泄
        case "exfiltration", "data_exfiltration":
            return "数据外泄"
        // 影响/破坏
        case "impact":
            return "破坏清理"
        }
    }

	// 类别未知时，按事件类型回退映射
	switch event.EventType {
	case "connect", "accept", "sendto", "recvfrom":
		return "外联通信"
	case "bind", "listen":
		return "后门服务"
	case "execve":
		return "执行行为"
	case "exit", "fork", "clone":
		return "执行行为"
	case "setuid", "setgid", "chmod", "chown":
		return "权限变更"
	case "openat", "read", "write", "unlink", "rename", "close":
		return "文件操作"
	case "mmap", "mprotect", "ptrace":
		return "内存/注入"
	case "kill":
		return "破坏清理"
	}

	return "未知阶段"
}

func (ec *EventContext) calculateImpactScore(chain *AttackChain) float64 {
	score := 0.0

	// 基于涉及的进程数量
	score += float64(len(chain.InvolvedProcesses)) * 0.1

	// 基于涉及的文件数量
	score += float64(len(chain.InvolvedFiles)) * 0.05

	// 基于涉及的网络连接数量
	score += float64(len(chain.InvolvedNetworks)) * 0.15

	// 引入阶段权重（更贴近损失评估），按唯一阶段求和
	stageWeights := map[string]float64{
		"数据外泄":  1.2,
		"持久化":   1.0,
		"权限变更":  1.0,
		"破坏清理":  1.1,
		"横向移动":  0.9,
		"凭据访问":  0.9,
		"内存/注入": 0.8,
		"后门服务":  0.8,
		"防御规避":  0.6,
		"执行行为":  0.5,
		"外联通信":  0.4,
		"文件操作":  0.3,
		"探索行为":  0.2,
	}
	seenStages := make(map[string]struct{})
	stageScore := 0.0
	for _, st := range chain.Stages {
		if _, ok := seenStages[st.Stage]; ok {
			continue
		}
		seenStages[st.Stage] = struct{}{}
		if w, ok := stageWeights[st.Stage]; ok {
			stageScore += w
		} else {
			// 未知阶段给予较低权重
			stageScore += 0.2
		}
	}
	// 阶段权重整体缩放，避免过高，同时兼容旧逻辑
	score += stageScore * 0.5

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
