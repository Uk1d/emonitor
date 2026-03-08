package main

import (
	"fmt"
	"log"
	"math"
	"sort"
	"sync"
	"time"
)

// AIDetector AI 异常检测器
// 使用统计方法和规则引擎结合的轻量级异常检测
type AIDetector struct {
	mu sync.RWMutex

	// 配置
	config *AIDetectorConfig

	// 统计数据
	statistics map[uint32]*ProcessStatistics
	networkStats map[string]*NetworkStatistics

	// 异常分数历史
	anomalyHistory map[uint32][]float64

	// 基线数据
	baselines *BaselineData

	// 检测到的异常
	detectedAnomalies []Anomaly
}

// AIDetectorConfig AI 检测器配置
type AIDetectorConfig struct {
	// 统计窗口配置
	StatisticsWindow      time.Duration // 统计时间窗口
	MinSamplesForBaseline int           // 计算基线所需的最小样本数

	// 异常检测阈值
	ProcessRateAnomalyThreshold    float64 // 进程创建速率异常阈值（标准差倍数）
	NetworkConnectionRateThreshold float64 // 网络连接速率异常阈值
	FileAccessRateThreshold       float64 // 文件访问速率异常阈值

	// 异常分数阈值
	AnomalyScoreThreshold float64 // 异常分数阈值（0-1）
	HighRiskThreshold    float64 // 高风险阈值
	CriticalThreshold    float64 // 严重风险阈值

	// 历史数据保留
	MaxHistorySize int // 最大历史记录数量
}

// BaselineData 基线数据
type BaselineData struct {
	// 进程基线
	AverageProcessRate    float64
	ProcessRateStdDev     float64
	CommonProcessNames    map[string]int
	CommonExecutionPaths  map[string]int

	// 网络基线
	AverageConnectionRate float64
	ConnectionRateStdDev  float64
	CommonRemoteHosts    map[string]int
	CommonRemotePorts    map[int]int

	// 文件基线
	AverageFileAccessRate float64
	FileAccessRateStdDev  float64
	SensitiveFileAccess   map[string]int

	// 更新时间
	LastUpdated time.Time
}

// ProcessStatistics 进程统计信息
type ProcessStatistics struct {
	PID                 uint32
	Comm                string
	StartTime           time.Time
	LastActivity        time.Time

	// 行为统计
	ExecCount          int
	FileReadCount      int
	FileWriteCount     int
	FileDeleteCount    int
	NetConnectCount    int
	NetAcceptCount     int
	NetBindCount       int

	// 系统调用统计
	SyscallStats       map[string]int

	// 资源使用
	FilesAccessed      []string
	NetworkConnections []AIConnInfo
	ChildProcesses     []uint32
}

// NetworkStatistics 网络统计信息
type NetworkStatistics struct {
	ConnectionID       string
	RemoteAddr        string
	RemotePort        uint16
	Protocol          string
	FirstSeen         time.Time
	LastSeen          time.Time

	BytesSent         uint64
	BytesReceived     uint64
	PacketsSent       uint64
	PacketsReceived   uint64

	ConnectionCount   int
	DataTransferCount  int
}

// AIConnInfo AI 连接信息
type AIConnInfo struct {
	RemoteAddr string
	RemotePort uint16
	Protocol   string
	StartTime time.Time
}

// Anomaly 异常事件
type Anomaly struct {
	ID             string
	Type           AnomalyType
	Severity       string
	Confidence     float64
	Description    string
	DetectedAt     time.Time

	// 关联信息
	PID            uint32
	ProcessName    string
	Category       string

	// 证据
	Evidence       []AnomalyEvidence

	// AI 分析结果
	AnomalyScore   float64
	ContributingFactors map[string]float64
}

// AnomalyType 异常类型
type AnomalyType string

const (
	AnomalyTypeProcessBehavior   AnomalyType = "process_behavior"
	AnomalyTypeNetworkActivity  AnomalyType = "network_activity"
	AnomalyTypeFileActivity     AnomalyType = "file_activity"
	AnomalyTypePrivilegeEscalation AnomalyType = "privilege_escalation"
	AnomalyTypeInjection       AnomalyType = "injection"
	AnomalyTypePersistence     AnomalyType = "persistence"
	AnomalyTypeDataExfiltration AnomalyType = "data_exfiltration"
)

// AnomalyEvidence 异常证据
type AnomalyEvidence struct {
	Type      string
	Value     interface{}
	Timestamp time.Time
	Context   string
}

// NewAIDetector 创建 AI 异常检测器
func NewAIDetector(config *AIDetectorConfig) *AIDetector {
	if config == nil {
		config = &AIDetectorConfig{
			StatisticsWindow:            5 * time.Minute,
			MinSamplesForBaseline:      100,
			ProcessRateAnomalyThreshold: 3.0,
			NetworkConnectionRateThreshold: 3.0,
			FileAccessRateThreshold:     3.0,
			AnomalyScoreThreshold:      0.7,
			HighRiskThreshold:           0.8,
			CriticalThreshold:           0.9,
			MaxHistorySize:             1000,
		}
	}

	return &AIDetector{
		config:            config,
		statistics:        make(map[uint32]*ProcessStatistics),
		networkStats:      make(map[string]*NetworkStatistics),
		anomalyHistory:    make(map[uint32][]float64),
		baselines:         &BaselineData{
			CommonProcessNames:   make(map[string]int),
			CommonExecutionPaths: make(map[string]int),
			CommonRemoteHosts:   make(map[string]int),
			CommonRemotePorts:   make(map[int]int),
			SensitiveFileAccess: make(map[string]int),
		},
		detectedAnomalies: make([]Anomaly, 0),
	}
}

// ProcessEvent 处理事件进行异常检测
func (ai *AIDetector) ProcessEvent(event *EventJSON) *Anomaly {
	ai.mu.Lock()
	defer ai.mu.Unlock()

	// 更新统计信息
	ai.updateStatistics(event)

	// 检查基线是否建立
	if time.Since(ai.baselines.LastUpdated) < ai.config.StatisticsWindow &&
		ai.config.MinSamplesForBaseline > 0 {
		// 基线已建立，执行异常检测
		anomaly := ai.detectAnomaly(event)
		if anomaly != nil {
			ai.recordAnomaly(anomaly)
		}
		return anomaly
	}

	return nil
}

// updateStatistics 更新事件统计信息
func (ai *AIDetector) updateStatistics(event *EventJSON) {
	// 获取或创建进程统计
	stats, exists := ai.statistics[event.PID]
	if !exists {
		stats = &ProcessStatistics{
			PID:             event.PID,
			Comm:            event.Comm,
			StartTime:       time.Now(),
			LastActivity:    time.Now(),
			SyscallStats:    make(map[string]int),
			FilesAccessed:   make([]string, 0),
			NetworkConnections: make([]AIConnInfo, 0),
			ChildProcesses:   make([]uint32, 0),
		}
		ai.statistics[event.PID] = stats
	}

	stats.LastActivity = time.Now()

	// 根据事件类型更新统计
	switch event.EventType {
	case "execve", "execveat":
		stats.ExecCount++
	case "openat", "read":
		stats.FileReadCount++
	case "write":
		stats.FileWriteCount++
	case "unlink":
		stats.FileDeleteCount++
	case "connect":
		stats.NetConnectCount++
	case "accept":
		stats.NetAcceptCount++
	case "bind":
		stats.NetBindCount++
	}

	// 记录系统调用
	stats.SyscallStats[event.EventType]++

	// 记录文件访问
	if event.Filename != "" {
		found := false
		for _, f := range stats.FilesAccessed {
			if f == event.Filename {
				found = true
				break
			}
		}
		if !found && len(stats.FilesAccessed) < 100 {
			stats.FilesAccessed = append(stats.FilesAccessed, event.Filename)
		}
	}

	// 记录网络连接
	if event.DstAddr != nil {
		conn := AIConnInfo{
			RemoteAddr: event.DstAddr.IP,
			RemotePort: event.DstAddr.Port,
			Protocol:   "tcp",
			StartTime:  time.Now(),
		}
		stats.NetworkConnections = append(stats.NetworkConnections, conn)
	}
}

// detectAnomaly 检测异常
func (ai *AIDetector) detectAnomaly(event *EventJSON) *Anomaly {
	anomalyScore := 0.0
	factors := make(map[string]float64)
	evidences := make([]AnomalyEvidence, 0)

	stats := ai.statistics[event.PID]
	if stats == nil {
		return nil
	}

	// 1. 检测进程行为异常
	if factor, evidence := ai.checkProcessBehavior(stats, event); factor > 0 {
		factors["process_behavior"] = factor
		anomalyScore += factor * 0.3
		evidences = append(evidences, evidence...)
	}

	// 2. 检测网络活动异常
	if factor, evidence := ai.checkNetworkActivity(stats, event); factor > 0 {
		factors["network_activity"] = factor
		anomalyScore += factor * 0.25
		evidences = append(evidences, evidence...)
	}

	// 3. 检测文件活动异常
	if factor, evidence := ai.checkFileActivity(stats, event); factor > 0 {
		factors["file_activity"] = factor
		anomalyScore += factor * 0.25
		evidences = append(evidences, evidence...)
	}

	// 4. 检测权限变更异常
	if factor, evidence := ai.checkPrivilegeChange(event); factor > 0 {
		factors["privilege_change"] = factor
		anomalyScore += factor * 0.2
		evidences = append(evidences, evidence...)
	}

	// 如果异常分数超过阈值，创建异常
	if anomalyScore >= ai.config.AnomalyScoreThreshold {
		severity := "low"
		if anomalyScore >= ai.config.CriticalThreshold {
			severity = "critical"
		} else if anomalyScore >= ai.config.HighRiskThreshold {
			severity = "high"
		} else if anomalyScore >= 0.75 {
			severity = "medium"
		}

		anomalyType := ai.determineAnomalyType(factors)
		description := ai.generateAnomalyDescription(anomalyType, factors)

		anomaly := &Anomaly{
			ID:                 generateAnomalyID(),
			Type:               anomalyType,
			Severity:           severity,
			Confidence:         anomalyScore,
			Description:        description,
			DetectedAt:         time.Now(),
			PID:                event.PID,
			ProcessName:        event.Comm,
			Category:           ai.getCategoryForType(anomalyType),
			Evidence:           evidences,
			AnomalyScore:       anomalyScore,
			ContributingFactors: factors,
		}

		return anomaly
	}

	return nil
}

// checkProcessBehavior 检测进程行为异常
func (ai *AIDetector) checkProcessBehavior(stats *ProcessStatistics, event *EventJSON) (float64, []AnomalyEvidence) {
	score := 0.0
	evidences := make([]AnomalyEvidence, 0)

	// 检查异常的系统调用组合
	if stats.SyscallStats["execve"] > 10 && stats.SyscallStats["connect"] > 5 {
		score += 0.6
		evidences = append(evidences, AnomalyEvidence{
			Type:      "high_exec_rate",
			Value:     stats.SyscallStats["execve"],
			Timestamp: time.Now(),
			Context:   "进程频繁执行",
		})
	}

	// 检查可疑的进程名
	suspiciousNames := map[string]bool{
		".":      true,
		"null":    true,
		"random":  true,
		"unknown": true,
	}
	if suspiciousNames[stats.Comm] {
		score += 0.8
		evidences = append(evidences, AnomalyEvidence{
			Type:      "suspicious_name",
			Value:     stats.Comm,
			Timestamp: time.Now(),
			Context:   "可疑进程名",
		})
	}

	return score, evidences
}

// checkNetworkActivity 检测网络活动异常
func (ai *AIDetector) checkNetworkActivity(stats *ProcessStatistics, event *EventJSON) (float64, []AnomalyEvidence) {
	score := 0.0
	evidences := make([]AnomalyEvidence, 0)

	// 检查过多的连接
	if stats.NetConnectCount > 20 {
		score += 0.7
		evidences = append(evidences, AnomalyEvidence{
			Type:      "excessive_connections",
			Value:     stats.NetConnectCount,
			Timestamp: time.Now(),
			Context:   "过多的网络连接",
		})
	}

	// 检查连接到非常见端口
	suspiciousPorts := map[uint16]bool{
		4444: true, 5555: true, 6666: true,
		31337: true, 1337: true, 1234: true,
	}
	if event.DstAddr != nil && suspiciousPorts[event.DstAddr.Port] {
		score += 0.5
		evidences = append(evidences, AnomalyEvidence{
			Type:      "suspicious_port",
			Value:     event.DstAddr.Port,
			Timestamp: time.Now(),
			Context:   "连接到可疑端口",
		})
	}

	return score, evidences
}

// checkFileActivity 检测文件活动异常
func (ai *AIDetector) checkFileActivity(stats *ProcessStatistics, event *EventJSON) (float64, []AnomalyEvidence) {
	score := 0.0
	evidences := make([]AnomalyEvidence, 0)

	// 检查敏感文件访问
	sensitiveFiles := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/root/.ssh/", "/home/.ssh/",
		"/var/log/auth.log", "/var/log/secure",
	}
	if event.Filename != "" {
		for _, sensitive := range sensitiveFiles {
			if len(event.Filename) >= len(sensitive) &&
				event.Filename[:len(sensitive)] == sensitive {
				score += 0.9
				evidences = append(evidences, AnomalyEvidence{
					Type:      "sensitive_file_access",
					Value:     event.Filename,
					Timestamp: time.Now(),
					Context:   "访问敏感文件",
				})
				break
			}
		}
	}

	// 检查频繁的文件删除
	if stats.FileDeleteCount > 10 {
		score += 0.5
		evidences = append(evidences, AnomalyEvidence{
			Type:      "excessive_file_deletion",
			Value:     stats.FileDeleteCount,
			Timestamp: time.Now(),
			Context:   "频繁删除文件",
		})
	}

	return score, evidences
}

// checkPrivilegeChange 检测权限变更异常
func (ai *AIDetector) checkPrivilegeChange(event *EventJSON) (float64, []AnomalyEvidence) {
	score := 0.0
	evidences := make([]AnomalyEvidence, 0)

	// 检查可疑的权限变更
	if event.EventType == "setuid" || event.EventType == "setgid" {
		if event.NewUID != 0 && event.NewUID != event.UID {
			score += 0.8
			evidences = append(evidences, AnomalyEvidence{
				Type:      "privilege_escalation",
				Value:     map[string]uint32{"old": event.UID, "new": event.NewUID},
				Timestamp: time.Now(),
				Context:   "权限提升",
			})
		}
	}

	return score, evidences
}

// determineAnomalyType 确定异常类型
func (ai *AIDetector) determineAnomalyType(factors map[string]float64) AnomalyType {
	maxFactor := 0.0
	var resultType AnomalyType

	for factorType, factorValue := range factors {
		if factorValue > maxFactor {
			maxFactor = factorValue
			switch factorType {
			case "process_behavior":
				resultType = AnomalyTypeProcessBehavior
			case "network_activity":
				resultType = AnomalyTypeNetworkActivity
			case "file_activity":
				resultType = AnomalyTypeFileActivity
			case "privilege_change":
				resultType = AnomalyTypePrivilegeEscalation
			}
		}
	}

	return resultType
}

// getCategoryForType 获取异常类型对应的类别
func (ai *AIDetector) getCategoryForType(anomalyType AnomalyType) string {
	switch anomalyType {
	case AnomalyTypeProcessBehavior:
		return "process"
	case AnomalyTypeNetworkActivity:
		return "network"
	case AnomalyTypeFileActivity:
		return "file"
	case AnomalyTypePrivilegeEscalation:
		return "permission"
	case AnomalyTypeInjection:
		return "memory"
	case AnomalyTypePersistence:
		return "system"
	case AnomalyTypeDataExfiltration:
		return "network"
	default:
		return "unknown"
	}
}

// generateAnomalyDescription 生成异常描述
func (ai *AIDetector) generateAnomalyDescription(anomalyType AnomalyType, factors map[string]float64) string {
	switch anomalyType {
	case AnomalyTypeProcessBehavior:
		return "检测到异常的进程行为模式"
	case AnomalyTypeNetworkActivity:
		return "检测到异常的网络活动"
	case AnomalyTypeFileActivity:
		return "检测到异常的文件访问行为"
	case AnomalyTypePrivilegeEscalation:
		return "检测到权限提升行为"
	case AnomalyTypeInjection:
		return "检测到潜在的代码注入行为"
	case AnomalyTypePersistence:
		return "检测到持久化机制尝试"
	case AnomalyTypeDataExfiltration:
		return "检测到潜在的数据外泄行为"
	default:
		return "检测到异常行为"
	}
}

// recordAnomaly 记录异常
func (ai *AIDetector) recordAnomaly(anomaly *Anomaly) {
	// 添加到历史记录
	ai.detectedAnomalies = append(ai.detectedAnomalies, *anomaly)

	// 添加到进程异常历史
	if _, exists := ai.anomalyHistory[anomaly.PID]; !exists {
		ai.anomalyHistory[anomaly.PID] = make([]float64, 0)
	}
	ai.anomalyHistory[anomaly.PID] = append(ai.anomalyHistory[anomaly.PID], anomaly.AnomalyScore)

	// 限制历史记录大小
	if len(ai.detectedAnomalies) > ai.config.MaxHistorySize {
		ai.detectedAnomalies = ai.detectedAnomalies[1:]
	}

	log.Printf("[AI] 检测到异常: ID=%s, Type=%s, Score=%.2f, PID=%d",
		anomaly.ID, anomaly.Type, anomaly.Confidence, anomaly.PID)
}

// UpdateBaselines 更新基线数据
func (ai *AIDetector) UpdateBaselines() {
	ai.mu.Lock()
	defer ai.mu.Unlock()

	if len(ai.statistics) < ai.config.MinSamplesForBaseline {
		return
	}

	// 计算进程行为基线
	totalExecCount := 0
	processNameCounts := make(map[string]int)
	for _, stats := range ai.statistics {
		totalExecCount += stats.ExecCount
		processNameCounts[stats.Comm]++
	}

	// 计算平均值和标准差
	avgProcessRate := float64(totalExecCount) / float64(len(ai.statistics))
	variance := 0.0
	for _, stats := range ai.statistics {
		diff := float64(stats.ExecCount) - avgProcessRate
		variance += diff * diff
	}
	stdDev := math.Sqrt(variance / float64(len(ai.statistics)))

	// 更新基线
	ai.baselines.AverageProcessRate = avgProcessRate
	ai.baselines.ProcessRateStdDev = stdDev
	ai.baselines.CommonProcessNames = processNameCounts
	ai.baselines.LastUpdated = time.Now()

	log.Printf("[AI] 基线已更新: 平均进程速率=%.2f, 标准差=%.2f",
		avgProcessRate, stdDev)
}

// GetAnomalyScore 获取进程的异常分数
func (ai *AIDetector) GetAnomalyScore(pid uint32) float64 {
	ai.mu.RLock()
	defer ai.mu.RUnlock()

	history, exists := ai.anomalyHistory[pid]
	if !exists || len(history) == 0 {
		return 0.0
	}

	// 返回最近的最大异常分数
	maxScore := 0.0
	for _, score := range history {
		if score > maxScore {
			maxScore = score
		}
	}
	return maxScore
}

// GetRecentAnomalies 获取最近的异常
func (ai *AIDetector) GetRecentAnomalies(limit int) []Anomaly {
	ai.mu.RLock()
	defer ai.mu.RUnlock()

	anomalies := make([]Anomaly, len(ai.detectedAnomalies))
	copy(anomalies, ai.detectedAnomalies)

	// 按时间倒序排序
	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].DetectedAt.After(anomalies[j].DetectedAt)
	})

	if limit > 0 && limit < len(anomalies) {
		return anomalies[:limit]
	}
	return anomalies
}

// ClearOldStatistics 清理旧的统计数据
func (ai *AIDetector) ClearOldStatistics() {
	ai.mu.Lock()
	defer ai.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-30 * time.Minute)

	for pid, stats := range ai.statistics {
		if stats.LastActivity.Before(cutoff) {
			delete(ai.statistics, pid)
			delete(ai.anomalyHistory, pid)
		}
	}
}

// generateAnomalyID 生成异常 ID
func generateAnomalyID() string {
	return fmt.Sprintf("anomaly_%d", time.Now().UnixNano())
}
