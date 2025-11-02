package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// AggregatedStats 聚合统计数据结构
type AggregatedStats struct {
	mu                sync.RWMutex
	StartTime         time.Time
	TotalEvents       uint64
	EventsByType      map[string]uint64
	EventsByUID       map[uint32]uint64
	EventsByPID       map[uint32]uint64
	EventsByComm      map[string]uint64
	EventsBySeverity  map[string]uint64
	EventsByHour      map[int]uint64
	TopProcesses      []ProcessAggregation
	TopSyscalls       []SyscallAggregation
	TopUsers          []UserAggregation
	SecurityAlerts    []SecurityAlert
	NetworkConnections []NetworkConnection
	FileOperations    []FileOperationAggregation
	LastUpdate        time.Time
}

// ProcessAggregation 进程聚合统计
type ProcessAggregation struct {
	PID       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	UID       uint32 `json:"uid"`
	Count     uint64 `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
	EventTypes map[string]uint64 `json:"event_types"`
}

// SyscallAggregation 系统调用聚合统计
type SyscallAggregation struct {
	SyscallID uint32 `json:"syscall_id"`
	Name      string `json:"name"`
	Count     uint64 `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
	Processes map[string]uint64 `json:"processes"`
}

// UserAggregation 用户聚合统计
type UserAggregation struct {
	UID       uint32 `json:"uid"`
	Count     uint64 `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
	Processes map[string]uint64 `json:"processes"`
}

// SecurityAlert 安全告警
type SecurityAlert struct {
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`
	RuleMatched string    `json:"rule_matched"`
	PID         uint32    `json:"pid"`
	Comm        string    `json:"comm"`
	UID         uint32    `json:"uid"`
	EventType   string    `json:"event_type"`
	Description string    `json:"description"`
}

// NetworkConnection 网络连接统计
type NetworkConnection struct {
	SrcIP     string    `json:"src_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstIP     string    `json:"dst_ip"`
	DstPort   uint16    `json:"dst_port"`
	Count     uint64    `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Processes map[string]uint64 `json:"processes"`
}

// FileOperationAggregation 用于聚合文件操作统计
type FileOperationAggregation struct {
	Filename  string    `json:"filename"`
	Operation string    `json:"operation"`
	Count     uint64    `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Processes map[string]uint64 `json:"processes"`
}

// NewAggregatedStats 创建新的聚合统计实例
func NewAggregatedStats() *AggregatedStats {
	return &AggregatedStats{
		StartTime:         time.Now(),
		EventsByType:      make(map[string]uint64),
		EventsByUID:       make(map[uint32]uint64),
		EventsByPID:       make(map[uint32]uint64),
		EventsByComm:      make(map[string]uint64),
		EventsBySeverity:  make(map[string]uint64),
		EventsByHour:      make(map[int]uint64),
		TopProcesses:      make([]ProcessAggregation, 0),
		TopSyscalls:       make([]SyscallAggregation, 0),
		TopUsers:          make([]UserAggregation, 0),
		SecurityAlerts:    make([]SecurityAlert, 0),
		NetworkConnections: make([]NetworkConnection, 0),
		FileOperations:    make([]FileOperationAggregation, 0),
		LastUpdate:        time.Now(),
	}
}

// UpdateStats 更新聚合统计
func (as *AggregatedStats) UpdateStats(event *EventJSON) {
	as.mu.Lock()
	defer as.mu.Unlock()

	now := time.Now()
	as.TotalEvents++
	as.LastUpdate = now

	// 按事件类型统计
	as.EventsByType[event.EventType]++

	// 按用户ID统计
	as.EventsByUID[event.UID]++

	// 按进程ID统计
	as.EventsByPID[event.PID]++

	// 按进程名统计
	as.EventsByComm[event.Comm]++

	// 按严重程度统计
	if event.Severity != "" {
		as.EventsBySeverity[event.Severity]++
	}

	// 按小时统计
	hour := now.Hour()
	as.EventsByHour[hour]++

	// 更新进程聚合统计
	as.updateProcessAggregation(event, now)

	// 更新系统调用聚合统计
	as.updateSyscallAggregation(event, now)

	// 更新用户聚合统计
	as.updateUserAggregation(event, now)

	// 记录安全告警
	if event.Severity != "" && event.RuleMatched != "" {
		as.recordSecurityAlert(event, now)
	}

	// 记录网络连接
	if event.SrcAddr != nil && event.DstAddr != nil {
		as.recordNetworkConnection(event, now)
	}

	// 记录文件操作
	if event.Filename != "" {
		as.recordFileOperation(event, now)
	}
}

// updateProcessAggregation 更新进程聚合统计
func (as *AggregatedStats) updateProcessAggregation(event *EventJSON, now time.Time) {
	found := false
	for i := range as.TopProcesses {
		if as.TopProcesses[i].PID == event.PID && as.TopProcesses[i].Comm == event.Comm {
			as.TopProcesses[i].Count++
			as.TopProcesses[i].LastSeen = now
			if as.TopProcesses[i].EventTypes == nil {
				as.TopProcesses[i].EventTypes = make(map[string]uint64)
			}
			as.TopProcesses[i].EventTypes[event.EventType]++
			found = true
			break
		}
	}

	if !found {
		newProcess := ProcessAggregation{
			PID:        event.PID,
			Comm:       event.Comm,
			UID:        event.UID,
			Count:      1,
			LastSeen:   now,
			EventTypes: map[string]uint64{event.EventType: 1},
		}
		as.TopProcesses = append(as.TopProcesses, newProcess)
	}

	// 保持Top 20进程
	if len(as.TopProcesses) > 20 {
		sort.Slice(as.TopProcesses, func(i, j int) bool {
			return as.TopProcesses[i].Count > as.TopProcesses[j].Count
		})
		as.TopProcesses = as.TopProcesses[:20]
	}
}

// updateSyscallAggregation 更新系统调用聚合统计
func (as *AggregatedStats) updateSyscallAggregation(event *EventJSON, now time.Time) {
	found := false
	for i := range as.TopSyscalls {
		if as.TopSyscalls[i].SyscallID == event.SyscallID {
			as.TopSyscalls[i].Count++
			as.TopSyscalls[i].LastSeen = now
			if as.TopSyscalls[i].Processes == nil {
				as.TopSyscalls[i].Processes = make(map[string]uint64)
			}
			as.TopSyscalls[i].Processes[event.Comm]++
			found = true
			break
		}
	}

	if !found {
		newSyscall := SyscallAggregation{
			SyscallID: event.SyscallID,
			Name:      getSyscallName(event.SyscallID),
			Count:     1,
			LastSeen:  now,
			Processes: map[string]uint64{event.Comm: 1},
		}
		as.TopSyscalls = append(as.TopSyscalls, newSyscall)
	}

	// 保持Top 15系统调用
	if len(as.TopSyscalls) > 15 {
		sort.Slice(as.TopSyscalls, func(i, j int) bool {
			return as.TopSyscalls[i].Count > as.TopSyscalls[j].Count
		})
		as.TopSyscalls = as.TopSyscalls[:15]
	}
}

// updateUserAggregation 更新用户聚合统计
func (as *AggregatedStats) updateUserAggregation(event *EventJSON, now time.Time) {
	found := false
	for i := range as.TopUsers {
		if as.TopUsers[i].UID == event.UID {
			as.TopUsers[i].Count++
			as.TopUsers[i].LastSeen = now
			if as.TopUsers[i].Processes == nil {
				as.TopUsers[i].Processes = make(map[string]uint64)
			}
			as.TopUsers[i].Processes[event.Comm]++
			found = true
			break
		}
	}

	if !found {
		newUser := UserAggregation{
			UID:       event.UID,
			Count:     1,
			LastSeen:  now,
			Processes: map[string]uint64{event.Comm: 1},
		}
		as.TopUsers = append(as.TopUsers, newUser)
	}

	// 保持Top 10用户
	if len(as.TopUsers) > 10 {
		sort.Slice(as.TopUsers, func(i, j int) bool {
			return as.TopUsers[i].Count > as.TopUsers[j].Count
		})
		as.TopUsers = as.TopUsers[:10]
	}
}

// recordSecurityAlert 记录安全告警
func (as *AggregatedStats) recordSecurityAlert(event *EventJSON, now time.Time) {
	alert := SecurityAlert{
		Timestamp:   now,
		Severity:    event.Severity,
		RuleMatched: event.RuleMatched,
		PID:         event.PID,
		Comm:        event.Comm,
		UID:         event.UID,
		EventType:   event.EventType,
		Description: generateAlertDescription(event),
	}

	as.SecurityAlerts = append(as.SecurityAlerts, alert)

	// 保持最近100个告警
	if len(as.SecurityAlerts) > 100 {
		as.SecurityAlerts = as.SecurityAlerts[len(as.SecurityAlerts)-100:]
	}
}

// recordNetworkConnection 记录网络连接
func (as *AggregatedStats) recordNetworkConnection(event *EventJSON, now time.Time) {
	if event.SrcAddr == nil || event.DstAddr == nil {
		return
	}

	found := false
	for i := range as.NetworkConnections {
		if as.NetworkConnections[i].SrcIP == event.SrcAddr.IP &&
			as.NetworkConnections[i].SrcPort == event.SrcAddr.Port &&
			as.NetworkConnections[i].DstIP == event.DstAddr.IP &&
			as.NetworkConnections[i].DstPort == event.DstAddr.Port {
			as.NetworkConnections[i].Count++
			as.NetworkConnections[i].LastSeen = now
			if as.NetworkConnections[i].Processes == nil {
				as.NetworkConnections[i].Processes = make(map[string]uint64)
			}
			as.NetworkConnections[i].Processes[event.Comm]++
			found = true
			break
		}
	}

	if !found {
		newConn := NetworkConnection{
			SrcIP:     event.SrcAddr.IP,
			SrcPort:   event.SrcAddr.Port,
			DstIP:     event.DstAddr.IP,
			DstPort:   event.DstAddr.Port,
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
			Processes: map[string]uint64{event.Comm: 1},
		}
		as.NetworkConnections = append(as.NetworkConnections, newConn)
	}

	// 保持最近50个连接
	if len(as.NetworkConnections) > 50 {
		sort.Slice(as.NetworkConnections, func(i, j int) bool {
			return as.NetworkConnections[i].LastSeen.After(as.NetworkConnections[j].LastSeen)
		})
		as.NetworkConnections = as.NetworkConnections[:50]
	}
}

// recordFileOperation 记录文件操作
func (as *AggregatedStats) recordFileOperation(event *EventJSON, now time.Time) {
	operation := getFileOperation(event.EventType)
	if operation == "" {
		return
	}

	found := false
	for i := range as.FileOperations {
		if as.FileOperations[i].Filename == event.Filename &&
			as.FileOperations[i].Operation == operation {
			as.FileOperations[i].Count++
			as.FileOperations[i].LastSeen = now
			if as.FileOperations[i].Processes == nil {
				as.FileOperations[i].Processes = make(map[string]uint64)
			}
			as.FileOperations[i].Processes[event.Comm]++
			found = true
			break
		}
	}

	if !found {
		newOp := FileOperationAggregation{
			Filename:  event.Filename,
			Operation: operation,
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
			Processes: map[string]uint64{event.Comm: 1},
		}
		as.FileOperations = append(as.FileOperations, newOp)
	}

	// 保持最近100个文件操作
	if len(as.FileOperations) > 100 {
		sort.Slice(as.FileOperations, func(i, j int) bool {
			return as.FileOperations[i].LastSeen.After(as.FileOperations[j].LastSeen)
		})
		as.FileOperations = as.FileOperations[:100]
	}
}

// GetStats 获取聚合统计数据（只读）
func (as *AggregatedStats) GetStats() AggregatedStats {
	as.mu.RLock()
	defer as.mu.RUnlock()

	// 创建副本以避免并发访问问题
	stats := AggregatedStats{
		StartTime:        as.StartTime,
		TotalEvents:      as.TotalEvents,
		EventsByType:     make(map[string]uint64),
		EventsByUID:      make(map[uint32]uint64),
		EventsByPID:      make(map[uint32]uint64),
		EventsByComm:     make(map[string]uint64),
		EventsBySeverity: make(map[string]uint64),
		EventsByHour:     make(map[int]uint64),
		LastUpdate:       as.LastUpdate,
	}

	// 复制map数据
	for k, v := range as.EventsByType {
		stats.EventsByType[k] = v
	}
	for k, v := range as.EventsByUID {
		stats.EventsByUID[k] = v
	}
	for k, v := range as.EventsByPID {
		stats.EventsByPID[k] = v
	}
	for k, v := range as.EventsByComm {
		stats.EventsByComm[k] = v
	}
	for k, v := range as.EventsBySeverity {
		stats.EventsBySeverity[k] = v
	}
	for k, v := range as.EventsByHour {
		stats.EventsByHour[k] = v
	}

	// 复制切片数据
	stats.TopProcesses = make([]ProcessAggregation, len(as.TopProcesses))
	copy(stats.TopProcesses, as.TopProcesses)

	stats.TopSyscalls = make([]SyscallAggregation, len(as.TopSyscalls))
	copy(stats.TopSyscalls, as.TopSyscalls)

	stats.TopUsers = make([]UserAggregation, len(as.TopUsers))
	copy(stats.TopUsers, as.TopUsers)

	stats.SecurityAlerts = make([]SecurityAlert, len(as.SecurityAlerts))
	copy(stats.SecurityAlerts, as.SecurityAlerts)

	stats.NetworkConnections = make([]NetworkConnection, len(as.NetworkConnections))
	copy(stats.NetworkConnections, as.NetworkConnections)

	stats.FileOperations = make([]FileOperationAggregation, len(as.FileOperations))
	copy(stats.FileOperations, as.FileOperations)

	return stats
}

// getSyscallName 获取系统调用名称
func getSyscallName(syscallID uint32) string {
	syscallNames := map[uint32]string{
		1:   "sys_exit",
		2:   "sys_fork",
		3:   "sys_read",
		4:   "sys_write",
		5:   "sys_open",
		6:   "sys_close",
		11:  "sys_execve",
		56:  "sys_clone",
		257: "sys_openat",
		262: "sys_newfstatat",
		263: "sys_unlinkat",
		264: "sys_renameat",
		268: "sys_fchownat",
		269: "sys_fchmodat",
		42:  "sys_connect",
		43:  "sys_accept",
		44:  "sys_sendto",
		45:  "sys_recvfrom",
		49:  "sys_bind",
		50:  "sys_listen",
	}

	if name, exists := syscallNames[syscallID]; exists {
		return name
	}
	return "unknown"
}

// generateAlertDescription 生成告警描述
func generateAlertDescription(event *EventJSON) string {
	return fmt.Sprintf("进程 %s (PID: %d, UID: %d) 触发安全规则: %s",
		event.Comm, event.PID, event.UID, event.RuleMatched)
}

// getFileOperation 获取文件操作类型
func getFileOperation(eventType string) string {
	switch eventType {
	case "EVENT_OPENAT":
		return "open"
	case "EVENT_CLOSE":
		return "close"
	case "EVENT_READ":
		return "read"
	case "EVENT_WRITE":
		return "write"
	case "EVENT_UNLINK":
		return "delete"
	case "EVENT_RENAME":
		return "rename"
	case "EVENT_CHMOD":
		return "chmod"
	case "EVENT_CHOWN":
		return "chown"
	default:
		return ""
	}
}