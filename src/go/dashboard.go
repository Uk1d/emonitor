package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Dashboard 命令行仪表板
type Dashboard struct {
	mu         sync.RWMutex
	stats      *DashboardStats
	aggregator *AggregatedStats
	startTime  time.Time
	running    bool
}

// DashboardStats 仪表板统计数据
type DashboardStats struct {
	TotalEvents    uint64
	EventsPerSec   float64
	TopProcesses   []ProcessStat
	TopSyscalls    []SyscallStat
	RecentEvents   []EventSummary
	SecurityAlerts []SecurityAlert
	LastUpdate     time.Time
}

// ProcessStat 进程统计
type ProcessStat struct {
	PID      uint32
	Comm     string
	UID      uint32
	Count    uint64
	LastSeen time.Time
}

// SyscallStat 系统调用统计
type SyscallStat struct {
	SyscallID uint32
	Name      string
	Count     uint64
	LastSeen  time.Time
}

// EventSummary 事件摘要
type EventSummary struct {
	Timestamp string
	PID       uint32
	Comm      string
	EventType string
	Severity  string
}

// 全局Dashboard实例
var dashboard *Dashboard

// NewDashboard 创建新的仪表板实例
func NewDashboard() *Dashboard {
	return &Dashboard{
		stats: &DashboardStats{
			TopProcesses:   make([]ProcessStat, 0),
			TopSyscalls:    make([]SyscallStat, 0),
			RecentEvents:   make([]EventSummary, 0),
			SecurityAlerts: make([]SecurityAlert, 0),
		},
		aggregator: NewAggregatedStats(),
		startTime:  time.Now(),
		running:    false,
	}
}

// UpdateStats 更新统计数据
func (d *Dashboard) UpdateStats(event *EventJSON) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 更新聚合统计
	d.aggregator.UpdateStats(event)

	// 更新基础统计
	d.stats.TotalEvents++
	d.stats.LastUpdate = time.Now()

	// 计算每秒事件数
	duration := time.Since(d.startTime).Seconds()
	if duration > 0 {
		d.stats.EventsPerSec = float64(d.stats.TotalEvents) / duration
	}

	// 更新最近事件
	d.updateRecentEvents(event)

	// 从聚合器获取Top统计
	d.updateTopStats()
}

// updateRecentEvents 更新最近事件列表
func (d *Dashboard) updateRecentEvents(event *EventJSON) {
	summary := EventSummary{
		Timestamp: event.Timestamp,
		PID:       event.PID,
		Comm:      event.Comm,
		EventType: event.EventType,
		Severity:  event.Severity,
	}

	d.stats.RecentEvents = append([]EventSummary{summary}, d.stats.RecentEvents...)

	// 保持最近20个事件
	if len(d.stats.RecentEvents) > 20 {
		d.stats.RecentEvents = d.stats.RecentEvents[:20]
	}
}

// updateTopStats 从聚合器更新Top统计
func (d *Dashboard) updateTopStats() {
	aggStats := d.aggregator.GetStats()

	// 更新Top进程
	d.stats.TopProcesses = make([]ProcessStat, 0)
	for _, proc := range aggStats.TopProcesses {
		if len(d.stats.TopProcesses) >= 10 {
			break
		}
		d.stats.TopProcesses = append(d.stats.TopProcesses, ProcessStat{
			PID:      proc.PID,
			Comm:     proc.Comm,
			UID:      proc.UID,
			Count:    proc.Count,
			LastSeen: proc.LastSeen,
		})
	}

	// 更新Top系统调用
	d.stats.TopSyscalls = make([]SyscallStat, 0)
	for _, syscall := range aggStats.TopSyscalls {
		if len(d.stats.TopSyscalls) >= 10 {
			break
		}
		d.stats.TopSyscalls = append(d.stats.TopSyscalls, SyscallStat{
			SyscallID: syscall.SyscallID,
			Name:      syscall.Name,
			Count:     syscall.Count,
			LastSeen:  syscall.LastSeen,
		})
	}

	// 更新安全告警
	d.stats.SecurityAlerts = aggStats.SecurityAlerts
}

// GetStats 获取当前统计数据
func (d *Dashboard) GetStats() DashboardStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// 返回统计数据的副本
	stats := DashboardStats{
		TotalEvents:  d.stats.TotalEvents,
		EventsPerSec: d.stats.EventsPerSec,
		LastUpdate:   d.stats.LastUpdate,
	}

	// 复制切片数据
	stats.TopProcesses = make([]ProcessStat, len(d.stats.TopProcesses))
	copy(stats.TopProcesses, d.stats.TopProcesses)

	stats.TopSyscalls = make([]SyscallStat, len(d.stats.TopSyscalls))
	copy(stats.TopSyscalls, d.stats.TopSyscalls)

	stats.RecentEvents = make([]EventSummary, len(d.stats.RecentEvents))
	copy(stats.RecentEvents, d.stats.RecentEvents)

	stats.SecurityAlerts = make([]SecurityAlert, len(d.stats.SecurityAlerts))
	copy(stats.SecurityAlerts, d.stats.SecurityAlerts)

	return stats
}

// GetAggregatedStats 获取详细聚合统计
func (d *Dashboard) GetAggregatedStats() AggregatedStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.aggregator.GetStats()
}

// Start 启动仪表板显示
func (d *Dashboard) Start() {
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		d.mu.RLock()
		running := d.running
		d.mu.RUnlock()

		if !running {
			break
		}

		select {
		case <-ticker.C:
			d.display()
		}
	}
}

// Stop 停止仪表板
func (d *Dashboard) Stop() {
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
}

// clearScreen 清屏
func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

// display 显示仪表板
func (d *Dashboard) display() {
	clearScreen()

	stats := d.GetStats()
	aggStats := d.GetAggregatedStats()

	// 标题
    fmt.Println("==============================================================================")
    fmt.Println("|                            eTracee 实时监控仪表板                           |")
    fmt.Println("==============================================================================")
	fmt.Println()

	// 基础统计
	fmt.Printf("运行时间: %s | 总事件数: %d | 事件速率: %.2f/秒 | 最后更新: %s\n",
		formatDuration(time.Since(d.startTime)),
		stats.TotalEvents,
		stats.EventsPerSec,
		stats.LastUpdate.Format("15:04:05"))
	fmt.Println()

	// 分两列显示
	leftColumn := d.generateLeftColumn(stats, aggStats)
	rightColumn := d.generateRightColumn(stats, aggStats)

	d.displayTwoColumns(leftColumn, rightColumn)

	// 安全告警（如果有）
    if len(stats.SecurityAlerts) > 0 {
        fmt.Println("\n[!] 最近安全告警:")
        fmt.Println("+---------------------------------------------------------------------------+")
		for i, alert := range stats.SecurityAlerts {
			if i >= 5 {
				break
			}
			severity := alert.Severity
            if severity == "high" {
                severity = "[!] 高"
            } else if severity == "medium" {
                severity = "[*] 中"
            } else {
                severity = "[+] 低"
            }
            fmt.Printf("| %s %s | %s | PID:%d | %s\n",
                alert.Timestamp.Format("15:04:05"),
                severity,
                truncateString(alert.RuleMatched, 20),
                alert.PID,
                truncateString(alert.Comm, 15))
		}
        fmt.Println("+---------------------------------------------------------------------------+")
	}

	fmt.Println("\n按 Ctrl+C 退出仪表板模式")
}

// generateLeftColumn 生成左列内容
func (d *Dashboard) generateLeftColumn(stats DashboardStats, aggStats AggregatedStats) []string {
	var lines []string

	// Top进程
    lines = append(lines, "[*] Top 进程 (按事件数)")
    lines = append(lines, "+-------------------------------------+")
	for i, proc := range stats.TopProcesses {
		if i >= 8 {
			break
		}
        lines = append(lines, fmt.Sprintf("| %-15s %6d %8d |",
            truncateString(proc.Comm, 15), proc.PID, proc.Count))
	}
	for len(lines) < 11 {
        lines = append(lines, "|                                     |")
	}
    lines = append(lines, "+-------------------------------------+")

	lines = append(lines, "")

	// 事件类型分布
    lines = append(lines, "[*] 事件类型分布")
    lines = append(lines, "+-------------------------------------+")

	// 按数量排序事件类型
	type eventTypeCount struct {
		eventType string
		count     uint64
	}
	var eventTypes []eventTypeCount
	for eventType, count := range aggStats.EventsByType {
		eventTypes = append(eventTypes, eventTypeCount{eventType, count})
	}
	sort.Slice(eventTypes, func(i, j int) bool {
		return eventTypes[i].count > eventTypes[j].count
	})

	for i, et := range eventTypes {
		if i >= 8 {
			break
		}
		percentage := float64(et.count) / float64(stats.TotalEvents) * 100
        lines = append(lines, fmt.Sprintf("| %-20s %6d %5.1f%% |",
            truncateString(et.eventType, 20), et.count, percentage))
	}
	for len(lines) < 23 {
    lines = append(lines, "|                                     |")
	}
	lines = append(lines, "+-------------------------------------+")

	return lines
}

// generateRightColumn 生成右列内容
func (d *Dashboard) generateRightColumn(stats DashboardStats, aggStats AggregatedStats) []string {
	var lines []string

	// Top系统调用
    lines = append(lines, "[*] Top 系统调用")
    lines = append(lines, "+-------------------------------------+")
	for i, syscall := range stats.TopSyscalls {
		if i >= 8 {
			break
		}
        lines = append(lines, fmt.Sprintf("| %-20s %10d |",
            truncateString(syscall.Name, 20), syscall.Count))
	}
	for len(lines) < 11 {
        lines = append(lines, "|                                     |")
	}
    lines = append(lines, "+-------------------------------------+")

	lines = append(lines, "")

	// 最近事件
    lines = append(lines, "[*] 最近事件")
    lines = append(lines, "+-------------------------------------+")
	for i, event := range stats.RecentEvents {
		if i >= 8 {
			break
		}
		severity := ""
		if event.Severity != "" {
            if event.Severity == "high" {
                severity = "[!]"
            } else if event.Severity == "medium" {
                severity = "[*]"
            } else {
                severity = "[+]"
            }
		}
		timestamp := ""
		if len(event.Timestamp) >= 8 {
			timestamp = event.Timestamp[11:19] // 提取时间部分
		}
        lines = append(lines, fmt.Sprintf("|%s %s %s %6d %-10s |",
            severity,
            timestamp,
            truncateString(event.EventType, 12),
            event.PID,
            truncateString(event.Comm, 10)))
	}
	for len(lines) < 23 {
        lines = append(lines, "|                                     |")
	}
    lines = append(lines, "+-------------------------------------+")

	return lines
}

// displayTwoColumns 显示两列内容
func (d *Dashboard) displayTwoColumns(leftColumn, rightColumn []string) {
	maxLines := len(leftColumn)
	if len(rightColumn) > maxLines {
		maxLines = len(rightColumn)
	}

	for i := 0; i < maxLines; i++ {
		left := ""
		right := ""

		if i < len(leftColumn) {
			left = leftColumn[i]
		}
		if i < len(rightColumn) {
			right = rightColumn[i]
		}

		// 确保左列宽度为39字符
		if len(left) < 39 {
			left = left + strings.Repeat(" ", 39-len(left))
		}

		fmt.Printf("%s  %s\n", left, right)
	}
}

// 格式化持续时间
func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	} else {
		return fmt.Sprintf("%ds", seconds)
	}
}

// truncateString 截断字符串
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// 简化版Dashboard显示（用于非交互模式）
func displaySimpleDashboard() {
	if dashboard == nil {
		fmt.Println("Dashboard not initialized")
		return
	}
	
	stats := dashboard.GetStats()
	uptime := time.Since(dashboard.startTime)
	
	fmt.Printf("\n=== eTracee 监控统计 ===\n")
	fmt.Printf("运行时间: %s\n", formatDuration(uptime))
	fmt.Printf("总事件数: %d\n", stats.TotalEvents)
	fmt.Printf("安全告警: %d\n", len(stats.SecurityAlerts))
	fmt.Printf("事件速率: %.2f events/sec\n", stats.EventsPerSec)
	
	if len(stats.TopProcesses) > 0 {
		fmt.Printf("\nTop 3 进程:\n")
		for i, proc := range stats.TopProcesses {
			if i >= 3 {
				break
			}
			fmt.Printf("  %d. %s: %d events\n", i+1, proc.Comm, proc.Count)
		}
	}
	
	if len(stats.TopSyscalls) > 0 {
		fmt.Printf("\nTop 3 系统调用:\n")
		for i, syscall := range stats.TopSyscalls {
			if i >= 3 {
				break
			}
			fmt.Printf("  %d. %s: %d events\n", i+1, syscall.Name, syscall.Count)
		}
	}
	fmt.Printf("========================\n\n")
}