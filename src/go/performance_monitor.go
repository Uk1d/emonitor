package main

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"
)

// PerformanceMonitor 性能监控器
type PerformanceMonitor struct {
	ruleEngine    *EnhancedRuleEngine
	startTime     time.Time
	lastReportTime time.Time
	
	// 监控统计
	totalEvents   uint64
	totalAlerts   uint64
	totalErrors   uint64
	
	// 性能指标
	avgProcessingTime time.Duration
	peakMemoryUsage   uint64
	currentMemoryUsage uint64
	
	// 规则性能统计
	rulePerformance map[string]*RulePerformanceMetrics
	
	mutex sync.RWMutex
}

// RulePerformanceMetrics 规则性能指标
type RulePerformanceMetrics struct {
	RuleName        string        `json:"rule_name"`
	TotalMatches    uint64        `json:"total_matches"`
	SuccessMatches  uint64        `json:"success_matches"`
	AvgMatchTime    time.Duration `json:"avg_match_time"`
	MinMatchTime    time.Duration `json:"min_match_time"`
	MaxMatchTime    time.Duration `json:"max_match_time"`
	LastMatchTime   time.Time     `json:"last_match_time"`
	ErrorCount      uint64        `json:"error_count"`
	MatchRate       float64       `json:"match_rate"`
}

// PerformanceReport 性能报告
type PerformanceReport struct {
	Timestamp         time.Time                          `json:"timestamp"`
	Uptime           time.Duration                      `json:"uptime"`
	TotalEvents      uint64                             `json:"total_events"`
	TotalAlerts      uint64                             `json:"total_alerts"`
	TotalErrors      uint64                             `json:"total_errors"`
	AlertRate        float64                            `json:"alert_rate"`
	EventsPerSecond  float64                            `json:"events_per_second"`
	AlertsPerSecond  float64                            `json:"alerts_per_second"`
	AvgProcessingTime time.Duration                     `json:"avg_processing_time"`
	MemoryUsage      uint64                             `json:"memory_usage_mb"`
	PeakMemoryUsage  uint64                             `json:"peak_memory_usage_mb"`
	RuleMetrics      map[string]*RulePerformanceMetrics `json:"rule_metrics"`
	SystemMetrics    *SystemMetrics                     `json:"system_metrics"`
}

// SystemMetrics 系统指标
type SystemMetrics struct {
	CPUUsage        float64 `json:"cpu_usage_percent"`
	MemoryTotal     uint64  `json:"memory_total_mb"`
	MemoryUsed      uint64  `json:"memory_used_mb"`
	MemoryAvailable uint64  `json:"memory_available_mb"`
	GoroutineCount  int     `json:"goroutine_count"`
	GCCount         uint32  `json:"gc_count"`
	GCPauseTime     time.Duration `json:"gc_pause_time"`
}

// NewPerformanceMonitor 创建性能监控器
func NewPerformanceMonitor(ruleEngine *EnhancedRuleEngine) *PerformanceMonitor {
	return &PerformanceMonitor{
		ruleEngine:      ruleEngine,
		startTime:       time.Now(),
		lastReportTime:  time.Now(),
		rulePerformance: make(map[string]*RulePerformanceMetrics),
	}
}

// RecordEvent 记录事件处理
func (pm *PerformanceMonitor) RecordEvent(processingTime time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.totalEvents++
	
	// 更新平均处理时间
	if pm.totalEvents == 1 {
		pm.avgProcessingTime = processingTime
	} else {
		pm.avgProcessingTime = time.Duration(
			(int64(pm.avgProcessingTime)*int64(pm.totalEvents-1) + int64(processingTime)) / int64(pm.totalEvents),
		)
	}

	// 更新内存使用情况
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	pm.currentMemoryUsage = memStats.Alloc / (1024 * 1024) // MB
	if pm.currentMemoryUsage > pm.peakMemoryUsage {
		pm.peakMemoryUsage = pm.currentMemoryUsage
	}
}

// RecordAlert 记录告警生成
func (pm *PerformanceMonitor) RecordAlert(ruleName string, matchTime time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.totalAlerts++

	// 更新规则性能统计
	if metrics, exists := pm.rulePerformance[ruleName]; exists {
		metrics.TotalMatches++
		metrics.SuccessMatches++
		
		// 更新平均匹配时间
		if metrics.TotalMatches == 1 {
			metrics.AvgMatchTime = matchTime
			metrics.MinMatchTime = matchTime
			metrics.MaxMatchTime = matchTime
		} else {
			metrics.AvgMatchTime = time.Duration(
				(int64(metrics.AvgMatchTime)*int64(metrics.TotalMatches-1) + int64(matchTime)) / int64(metrics.TotalMatches),
			)
			if matchTime < metrics.MinMatchTime {
				metrics.MinMatchTime = matchTime
			}
			if matchTime > metrics.MaxMatchTime {
				metrics.MaxMatchTime = matchTime
			}
		}
		
		metrics.LastMatchTime = time.Now()
		metrics.MatchRate = float64(metrics.SuccessMatches) / float64(metrics.TotalMatches)
	} else {
		pm.rulePerformance[ruleName] = &RulePerformanceMetrics{
			RuleName:       ruleName,
			TotalMatches:   1,
			SuccessMatches: 1,
			AvgMatchTime:   matchTime,
			MinMatchTime:   matchTime,
			MaxMatchTime:   matchTime,
			LastMatchTime:  time.Now(),
			MatchRate:      1.0,
		}
	}
}

// RecordRuleExecution 记录规则执行（无论是否匹配）
func (pm *PerformanceMonitor) RecordRuleExecution(ruleName string, matchTime time.Duration, matched bool) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if metrics, exists := pm.rulePerformance[ruleName]; exists {
		metrics.TotalMatches++
		if matched {
			metrics.SuccessMatches++
		}
		
		// 更新时间统计
		if metrics.TotalMatches == 1 {
			metrics.AvgMatchTime = matchTime
			metrics.MinMatchTime = matchTime
			metrics.MaxMatchTime = matchTime
		} else {
			metrics.AvgMatchTime = time.Duration(
				(int64(metrics.AvgMatchTime)*int64(metrics.TotalMatches-1) + int64(matchTime)) / int64(metrics.TotalMatches),
			)
			if matchTime < metrics.MinMatchTime {
				metrics.MinMatchTime = matchTime
			}
			if matchTime > metrics.MaxMatchTime {
				metrics.MaxMatchTime = matchTime
			}
		}
		
		metrics.MatchRate = float64(metrics.SuccessMatches) / float64(metrics.TotalMatches)
	} else {
		successCount := uint64(0)
		if matched {
			successCount = 1
		}
		
		pm.rulePerformance[ruleName] = &RulePerformanceMetrics{
			RuleName:       ruleName,
			TotalMatches:   1,
			SuccessMatches: successCount,
			AvgMatchTime:   matchTime,
			MinMatchTime:   matchTime,
			MaxMatchTime:   matchTime,
			LastMatchTime:  time.Now(),
			MatchRate:      float64(successCount),
		}
	}
}

// RecordError 记录错误
func (pm *PerformanceMonitor) RecordError(ruleName string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.totalErrors++
	
	if metrics, exists := pm.rulePerformance[ruleName]; exists {
		metrics.ErrorCount++
	}
}

// GenerateReport 生成性能报告
func (pm *PerformanceMonitor) GenerateReport() *PerformanceReport {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	uptime := time.Since(pm.startTime)
	
	// 计算速率
	var eventsPerSecond, alertsPerSecond, alertRate float64
	if uptime.Seconds() > 0 {
		eventsPerSecond = float64(pm.totalEvents) / uptime.Seconds()
		alertsPerSecond = float64(pm.totalAlerts) / uptime.Seconds()
	}
	
	if pm.totalEvents > 0 {
		alertRate = float64(pm.totalAlerts) / float64(pm.totalEvents)
	}

	// 获取系统指标
	systemMetrics := pm.getSystemMetrics()

	// 复制规则性能指标
	ruleMetrics := make(map[string]*RulePerformanceMetrics)
	for name, metrics := range pm.rulePerformance {
		ruleMetrics[name] = &RulePerformanceMetrics{
			RuleName:       metrics.RuleName,
			TotalMatches:   metrics.TotalMatches,
			SuccessMatches: metrics.SuccessMatches,
			AvgMatchTime:   metrics.AvgMatchTime,
			MinMatchTime:   metrics.MinMatchTime,
			MaxMatchTime:   metrics.MaxMatchTime,
			LastMatchTime:  metrics.LastMatchTime,
			ErrorCount:     metrics.ErrorCount,
			MatchRate:      metrics.MatchRate,
		}
	}

	return &PerformanceReport{
		Timestamp:         time.Now(),
		Uptime:           uptime,
		TotalEvents:      pm.totalEvents,
		TotalAlerts:      pm.totalAlerts,
		TotalErrors:      pm.totalErrors,
		AlertRate:        alertRate,
		EventsPerSecond:  eventsPerSecond,
		AlertsPerSecond:  alertsPerSecond,
		AvgProcessingTime: pm.avgProcessingTime,
		MemoryUsage:      pm.currentMemoryUsage,
		PeakMemoryUsage:  pm.peakMemoryUsage,
		RuleMetrics:      ruleMetrics,
		SystemMetrics:    systemMetrics,
	}
}

// PrintReport 打印性能报告
func (pm *PerformanceMonitor) PrintReport() {
	report := pm.GenerateReport()
	
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("                    eTracee 性能监控报告")
	fmt.Println(strings.Repeat("=", 80))
	
	fmt.Printf("报告时间: %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("运行时间: %v\n", report.Uptime.Round(time.Second))
	fmt.Println(strings.Repeat("-", 80))
	
	// 事件统计
	fmt.Println("事件处理统计:")
	fmt.Printf("  总事件数: %d\n", report.TotalEvents)
	fmt.Printf("  总告警数: %d\n", report.TotalAlerts)
	fmt.Printf("  总错误数: %d\n", report.TotalErrors)
	fmt.Printf("  告警率: %.2f%%\n", report.AlertRate*100)
	fmt.Printf("  事件处理速率: %.2f 事件/秒\n", report.EventsPerSecond)
	fmt.Printf("  告警生成速率: %.2f 告警/秒\n", report.AlertsPerSecond)
	fmt.Printf("  平均处理时间: %v\n", report.AvgProcessingTime)
	fmt.Println(strings.Repeat("-", 80))
	
	// 内存使用
	fmt.Println("内存使用情况:")
	fmt.Printf("  当前内存使用: %d MB\n", report.MemoryUsage)
	fmt.Printf("  峰值内存使用: %d MB\n", report.PeakMemoryUsage)
	fmt.Printf("  系统总内存: %d MB\n", report.SystemMetrics.MemoryTotal)
	fmt.Printf("  系统可用内存: %d MB\n", report.SystemMetrics.MemoryAvailable)
	fmt.Println(strings.Repeat("-", 80))
	
	// 系统指标
	fmt.Println("系统性能指标:")
	fmt.Printf("  Goroutine 数量: %d\n", report.SystemMetrics.GoroutineCount)
	fmt.Printf("  GC 次数: %d\n", report.SystemMetrics.GCCount)
	fmt.Printf("  GC 暂停时间: %v\n", report.SystemMetrics.GCPauseTime)
	fmt.Println(strings.Repeat("-", 80))
	
	// 规则性能统计（显示前10个最活跃的规则）
	fmt.Println("规则性能统计 (Top 10):")
	fmt.Printf("%-25s %-10s %-10s %-12s %-10s %-10s\n", 
		"规则名称", "总执行", "成功匹配", "平均时间", "最小时间", "最大时间")
	
	count := 0
	for _, metrics := range report.RuleMetrics {
		if count >= 10 {
			break
		}
		fmt.Printf("%-25s %-10d %-10d %-12v %-10v %-10v\n",
			truncateString(metrics.RuleName, 24),
			metrics.TotalMatches,
			metrics.SuccessMatches,
			metrics.AvgMatchTime.Round(time.Microsecond),
			metrics.MinMatchTime.Round(time.Microsecond),
			metrics.MaxMatchTime.Round(time.Microsecond))
		count++
	}
	
	fmt.Println(strings.Repeat("=", 80))
}

// GetReportJSON 获取JSON格式的性能报告
func (pm *PerformanceMonitor) GetReportJSON() (string, error) {
	report := pm.GenerateReport()
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

// StartPeriodicReporting 启动定期报告
func (pm *PerformanceMonitor) StartPeriodicReporting(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			pm.PrintReport()
			pm.lastReportTime = time.Now()
		}
	}()
}

// Reset 重置统计数据
func (pm *PerformanceMonitor) Reset() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.totalEvents = 0
	pm.totalAlerts = 0
	pm.totalErrors = 0
	pm.avgProcessingTime = 0
	pm.peakMemoryUsage = 0
	pm.rulePerformance = make(map[string]*RulePerformanceMetrics)
	pm.startTime = time.Now()
	pm.lastReportTime = time.Now()
	
	log.Println("性能监控统计已重置")
}

// 私有方法

func (pm *PerformanceMonitor) getSystemMetrics() *SystemMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &SystemMetrics{
		CPUUsage:        0.0, // 简化实现
		MemoryTotal:     memStats.Sys / 1024 / 1024,
		MemoryUsed:      memStats.Alloc / 1024 / 1024,
		MemoryAvailable: (memStats.Sys - memStats.Alloc) / 1024 / 1024,
		GoroutineCount:  runtime.NumGoroutine(),
		GCCount:         memStats.NumGC,
		GCPauseTime:     time.Duration(memStats.PauseNs[(memStats.NumGC+255)%256]),
	}
}