package main

import (
	"sync"
	"time"
	"runtime"
	"log"
	"strings"
)

// PerformanceOptimizer 性能优化器
type PerformanceOptimizer struct {
	// 规则索引缓存
	ruleIndexCache map[string]*RuleIndex
	cacheMutex     sync.RWMutex
	
	// 性能统计
	stats          *PerformanceStats
	statsMutex     sync.RWMutex
	
	// 内存池
	eventPool      sync.Pool
	alertPool      sync.Pool
	
	// 配置参数
	config         *OptimizerConfig
}

// RuleIndex 规则索引结构
type RuleIndex struct {
	EventTypeRules map[string][]int  // 按事件类型索引的规则
	FieldRules     map[string][]int  // 按字段索引的规则
	SeverityRules  map[string][]int  // 按严重级别索引的规则
	LastUpdated    time.Time         // 最后更新时间
}

// PerformanceStats 性能统计
type PerformanceStats struct {
	TotalMatches       uint64        // 总匹配次数
	SuccessfulMatches  uint64        // 成功匹配次数
	AverageMatchTime   time.Duration // 平均匹配时间
	CacheHitRate       float64       // 缓存命中率
	MemoryUsage        uint64        // 内存使用量
	LastResetTime      time.Time     // 最后重置时间
	
	// 详细统计
	MatchTimeHistogram map[string]uint64 // 匹配时间直方图
	RuleHitCount       map[string]uint64 // 规则命中计数
}

// OptimizerConfig 优化器配置
type OptimizerConfig struct {
	EnableIndexing     bool          // 启用索引
	EnableCaching      bool          // 启用缓存
	EnablePooling      bool          // 启用对象池
	CacheExpireTime    time.Duration // 缓存过期时间
	MaxCacheSize       int           // 最大缓存大小
	StatsResetInterval time.Duration // 统计重置间隔
	MemoryThreshold    uint64        // 内存阈值（字节）
}

// NewPerformanceOptimizer 创建性能优化器
func NewPerformanceOptimizer(config *OptimizerConfig) *PerformanceOptimizer {
	if config == nil {
		config = &OptimizerConfig{
			EnableIndexing:     true,
			EnableCaching:      true,
			EnablePooling:      true,
			CacheExpireTime:    5 * time.Minute,
			MaxCacheSize:       1000,
			StatsResetInterval: 1 * time.Hour,
			MemoryThreshold:    100 * 1024 * 1024, // 100MB
		}
	}

	optimizer := &PerformanceOptimizer{
		ruleIndexCache: make(map[string]*RuleIndex),
		config:         config,
		stats: &PerformanceStats{
			MatchTimeHistogram: make(map[string]uint64),
			RuleHitCount:       make(map[string]uint64),
			LastResetTime:      time.Now(),
		},
	}

	// 初始化对象池
	if config.EnablePooling {
		optimizer.eventPool = sync.Pool{
			New: func() interface{} {
				return &EventJSON{}
			},
		}
		optimizer.alertPool = sync.Pool{
			New: func() interface{} {
				return &AlertEvent{}
			},
		}
	}

	// 启动统计重置定时器
	go optimizer.startStatsResetTimer()

	return optimizer
}

// BuildRuleIndex 构建规则索引
func (po *PerformanceOptimizer) BuildRuleIndex(rules []EnhancedDetectionRule) *RuleIndex {
	index := &RuleIndex{
		EventTypeRules: make(map[string][]int),
		FieldRules:     make(map[string][]int),
		SeverityRules:  make(map[string][]int),
		LastUpdated:    time.Now(),
	}

	for i, rule := range rules {
		// 按严重级别索引
		index.SeverityRules[rule.Severity] = append(index.SeverityRules[rule.Severity], i)

		// 按条件字段索引
		for _, condition := range rule.Conditions {
			if field, ok := condition["field"].(string); ok {
				index.FieldRules[field] = append(index.FieldRules[field], i)
			}
		}

		// 按事件类型索引（如果规则中包含事件类型条件）
		for _, condition := range rule.Conditions {
			if field, ok := condition["field"].(string); ok && field == "event_type" {
				if eventType, ok := condition["value"].(string); ok {
					index.EventTypeRules[eventType] = append(index.EventTypeRules[eventType], i)
				}
			}
		}
	}

	return index
}

// GetOptimizedRuleSet 获取优化的规则集
func (po *PerformanceOptimizer) GetOptimizedRuleSet(event *EventJSON, rules []EnhancedDetectionRule) []int {
	if !po.config.EnableIndexing {
		// 如果未启用索引，返回所有规则
		result := make([]int, len(rules))
		for i := range rules {
			result[i] = i
		}
		return result
	}

	// 尝试从缓存获取索引
	cacheKey := po.generateCacheKey(event)
	po.cacheMutex.RLock()
	index, exists := po.ruleIndexCache[cacheKey]
	po.cacheMutex.RUnlock()

	if !exists || time.Since(index.LastUpdated) > po.config.CacheExpireTime {
		// 重新构建索引
		index = po.BuildRuleIndex(rules)
		
		po.cacheMutex.Lock()
		po.ruleIndexCache[cacheKey] = index
		// 清理过期缓存
		po.cleanExpiredCache()
		po.cacheMutex.Unlock()
	}

	// 根据事件特征选择相关规则
	relevantRules := make(map[int]bool)

	// 按事件类型筛选
	if eventTypeRules, ok := index.EventTypeRules[event.EventType]; ok {
		for _, ruleIdx := range eventTypeRules {
			relevantRules[ruleIdx] = true
		}
	}

	// 按字段筛选
	eventFields := po.extractEventFields(event)
	for field := range eventFields {
		if fieldRules, ok := index.FieldRules[field]; ok {
			for _, ruleIdx := range fieldRules {
				relevantRules[ruleIdx] = true
			}
		}
	}

	// 如果没有找到相关规则，返回所有规则
	if len(relevantRules) == 0 {
		result := make([]int, len(rules))
		for i := range rules {
			result[i] = i
		}
		return result
	}

	// 转换为切片
	result := make([]int, 0, len(relevantRules))
	for ruleIdx := range relevantRules {
		result = append(result, ruleIdx)
	}

	return result
}

// RecordMatchPerformance 记录匹配性能
func (po *PerformanceOptimizer) RecordMatchPerformance(duration time.Duration, success bool, ruleName string) {
	po.statsMutex.Lock()
	defer po.statsMutex.Unlock()

	po.stats.TotalMatches++
	if success {
		po.stats.SuccessfulMatches++
		po.stats.RuleHitCount[ruleName]++
	}

	// 更新平均匹配时间
	if po.stats.TotalMatches == 1 {
		po.stats.AverageMatchTime = duration
	} else {
		po.stats.AverageMatchTime = time.Duration(
			(int64(po.stats.AverageMatchTime)*int64(po.stats.TotalMatches-1) + int64(duration)) / int64(po.stats.TotalMatches),
		)
	}

	// 更新时间直方图
	timeRange := po.getTimeRange(duration)
	po.stats.MatchTimeHistogram[timeRange]++
}

// GetPerformanceStats 获取性能统计
func (po *PerformanceOptimizer) GetPerformanceStats() *PerformanceStats {
	po.statsMutex.RLock()
	defer po.statsMutex.RUnlock()

	// 计算缓存命中率
	po.cacheMutex.RLock()
	cacheSize := len(po.ruleIndexCache)
	po.cacheMutex.RUnlock()

	stats := *po.stats
	if po.stats.TotalMatches > 0 {
		stats.CacheHitRate = float64(po.stats.SuccessfulMatches) / float64(po.stats.TotalMatches)
	}

	// 获取内存使用情况
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	stats.MemoryUsage = memStats.Alloc

	log.Printf("性能统计 - 总匹配: %d, 成功匹配: %d, 平均时间: %v, 缓存大小: %d, 内存使用: %d MB",
		stats.TotalMatches, stats.SuccessfulMatches, stats.AverageMatchTime, cacheSize, stats.MemoryUsage/(1024*1024))

	return &stats
}

// OptimizeMemoryUsage 优化内存使用
func (po *PerformanceOptimizer) OptimizeMemoryUsage() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	if memStats.Alloc > po.config.MemoryThreshold {
		log.Printf("内存使用超过阈值 (%d MB)，开始优化...", memStats.Alloc/(1024*1024))

		// 清理缓存
		po.cacheMutex.Lock()
		po.ruleIndexCache = make(map[string]*RuleIndex)
		po.cacheMutex.Unlock()

		// 强制垃圾回收
		runtime.GC()

		runtime.ReadMemStats(&memStats)
		log.Printf("内存优化完成，当前使用: %d MB", memStats.Alloc/(1024*1024))
	}
}

// GetEventFromPool 从对象池获取事件对象
func (po *PerformanceOptimizer) GetEventFromPool() *EventJSON {
	if po.config.EnablePooling {
		return po.eventPool.Get().(*EventJSON)
	}
	return &EventJSON{}
}

// PutEventToPool 将事件对象放回对象池
func (po *PerformanceOptimizer) PutEventToPool(event *EventJSON) {
	if po.config.EnablePooling {
		// 重置对象状态
		*event = EventJSON{}
		po.eventPool.Put(event)
	}
}

// GetAlertFromPool 从对象池获取告警对象
func (po *PerformanceOptimizer) GetAlertFromPool() *AlertEvent {
	if po.config.EnablePooling {
		return po.alertPool.Get().(*AlertEvent)
	}
	return &AlertEvent{}
}

// PutAlertToPool 将告警对象放回对象池
func (po *PerformanceOptimizer) PutAlertToPool(alert *AlertEvent) {
	if po.config.EnablePooling {
		// 重置对象状态
		*alert = AlertEvent{}
		po.alertPool.Put(alert)
	}
}

// 私有方法

func (po *PerformanceOptimizer) generateCacheKey(event *EventJSON) string {
	return event.EventType + "_" + event.Comm
}

func (po *PerformanceOptimizer) extractEventFields(event *EventJSON) map[string]interface{} {
	fields := make(map[string]interface{})
	fields["event_type"] = event.EventType
	fields["comm"] = event.Comm
	fields["pid"] = event.PID
	fields["uid"] = event.UID
	fields["filename"] = event.Filename
	return fields
}

func (po *PerformanceOptimizer) cleanExpiredCache() {
	if len(po.ruleIndexCache) <= po.config.MaxCacheSize {
		return
	}

	// 删除最旧的缓存项
	oldestKey := ""
	oldestTime := time.Now()
	
	for key, index := range po.ruleIndexCache {
		if index.LastUpdated.Before(oldestTime) {
			oldestTime = index.LastUpdated
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(po.ruleIndexCache, oldestKey)
	}
}

func (po *PerformanceOptimizer) getTimeRange(duration time.Duration) string {
	if duration < time.Microsecond {
		return "<1μs"
	} else if duration < 10*time.Microsecond {
		return "1-10μs"
	} else if duration < 100*time.Microsecond {
		return "10-100μs"
	} else if duration < time.Millisecond {
		return "100μs-1ms"
	} else if duration < 10*time.Millisecond {
		return "1-10ms"
	} else {
		return ">10ms"
	}
}

func (po *PerformanceOptimizer) startStatsResetTimer() {
	ticker := time.NewTicker(po.config.StatsResetInterval)
	defer ticker.Stop()

	for range ticker.C {
		po.statsMutex.Lock()
		po.stats = &PerformanceStats{
			MatchTimeHistogram: make(map[string]uint64),
			RuleHitCount:       make(map[string]uint64),
			LastResetTime:      time.Now(),
		}
		po.statsMutex.Unlock()
		log.Println("性能统计已重置")
	}
}

// GetOptimizedRuleCategories 获取优化的规则类别
func (po *PerformanceOptimizer) GetOptimizedRuleCategories(event *EventJSON) []string {
	if !po.config.EnableIndexing {
		// 如果未启用索引，返回空切片表示处理所有类别
		return []string{}
	}

	// 根据事件类型和特征确定相关的规则类别
	categories := make([]string, 0)
	
	// 根据事件类型映射到相关类别
	switch event.EventType {
	case "execve", "process":
		categories = append(categories, "process_monitoring", "execution_detection", "privilege_escalation")
	case "openat", "open", "write", "read":
		categories = append(categories, "file_monitoring", "data_exfiltration", "persistence")
	case "connect", "accept", "sendto", "recvfrom":
		categories = append(categories, "network_monitoring", "lateral_movement", "command_control")
	case "setuid", "setgid", "chmod":
		categories = append(categories, "privilege_escalation", "permission_changes")
	case "mmap", "mprotect":
		categories = append(categories, "memory_protection", "code_injection")
	default:
		// 对于未知事件类型，返回空切片处理所有类别
		return []string{}
	}

	// 根据进程名称添加额外的类别
	if event.Comm != "" {
		// 系统关键进程
		systemProcesses := []string{"systemd", "init", "kernel", "kthreadd"}
		for _, sysProc := range systemProcesses {
			if strings.Contains(event.Comm, sysProc) {
				categories = append(categories, "system_integrity")
				break
			}
		}

		// 网络相关进程
		networkProcesses := []string{"ssh", "scp", "wget", "curl", "nc", "netcat"}
		for _, netProc := range networkProcesses {
			if strings.Contains(event.Comm, netProc) {
				categories = append(categories, "network_monitoring", "data_exfiltration")
				break
			}
		}

		// Shell相关进程
		shellProcesses := []string{"bash", "sh", "zsh", "fish", "csh"}
		for _, shellProc := range shellProcesses {
			if strings.Contains(event.Comm, shellProc) {
				categories = append(categories, "command_execution", "shell_activity")
				break
			}
		}
	}

	// 去重
	uniqueCategories := make([]string, 0)
	seen := make(map[string]bool)
	for _, category := range categories {
		if !seen[category] {
			uniqueCategories = append(uniqueCategories, category)
			seen[category] = true
		}
	}

	return uniqueCategories
}