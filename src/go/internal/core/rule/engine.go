// Package rule 提供统一的安全检测规则引擎
// 支持 Falco、Tracee 和原生规则格式，实现高效的事件匹配和告警生成
package rule

import (
	"log"
	"sync"
	"time"
)

// Engine 规则引擎核心结构
// 负责规则加载、编译、索引构建和事件匹配
type Engine struct {
	mu            sync.RWMutex        // 读写锁，保护并发访问
	ruleSets      map[string]*RuleSet // 规则集映射，按名称索引
	compiledRules []*CompiledRule     // 编译后的规则列表
	index         *RuleIndex          // 规则索引，加速匹配
	matcher       *Matcher            // 条件匹配器
	whitelist     *WhitelistMatcher   // 白名单匹配器
	stats         *EngineStats        // 引擎统计数据
	config        *EngineConfig       // 引擎配置
}

// EngineConfig 引擎配置
type EngineConfig struct {
	EnableStats     bool          // 是否启用统计
	MaxHistory      int           // 最大历史记录数
	DefaultThrottle time.Duration // 默认节流时间
}

// EngineStats 引擎统计数据
type EngineStats struct {
	mu              sync.Mutex       // 互斥锁
	TotalMatches    uint64           // 总匹配次数
	SuccessfulMatch uint64           // 成功匹配次数
	RuleHits        map[string]uint64 // 各规则命中次数
	AvgMatchTime    time.Duration    // 平均匹配耗时
}

// NewEngine 创建规则引擎实例
// 参数 config 为引擎配置，为 nil 时使用默认配置
func NewEngine(config *EngineConfig) *Engine {
	// 使用默认配置
	if config == nil {
		config = &EngineConfig{
			EnableStats:     true,
			MaxHistory:      1000,
			DefaultThrottle: 60 * time.Second,
		}
	}

	return &Engine{
		ruleSets:  make(map[string]*RuleSet),
		matcher:   NewMatcher(),
		whitelist: NewWhitelistMatcher(),
		stats: &EngineStats{
			RuleHits: make(map[string]uint64),
		},
		config: config,
	}
}

// LoadRuleSet 加载规则集
// 参数 rs 为要加载的规则集
// 加载后会自动重建规则索引
func (e *Engine) LoadRuleSet(rs *RuleSet) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.ruleSets[rs.Name] = rs
	e.rebuildIndex()

	log.Printf("已加载规则集 '%s'，包含 %d 条规则", rs.Name, len(rs.Rules))
	return nil
}

// LoadRulesFromSource 从指定来源加载规则
// 参数 source 为规则来源类型（Falco、Tracee 或原生格式）
// 参数 data 为规则数据（通常是 YAML 或 JSON 格式）
func (e *Engine) LoadRulesFromSource(source RuleSource, data []byte) error {
	switch source {
	case SourceFalco:
		return e.loadFalcoRules(data)
	case SourceTracee:
		return e.loadTraceeRules(data)
	default:
		return e.loadNativeRules(data)
	}
}

// loadFalcoRules 加载 Falco 格式规则（预留接口）
func (e *Engine) loadFalcoRules(data []byte) error {
	return nil
}

// loadTraceeRules 加载 Tracee 格式规则（预留接口）
func (e *Engine) loadTraceeRules(data []byte) error {
	return nil
}

// loadNativeRules 加载原生格式规则（预留接口）
func (e *Engine) loadNativeRules(data []byte) error {
	return nil
}

// rebuildIndex 重建规则索引
// 遍历所有规则集，编译启用的规则并构建索引
// 在加载或更新规则后调用
func (e *Engine) rebuildIndex() {
	// 收集所有规则
	allRules := make([]*UnifiedRule, 0)
	for _, rs := range e.ruleSets {
		allRules = append(allRules, rs.GetEnabledRules()...)
	}

	// 编译规则
	e.compiledRules = make([]*CompiledRule, 0, len(allRules))
	for _, r := range allRules {
		compiled, err := r.Compile()
		if err != nil {
			log.Printf("规则编译失败 %s: %v", r.Name, err)
			continue
		}
		e.compiledRules = append(e.compiledRules, compiled)
	}

	// 构建索引
	e.index = BuildRuleIndex(allRules)
	log.Printf("已重建规则索引，包含 %d 条编译后的规则", len(e.compiledRules))
}

// Match 对事件进行规则匹配
// 参数 event 为待匹配的事件数据（键值对形式）
// 返回所有匹配的规则结果列表，未匹配时返回空列表
//
// 匹配流程：
//  1. 检查白名单，白名单内的事件直接跳过
//  2. 遍历所有已编译的规则
//  3. 检查节流状态，节流中的规则跳过
//  4. 执行条件匹配，记录匹配结果
//  5. 更新统计数据（如果启用）
func (e *Engine) Match(event map[string]interface{}) []*MatchResult {
	startTime := time.Now()
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 白名单检查
	if e.whitelist.IsWhitelisted(event) {
		return nil
	}

	results := make([]*MatchResult, 0)

	// 遍历所有规则进行匹配
	for _, compiled := range e.compiledRules {
		// 跳过无效或禁用的规则
		if compiled.ConditionAST == nil || !compiled.Original.Enabled {
			continue
		}

		// 节流检查
		if e.isThrottled(compiled) {
			continue
		}

		// 执行条件匹配
		if compiled.ConditionAST.Evaluate(event) {
			compiled.TriggerCount++
			compiled.LastTriggered = time.Now()

			// 记录匹配结果
			results = append(results, &MatchResult{
				Rule:      compiled.Original,
				Timestamp: time.Now(),
				Event:     event,
			})

			// 更新统计
			if e.config.EnableStats {
				e.recordMatch(compiled.Original.Name, time.Since(startTime))
			}
		}
	}

	return results
}

// isThrottled 检查规则是否处于节流状态
// 节流用于防止同一规则频繁触发告警
func (e *Engine) isThrottled(compiled *CompiledRule) bool {
	if compiled.Original.Throttle == 0 {
		return false
	}
	return time.Since(compiled.LastTriggered) < compiled.Original.Throttle
}

// recordMatch 记录匹配统计
// 更新总匹配次数、规则命中次数和平均匹配耗时
func (e *Engine) recordMatch(ruleName string, duration time.Duration) {
	e.stats.mu.Lock()
	defer e.stats.mu.Unlock()

	e.stats.TotalMatches++
	e.stats.SuccessfulMatch++
	e.stats.RuleHits[ruleName]++

	// 计算滑动平均匹配时间
	if e.stats.TotalMatches == 1 {
		e.stats.AvgMatchTime = duration
	} else {
		total := int64(e.stats.AvgMatchTime) * int64(e.stats.TotalMatches-1)
		e.stats.AvgMatchTime = time.Duration((total + int64(duration)) / int64(e.stats.TotalMatches))
	}
}

// GetStats 获取引擎统计数据
// 返回统计数据的副本，避免并发问题
func (e *Engine) GetStats() *EngineStats {
	e.stats.mu.Lock()
	defer e.stats.mu.Unlock()

	return &EngineStats{
		TotalMatches:    e.stats.TotalMatches,
		SuccessfulMatch: e.stats.SuccessfulMatch,
		RuleHits:        e.stats.RuleHits,
		AvgMatchTime:    e.stats.AvgMatchTime,
	}
}

// GetRules 获取所有已加载的规则
// 返回规则列表的副本
func (e *Engine) GetRules() []*UnifiedRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]*UnifiedRule, 0, len(e.compiledRules))
	for _, compiled := range e.compiledRules {
		rules = append(rules, compiled.Original)
	}
	return rules
}

// GetRuleByID 根据ID获取规则
// 参数 id 为规则唯一标识
// 返回规则指针，未找到时返回 nil
func (e *Engine) GetRuleByID(id string) *UnifiedRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, compiled := range e.compiledRules {
		if compiled.Original.ID == id {
			return compiled.Original
		}
	}
	return nil
}

// EnableRule 启用指定规则
// 参数 id 为规则唯一标识
// 返回是否成功启用（规则存在则返回 true）
func (e *Engine) EnableRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, compiled := range e.compiledRules {
		if compiled.Original.ID == id {
			compiled.Original.Enabled = true
			return true
		}
	}
	return false
}

// DisableRule 禁用指定规则
// 参数 id 为规则唯一标识
// 返回是否成功禁用（规则存在则返回 true）
func (e *Engine) DisableRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, compiled := range e.compiledRules {
		if compiled.Original.ID == id {
			compiled.Original.Enabled = false
			return true
		}
	}
	return false
}

// GetWhitelist 获取白名单匹配器
// 用于添加或移除白名单项
func (e *Engine) GetWhitelist() *WhitelistMatcher {
	return e.whitelist
}
