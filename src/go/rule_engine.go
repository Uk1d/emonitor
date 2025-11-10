package main

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 增强的规则引擎结构
type EnhancedRuleEngine struct {
	Rules           map[string][]EnhancedDetectionRule `yaml:"detection_rules"`
	GlobalConfig    EnhancedGlobalConfig               `yaml:"global"`
	WhitelistConfig WhitelistConfig                    `yaml:"whitelist"`
	ResponseActions ResponseActionsConfig              `yaml:"response_actions"`
	
	// 运行时状态
	compiledRules   map[string][]*CompiledRule
	ruleStats       map[string]*RuleStatistics
	alertHistory    []AlertEvent
	maxAlertHistory int
	
	// 性能优化器
	Optimizer       *PerformanceOptimizer
}

// 增强的全局配置
type EnhancedGlobalConfig struct {
	EnableFileEvents       bool `yaml:"enable_file_events"`
	EnableNetworkEvents    bool `yaml:"enable_network_events"`
	EnableProcessEvents    bool `yaml:"enable_process_events"`
	EnablePermissionEvents bool `yaml:"enable_permission_events"`
	EnableMemoryEvents     bool `yaml:"enable_memory_events"`
	
	MinUIDFilter         uint32 `yaml:"min_uid_filter"`
	MaxUIDFilter         uint32 `yaml:"max_uid_filter"`
	MaxEventsPerSecond   int    `yaml:"max_events_per_second"`
	RingBufferSize       int    `yaml:"ring_buffer_size"`
	
	// 新增配置
	AlertThrottleSeconds int    `yaml:"alert_throttle_seconds"`
	MaxAlertHistory      int    `yaml:"max_alert_history"`
	EnableRuleStats      bool   `yaml:"enable_rule_stats"`
	LogLevel             string `yaml:"log_level"`
}

// 增强的检测规则
type EnhancedDetectionRule struct {
	Name        string                   `yaml:"name"`
	Description string                   `yaml:"description"`
	Conditions  []map[string]interface{} `yaml:"conditions"`
	Severity    string                   `yaml:"severity"`
	
	// 新增字段
	LogicOperator string            `yaml:"logic_operator"` // AND, OR, NOT
	Tags          []string          `yaml:"tags"`
	Enabled       bool              `yaml:"enabled"`
	Throttle      int               `yaml:"throttle_seconds"`
	Actions       []string          `yaml:"actions"`
	Metadata      map[string]string `yaml:"metadata"`
	Category      string            `yaml:"category"`
}

// 编译后的规则（优化性能）
type CompiledRule struct {
	Original       *EnhancedDetectionRule
	CompiledConds  []*CompiledCondition
	LogicOperator  LogicOp
	LastTriggered  time.Time
	TriggerCount   int64
	RegexCache     map[string]*regexp.Regexp
}

// 编译后的条件
type CompiledCondition struct {
	Field         string
	Operator      ComparisonOp
	Values        []interface{}
	CompiledRegex *regexp.Regexp
	NumericValue  float64
	IsNumeric     bool
}

// 逻辑运算符
type LogicOp int

const (
	LogicAND LogicOp = iota
	LogicOR
	LogicNOT
)

// 比较运算符
type ComparisonOp int

const (
	OpEquals ComparisonOp = iota
	OpNotEquals
	OpContains
	OpNotContains
	OpRegexMatch
	OpGreaterThan
	OpLessThan
	OpGreaterEqual
	OpLessEqual
	OpIn
	OpNotIn
)

// 规则统计信息
type RuleStatistics struct {
	RuleName      string
	TriggerCount  int64
	LastTriggered time.Time
	AvgMatchTime  time.Duration
	TotalMatchTime time.Duration
}

// 告警事件
type AlertEvent struct {
	Timestamp   time.Time             `json:"timestamp"`
	RuleName    string                `json:"rule_name"`
	Severity    string                `json:"severity"`
	Description string                `json:"description"`
	Event       *EventJSON            `json:"event"`
	Tags        []string              `json:"tags"`
	Metadata    map[string]string     `json:"metadata"`
	Actions     []string              `json:"actions"`
	Category    string                `json:"category"`
}

// 白名单配置
type WhitelistConfig struct {
	Processes []string `yaml:"processes"`
	Users     []string `yaml:"users"`
	Files     []string `yaml:"files"`
	Networks  []string `yaml:"networks"`
}

// 响应动作配置
type ResponseActionsConfig struct {
	CriticalSeverity []string `yaml:"critical_severity"`
	HighSeverity     []string `yaml:"high_severity"`
	MediumSeverity   []string `yaml:"medium_severity"`
	LowSeverity      []string `yaml:"low_severity"`
}

// 创建增强规则引擎
func NewEnhancedRuleEngine() *EnhancedRuleEngine {
	// 创建性能优化器配置
	optimizerConfig := &OptimizerConfig{
		EnableIndexing:     true,
		EnableCaching:      true,
		EnablePooling:      true,
		CacheExpireTime:    5 * time.Minute,
		MaxCacheSize:       1000,
		StatsResetInterval: 1 * time.Hour,
		MemoryThreshold:    100 * 1024 * 1024, // 100MB
	}

	return &EnhancedRuleEngine{
		compiledRules:   make(map[string][]*CompiledRule),
		ruleStats:       make(map[string]*RuleStatistics),
		alertHistory:    make([]AlertEvent, 0),
		maxAlertHistory: 1000,
		Optimizer:       NewPerformanceOptimizer(optimizerConfig),
	}
}

// 编译规则（启动时预编译提升性能）
func (e *EnhancedRuleEngine) CompileRules() error {
	log.Println("开始编译安全规则...")
	
	if e.Rules == nil || len(e.Rules) == 0 {
		log.Println("警告: 没有找到任何规则定义")
		return nil
	}
	
	log.Printf("发现 %d 个规则类别", len(e.Rules))
	
	for category, rules := range e.Rules {
		log.Printf("正在编译类别 '%s', 包含 %d 条规则", category, len(rules))
		compiledCategoryRules := make([]*CompiledRule, 0, len(rules))
		
		for i := range rules {
			rule := &rules[i]
			log.Printf("  编译规则: %s (启用: %v)", rule.Name, rule.Enabled)
			
			// 跳过禁用的规则
			if !rule.Enabled {
				log.Printf("  跳过禁用的规则: %s", rule.Name)
				continue
			}
			
			compiledRule := &CompiledRule{
				Original:      rule,
				CompiledConds: make([]*CompiledCondition, 0, len(rule.Conditions)),
				RegexCache:    make(map[string]*regexp.Regexp),
			}
			
			// 解析逻辑运算符
			switch strings.ToUpper(rule.LogicOperator) {
			case "OR":
				compiledRule.LogicOperator = LogicOR
			case "NOT":
				compiledRule.LogicOperator = LogicNOT
			default:
				compiledRule.LogicOperator = LogicAND
			}
			
			// 编译条件
			log.Printf("  编译 %d 个条件", len(rule.Conditions))
			for j, condition := range rule.Conditions {
				compiledCond, err := e.compileCondition(condition)
				if err != nil {
					log.Printf("编译规则 %s 的条件 %d 失败: %v", rule.Name, j, err)
					continue
				}
				compiledRule.CompiledConds = append(compiledRule.CompiledConds, compiledCond)
				log.Printf("    条件 %d: 字段=%s, 操作符=%d", j, compiledCond.Field, compiledCond.Operator)
			}
			
			if len(compiledRule.CompiledConds) > 0 {
				compiledCategoryRules = append(compiledCategoryRules, compiledRule)
				
				// 初始化统计信息
				e.ruleStats[rule.Name] = &RuleStatistics{
					RuleName: rule.Name,
				}
				log.Printf("  成功编译规则: %s", rule.Name)
			} else {
				log.Printf("  规则 %s 没有有效条件，跳过", rule.Name)
			}
		}
		
		e.compiledRules[category] = compiledCategoryRules
		log.Printf("类别 %s: 编译了 %d 条规则", category, len(compiledCategoryRules))
	}
	
	log.Printf("规则编译完成，总共编译了 %d 个类别的规则", len(e.compiledRules))
	return nil
}

// 编译单个条件
func (e *EnhancedRuleEngine) compileCondition(condition map[string]interface{}) (*CompiledCondition, error) {
	cond := &CompiledCondition{
		Values: make([]interface{}, 0), // 初始化空的Values数组
	}
	
	for field, value := range condition {
		cond.Field = field
		
		switch v := value.(type) {
		case string:
			// 解析操作符和值
			if strings.Contains(v, "regex:") {
				cond.Operator = OpRegexMatch
				regexPattern := strings.TrimPrefix(v, "regex:")
				regex, err := regexp.Compile(regexPattern)
				if err != nil {
					return nil, fmt.Errorf("无效的正则表达式: %s", regexPattern)
				}
				cond.CompiledRegex = regex
				// 为正则匹配也保存原始值，以便调试
				cond.Values = []interface{}{regexPattern}
			} else if strings.HasPrefix(v, ">") {
				cond.Operator = OpGreaterThan
				numStr := strings.TrimPrefix(v, ">")
				if num, err := strconv.ParseFloat(numStr, 64); err == nil {
					cond.NumericValue = num
					cond.IsNumeric = true
					cond.Values = []interface{}{num} // 保存数值到Values中
				}
			} else if strings.HasPrefix(v, "<") {
				cond.Operator = OpLessThan
				numStr := strings.TrimPrefix(v, "<")
				if num, err := strconv.ParseFloat(numStr, 64); err == nil {
					cond.NumericValue = num
					cond.IsNumeric = true
					cond.Values = []interface{}{num} // 保存数值到Values中
				}
			} else if strings.HasPrefix(v, ">=") {
				cond.Operator = OpGreaterEqual
				numStr := strings.TrimPrefix(v, ">=")
				if num, err := strconv.ParseFloat(numStr, 64); err == nil {
					cond.NumericValue = num
					cond.IsNumeric = true
					cond.Values = []interface{}{num} // 保存数值到Values中
				}
			} else if strings.HasPrefix(v, "<=") {
				cond.Operator = OpLessEqual
				numStr := strings.TrimPrefix(v, "<=")
				if num, err := strconv.ParseFloat(numStr, 64); err == nil {
					cond.NumericValue = num
					cond.IsNumeric = true
					cond.Values = []interface{}{num} // 保存数值到Values中
				}
			} else if strings.HasPrefix(v, "!=") {
				cond.Operator = OpNotEquals
				cond.Values = []interface{}{strings.TrimPrefix(v, "!=")}
			} else if strings.Contains(v, "*") {
				// 通配符转正则
				cond.Operator = OpRegexMatch
				regexPattern := strings.ReplaceAll(regexp.QuoteMeta(v), "\\*", ".*")
				regex, err := regexp.Compile(regexPattern)
				if err != nil {
					return nil, fmt.Errorf("无效的通配符模式: %s", v)
				}
				cond.CompiledRegex = regex
				// 为通配符匹配也保存原始值
				cond.Values = []interface{}{v}
			} else {
				cond.Operator = OpEquals
				cond.Values = []interface{}{v}
			}
			
		case []interface{}:
			cond.Operator = OpIn
			cond.Values = v
			
		case map[string]interface{}:
			// 处理复杂条件对象
			if op, exists := v["operator"]; exists {
				switch op.(string) {
				case "contains":
					cond.Operator = OpContains
				case "not_contains":
					cond.Operator = OpNotContains
				case "regex":
					cond.Operator = OpRegexMatch
					if pattern, ok := v["pattern"].(string); ok {
						regex, err := regexp.Compile(pattern)
						if err != nil {
							return nil, fmt.Errorf("无效的正则表达式: %s", pattern)
						}
						cond.CompiledRegex = regex
						cond.Values = []interface{}{pattern} // 保存正则模式
					}
				default:
					cond.Operator = OpEquals
				}
				
				if val, exists := v["value"]; exists {
					cond.Values = []interface{}{val}
				} else if len(cond.Values) == 0 {
					// 如果没有值，至少设置一个空值以避免数组越界
					cond.Values = []interface{}{""}
				}
			}
		}
		
		break // 只处理第一个字段
	}
	
	return cond, nil
}

// 增强的规则匹配
func (e *EnhancedRuleEngine) MatchRules(event *EventJSON) []AlertEvent {
	startTime := time.Now()
	alerts := make([]AlertEvent, 0)
	
	// 检查白名单
	if e.isWhitelisted(event) {
		return alerts
	}
	
	// 使用性能优化器获取相关规则集
	relevantCategories := e.Optimizer.GetOptimizedRuleCategories(event)
	
	for category, rules := range e.compiledRules {
		// 如果优化器返回了特定类别，只处理相关类别
		if len(relevantCategories) > 0 {
			found := false
			for _, relevantCat := range relevantCategories {
				if category == relevantCat {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		for _, rule := range rules {
			ruleStartTime := time.Now()
			
			// 检查节流
			if e.isThrottled(rule) {
				continue
			}
			
			// 执行规则匹配
			matched := e.matchCompiledRule(event, rule)
			ruleMatchTime := time.Since(ruleStartTime)
			
			// 记录规则匹配性能
			e.Optimizer.RecordMatchPerformance(ruleMatchTime, matched, rule.Original.Name)
			
            if matched {
                alert := AlertEvent{
                    Timestamp:   time.Now(),
                    RuleName:    rule.Original.Name,
                    Severity:    rule.Original.Severity,
                    Description: rule.Original.Description,
                    Event:       event,
                    Tags:        rule.Original.Tags,
                    Metadata:    rule.Original.Metadata,
                    Actions:     rule.Original.Actions,
                    // 关键修复：为告警设置类别，供攻击链阶段与技术映射使用
                    Category:    rule.Original.Category,
                }
                
                alerts = append(alerts, alert)
				
				// 更新规则统计
				e.updateRuleStats(rule.Original.Name, ruleMatchTime)
				
				// 更新触发时间
				rule.LastTriggered = time.Now()
				rule.TriggerCount++
				
				// 记录告警历史
				e.addAlertHistory(alert)
				
				log.Printf("SECURITY ALERT [%s]: %s - %s (PID: %d, Comm: %s, Category: %s)",
					alert.Severity, alert.RuleName, alert.Description,
					event.PID, event.Comm, category)
			}
			
			// 更新匹配时间统计
			if e.GlobalConfig.EnableRuleStats {
				e.updateRuleStats(rule.Original.Name, ruleMatchTime)
			}
		}
	}
	
	// 记录总体匹配性能
	totalMatchTime := time.Since(startTime)
	e.Optimizer.RecordMatchPerformance(totalMatchTime, len(alerts) > 0, "total_match")
	
	// 定期优化内存使用
	if time.Now().Unix()%300 == 0 { // 每5分钟检查一次
		go e.Optimizer.OptimizeMemoryUsage()
	}
	
	return alerts
}

// 匹配编译后的规则
func (e *EnhancedRuleEngine) matchCompiledRule(event *EventJSON, rule *CompiledRule) bool {
	if len(rule.CompiledConds) == 0 {
		return false
	}
	
	switch rule.LogicOperator {
	case LogicAND:
		for _, cond := range rule.CompiledConds {
			if !e.matchCondition(event, cond) {
				return false
			}
		}
		return true
		
	case LogicOR:
		for _, cond := range rule.CompiledConds {
			if e.matchCondition(event, cond) {
				return true
			}
		}
		return false
		
	case LogicNOT:
		for _, cond := range rule.CompiledConds {
			if e.matchCondition(event, cond) {
				return false
			}
		}
		return true
		
	default:
		return false
	}
}

// 匹配单个条件
func (e *EnhancedRuleEngine) matchCondition(event *EventJSON, cond *CompiledCondition) bool {
	fieldValue := e.getFieldValue(event, cond.Field)
	if fieldValue == nil {
		return false
	}
	
	switch cond.Operator {
	case OpEquals:
		if len(cond.Values) == 0 {
			return false
		}
		return e.compareValues(fieldValue, cond.Values[0], OpEquals)
		
	case OpNotEquals:
		if len(cond.Values) == 0 {
			return false
		}
		return !e.compareValues(fieldValue, cond.Values[0], OpEquals)
		
	case OpContains:
		if len(cond.Values) == 0 {
			return false
		}
		if str, ok := fieldValue.(string); ok {
			if searchStr, ok := cond.Values[0].(string); ok {
				return strings.Contains(str, searchStr)
			}
		}
		return false
		
	case OpNotContains:
		if len(cond.Values) == 0 {
			return true // 如果没有值要检查，则认为不包含任何内容
		}
		if str, ok := fieldValue.(string); ok {
			if searchStr, ok := cond.Values[0].(string); ok {
				return !strings.Contains(str, searchStr)
			}
		}
		return true
		
	case OpRegexMatch:
		if str, ok := fieldValue.(string); ok && cond.CompiledRegex != nil {
			return cond.CompiledRegex.MatchString(str)
		}
		return false
		
	case OpGreaterThan, OpLessThan, OpGreaterEqual, OpLessEqual:
		if cond.IsNumeric {
			if num := e.toNumeric(fieldValue); num != nil {
				switch cond.Operator {
				case OpGreaterThan:
					return *num > cond.NumericValue
				case OpLessThan:
					return *num < cond.NumericValue
				case OpGreaterEqual:
					return *num >= cond.NumericValue
				case OpLessEqual:
					return *num <= cond.NumericValue
				}
			}
		}
		return false
		
	case OpIn:
		for _, val := range cond.Values {
			if e.compareValues(fieldValue, val, OpEquals) {
				return true
			}
		}
		return false
		
	case OpNotIn:
		for _, val := range cond.Values {
			if e.compareValues(fieldValue, val, OpEquals) {
				return false
			}
		}
		return true
	}
	
	return false
}

// 获取事件字段值
func (e *EnhancedRuleEngine) getFieldValue(event *EventJSON, field string) interface{} {
	switch field {
	case "event_type":
		return event.EventType
	case "pid":
		return event.PID
	case "ppid":
		return event.PPID
	case "uid":
		return event.UID
	case "gid":
		return event.GID
	case "comm":
		return event.Comm
	case "filename":
		return event.Filename
	case "syscall_id":
		return event.SyscallID
	case "severity":
		return event.Severity
	default:
		return nil
	}
}

// 比较值
func (e *EnhancedRuleEngine) compareValues(a, b interface{}, op ComparisonOp) bool {
	// 类型转换和比较逻辑
	switch va := a.(type) {
	case string:
		if vb, ok := b.(string); ok {
			return va == vb
		}
	case uint32:
		if vb, ok := b.(uint32); ok {
			return va == vb
		}
		if vb, ok := b.(int); ok {
			return va == uint32(vb)
		}
		if vb, ok := b.(float64); ok {
			return float64(va) == vb
		}
	case int:
		if vb, ok := b.(int); ok {
			return va == vb
		}
		if vb, ok := b.(uint32); ok {
			return uint32(va) == vb
		}
		if vb, ok := b.(float64); ok {
			return float64(va) == vb
		}
	}
	return false
}

// 转换为数值
func (e *EnhancedRuleEngine) toNumeric(value interface{}) *float64 {
	switch v := value.(type) {
	case int:
		f := float64(v)
		return &f
	case uint32:
		f := float64(v)
		return &f
	case float64:
		return &v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return &f
		}
	}
	return nil
}

// 检查是否在白名单中
func (e *EnhancedRuleEngine) isWhitelisted(event *EventJSON) bool {
	// 检查进程白名单
	for _, process := range e.WhitelistConfig.Processes {
		if strings.Contains(event.Filename, process) || strings.Contains(event.Comm, process) {
			return true
		}
	}
	
	// 可以添加更多白名单检查逻辑
	return false
}

// 检查是否被节流
func (e *EnhancedRuleEngine) isThrottled(rule *CompiledRule) bool {
	if rule.Original.Throttle <= 0 {
		return false
	}
	
	return time.Since(rule.LastTriggered) < time.Duration(rule.Original.Throttle)*time.Second
}

// 更新规则统计
func (e *EnhancedRuleEngine) updateRuleStats(ruleName string, matchTime time.Duration) {
	if !e.GlobalConfig.EnableRuleStats {
		return
	}
	
	stats, exists := e.ruleStats[ruleName]
	if !exists {
		stats = &RuleStatistics{RuleName: ruleName}
		e.ruleStats[ruleName] = stats
	}
	
	stats.TriggerCount++
	stats.LastTriggered = time.Now()
	stats.TotalMatchTime += matchTime
	stats.AvgMatchTime = stats.TotalMatchTime / time.Duration(stats.TriggerCount)
}

// 添加告警历史
func (e *EnhancedRuleEngine) addAlertHistory(alert AlertEvent) {
	e.alertHistory = append(e.alertHistory, alert)
	
	// 保持历史记录在限制范围内
	if len(e.alertHistory) > e.maxAlertHistory {
		e.alertHistory = e.alertHistory[1:]
	}
}

// 获取规则统计信息
func (e *EnhancedRuleEngine) GetRuleStatistics() map[string]*RuleStatistics {
	return e.ruleStats
}

// 获取告警历史
func (e *EnhancedRuleEngine) GetAlertHistory(limit int) []AlertEvent {
	if limit <= 0 || limit > len(e.alertHistory) {
		return e.alertHistory
	}
	
	start := len(e.alertHistory) - limit
	return e.alertHistory[start:]
}

// 兼容性类型定义（用于集成测试）
type EnhancedRule struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    string          `json:"category"`
	Severity    string          `json:"severity"`
	Enabled     bool            `json:"enabled"`
	Conditions  []RuleCondition `json:"conditions"`
	Actions     []RuleAction    `json:"actions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type RuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

type RuleAction struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// AddRule 添加规则到规则引擎（兼容性方法）
func (e *EnhancedRuleEngine) AddRule(rule *EnhancedRule) error {
	if e.Rules == nil {
		e.Rules = make(map[string][]EnhancedDetectionRule)
	}
	
	// 转换 EnhancedRule 到 EnhancedDetectionRule
	detectionRule := EnhancedDetectionRule{
		Name:          rule.Name,
		Description:   rule.Description,
		Severity:      rule.Severity,
		LogicOperator: "AND", // 默认使用 AND
		Tags:          []string{},
		Enabled:       rule.Enabled,
		Throttle:      0,
		Actions:       make([]string, len(rule.Actions)),
		Metadata:      make(map[string]string),
		Category:      rule.Category,
		Conditions:    make([]map[string]interface{}, len(rule.Conditions)),
	}
	
	// 转换条件
	for i, cond := range rule.Conditions {
		detectionRule.Conditions[i] = map[string]interface{}{
			"field":    cond.Field,
			"operator": cond.Operator,
			"value":    cond.Value,
		}
	}
	
	// 转换动作
	for i, action := range rule.Actions {
		detectionRule.Actions[i] = action.Type
	}
	
	// 添加到规则集合
	e.Rules[rule.Category] = append(e.Rules[rule.Category], detectionRule)
	
	// 重新编译规则
	return e.CompileRules()
}