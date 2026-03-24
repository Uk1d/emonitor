// Copyright 2026 Uk1d
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


package main

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Boolish bool

func (b *Boolish) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw interface{}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case bool:
		*b = Boolish(v)
	case int:
		*b = v != 0
	case int64:
		*b = v != 0
	case uint64:
		*b = v != 0
	case float64:
		*b = v != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		switch s {
		case "true", "t", "yes", "y", "on", "1":
			*b = true
		case "false", "f", "no", "n", "off", "0", "":
			*b = false
		default:
			*b = false
		}
	default:
		*b = false
	}
	return nil
}

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
	Optimizer *PerformanceOptimizer
}

// 增强的全局配置
type EnhancedGlobalConfig struct {
	EnableFileEvents       Boolish `yaml:"enable_file_events"`
	EnableNetworkEvents    Boolish `yaml:"enable_network_events"`
	EnableProcessEvents    Boolish `yaml:"enable_process_events"`
	EnablePermissionEvents Boolish `yaml:"enable_permission_events"`
	EnableMemoryEvents     Boolish `yaml:"enable_memory_events"`

	MinUIDFilter       uint32 `yaml:"min_uid_filter"`
	MaxUIDFilter       uint32 `yaml:"max_uid_filter"`
	MaxEventsPerSecond int    `yaml:"max_events_per_second"`
	RingBufferSize     int    `yaml:"ring_buffer_size"`

	// 新增配置
	AlertThrottleSeconds int     `yaml:"alert_throttle_seconds"`
	MaxAlertHistory      int     `yaml:"max_alert_history"`
	EnableRuleStats      Boolish `yaml:"enable_rule_stats"`
	LogLevel             string  `yaml:"log_level"`
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
	Enabled       Boolish           `yaml:"enabled"`
	Throttle      int               `yaml:"throttle_seconds"`
	Actions       []string          `yaml:"actions"`
	Metadata      map[string]string `yaml:"metadata"`
	Category      string            `yaml:"category"`
}

// 编译后的规则（优化性能）
type CompiledRule struct {
	Original      *EnhancedDetectionRule
	CompiledConds []*CompiledCondition
	LogicOperator LogicOp
	LastTriggered time.Time
	TriggerCount  int64
	RegexCache    map[string]*regexp.Regexp
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
	OpNotRegex
	OpGreaterThan
	OpLessThan
	OpGreaterEqual
	OpLessEqual
	OpIn
	OpNotIn
	OpExists
	OpNotExists
)

// 规则统计信息
type RuleStatistics struct {
	RuleName       string
	TriggerCount   int64
	LastTriggered  time.Time
	AvgMatchTime   time.Duration
	TotalMatchTime time.Duration
}

// 告警事件
type AlertEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	RuleName    string            `json:"rule_name"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Event       *EventJSON        `json:"event"`
	Tags        []string          `json:"tags"`
	Metadata    map[string]string `json:"metadata"`
	Actions     []string          `json:"actions"`
	Category    string            `json:"category"`
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
// 支持多种条件格式：
// - 简单值: field: value
// - 正则表达式: field: "regex:pattern"
// - 比较操作: field: ">=1000", "<1024", 等
// - 列表成员: field: "in:[1,2,3]", "notin:[1,2,3]"
// - 复杂对象: field: {operator: "contains", value: "xxx"}
func (e *EnhancedRuleEngine) compileCondition(condition map[string]interface{}) (*CompiledCondition, error) {
	cond := &CompiledCondition{
		Values: make([]interface{}, 0), // 初始化空的Values数组
	}

	for field, value := range condition {
		cond.Field = field

		switch v := value.(type) {
		case string:
			// 解析操作符和值
			if strings.HasPrefix(v, "regex:") {
				cond.Operator = OpRegexMatch
				regexPattern := strings.TrimPrefix(v, "regex:")
				regex, err := regexp.Compile(regexPattern)
				if err != nil {
					return nil, fmt.Errorf("无效的正则表达式: %s", regexPattern)
				}
				cond.CompiledRegex = regex
				// 为正则匹配也保存原始值，以便调试
				cond.Values = []interface{}{regexPattern}
			} else if strings.HasPrefix(v, "notregex:") || strings.HasPrefix(v, "not_regex:") {
				cond.Operator = OpNotRegex
				listStr := strings.TrimPrefix(v, "notregex:")
				listStr = strings.TrimPrefix(listStr, "not_regex:")
				regex, err := regexp.Compile(listStr)
				if err != nil {
					return nil, fmt.Errorf("无效的正则表达式: %s", listStr)
				}
				cond.CompiledRegex = regex
				cond.Values = []interface{}{listStr}
			} else if strings.HasPrefix(v, "notin:") || strings.HasPrefix(v, "not_in:") {
				cond.Operator = OpNotIn
				listStr := strings.TrimPrefix(v, "notin:")
				listStr = strings.TrimPrefix(listStr, "not_in:")
				cond.Values = parseListValue(listStr)
			} else if strings.HasPrefix(v, "in:") {
				cond.Operator = OpIn
				listStr := strings.TrimPrefix(v, "in:")
				cond.Values = parseListValue(listStr)
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
				case "not_regex":
					cond.Operator = OpNotRegex
					if pattern, ok := v["pattern"].(string); ok {
						regex, err := regexp.Compile(pattern)
						if err != nil {
							return nil, fmt.Errorf("无效的正则表达式: %s", pattern)
						}
						cond.CompiledRegex = regex
						cond.Values = []interface{}{pattern}
					}
				case "not_equals":
					cond.Operator = OpNotEquals
				case "not_in":
					cond.Operator = OpNotIn
				case "in":
					cond.Operator = OpIn
				case "gt":
					cond.Operator = OpGreaterThan
				case "gte":
					cond.Operator = OpGreaterEqual
				case "lt":
					cond.Operator = OpLessThan
				case "lte":
					cond.Operator = OpLessEqual
				case "exists":
					cond.Operator = OpExists
				case "not_exists":
					cond.Operator = OpNotExists
				default:
					cond.Operator = OpEquals
				}

				if val, exists := v["value"]; exists {
					switch cond.Operator {
					case OpIn, OpNotIn:
						if list, ok := val.([]interface{}); ok {
							cond.Values = list
						} else {
							cond.Values = []interface{}{val}
						}
					case OpGreaterThan, OpGreaterEqual, OpLessThan, OpLessEqual:
						if num, err := strconv.ParseFloat(fmt.Sprintf("%v", val), 64); err == nil {
							cond.NumericValue = num
							cond.IsNumeric = true
							cond.Values = []interface{}{num}
						}
					default:
						cond.Values = []interface{}{val}
					}
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

// parseListValue 解析列表值字符串
// 支持格式: [1,2,3] 或 1,2,3
func parseListValue(listStr string) []interface{} {
	// 移除方括号
	listStr = strings.TrimSpace(listStr)
	listStr = strings.TrimPrefix(listStr, "[")
	listStr = strings.TrimSuffix(listStr, "]")

	if listStr == "" {
		return []interface{}{}
	}

	parts := strings.Split(listStr, ",")
	result := make([]interface{}, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 尝试解析为数字
		if num, err := strconv.ParseFloat(part, 64); err == nil {
			result = append(result, num)
		} else {
			// 作为字符串处理
			result = append(result, part)
		}
	}

	return result
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
					Category: rule.Original.Category,
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

			// 保留性能记录，避免重复计数，不再二次更新规则统计
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
		if cond.Field == "event_type" {
			if eventType, ok := fieldValue.(string); ok {
				return matchEventType(eventType, cond.Values[0])
			}
		}
		return e.compareValues(fieldValue, cond.Values[0], OpEquals)

	case OpNotEquals:
		if len(cond.Values) == 0 {
			return false
		}
		// 对于 event_type 字段，使用别名匹配
		if cond.Field == "event_type" {
			if eventType, ok := fieldValue.(string); ok {
				return !matchEventType(eventType, cond.Values[0])
			}
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
	case OpNotRegex:
		if str, ok := fieldValue.(string); ok && cond.CompiledRegex != nil {
			return !cond.CompiledRegex.MatchString(str)
		}
		return true

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
			if cond.Field == "event_type" {
				if eventType, ok := fieldValue.(string); ok {
					if matchEventType(eventType, val) {
						return true
					}
					continue
				}
			}
			if e.compareValues(fieldValue, val, OpEquals) {
				return true
			}
		}
		return false

	case OpNotIn:
		for _, val := range cond.Values {
			if cond.Field == "event_type" {
				if eventType, ok := fieldValue.(string); ok {
					if matchEventType(eventType, val) {
						return false
					}
					continue
				}
			}
			if e.compareValues(fieldValue, val, OpEquals) {
				return false
			}
		}
		return true
	case OpExists:
		switch v := fieldValue.(type) {
		case string:
			return strings.TrimSpace(v) != ""
		default:
			return true
		}
	case OpNotExists:
		switch v := fieldValue.(type) {
		case string:
			return strings.TrimSpace(v) == ""
		default:
			return fieldValue == nil
		}
	}

	return false
}

func matchEventType(eventType string, expected interface{}) bool {
	switch v := expected.(type) {
	case string:
		return matchEventTypeString(eventType, v)
	case []interface{}:
		for _, item := range v {
			if matchEventType(eventType, item) {
				return true
			}
		}
	}
	return false
}

// matchEventTypeString 事件类型别名匹配
// 将配置中的事件类型别名映射到实际的事件类型名称
func matchEventTypeString(eventType, expected string) bool {
	// 首先尝试精确匹配
	if eventType == expected {
		return true
	}

	// 转换为小写进行比较（不区分大小写）
	eventTypeLower := strings.ToLower(strings.TrimSpace(eventType))
	expectedLower := strings.ToLower(strings.TrimSpace(expected))

	if eventTypeLower == expectedLower {
		return true
	}

	// 事件类型别名映射表
	aliasMappings := map[string][]string{
		"file_open":        {"openat"},
		"file_modify":      {"write", "chmod", "chown", "rename"},
		"file_delete":      {"unlink"},
		"file_access":      {"openat", "read", "write"},
		"process_create":   {"execve", "execveat", "fork", "clone"},
		"process_exit":     {"exit"},
		"network_connect":  {"connect"},
		"network_bind":     {"bind"},
		"network_listen":   {"listen"},
		"network_accept":   {"accept"},
		"network_send":     {"sendto"},
		"network_recv":     {"recvfrom"},
		"network_socket":   {"socket"},
		"memory_mmap":      {"mmap"},
		"memory_mprotect":  {"mprotect"},
		"memory_munmap":    {"munmap"},
		"privilege_setuid": {"setuid"},
		"privilege_setgid": {"setgid"},
		"privilege_ptrace": {"ptrace"},
		"system_mount":     {"mount"},
		"system_umount":    {"umount"},
		"system_module":    {"init_module", "delete_module"},
	}

	// 检查 expected 是否是别名
	if aliases, ok := aliasMappings[expectedLower]; ok {
		for _, alias := range aliases {
			if eventTypeLower == alias || eventType == alias {
				return true
			}
		}
	}

	// 检查 eventType 是否是别名，expected 是实际类型
	if aliases, ok := aliasMappings[eventTypeLower]; ok {
		for _, alias := range aliases {
			if expectedLower == alias || expected == alias {
				return true
			}
		}
	}

	return false
}

// 获取事件字段值
// 支持嵌套字段访问，如 dst_addr.port、src_addr.ip 等
func (e *EnhancedRuleEngine) getFieldValue(event *EventJSON, field string) interface{} {
	// 处理嵌套字段 (如 dst_addr.port)
	if strings.Contains(field, ".") {
		parts := strings.SplitN(field, ".", 2)
		if len(parts) != 2 {
			return nil
		}
		parent := parts[0]
		child := parts[1]

		switch parent {
		case "src_addr":
			if event.SrcAddr == nil {
				return nil
			}
			switch child {
			case "ip":
				return event.SrcAddr.IP
			case "port":
				return uint32(event.SrcAddr.Port)
			case "family":
				return event.SrcAddr.Family
			}
		case "dst_addr":
			if event.DstAddr == nil {
				return nil
			}
			switch child {
			case "ip":
				return event.DstAddr.IP
			case "port":
				return uint32(event.DstAddr.Port)
			case "family":
				return event.DstAddr.Family
			}
		}
		return nil
	}

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
	case "cmdline":
		return event.Cmdline
	case "mode":
		// 将 mode 数值转换为标志字符串（如 "O_RDONLY|O_CREAT"）
		return formatFileMode(event.Mode)
	case "size":
		return event.Size
	case "flags":
		// 将 flags 数值转换为标志字符串
		return formatFileFlags(event.Flags)
	case "ret_code":
		return event.RetCode
	case "addr":
		return event.Addr
	case "len":
		return event.Len
	case "prot":
		return event.Prot
	case "target_comm":
		return event.TargetComm
	case "target_pid":
		return event.TargetPID
	case "signal":
		return event.Signal
	case "src_addr":
		if event.SrcAddr == nil {
			return nil
		}
		return event.SrcAddr.IP
	case "dst_addr":
		if event.DstAddr == nil {
			return nil
		}
		return event.DstAddr.IP
	case "old_uid":
		return event.OldUID
	case "old_gid":
		return event.OldGID
	case "new_uid":
		return event.NewUID
	case "new_gid":
		return event.NewGID
	default:
		return nil
	}
}

// formatFileMode 将文件 mode 数值转换为标志字符串
// 用于匹配规则中的正则表达式（如 ".*O_CREAT.*" 或 ".*[1457][0457][0457]$"）
// 同时返回八进制格式（用于chmod权限匹配）和O_xxx格式（用于openat标志匹配）
func formatFileMode(mode uint32) string {
	if mode == 0 {
		return ""
	}
	var flags []string

	// 添加八进制格式（用于chmod权限匹配，如 "0755"）
	octalStr := fmt.Sprintf("%04o", mode&0777)
	flags = append(flags, octalStr)

	// 文件访问模式 (O_ACCMODE = 0x3)
	switch mode & 0x3 {
	case 0:
		flags = append(flags, "O_RDONLY")
	case 1:
		flags = append(flags, "O_WRONLY")
	case 2:
		flags = append(flags, "O_RDWR")
	}

	// 文件创建和状态标志
	if mode&0x40 != 0 {
		flags = append(flags, "O_CREAT")
	}
	if mode&0x80 != 0 {
		flags = append(flags, "O_EXCL")
	}
	if mode&0x100 != 0 {
		flags = append(flags, "O_NOCTTY")
	}
	if mode&0x200 != 0 {
		flags = append(flags, "O_TRUNC")
	}
	if mode&0x400 != 0 {
		flags = append(flags, "O_APPEND")
	}
	if mode&0x800 != 0 {
		flags = append(flags, "O_NONBLOCK")
	}
	if mode&0x4000 != 0 {
		flags = append(flags, "O_DIRECTORY")
	}
	if mode&0x20000 != 0 {
		flags = append(flags, "O_NOFOLLOW")
	}
	if mode&0x100000 != 0 {
		flags = append(flags, "O_CLOEXEC")
	}

	return strings.Join(flags, "|")
}

// formatFileFlags 将文件 flags 数值转换为标志字符串
func formatFileFlags(flags uint32) string {
	if flags == 0 {
		return ""
	}
	return formatFileMode(flags) // 使用相同的转换逻辑
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

	// 检查用户白名单
	for _, user := range e.WhitelistConfig.Users {
		// 支持UID数字和用户名匹配
		if user == fmt.Sprintf("%d", event.UID) {
			return true
		}
	}

	// 检查文件白名单
	if event.Filename != "" {
		for _, file := range e.WhitelistConfig.Files {
			if strings.HasPrefix(event.Filename, file) {
				return true
			}
		}
	}

	// 检查网络白名单
	if event.SrcAddr != nil {
		srcIP := event.SrcAddr.IP
		for _, network := range e.WhitelistConfig.Networks {
			if isIPInNetwork(srcIP, network) {
				return true
			}
		}
	}
	if event.DstAddr != nil {
		dstIP := event.DstAddr.IP
		for _, network := range e.WhitelistConfig.Networks {
			if isIPInNetwork(dstIP, network) {
				return true
			}
		}
	}

	return false
}

// isIPInNetwork 检查IP地址是否在指定的CIDR网络范围内
func isIPInNetwork(ipStr, cidr string) bool {
	// 处理单个IP地址
	if !strings.Contains(cidr, "/") {
		return ipStr == cidr
	}

	// 解析CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	return ipNet.Contains(ip)
}

// 检查是否被节流
func (e *EnhancedRuleEngine) isThrottled(rule *CompiledRule) bool {
	// 先检查全局节流配置
	if e.GlobalConfig.AlertThrottleSeconds > 0 {
		globalThrottle := time.Duration(e.GlobalConfig.AlertThrottleSeconds) * time.Second
		if time.Since(rule.LastTriggered) < globalThrottle {
			return true
		}
	}

	// 再检查规则级别的节流配置
	if rule.Original.Throttle > 0 {
		ruleThrottle := time.Duration(rule.Original.Throttle) * time.Second
		if time.Since(rule.LastTriggered) < ruleThrottle {
			return true
		}
	}

	return false
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
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	Enabled     bool                   `json:"enabled"`
	Conditions  []RuleCondition        `json:"conditions"`
	Actions     []RuleAction           `json:"actions"`
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
		Enabled:       Boolish(rule.Enabled),
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
