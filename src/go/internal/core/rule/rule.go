package rule

import (
	"time"
)

// RuleSource 规则来源类型
// 标识规则的原始格式，用于解析和适配
type RuleSource string

const (
	SourceFalco  RuleSource = "falco"  // Falco 规则格式
	SourceTracee RuleSource = "tracee" // Tracee 规则格式
	SourceNative RuleSource = "native" // 原生规则格式
)

// Severity 告警严重级别
// 用于区分告警的紧急程度和响应优先级
type Severity string

const (
	SeverityCritical Severity = "critical" // 严重：需要立即处理的安全事件
	SeverityHigh     Severity = "high"     // 高危：重要的安全事件
	SeverityMedium   Severity = "medium"   // 中危：需要关注的安全事件
	SeverityLow      Severity = "low"      // 低危：轻微的安全事件
	SeverityInfo     Severity = "info"     // 信息：仅供记录的事件
)

// LogicOperator 条件逻辑运算符
// 用于组合多个条件表达式
type LogicOperator string

const (
	LogicAND LogicOperator = "AND" // 逻辑与：所有条件都满足
	LogicOR  LogicOperator = "OR"  // 逻辑或：任一条件满足
	LogicNOT LogicOperator = "NOT" // 逻辑非：条件不满足
)

// UnifiedRule 统一规则结构
// 提供与 Falco/Tracee 兼容的规则表示，支持多种规则来源的统一处理
type UnifiedRule struct {
	ID           string                 `json:"id" yaml:"id"`                       // 规则唯一标识
	Name         string                 `json:"name" yaml:"name"`                   // 规则名称
	Description  string                 `json:"description" yaml:"description"`     // 规则描述
	Source       RuleSource             `json:"source" yaml:"source"`               // 规则来源
	Severity     Severity               `json:"severity" yaml:"severity"`           // 严重级别
	Category     string                 `json:"category" yaml:"category"`           // 事件类别
	Enabled      bool                   `json:"enabled" yaml:"enabled"`             // 是否启用
	Conditions   []ConditionExpr        `json:"-" yaml:"-"`                         // 条件表达式列表（编译后）
	RawCondition string                 `json:"raw_condition,omitempty" yaml:"raw_condition,omitempty"` // 原始条件字符串
	LogicOp      LogicOperator          `json:"logic_operator" yaml:"logic_operator"` // 条件逻辑运算符
	Tags         []string               `json:"tags" yaml:"tags"`                   // 标签（如 MITRE ATT&CK）
	Actions      []string               `json:"actions" yaml:"actions"`             // 触发后的动作列表
	Throttle     time.Duration          `json:"throttle" yaml:"throttle"`           // 节流时间
	Metadata     map[string]interface{} `json:"metadata" yaml:"metadata"`           // 元数据

	compiled *CompiledRule // 编译后的规则缓存
}

// CompiledRule 编译后的规则
// 包含原始规则和编译后的条件表达式树
type CompiledRule struct {
	Original      *UnifiedRule   // 原始规则引用
	ConditionAST  ConditionExpr  // 条件表达式抽象语法树
	LastTriggered time.Time      // 最后触发时间
	TriggerCount  int64          // 触发次数统计
}

// Compile 编译规则
// 将条件列表转换为可执行的抽象语法树
// 编译结果会被缓存，后续调用直接返回缓存结果
func (r *UnifiedRule) Compile() (*CompiledRule, error) {
	// 检查缓存
	if r.compiled != nil {
		return r.compiled, nil
	}

	compiled := &CompiledRule{
		Original: r,
	}

	// 构建条件表达式树
	if len(r.Conditions) > 0 {
		compiled.ConditionAST = BuildConditionTree(r.Conditions, r.LogicOp)
	}

	r.compiled = compiled
	return compiled, nil
}

// GetCompiled 获取已编译的规则
// 返回编译缓存，未编译时返回 nil
func (r *UnifiedRule) GetCompiled() *CompiledRule {
	return r.compiled
}

// RuleSet 规则集
// 包含一组相关规则及其共享的宏和列表定义
type RuleSet struct {
	Name     string                // 规则集名称
	Version  string                // 规则集版本
	Source   RuleSource            // 规则来源
	Rules    []*UnifiedRule        // 规则列表
	Macros   map[string]string     // 宏定义
	Lists    map[string][]string   // 列表定义
	LoadedAt time.Time             // 加载时间
}

// NewRuleSet 创建新的规则集
// 参数 name 为规则集名称
// 参数 source 为规则来源类型
func NewRuleSet(name string, source RuleSource) *RuleSet {
	return &RuleSet{
		Name:     name,
		Source:   source,
		Rules:    make([]*UnifiedRule, 0),
		Macros:   make(map[string]string),
		Lists:    make(map[string][]string),
		LoadedAt: time.Now(),
	}
}

// AddRule 向规则集添加规则
// 参数 rule 为要添加的规则
func (rs *RuleSet) AddRule(rule *UnifiedRule) {
	rs.Rules = append(rs.Rules, rule)
}

// GetEnabledRules 获取所有已启用的规则
// 返回启用状态的规则列表
func (rs *RuleSet) GetEnabledRules() []*UnifiedRule {
	enabled := make([]*UnifiedRule, 0)
	for _, rule := range rs.Rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	return enabled
}

// RuleIndex 规则索引
// 用于加速规则查找和匹配
type RuleIndex struct {
	ByEventType map[string][]int    // 按事件类型索引
	BySeverity  map[Severity][]int  // 按严重级别索引
	ByCategory  map[string][]int    // 按类别索引
	ByField     map[string][]int    // 按字段索引
}

// BuildRuleIndex 构建规则索引
// 参数 rules 为要索引的规则列表
// 返回构建好的索引结构
func BuildRuleIndex(rules []*UnifiedRule) *RuleIndex {
	idx := &RuleIndex{
		ByEventType: make(map[string][]int),
		BySeverity:  make(map[Severity][]int),
		ByCategory:  make(map[string][]int),
		ByField:     make(map[string][]int),
	}

	// 遍历规则，建立索引
	for i, rule := range rules {
		// 按严重级别索引
		idx.BySeverity[rule.Severity] = append(idx.BySeverity[rule.Severity], i)

		// 按类别索引
		if rule.Category != "" {
			idx.ByCategory[rule.Category] = append(idx.ByCategory[rule.Category], i)
		}
	}

	return idx
}
