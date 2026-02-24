package rule

import (
	"time"
)

type RuleSource string

const (
	SourceFalco  RuleSource = "falco"
	SourceTracee RuleSource = "tracee"
	SourceNative RuleSource = "native"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type LogicOperator string

const (
	LogicAND LogicOperator = "AND"
	LogicOR  LogicOperator = "OR"
	LogicNOT LogicOperator = "NOT"
)

type UnifiedRule struct {
	ID           string                 `json:"id" yaml:"id"`
	Name         string                 `json:"name" yaml:"name"`
	Description  string                 `json:"description" yaml:"description"`
	Source       RuleSource             `json:"source" yaml:"source"`
	Severity     Severity               `json:"severity" yaml:"severity"`
	Category     string                 `json:"category" yaml:"category"`
	Enabled      bool                   `json:"enabled" yaml:"enabled"`
	Conditions   []ConditionExpr        `json:"-" yaml:"-"`
	RawCondition string                 `json:"raw_condition,omitempty" yaml:"raw_condition,omitempty"`
	LogicOp      LogicOperator          `json:"logic_operator" yaml:"logic_operator"`
	Tags         []string               `json:"tags" yaml:"tags"`
	Actions      []string               `json:"actions" yaml:"actions"`
	Throttle     time.Duration          `json:"throttle" yaml:"throttle"`
	Metadata     map[string]interface{} `json:"metadata" yaml:"metadata"`

	compiled *CompiledRule
}

type CompiledRule struct {
	Original      *UnifiedRule
	ConditionAST  ConditionExpr
	LastTriggered time.Time
	TriggerCount  int64
}

func (r *UnifiedRule) Compile() (*CompiledRule, error) {
	if r.compiled != nil {
		return r.compiled, nil
	}

	compiled := &CompiledRule{
		Original: r,
	}

	if len(r.Conditions) > 0 {
		compiled.ConditionAST = BuildConditionTree(r.Conditions, r.LogicOp)
	}

	r.compiled = compiled
	return compiled, nil
}

func (r *UnifiedRule) GetCompiled() *CompiledRule {
	return r.compiled
}

type RuleSet struct {
	Name     string
	Version  string
	Source   RuleSource
	Rules    []*UnifiedRule
	Macros   map[string]string
	Lists    map[string][]string
	LoadedAt time.Time
}

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

func (rs *RuleSet) AddRule(rule *UnifiedRule) {
	rs.Rules = append(rs.Rules, rule)
}

func (rs *RuleSet) GetEnabledRules() []*UnifiedRule {
	enabled := make([]*UnifiedRule, 0)
	for _, rule := range rs.Rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	return enabled
}

type RuleIndex struct {
	ByEventType map[string][]int
	BySeverity  map[Severity][]int
	ByCategory  map[string][]int
	ByField     map[string][]int
}

func BuildRuleIndex(rules []*UnifiedRule) *RuleIndex {
	idx := &RuleIndex{
		ByEventType: make(map[string][]int),
		BySeverity:  make(map[Severity][]int),
		ByCategory:  make(map[string][]int),
		ByField:     make(map[string][]int),
	}

	for i, rule := range rules {
		idx.BySeverity[rule.Severity] = append(idx.BySeverity[rule.Severity], i)
		if rule.Category != "" {
			idx.ByCategory[rule.Category] = append(idx.ByCategory[rule.Category], i)
		}
	}

	return idx
}
