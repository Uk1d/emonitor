package tracee

import (
	"encoding/json"
	"fmt"
	"strings"

	"etracee/internal/core/rule"
)

type Parser struct {
	fieldMapper rule.FieldMapper
}

func NewTraceeParser() *Parser {
	return &Parser{
		fieldMapper: rule.NewTraceeFieldMapper(),
	}
}

func (p *Parser) SetFieldMapper(mapper rule.FieldMapper) {
	p.fieldMapper = mapper
}

func (p *Parser) Parse(data []byte) (*rule.RuleSet, error) {
	var signatures []TraceeSignature
	if err := json.Unmarshal(data, &signatures); err != nil {
		var single TraceeSignature
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, fmt.Errorf("failed to parse Tracee signatures: %w", err)
		}
		signatures = []TraceeSignature{single}
	}

	rs := rule.NewRuleSet("tracee-signatures", rule.SourceTracee)

	for _, sig := range signatures {
		ur, err := p.convertSignature(sig)
		if err != nil {
			continue
		}
		if ur != nil {
			rs.AddRule(ur)
		}
	}

	return rs, nil
}

type TraceeSignature struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	SeverityInt int                    `json:"severityLevel"`
	Version     string                 `json:"version"`
	Tags        []string               `json:"tags"`
	Properties  map[string]interface{} `json:"properties"`
	Metadata    *TraceeMetadata        `json:"metadata"`
	Selectors   []TraceeSelector       `json:"selectors"`
	Event       string                 `json:"event"`
	Events      []string               `json:"events"`
}

type TraceeMetadata struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Tags        []string `json:"tags"`
	Severity    string   `json:"severity"`
}

type TraceeSelector struct {
	Name       string                 `json:"name"`
	Event      string                 `json:"event"`
	Events     []string               `json:"events"`
	ArgsFilter []TraceeArgFilter      `json:"argsFilters"`
	Filter     map[string]interface{} `json:"filter"`
}

type TraceeArgFilter struct {
	ArgName   string      `json:"name"`
	ArgValues interface{} `json:"values"`
	Operator  string      `json:"operator"`
}

func (p *Parser) convertSignature(sig TraceeSignature) (*rule.UnifiedRule, error) {
	name := sig.Name
	if name == "" && sig.Metadata != nil {
		name = sig.Metadata.Name
	}
	if name == "" {
		name = sig.ID
	}
	if name == "" {
		return nil, fmt.Errorf("signature name is required")
	}

	desc := sig.Description
	if desc == "" && sig.Metadata != nil {
		desc = sig.Metadata.Description
	}

	severity := sig.Severity
	if severity == "" && sig.Metadata != nil {
		severity = sig.Metadata.Severity
	}

	tags := sig.Tags
	if len(tags) == 0 && sig.Metadata != nil {
		tags = sig.Metadata.Tags
	}

	conditions := p.buildConditions(sig)

	ur := &rule.UnifiedRule{
		ID:          sig.ID,
		Name:        name,
		Description: desc,
		Source:      rule.SourceTracee,
		Severity:    rule.MapSeverity(severity),
		Category:    inferCategoryFromTags(tags),
		Enabled:     len(conditions) > 0,
		Conditions:  conditions,
		LogicOp:     rule.LogicAND,
		Tags:        tags,
		Actions:     []string{"log"},
		Metadata: map[string]interface{}{
			"version":      sig.Version,
			"severity_int": sig.SeverityInt,
			"properties":   sig.Properties,
		},
	}

	ur.Compile()
	return ur, nil
}

func (p *Parser) buildConditions(sig TraceeSignature) []rule.ConditionExpr {
	conditions := make([]rule.ConditionExpr, 0)

	eventNames := p.extractEventNames(sig)
	if len(eventNames) > 0 {
		if len(eventNames) == 1 {
			conditions = append(conditions, &rule.ComparisonExpr{
				Field:    "event_type",
				Operator: rule.OpEquals,
				Value:    rule.MapEventType(eventNames[0]),
			})
		} else {
			mappedEvents := make([]interface{}, len(eventNames))
			for i, e := range eventNames {
				mappedEvents[i] = rule.MapEventType(e)
			}
			conditions = append(conditions, &rule.ComparisonExpr{
				Field:    "event_type",
				Operator: rule.OpIn,
				Value:    mappedEvents,
			})
		}
	}

	for _, selector := range sig.Selectors {
		selectorConds := p.buildSelectorConditions(selector)
		conditions = append(conditions, selectorConds...)
	}

	return conditions
}

func (p *Parser) extractEventNames(sig TraceeSignature) []string {
	events := make([]string, 0)

	if sig.Event != "" {
		events = append(events, sig.Event)
	}
	events = append(events, sig.Events...)

	for _, selector := range sig.Selectors {
		if selector.Event != "" {
			events = append(events, selector.Event)
		}
		events = append(events, selector.Events...)
	}

	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, e := range events {
		if !seen[e] {
			seen[e] = true
			result = append(result, e)
		}
	}

	return result
}

func (p *Parser) buildSelectorConditions(selector TraceeSelector) []rule.ConditionExpr {
	conditions := make([]rule.ConditionExpr, 0)

	for _, filter := range selector.ArgsFilter {
		cond := p.buildArgFilterCondition(filter)
		if cond != nil {
			conditions = append(conditions, cond)
		}
	}

	return conditions
}

func (p *Parser) buildArgFilterCondition(filter TraceeArgFilter) rule.ConditionExpr {
	if filter.ArgName == "" {
		return nil
	}

	mappedField, ok := p.fieldMapper.Map(filter.ArgName)
	if !ok {
		mappedField = filter.ArgName
	}

	switch v := filter.ArgValues.(type) {
	case string:
		return &rule.ComparisonExpr{
			Field:    mappedField,
			Operator: rule.OpEquals,
			Value:    v,
		}
	case []interface{}:
		return &rule.ComparisonExpr{
			Field:    mappedField,
			Operator: rule.OpIn,
			Value:    v,
		}
	}

	return nil
}

func inferCategoryFromTags(tags []string) string {
	if len(tags) == 0 {
		return "general"
	}

	joined := strings.ToLower(strings.Join(tags, ","))
	switch {
	case strings.Contains(joined, "network"):
		return "network"
	case strings.Contains(joined, "file"):
		return "file"
	case strings.Contains(joined, "process"):
		return "process"
	case strings.Contains(joined, "privilege"):
		return "privilege"
	default:
		return "general"
	}
}
