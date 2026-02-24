package falco

import (
	"fmt"
	"strings"

	"etracee/internal/core/rule"
	"gopkg.in/yaml.v2"
)

type Parser struct {
	*FalcoParser
}

func NewFalcoParser() *Parser {
	return &Parser{
		FalcoParser: NewParser(),
	}
}

func (p *Parser) Parse(data []byte) (*rule.RuleSet, error) {
	var items []map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("failed to parse Falco rules: %w", err)
	}

	rs := rule.NewRuleSet("falco-rules", rule.SourceFalco)

	for _, item := range items {
		if name := getString(item, "macro"); name != "" {
			cond := getString(item, "condition")
			if cond != "" {
				p.macros[name] = cond
				rs.Macros[name] = cond
			}
			continue
		}

		if name := getString(item, "list"); name != "" {
			items := getStringSlice(item, "items")
			if len(items) > 0 {
				p.lists[name] = items
				rs.Lists[name] = items
			}
			continue
		}

		if name := getString(item, "rule"); name != "" {
			ur, err := p.parseRule(item)
			if err != nil {
				continue
			}
			if ur != nil {
				rs.AddRule(ur)
			}
		}
	}

	return rs, nil
}

func (p *Parser) parseRule(item map[interface{}]interface{}) (*rule.UnifiedRule, error) {
	name := getString(item, "rule")
	if name == "" {
		return nil, fmt.Errorf("rule name is required")
	}

	desc := getString(item, "desc")
	if desc == "" {
		desc = getString(item, "output")
	}

	condition := getString(item, "condition")
	priority := getString(item, "priority")
	tags := getStringSlice(item, "tags")

	conditions, err := p.ParseCondition(condition)
	if err != nil {
		conditions = nil
	}

	ur := &rule.UnifiedRule{
		ID:           generateRuleID(name),
		Name:         name,
		Description:  desc,
		Source:       rule.SourceFalco,
		Severity:     rule.MapSeverity(priority),
		Category:     inferCategory(tags),
		Enabled:      true,
		Conditions:   conditions,
		RawCondition: condition,
		LogicOp:      rule.LogicAND,
		Tags:         tags,
		Actions:      []string{"log"},
		Metadata: map[string]interface{}{
			"original_output": getString(item, "output"),
			"priority":        priority,
		},
	}

	_, err = ur.Compile()
	if err != nil {
		return ur, nil
	}

	return ur, nil
}

func getString(item map[interface{}]interface{}, key string) string {
	if val, ok := item[key]; ok {
		if s, ok := val.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func getStringSlice(item map[interface{}]interface{}, key string) []string {
	val, ok := item[key]
	if !ok {
		return nil
	}

	switch v := val.(type) {
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, strings.TrimSpace(s))
			}
		}
		return result
	case []string:
		result := make([]string, 0, len(v))
		for _, s := range v {
			result = append(result, strings.TrimSpace(s))
		}
		return result
	default:
		return nil
	}
}

func generateRuleID(name string) string {
	return "falco-" + strings.ToLower(strings.ReplaceAll(name, " ", "-"))
}

func inferCategory(tags []string) string {
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
	case strings.Contains(joined, "credential"):
		return "credential_access"
	case strings.Contains(joined, "execution"):
		return "execution"
	case strings.Contains(joined, "persistence"):
		return "persistence"
	case strings.Contains(joined, "defense_evasion"):
		return "defense_evasion"
	default:
		return "general"
	}
}
