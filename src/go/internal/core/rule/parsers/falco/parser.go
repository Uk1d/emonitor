package falco

import (
	"regexp"
	"strings"

	"etracee/internal/core/rule"
)

type FalcoParser struct {
	fieldMapper rule.FieldMapper
	macros      map[string]string
	lists       map[string][]string
}

func NewParser() *FalcoParser {
	return &FalcoParser{
		fieldMapper: rule.NewFalcoFieldMapper(),
		macros:      make(map[string]string),
		lists:       make(map[string][]string),
	}
}

func (p *FalcoParser) SetFieldMapper(mapper rule.FieldMapper) {
	p.fieldMapper = mapper
}

type FalcoRuleFile struct {
	Rules []FalcoRuleItem `yaml:"rules"`
}

type FalcoRuleItem map[interface{}]interface{}

type FalcoRule struct {
	Name      string   `yaml:"rule"`
	Desc      string   `yaml:"desc"`
	Condition string   `yaml:"condition"`
	Output    string   `yaml:"output"`
	Priority  string   `yaml:"priority"`
	Tags      []string `yaml:"tags"`
	Enabled   bool     `yaml:"enabled"`
	Source    string   `yaml:"source"`
}

type FalcoMacro struct {
	Name      string `yaml:"macro"`
	Condition string `yaml:"condition"`
}

type FalcoList struct {
	Name  string   `yaml:"list"`
	Items []string `yaml:"items"`
}

func (p *FalcoParser) ParseCondition(condition string) ([]rule.ConditionExpr, error) {
	expanded := p.expandMacros(condition)
	conditions := make([]rule.ConditionExpr, 0)

	groups := p.buildDNFGroups(expanded)
	for _, group := range groups {
		expr, err := p.parseConditionGroup(group)
		if err != nil {
			continue
		}
		if expr != nil {
			conditions = append(conditions, expr)
		}
	}

	return conditions, nil
}

func (p *FalcoParser) expandMacros(condition string) string {
	result := condition
	for i := 0; i < 20; i++ {
		changed := false
		for name, value := range p.macros {
			if strings.Contains(result, name) {
				result = strings.ReplaceAll(result, name, "("+value+")")
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return result
}

func (p *FalcoParser) buildDNFGroups(condition string) [][]string {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return nil
	}

	orParts := p.splitTopLevel(condition, " or ")
	if len(orParts) > 1 {
		result := make([][]string, 0)
		for _, part := range orParts {
			result = append(result, p.buildDNFGroups(part)...)
		}
		return result
	}

	andParts := p.splitTopLevel(condition, " and ")
	if len(andParts) > 1 {
		result := [][]string{{}}
		for _, part := range andParts {
			subGroups := p.buildDNFGroups(part)
			newResult := make([][]string, 0)
			for _, existing := range result {
				for _, sub := range subGroups {
					combined := append(append([]string{}, existing...), sub...)
					newResult = append(newResult, combined)
				}
			}
			result = newResult
		}
		return result
	}

	return [][]string{{condition}}
}

func (p *FalcoParser) splitTopLevel(condition, separator string) []string {
	lower := strings.ToLower(condition)
	sep := strings.ToLower(separator)

	result := make([]string, 0)
	start := 0
	depth := 0
	inSingle := false
	inDouble := false

	for i := 0; i < len(lower); {
		ch := lower[i]

		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			i++
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			i++
			continue
		}

		if inSingle || inDouble {
			i++
			continue
		}

		if ch == '(' {
			depth++
			i++
			continue
		}
		if ch == ')' {
			if depth > 0 {
				depth--
			}
			i++
			continue
		}

		if depth == 0 && i+len(sep) <= len(lower) && lower[i:i+len(sep)] == sep {
			part := strings.TrimSpace(condition[start:i])
			if part != "" {
				result = append(result, part)
			}
			i += len(sep)
			start = i
			continue
		}

		i++
	}

	last := strings.TrimSpace(condition[start:])
	if last != "" {
		result = append(result, last)
	}

	if len(result) == 0 {
		return []string{condition}
	}
	return result
}

func (p *FalcoParser) parseConditionGroup(parts []string) (rule.ConditionExpr, error) {
	conditions := make([]rule.ConditionExpr, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "(")
		part = strings.TrimSuffix(part, ")")
		part = strings.TrimSpace(part)

		if part == "" {
			continue
		}

		expr, err := p.parseExpression(part)
		if err != nil {
			continue
		}
		if expr != nil {
			conditions = append(conditions, expr)
		}
	}

	if len(conditions) == 0 {
		return nil, nil
	}
	if len(conditions) == 1 {
		return conditions[0], nil
	}

	return rule.BuildConditionTree(conditions, rule.LogicAND), nil
}

func (p *FalcoParser) parseExpression(expr string) (rule.ConditionExpr, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}

	if strings.HasPrefix(expr, "not ") {
		inner, err := p.parseExpression(expr[4:])
		if err != nil {
			return nil, err
		}
		return &rule.UnaryExpr{Op: rule.LogicNOT, Expr: inner}, nil
	}

	if m := reIn.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildInExpr(m[1], m[2], false)
	}
	if m := reNotIn.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildInExpr(m[1], m[2], true)
	}
	if m := reContains.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildComparison(m[1], rule.OpContains, m[2]), nil
	}
	if m := reIContains.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildRegexFromIContains(m[1], m[2]), nil
	}
	if m := reStartsWith.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildStartsWith(m[1], m[2]), nil
	}
	if m := reEndsWith.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildEndsWith(m[1], m[2]), nil
	}
	if m := reRegex.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildComparison(m[1], rule.OpRegex, m[2]), nil
	}
	if m := reCompare.FindStringSubmatch(expr); len(m) == 4 {
		return p.buildComparison(m[1], rule.Operator(m[2]), m[3]), nil
	}
	if m := reEquals.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildComparison(m[1], rule.OpEquals, m[2]), nil
	}
	if m := reNotEquals.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildComparison(m[1], rule.OpNotEquals, m[2]), nil
	}
	if m := reExists.FindStringSubmatch(expr); len(m) == 2 {
		return p.buildExists(m[1], false), nil
	}

	return nil, nil
}

func (p *FalcoParser) buildInExpr(field, valuesStr string, negate bool) (rule.ConditionExpr, error) {
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	values := p.parseListValues(valuesStr)

	op := rule.OpIn
	if negate {
		op = rule.OpNotIn
	}

	expr := &rule.ComparisonExpr{
		Field:    mappedField,
		Operator: op,
		Value:    values,
	}

	return expr, nil
}

func (p *FalcoParser) buildComparison(field string, op rule.Operator, value string) *rule.ComparisonExpr {
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	cleanValue := strings.Trim(strings.TrimSpace(value), `"'`)

	expr := &rule.ComparisonExpr{
		Field:    mappedField,
		Operator: op,
		Value:    cleanValue,
	}

	if op == rule.OpRegex {
		expr.Compile()
	}

	return expr
}

func (p *FalcoParser) buildRegexFromIContains(field, value string) *rule.ComparisonExpr {
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	cleanValue := strings.Trim(strings.TrimSpace(value), `"'`)
	pattern := "(?i)" + regexp.QuoteMeta(cleanValue)

	expr := &rule.ComparisonExpr{
		Field:    mappedField,
		Operator: rule.OpRegex,
		Value:    pattern,
	}
	expr.Compile()

	return expr
}

func (p *FalcoParser) buildStartsWith(field, value string) *rule.ComparisonExpr {
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	cleanValue := strings.Trim(strings.TrimSpace(value), `"'`)
	pattern := "^" + regexp.QuoteMeta(cleanValue)

	expr := &rule.ComparisonExpr{
		Field:    mappedField,
		Operator: rule.OpRegex,
		Value:    pattern,
	}
	expr.Compile()

	return expr
}

func (p *FalcoParser) buildEndsWith(field, value string) *rule.ComparisonExpr {
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	cleanValue := strings.Trim(strings.TrimSpace(value), `"'`)
	pattern := regexp.QuoteMeta(cleanValue) + "$"

	expr := &rule.ComparisonExpr{
		Field:    mappedField,
		Operator: rule.OpRegex,
		Value:    pattern,
	}
	expr.Compile()

	return expr
}

func (p *FalcoParser) buildExists(field string, negate bool) *rule.ComparisonExpr {
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	op := rule.OpExists
	if negate {
		op = rule.OpNotExists
	}

	return &rule.ComparisonExpr{
		Field:    mappedField,
		Operator: op,
	}
}

func (p *FalcoParser) parseListValues(valuesStr string) []interface{} {
	valuesStr = strings.TrimSpace(valuesStr)
	valuesStr = strings.Trim(valuesStr, "()")

	parts := strings.Split(valuesStr, ",")
	result := make([]interface{}, 0)

	for _, part := range parts {
		item := strings.TrimSpace(part)
		item = strings.Trim(item, `"'`)

		if listValues, ok := p.lists[item]; ok {
			for _, v := range listValues {
				result = append(result, strings.TrimSpace(v))
			}
			continue
		}

		if item != "" {
			result = append(result, item)
		}
	}

	return result
}

var (
	reIn         = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+in\s*\(([^)]*)\)\s*$`)
	reNotIn      = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+not\s+in\s*\(([^)]*)\)\s*$`)
	reContains   = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+contains\s+(.+?)\s*$`)
	reIContains  = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+icontains\s+(.+?)\s*$`)
	reStartsWith = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+startswith\s+(.+?)\s*$`)
	reEndsWith   = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+endswith\s+(.+?)\s*$`)
	reRegex      = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+regex\s+(.+?)\s*$`)
	reCompare    = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s*(>=|<=|>|<)\s*(.+?)\s*$`)
	reEquals     = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s*=\s*(.+?)\s*$`)
	reNotEquals  = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s*!=\s*(.+?)\s*$`)
	reExists     = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+exists\s*$`)
)
