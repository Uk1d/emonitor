// Package falco 提供 Falco 规则格式解析器
// 实现 Falco 规则语法到统一规则格式的转换
package falco

import (
	"regexp"
	"strings"

	"etracee/internal/engine"
)

// FalcoParser Falco 规则解析器
// 负责将 Falco 格式的规则转换为统一规则格式
type FalcoParser struct {
	fieldMapper engine.FieldMapper  // 字段映射器，用于转换 Falco 字段名
	macros      map[string]string // 宏定义
	lists       map[string][]string // 列表定义
}

// NewParser 创建 Falco 解析器实例
func NewParser() *FalcoParser {
	return &FalcoParser{
		fieldMapper: engine.NewFalcoFieldMapper(),
		macros:      make(map[string]string),
		lists:       make(map[string][]string),
	}
}

// SetFieldMapper 设置字段映射器
// 用于自定义 Falco 字段到统一字段的映射规则
func (p *FalcoParser) SetFieldMapper(mapper engine.FieldMapper) {
	p.fieldMapper = mapper
}

// FalcoRuleFile Falco 规则文件结构
type FalcoRuleFile struct {
	Rules []FalcoRuleItem `yaml:"rules"` // 规则项列表
}

// FalcoRuleItem Falco 规则项（通用映射类型）
type FalcoRuleItem map[interface{}]interface{}

// FalcoRule Falco 规则定义
type FalcoRule struct {
	Name      string   `yaml:"rule"`     // 规则名称
	Desc      string   `yaml:"desc"`     // 规则描述
	Condition string   `yaml:"condition"` // 规则条件
	Output    string   `yaml:"output"`   // 输出格式
	Priority  string   `yaml:"priority"` // 优先级
	Tags      []string `yaml:"tags"`     // 标签列表
	Enabled   bool     `yaml:"enabled"`  // 是否启用
	Source    string   `yaml:"source"`   // 规则来源
}

// FalcoMacro Falco 宏定义
type FalcoMacro struct {
	Name      string `yaml:"macro"`     // 宏名称
	Condition string `yaml:"condition"` // 宏条件
}

// FalcoList Falco 列表定义
type FalcoList struct {
	Name  string   `yaml:"list"`  // 列表名称
	Items []string `yaml:"items"` // 列表项
}

// ParseCondition 解析 Falco 条件表达式
// 将 Falco 语法转换为统一条件表达式列表
func (p *FalcoParser) ParseCondition(condition string) ([]engine.ConditionExpr, error) {
	// 展开宏定义
	expanded := p.expandMacros(condition)
	conditions := make([]engine.ConditionExpr, 0)

	// 构建析取范式(DNF)组
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

// expandMacros 展开条件中的宏定义
// 递归替换宏引用为实际条件，最多迭代 20 次
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

// buildDNFGroups 构建析取范式(DNF)组
// 将条件表达式转换为 OR-of-ANDs 形式
func (p *FalcoParser) buildDNFGroups(condition string) [][]string {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return nil
	}

	// 处理 OR 分割
	orParts := p.splitTopLevel(condition, " or ")
	if len(orParts) > 1 {
		result := make([][]string, 0)
		for _, part := range orParts {
			result = append(result, p.buildDNFGroups(part)...)
		}
		return result
	}

	// 处理 AND 分割
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

// splitTopLevel 在顶层分割条件字符串
// 跳过括号和引号内的内容，只处理顶层操作符
func (p *FalcoParser) splitTopLevel(condition, separator string) []string {
	lower := strings.ToLower(condition)
	sep := strings.ToLower(separator)

	result := make([]string, 0)
	start := 0
	depth := 0      // 括号深度
	inSingle := false // 单引号内
	inDouble := false // 双引号内

	for i := 0; i < len(lower); {
		ch := lower[i]

		// 处理引号状态
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

		// 引号内跳过
		if inSingle || inDouble {
			i++
			continue
		}

		// 处理括号深度
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

		// 顶层匹配分隔符
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

	// 添加最后一部分
	last := strings.TrimSpace(condition[start:])
	if last != "" {
		result = append(result, last)
	}

	if len(result) == 0 {
		return []string{condition}
	}
	return result
}

// parseConditionGroup 解析条件组
// 将一组 AND 连接的条件转换为表达式树
func (p *FalcoParser) parseConditionGroup(parts []string) (engine.ConditionExpr, error) {
	conditions := make([]engine.ConditionExpr, 0, len(parts))

	for _, part := range parts {
		// 清理括号和空白
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

	return engine.BuildConditionTree(conditions, engine.LogicAND), nil
}

// parseExpression 解析单个条件表达式
// 根据模式匹配确定表达式类型并构建相应的条件对象
func (p *FalcoParser) parseExpression(expr string) (engine.ConditionExpr, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}

	// 处理 NOT 运算符
	if strings.HasPrefix(expr, "not ") {
		inner, err := p.parseExpression(expr[4:])
		if err != nil {
			return nil, err
		}
		return &engine.UnaryExpr{Op: engine.LogicNOT, Expr: inner}, nil
	}

	// 按优先级匹配各种操作符
	if m := reIn.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildInExpr(m[1], m[2], false)
	}
	if m := reNotIn.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildInExpr(m[1], m[2], true)
	}
	if m := reContains.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildComparison(m[1], engine.OpContains, m[2]), nil
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
		return p.buildComparison(m[1], engine.OpRegex, m[2]), nil
	}
	if m := reCompare.FindStringSubmatch(expr); len(m) == 4 {
		return p.buildComparison(m[1], engine.Operator(m[2]), m[3]), nil
	}
	if m := reEquals.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildComparison(m[1], engine.OpEquals, m[2]), nil
	}
	if m := reNotEquals.FindStringSubmatch(expr); len(m) == 3 {
		return p.buildComparison(m[1], engine.OpNotEquals, m[2]), nil
	}
	if m := reExists.FindStringSubmatch(expr); len(m) == 2 {
		return p.buildExists(m[1], false), nil
	}

	return nil, nil
}

// buildInExpr 构建 IN 表达式
// 参数 field 为字段名，valuesStr 为值列表字符串
// 参数 negate 为 true 时构建 NOT IN 表达式
func (p *FalcoParser) buildInExpr(field, valuesStr string, negate bool) (engine.ConditionExpr, error) {
	// 映射字段名
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	values := p.parseListValues(valuesStr)

	op := engine.OpIn
	if negate {
		op = engine.OpNotIn
	}

	expr := &engine.ComparisonExpr{
		Field:    mappedField,
		Operator: op,
		Value:    values,
	}

	return expr, nil
}

// buildComparison 构建比较表达式
func (p *FalcoParser) buildComparison(field string, op engine.Operator, value string) *engine.ComparisonExpr {
	// 映射字段名
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	// 清理值
	cleanValue := strings.Trim(strings.TrimSpace(value), `"'`)

	expr := &engine.ComparisonExpr{
		Field:    mappedField,
		Operator: op,
		Value:    cleanValue,
	}

	// 正则表达式需要编译
	if op == engine.OpRegex {
		expr.Compile()
	}

	return expr
}

// buildRegexFromIContains 构建不区分大小写的包含匹配
// icontains 转换为带 (?i) 标志的正则表达式
func (p *FalcoParser) buildRegexFromIContains(field, value string) *engine.ComparisonExpr {
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	cleanValue := strings.Trim(strings.TrimSpace(value), `"'`)
	pattern := "(?i)" + regexp.QuoteMeta(cleanValue)

	expr := &engine.ComparisonExpr{
		Field:    mappedField,
		Operator: engine.OpRegex,
		Value:    pattern,
	}
	expr.Compile()

	return expr
}

// buildStartsWith 构建前缀匹配表达式
// 转换为正则表达式 ^value 形式
func (p *FalcoParser) buildStartsWith(field, value string) *engine.ComparisonExpr {
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	cleanValue := strings.Trim(strings.TrimSpace(value), `"'`)
	pattern := "^" + regexp.QuoteMeta(cleanValue)

	expr := &engine.ComparisonExpr{
		Field:    mappedField,
		Operator: engine.OpRegex,
		Value:    pattern,
	}
	expr.Compile()

	return expr
}

// buildEndsWith 构建后缀匹配表达式
// 转换为正则表达式 value$ 形式
func (p *FalcoParser) buildEndsWith(field, value string) *engine.ComparisonExpr {
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	cleanValue := strings.Trim(strings.TrimSpace(value), `"'`)
	pattern := regexp.QuoteMeta(cleanValue) + "$"

	expr := &engine.ComparisonExpr{
		Field:    mappedField,
		Operator: engine.OpRegex,
		Value:    pattern,
	}
	expr.Compile()

	return expr
}

// buildExists 构建存在性检查表达式
func (p *FalcoParser) buildExists(field string, negate bool) *engine.ComparisonExpr {
	mappedField, ok := p.fieldMapper.Map(strings.TrimSpace(field))
	if !ok {
		mappedField = strings.TrimSpace(field)
	}

	op := engine.OpExists
	if negate {
		op = engine.OpNotExists
	}

	return &engine.ComparisonExpr{
		Field:    mappedField,
		Operator: op,
	}
}

// parseListValues 解析列表值
// 支持直接值和列表引用
func (p *FalcoParser) parseListValues(valuesStr string) []interface{} {
	valuesStr = strings.TrimSpace(valuesStr)
	valuesStr = strings.Trim(valuesStr, "()")

	parts := strings.Split(valuesStr, ",")
	result := make([]interface{}, 0)

	for _, part := range parts {
		item := strings.TrimSpace(part)
		item = strings.Trim(item, `"'`)

		// 检查是否为列表引用
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

// 正则表达式模式定义
var (
	reIn         = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+in\s*\(([^)]*)\)\s*$`)       // in 操作
	reNotIn      = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+not\s+in\s*\(([^)]*)\)\s*$`) // not in 操作
	reContains   = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+contains\s+(.+?)\s*$`)      // contains 操作
	reIContains  = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+icontains\s+(.+?)\s*$`)     // icontains 操作
	reStartsWith = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+startswith\s+(.+?)\s*$`)    // startswith 操作
	reEndsWith   = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+endswith\s+(.+?)\s*$`)      // endswith 操作
	reRegex      = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+regex\s+(.+?)\s*$`)         // regex 操作
	reCompare    = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s*(>=|<=|>|<)\s*(.+?)\s*$`)   // 比较操作
	reEquals     = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s*=\s*(.+?)\s*$`)             // 等于操作
	reNotEquals  = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s*!=\s*(.+?)\s*$`)            // 不等于操作
	reExists     = regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+)\s+exists\s*$`)                // exists 操作
)
