package engine

import (
	"log"
	"regexp"
	"strings"
)

// Operator 比较运算符类型
// 定义条件表达式中使用的各种比较操作
type Operator string

const (
	OpEquals      Operator = "="           // 等于
	OpNotEquals   Operator = "!="          // 不等于
	OpContains    Operator = "contains"    // 包含
	OpNotContains Operator = "not_contains" // 不包含
	OpStartsWith  Operator = "startswith"  // 以...开头
	OpEndsWith    Operator = "endswith"    // 以...结尾
	OpRegex       Operator = "regex"       // 正则匹配
	OpNotRegex    Operator = "not_regex"   // 正则不匹配
	OpIn          Operator = "in"          // 在列表中
	OpNotIn       Operator = "not_in"      // 不在列表中
	OpExists      Operator = "exists"      // 字段存在
	OpNotExists   Operator = "not_exists"  // 字段不存在
	OpGT          Operator = ">"           // 大于
	OpLT          Operator = "<"           // 小于
	OpGTE         Operator = ">="          // 大于等于
	OpLTE         Operator = "<="          // 小于等于
)

// ConditionExpr 条件表达式接口
// 所有条件表达式都必须实现 Evaluate 方法和 String 方法
type ConditionExpr interface {
	// Evaluate 对给定事件评估条件表达式
	// 参数 event 为事件数据
	// 返回条件是否满足
	Evaluate(event map[string]interface{}) bool

	// String 返回表达式的字符串表示
	String() string
}

// BinaryExpr 二元表达式
// 用于表示 AND、OR 等二元逻辑运算
type BinaryExpr struct {
	Op    LogicOperator // 逻辑运算符
	Left  ConditionExpr // 左操作数
	Right ConditionExpr // 右操作数
}

// Evaluate 评估二元表达式
// 根据 AND/OR 运算符组合左右操作数的结果
func (e *BinaryExpr) Evaluate(event map[string]interface{}) bool {
	switch e.Op {
	case LogicAND:
		return e.Left.Evaluate(event) && e.Right.Evaluate(event)
	case LogicOR:
		return e.Left.Evaluate(event) || e.Right.Evaluate(event)
	default:
		return false
	}
}

// String 返回二元表达式的字符串表示
func (e *BinaryExpr) String() string {
	return "(" + e.Left.String() + " " + string(e.Op) + " " + e.Right.String() + ")"
}

// UnaryExpr 一元表达式
// 用于表示 NOT 等一元逻辑运算
type UnaryExpr struct {
	Op   LogicOperator // 逻辑运算符
	Expr ConditionExpr // 操作数
}

// Evaluate 评估一元表达式
// 根据 NOT 运算符取反操作数的结果
func (e *UnaryExpr) Evaluate(event map[string]interface{}) bool {
	switch e.Op {
	case LogicNOT:
		return !e.Expr.Evaluate(event)
	default:
		return false
	}
}

// String 返回一元表达式的字符串表示
func (e *UnaryExpr) String() string {
	return "(" + string(e.Op) + " " + e.Expr.String() + ")"
}

// ComparisonExpr 比较表达式
// 用于表示字段与值之间的比较操作
type ComparisonExpr struct {
	Field    string        // 字段名（支持点号分隔的嵌套字段）
	Operator Operator      // 比较运算符
	Value    interface{}   // 比较值
	regex    *regexp.Regexp // 编译后的正则表达式（用于 regex 操作）
}

// Evaluate 评估比较表达式
// 从事件中获取字段值并与目标值进行比较
func (e *ComparisonExpr) Evaluate(event map[string]interface{}) bool {
	fieldValue, exists := getFieldValue(event, e.Field)

	// 处理 exists/not_exists 运算符
	switch e.Operator {
	case OpExists:
		return exists && fieldValue != nil && fieldValue != ""
	case OpNotExists:
		return !exists || fieldValue == nil || fieldValue == ""
	}

	// 字段不存在或值为空时，其他比较均返回 false
	if !exists || fieldValue == nil {
		return false
	}

	return e.compare(fieldValue)
}

// compare 执行实际的比较操作
// 根据运算符类型选择相应的比较方法
func (e *ComparisonExpr) compare(fieldValue interface{}) bool {
	fieldStr, isStr := fieldValue.(string)
	valueStr, _ := e.Value.(string)

	switch e.Operator {
	case OpEquals:
		return compareValues(fieldValue, e.Value)
	case OpNotEquals:
		return !compareValues(fieldValue, e.Value)
	case OpContains:
		// 包含检查（不区分大小写）
		if isStr {
			return strings.Contains(strings.ToLower(fieldStr), strings.ToLower(valueStr))
		}
		return false
	case OpNotContains:
		// 不包含检查（不区分大小写）
		if isStr {
			return !strings.Contains(strings.ToLower(fieldStr), strings.ToLower(valueStr))
		}
		return true
	case OpStartsWith:
		// 前缀检查（不区分大小写）
		if isStr {
			return strings.HasPrefix(strings.ToLower(fieldStr), strings.ToLower(valueStr))
		}
		return false
	case OpEndsWith:
		// 后缀检查（不区分大小写）
		if isStr {
			return strings.HasSuffix(strings.ToLower(fieldStr), strings.ToLower(valueStr))
		}
		return false
	case OpRegex:
		// 正则匹配
		if isStr && e.regex != nil {
			return e.regex.MatchString(fieldStr)
		}
		return false
	case OpNotRegex:
		// 正则不匹配
		if isStr && e.regex != nil {
			return !e.regex.MatchString(fieldStr)
		}
		return true
	case OpIn:
		// 在列表中检查
		return e.checkIn(fieldValue)
	case OpNotIn:
		// 不在列表中检查
		return !e.checkIn(fieldValue)
	case OpGT, OpLT, OpGTE, OpLTE:
		// 数值比较
		return e.compareNumeric(fieldValue)
	}
	return false
}

// checkIn 检查值是否在列表中
func (e *ComparisonExpr) checkIn(fieldValue interface{}) bool {
	values, ok := e.Value.([]interface{})
	if !ok {
		return compareValues(fieldValue, e.Value)
	}
	for _, v := range values {
		if compareValues(fieldValue, v) {
			return true
		}
	}
	return false
}

// compareNumeric 执行数值比较
func (e *ComparisonExpr) compareNumeric(fieldValue interface{}) bool {
	fieldNum, ok1 := toFloat64(fieldValue)
	valueNum, ok2 := toFloat64(e.Value)
	if !ok1 || !ok2 {
		return false
	}
	switch e.Operator {
	case OpGT:
		return fieldNum > valueNum
	case OpLT:
		return fieldNum < valueNum
	case OpGTE:
		return fieldNum >= valueNum
	case OpLTE:
		return fieldNum <= valueNum
	}
	return false
}

// String 返回比较表达式的字符串表示
func (e *ComparisonExpr) String() string {
	return e.Field + " " + string(e.Operator) + " " + formatValue(e.Value)
}

// Compile 编译表达式
// 为需要预编译的操作（如正则表达式）做准备
func (e *ComparisonExpr) Compile() error {
	if e.Operator == OpRegex || e.Operator == OpNotRegex {
		if pattern, ok := e.Value.(string); ok {
			regex, err := regexp.Compile(pattern)
			if err != nil {
				return err
			}
			e.regex = regex
		}
	}
	return nil
}

// BuildConditionTree 构建条件表达式树
// 将多个条件表达式按照指定逻辑运算符组合成一棵表达式树
// 参数 conditions 为条件表达式列表
// 参数 op 为组合使用的逻辑运算符
func BuildConditionTree(conditions []ConditionExpr, op LogicOperator) ConditionExpr {
	if len(conditions) == 0 {
		return nil
	}

	// 编译所有需要预编译的条件表达式（如正则表达式）
	for _, cond := range conditions {
		if cmpExpr, ok := cond.(*ComparisonExpr); ok {
			if err := cmpExpr.Compile(); err != nil {
				log.Printf("条件表达式编译失败: %v", err)
			}
		}
		// 递归处理嵌套的表达式
		compileNestedExpr(cond)
	}

	if len(conditions) == 1 {
		return conditions[0]
	}

	// 使用左结合方式构建表达式树
	result := conditions[0]
	for i := 1; i < len(conditions); i++ {
		result = &BinaryExpr{
			Op:    op,
			Left:  result,
			Right: conditions[i],
		}
	}
	return result
}

// compileNestedExpr 递归编译嵌套的条件表达式
func compileNestedExpr(expr ConditionExpr) {
	switch e := expr.(type) {
	case *BinaryExpr:
		if cmpExpr, ok := e.Left.(*ComparisonExpr); ok {
			cmpExpr.Compile()
		} else {
			compileNestedExpr(e.Left)
		}
		if cmpExpr, ok := e.Right.(*ComparisonExpr); ok {
			cmpExpr.Compile()
		} else {
			compileNestedExpr(e.Right)
		}
	case *UnaryExpr:
		if cmpExpr, ok := e.Expr.(*ComparisonExpr); ok {
			cmpExpr.Compile()
		} else {
			compileNestedExpr(e.Expr)
		}
	}
}

// getFieldValue 从事件中获取字段值
// 支持点号分隔的嵌套字段访问，如 "event.comm"
func getFieldValue(event map[string]interface{}, field string) (interface{}, bool) {
	parts := strings.Split(field, ".")
	var current interface{} = event

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			val, exists := v[part]
			if !exists {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}
	return current, true
}

// compareValues 比较两个值是否相等
// 支持字符串（不区分大小写）和数值比较
func compareValues(a, b interface{}) bool {
	// 字符串比较（不区分大小写）
	strA, okA := a.(string)
	strB, okB := b.(string)
	if okA && okB {
		return strings.EqualFold(strA, strB)
	}

	// 数值比较
	numA, okA := toFloat64(a)
	numB, okB := toFloat64(b)
	if okA && okB {
		return numA == numB
	}

	// 直接比较
	return a == b
}

// toFloat64 将各种数值类型转换为 float64
// 用于统一的数值比较
func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case int:
		return float64(val), true
	case int32:
		return float64(val), true
	case int64:
		return float64(val), true
	case uint:
		return float64(val), true
	case uint32:
		return float64(val), true
	case uint64:
		return float64(val), true
	case float32:
		return float64(val), true
	case float64:
		return val, true
	case string:
		var f float64
		_, err := strings.NewReader(val).Read(make([]byte, 0))
		return f, err == nil
	default:
		return 0, false
	}
}

// formatValue 将值格式化为字符串表示
// 用于生成表达式的字符串表示
func formatValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return "\"" + val + "\""
	case []interface{}:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = formatValue(item)
		}
		return "(" + strings.Join(parts, ", ") + ")"
	default:
		return ""
	}
}
