package rule

import (
	"regexp"
	"strings"
)

type Operator string

const (
	OpEquals      Operator = "="
	OpNotEquals   Operator = "!="
	OpContains    Operator = "contains"
	OpNotContains Operator = "not_contains"
	OpStartsWith  Operator = "startswith"
	OpEndsWith    Operator = "endswith"
	OpRegex       Operator = "regex"
	OpNotRegex    Operator = "not_regex"
	OpIn          Operator = "in"
	OpNotIn       Operator = "not_in"
	OpExists      Operator = "exists"
	OpNotExists   Operator = "not_exists"
	OpGT          Operator = ">"
	OpLT          Operator = "<"
	OpGTE         Operator = ">="
	OpLTE         Operator = "<="
)

type ConditionExpr interface {
	Evaluate(event map[string]interface{}) bool
	String() string
}

type BinaryExpr struct {
	Op    LogicOperator
	Left  ConditionExpr
	Right ConditionExpr
}

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

func (e *BinaryExpr) String() string {
	return "(" + e.Left.String() + " " + string(e.Op) + " " + e.Right.String() + ")"
}

type UnaryExpr struct {
	Op   LogicOperator
	Expr ConditionExpr
}

func (e *UnaryExpr) Evaluate(event map[string]interface{}) bool {
	switch e.Op {
	case LogicNOT:
		return !e.Expr.Evaluate(event)
	default:
		return false
	}
}

func (e *UnaryExpr) String() string {
	return "(" + string(e.Op) + " " + e.Expr.String() + ")"
}

type ComparisonExpr struct {
	Field    string
	Operator Operator
	Value    interface{}
	regex    *regexp.Regexp
}

func (e *ComparisonExpr) Evaluate(event map[string]interface{}) bool {
	fieldValue, exists := getFieldValue(event, e.Field)

	switch e.Operator {
	case OpExists:
		return exists && fieldValue != nil && fieldValue != ""
	case OpNotExists:
		return !exists || fieldValue == nil || fieldValue == ""
	}

	if !exists || fieldValue == nil {
		return false
	}

	return e.compare(fieldValue)
}

func (e *ComparisonExpr) compare(fieldValue interface{}) bool {
	fieldStr, isStr := fieldValue.(string)
	valueStr, _ := e.Value.(string)

	switch e.Operator {
	case OpEquals:
		return compareValues(fieldValue, e.Value)
	case OpNotEquals:
		return !compareValues(fieldValue, e.Value)
	case OpContains:
		if isStr {
			return strings.Contains(strings.ToLower(fieldStr), strings.ToLower(valueStr))
		}
		return false
	case OpNotContains:
		if isStr {
			return !strings.Contains(strings.ToLower(fieldStr), strings.ToLower(valueStr))
		}
		return true
	case OpStartsWith:
		if isStr {
			return strings.HasPrefix(strings.ToLower(fieldStr), strings.ToLower(valueStr))
		}
		return false
	case OpEndsWith:
		if isStr {
			return strings.HasSuffix(strings.ToLower(fieldStr), strings.ToLower(valueStr))
		}
		return false
	case OpRegex:
		if isStr && e.regex != nil {
			return e.regex.MatchString(fieldStr)
		}
		return false
	case OpNotRegex:
		if isStr && e.regex != nil {
			return !e.regex.MatchString(fieldStr)
		}
		return true
	case OpIn:
		return e.checkIn(fieldValue)
	case OpNotIn:
		return !e.checkIn(fieldValue)
	case OpGT, OpLT, OpGTE, OpLTE:
		return e.compareNumeric(fieldValue)
	}
	return false
}

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

func (e *ComparisonExpr) String() string {
	return e.Field + " " + string(e.Operator) + " " + formatValue(e.Value)
}

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

func BuildConditionTree(conditions []ConditionExpr, op LogicOperator) ConditionExpr {
	if len(conditions) == 0 {
		return nil
	}
	if len(conditions) == 1 {
		return conditions[0]
	}

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

func compareValues(a, b interface{}) bool {
	strA, okA := a.(string)
	strB, okB := b.(string)
	if okA && okB {
		return strings.EqualFold(strA, strB)
	}

	numA, okA := toFloat64(a)
	numB, okB := toFloat64(b)
	if okA && okB {
		return numA == numB
	}

	return a == b
}

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
