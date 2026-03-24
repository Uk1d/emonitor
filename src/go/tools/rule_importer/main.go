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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
)

type OutputConfig struct {
	Global          GlobalConfig               `yaml:"global"`
	DetectionRules  map[string][]DetectionRule `yaml:"detection_rules"`
	Whitelist       WhitelistConfig            `yaml:"whitelist"`
	ResponseActions ResponseActionsConfig      `yaml:"response_actions"`
}

type GlobalConfig struct {
	EnableFileEvents       bool   `yaml:"enable_file_events"`
	EnableNetworkEvents    bool   `yaml:"enable_network_events"`
	EnableProcessEvents    bool   `yaml:"enable_process_events"`
	EnablePermissionEvents bool   `yaml:"enable_permission_events"`
	EnableMemoryEvents     bool   `yaml:"enable_memory_events"`
	MinUIDFilter           uint32 `yaml:"min_uid_filter"`
	MaxUIDFilter           uint32 `yaml:"max_uid_filter"`
	MaxEventsPerSecond     int    `yaml:"max_events_per_second"`
	RingBufferSize         int    `yaml:"ring_buffer_size"`
	AlertThrottleSeconds   int    `yaml:"alert_throttle_seconds"`
	MaxAlertHistory        int    `yaml:"max_alert_history"`
	EnableRuleStats        bool   `yaml:"enable_rule_stats"`
	LogLevel               string `yaml:"log_level"`
}

type DetectionRule struct {
	Name          string                   `yaml:"name"`
	Description   string                   `yaml:"description"`
	Conditions    []map[string]interface{} `yaml:"conditions"`
	Severity      string                   `yaml:"severity"`
	LogicOperator string                   `yaml:"logic_operator"`
	Tags          []string                 `yaml:"tags"`
	Enabled       bool                     `yaml:"enabled"`
	Throttle      int                      `yaml:"throttle_seconds"`
	Actions       []string                 `yaml:"actions"`
	Metadata      map[string]string        `yaml:"metadata"`
	Category      string                   `yaml:"category"`
}

type WhitelistConfig struct {
	Processes []string `yaml:"processes"`
	Users     []string `yaml:"users"`
	Files     []string `yaml:"files"`
	Networks  []string `yaml:"networks"`
}

type ResponseActionsConfig struct {
	CriticalSeverity []string `yaml:"critical_severity"`
	HighSeverity     []string `yaml:"high_severity"`
	MediumSeverity   []string `yaml:"medium_severity"`
	LowSeverity      []string `yaml:"low_severity"`
}

type FalcoRuleFile struct {
	Rules []FalcoRule `yaml:"rules"`
}

type FalcoRule struct {
	Rule      string   `yaml:"rule"`
	Desc      string   `yaml:"desc"`
	Condition string   `yaml:"condition"`
	Output    string   `yaml:"output"`
	Priority  string   `yaml:"priority"`
	Tags      []string `yaml:"tags"`
}

type FalcoContent struct {
	Rules  []FalcoRule
	Macros map[string]string
	Lists  map[string][]string
}

type FieldMap map[string]string

func main() {
	input := flag.String("input", "", "输入规则文件路径")
	format := flag.String("format", "", "规则格式: falco 或 tracee")
	output := flag.String("output", "", "输出规则文件路径")
	defaultCategory := flag.String("default-category", "general", "默认类别")
	defaultSeverity := flag.String("default-severity", "medium", "默认严重级别")
	enableRules := flag.Bool("enable", true, "是否启用导入的规则")
	allowPartial := flag.Bool("allow-partial", false, "允许存在未映射字段的规则启用")
	fieldMapString := flag.String("field-map", "", "字段映射JSON字符串")
	fieldMapFile := flag.String("field-map-file", "", "字段映射JSON文件路径")
	flag.Parse()

	if *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "缺少必要参数: -input 与 -output")
		os.Exit(1)
	}

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取输入文件失败: %v\n", err)
		os.Exit(1)
	}

	inferred := strings.ToLower(strings.TrimSpace(*format))
	if inferred == "" {
		if looksLikeJSON(data) {
			inferred = "tracee"
		} else {
			ext := strings.ToLower(filepath.Ext(*input))
			if ext == ".json" {
				inferred = "tracee"
			} else {
				inferred = "falco"
			}
		}
	}

	fieldMap := defaultFieldMap()
	if *fieldMapFile != "" {
		custom, err := loadFieldMapFromFile(*fieldMapFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取字段映射文件失败: %v\n", err)
			os.Exit(1)
		}
		mergeFieldMap(fieldMap, custom)
	}
	if *fieldMapString != "" {
		custom, err := loadFieldMapFromString(*fieldMapString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "解析字段映射失败: %v\n", err)
			os.Exit(1)
		}
		mergeFieldMap(fieldMap, custom)
	}

	var rules []DetectionRule
	switch inferred {
	case "falco":
		rules, err = convertFalco(data, *defaultCategory, *defaultSeverity, *enableRules, *allowPartial, fieldMap)
	case "tracee":
		rules, err = convertTracee(data, *defaultCategory, *defaultSeverity, *enableRules)
	default:
		err = fmt.Errorf("不支持的格式: %s", inferred)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "规则转换失败: %v\n", err)
		os.Exit(1)
	}

	out := OutputConfig{
		Global: GlobalConfig{
			EnableFileEvents:       true,
			EnableNetworkEvents:    true,
			EnableProcessEvents:    true,
			EnablePermissionEvents: true,
			EnableMemoryEvents:     true,
			MinUIDFilter:           0,
			MaxUIDFilter:           65535,
			MaxEventsPerSecond:     10000,
			AlertThrottleSeconds:   60,
			MaxAlertHistory:        1000,
			EnableRuleStats:        true,
			LogLevel:               "info",
		},
		DetectionRules: make(map[string][]DetectionRule),
	}
	for _, rule := range rules {
		category := rule.Category
		if category == "" {
			category = *defaultCategory
		}
		out.DetectionRules[category] = append(out.DetectionRules[category], rule)
	}

	encoded, err := yaml.Marshal(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "序列化输出失败: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*output, encoded, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "写入输出文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("已转换规则数量: %d\n", len(rules))
	fmt.Printf("输出文件: %s\n", *output)
}

func convertFalco(data []byte, defaultCategory, defaultSeverity string, enableRules bool, allowPartial bool, fieldMap FieldMap) ([]DetectionRule, error) {
	content, err := parseFalcoContent(data)
	if err != nil {
		return nil, err
	}
	rules := content.Rules
	results := make([]DetectionRule, 0, len(rules))
	for _, rule := range rules {
		name := strings.TrimSpace(rule.Rule)
		if name == "" {
			continue
		}
		description := strings.TrimSpace(rule.Desc)
		if description == "" {
			description = strings.TrimSpace(rule.Output)
		}

		expanded := expandMacros(rule.Condition, content.Macros, nil, 0)
		variants := parseFalcoConditionVariants(expanded, fieldMap, content.Lists)
		if len(variants) == 0 {
			variants = []ConditionVariant{{Conditions: nil, Unmapped: nil, Unparsed: []string{strings.TrimSpace(expanded)}}}
		}
		category := inferCategory(rule.Tags, defaultCategory)
		for i, variant := range variants {
			enabled := enableRules && len(variant.Conditions) > 0 && (allowPartial || len(variant.Unmapped) == 0)
			metadata := map[string]string{
				"source":          "falco",
				"priority":        strings.TrimSpace(rule.Priority),
				"raw_condition":   rule.Condition,
				"expanded_cond":   expanded,
				"original_output": rule.Output,
			}
			nameWithVariant := name
			if len(variants) > 1 {
				nameWithVariant = fmt.Sprintf("%s [variant %d]", name, i+1)
				metadata["original_rule_name"] = name
				metadata["variant_index"] = fmt.Sprintf("%d", i+1)
				metadata["variant_total"] = fmt.Sprintf("%d", len(variants))
			}
			if len(variant.Unmapped) > 0 {
				metadata["unmapped_fields"] = strings.Join(variant.Unmapped, ",")
			}
			if len(variant.Unparsed) > 0 {
				metadata["unparsed_conditions"] = strings.Join(variant.Unparsed, " | ")
			}
			if !allowPartial && len(variant.Unmapped) > 0 {
				metadata["disabled_reason"] = "unmapped_fields"
			}
			results = append(results, DetectionRule{
				Name:          nameWithVariant,
				Description:   description,
				Conditions:    variant.Conditions,
				Severity:      mapFalcoPriority(rule.Priority, defaultSeverity),
				LogicOperator: "AND",
				Tags:          rule.Tags,
				Enabled:       enabled,
				Actions:       []string{"log"},
				Metadata:      metadata,
				Category:      category,
			})
		}
	}
	return results, nil
}

func convertTracee(data []byte, defaultCategory, defaultSeverity string, enableRules bool) ([]DetectionRule, error) {
	var raw []map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	results := make([]DetectionRule, 0, len(raw))
	for _, item := range raw {
		name := pickStringPath(item, "name", "id", "title", "metadata.name")
		if name == "" {
			continue
		}
		description := pickStringPath(item, "description", "desc", "metadata.description")
		tags := pickStringSlicePath(item, "tags", "metadata.tags")
		severity := pickStringPath(item, "severity", "level", "metadata.severity")
		if severity == "" {
			severity = defaultSeverity
		}
		category := inferCategory(tags, defaultCategory)

		conditions := make([]map[string]interface{}, 0)
		eventNames := extractTraceeEventNames(item)
		if len(eventNames) > 0 {
			values := make([]interface{}, 0, len(eventNames))
			for _, v := range eventNames {
				values = append(values, v)
			}
			conditions = append(conditions, map[string]interface{}{"event_type": values})
		}

		metadata := map[string]string{
			"source": "tracee",
		}
		if rawStr := stringify(item); rawStr != "" {
			metadata["raw_signature"] = rawStr
		}

		enabled := enableRules && len(conditions) > 0
		results = append(results, DetectionRule{
			Name:          name,
			Description:   description,
			Conditions:    conditions,
			Severity:      normalizeSeverity(severity),
			LogicOperator: "AND",
			Tags:          tags,
			Enabled:       enabled,
			Actions:       []string{"log"},
			Metadata:      metadata,
			Category:      category,
		})
	}
	return results, nil
}

type ConditionVariant struct {
	Conditions []map[string]interface{}
	Unmapped   []string
	Unparsed   []string
}

func parseFalcoConditionVariants(condition string, fieldMap FieldMap, lists map[string][]string) []ConditionVariant {
	condText := strings.TrimSpace(condition)
	if condText == "" {
		return nil
	}
	normalized := trimOuterParens(condText)
	groups := buildDNFGroups(normalized)
	if len(groups) == 0 {
		groups = [][]string{{normalized}}
	}
	variants := make([]ConditionVariant, 0, len(groups))
	for _, group := range groups {
		results := make([]map[string]interface{}, 0, len(group))
		unmapped := make([]string, 0)
		unparsed := make([]string, 0)
		for _, rawPart := range group {
			part := trimOuterParens(strings.TrimSpace(rawPart))
			if part == "" {
				continue
			}
			field, op, value, ok := parseFalcoExpression(part, lists)
			if !ok {
				unparsed = append(unparsed, part)
				continue
			}
			mapped := mapField(field, fieldMap)
			if mapped == "" {
				unmapped = append(unmapped, field)
				continue
			}
			if mapped == "event_type" {
				switch v := value.(type) {
				case []interface{}:
					value = normalizeEventTypeList(v)
				default:
					value = normalizeEventTypeValue(v)
				}
			}
			switch op {
			case "in":
				results = append(results, map[string]interface{}{mapped: value})
			case "not_in":
				results = append(results, map[string]interface{}{mapped: map[string]interface{}{
					"operator": "not_in",
					"value":    value,
				}})
			case "contains":
				results = append(results, map[string]interface{}{mapped: map[string]interface{}{
					"operator": "contains",
					"value":    value,
				}})
			case "not_contains":
				results = append(results, map[string]interface{}{mapped: map[string]interface{}{
					"operator": "not_contains",
					"value":    value,
				}})
			case "regex":
				results = append(results, map[string]interface{}{mapped: map[string]interface{}{
					"operator": "regex",
					"pattern":  value,
				}})
			case "not_regex":
				results = append(results, map[string]interface{}{mapped: map[string]interface{}{
					"operator": "not_regex",
					"pattern":  value,
				}})
			case "not_equals":
				results = append(results, map[string]interface{}{mapped: map[string]interface{}{
					"operator": "not_equals",
					"value":    value,
				}})
			case "exists":
				results = append(results, map[string]interface{}{mapped: map[string]interface{}{
					"operator": "exists",
				}})
			case "not_exists":
				results = append(results, map[string]interface{}{mapped: map[string]interface{}{
					"operator": "not_exists",
				}})
			case "gt", "gte", "lt", "lte":
				results = append(results, map[string]interface{}{mapped: map[string]interface{}{
					"operator": op,
					"value":    value,
				}})
			default:
				results = append(results, map[string]interface{}{mapped: value})
			}
		}
		if len(results) == 0 && len(unmapped) == 0 && len(unparsed) == 0 {
			continue
		}
		variants = append(variants, ConditionVariant{
			Conditions: results,
			Unmapped:   unmapped,
			Unparsed:   unparsed,
		})
	}
	return variants
}

func parseFalcoExpression(expr string, lists map[string][]string) (string, string, interface{}, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", "", nil, false
	}
	negated := false
	lower := strings.ToLower(expr)
	if strings.HasPrefix(lower, "not ") {
		negated = true
		expr = strings.TrimSpace(expr[4:])
	}
	if m := reFalcoNotIn.FindStringSubmatch(expr); len(m) == 3 {
		field := strings.TrimSpace(m[1])
		values := parseListValues(m[2], lists)
		if field == "" || len(values) == 0 {
			return "", "", nil, false
		}
		return field, "not_in", values, true
	}
	if m := reFalcoIn.FindStringSubmatch(expr); len(m) == 3 {
		field := strings.TrimSpace(m[1])
		values := parseListValues(m[2], lists)
		if field == "" || len(values) == 0 {
			return "", "", nil, false
		}
		if negated {
			return field, "not_in", values, true
		}
		return field, "in", values, true
	}

	if m := reFalcoContains.FindStringSubmatch(expr); len(m) == 3 {
		field := strings.TrimSpace(m[1])
		value := strings.Trim(strings.TrimSpace(m[2]), `"'`)
		if field == "" || value == "" {
			return "", "", nil, false
		}
		if negated {
			return field, "not_contains", value, true
		}
		return field, "contains", value, true
	}
	if m := reFalcoIContains.FindStringSubmatch(expr); len(m) == 3 {
		field := strings.TrimSpace(m[1])
		value := strings.Trim(strings.TrimSpace(m[2]), `"'`)
		if field == "" || value == "" {
			return "", "", nil, false
		}
		pattern := "(?i)" + regexp.QuoteMeta(value)
		if negated {
			return field, "not_regex", pattern, true
		}
		return field, "regex", pattern, true
	}
	if m := reFalcoStartsWith.FindStringSubmatch(expr); len(m) == 3 {
		field := strings.TrimSpace(m[1])
		value := strings.Trim(strings.TrimSpace(m[2]), `"'`)
		if field == "" || value == "" {
			return "", "", nil, false
		}
		pattern := "^" + regexp.QuoteMeta(value)
		if negated {
			return field, "not_regex", pattern, true
		}
		return field, "regex", pattern, true
	}
	if m := reFalcoEndsWith.FindStringSubmatch(expr); len(m) == 3 {
		field := strings.TrimSpace(m[1])
		value := strings.Trim(strings.TrimSpace(m[2]), `"'`)
		if field == "" || value == "" {
			return "", "", nil, false
		}
		pattern := regexp.QuoteMeta(value) + "$"
		if negated {
			return field, "not_regex", pattern, true
		}
		return field, "regex", pattern, true
	}

	if m := reFalcoNotEq.FindStringSubmatch(expr); len(m) == 3 {
		field := strings.TrimSpace(m[1])
		value := strings.Trim(strings.TrimSpace(m[2]), `"'`)
		if field == "" || value == "" {
			return "", "", nil, false
		}
		if negated {
			return field, "equals", value, true
		}
		return field, "not_equals", value, true
	}

	if m := reFalcoEq.FindStringSubmatch(expr); len(m) == 3 {
		field := strings.TrimSpace(m[1])
		value := strings.Trim(strings.TrimSpace(m[2]), `"'`)
		if field == "" || value == "" {
			return "", "", nil, false
		}
		if negated {
			return field, "not_equals", value, true
		}
		return field, "equals", value, true
	}
	if m := reFalcoCompare.FindStringSubmatch(expr); len(m) == 4 {
		field := strings.TrimSpace(m[1])
		op := strings.TrimSpace(m[2])
		value := strings.Trim(strings.TrimSpace(m[3]), `"'`)
		if field == "" || value == "" {
			return "", "", nil, false
		}
		if negated {
			switch op {
			case ">":
				return field, "lte", value, true
			case ">=":
				return field, "lt", value, true
			case "<":
				return field, "gte", value, true
			case "<=":
				return field, "gt", value, true
			}
		}
		switch op {
		case ">":
			return field, "gt", value, true
		case ">=":
			return field, "gte", value, true
		case "<":
			return field, "lt", value, true
		case "<=":
			return field, "lte", value, true
		}
	}
	if m := reFalcoExists.FindStringSubmatch(expr); len(m) == 2 {
		field := strings.TrimSpace(m[1])
		if field == "" {
			return "", "", nil, false
		}
		if negated {
			return field, "not_exists", nil, true
		}
		return field, "exists", nil, true
	}
	return "", "", nil, false
}

func trimOuterParens(input string) string {
	s := strings.TrimSpace(input)
	for {
		if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
			return s
		}
		depth := 0
		inSingle := false
		inDouble := false
		valid := true
		for i := 0; i < len(s); i++ {
			ch := s[i]
			if ch == '\'' && !inDouble {
				inSingle = !inSingle
				continue
			}
			if ch == '"' && !inSingle {
				inDouble = !inDouble
				continue
			}
			if inSingle || inDouble {
				continue
			}
			if ch == '(' {
				depth++
				continue
			}
			if ch == ')' {
				depth--
				if depth == 0 && i != len(s)-1 {
					valid = false
					break
				}
			}
		}
		if !valid || depth != 0 {
			return s
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
}

func buildDNFGroups(condition string) [][]string {
	expr := trimOuterParens(strings.TrimSpace(condition))
	if expr == "" {
		return nil
	}
	if parts := splitTopLevelWord(expr, "or"); len(parts) > 1 {
		out := make([][]string, 0, len(parts))
		for _, part := range parts {
			out = append(out, buildDNFGroups(part)...)
		}
		return out
	}
	if parts := splitTopLevelWord(expr, "and"); len(parts) > 1 {
		out := [][]string{{}}
		for _, part := range parts {
			partGroups := buildDNFGroups(part)
			if len(partGroups) == 0 {
				continue
			}
			next := make([][]string, 0, len(out)*len(partGroups))
			for _, left := range out {
				for _, right := range partGroups {
					merged := append(append([]string{}, left...), right...)
					next = append(next, merged)
				}
			}
			out = next
		}
		return out
	}
	return [][]string{{expr}}
}

func mapField(field string, fieldMap FieldMap) string {
	key := strings.TrimSpace(field)
	if key == "" {
		return ""
	}
	if mapped, ok := fieldMap[key]; ok {
		return mapped
	}
	return ""
}

func inferCategory(tags []string, fallback string) string {
	joined := strings.ToLower(strings.Join(tags, ","))
	switch {
	case strings.Contains(joined, "network"):
		return "network"
	case strings.Contains(joined, "file"):
		return "file"
	case strings.Contains(joined, "process") || strings.Contains(joined, "exec"):
		return "process"
	case strings.Contains(joined, "privilege"):
		return "privilege"
	default:
		return fallback
	}
}

func mapFalcoPriority(priority, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "emergency", "alert", "critical":
		return "critical"
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "notice", "informational", "info", "debug":
		return "low"
	default:
		return fallback
	}
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(strings.TrimSpace(value))
	case "warning":
		return "medium"
	case "error":
		return "high"
	default:
		return "low"
	}
}

func pickString(data map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := data[key]; ok {
			if s, ok := val.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func pickStringSlice(data map[string]interface{}, key string) []string {
	val, ok := data[key]
	if !ok {
		return nil
	}
	switch v := val.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}
func pickStringPath(data map[string]interface{}, paths ...string) string {
	for _, path := range paths {
		segments := strings.Split(path, ".")
		current := data
		var value interface{}
		for i, segment := range segments {
			item, ok := current[segment]
			if !ok {
				value = nil
				break
			}
			if i == len(segments)-1 {
				value = item
				break
			}
			child, ok := item.(map[string]interface{})
			if !ok {
				value = nil
				break
			}
			current = child
		}
		if s, ok := value.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func pickStringSlicePath(data map[string]interface{}, paths ...string) []string {
	for _, path := range paths {
		segments := strings.Split(path, ".")
		current := data
		var value interface{}
		for i, segment := range segments {
			item, ok := current[segment]
			if !ok {
				value = nil
				break
			}
			if i == len(segments)-1 {
				value = item
				break
			}
			child, ok := item.(map[string]interface{})
			if !ok {
				value = nil
				break
			}
			current = child
		}
		if value == nil {
			continue
		}
		if list, ok := value.([]interface{}); ok {
			out := make([]string, 0, len(list))
			for _, item := range list {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				}
			}
			if len(out) > 0 {
				return out
			}
		}
		if list, ok := value.([]string); ok {
			out := make([]string, 0, len(list))
			for _, s := range list {
				if strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

func stringify(value interface{}) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(data)
}

func looksLikeJSON(data []byte) bool {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return false
	}
	switch v.(type) {
	case []interface{}, map[string]interface{}:
		return true
	default:
		return false
	}
}

func parseFalcoContent(data []byte) (FalcoContent, error) {
	items, err := parseFalcoItems(data)
	if err != nil {
		return FalcoContent{}, err
	}
	content := FalcoContent{
		Macros: map[string]string{},
		Lists:  map[string][]string{},
	}
	for _, item := range items {
		if name := pickItemString(item, "macro"); name != "" {
			cond := pickItemString(item, "condition")
			if cond != "" {
				content.Macros[name] = cond
			}
			continue
		}
		if name := pickItemString(item, "list"); name != "" {
			items := pickItemStringSlice(item, "items")
			if len(items) > 0 {
				content.Lists[name] = items
			}
			continue
		}
		if name := pickItemString(item, "rule"); name != "" {
			content.Rules = append(content.Rules, FalcoRule{
				Rule:      name,
				Desc:      pickItemString(item, "desc"),
				Condition: pickItemString(item, "condition"),
				Output:    pickItemString(item, "output"),
				Priority:  pickItemString(item, "priority"),
				Tags:      pickItemStringSlice(item, "tags"),
			})
		}
	}
	if len(content.Rules) > 0 {
		return content, nil
	}
	var file FalcoRuleFile
	if err := yaml.Unmarshal(data, &file); err == nil && len(file.Rules) > 0 {
		content.Rules = file.Rules
		return content, nil
	}
	return FalcoContent{}, fmt.Errorf("无法解析Falco规则")
}

func parseFalcoItems(data []byte) ([]map[interface{}]interface{}, error) {
	var raw []map[interface{}]interface{}
	if err := yaml.Unmarshal(data, &raw); err == nil && len(raw) > 0 {
		return raw, nil
	}
	var wrapper map[string]interface{}
	if err := yaml.Unmarshal(data, &wrapper); err == nil {
		if items, ok := wrapper["rules"]; ok {
			if list, ok := items.([]interface{}); ok {
				out := make([]map[interface{}]interface{}, 0, len(list))
				for _, item := range list {
					if m, ok := item.(map[interface{}]interface{}); ok {
						out = append(out, m)
					}
				}
				if len(out) > 0 {
					return out, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("无法解析Falco规则")
}

func pickItemString(item map[interface{}]interface{}, key string) string {
	val, ok := item[key]
	if !ok {
		return ""
	}
	if s, ok := val.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func pickItemStringSlice(item map[interface{}]interface{}, key string) []string {
	val, ok := item[key]
	if !ok {
		return nil
	}
	switch v := val.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func parseListValues(raw string, lists map[string][]string) []interface{} {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := splitCSV(raw)
	values := make([]interface{}, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		item := strings.Trim(strings.TrimSpace(part), `"'`)
		if item == "" {
			continue
		}
		if listItems, ok := lists[item]; ok {
			for _, v := range listItems {
				val := strings.TrimSpace(v)
				if val == "" {
					continue
				}
				if _, ok := seen[val]; ok {
					continue
				}
				seen[val] = struct{}{}
				values = append(values, val)
			}
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		values = append(values, item)
	}
	return values
}

func splitCSV(raw string) []string {
	out := make([]string, 0, 4)
	var buf strings.Builder
	var quote rune
	for _, ch := range raw {
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			buf.WriteRune(ch)
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			buf.WriteRune(ch)
			continue
		}
		if ch == ',' {
			part := strings.TrimSpace(buf.String())
			if part != "" {
				out = append(out, part)
			}
			buf.Reset()
			continue
		}
		buf.WriteRune(ch)
	}
	last := strings.TrimSpace(buf.String())
	if last != "" {
		out = append(out, last)
	}
	return out
}

func expandMacros(condition string, macros map[string]string, stack map[string]bool, depth int) string {
	if condition == "" || len(macros) == 0 {
		return condition
	}
	if depth > 20 {
		return condition
	}
	if stack == nil {
		stack = map[string]bool{}
	}
	var out strings.Builder
	inSingle := false
	inDouble := false
	for i := 0; i < len(condition); {
		ch := condition[i]
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			out.WriteByte(ch)
			i++
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			out.WriteByte(ch)
			i++
			continue
		}
		if inSingle || inDouble {
			out.WriteByte(ch)
			i++
			continue
		}
		if isIdentStart(ch) {
			start := i
			i++
			for i < len(condition) && isIdentChar(condition[i]) {
				i++
			}
			token := condition[start:i]
			if expanded, ok := macros[token]; ok && !stack[token] {
				stack[token] = true
				out.WriteByte('(')
				out.WriteString(expandMacros(expanded, macros, stack, depth+1))
				out.WriteByte(')')
				delete(stack, token)
			} else {
				out.WriteString(token)
			}
			continue
		}
		out.WriteByte(ch)
		i++
	}
	return out.String()
}

func isIdentStart(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_'
}

func isIdentChar(ch byte) bool {
	return isIdentStart(ch) || (ch >= '0' && ch <= '9') || ch == '.'
}

func normalizeEventTypeValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return trimmed
		}
		if mapped, ok := eventTypeAlias[strings.ToLower(trimmed)]; ok {
			return mapped
		}
		return trimmed
	default:
		return value
	}
}

func normalizeEventTypeList(values []interface{}) []interface{} {
	out := make([]interface{}, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if s, ok := normalizeEventTypeValue(value).(string); ok {
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
			continue
		}
		out = append(out, value)
	}
	return out
}

func defaultFieldMap() FieldMap {
	return FieldMap{
		"evt.type":             "event_type",
		"evt.name":             "event_type",
		"evt.res":              "ret_code",
		"proc.name":            "comm",
		"proc.exe":             "filename",
		"proc.pid":             "pid",
		"proc.ppid":            "ppid",
		"proc.cmdline":         "cmdline",
		"proc.args":            "cmdline",
		"user.uid":             "uid",
		"user.gid":             "gid",
		"group.gid":            "gid",
		"fd.name":              "filename",
		"file.path":            "filename",
		"evt.severity":         "severity",
		"evt.arg.flags":        "flags",
		"evt.arg.mode":         "mode",
		"evt.arg.size":         "size",
		"evt.arg.addr":         "addr",
		"evt.arg.len":          "len",
		"evt.arg.prot":         "prot",
		"fd.sip":               "src_addr.ip",
		"fd.sport":             "src_addr.port",
		"fd.sproto":            "src_addr.family",
		"fd.cip":               "dst_addr.ip",
		"fd.cport":             "dst_addr.port",
		"fd.cproto":            "dst_addr.family",
		"evt.arg.target":       "target_comm",
		"evt.arg.signal":       "signal",
		"evt.arg.tid":          "target_pid",
		"evt.arg.pid":          "target_pid",
		"proc.aname":           "comm",
		"proc.pname":           "comm",
		"proc.cwd":             "filename",
		"proc.exepath":         "filename",
		"proc.nthreads":        "len",
		"proc.is_exe_writable": "flags",
	}
}

func loadFieldMapFromFile(path string) (FieldMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadFieldMapFromString(string(data))
}

func loadFieldMapFromString(raw string) (FieldMap, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return FieldMap{}, nil
	}
	var data map[string]string
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, err
	}
	out := FieldMap{}
	for k, v := range data {
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		if key == "" || val == "" {
			continue
		}
		if isAllowedTarget(val) {
			out[key] = val
		}
	}
	return out, nil
}

func mergeFieldMap(base FieldMap, custom FieldMap) {
	for k, v := range custom {
		base[k] = v
	}
}

func isAllowedTarget(field string) bool {
	switch field {
	case "event_type", "pid", "ppid", "uid", "gid", "comm", "filename", "syscall_id", "severity",
		"cmdline", "mode", "size", "flags", "ret_code", "addr", "len", "prot",
		"src_addr.ip", "src_addr.port", "src_addr.family", "dst_addr.ip", "dst_addr.port", "dst_addr.family",
		"target_comm", "target_pid", "signal":
		return true
	default:
		return false
	}
}

func splitLogicalCondition(condition string) (string, []string) {
	if parts := splitTopLevelWord(condition, "or"); len(parts) > 1 {
		return "OR", parts
	}
	return "AND", splitTopLevelWord(condition, "and")
}

func splitTopLevelWord(original string, word string) []string {
	lower := strings.ToLower(original)
	w := strings.ToLower(word)
	out := make([]string, 0, 4)

	isSep := func(i int) bool {
		if i < 0 || i >= len(lower) {
			return true
		}
		switch lower[i] {
		case ' ', '\t', '\n', '\r', '(', ')':
			return true
		default:
			return false
		}
	}

	start := 0
	depth := 0
	inSingle := false
	inDouble := false
	for i := 0; i < len(lower); {
		if lower[i] == '\'' && !inDouble {
			inSingle = !inSingle
			i++
			continue
		}
		if lower[i] == '"' && !inSingle {
			inDouble = !inDouble
			i++
			continue
		}
		if inSingle || inDouble {
			i++
			continue
		}
		switch lower[i] {
		case '(':
			depth++
			i++
			continue
		case ')':
			if depth > 0 {
				depth--
			}
			i++
			continue
		default:
		}

		if depth == 0 && i+len(w) <= len(lower) && lower[i:i+len(w)] == w && isSep(i-1) && isSep(i+len(w)) {
			part := strings.TrimSpace(original[start:i])
			if part != "" {
				out = append(out, part)
			}
			i += len(w)
			start = i
			continue
		}
		i++
	}

	last := strings.TrimSpace(original[start:])
	if last != "" {
		out = append(out, last)
	}
	if len(out) == 0 {
		return []string{original}
	}
	return out
}

func extractTraceeEventNames(item map[string]interface{}) []string {
	if name := pickStringPath(item, "event", "eventName", "event_name"); name != "" {
		return []string{name}
	}
	if names := pickStringSlicePath(item, "events", "eventNames", "event_names"); len(names) > 0 {
		return names
	}
	if selectors, ok := item["selectors"].([]interface{}); ok {
		for _, selector := range selectors {
			if selMap, ok := selector.(map[string]interface{}); ok {
				if name := pickStringPath(selMap, "event", "eventName", "event_name"); name != "" {
					return []string{name}
				}
				if names := pickStringSlicePath(selMap, "events", "eventNames", "event_names"); len(names) > 0 {
					return names
				}
			}
		}
	}
	return nil
}

var (
	reFalcoNotIn      = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s+not\s+in\s*\((.*)\)\s*$`)
	reFalcoIn         = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s+in\s*\((.*)\)\s*$`)
	reFalcoContains   = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s+contains\s+(.+?)\s*$`)
	reFalcoIContains  = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s+icontains\s+(.+?)\s*$`)
	reFalcoStartsWith = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s+startswith\s+(.+?)\s*$`)
	reFalcoEndsWith   = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s+endswith\s+(.+?)\s*$`)
	reFalcoNotEq      = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s*!=\s*(.+?)\s*$`)
	reFalcoEq         = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s*=\s*(.+?)\s*$`)
	reFalcoCompare    = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s*(>=|<=|>|<)\s*(.+?)\s*$`)
	reFalcoExists     = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s+exists\s*$`)
)

var eventTypeAlias = map[string]string{
	"open":         "openat",
	"openat":       "openat",
	"openat2":      "openat",
	"execve":       "execve",
	"execveat":     "execveat",
	"fork":         "fork",
	"clone":        "clone",
	"exit":         "exit",
	"read":         "read",
	"write":        "write",
	"close":        "close",
	"unlink":       "unlink",
	"rename":       "rename",
	"chmod":        "chmod",
	"chown":        "chown",
	"connect":      "connect",
	"bind":         "bind",
	"listen":       "listen",
	"accept":       "accept",
	"sendto":       "sendto",
	"recvfrom":     "recvfrom",
	"socket":       "socket",
	"shutdown":     "shutdown",
	"setuid":       "setuid",
	"setgid":       "setgid",
	"setreuid":     "setreuid",
	"setregid":     "setregid",
	"setresuid":    "setresuid",
	"setresgid":    "setresgid",
	"setns":        "setns",
	"unshare":      "unshare",
	"ptrace":       "ptrace",
	"kill":         "kill",
	"mount":        "mount",
	"umount2":      "umount",
	"umount":       "umount",
	"init_module":  "init_module",
	"finit_module": "init_module",
}
