package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	rules, err := parseFalcoRules(data)
	if err != nil {
		return nil, err
	}
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

		conditions, logicOp, ok, unmapped := parseFalcoCondition(rule.Condition, fieldMap)
		enabled := enableRules && ok && len(conditions) > 0 && (allowPartial || len(unmapped) == 0)
		metadata := map[string]string{
			"source":          "falco",
			"priority":        strings.TrimSpace(rule.Priority),
			"raw_condition":   rule.Condition,
			"original_output": rule.Output,
		}
		if len(unmapped) > 0 {
			metadata["unmapped_fields"] = strings.Join(unmapped, ",")
		}
		if !allowPartial && len(unmapped) > 0 {
			metadata["disabled_reason"] = "unmapped_fields"
		}

		category := inferCategory(rule.Tags, defaultCategory)
		results = append(results, DetectionRule{
			Name:          name,
			Description:   description,
			Conditions:    conditions,
			Severity:      mapFalcoPriority(rule.Priority, defaultSeverity),
			LogicOperator: logicOp,
			Tags:          rule.Tags,
			Enabled:       enabled,
			Actions:       []string{"log"},
			Metadata:      metadata,
			Category:      category,
		})
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

func parseFalcoCondition(condition string, fieldMap FieldMap) ([]map[string]interface{}, string, bool, []string) {
	condText := strings.TrimSpace(condition)
	if condText == "" {
		return nil, "AND", false, nil
	}
	logic, parts := splitLogicalCondition(condText)
	results := make([]map[string]interface{}, 0, len(parts))
	unmapped := make([]string, 0)
	for _, rawPart := range parts {
		part := strings.Trim(strings.TrimSpace(rawPart), "()")
		if part == "" {
			continue
		}
		field, op, value, ok := parseFalcoExpression(part)
		if !ok {
			return results, logic, false, unmapped
		}
		mapped := mapField(field, fieldMap)
		if mapped == "" {
			unmapped = append(unmapped, field)
			continue
		}
		switch op {
		case "in":
			results = append(results, map[string]interface{}{mapped: value})
		case "contains":
			results = append(results, map[string]interface{}{mapped: map[string]interface{}{
				"operator": "contains",
				"value":    value,
			}})
		case "not_equals":
			results = append(results, map[string]interface{}{mapped: fmt.Sprintf("!=%v", value)})
		default:
			results = append(results, map[string]interface{}{mapped: value})
		}
	}
	return results, logic, len(results) > 0, unmapped
}

func parseFalcoExpression(expr string) (string, string, interface{}, bool) {
	if strings.Contains(expr, " in ") {
		parts := strings.SplitN(expr, " in ", 2)
		field := strings.TrimSpace(parts[0])
		listText := strings.TrimSpace(parts[1])
		listText = strings.Trim(listText, "()")
		if listText == "" {
			return "", "", nil, false
		}
		items := strings.Split(listText, ",")
		values := make([]interface{}, 0, len(items))
		for _, item := range items {
			val := strings.Trim(strings.TrimSpace(item), `"'`)
			if val != "" {
				values = append(values, val)
			}
		}
		if field == "" || len(values) == 0 {
			return "", "", nil, false
		}
		return field, "in", values, true
	}

	if strings.Contains(expr, " contains ") {
		parts := strings.SplitN(expr, " contains ", 2)
		field := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if field == "" || value == "" {
			return "", "", nil, false
		}
		return field, "contains", value, true
	}

	if strings.Contains(expr, "!=") {
		parts := strings.SplitN(expr, "!=", 2)
		field := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if field == "" || value == "" {
			return "", "", nil, false
		}
		return field, "not_equals", value, true
	}

	if strings.Contains(expr, "=") {
		parts := strings.SplitN(expr, "=", 2)
		field := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if field == "" || value == "" {
			return "", "", nil, false
		}
		return field, "equals", value, true
	}

	return "", "", nil, false
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

func parseFalcoRules(data []byte) ([]FalcoRule, error) {
	var file FalcoRuleFile
	if err := yaml.Unmarshal(data, &file); err == nil && len(file.Rules) > 0 {
		return file.Rules, nil
	}
	var raw []FalcoRule
	if err := yaml.Unmarshal(data, &raw); err == nil && len(raw) > 0 {
		return raw, nil
	}
	var wrapper map[string]interface{}
	if err := yaml.Unmarshal(data, &wrapper); err == nil {
		if items, ok := wrapper["rules"]; ok {
			if list, ok := items.([]interface{}); ok {
				out := make([]FalcoRule, 0, len(list))
				for _, item := range list {
					if m, ok := item.(map[interface{}]interface{}); ok {
						converted := make(map[string]interface{})
						for k, v := range m {
							if ks, ok := k.(string); ok {
								converted[ks] = v
							}
						}
						data, err := yaml.Marshal(converted)
						if err == nil {
							var rule FalcoRule
							if err := yaml.Unmarshal(data, &rule); err == nil {
								out = append(out, rule)
							}
						}
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

func defaultFieldMap() FieldMap {
	return FieldMap{
		"evt.type":     "event_type",
		"evt.name":     "event_type",
		"proc.name":    "comm",
		"proc.exe":     "filename",
		"proc.pid":     "pid",
		"proc.ppid":    "ppid",
		"user.uid":     "uid",
		"user.gid":     "gid",
		"group.gid":    "gid",
		"fd.name":      "filename",
		"file.path":    "filename",
		"evt.severity": "severity",
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
	case "event_type", "pid", "ppid", "uid", "gid", "comm", "filename", "syscall_id", "severity":
		return true
	default:
		return false
	}
}

func splitLogicalCondition(condition string) (string, []string) {
	lower := strings.ToLower(condition)
	if strings.Contains(lower, " or ") {
		return "OR", splitByToken(condition, lower, " or ")
	}
	return "AND", splitByToken(condition, lower, " and ")
}

func splitByToken(original string, lower string, token string) []string {
	indices := make([]int, 0)
	start := 0
	for {
		idx := strings.Index(lower[start:], token)
		if idx == -1 {
			break
		}
		indices = append(indices, start+idx)
		start = start + idx + len(token)
	}
	if len(indices) == 0 {
		return []string{original}
	}
	out := make([]string, 0, len(indices)+1)
	prev := 0
	for _, idx := range indices {
		out = append(out, strings.TrimSpace(original[prev:idx]))
		prev = idx + len(token)
	}
	out = append(out, strings.TrimSpace(original[prev:]))
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
