package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"etracee/internal/engine"
	"etracee/internal/engine/parser/falco"
	"etracee/internal/engine/parser/tracee"
	"gopkg.in/yaml.v2"
)

type UnifiedRuleManager struct {
	mu           sync.RWMutex
	engine       *engine.Engine
	bridge       *RuleEngineBridge
	configPath   string
	falcoParser  *falco.Parser
	traceeParser *tracee.Parser
}

func NewUnifiedRuleManager(configPath string) *UnifiedRuleManager {
	mgr := &UnifiedRuleManager{
		configPath:   configPath,
		falcoParser:  falco.NewFalcoParser(),
		traceeParser: tracee.NewTraceeParser(),
	}

	engineConfig := &engine.EngineConfig{
		EnableStats:     true,
		MaxHistory:      1000,
		DefaultThrottle: 60 * time.Second,
	}
	mgr.engine = engine.NewEngine(engineConfig)
	mgr.bridge = NewRuleEngineBridge(engineConfig)

	return mgr
}

func (m *UnifiedRuleManager) LoadConfig(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return m.loadJSONConfig(data)
	case ".yaml", ".yml":
		return m.loadYAMLConfig(data)
	default:
		return fmt.Errorf("unsupported config format: %s", ext)
	}
}

func (m *UnifiedRuleManager) loadYAMLConfig(data []byte) error {
	var rawConfig struct {
		Global    interface{}              `yaml:"global"`
		Rules     []map[string]interface{} `yaml:"rules"`
		RuleFiles []string                 `yaml:"rule_files"`
		Source    string                   `yaml:"source"`
	}

	if err := yaml.Unmarshal(data, &rawConfig); err != nil {
		return m.loadLegacyYAMLConfig(data)
	}

	if len(rawConfig.RuleFiles) > 0 {
		for _, rf := range rawConfig.RuleFiles {
			if err := m.LoadConfig(rf); err != nil {
				log.Printf("Warning: failed to load rule file %s: %v", rf, err)
			}
		}
	}

	if len(rawConfig.Rules) > 0 {
		source := engine.SourceNative
		if strings.ToLower(rawConfig.Source) == "falco" {
			source = engine.SourceFalco
		} else if strings.ToLower(rawConfig.Source) == "tracee" {
			source = engine.SourceTracee
		}

		rs := engine.NewRuleSet("inline-rules", source)
		for _, r := range rawConfig.Rules {
			ur := m.parseRuleFromMap(r, source)
			if ur != nil {
				rs.AddRule(ur)
			}
		}
		if err := m.engine.LoadRuleSet(rs); err != nil {
			return err
		}
	}

	return nil
}

func (m *UnifiedRuleManager) loadLegacyYAMLConfig(data []byte) error {
	var config struct {
		Global          interface{}              `yaml:"global"`
		DetectionRules  map[string][]interface{} `yaml:"detection_rules"`
		Whitelist       interface{}              `yaml:"whitelist"`
		ResponseActions interface{}              `yaml:"response_actions"`
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	rs := engine.NewRuleSet("legacy-rules", engine.SourceNative)

	for category, rules := range config.DetectionRules {
		for _, r := range rules {
			if ruleMap, ok := r.(map[interface{}]interface{}); ok {
				ur := m.parseLegacyRule(ruleMap, category)
				if ur != nil {
					rs.AddRule(ur)
				}
			} else if ruleMap, ok := r.(map[string]interface{}); ok {
				ur := m.parseRuleFromMap(ruleMap, engine.SourceNative)
				if ur != nil {
					ur.Category = category
					rs.AddRule(ur)
				}
			}
		}
	}

	if whitelist, ok := config.Whitelist.(map[interface{}]interface{}); ok {
		m.loadWhitelist(whitelist)
	}

	return m.engine.LoadRuleSet(rs)
}

func (m *UnifiedRuleManager) loadJSONConfig(data []byte) error {
	var signatures []map[string]interface{}
	if err := json.Unmarshal(data, &signatures); err != nil {
		var single map[string]interface{}
		if err := json.Unmarshal(data, &single); err != nil {
			return fmt.Errorf("failed to parse JSON config: %w", err)
		}
		signatures = []map[string]interface{}{single}
	}

	rs := engine.NewRuleSet("json-rules", engine.SourceTracee)

	for _, sig := range signatures {
		ur := m.parseTraceeSignature(sig)
		if ur != nil {
			rs.AddRule(ur)
		}
	}

	return m.engine.LoadRuleSet(rs)
}

func (m *UnifiedRuleManager) parseRuleFromMap(r map[string]interface{}, source engine.RuleSource) *engine.UnifiedRule {
	name, _ := r["name"].(string)
	if name == "" {
		name, _ = r["rule"].(string)
	}
	if name == "" {
		return nil
	}

	desc, _ := r["description"].(string)
	if desc == "" {
		desc, _ = r["desc"].(string)
	}

	severity := m.parseSeverity(r["severity"])
	if severity == "" {
		severity = m.parseSeverity(r["priority"])
	}

	category, _ := r["category"].(string)
	enabled := true
	if e, ok := r["enabled"]; ok {
		switch v := e.(type) {
		case bool:
			enabled = v
		case string:
			enabled = strings.ToLower(v) == "true"
		}
	}

	tags := m.parseStringSlice(r["tags"])
	actions := m.parseStringSlice(r["actions"])

	conditions := m.parseConditions(r["conditions"])
	if condStr, ok := r["condition"].(string); ok && len(conditions) == 0 {
		conditions = m.parseConditionString(condStr)
	}

	ur := &engine.UnifiedRule{
		ID:          m.generateID(name, source),
		Name:        name,
		Description: desc,
		Source:      source,
		Severity:    engine.Severity(severity),
		Category:    category,
		Enabled:     enabled,
		Conditions:  conditions,
		LogicOp:     engine.LogicAND,
		Tags:        tags,
		Actions:     actions,
		Metadata:    r,
	}

	ur.Compile()
	return ur
}

func (m *UnifiedRuleManager) parseLegacyRule(r map[interface{}]interface{}, category string) *engine.UnifiedRule {
	getString := func(key string) string {
		if v, ok := r[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}

	name := getString("name")
	if name == "" {
		return nil
	}

	enabled := true
	if e, ok := r["enabled"]; ok {
		if b, ok := e.(bool); ok {
			enabled = b
		}
	}

	conditions := make([]engine.ConditionExpr, 0)
	if conds, ok := r["conditions"].([]interface{}); ok {
		for _, c := range conds {
			if condMap, ok := c.(map[string]interface{}); ok {
				cond := m.parseCondition(condMap)
				if cond != nil {
					conditions = append(conditions, cond)
				}
			}
		}
	}

	ur := &engine.UnifiedRule{
		ID:          m.generateID(name, engine.SourceNative),
		Name:        name,
		Description: getString("description"),
		Source:      engine.SourceNative,
		Severity:    engine.Severity(getString("severity")),
		Category:    category,
		Enabled:     enabled,
		Conditions:  conditions,
		LogicOp:     engine.LogicAND,
		Tags:        m.parseLegacyStringSlice(r["tags"]),
		Actions:     m.parseLegacyStringSlice(r["actions"]),
	}

	ur.Compile()
	return ur
}

func (m *UnifiedRuleManager) parseTraceeSignature(sig map[string]interface{}) *engine.UnifiedRule {
	name, _ := sig["name"].(string)
	if name == "" {
		name, _ = sig["metadata"].(map[string]interface{})["name"].(string)
	}
	if name == "" {
		return nil
	}

	conditions := make([]engine.ConditionExpr, 0)

	events := m.extractEvents(sig)
	if len(events) > 0 {
		if len(events) == 1 {
			conditions = append(conditions, &engine.ComparisonExpr{
				Field:    "event_type",
				Operator: engine.OpEquals,
				Value:    events[0],
			})
		} else {
			values := make([]interface{}, len(events))
			for i, e := range events {
				values[i] = e
			}
			conditions = append(conditions, &engine.ComparisonExpr{
				Field:    "event_type",
				Operator: engine.OpIn,
				Value:    values,
			})
		}
	}

	severity, _ := sig["severity"].(string)
	if severity == "" {
		severity = "medium"
	}

	ur := &engine.UnifiedRule{
		ID:          sig["id"].(string),
		Name:        name,
		Description: sig["description"].(string),
		Source:      engine.SourceTracee,
		Severity:    engine.Severity(severity),
		Enabled:     len(conditions) > 0,
		Conditions:  conditions,
		LogicOp:     engine.LogicAND,
		Tags:        m.parseStringSlice(sig["tags"]),
	}

	ur.Compile()
	return ur
}

func (m *UnifiedRuleManager) extractEvents(sig map[string]interface{}) []string {
	events := make([]string, 0)

	if e, ok := sig["event"].(string); ok && e != "" {
		events = append(events, engine.MapEventType(e))
	}

	if es, ok := sig["events"].([]interface{}); ok {
		for _, e := range es {
			if s, ok := e.(string); ok {
				events = append(events, engine.MapEventType(s))
			}
		}
	}

	return events
}

func (m *UnifiedRuleManager) parseCondition(cond map[string]interface{}) engine.ConditionExpr {
	if len(cond) == 0 {
		return nil
	}

	for field, value := range cond {
		mappedField, ok := engine.NewFalcoFieldMapper().Map(field)
		if !ok {
			mappedField = field
		}

		switch v := value.(type) {
		case string:
			return m.parseValueCondition(mappedField, v)
		case map[string]interface{}:
			return m.parseComplexCondition(mappedField, v)
		case []interface{}:
			return &engine.ComparisonExpr{
				Field:    mappedField,
				Operator: engine.OpIn,
				Value:    v,
			}
		}
	}

	return nil
}

func (m *UnifiedRuleManager) parseValueCondition(field, value string) *engine.ComparisonExpr {
	if strings.HasPrefix(value, "regex:") {
		return &engine.ComparisonExpr{
			Field:    field,
			Operator: engine.OpRegex,
			Value:    strings.TrimPrefix(value, "regex:"),
		}
	}

	if strings.Contains(value, "*") {
		pattern := strings.ReplaceAll(strings.ReplaceAll(value, "*", ".*"), ".", "\\.")
		return &engine.ComparisonExpr{
			Field:    field,
			Operator: engine.OpRegex,
			Value:    "^" + pattern + "$",
		}
	}

	if strings.HasPrefix(value, ">=") || strings.HasPrefix(value, "<=") ||
		strings.HasPrefix(value, ">") || strings.HasPrefix(value, "<") {
		return m.parseNumericCondition(field, value)
	}

	return &engine.ComparisonExpr{
		Field:    field,
		Operator: engine.OpEquals,
		Value:    value,
	}
}

func (m *UnifiedRuleManager) parseNumericCondition(field, value string) *engine.ComparisonExpr {
	if strings.HasPrefix(value, ">=") {
		return &engine.ComparisonExpr{
			Field:    field,
			Operator: engine.OpGTE,
			Value:    strings.TrimPrefix(value, ">="),
		}
	}
	if strings.HasPrefix(value, "<=") {
		return &engine.ComparisonExpr{
			Field:    field,
			Operator: engine.OpLTE,
			Value:    strings.TrimPrefix(value, "<="),
		}
	}
	if strings.HasPrefix(value, ">") {
		return &engine.ComparisonExpr{
			Field:    field,
			Operator: engine.OpGT,
			Value:    strings.TrimPrefix(value, ">"),
		}
	}
	if strings.HasPrefix(value, "<") {
		return &engine.ComparisonExpr{
			Field:    field,
			Operator: engine.OpLT,
			Value:    strings.TrimPrefix(value, "<"),
		}
	}

	return &engine.ComparisonExpr{
		Field:    field,
		Operator: engine.OpEquals,
		Value:    value,
	}
}

func (m *UnifiedRuleManager) parseComplexCondition(field string, v map[string]interface{}) *engine.ComparisonExpr {
	op, _ := v["operator"].(string)
	val := v["value"]

	switch strings.ToLower(op) {
	case "contains":
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpContains, Value: val}
	case "not_contains":
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpNotContains, Value: val}
	case "regex":
		pattern, _ := val.(string)
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpRegex, Value: pattern}
	case "not_regex":
		pattern, _ := val.(string)
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpNotRegex, Value: pattern}
	case "in":
		if list, ok := val.([]interface{}); ok {
			return &engine.ComparisonExpr{Field: field, Operator: engine.OpIn, Value: list}
		}
	case "not_in":
		if list, ok := val.([]interface{}); ok {
			return &engine.ComparisonExpr{Field: field, Operator: engine.OpNotIn, Value: list}
		}
	case "exists":
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpExists}
	case "not_exists":
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpNotExists}
	case "gt", ">":
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpGT, Value: val}
	case "gte", ">=":
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpGTE, Value: val}
	case "lt", "<":
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpLT, Value: val}
	case "lte", "<=":
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpLTE, Value: val}
	default:
		return &engine.ComparisonExpr{Field: field, Operator: engine.OpEquals, Value: val}
	}

	return nil
}

func (m *UnifiedRuleManager) parseConditions(conds interface{}) []engine.ConditionExpr {
	result := make([]engine.ConditionExpr, 0)

	switch c := conds.(type) {
	case []interface{}:
		for _, cond := range c {
			if condMap, ok := cond.(map[string]interface{}); ok {
				if expr := m.parseCondition(condMap); expr != nil {
					result = append(result, expr)
				}
			}
		}
	case map[string]interface{}:
		if expr := m.parseCondition(c); expr != nil {
			result = append(result, expr)
		}
	}

	return result
}

func (m *UnifiedRuleManager) parseConditionString(cond string) []engine.ConditionExpr {
	conditions, err := m.falcoParser.ParseCondition(cond)
	if err != nil {
		log.Printf("Warning: failed to parse condition string: %v", err)
		return nil
	}
	return conditions
}

func (m *UnifiedRuleManager) parseSeverity(v interface{}) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return strings.ToLower(s)
	default:
		return ""
	}
}

func (m *UnifiedRuleManager) parseStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return nil
	}
}

func (m *UnifiedRuleManager) parseLegacyStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return nil
	}
}

func (m *UnifiedRuleManager) loadWhitelist(whitelist map[interface{}]interface{}) {
	wl := m.engine.GetWhitelist()

	if procs, ok := whitelist["processes"].([]interface{}); ok {
		for _, p := range procs {
			if s, ok := p.(string); ok {
				wl.AddProcess(s)
			}
		}
	}

	if users, ok := whitelist["users"].([]interface{}); ok {
		for _, u := range users {
			if s, ok := u.(string); ok {
				wl.AddUser(s)
			}
		}
	}

	if files, ok := whitelist["files"].([]interface{}); ok {
		for _, f := range files {
			if s, ok := f.(string); ok {
				wl.AddFile(s)
			}
		}
	}

	if networks, ok := whitelist["networks"].([]interface{}); ok {
		for _, n := range networks {
			if s, ok := n.(string); ok {
				wl.AddNetwork(s)
			}
		}
	}
}

func (m *UnifiedRuleManager) generateID(name string, source engine.RuleSource) string {
	return string(source) + "-" + strings.ToLower(strings.ReplaceAll(name, " ", "-"))
}

func (m *UnifiedRuleManager) MatchEvent(event *EventJSON) []AlertEvent {
	return m.bridge.MatchEvent(event)
}

func (m *UnifiedRuleManager) GetEngine() *engine.Engine {
	return m.engine
}

func (m *UnifiedRuleManager) GetBridge() *RuleEngineBridge {
	return m.bridge
}

func (m *UnifiedRuleManager) GetStats() *engine.EngineStats {
	return m.engine.GetStats()
}

func (m *UnifiedRuleManager) GetRules() []*engine.UnifiedRule {
	return m.engine.GetRules()
}

func (m *UnifiedRuleManager) EnableRule(id string) bool {
	return m.engine.EnableRule(id)
}

func (m *UnifiedRuleManager) DisableRule(id string) bool {
	return m.engine.DisableRule(id)
}

func (m *UnifiedRuleManager) GetRuleCount() int {
	return len(m.engine.GetRules())
}
