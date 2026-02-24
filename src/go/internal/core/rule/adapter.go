package rule

import (
	"encoding/json"
	"fmt"
	"time"
)

type EventAdapter struct {
	Timestamp  string                 `json:"timestamp"`
	PID        uint32                 `json:"pid"`
	PPID       uint32                 `json:"ppid"`
	UID        uint32                 `json:"uid"`
	GID        uint32                 `json:"gid"`
	SyscallID  uint32                 `json:"syscall_id"`
	EventType  string                 `json:"event_type"`
	RetCode    int32                  `json:"ret_code"`
	Comm       string                 `json:"comm"`
	Cmdline    string                 `json:"cmdline,omitempty"`
	Filename   string                 `json:"filename,omitempty"`
	Mode       uint32                 `json:"mode,omitempty"`
	Size       uint64                 `json:"size,omitempty"`
	Flags      uint32                 `json:"flags,omitempty"`
	SrcAddr    *AddrAdapter           `json:"src_addr,omitempty"`
	DstAddr    *AddrAdapter           `json:"dst_addr,omitempty"`
	TargetComm string                 `json:"target_comm,omitempty"`
	TargetPID  uint32                 `json:"target_pid,omitempty"`
	Signal     uint32                 `json:"signal,omitempty"`
	Severity   string                 `json:"severity,omitempty"`
	extra      map[string]interface{} `json:"-"`
}

type AddrAdapter struct {
	Family string `json:"family"`
	Port   uint16 `json:"port,omitempty"`
	IP     string `json:"ip"`
}

func NewEventAdapter() *EventAdapter {
	return &EventAdapter{
		extra: make(map[string]interface{}),
	}
}

func (e *EventAdapter) ToMap() map[string]interface{} {
	data, err := json.Marshal(e)
	if err != nil {
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	for k, v := range e.extra {
		result[k] = v
	}

	return result
}

func (e *EventAdapter) SetExtra(key string, value interface{}) {
	if e.extra == nil {
		e.extra = make(map[string]interface{})
	}
	e.extra[key] = value
}

type AlertAdapter struct {
	Timestamp   time.Time              `json:"timestamp"`
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Event       map[string]interface{} `json:"event"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
	Actions     []string               `json:"actions"`
	Category    string                 `json:"category"`
}

func NewAlertAdapter(result *MatchResult) *AlertAdapter {
	if result == nil || result.Rule == nil {
		return nil
	}

	return &AlertAdapter{
		Timestamp:   result.Timestamp,
		RuleName:    result.Rule.Name,
		Severity:    string(result.Rule.Severity),
		Description: result.Rule.Description,
		Event:       result.Event,
		Tags:        result.Rule.Tags,
		Metadata:    result.Rule.Metadata,
		Actions:     result.Rule.Actions,
		Category:    result.Rule.Category,
	}
}

type RuleAdapter struct {
	engine *Engine
}

func NewRuleAdapter(config *EngineConfig) *RuleAdapter {
	return &RuleAdapter{
		engine: NewEngine(config),
	}
}

func (a *RuleAdapter) LoadRulesFromYAML(data []byte, source RuleSource) error {
	rs, err := a.parseRuleSet(data, source)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}
	return a.engine.LoadRuleSet(rs)
}

func (a *RuleAdapter) parseRuleSet(data []byte, source RuleSource) (*RuleSet, error) {
	switch source {
	case SourceFalco:
		return a.parseFalcoRuleSet(data)
	case SourceTracee:
		return a.parseTraceeRuleSet(data)
	default:
		return a.parseNativeRuleSet(data)
	}
}

func (a *RuleAdapter) parseFalcoRuleSet(data []byte) (*RuleSet, error) {
	return nil, fmt.Errorf("not implemented")
}

func (a *RuleAdapter) parseTraceeRuleSet(data []byte) (*RuleSet, error) {
	return nil, fmt.Errorf("not implemented")
}

func (a *RuleAdapter) parseNativeRuleSet(data []byte) (*RuleSet, error) {
	return nil, fmt.Errorf("not implemented")
}

func (a *RuleAdapter) MatchEvent(event interface{}) []*AlertAdapter {
	eventMap := a.convertEvent(event)
	if eventMap == nil {
		return nil
	}

	results := a.engine.Match(eventMap)
	alerts := make([]*AlertAdapter, 0, len(results))
	for _, result := range results {
		if alert := NewAlertAdapter(result); alert != nil {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

func (a *RuleAdapter) convertEvent(event interface{}) map[string]interface{} {
	switch e := event.(type) {
	case map[string]interface{}:
		return e
	case *EventAdapter:
		return e.ToMap()
	default:
		data, err := json.Marshal(event)
		if err != nil {
			return nil
		}
		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			return nil
		}
		return result
	}
}

func (a *RuleAdapter) GetEngine() *Engine {
	return a.engine
}

func (a *RuleAdapter) GetStats() *EngineStats {
	return a.engine.GetStats()
}

func (a *RuleAdapter) GetRules() []*UnifiedRule {
	return a.engine.GetRules()
}
