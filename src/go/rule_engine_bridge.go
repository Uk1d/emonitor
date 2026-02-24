package main

import (
	"encoding/json"

	rule "etracee/internal/core/rule"
)

type RuleEngineBridge struct {
	adapter *rule.RuleAdapter
}

func NewRuleEngineBridge(config *rule.EngineConfig) *RuleEngineBridge {
	return &RuleEngineBridge{
		adapter: rule.NewRuleAdapter(config),
	}
}

func (b *RuleEngineBridge) LoadRulesFromYAML(data []byte, source rule.RuleSource) error {
	return b.adapter.LoadRulesFromYAML(data, source)
}

func (b *RuleEngineBridge) MatchEvent(event *EventJSON) []AlertEvent {
	if event == nil {
		return nil
	}

	eventMap := b.convertEventJSON(event)
	if eventMap == nil {
		return nil
	}

	results := b.adapter.GetEngine().Match(eventMap)
	alerts := make([]AlertEvent, 0, len(results))

	for _, result := range results {
		if result == nil || result.Rule == nil {
			continue
		}

		alert := AlertEvent{
			Timestamp:   result.Timestamp,
			RuleName:    result.Rule.Name,
			Severity:    string(result.Rule.Severity),
			Description: result.Rule.Description,
			Event:       event,
			Tags:        result.Rule.Tags,
			Metadata:    convertMetadata(result.Rule.Metadata),
			Actions:     result.Rule.Actions,
			Category:    result.Rule.Category,
		}
		alerts = append(alerts, alert)
	}

	return alerts
}

func (b *RuleEngineBridge) convertEventJSON(event *EventJSON) map[string]interface{} {
	if event == nil {
		return nil
	}

	result := map[string]interface{}{
		"timestamp":   event.Timestamp,
		"pid":         event.PID,
		"ppid":        event.PPID,
		"uid":         event.UID,
		"gid":         event.GID,
		"syscall_id":  event.SyscallID,
		"event_type":  event.EventType,
		"ret_code":    event.RetCode,
		"comm":        event.Comm,
		"cmdline":     event.Cmdline,
		"filename":    event.Filename,
		"mode":        event.Mode,
		"size":        event.Size,
		"flags":       event.Flags,
		"severity":    event.Severity,
		"target_comm": event.TargetComm,
		"target_pid":  event.TargetPID,
		"signal":      event.Signal,
	}

	if event.SrcAddr != nil {
		result["src_addr"] = map[string]interface{}{
			"family": event.SrcAddr.Family,
			"port":   event.SrcAddr.Port,
			"ip":     event.SrcAddr.IP,
		}
		result["src_addr.ip"] = event.SrcAddr.IP
		result["src_addr.port"] = event.SrcAddr.Port
		result["src_addr.family"] = event.SrcAddr.Family
	}

	if event.DstAddr != nil {
		result["dst_addr"] = map[string]interface{}{
			"family": event.DstAddr.Family,
			"port":   event.DstAddr.Port,
			"ip":     event.DstAddr.IP,
		}
		result["dst_addr.ip"] = event.DstAddr.IP
		result["dst_addr.port"] = event.DstAddr.Port
		result["dst_addr.family"] = event.DstAddr.Family
	}

	return result
}

func convertMetadata(m map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		switch val := v.(type) {
		case string:
			result[k] = val
		default:
			if b, err := json.Marshal(val); err == nil {
				result[k] = string(b)
			}
		}
	}
	return result
}

func (b *RuleEngineBridge) GetEngine() *rule.Engine {
	return b.adapter.GetEngine()
}

func (b *RuleEngineBridge) GetStats() *rule.EngineStats {
	return b.adapter.GetStats()
}

func (b *RuleEngineBridge) GetRules() []*rule.UnifiedRule {
	return b.adapter.GetRules()
}

func (b *RuleEngineBridge) EnableRule(id string) bool {
	return b.adapter.GetEngine().EnableRule(id)
}

func (b *RuleEngineBridge) DisableRule(id string) bool {
	return b.adapter.GetEngine().DisableRule(id)
}
