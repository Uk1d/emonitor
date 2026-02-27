package engine

import (
	"encoding/json"
	"fmt"
	"time"
)

// EventAdapter 事件适配器
// 用于将不同格式的事件转换为规则引擎可处理的统一格式
type EventAdapter struct {
	Timestamp  string                 `json:"timestamp"`            // 时间戳
	PID        uint32                 `json:"pid"`                  // 进程ID
	PPID       uint32                 `json:"ppid"`                 // 父进程ID
	UID        uint32                 `json:"uid"`                  // 用户ID
	GID        uint32                 `json:"gid"`                  // 组ID
	SyscallID  uint32                 `json:"syscall_id"`           // 系统调用ID
	EventType  string                 `json:"event_type"`           // 事件类型
	RetCode    int32                  `json:"ret_code"`             // 返回码
	Comm       string                 `json:"comm"`                 // 进程名
	Cmdline    string                 `json:"cmdline,omitempty"`    // 命令行参数
	Filename   string                 `json:"filename,omitempty"`   // 文件名
	Mode       uint32                 `json:"mode,omitempty"`       // 文件模式
	Size       uint64                 `json:"size,omitempty"`       // 文件大小
	Flags      uint32                 `json:"flags,omitempty"`      // 标志位
	SrcAddr    *AddrAdapter           `json:"src_addr,omitempty"`   // 源地址
	DstAddr    *AddrAdapter           `json:"dst_addr,omitempty"`   // 目标地址
	TargetComm string                 `json:"target_comm,omitempty"` // 目标进程名
	TargetPID  uint32                 `json:"target_pid,omitempty"` // 目标进程ID
	Signal     uint32                 `json:"signal,omitempty"`     // 信号值
	Severity   string                 `json:"severity,omitempty"`   // 严重级别
	extra      map[string]interface{} `json:"-"`                    // 额外字段
}

// AddrAdapter 网络地址适配器
type AddrAdapter struct {
	Family string `json:"family"`          // 地址族（IPv4/IPv6）
	Port   uint16 `json:"port,omitempty"`  // 端口号
	IP     string `json:"ip"`              // IP地址
}

// NewEventAdapter 创建事件适配器实例
func NewEventAdapter() *EventAdapter {
	return &EventAdapter{
		extra: make(map[string]interface{}),
	}
}

// ToMap 将事件转换为 map 格式
// 用于规则引擎的统一处理
func (e *EventAdapter) ToMap() map[string]interface{} {
	data, err := json.Marshal(e)
	if err != nil {
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	// 合并额外字段
	for k, v := range e.extra {
		result[k] = v
	}

	return result
}

// SetExtra 设置额外字段
// 用于存储不在标准字段中的自定义数据
func (e *EventAdapter) SetExtra(key string, value interface{}) {
	if e.extra == nil {
		e.extra = make(map[string]interface{})
	}
	e.extra[key] = value
}

// AlertAdapter 告警适配器
// 用于生成标准化格式的告警数据
type AlertAdapter struct {
	Timestamp   time.Time              `json:"timestamp"`   // 告警时间
	RuleName    string                 `json:"rule_name"`   // 触发的规则名称
	Severity    string                 `json:"severity"`    // 严重级别
	Description string                 `json:"description"` // 规则描述
	Event       map[string]interface{} `json:"event"`       // 触发告警的事件
	Tags        []string               `json:"tags"`        // 标签列表
	Metadata    map[string]interface{} `json:"metadata"`    // 元数据
	Actions     []string               `json:"actions"`     // 响应动作
	Category    string                 `json:"category"`    // 事件类别
}

// NewAlertAdapter 从匹配结果创建告警适配器
// 参数 result 为规则匹配结果
// 返回标准化格式的告警，如果结果无效则返回 nil
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

// RuleAdapter 规则适配器
// 提供规则加载和事件匹配的高层接口
type RuleAdapter struct {
	engine *Engine // 规则引擎实例
}

// NewRuleAdapter 创建规则适配器
// 参数 config 为引擎配置
func NewRuleAdapter(config *EngineConfig) *RuleAdapter {
	return &RuleAdapter{
		engine: NewEngine(config),
	}
}

// LoadRulesFromYAML 从 YAML 数据加载规则
// 参数 data 为 YAML 格式的规则数据
// 参数 source 为规则来源类型
func (a *RuleAdapter) LoadRulesFromYAML(data []byte, source RuleSource) error {
	rs, err := a.parseRuleSet(data, source)
	if err != nil {
		return fmt.Errorf("解析规则失败: %w", err)
	}
	return a.engine.LoadRuleSet(rs)
}

// parseRuleSet 解析规则集
// 根据规则来源选择相应的解析器
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

// parseFalcoRuleSet 解析 Falco 格式规则集（预留接口）
func (a *RuleAdapter) parseFalcoRuleSet(data []byte) (*RuleSet, error) {
	return nil, fmt.Errorf("尚未实现")
}

// parseTraceeRuleSet 解析 Tracee 格式规则集（预留接口）
func (a *RuleAdapter) parseTraceeRuleSet(data []byte) (*RuleSet, error) {
	return nil, fmt.Errorf("尚未实现")
}

// parseNativeRuleSet 解析原生格式规则集（预留接口）
func (a *RuleAdapter) parseNativeRuleSet(data []byte) (*RuleSet, error) {
	return nil, fmt.Errorf("尚未实现")
}

// MatchEvent 对事件进行规则匹配
// 参数 event 为待匹配的事件，支持多种格式
// 返回匹配产生的告警列表
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

// convertEvent 将事件转换为 map 格式
// 支持 map、EventAdapter 和其他可 JSON 序列化的类型
func (a *RuleAdapter) convertEvent(event interface{}) map[string]interface{} {
	switch e := event.(type) {
	case map[string]interface{}:
		return e
	case *EventAdapter:
		return e.ToMap()
	default:
		// 尝试 JSON 序列化转换
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

// GetEngine 获取底层规则引擎实例
func (a *RuleAdapter) GetEngine() *Engine {
	return a.engine
}

// GetStats 获取引擎统计数据
func (a *RuleAdapter) GetStats() *EngineStats {
	return a.engine.GetStats()
}

// GetRules 获取所有已加载的规则
func (a *RuleAdapter) GetRules() []*UnifiedRule {
	return a.engine.GetRules()
}
