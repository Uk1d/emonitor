package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// AlertManager 告警管理器
type AlertManager struct {
	// 告警存储
	activeAlerts map[string]*ManagedAlert
	alertHistory []ManagedAlert

	// 告警配置
	config *AlertManagerConfig

	// 告警处理器
	processors map[string]AlertProcessor

	// 统计信息
	stats *AlertStats

	// 同步控制
	mutex sync.RWMutex

	// 通知渠道
	notificationChannels map[string]NotificationChannel

	// 外部存储（可选）
	storage Storage
}

// ManagedAlert 管理的告警
type ManagedAlert struct {
	AlertEvent

	// 唯一标识
	ID string `json:"id"`

	// 管理信息
	Status         AlertStatus `json:"status"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
	AcknowledgedAt *time.Time  `json:"acknowledged_at,omitempty"`
	ResolvedAt     *time.Time  `json:"resolved_at,omitempty"`

	// 处理信息
	AssignedTo      string   `json:"assigned_to,omitempty"`
	ProcessingNotes []string `json:"processing_notes,omitempty"`

	// 关联信息
	RelatedAlerts []string `json:"related_alerts,omitempty"`
	AttackChainID string   `json:"attack_chain_id,omitempty"`

	// 响应动作执行状态
	ActionResults map[string]ActionResult `json:"action_results,omitempty"`

	// 分类和攻击技术信息
	Category    string          `json:"category"`
	MitreAttack *MITRETechnique `json:"mitre_attack,omitempty"`
}

// AlertStatus 告警状态
type AlertStatus string

const (
	AlertStatusNew           AlertStatus = "new"
	AlertStatusAcknowledged  AlertStatus = "acknowledged"
	AlertStatusInProgress    AlertStatus = "in_progress"
	AlertStatusResolved      AlertStatus = "resolved"
	AlertStatusFalsePositive AlertStatus = "false_positive"
	AlertStatusSuppressed    AlertStatus = "suppressed"
)

// ActionResult 动作执行结果
type ActionResult struct {
	Action     string        `json:"action"`
	Status     string        `json:"status"`
	Message    string        `json:"message"`
	ExecutedAt time.Time     `json:"executed_at"`
	Duration   time.Duration `json:"duration"`
	Error      string        `json:"error,omitempty"`
}

// AlertManagerConfig 告警管理器配置
type AlertManagerConfig struct {
	// 告警保留策略
	MaxActiveAlerts    int `yaml:"max_active_alerts"`
	MaxHistoryAlerts   int `yaml:"max_history_alerts"`
	AlertRetentionDays int `yaml:"alert_retention_days"`

	// 告警聚合配置
	EnableAggregation    bool          `yaml:"enable_aggregation"`
	AggregationWindow    time.Duration `yaml:"aggregation_window"`
	AggregationThreshold int           `yaml:"aggregation_threshold"`

	// 自动处理配置
	EnableAutoResolve  bool          `yaml:"enable_auto_resolve"`
	AutoResolveTimeout time.Duration `yaml:"auto_resolve_timeout"`

	// 通知配置
	EnableNotifications bool          `yaml:"enable_notifications"`
	NotificationDelay   time.Duration `yaml:"notification_delay"`

	// 存储配置
	PersistAlerts    bool   `yaml:"persist_alerts"`
	AlertStoragePath string `yaml:"alert_storage_path"`
}

// AlertProcessor 告警处理器接口
type AlertProcessor interface {
	ProcessAlert(alert *ManagedAlert) error
	GetProcessorName() string
}

// NotificationChannel 通知渠道接口
type NotificationChannel interface {
	SendNotification(alert *ManagedAlert) error
	GetChannelName() string
}

// AlertStats 告警统计
type AlertStats struct {
	TotalAlerts           uint64            `json:"total_alerts"`
	ActiveAlerts          uint64            `json:"active_alerts"`
	ResolvedAlerts        uint64            `json:"resolved_alerts"`
	FalsePositives        uint64            `json:"false_positives"`
	SeverityDistribution  map[string]uint64 `json:"severity_distribution"`
	CategoryDistribution  map[string]uint64 `json:"category_distribution"`
	AverageResolutionTime time.Duration     `json:"average_resolution_time"`
	LastResetTime         time.Time         `json:"last_reset_time"`
}

// NewAlertManager 创建告警管理器
func NewAlertManager(config *AlertManagerConfig) *AlertManager {
	if config == nil {
		config = &AlertManagerConfig{
			MaxActiveAlerts:      10000,
			MaxHistoryAlerts:     50000,
			AlertRetentionDays:   30,
			EnableAggregation:    true,
			AggregationWindow:    5 * time.Minute,
			AggregationThreshold: 5,
			EnableAutoResolve:    true,
			AutoResolveTimeout:   24 * time.Hour,
			EnableNotifications:  true,
			NotificationDelay:    30 * time.Second,
			PersistAlerts:        true,
			AlertStoragePath:     "data/alerts",
		}
	}

	am := &AlertManager{
		activeAlerts:         make(map[string]*ManagedAlert),
		alertHistory:         make([]ManagedAlert, 0),
		config:               config,
		processors:           make(map[string]AlertProcessor),
		notificationChannels: make(map[string]NotificationChannel),
		stats: &AlertStats{
			SeverityDistribution: make(map[string]uint64),
			CategoryDistribution: make(map[string]uint64),
			LastResetTime:        time.Now(),
		},
	}

	// 注册默认处理器
	am.RegisterProcessor(&DefaultAlertProcessor{})
	am.RegisterProcessor(&SeverityBasedProcessor{})

	// 注册默认通知渠道
	am.RegisterNotificationChannel(&LogNotificationChannel{})
	am.RegisterNotificationChannel(&FileNotificationChannel{Path: config.AlertStoragePath})

	// 启动后台任务
	go am.startBackgroundTasks()

	return am
}

// SetStorage 注入外部存储
func (am *AlertManager) SetStorage(storage Storage) {
	am.storage = storage
}

// ProcessAlert 处理告警事件
func (am *AlertManager) ProcessAlert(alertEvent AlertEvent) (*ManagedAlert, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// 创建管理告警
	managedAlert := &ManagedAlert{
		AlertEvent:    alertEvent,
		ID:            generateAlertID(),
		Status:        AlertStatusNew,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ActionResults: make(map[string]ActionResult),
	}

	// 检查是否需要聚合
	if am.config.EnableAggregation {
		if existingAlert := am.findSimilarAlert(managedAlert); existingAlert != nil {
			return am.aggregateAlert(existingAlert, managedAlert)
		}
	}

	// 执行响应动作
	am.executeActions(managedAlert)

	// 添加到活跃告警
	am.activeAlerts[managedAlert.ID] = managedAlert

	// 更新统计
	am.updateStats(managedAlert)

	// 运行处理器
	for _, processor := range am.processors {
		if err := processor.ProcessAlert(managedAlert); err != nil {
			log.Printf("告警处理器 %s 执行失败: %v", processor.GetProcessorName(), err)
		}
	}

	// 发送通知
	if am.config.EnableNotifications {
		go am.sendNotifications(managedAlert)
	}

	// 持久化告警
	if am.config.PersistAlerts {
		go am.persistAlert(managedAlert)
	}

	log.Printf("告警已处理: ID=%s, 规则=%s, 严重级别=%s",
		managedAlert.ID, managedAlert.RuleName, managedAlert.Severity)

	return managedAlert, nil
}

// AcknowledgeAlert 确认告警
func (am *AlertManager) AcknowledgeAlert(alertID, acknowledgedBy string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	alert, exists := am.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("告警不存在: %s", alertID)
	}

	now := time.Now()
	alert.Status = AlertStatusAcknowledged
	alert.AcknowledgedAt = &now
	alert.UpdatedAt = now
	alert.AssignedTo = acknowledgedBy

	// 持久化最新状态（acknowledged），确保统计与列表一致
	go am.persistAlert(alert)

	log.Printf("告警已确认: ID=%s, 确认人=%s", alertID, acknowledgedBy)
	return nil
}

// ResolveAlert 解决告警
func (am *AlertManager) ResolveAlert(alertID, resolvedBy, notes string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	alert, exists := am.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("告警不存在: %s", alertID)
	}

	now := time.Now()
	alert.Status = AlertStatusResolved
	alert.ResolvedAt = &now
	alert.UpdatedAt = now
	alert.AssignedTo = resolvedBy

	if notes != "" {
		alert.ProcessingNotes = append(alert.ProcessingNotes,
			fmt.Sprintf("[%s] %s: %s", now.Format("2006-01-02 15:04:05"), resolvedBy, notes))
	}

	// 持久化最新状态（resolved）
	go am.persistAlert(alert)

	// 移动到历史记录
	am.alertHistory = append(am.alertHistory, *alert)
	delete(am.activeAlerts, alertID)

	// 更新统计
	am.stats.ResolvedAlerts++

	log.Printf("告警已解决: ID=%s, 解决人=%s", alertID, resolvedBy)
	return nil
}

// GetActiveAlerts 获取活跃告警
func (am *AlertManager) GetActiveAlerts(filters map[string]interface{}) []*ManagedAlert {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	alerts := make([]*ManagedAlert, 0)
	for _, alert := range am.activeAlerts {
		if am.matchesFilters(alert, filters) {
			alerts = append(alerts, alert)
		}
	}

	// 按创建时间排序（最新的在前）
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].CreatedAt.After(alerts[j].CreatedAt)
	})

	return alerts
}

// GetAlertStats 获取告警统计
func (am *AlertManager) GetAlertStats() *AlertStats {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	stats := *am.stats
	stats.ActiveAlerts = uint64(len(am.activeAlerts))

	// 计算平均解决时间
	if am.stats.ResolvedAlerts > 0 {
		totalResolutionTime := time.Duration(0)
		count := 0

		for _, alert := range am.alertHistory {
			if alert.ResolvedAt != nil {
				resolutionTime := alert.ResolvedAt.Sub(alert.CreatedAt)
				totalResolutionTime += resolutionTime
				count++
			}
		}

		if count > 0 {
			stats.AverageResolutionTime = totalResolutionTime / time.Duration(count)
		}
	}

	return &stats
}

// RegisterProcessor 注册告警处理器
func (am *AlertManager) RegisterProcessor(processor AlertProcessor) {
	am.processors[processor.GetProcessorName()] = processor
	log.Printf("告警处理器已注册: %s", processor.GetProcessorName())
}

// RegisterNotificationChannel 注册通知渠道
func (am *AlertManager) RegisterNotificationChannel(channel NotificationChannel) {
	am.notificationChannels[channel.GetChannelName()] = channel
	log.Printf("通知渠道已注册: %s", channel.GetChannelName())
}

// 私有方法

func (am *AlertManager) executeActions(alert *ManagedAlert) {
	if alert.Actions == nil {
		return
	}

	for _, action := range alert.Actions {
		startTime := time.Now()
		result := ActionResult{
			Action:     action,
			ExecutedAt: startTime,
		}

		switch action {
		case "log":
			result.Status = "success"
			result.Message = "告警已记录到日志"
			log.Printf("执行动作[LOG]: %s", alert.Description)

		case "alert":
			result.Status = "success"
			result.Message = "高优先级告警已生成"
			log.Printf("执行动作[ALERT]: 高危事件 - %s", alert.Description)

		case "block":
			result.Status = "warning"
			result.Message = "阻止动作已记录（需要内核模块支持实际阻止）"
			log.Printf("执行动作[BLOCK]: 阻止事件 - %s", alert.Description)

		case "quarantine":
			result.Status = "warning"
			result.Message = "隔离动作已记录（需要额外权限）"
			pid := uint32(0)
			if alert.Event != nil {
				pid = alert.Event.PID
			}
			log.Printf("执行动作[QUARANTINE]: 隔离进程 - PID: %d", pid)

		case "notify":
			result.Status = "success"
			result.Message = "通知已发送"
			// 通知逻辑在 sendNotifications 中处理

		default:
			result.Status = "error"
			result.Message = fmt.Sprintf("未知动作: %s", action)
			result.Error = "unsupported action"
		}

		result.Duration = time.Since(startTime)
		alert.ActionResults[action] = result
	}
}

func (am *AlertManager) findSimilarAlert(newAlert *ManagedAlert) *ManagedAlert {
	cutoffTime := time.Now().Add(-am.config.AggregationWindow)

	for _, alert := range am.activeAlerts {
		if alert.CreatedAt.Before(cutoffTime) {
			continue
		}

		// 检查相似性：相同规则、相同进程、相同用户
		if alert.Event == nil || newAlert.Event == nil {
			continue
		}
		if alert.RuleName == newAlert.RuleName &&
			alert.Event.Comm == newAlert.Event.Comm &&
			alert.Event.UID == newAlert.Event.UID {
			return alert
		}
	}

	return nil
}

func (am *AlertManager) aggregateAlert(existingAlert, newAlert *ManagedAlert) (*ManagedAlert, error) {
	existingAlert.UpdatedAt = time.Now()

	// 添加处理注释
	note := fmt.Sprintf("聚合告警: 相似事件在 %s 再次发生", newAlert.CreatedAt.Format("15:04:05"))
	existingAlert.ProcessingNotes = append(existingAlert.ProcessingNotes, note)

	log.Printf("告警已聚合: 现有ID=%s, 新事件时间=%s",
		existingAlert.ID, newAlert.CreatedAt.Format("15:04:05"))

	return existingAlert, nil
}

func (am *AlertManager) sendNotifications(alert *ManagedAlert) {
	// 延迟发送通知（避免误报）
	time.Sleep(am.config.NotificationDelay)

	for _, channel := range am.notificationChannels {
		if err := channel.SendNotification(alert); err != nil {
			log.Printf("通知发送失败 [%s]: %v", channel.GetChannelName(), err)
		}
	}
}

// generateAlertID 生成唯一的告警ID
func generateAlertID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// 如果随机数生成失败，使用时间戳作为后备方案
		return fmt.Sprintf("alert_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("alert_%s", hex.EncodeToString(bytes))
}

func (am *AlertManager) persistAlert(alert *ManagedAlert) {
	// 同步写入外部存储（如可用）
	if am.storage != nil {
		if err := am.storage.SaveAlert(alert); err != nil {
			log.Printf("保存告警到存储失败: %v", err)
		}
	}
	if am.config.AlertStoragePath == "" {
		return
	}

	// 确保目录存在
	if err := os.MkdirAll(am.config.AlertStoragePath, 0755); err != nil {
		log.Printf("创建告警存储目录失败: %v", err)
		return
	}

	// 生成文件名
	filename := fmt.Sprintf("alert_%s_%s.json",
		alert.CreatedAt.Format("20060102"), alert.ID)
	filepath := filepath.Join(am.config.AlertStoragePath, filename)

	// 序列化告警
	data, err := json.MarshalIndent(alert, "", "  ")
	if err != nil {
		log.Printf("序列化告警失败: %v", err)
		return
	}

	// 写入文件
	if err := os.WriteFile(filepath, data, 0644); err != nil {
		log.Printf("保存告警文件失败: %v", err)
	}
}

func (am *AlertManager) updateStats(alert *ManagedAlert) {
	am.stats.TotalAlerts++
	am.stats.SeverityDistribution[alert.Severity]++
	am.stats.CategoryDistribution[alert.Category]++
}

func (am *AlertManager) matchesFilters(alert *ManagedAlert, filters map[string]interface{}) bool {
	if len(filters) == 0 {
		return true
	}

	for key, value := range filters {
		switch key {
		case "severity":
			v, ok := value.(string)
			if !ok || alert.Severity != v {
				return false
			}
		case "category":
			v, ok := value.(string)
			if !ok || alert.Category != v {
				return false
			}
		case "status":
			v, ok := value.(string)
			if !ok || alert.Status != AlertStatus(v) {
				return false
			}
		case "rule_name":
			v, ok := value.(string)
			if !ok || alert.RuleName != v {
				return false
			}
		}
	}

	return true
}

func (am *AlertManager) startBackgroundTasks() {
	// 定期清理过期告警
	cleanupTicker := time.NewTicker(1 * time.Hour)
	go func() {
		defer cleanupTicker.Stop()
		for range cleanupTicker.C {
			am.cleanupExpiredAlerts()
		}
	}()

	// 定期自动解决超时告警
	if am.config.EnableAutoResolve {
		autoResolveTicker := time.NewTicker(10 * time.Minute)
		go func() {
			defer autoResolveTicker.Stop()
			for range autoResolveTicker.C {
				am.autoResolveTimeoutAlerts()
			}
		}()
	}
}

func (am *AlertManager) cleanupExpiredAlerts() {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	cutoffTime := time.Now().AddDate(0, 0, -am.config.AlertRetentionDays)

	// 清理历史告警
	newHistory := make([]ManagedAlert, 0)
	for _, alert := range am.alertHistory {
		if alert.CreatedAt.After(cutoffTime) {
			newHistory = append(newHistory, alert)
		}
	}

	removed := len(am.alertHistory) - len(newHistory)
	am.alertHistory = newHistory

	if removed > 0 {
		log.Printf("已清理 %d 个过期历史告警", removed)
	}
}

func (am *AlertManager) autoResolveTimeoutAlerts() {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	cutoffTime := time.Now().Add(-am.config.AutoResolveTimeout)
	resolvedCount := 0

	for id, alert := range am.activeAlerts {
		if alert.CreatedAt.Before(cutoffTime) && alert.Status == AlertStatusNew {
			now := time.Now()
			alert.Status = AlertStatusResolved
			alert.ResolvedAt = &now
			alert.UpdatedAt = now
			alert.ProcessingNotes = append(alert.ProcessingNotes,
				fmt.Sprintf("[%s] 系统: 自动解决超时告警", now.Format("2006-01-02 15:04:05")))

			// 持久化最新状态（resolved）
			go am.persistAlert(alert)

			// 移动到历史记录
			am.alertHistory = append(am.alertHistory, *alert)
			delete(am.activeAlerts, id)

			resolvedCount++
		}
	}

	if resolvedCount > 0 {
		log.Printf("自动解决了 %d 个超时告警", resolvedCount)
	}
}
