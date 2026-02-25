package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v2"
)

// ConfigManager 配置管理器
type ConfigManager struct {
	mu     sync.RWMutex
	config *SecurityConfig

	// 配置文件路径
	configPath string

	// 热重载支持
	watcher    *ConfigWatcher
	onReload   []func(*SecurityConfig)
}

// SecurityConfig 安全配置结构
type SecurityConfig struct {
	Global          GlobalConfig               `yaml:"global"`
	DetectionRules  map[string][]DetectionRule `yaml:"detection_rules"`
	Whitelist       WhitelistConfig            `yaml:"whitelist"`
	ResponseActions ResponseActionsConfig      `yaml:"response_actions"`
}

// GlobalConfig 全局配置
type GlobalConfig struct {
	EnableFileEvents       bool   `yaml:"enable_file_events"`
	EnableNetworkEvents    bool   `yaml:"enable_network_events"`
	EnableProcessEvents    bool   `yaml:"enable_process_events"`
	EnablePermissionEvents bool   `yaml:"enable_permission_events"`
	EnableMemoryEvents     bool   `yaml:"enable_memory_events"`

	MinUIDFilter       uint32 `yaml:"min_uid_filter"`
	MaxUIDFilter       uint32 `yaml:"max_uid_filter"`
	MaxEventsPerSecond int    `yaml:"max_events_per_second"`
	RingBufferSize     int    `yaml:"ring_buffer_size"`

	AlertThrottleSeconds int    `yaml:"alert_throttle_seconds"`
	MaxAlertHistory      int    `yaml:"max_alert_history"`
	EnableRuleStats      bool   `yaml:"enable_rule_stats"`
	LogLevel             string `yaml:"log_level"`
}

// DetectionRule 检测规则
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

// ConfigWatcher 配置监视器（预留热重载接口）
type ConfigWatcher struct {
	stopCh chan struct{}
}

// NewConfigManager 创建配置管理器
func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		onReload: make([]func(*SecurityConfig), 0),
	}
}

// LoadFromFile 从文件加载配置
func (cm *ConfigManager) LoadFromFile(path string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 读取文件
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// 解析配置
	config, err := cm.parseConfig(data)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// 验证配置
	if err := cm.validateConfig(config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// 设置默认值
	cm.applyDefaults(config)

	cm.config = config
	cm.configPath = path

	return nil
}

// LoadWithFallback 带回退机制的配置加载
func (cm *ConfigManager) LoadWithFallback(primaryPath string, fallbackPaths []string) error {
	// 尝试加载主配置
	if err := cm.LoadFromFile(primaryPath); err == nil {
		return nil
	}

	// 尝试回退路径
	for _, path := range fallbackPaths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := cm.LoadFromFile(path); err == nil {
			return nil
		}
	}

	// 使用默认配置
	return cm.LoadDefaults()
}

// LoadDefaults 加载默认配置
func (cm *ConfigManager) LoadDefaults() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.config = &SecurityConfig{
		Global: GlobalConfig{
			EnableFileEvents:       true,
			EnableNetworkEvents:    true,
			EnableProcessEvents:    true,
			EnablePermissionEvents: true,
			EnableMemoryEvents:     true,
			MinUIDFilter:           0,
			MaxUIDFilter:           65535,
			MaxEventsPerSecond:     10000,
			RingBufferSize:         262144,
			AlertThrottleSeconds:   60,
			MaxAlertHistory:        1000,
			EnableRuleStats:        true,
			LogLevel:               "info",
		},
		DetectionRules: make(map[string][]DetectionRule),
		Whitelist:      WhitelistConfig{},
		ResponseActions: ResponseActionsConfig{
			CriticalSeverity: []string{"log", "alert"},
			HighSeverity:     []string{"log", "alert"},
			MediumSeverity:   []string{"log"},
			LowSeverity:      []string{"log"},
		},
	}

	return nil
}

// parseConfig 解析配置
func (cm *ConfigManager) parseConfig(data []byte) (*SecurityConfig, error) {
	// 先解析为通用结构，处理 Boolish 类型
	var rawConfig struct {
		Global          GlobalConfig               `yaml:"global"`
		DetectionRules  map[string][]DetectionRule `yaml:"detection_rules"`
		Whitelist       WhitelistConfig            `yaml:"whitelist"`
		ResponseActions ResponseActionsConfig      `yaml:"response_actions"`
	}

	if err := yaml.Unmarshal(data, &rawConfig); err != nil {
		return nil, err
	}

	return &SecurityConfig{
		Global:          rawConfig.Global,
		DetectionRules:  rawConfig.DetectionRules,
		Whitelist:       rawConfig.Whitelist,
		ResponseActions: rawConfig.ResponseActions,
	}, nil
}

// validateConfig 验证配置
func (cm *ConfigManager) validateConfig(config *SecurityConfig) error {
	// 验证日志级别
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if config.Global.LogLevel != "" && !validLogLevels[config.Global.LogLevel] {
		return fmt.Errorf("invalid log level: %s", config.Global.LogLevel)
	}

	// 验证严重级别
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	for category, rules := range config.DetectionRules {
		for _, rule := range rules {
			if !validSeverities[rule.Severity] {
				return fmt.Errorf("invalid severity '%s' in rule '%s' (category: %s)",
					rule.Severity, rule.Name, category)
			}
		}
	}

	// 验证 UID 范围
	if config.Global.MinUIDFilter > config.Global.MaxUIDFilter {
		return fmt.Errorf("min_uid_filter (%d) cannot be greater than max_uid_filter (%d)",
			config.Global.MinUIDFilter, config.Global.MaxUIDFilter)
	}

	return nil
}

// applyDefaults 应用默认值
func (cm *ConfigManager) applyDefaults(config *SecurityConfig) {
	// 全局配置默认值
	if config.Global.MaxEventsPerSecond == 0 {
		config.Global.MaxEventsPerSecond = 10000
	}
	if config.Global.MaxAlertHistory == 0 {
		config.Global.MaxAlertHistory = 1000
	}
	if config.Global.AlertThrottleSeconds == 0 {
		config.Global.AlertThrottleSeconds = 60
	}
	if config.Global.MaxUIDFilter == 0 {
		config.Global.MaxUIDFilter = 65535
	}
	if config.Global.LogLevel == "" {
		config.Global.LogLevel = "info"
	}

	// 规则默认值
	for category, rules := range config.DetectionRules {
		for i := range rules {
			// 设置类别
			rules[i].Category = category

			// 设置默认逻辑运算符
			if rules[i].LogicOperator == "" {
				rules[i].LogicOperator = "AND"
			}

			// 设置默认严重级别
			if rules[i].Severity == "" {
				rules[i].Severity = "medium"
			}
		}
	}
}

// GetConfig 获取配置
func (cm *ConfigManager) GetConfig() *SecurityConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.config
}

// GetGlobalConfig 获取全局配置
func (cm *ConfigManager) GetGlobalConfig() GlobalConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.config.Global
}

// GetRules 获取检测规则
func (cm *ConfigManager) GetRules() map[string][]DetectionRule {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// 返回副本
	rules := make(map[string][]DetectionRule)
	for k, v := range cm.config.DetectionRules {
		rules[k] = v
	}
	return rules
}

// OnReload 注册配置重载回调
func (cm *ConfigManager) OnReload(callback func(*SecurityConfig)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.onReload = append(cm.onReload, callback)
}

// Reload 重新加载配置
func (cm *ConfigManager) Reload() error {
	if cm.configPath == "" {
		return fmt.Errorf("no config path set")
	}

	return cm.LoadFromFile(cm.configPath)
}

// SaveToFile 保存配置到文件
func (cm *ConfigManager) SaveToFile(path string) error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	data, err := yaml.Marshal(cm.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// 确保目录存在
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetConfigPaths 获取配置文件搜索路径
func GetConfigPaths(configName string) []string {
	paths := []string{}

	// 当前目录
	paths = append(paths, configName)

	// config 目录
	paths = append(paths, filepath.Join("config", configName))

	// 可执行文件目录
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "config", configName))
	}

	// /etc/etracee 目录
	paths = append(paths, filepath.Join("/etc/etracee", configName))

	return paths
}
