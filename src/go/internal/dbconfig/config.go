// Package dbconfig 提供数据库配置加载功能
// 监控程序和 Web 服务共用此包
package dbconfig

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Host            string `yaml:"host"`
	Port            int    `yaml:"port"`
	User            string `yaml:"user"`
	Password        string `yaml:"password"`
	Database        string `yaml:"database"`
	MaxOpenConns    int    `yaml:"max_open_conns"`
	MaxIdleConns    int    `yaml:"max_idle_conns"`
	ConnMaxLifetime int    `yaml:"conn_max_lifetime_seconds"`
}

// AdminConfig 管理员配置
type AdminConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// JWTConfig JWT 配置
type JWTConfig struct {
	Secret      string `yaml:"secret"`
	ExpiryHours int    `yaml:"expiry_hours"`
}

// AppConfig 应用配置
type AppConfig struct {
	MonitorDatabase DatabaseConfig `yaml:"monitor_database"`
	WebDatabase     DatabaseConfig `yaml:"web_database"`
	Admin           AdminConfig    `yaml:"admin"`
	JWT             JWTConfig      `yaml:"jwt"`
	RetentionDays   int            `yaml:"retention_days"`
}

// 全局配置
var globalAppConfig *AppConfig

// LoadAppConfig 加载应用配置
func LoadAppConfig() (*AppConfig, error) {
	if globalAppConfig != nil {
		return globalAppConfig, nil
	}

	// 配置文件搜索路径
	configPaths := []string{
		"config/database.yaml",
		"./config/database.yaml",
		"/etc/etracee/database.yaml",
	}

	// 获取可执行文件目录，添加相对路径
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		configPaths = append([]string{
			filepath.Join(execDir, "config/database.yaml"),
			filepath.Join(execDir, "../config/database.yaml"),
		}, configPaths...)
	}

	var configData []byte
	var configPath string
	var err error

	for _, path := range configPaths {
		configData, err = os.ReadFile(path)
		if err == nil {
			configPath = path
			break
		}
	}

	if configData == nil {
		return nil, fmt.Errorf("未找到配置文件，请确保 config/database.yaml 存在")
	}

	var cfg AppConfig
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 设置默认值
	setDefaults(&cfg)

	globalAppConfig = &cfg
	log.Printf("[+] 已加载配置文件: %s", configPath)

	return &cfg, nil
}

// setDefaults 设置默认值
func setDefaults(cfg *AppConfig) {
	// 监控数据库默认值
	if cfg.MonitorDatabase.Host == "" {
		cfg.MonitorDatabase.Host = "localhost"
	}
	if cfg.MonitorDatabase.Port == 0 {
		cfg.MonitorDatabase.Port = 3306
	}
	if cfg.MonitorDatabase.Database == "" {
		cfg.MonitorDatabase.Database = "etracee_events"
	}
	if cfg.MonitorDatabase.MaxOpenConns == 0 {
		cfg.MonitorDatabase.MaxOpenConns = 50
	}
	if cfg.MonitorDatabase.MaxIdleConns == 0 {
		cfg.MonitorDatabase.MaxIdleConns = 10
	}
	if cfg.MonitorDatabase.ConnMaxLifetime == 0 {
		cfg.MonitorDatabase.ConnMaxLifetime = 3600
	}

	// Web 数据库默认值
	if cfg.WebDatabase.Host == "" {
		cfg.WebDatabase.Host = "localhost"
	}
	if cfg.WebDatabase.Port == 0 {
		cfg.WebDatabase.Port = 3306
	}
	if cfg.WebDatabase.Database == "" {
		cfg.WebDatabase.Database = "etracee_web"
	}
	if cfg.WebDatabase.MaxOpenConns == 0 {
		cfg.WebDatabase.MaxOpenConns = 10
	}
	if cfg.WebDatabase.MaxIdleConns == 0 {
		cfg.WebDatabase.MaxIdleConns = 5
	}
	if cfg.WebDatabase.ConnMaxLifetime == 0 {
		cfg.WebDatabase.ConnMaxLifetime = 3600
	}

	// 管理员默认值
	if cfg.Admin.Username == "" {
		cfg.Admin.Username = "admin"
	}
	if cfg.Admin.Password == "" {
		cfg.Admin.Password = "admin123"
	}

	// JWT 默认值
	if cfg.JWT.ExpiryHours == 0 {
		cfg.JWT.ExpiryHours = 24
	}

	// 数据保留默认值
	if cfg.RetentionDays == 0 {
		cfg.RetentionDays = 30
	}
}

// GetMonitorDBConfig 获取监控数据库配置
func (c *AppConfig) GetMonitorDBConfig() *DatabaseConfig {
	return &c.MonitorDatabase
}

// GetWebDBConfig 获取 Web 数据库配置
func (c *AppConfig) GetWebDBConfig() *DatabaseConfig {
	return &c.WebDatabase
}

// GetAppConfig 获取全局配置
func GetAppConfig() *AppConfig {
	return globalAppConfig
}
