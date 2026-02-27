package main

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v2"
)

type storageRoot struct {
	Storage StorageConfig `yaml:"storage"`
}

// StorageConfig 存储配置（MySQL）
type StorageConfig struct {
	Backend string `yaml:"backend"` // mysql

	// MySQL 配置
	MySQL MySQLStorageConfig `yaml:"mysql"`

	// 数据保留策略
	RetentionDays int `yaml:"retention_days"` // 数据保留天数，0表示永久保留
}

// LoadStorageConfig 读取存储配置
func LoadStorageConfig(path string) (*StorageConfig, error) {
	// 默认配置 - 使用 MySQL
	defaultCfg := &StorageConfig{
		Backend: "mysql",
		MySQL: MySQLStorageConfig{
			Host:            "localhost",
			Port:            3306,
			User:            "root",
			Password:        "",
			Database:        "etracee_events",
			MaxOpenConns:    50,
			MaxIdleConns:    10,
			ConnMaxLifetime: 3600,
		},
		RetentionDays: 30, // 默认保留30天
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// 文件不存在，返回默认配置
		return defaultCfg, nil
	}

	var root storageRoot
	if err := yaml.Unmarshal(data, &root); err != nil {
		return defaultCfg, nil
	}

	cfg := root.Storage

	// 设置默认值
	if cfg.Backend == "" {
		cfg.Backend = "mysql"
	}

	// MySQL 默认值
	if cfg.MySQL.Host == "" {
		cfg.MySQL.Host = "localhost"
	}
	if cfg.MySQL.Port == 0 {
		cfg.MySQL.Port = 3306
	}
	if cfg.MySQL.Database == "" {
		cfg.MySQL.Database = "etracee_events"
	}
	if cfg.MySQL.MaxOpenConns == 0 {
		cfg.MySQL.MaxOpenConns = 50
	}
	if cfg.MySQL.MaxIdleConns == 0 {
		cfg.MySQL.MaxIdleConns = 10
	}
	if cfg.MySQL.ConnMaxLifetime == 0 {
		cfg.MySQL.ConnMaxLifetime = 3600
	}

	// 数据保留默认值
	if cfg.RetentionDays == 0 {
		cfg.RetentionDays = 30
	}

	return &cfg, nil
}

// GetStorageConfigFromEnv 从环境变量获取存储配置
func GetStorageConfigFromEnv() *StorageConfig {
	cfg := &StorageConfig{
		Backend: "mysql",
		MySQL: MySQLStorageConfig{
			Host:            getEnvOrDefault("MYSQL_EVENTS_HOST", getEnvOrDefault("MYSQL_HOST", "localhost")),
			Port:            getEnvIntOrDefault("MYSQL_EVENTS_PORT", getEnvIntOrDefault("MYSQL_PORT", 3306)),
			User:            getEnvOrDefault("MYSQL_EVENTS_USER", getEnvOrDefault("MYSQL_USER", "root")),
			Password:        getEnvOrDefault("MYSQL_EVENTS_PASSWORD", getEnvOrDefault("MYSQL_PASSWORD", "")),
			Database:        getEnvOrDefault("MYSQL_EVENTS_DATABASE", "etracee_events"),
			MaxOpenConns:    getEnvIntOrDefault("MYSQL_MAX_OPEN_CONNS", 50),
			MaxIdleConns:    getEnvIntOrDefault("MYSQL_MAX_IDLE_CONNS", 10),
			ConnMaxLifetime: getEnvIntOrDefault("MYSQL_CONN_MAX_LIFETIME", 3600),
		},
		RetentionDays: getEnvIntOrDefault("ETRACEE_RETENTION_DAYS", 30),
	}

	return cfg
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
		return defaultValue
	}
	return defaultValue
}
