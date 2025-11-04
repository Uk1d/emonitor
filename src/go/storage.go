package main

import (
    "fmt"
)

// Storage 抽象：支持告警与事件的写入与查询
type Storage interface {
    Init() error
    Close() error
    SaveAlert(alert *ManagedAlert) error
    QueryAlerts(filters map[string]interface{}, page, pageSize int) ([]*ManagedAlert, int, error)
    SaveEvent(event *EventJSON) error
    QueryEvents(filters map[string]interface{}, page, pageSize int) ([]*EventJSON, int, error)
}

// StorageConfig 存储配置
type StorageConfig struct {
    Backend string `yaml:"backend"`
    SQLite  struct {
        Path        string `yaml:"path"`
        JournalMode string `yaml:"journal_mode"`
        Synchronous string `yaml:"synchronous"`
    } `yaml:"sqlite"`
}

// NewStorageFromConfig 根据配置创建存储实例并初始化
func NewStorageFromConfig(cfg *StorageConfig) (Storage, error) {
    if cfg == nil {
        return nil, fmt.Errorf("nil storage config")
    }
    switch cfg.Backend {
    case "sqlite":
        st := &SQLiteStorage{
            Path:        cfg.SQLite.Path,
            JournalMode: cfg.SQLite.JournalMode,
            Synchronous: cfg.SQLite.Synchronous,
        }
        if err := st.Init(); err != nil {
            return nil, err
        }
        return st, nil
    default:
        return nil, fmt.Errorf("unsupported storage backend: %s", cfg.Backend)
    }
}