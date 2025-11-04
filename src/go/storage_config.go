package main

import (
    "os"
    "path/filepath"

    "gopkg.in/yaml.v2"
)

type storageRoot struct {
    Storage StorageConfig `yaml:"storage"`
}

// LoadStorageConfig 读取存储配置，若不存在则返回默认SQLite配置
func LoadStorageConfig(path string) (*StorageConfig, error) {
    // 默认配置
    defaultCfg := &StorageConfig{
        Backend: "sqlite",
    }
    defaultCfg.SQLite.Path = filepath.ToSlash("data/etracee.db")
    defaultCfg.SQLite.JournalMode = "WAL"
    defaultCfg.SQLite.Synchronous = "NORMAL"

    data, err := os.ReadFile(path)
    if err != nil {
        // 文件不存在，返回默认
        return defaultCfg, nil
    }
    var root storageRoot
    if err := yaml.Unmarshal(data, &root); err != nil {
        return defaultCfg, nil
    }
    cfg := root.Storage
    if cfg.Backend == "" {
        cfg.Backend = "sqlite"
    }
    if cfg.SQLite.Path == "" {
        cfg.SQLite.Path = defaultCfg.SQLite.Path
    }
    if cfg.SQLite.JournalMode == "" {
        cfg.SQLite.JournalMode = defaultCfg.SQLite.JournalMode
    }
    if cfg.SQLite.Synchronous == "" {
        cfg.SQLite.Synchronous = defaultCfg.SQLite.Synchronous
    }
    return &cfg, nil
}