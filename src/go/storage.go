// Copyright 2026 Uk1d
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


package main

import (
	"fmt"
	"log"
	"strconv"
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

// NewStorageFromConfig 根据配置创建存储实例并初始化
func NewStorageFromConfig(cfg *StorageConfig) (Storage, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil storage config")
	}

	// 目前只支持 MySQL
	if cfg.Backend != "mysql" && cfg.Backend != "" {
		return nil, fmt.Errorf("unsupported storage backend: %s (仅支持 mysql)", cfg.Backend)
	}

	storage := NewMySQLStorage(&cfg.MySQL)
	if err := storage.Init(); err != nil {
		return nil, err
	}
	log.Printf("[+] 使用 MySQL 存储: %s@%s:%d/%s", cfg.MySQL.User, cfg.MySQL.Host, cfg.MySQL.Port, cfg.MySQL.Database)
	return storage, nil
}

// getEnvInt 从环境变量获取整数值
func getEnvInt(key string, defaultValue int) int {
	if value := getEnvStr(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getEnvStr 从环境变量获取字符串值
func getEnvStr(key string) string {
	return getEnvOrDefault(key, "")
}
