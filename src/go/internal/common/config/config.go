// Package config 提供环境变量配置读取功能
// 该包封装了从环境变量读取各类配置的辅助函数，支持默认值设置
package config

import (
	"os"
	"strconv"
	"strings"
)

// AllowedOriginsFromEnv 从环境变量 ETRACEE_ALLOWED_ORIGINS 读取允许的 CORS 来源列表
// 环境变量格式：逗号分隔的域名列表，例如 "http://localhost:3000,https://example.com"
// 返回值为一个空结构体集合，用于高效的 O(1) 查找
func AllowedOriginsFromEnv() map[string]struct{} {
	m := make(map[string]struct{})
	v := strings.TrimSpace(os.Getenv("ETRACEE_ALLOWED_ORIGINS"))
	if v != "" {
		for _, o := range strings.Split(v, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				m[o] = struct{}{}
			}
		}
	}
	return m
}

// APITokenFromEnv 从环境变量 ETRACEE_API_TOKEN 读取 API 认证令牌
// 如果未设置，返回空字符串，表示无需认证
func APITokenFromEnv() string {
	return strings.TrimSpace(os.Getenv("ETRACEE_API_TOKEN"))
}

// BindAddrFromEnv 从环境变量 ETRACEE_BIND_ADDR 读取服务绑定地址
// 格式可以是 "IP:PORT" 或仅 "IP"
// 如果未设置，返回空字符串，由调用方决定默认值
func BindAddrFromEnv() string {
	return strings.TrimSpace(os.Getenv("ETRACEE_BIND_ADDR"))
}

// WSQueueSizeFromEnv 从环境变量 ETRACEE_WS_QUEUE_SIZE 读取 WebSocket 发送队列大小
// 参数 def 为默认值，当环境变量未设置或无效时使用
// 有效范围：1-8192，超出范围则使用默认值
func WSQueueSizeFromEnv(def int) int {
	size := def
	if v := strings.TrimSpace(os.Getenv("ETRACEE_WS_QUEUE_SIZE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 8192 {
			size = n
		}
	}
	return size
}

// BoolFromEnv 从指定环境变量读取布尔值
// 参数 key 为环境变量名，def 为默认值
// 识别为 true 的值：1, true, yes, on（不区分大小写）
// 其他任何值均识别为 false
func BoolFromEnv(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	lv := strings.ToLower(v)
	return lv == "1" || lv == "true" || lv == "yes" || lv == "on"
}

// Uint32FromEnv 从指定环境变量读取无符号 32 位整数
// 参数 key 为环境变量名，def 为默认值
// 如果环境变量未设置或解析失败，返回默认值
func Uint32FromEnv(key string, def uint32) uint32 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	if n, err := strconv.ParseUint(v, 10, 32); err == nil {
		return uint32(n)
	}
	return def
}

// IntFromEnv 从指定环境变量读取整数
// 参数 key 为环境变量名，def 为默认值
// 如果环境变量未设置或解析失败，返回默认值
func IntFromEnv(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

// StringFromEnv 从指定环境变量读取字符串
// 参数 key 为环境变量名，def 为默认值
// 如果环境变量未设置或为空，返回默认值
func StringFromEnv(key string, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}
