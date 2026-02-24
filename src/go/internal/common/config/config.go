package config

import (
    "os"
    "strconv"
    "strings"
)

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

func APITokenFromEnv() string {
    return strings.TrimSpace(os.Getenv("ETRACEE_API_TOKEN"))
}

func BindAddrFromEnv() string {
    return strings.TrimSpace(os.Getenv("ETRACEE_BIND_ADDR"))
}

func WSQueueSizeFromEnv(def int) int {
    size := def
    if v := strings.TrimSpace(os.Getenv("ETRACEE_WS_QUEUE_SIZE")); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 8192 {
            size = n
        }
    }
    return size
}

func BoolFromEnv(key string, def bool) bool {
    v := strings.TrimSpace(os.Getenv(key))
    if v == "" { return def }
    lv := strings.ToLower(v)
    return lv == "1" || lv == "true" || lv == "yes" || lv == "on"
}

func Uint32FromEnv(key string, def uint32) uint32 {
    v := strings.TrimSpace(os.Getenv(key))
    if v == "" { return def }
    if n, err := strconv.ParseUint(v, 10, 32); err == nil {
        return uint32(n)
    }
    return def
}

func IntFromEnv(key string, def int) int {
    v := strings.TrimSpace(os.Getenv(key))
    if v == "" { return def }
    if n, err := strconv.Atoi(v); err == nil { return n }
    return def
}

func StringFromEnv(key string, def string) string {
    v := strings.TrimSpace(os.Getenv(key))
    if v == "" { return def }
    return v
}