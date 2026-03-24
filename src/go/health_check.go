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
	"os"
	"runtime"
	"sync"
	"time"
)

// HealthStatus 健康状态
type HealthStatus struct {
	Status      string                 `json:"status"` // "healthy", "degraded", "unhealthy"
	Timestamp   time.Time              `json:"timestamp"`
	Uptime      time.Duration          `json:"uptime"`
	Version     string                 `json:"version"`
	Checks      map[string]Check       `json:"checks"`
	Metrics     *HealthSystemMetrics   `json:"metrics,omitempty"`
}

// Check 单项检查结果
type Check struct {
	Status    string    `json:"status"` // "pass", "warn", "fail"
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// HealthSystemMetrics 健康检查系统指标（用于健康检查报告）
type HealthSystemMetrics struct {
	GoroutineCount int    `json:"goroutine_count"`
	MemoryAllocMB  uint64 `json:"memory_alloc_mb"`
	MemoryTotalMB  uint64 `json:"memory_total_mb"`
	MemorySysMB    uint64 `json:"memory_sys_mb"`
	CPUCount       int    `json:"cpu_count"`
	GOVersion      string `json:"go_version"`
}

// HealthChecker 健康检查器
type HealthChecker struct {
	mu           sync.RWMutex
	startTime    time.Time
	checks       map[string]func() Check
	lastStatus   *HealthStatus
	customChecks map[string]Check
}

// NewHealthChecker 创建健康检查器
func NewHealthChecker() *HealthChecker {
	hc := &HealthChecker{
		startTime:    time.Now(),
		checks:       make(map[string]func() Check),
		customChecks: make(map[string]Check),
	}

	// 注册默认检查
	hc.RegisterCheck("kernel_btf", hc.checkBTF)
	hc.RegisterCheck("kernel_version", hc.checkKernelVersion)
	hc.RegisterCheck("ebpf_permissions", hc.checkEBPFPermissions)
	hc.RegisterCheck("memory", hc.checkMemory)

	return hc
}

// RegisterCheck 注册自定义检查
func (hc *HealthChecker) RegisterCheck(name string, checkFunc func() Check) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.checks[name] = checkFunc
}

// RunChecks 执行所有检查
func (hc *HealthChecker) RunChecks() *HealthStatus {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	status := &HealthStatus{
		Timestamp: time.Now(),
		Uptime:    time.Since(hc.startTime),
		Checks:    make(map[string]Check),
		Version:   GetHealthVersion(),
	}

	allHealthy := true
	hasWarnings := false

	// 执行所有检查
	for name, checkFunc := range hc.checks {
		check := checkFunc()
		status.Checks[name] = check

		if check.Status == "fail" {
			allHealthy = false
		} else if check.Status == "warn" {
			hasWarnings = true
		}
	}

	// 添加自定义检查结果
	for name, check := range hc.customChecks {
		status.Checks[name] = check
	}

	// 收集系统指标
	status.Metrics = hc.collectMetrics()

	// 确定整体状态
	if allHealthy && !hasWarnings {
		status.Status = "healthy"
	} else if allHealthy && hasWarnings {
		status.Status = "degraded"
	} else {
		status.Status = "unhealthy"
	}

	hc.lastStatus = status
	return status
}

// GetLastStatus 获取最后一次检查结果
func (hc *HealthChecker) GetLastStatus() *HealthStatus {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.lastStatus
}

// UpdateCustomCheck 更新自定义检查状态
func (hc *HealthChecker) UpdateCustomCheck(name string, status string, message string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.customChecks[name] = Check{
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
	}
}

// 内置检查函数

func (hc *HealthChecker) checkBTF() Check {
	check := Check{
		Timestamp: time.Now(),
	}

	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		check.Status = "pass"
		check.Message = "BTF support available"
	} else {
		check.Status = "warn"
		check.Message = "BTF not available, may need manual vmlinux.h generation"
	}

	return check
}

func (hc *HealthChecker) checkKernelVersion() Check {
	check := Check{
		Timestamp: time.Now(),
	}

	// 读取内核版本
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		check.Status = "fail"
		check.Message = "Cannot read kernel version"
		return check
	}

	// 简单检查（实际应该解析版本号）
	version := string(data)
	check.Message = fmt.Sprintf("Kernel: %s", version[:minInt(50, len(version))])

	// 检查是否是较新的内核（简化检查）
	if len(version) > 0 {
		check.Status = "pass"
	} else {
		check.Status = "warn"
	}

	return check
}

func (hc *HealthChecker) checkEBPFPermissions() Check {
	check := Check{
		Timestamp: time.Now(),
	}

	if os.Geteuid() == 0 {
		check.Status = "pass"
		check.Message = "Running as root, eBPF permissions available"
	} else {
		check.Status = "fail"
		check.Message = "Not running as root, eBPF operations will fail"
	}

	return check
}

func (hc *HealthChecker) checkMemory() Check {
	check := Check{
		Timestamp: time.Now(),
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	allocMB := m.Alloc / 1024 / 1024
	totalMB := m.TotalAlloc / 1024 / 1024
	sysMB := m.Sys / 1024 / 1024

	check.Message = fmt.Sprintf("Alloc: %dMB, Total: %dMB, Sys: %dMB", allocMB, totalMB, sysMB)

	// 如果内存使用超过 500MB，发出警告
	if allocMB > 500 {
		check.Status = "warn"
	} else {
		check.Status = "pass"
	}

	return check
}

func (hc *HealthChecker) collectMetrics() *HealthSystemMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &HealthSystemMetrics{
		GoroutineCount: runtime.NumGoroutine(),
		MemoryAllocMB:  m.Alloc / 1024 / 1024,
		MemoryTotalMB:  m.TotalAlloc / 1024 / 1024,
		MemorySysMB:    m.Sys / 1024 / 1024,
		CPUCount:       runtime.NumCPU(),
		GOVersion:      runtime.Version(),
	}
}

// minInt 辅助函数
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetHealthVersion 获取版本信息
func GetHealthVersion() string {
	// 可以在编译时通过 -ldflags 注入
	return "dev"
}

// IsHealthy 检查是否健康
func (hc *HealthChecker) IsHealthy() bool {
	status := hc.RunChecks()
	return status.Status == "healthy" || status.Status == "degraded"
}

// Diagnostics 诊断信息
type Diagnostics struct {
	Timestamp   time.Time              `json:"timestamp"`
	Health      *HealthStatus          `json:"health"`
	Environment map[string]string      `json:"environment"`
	Statistics  map[string]interface{} `json:"statistics,omitempty"`
}

// RunDiagnostics 运行完整诊断
func (hc *HealthChecker) RunDiagnostics() *Diagnostics {
	diag := &Diagnostics{
		Timestamp: time.Now(),
		Health:    hc.RunChecks(),
		Environment: map[string]string{
			"GOOS":       runtime.GOOS,
			"GOARCH":     runtime.GOARCH,
			"GO_VERSION": runtime.Version(),
			"UID":        fmt.Sprintf("%d", os.Geteuid()),
			"GID":        fmt.Sprintf("%d", os.Getegid()),
			"PID":        fmt.Sprintf("%d", os.Getpid()),
			"PWD":        func() string { p, _ := os.Getwd(); return p }(),
		},
		Statistics: make(map[string]interface{}),
	}

	// 添加内存统计
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	diag.Statistics["memory"] = map[string]interface{}{
		"alloc":       m.Alloc,
		"total_alloc": m.TotalAlloc,
		"sys":         m.Sys,
		"num_gc":      m.NumGC,
	}

	// 添加 goroutine 统计
	diag.Statistics["goroutines"] = runtime.NumGoroutine()

	return diag
}
