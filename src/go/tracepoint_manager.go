package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TracepointManager 管理 eBPF 跟踪点的附加和分离
type TracepointManager struct {
	mu       sync.Mutex
	links    map[string]link.Link
	attached map[string]bool
	errors   map[string]error
}

// TracepointConfig 定义跟踪点配置
type TracepointConfig struct {
	Name     string // 唯一标识符
	Group    string // tracepoint 组名 (如 "syscalls", "sched")
	Event    string // tracepoint 事件名 (如 "sys_enter_execve")
	Program  string // eBPF 程序名
	Category string // 事件类别 (file, network, process, etc.)
	Required bool   // 是否必须成功附加
	Enabled  bool   // 是否启用
}

// NewTracepointManager 创建新的跟踪点管理器
func NewTracepointManager() *TracepointManager {
	return &TracepointManager{
		links:    make(map[string]link.Link),
		attached: make(map[string]bool),
		errors:   make(map[string]error),
	}
}

// Attach 附加单个跟踪点
func (tm *TracepointManager) Attach(cfg TracepointConfig, coll *ebpf.Collection) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// 如果已经附加，跳过
	if tm.attached[cfg.Name] {
		return nil
	}

	// 获取 eBPF 程序
	prog, exists := coll.Programs[cfg.Program]
	if !exists {
		err := fmt.Errorf("program %s not found", cfg.Program)
		tm.errors[cfg.Name] = err
		return err
	}

	// 附加跟踪点
	lnk, err := link.Tracepoint(cfg.Group, cfg.Event, prog, nil)
	if err != nil {
		tm.errors[cfg.Name] = err
		if cfg.Required {
			return fmt.Errorf("failed to attach required tracepoint %s: %w", cfg.Name, err)
		}
		return err
	}

	tm.links[cfg.Name] = lnk
	tm.attached[cfg.Name] = true
	return nil
}

// AttachAll 批量附加跟踪点
func (tm *TracepointManager) AttachAll(configs []TracepointConfig, coll *ebpf.Collection) (int, int) {
	success := 0
	failed := 0

	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		if err := tm.Attach(cfg, coll); err != nil {
			failed++
			if cfg.Required {
				log.Printf("警告: 无法附加必需的跟踪点 %s: %v", cfg.Name, err)
			} else {
				log.Printf("警告: 无法附加到 %s 跟踪点: %v", cfg.Name, err)
			}
		} else {
			success++
			log.Printf("[+] %s 跟踪点已成功附加", cfg.Name)
		}
	}

	return success, failed
}

// Close 关闭所有链接
func (tm *TracepointManager) Close() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for name, lnk := range tm.links {
		if lnk != nil {
			_ = lnk.Close()
			delete(tm.links, name)
		}
	}
}

// GetStatus 获取跟踪点状态
func (tm *TracepointManager) GetStatus(name string) (bool, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if err, exists := tm.errors[name]; exists {
		return false, err
	}
	return tm.attached[name], nil
}

// GetAllStatus 获取所有跟踪点状态
func (tm *TracepointManager) GetAllStatus() map[string]bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	result := make(map[string]bool)
	for name, attached := range tm.attached {
		result[name] = attached
	}
	return result
}

// GetDefaultTracepointConfigs 返回默认的跟踪点配置
func GetDefaultTracepointConfigs() []TracepointConfig {
	return []TracepointConfig{
		// 进程相关
		{Name: "execve", Group: "syscalls", Event: "sys_enter_execve", Program: "trace_execve", Category: CategoryProcess, Required: true, Enabled: true},
		{Name: "exit", Group: "sched", Event: "sched_process_exit", Program: "trace_exit", Category: CategoryProcess, Required: true, Enabled: true},
		{Name: "execveat", Group: "syscalls", Event: "sys_enter_execveat", Program: "trace_execveat", Category: CategoryProcess, Enabled: true},

		// 文件系统相关
		{Name: "openat", Group: "syscalls", Event: "sys_enter_openat", Program: "trace_openat", Category: CategoryFile, Required: true, Enabled: true},
		{Name: "close", Group: "syscalls", Event: "sys_enter_close", Program: "trace_close", Category: CategoryFile, Enabled: true},
		{Name: "read", Group: "syscalls", Event: "sys_exit_read", Program: "trace_read", Category: CategoryFile, Enabled: true},
		{Name: "write", Group: "syscalls", Event: "sys_exit_write", Program: "trace_write", Category: CategoryFile, Enabled: true},
		{Name: "unlinkat", Group: "syscalls", Event: "sys_enter_unlinkat", Program: "trace_unlink", Category: CategoryFile, Enabled: true},
		{Name: "renameat2", Group: "syscalls", Event: "sys_enter_renameat2", Program: "trace_rename", Category: CategoryFile, Enabled: true},
		{Name: "fchmodat", Group: "syscalls", Event: "sys_enter_fchmodat", Program: "trace_chmod", Category: CategoryFile, Enabled: true},
		{Name: "fchownat", Group: "syscalls", Event: "sys_enter_fchownat", Program: "trace_chown", Category: CategoryFile, Enabled: true},

		// 网络相关
		{Name: "connect", Group: "syscalls", Event: "sys_enter_connect", Program: "trace_connect", Category: CategoryNetwork, Required: true, Enabled: true},
		{Name: "bind", Group: "syscalls", Event: "sys_enter_bind", Program: "trace_bind", Category: CategoryNetwork, Enabled: true},
		{Name: "listen", Group: "syscalls", Event: "sys_enter_listen", Program: "trace_listen", Category: CategoryNetwork, Enabled: true},
		{Name: "accept", Group: "syscalls", Event: "sys_enter_accept", Program: "trace_accept", Category: CategoryNetwork, Enabled: true},
		{Name: "accept4", Group: "syscalls", Event: "sys_enter_accept4", Program: "trace_accept4", Category: CategoryNetwork, Enabled: true},
		{Name: "sendto", Group: "syscalls", Event: "sys_enter_sendto", Program: "trace_sendto", Category: CategoryNetwork, Enabled: true},
		{Name: "recvfrom", Group: "syscalls", Event: "sys_enter_recvfrom", Program: "trace_recvfrom", Category: CategoryNetwork, Enabled: true},
		{Name: "socket", Group: "syscalls", Event: "sys_enter_socket", Program: "trace_socket", Category: CategoryNetwork, Enabled: true},
		{Name: "shutdown", Group: "syscalls", Event: "sys_enter_shutdown", Program: "trace_shutdown", Category: CategoryNetwork, Enabled: true},

		// 权限相关
		{Name: "setuid", Group: "syscalls", Event: "sys_enter_setuid", Program: "trace_setuid", Category: CategoryPermission, Enabled: true},
		{Name: "setgid", Group: "syscalls", Event: "sys_enter_setgid", Program: "trace_setgid", Category: CategoryPermission, Enabled: true},
		{Name: "setreuid", Group: "syscalls", Event: "sys_enter_setreuid", Program: "trace_setreuid", Category: CategoryPermission, Enabled: true},
		{Name: "setregid", Group: "syscalls", Event: "sys_enter_setregid", Program: "trace_setregid", Category: CategoryPermission, Enabled: true},
		{Name: "setresuid", Group: "syscalls", Event: "sys_enter_setresuid", Program: "trace_setresuid", Category: CategoryPermission, Enabled: true},
		{Name: "setresgid", Group: "syscalls", Event: "sys_enter_setresgid", Program: "trace_setresgid", Category: CategoryPermission, Enabled: true},
		{Name: "setns", Group: "syscalls", Event: "sys_enter_setns", Program: "trace_setns", Category: CategoryPermission, Enabled: true},
		{Name: "unshare", Group: "syscalls", Event: "sys_enter_unshare", Program: "trace_unshare", Category: CategoryPermission, Enabled: true},
		{Name: "prctl", Group: "syscalls", Event: "sys_enter_prctl", Program: "trace_prctl", Category: CategoryPermission, Enabled: true},

		// 内存相关
		{Name: "mmap", Group: "syscalls", Event: "sys_enter_mmap", Program: "trace_mmap", Category: CategoryMemory, Enabled: true},
		{Name: "mprotect", Group: "syscalls", Event: "sys_enter_mprotect", Program: "trace_mprotect", Category: CategoryMemory, Enabled: true},
		{Name: "munmap", Group: "syscalls", Event: "sys_enter_munmap", Program: "trace_munmap", Category: CategoryMemory, Enabled: true},
		{Name: "mremap", Group: "syscalls", Event: "sys_enter_mremap", Program: "trace_mremap", Category: CategoryMemory, Enabled: true},

		// 系统调用相关
		{Name: "ptrace", Group: "syscalls", Event: "sys_enter_ptrace", Program: "trace_ptrace", Category: CategorySystem, Enabled: true},
		{Name: "kill", Group: "syscalls", Event: "sys_enter_kill", Program: "trace_kill", Category: CategorySystem, Enabled: true},
		{Name: "mount", Group: "syscalls", Event: "sys_enter_mount", Program: "trace_mount", Category: CategorySystem, Enabled: true},
		{Name: "umount", Group: "syscalls", Event: "sys_enter_umount2", Program: "trace_umount", Category: CategorySystem, Enabled: true},

		// 内核模块相关
		{Name: "init_module", Group: "syscalls", Event: "sys_enter_init_module", Program: "trace_init_module", Category: CategorySystem, Enabled: true},
		{Name: "delete_module", Group: "syscalls", Event: "sys_enter_delete_module", Program: "trace_delete_module", Category: CategorySystem, Enabled: true},
	}
}

// FilterByCategory 按类别过滤跟踪点配置
func FilterByCategory(configs []TracepointConfig, categories map[string]bool) []TracepointConfig {
	if len(categories) == 0 {
		return configs
	}

	result := make([]TracepointConfig, 0)
	for _, cfg := range configs {
		if categories[cfg.Category] {
			result = append(result, cfg)
		}
	}
	return result
}

// GetAttachedCount 获取成功附加的跟踪点数量
func (tm *TracepointManager) GetAttachedCount() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return len(tm.attached)
}
