package main

import (
	"strings"
	"sync"
)

// EventType 事件类型定义
type EventType uint32

// 事件类型常量 - 与 eBPF 程序保持一致
const (
	// 进程相关事件 (1-5)
	EventExecve EventType = 1
	EventFork   EventType = 2
	EventClone  EventType = 3
	EventExit   EventType = 4
	EventExecveat EventType = 5

	// 文件系统相关事件 (10-17)
	EventOpenat EventType = 10
	EventClose  EventType = 11
	EventRead   EventType = 12
	EventWrite  EventType = 13
	EventUnlink EventType = 14
	EventRename EventType = 15
	EventChmod  EventType = 16
	EventChown  EventType = 17

	// 网络相关事件 (20-27)
	EventConnect  EventType = 20
	EventBind     EventType = 21
	EventListen   EventType = 22
	EventAccept   EventType = 23
	EventSendto   EventType = 24
	EventRecvfrom EventType = 25
	EventSocket   EventType = 26
	EventShutdown EventType = 27

	// 权限相关事件 (30-38)
	EventSetuid    EventType = 30
	EventSetgid    EventType = 31
	EventSetreuid  EventType = 32
	EventSetregid  EventType = 33
	EventSetresuid EventType = 34
	EventSetresgid EventType = 35
	EventSetns     EventType = 36
	EventUnshare   EventType = 37
	EventPrctl     EventType = 38

	// 内存相关事件 (40-43)
	EventMmap     EventType = 40
	EventMprotect EventType = 41
	EventMunmap   EventType = 42
	EventMremap   EventType = 43

	// 模块相关事件 (50-51)
	EventInitModule   EventType = 50
	EventDeleteModule EventType = 51

	// 系统调用相关 (60-63)
	EventPtrace EventType = 60
	EventKill   EventType = 61
	EventMount  EventType = 62
	EventUmount EventType = 63
)

// 事件类别常量
const (
	CategoryFile       = "file"
	CategoryNetwork    = "network"
	CategoryProcess    = "process"
	CategoryPermission = "permission"
	CategoryMemory     = "memory"
	CategorySystem     = "system"
)

// EventTypeRegistry 事件类型注册表
type EventTypeRegistry struct {
	mu             sync.RWMutex
	typeToString   map[EventType]string
	stringToType   map[string]EventType
	typeToCategory map[EventType]string
	aliasMap       map[string]string // 事件类型别名映射
}

// NewEventTypeRegistry 创建事件类型注册表
func NewEventTypeRegistry() *EventTypeRegistry {
	r := &EventTypeRegistry{
		typeToString:   make(map[EventType]string),
		stringToType:   make(map[string]EventType),
		typeToCategory: make(map[EventType]string),
		aliasMap:       make(map[string]string),
	}

	// 注册基本事件类型
	r.registerBaseTypes()

	// 注册别名
	r.registerAliases()

	return r
}

// registerBaseTypes 注册基本事件类型
func (r *EventTypeRegistry) registerBaseTypes() {
	// 进程相关
	r.register(EventExecve, "execve", CategoryProcess)
	r.register(EventFork, "fork", CategoryProcess)
	r.register(EventClone, "clone", CategoryProcess)
	r.register(EventExit, "exit", CategoryProcess)
	r.register(EventExecveat, "execveat", CategoryProcess)

	// 文件系统相关
	r.register(EventOpenat, "openat", CategoryFile)
	r.register(EventClose, "close", CategoryFile)
	r.register(EventRead, "read", CategoryFile)
	r.register(EventWrite, "write", CategoryFile)
	r.register(EventUnlink, "unlink", CategoryFile)
	r.register(EventRename, "rename", CategoryFile)
	r.register(EventChmod, "chmod", CategoryFile)
	r.register(EventChown, "chown", CategoryFile)

	// 网络相关
	r.register(EventConnect, "connect", CategoryNetwork)
	r.register(EventBind, "bind", CategoryNetwork)
	r.register(EventListen, "listen", CategoryNetwork)
	r.register(EventAccept, "accept", CategoryNetwork)
	r.register(EventSendto, "sendto", CategoryNetwork)
	r.register(EventRecvfrom, "recvfrom", CategoryNetwork)
	r.register(EventSocket, "socket", CategoryNetwork)
	r.register(EventShutdown, "shutdown", CategoryNetwork)

	// 权限相关
	r.register(EventSetuid, "setuid", CategoryPermission)
	r.register(EventSetgid, "setgid", CategoryPermission)
	r.register(EventSetreuid, "setreuid", CategoryPermission)
	r.register(EventSetregid, "setregid", CategoryPermission)
	r.register(EventSetresuid, "setresuid", CategoryPermission)
	r.register(EventSetresgid, "setresgid", CategoryPermission)
	r.register(EventSetns, "setns", CategoryPermission)
	r.register(EventUnshare, "unshare", CategoryPermission)
	r.register(EventPrctl, "prctl", CategoryPermission)

	// 内存相关
	r.register(EventMmap, "mmap", CategoryMemory)
	r.register(EventMprotect, "mprotect", CategoryMemory)
	r.register(EventMunmap, "munmap", CategoryMemory)
	r.register(EventMremap, "mremap", CategoryMemory)

	// 系统调用相关
	r.register(EventPtrace, "ptrace", CategorySystem)
	r.register(EventKill, "kill", CategorySystem)
	r.register(EventMount, "mount", CategorySystem)
	r.register(EventUmount, "umount", CategorySystem)

	// 内核模块相关
	r.register(EventInitModule, "init_module", CategorySystem)
	r.register(EventDeleteModule, "delete_module", CategorySystem)
}

// registerAliases 注册事件类型别名
func (r *EventTypeRegistry) registerAliases() {
	// 文件相关别名
	r.aliasMap["file_open"] = "openat"
	r.aliasMap["file_delete"] = "unlink"
	r.aliasMap["file_modify"] = "write"

	// 网络相关别名
	r.aliasMap["network_connect"] = "connect"

	// 进程相关别名
	r.aliasMap["process_create"] = "execve"
}

// register 注册事件类型
func (r *EventTypeRegistry) register(et EventType, name string, category string) {
	r.typeToString[et] = name
	r.stringToType[name] = et
	r.typeToCategory[et] = category
}

// String 将事件类型转换为字符串
func (r *EventTypeRegistry) String(et EventType) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if s, ok := r.typeToString[et]; ok {
		return s
	}
	return "unknown"
}

// Parse 将字符串解析为事件类型
func (r *EventTypeRegistry) Parse(s string) EventType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 先检查别名
	if alias, ok := r.aliasMap[strings.ToLower(s)]; ok {
		s = alias
	}

	if et, ok := r.stringToType[strings.ToLower(s)]; ok {
		return et
	}
	return EventType(0)
}

// Category 获取事件类型的类别
func (r *EventTypeRegistry) Category(et EventType) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if c, ok := r.typeToCategory[et]; ok {
		return c
	}
	return "unknown"
}

// MatchEventType 匹配事件类型（支持别名）
func (r *EventTypeRegistry) MatchEventType(actual string, expected string) bool {
	// 直接匹配
	if strings.EqualFold(actual, expected) {
		return true
	}

	// 别名匹配
	if alias, ok := r.aliasMap[strings.ToLower(expected)]; ok {
		if strings.EqualFold(actual, alias) {
			return true
		}
	}

	// 特殊匹配规则
	switch strings.ToLower(expected) {
	case "network_connect":
		return actual == "connect"
	case "file_delete":
		return actual == "unlink"
	case "file_modify":
		return actual == "write" || actual == "chmod" || actual == "chown" || actual == "rename"
	case "file_open":
		return actual == "openat"
	case "process_create":
		return actual == "execve" || actual == "execveat" || actual == "fork" || actual == "clone"
	}

	return false
}

// GetEventsByCategory 获取指定类别的所有事件类型
func (r *EventTypeRegistry) GetEventsByCategory(category string) []EventType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var events []EventType
	for et, cat := range r.typeToCategory {
		if cat == category {
			events = append(events, et)
		}
	}
	return events
}

// GetAllCategories 获取所有事件类别
func (r *EventTypeRegistry) GetAllCategories() []string {
	return []string{
		CategoryFile,
		CategoryNetwork,
		CategoryProcess,
		CategoryPermission,
		CategoryMemory,
		CategorySystem,
	}
}

// 全局事件类型注册表实例
var globalRegistry = NewEventTypeRegistry()

// GetEventTypeRegistry 获取全局事件类型注册表
func GetEventTypeRegistry() *EventTypeRegistry {
	return globalRegistry
}
