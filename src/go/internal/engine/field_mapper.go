package engine

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// FieldMapper 字段映射器接口
// 用于将不同规则源的字段名映射到统一的内部字段名
type FieldMapper interface {
	// Map 将源字段名映射到目标字段名
	// 返回映射后的字段名和是否找到映射
	Map(field string) (string, bool)

	// GetAllMappings 获取所有映射关系
	GetAllMappings() map[string]string
}

// CompositeMapper 组合映射器
// 支持添加和合并多个字段映射
type CompositeMapper struct {
	mappings map[string]string // 字段映射表
}

// NewCompositeMapper 创建组合映射器
func NewCompositeMapper() *CompositeMapper {
	return &CompositeMapper{
		mappings: make(map[string]string),
	}
}

// AddMapping 添加字段映射
// 参数 falcoField 为源字段名，etraceeField 为目标字段名
func (m *CompositeMapper) AddMapping(falcoField, etraceeField string) {
	m.mappings[falcoField] = etraceeField
}

// Map 查找字段映射
func (m *CompositeMapper) Map(field string) (string, bool) {
	mapped, ok := m.mappings[field]
	return mapped, ok
}

// GetAllMappings 获取所有映射的副本
func (m *CompositeMapper) GetAllMappings() map[string]string {
	result := make(map[string]string)
	for k, v := range m.mappings {
		result[k] = v
	}
	return result
}

// Merge 合并其他映射器的映射
func (m *CompositeMapper) Merge(other FieldMapper) {
	for k, v := range other.GetAllMappings() {
		m.mappings[k] = v
	}
}

// NewFalcoFieldMapper 创建 Falco 字段映射器
// 将 Falco 字段名映射到 eTracee 内部字段名
func NewFalcoFieldMapper() FieldMapper {
	m := NewCompositeMapper()

	// Falco 到 eTracee 的字段映射
	mappings := map[string]string{
		// 进程相关字段
		"proc.name":               "comm",
		"proc.exe":                "filename",
		"proc.pid":                "pid",
		"proc.ppid":               "ppid",
		"proc.cmdline":            "cmdline",
		"proc.args":               "cmdline",
		"proc.pname":              "parent_comm",
		"proc.pexe":               "parent_filename",
		"proc.exepath":            "filename",
		"proc.cwd":                "cwd",
		"proc.tty":                "tty",
		"proc.is_exe_writable":    "is_exe_writable",
		"proc.is_exe_upper_layer": "is_exe_upper_layer",
		"proc.is_exe_from_memfd":  "is_exe_from_memfd",

		// 用户和组相关字段
		"user.uid":       "uid",
		"user.name":      "username",
		"user.loginuid":  "loginuid",
		"user.loginname": "loginname",
		"group.gid":      "gid",
		"group.name":     "groupname",

		// 文件描述符相关字段
		"fd.name":      "filename",
		"fd.directory": "directory",
		"fd.filename":  "basename",
		"fd.type":      "fd_type",
		"fd.typechar":  "fd_typechar",
		"fd.l4proto":   "protocol",
		"fd.lport":     "local_port",
		"fd.rport":     "remote_port",
		"fd.sport":     "src_addr.port",
		"fd.cport":     "dst_addr.port",
		"fd.sip":       "src_addr.ip",
		"fd.cip":       "dst_addr.ip",
		"fd.sproto":    "src_addr.family",
		"fd.cproto":    "dst_addr.family",
		"fd.nameraw":   "raw_filename",

		// 事件相关字段
		"evt.type":        "event_type",
		"evt.res":         "ret_code",
		"evt.rawres":      "ret_code",
		"evt.severity":    "severity",
		"evt.num":         "syscall_id",
		"evt.args":        "args",
		"evt.arg.flags":   "flags",
		"evt.arg.mode":    "mode",
		"evt.arg.size":    "size",
		"evt.arg.addr":    "addr",
		"evt.arg.len":     "len",
		"evt.arg.prot":    "prot",
		"evt.arg.target":  "target",
		"evt.arg.signal":  "signal",
		"evt.arg.tid":     "target_pid",
		"evt.arg.pid":     "target_pid",
		"evt.arg.oldpath": "oldpath",
		"evt.arg.newpath": "newpath",
		"evt.arg.domain":  "domain",
		"evt.arg.type":    "socket_type",
		"evt.arg.proto":   "protocol",
		"evt.arg.request": "ptrace_request",
		"evt.arg.uid":     "target_uid",
		"evt.arg.gid":     "target_gid",

		// 文件相关字段
		"file.path":      "filename",
		"file.name":      "basename",
		"file.directory": "directory",

		// 容器相关字段
		"container.id":               "container_id",
		"container.name":             "container_name",
		"container.image":            "container_image",
		"container.image.repository": "container_image_repo",
		"container.privileged":       "container_privileged",
		"container.start_ts":         "container_start_ts",

		// 线程相关字段
		"thread.cap_effective": "cap_effective",
		"thread.tid":           "tid",
		"thread.nam":           "thread_name",

		// Kubernetes 相关字段
		"k8s.ns":        "k8s_namespace",
		"k8s.pod":       "k8s_pod",
		"k8s.container": "k8s_container",
	}

	for k, v := range mappings {
		m.AddMapping(k, v)
	}

	return m
}

// NewTraceeFieldMapper 创建 Tracee 字段映射器
// 将 Tracee 字段名映射到 eTracee 内部字段名
func NewTraceeFieldMapper() FieldMapper {
	m := NewCompositeMapper()

	// Tracee 到 eTracee 的字段映射
	mappings := map[string]string{
		// 基本事件字段
		"eventName":           "event_type",
		"event":               "event_type",
		"processId":           "pid",
		"hostProcessId":       "host_pid",
		"parentProcessId":     "ppid",
		"hostParentProcessId": "host_ppid",
		"processName":         "comm",
		"execPath":            "filename",
		"executablePath":      "filename",
		"commandLine":         "cmdline",
		"args":                "cmdline",
		"userId":              "uid",
		"gid":                 "gid",
		"pgid":                "pgid",
		"tid":                 "tid",
		"returnValue":         "ret_code",
		"timestamp":           "timestamp",
		"processorId":         "cpu",
		"contextFlags":        "flags",
		"syscall":             "syscall_id",

		// 文件描述符字段
		"fd":       "fd",
		"fdName":   "filename",
		"dirfd":    "dirfd",
		"flags":    "flags",
		"mode":     "mode",
		"pathname": "filename",
		"dev":      "dev",
		"inode":    "inode",

		// 网络相关字段
		"srcIP":        "src_addr.ip",
		"dstIP":        "dst_addr.ip",
		"srcPort":      "src_addr.port",
		"dstPort":      "dst_addr.port",
		"protocol":     "protocol",
		"socketFamily": "family",
		"domain":       "domain",
		"sockType":     "socket_type",

		// 容器相关字段
		"container.id":          "container_id",
		"container.name":        "container_name",
		"container.image":       "container_image",
		"container.imageDigest": "container_image_digest",
		"container.privileged":  "container_privileged",

		// 权限相关字段
		"capabilities.effective":   "cap_effective",
		"capabilities.permitted":   "cap_permitted",
		"capabilities.inheritable": "cap_inheritable",

		// 凭证相关字段
		"cred.uid":  "uid",
		"cred.gid":  "gid",
		"cred.euid": "euid",
		"cred.egid": "egid",
		"cred.suid": "suid",
		"cred.sgid": "sgid",

		// 元数据字段
		"metadata.version":     "version",
		"metadata.name":        "name",
		"metadata.description": "description",
		"metadata.tags":        "tags",
		"metadata.severity":    "severity",
	}

	for k, v := range mappings {
		m.AddMapping(k, v)
	}

	return m
}

// MapEventToDict 将事件转换为字典格式
// 支持任意可 JSON 序列化的事件类型
func MapEventToDict(event interface{}) map[string]interface{} {
	data, err := json.Marshal(event)
	if err != nil {
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	return result
}

// MapEventType 映射事件类型别名
// 将不同来源的事件类型名称统一为标准名称
func MapEventType(eventType string) string {
	// 事件类型别名映射表
	aliases := map[string]string{
		"open":            "openat",
		"openat2":         "openat",
		"execveat":        "execve",
		"vfork":           "fork",
		"clone3":          "clone",
		"accept4":         "accept",
		"accept_conn":     "accept",
		"connect_unix":    "connect",
		"connect_tcp":     "connect",
		"sendmsg":         "sendto",
		"recvmsg":         "recvfrom",
		"fstat":           "stat",
		"lstat":           "stat",
		"newfstatat":      "stat",
		"statx":           "stat",
		"fchown":          "chown",
		"lchown":          "chown",
		"fchmod":          "chmod",
		"unlinkat":        "unlink",
		"renameat":        "rename",
		"renameat2":       "rename",
		"umount":          "umount2",
		"finit_module":    "init_module",
		"process_create":  "execve",
		"file_open":       "openat",
		"file_delete":     "unlink",
		"file_modify":     "write",
		"network_connect": "connect",
	}

	if mapped, ok := aliases[eventType]; ok {
		return mapped
	}
	return eventType
}

// MapSeverity 映射严重级别
// 将不同来源的优先级名称统一为标准严重级别
func MapSeverity(priority string) Severity {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "emergency", "alert", "critical", "criticality_critical":
		return SeverityCritical
	case "error", "high", "criticality_high":
		return SeverityHigh
	case "warning", "medium", "criticality_medium":
		return SeverityMedium
	case "notice", "informational", "info", "low", "criticality_low":
		return SeverityLow
	case "debug":
		return SeverityInfo
	default:
		return SeverityMedium
	}
}

// ParseNumericValue 解析数值字符串
// 支持十进制、十六进制和浮点数格式
func ParseNumericValue(value string) (interface{}, error) {
	// 十六进制格式
	if strings.HasPrefix(value, "0x") {
		return strconv.ParseInt(value[2:], 16, 64)
	}
	// 浮点数格式
	if strings.Contains(value, ".") {
		return strconv.ParseFloat(value, 64)
	}
	// 十进制整数格式
	return strconv.ParseInt(value, 10, 64)
}

// FormatEventField 格式化事件字段值
// 将任意类型的值转换为字符串表示
func FormatEventField(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case int, int32, int64, uint, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%f", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}
