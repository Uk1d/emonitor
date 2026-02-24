package rule

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type FieldMapper interface {
	Map(field string) (string, bool)
	GetAllMappings() map[string]string
}

type CompositeMapper struct {
	mappings map[string]string
}

func NewCompositeMapper() *CompositeMapper {
	return &CompositeMapper{
		mappings: make(map[string]string),
	}
}

func (m *CompositeMapper) AddMapping(falcoField, etraceeField string) {
	m.mappings[falcoField] = etraceeField
}

func (m *CompositeMapper) Map(field string) (string, bool) {
	mapped, ok := m.mappings[field]
	return mapped, ok
}

func (m *CompositeMapper) GetAllMappings() map[string]string {
	result := make(map[string]string)
	for k, v := range m.mappings {
		result[k] = v
	}
	return result
}

func (m *CompositeMapper) Merge(other FieldMapper) {
	for k, v := range other.GetAllMappings() {
		m.mappings[k] = v
	}
}

func NewFalcoFieldMapper() FieldMapper {
	m := NewCompositeMapper()

	mappings := map[string]string{
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

		"user.uid":       "uid",
		"user.name":      "username",
		"user.loginuid":  "loginuid",
		"user.loginname": "loginname",
		"group.gid":      "gid",
		"group.name":     "groupname",

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

		"file.path":      "filename",
		"file.name":      "basename",
		"file.directory": "directory",

		"container.id":               "container_id",
		"container.name":             "container_name",
		"container.image":            "container_image",
		"container.image.repository": "container_image_repo",
		"container.privileged":       "container_privileged",
		"container.start_ts":         "container_start_ts",

		"thread.cap_effective": "cap_effective",
		"thread.tid":           "tid",
		"thread.nam":           "thread_name",

		"k8s.ns":        "k8s_namespace",
		"k8s.pod":       "k8s_pod",
		"k8s.container": "k8s_container",
	}

	for k, v := range mappings {
		m.AddMapping(k, v)
	}

	return m
}

func NewTraceeFieldMapper() FieldMapper {
	m := NewCompositeMapper()

	mappings := map[string]string{
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

		"fd":       "fd",
		"fdName":   "filename",
		"dirfd":    "dirfd",
		"flags":    "flags",
		"mode":     "mode",
		"pathname": "filename",
		"dev":      "dev",
		"inode":    "inode",

		"srcIP":        "src_addr.ip",
		"dstIP":        "dst_addr.ip",
		"srcPort":      "src_addr.port",
		"dstPort":      "dst_addr.port",
		"protocol":     "protocol",
		"socketFamily": "family",
		"domain":       "domain",
		"sockType":     "socket_type",

		"container.id":          "container_id",
		"container.name":        "container_name",
		"container.image":       "container_image",
		"container.imageDigest": "container_image_digest",
		"container.privileged":  "container_privileged",

		"capabilities.effective":   "cap_effective",
		"capabilities.permitted":   "cap_permitted",
		"capabilities.inheritable": "cap_inheritable",

		"cred.uid":  "uid",
		"cred.gid":  "gid",
		"cred.euid": "euid",
		"cred.egid": "egid",
		"cred.suid": "suid",
		"cred.sgid": "sgid",

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

func MapEventType(eventType string) string {
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

func ParseNumericValue(value string) (interface{}, error) {
	if strings.HasPrefix(value, "0x") {
		return strconv.ParseInt(value[2:], 16, 64)
	}
	if strings.Contains(value, ".") {
		return strconv.ParseFloat(value, 64)
	}
	return strconv.ParseInt(value, 10, 64)
}

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
