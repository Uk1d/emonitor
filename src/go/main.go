package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"etracee/internal/common/config"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v2"
)

// 事件类型定义 - 与eBPF程序保持一致
type EventType uint32

const (
	// 进程相关事件
	EventExecve   EventType = 1
	EventFork     EventType = 2
	EventClone    EventType = 3
	EventExit     EventType = 4
	EventExecveat EventType = 5

	// 文件系统相关事件
	EventOpenat EventType = 10
	EventClose  EventType = 11
	EventRead   EventType = 12
	EventWrite  EventType = 13
	EventUnlink EventType = 14
	EventRename EventType = 15
	EventChmod  EventType = 16
	EventChown  EventType = 17

	// 网络相关事件
	EventConnect  EventType = 20
	EventBind     EventType = 21
	EventListen   EventType = 22
	EventAccept   EventType = 23
	EventSendto   EventType = 24
	EventRecvfrom EventType = 25
	EventSocket   EventType = 26
	EventShutdown EventType = 27

	// 权限相关事件
	EventSetuid    EventType = 30
	EventSetgid    EventType = 31
	EventSetreuid  EventType = 32
	EventSetregid  EventType = 33
	EventSetresuid EventType = 34
	EventSetresgid EventType = 35
	EventSetns     EventType = 36
	EventUnshare   EventType = 37
	EventPrctl     EventType = 38

	// 内存相关事件
	EventMmap     EventType = 40
	EventMprotect EventType = 41
	EventMunmap   EventType = 42
	EventMremap   EventType = 43

	// 模块相关事件
	EventInitModule   EventType = 50
	EventDeleteModule EventType = 51

	// 系统调用相关
	EventPtrace EventType = 60
	EventKill   EventType = 61
	EventMount  EventType = 62
	EventUmount EventType = 63
)

// 网络地址结构 - 对应eBPF中的network_addr
type NetworkAddr struct {
	Family uint16 `json:"family"`
	Port   uint16 `json:"port"`
	// 使用union的方式，IPv4和IPv6共享同一块内存
	Addr [16]uint8 `json:"addr"` // 对应eBPF中的union addr
}

// 原始事件结构 - 与eBPF程序保持一致
type RawEvent struct {
	Timestamp  uint64      `json:"timestamp"`
	PID        uint32      `json:"pid"`
	PPID       uint32      `json:"ppid"`
	UID        uint32      `json:"uid"`
	GID        uint32      `json:"gid"`
	SyscallID  uint32      `json:"syscall_id"`
	EventType  uint32      `json:"event_type"`
	RetCode    int32       `json:"ret_code"`
	Comm       [16]byte    `json:"-"`
	Filename   [256]byte   `json:"-"`
	Mode       uint32      `json:"mode"`
	Size       uint64      `json:"size"`
	Flags      uint32      `json:"flags"`
	SrcAddr    NetworkAddr `json:"src_addr"`
	DstAddr    NetworkAddr `json:"dst_addr"`
	OldUID     uint32      `json:"old_uid"`
	OldGID     uint32      `json:"old_gid"`
	NewUID     uint32      `json:"new_uid"`
	NewGID     uint32      `json:"new_gid"`
	Addr       uint64      `json:"addr"`
	Len        uint64      `json:"len"`
	Prot       uint32      `json:"prot"`
	TargetComm [16]byte    `json:"-"`
	TargetPID  uint32      `json:"target_pid"`
	Signal     uint32      `json:"signal"`
}

// JSON输出事件结构
type EventJSON struct {
	Timestamp   string    `json:"timestamp"`
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	UID         uint32    `json:"uid"`
	GID         uint32    `json:"gid"`
	SyscallID   uint32    `json:"syscall_id"`
	EventType   string    `json:"event_type"`
	RetCode     int32     `json:"ret_code"`
	Comm        string    `json:"comm"`
	Cmdline     string    `json:"cmdline,omitempty"`
	Filename    string    `json:"filename,omitempty"`
	Mode        uint32    `json:"mode,omitempty"`
	Size        uint64    `json:"size,omitempty"`
	Flags       uint32    `json:"flags,omitempty"`
	SrcAddr     *AddrJSON `json:"src_addr,omitempty"`
	DstAddr     *AddrJSON `json:"dst_addr,omitempty"`
	OldUID      uint32    `json:"old_uid,omitempty"`
	OldGID      uint32    `json:"old_gid,omitempty"`
	NewUID      uint32    `json:"new_uid,omitempty"`
	NewGID      uint32    `json:"new_gid,omitempty"`
	Addr        uint64    `json:"addr,omitempty"`
	Len         uint64    `json:"len,omitempty"`
	Prot        string    `json:"prot,omitempty"`
	TargetComm  string    `json:"target_comm,omitempty"`
	TargetPID   uint32    `json:"target_pid,omitempty"`
	Signal      uint32    `json:"signal,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	RuleMatched string    `json:"rule_matched,omitempty"`
}

// 地址JSON结构
type AddrJSON struct {
	Family string `json:"family"`
	Port   uint16 `json:"port,omitempty"`
	IP     string `json:"ip"`
}

// 事件类型转换
func (et EventType) String() string {
	switch et {
	// 进程相关
	case EventExecve:
		return "execve"
	case EventFork:
		return "fork"
	case EventClone:
		return "clone"
	case EventExit:
		return "exit"
	case EventExecveat:
		return "execveat"
	// 文件系统相关
	case EventOpenat:
		return "openat"
	case EventClose:
		return "close"
	case EventRead:
		return "read"
	case EventWrite:
		return "write"
	case EventUnlink:
		return "unlink"
	case EventRename:
		return "rename"
	case EventChmod:
		return "chmod"
	case EventChown:
		return "chown"
	// 网络相关
	case EventConnect:
		return "connect"
	case EventBind:
		return "bind"
	case EventListen:
		return "listen"
	case EventAccept:
		return "accept"
	case EventSendto:
		return "sendto"
	case EventRecvfrom:
		return "recvfrom"
	case EventSocket:
		return "socket"
	case EventShutdown:
		return "shutdown"
	// 权限相关
	case EventSetuid:
		return "setuid"
	case EventSetgid:
		return "setgid"
	case EventSetreuid:
		return "setreuid"
	case EventSetregid:
		return "setregid"
	case EventSetresuid:
		return "setresuid"
	case EventSetresgid:
		return "setresgid"
	case EventSetns:
		return "setns"
	case EventUnshare:
		return "unshare"
	case EventPrctl:
		return "prctl"
	// 内存相关
	case EventMmap:
		return "mmap"
	case EventMprotect:
		return "mprotect"
	case EventMunmap:
		return "munmap"
	case EventMremap:
		return "mremap"
	// 模块相关
	case EventInitModule:
		return "init_module"
	case EventDeleteModule:
		return "delete_module"
	// 系统调用相关
	case EventPtrace:
		return "ptrace"
	case EventKill:
		return "kill"
	case EventMount:
		return "mount"
	case EventUmount:
		return "umount"
	default:
		return "unknown"
	}
}

// 字节数组转字符串
func bytesToString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}

func parseRawEvent(b []byte) (*RawEvent, error) {
	if len(b) < 428 {
		return nil, fmt.Errorf("invalid event size: %d", len(b))
	}
	e := &RawEvent{}
	e.Timestamp = binary.LittleEndian.Uint64(b[0:8])
	e.PID = binary.LittleEndian.Uint32(b[8:12])
	e.PPID = binary.LittleEndian.Uint32(b[12:16])
	e.UID = binary.LittleEndian.Uint32(b[16:20])
	e.GID = binary.LittleEndian.Uint32(b[20:24])
	e.SyscallID = binary.LittleEndian.Uint32(b[24:28])
	e.EventType = binary.LittleEndian.Uint32(b[28:32])
	e.RetCode = int32(binary.LittleEndian.Uint32(b[32:36]))
	copy(e.Comm[:], b[36:52])
	copy(e.Filename[:], b[52:308])
	e.Mode = binary.LittleEndian.Uint32(b[308:312])
	e.Size = binary.LittleEndian.Uint64(b[312:320])
	e.Flags = binary.LittleEndian.Uint32(b[320:324])
	e.SrcAddr.Family = binary.LittleEndian.Uint16(b[324:326])
	e.SrcAddr.Port = binary.LittleEndian.Uint16(b[326:328])
	copy(e.SrcAddr.Addr[:], b[328:344])
	e.DstAddr.Family = binary.LittleEndian.Uint16(b[344:346])
	e.DstAddr.Port = binary.LittleEndian.Uint16(b[346:348])
	copy(e.DstAddr.Addr[:], b[348:364])
	e.OldUID = binary.LittleEndian.Uint32(b[364:368])
	e.OldGID = binary.LittleEndian.Uint32(b[368:372])
	e.NewUID = binary.LittleEndian.Uint32(b[372:376])
	e.NewGID = binary.LittleEndian.Uint32(b[376:380])
	e.Addr = binary.LittleEndian.Uint64(b[384:392])
	e.Len = binary.LittleEndian.Uint64(b[392:400])
	e.Prot = binary.LittleEndian.Uint32(b[400:404])
	copy(e.TargetComm[:], b[404:420])
	e.TargetPID = binary.LittleEndian.Uint32(b[420:424])
	e.Signal = binary.LittleEndian.Uint32(b[424:428])
	return e, nil
}

// 内存保护标志转换
func protToString(prot uint32) string {
	var flags []string
	if prot&0x1 != 0 {
		flags = append(flags, "READ")
	}
	if prot&0x2 != 0 {
		flags = append(flags, "WRITE")
	}
	if prot&0x4 != 0 {
		flags = append(flags, "EXEC")
	}
	return strings.Join(flags, "|")
}

// 地址族转换
func familyToString(family uint16) string {
	switch family {
	case 0:
		return "AF_UNSPEC"
	case 1:
		return "AF_UNIX"
	case 2:
		return "AF_INET"
	case 10:
		return "AF_INET6"
	case 16:
		return "AF_NETLINK"
	case 17:
		return "AF_PACKET"
	default:
		return fmt.Sprintf("AF_%d", family)
	}
}

// IP地址转换
func addrToString(addr NetworkAddr) *AddrJSON {
	if addr.Family == 0 {
		return nil
	}

	result := &AddrJSON{
		Family: familyToString(addr.Family),
	}

	switch addr.Family {
	case 2: // AF_INET
		result.Port = ntohs(addr.Port)
		ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
		result.IP = ip.String()
	case 10: // AF_INET6
		result.Port = ntohs(addr.Port)
		result.IP = net.IP(addr.Addr[:]).String()
	default:
		// 非IP地址族（如AF_UNIX/NETLINK/PACKET）不设置IP与端口
		result.Port = 0
		result.IP = ""
	}

	return result
}

// 网络字节序转主机字节序
func ntohs(port uint16) uint16 {
	return (port<<8)&0xff00 | (port>>8)&0x00ff
}

// 转换原始事件为JSON格式
func convertToJSON(raw *RawEvent) *EventJSON {
	// 修复时间戳：由于eBPF使用bpf_ktime_get_ns()返回单调时钟
	// 而事件是实时处理的，直接使用当前时间更准确
	timestamp := time.Now()

	event := &EventJSON{
		Timestamp: timestamp.Format(time.RFC3339Nano),
		PID:       raw.PID,
		PPID:      raw.PPID,
		UID:       raw.UID,
		GID:       raw.GID,
		SyscallID: raw.SyscallID,
		EventType: EventType(raw.EventType).String(),
		RetCode:   raw.RetCode,
		Comm:      bytesToString(raw.Comm[:]),
	}

	// 文件名
	if filename := bytesToString(raw.Filename[:]); filename != "" {
		event.Filename = filename
	}

	// 模式和标志
	if raw.Mode != 0 {
		event.Mode = raw.Mode
	}
	if raw.Size != 0 {
		event.Size = raw.Size
	}
	if raw.Flags != 0 {
		event.Flags = raw.Flags
	}

	// 网络地址：仅在网络类事件中输出，避免非网络事件出现误填字段
	isNetEvent := false
	switch event.EventType {
	case "connect", "bind", "listen", "accept", "sendto", "recvfrom", "socket", "shutdown":
		isNetEvent = true
	}
	if isNetEvent {
		if srcAddr := addrToString(raw.SrcAddr); srcAddr != nil {
			event.SrcAddr = srcAddr
		}
		if dstAddr := addrToString(raw.DstAddr); dstAddr != nil {
			event.DstAddr = dstAddr
		}
	}

	// 权限相关
	if raw.OldUID != 0 || raw.NewUID != 0 {
		event.OldUID = raw.OldUID
		event.NewUID = raw.NewUID
	}
	if raw.OldGID != 0 || raw.NewGID != 0 {
		event.OldGID = raw.OldGID
		event.NewGID = raw.NewGID
	}

	// 内存相关
	if raw.Addr != 0 {
		event.Addr = raw.Addr
	}
	if raw.Len != 0 {
		event.Len = raw.Len
	}
	if raw.Prot != 0 {
		event.Prot = protToString(raw.Prot)
	}

	// 目标进程相关
	if targetComm := bytesToString(raw.TargetComm[:]); targetComm != "" {
		event.TargetComm = targetComm
	}
	if raw.TargetPID != 0 {
		event.TargetPID = raw.TargetPID
	}
	if raw.Signal != 0 {
		event.Signal = raw.Signal
	}

	return event
}

// 补充事件的命令行：仅在Linux可用，读取 /proc/<pid>/cmdline
func enrichEventCmdline(event *EventJSON) {
	if runtime.GOOS != "linux" {
		return
	}
	// 仅在进程类事件中尝试填充，避免无意义的开销
	switch event.EventType {
	case "execve", "fork", "clone", "exit":
		// 读取cmdline（以\0分隔），转换为空格分隔的字符串
		path := fmt.Sprintf("/proc/%d/cmdline", event.PID)
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			return
		}
		s := strings.ReplaceAll(string(data), "\x00", " ")
		s = strings.TrimSpace(s)
		if s != "" {
			event.Cmdline = s
		}
	}
}

// 加载安全配置
// 加载增强安全配置到规则引擎
func loadEnhancedSecurityConfig(configPath string, ruleEngine *EnhancedRuleEngine) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config struct {
		Global          EnhancedGlobalConfig               `yaml:"global"`
		DetectionRules  map[string][]EnhancedDetectionRule `yaml:"detection_rules"`
		Whitelist       WhitelistConfig                    `yaml:"whitelist"`
		ResponseActions ResponseActionsConfig              `yaml:"response_actions"`
		Logging         struct {
			Level      string `yaml:"level"`
			OutputFile string `yaml:"output_file"`
		} `yaml:"logging"`
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 设置全局配置
	ruleEngine.GlobalConfig = config.Global

	// 设置白名单配置
	ruleEngine.WhitelistConfig = config.Whitelist

	// 设置响应动作配置
	ruleEngine.ResponseActions = config.ResponseActions

	// 加载检测规则
	ruleEngine.Rules = make(map[string][]EnhancedDetectionRule)
	log.Printf("开始加载检测规则，发现 %d 个类别", len(config.DetectionRules))

	totalRules := 0
	for category, rules := range config.DetectionRules {
		log.Printf("加载类别 '%s': %d 条规则", category, len(rules))
		for i := range rules {
			rules[i].Category = category
			log.Printf("  规则 %d: %s (启用: %v)", i, rules[i].Name, rules[i].Enabled)
		}
		ruleEngine.Rules[category] = rules
		totalRules += len(rules)
	}

	log.Printf("成功加载 %d 个类别的 %d 条安全规则", len(ruleEngine.Rules), totalRules)
	return nil
}

func main() {
	// 检查是否运行测试
	if len(os.Args) > 1 && os.Args[1] == "test" {
		// 移除 "test" 参数，让测试框架处理剩余参数
		os.Args = append(os.Args[:1], os.Args[2:]...)
		RunTestCommand()
		return
	}

	// 检查是否运行集成测试
	if len(os.Args) > 1 && os.Args[1] == "integration-test" {
		RunIntegrationTestCommand()
		return
	}

	// 命令行参数解析
	var (
		configPath = flag.String("config", "config/enhanced_security_config.yaml", "安全规则配置文件路径")
		dashboard  = flag.Bool("dashboard", false, "启用命令行Dashboard")
		pidMin     = flag.Uint("pid-min", 0, "过滤PID最小值")
		pidMax     = flag.Uint("pid-max", 0, "过滤PID最大值")
		uidMin     = flag.Uint("uid-min", 0, "过滤UID最小值")
		uidMax     = flag.Uint("uid-max", 0, "过滤UID最大值")
	)
	flag.Parse()

	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 创建并初始化增强规则引擎
	ruleEngine := NewEnhancedRuleEngine()

	// 创建性能监控器
	perfMonitor := NewPerformanceMonitor(ruleEngine)

	// 启动定期性能报告（每10分钟）
	perfMonitor.StartPeriodicReporting(10 * time.Minute)

	// 创建事件上下文管理器
	eventContext := NewEventContext(nil) // 使用默认配置

	// 创建告警管理器
	alertManagerConfig := &AlertManagerConfig{
		MaxActiveAlerts:      10000,
		MaxHistoryAlerts:     50000,
		AlertRetentionDays:   30,
		EnableAggregation:    true,
		AggregationWindow:    5 * time.Minute,
		AggregationThreshold: 5,
		EnableAutoResolve:    true,
		AutoResolveTimeout:   24 * time.Hour,
		EnableNotifications:  true,
		NotificationDelay:    0,
		PersistAlerts:        true,
		AlertStoragePath:     "data/alerts",
	}
	alertManager := NewAlertManager(alertManagerConfig)

	// 读取并初始化存储配置（Week 5）
	storageCfg, _ := LoadStorageConfig("config/storage.yaml")
	var storage Storage
	if storageCfg != nil {
		st, err := NewStorageFromConfig(storageCfg)
		if err != nil {
			log.Printf("初始化存储失败: %v", err)
		} else {
			storage = st
			alertManager.SetStorage(storage)
			log.Printf("[+] 存储后端已初始化: %s -> %s", storageCfg.Backend, storageCfg.SQLite.Path)
		}
	}

	alertManager.RegisterProcessor(NewThreatIntelProcessor())

	// 注册额外的通知渠道
	alertManager.RegisterNotificationChannel(&ConsoleNotificationChannel{EnableColors: true})
	// Webhook 通道改为按环境变量启用，避免默认连接失败噪声
	if url := os.Getenv("ETRACEE_WEBHOOK_URL"); url != "" {
		// 可选配置：超时、重试、签名密钥
		timeout := 10 * time.Second
		if t := os.Getenv("ETRACEE_WEBHOOK_TIMEOUT"); t != "" {
			if d, err := time.ParseDuration(t); err == nil {
				timeout = d
			}
		}
		retry := 0
		if r := os.Getenv("ETRACEE_WEBHOOK_RETRY"); r != "" {
			if n, err := strconv.Atoi(r); err == nil && n >= 0 {
				retry = n
			}
		}
		secret := os.Getenv("ETRACEE_WEBHOOK_SECRET")

		alertManager.RegisterNotificationChannel(&WebhookNotificationChannel{
			URL:     url,
			Method:  "POST",
			Headers: map[string]string{"Content-Type": "application/json"},
			Timeout: timeout,
			Secret:  secret,
			Retry:   retry,
		})
		log.Printf("[+] Webhook 通知已启用: %s (timeout=%s, retry=%d)", url, timeout.String(), retry)
	} else {
		log.Printf("[*] Webhook 通知未配置，跳过注册（设置 ETRACEE_WEBHOOK_URL 启用）")
	}

	// 初始化告警管理API服务器（接入存储查询）
	alertAPI := NewAlertAPI(alertManager, 8888, storage, eventContext)
	go func() {
		log.Println("[+] 告警管理API服务器启动在端口 8888")
		log.Println("  Web界面: http://localhost:8888")
		log.Println("  API文档: http://localhost:8888/api/alerts")
		if err := alertAPI.Start(); err != nil && err != http.ErrServerClosed {
			log.Printf("告警API服务器错误: %v", err)
		}
	}()

	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			if alertAPI != nil {
				if stats := alertAPI.computeAlertStats(); stats != nil {
					alertAPI.broadcast(map[string]interface{}{"type": "stats", "ts": time.Now().Format(time.RFC3339), "data": stats})
				}
			}
		}
	}()

	// 加载安全配置到增强规则引擎
	if err := loadEnhancedSecurityConfig(*configPath, ruleEngine); err != nil {
		log.Printf("Warning: Failed to load enhanced security config: %v", err)
		// 使用环境变量回退配置
		ruleEngine.GlobalConfig = EnhancedGlobalConfig{
			EnableFileEvents:       config.BoolFromEnv("ETRACEE_ENABLE_FILE", true),
			EnableNetworkEvents:    config.BoolFromEnv("ETRACEE_ENABLE_NETWORK", true),
			EnableProcessEvents:    config.BoolFromEnv("ETRACEE_ENABLE_PROCESS", true),
			EnablePermissionEvents: config.BoolFromEnv("ETRACEE_ENABLE_PERMISSION", true),
			EnableMemoryEvents:     config.BoolFromEnv("ETRACEE_ENABLE_MEMORY", true),
			MinUIDFilter:           config.Uint32FromEnv("ETRACEE_UID_MIN", 0),
			MaxUIDFilter:           config.Uint32FromEnv("ETRACEE_UID_MAX", 65535),
			MaxEventsPerSecond:     config.IntFromEnv("ETRACEE_MAX_EPS", 10000),
			AlertThrottleSeconds:   config.IntFromEnv("ETRACEE_ALERT_THROTTLE", 60),
			MaxAlertHistory:        config.IntFromEnv("ETRACEE_MAX_ALERT_HISTORY", 1000),
			EnableRuleStats:        config.BoolFromEnv("ETRACEE_ENABLE_RULE_STATS", true),
			LogLevel:               config.StringFromEnv("ETRACEE_LOG_LEVEL", "info"),
		}
	}

	// 编译规则以提升性能
	if err := ruleEngine.CompileRules(); err != nil {
		log.Printf("Warning: Failed to compile rules: %v", err)
	}

	// 加载eBPF程序
	spec, err := ebpf.LoadCollectionSpec("build/etracee.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// 设置配置映射
	configMap := coll.Maps["etracee_config"]
	if configMap != nil {
		// 设置事件类型开关
		configMap.Put(uint32(0), uint64(boolToUint64(ruleEngine.GlobalConfig.EnableFileEvents)))
		configMap.Put(uint32(1), uint64(boolToUint64(ruleEngine.GlobalConfig.EnableNetworkEvents)))
		configMap.Put(uint32(2), uint64(boolToUint64(ruleEngine.GlobalConfig.EnableProcessEvents)))
		configMap.Put(uint32(3), uint64(boolToUint64(ruleEngine.GlobalConfig.EnablePermissionEvents)))
		configMap.Put(uint32(4), uint64(boolToUint64(ruleEngine.GlobalConfig.EnableMemoryEvents)))
		configMap.Put(uint32(5), uint64(ruleEngine.GlobalConfig.MinUIDFilter))
		configMap.Put(uint32(6), uint64(ruleEngine.GlobalConfig.MaxUIDFilter))
	}

	if pidMap := coll.Maps["pid_filter"]; pidMap != nil {
		pid := uint32(os.Getpid())
		var v uint8 = 1
		_ = pidMap.Put(pid, v)
	}

	// 附加到 execve 系统调用跟踪点
	execLink, err := link.Tracepoint("syscalls", "sys_enter_execve", coll.Programs["trace_execve"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 execve 跟踪点: %v", err)
		execLink = nil
	} else {
		defer execLink.Close()
	}

	// 附加到 sched_process_exit 跟踪点
	exitLink, err := link.Tracepoint("sched", "sched_process_exit", coll.Programs["trace_exit"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 exit 跟踪点: %v", err)
		exitLink = nil
	} else {
		defer exitLink.Close()
	}

	// 附加到网络跟踪点
	netLink, err := link.Tracepoint("syscalls", "sys_enter_connect", coll.Programs["trace_connect"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 connect 跟踪点: %v", err)
		netLink = nil
	}
	if netLink != nil {
		defer netLink.Close()
	}

	bindLink, err := link.Tracepoint("syscalls", "sys_enter_bind", coll.Programs["trace_bind"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 bind 跟踪点: %v", err)
		bindLink = nil
	} else {
		defer bindLink.Close()
	}

	listenLink, err := link.Tracepoint("syscalls", "sys_enter_listen", coll.Programs["trace_listen"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 listen 跟踪点: %v", err)
		listenLink = nil
	} else {
		defer listenLink.Close()
	}

	openLink, err := link.Tracepoint("syscalls", "sys_enter_openat", coll.Programs["trace_openat"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 openat 跟踪点: %v", err)
		openLink = nil
	} else {
		defer openLink.Close()
	}

	closeLink, err := link.Tracepoint("syscalls", "sys_enter_close", coll.Programs["trace_close"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 close 跟踪点: %v", err)
		closeLink = nil
	} else {
		defer closeLink.Close()
	}

	unlinkLink, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", coll.Programs["trace_unlink"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 unlinkat 跟踪点: %v", err)
		unlinkLink = nil
	} else {
		defer unlinkLink.Close()
	}

	chmodLink, err := link.Tracepoint("syscalls", "sys_enter_fchmodat", coll.Programs["trace_chmod"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 fchmodat 跟踪点: %v", err)
		chmodLink = nil
	} else {
		defer chmodLink.Close()
	}

	mmapLink, err := link.Tracepoint("syscalls", "sys_enter_mmap", coll.Programs["trace_mmap"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 mmap 跟踪点: %v", err)
		mmapLink = nil
	} else {
		defer mmapLink.Close()
	}

	mprotectLink, err := link.Tracepoint("syscalls", "sys_enter_mprotect", coll.Programs["trace_mprotect"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 mprotect 跟踪点: %v", err)
		mprotectLink = nil
	} else {
		defer mprotectLink.Close()
	}

	ptraceLink, err := link.Tracepoint("syscalls", "sys_enter_ptrace", coll.Programs["trace_ptrace"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 ptrace 跟踪点: %v", err)
		ptraceLink = nil
	} else {
		defer ptraceLink.Close()
	}

	killLink, err := link.Tracepoint("syscalls", "sys_enter_kill", coll.Programs["trace_kill"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 kill 跟踪点: %v", err)
		killLink = nil
	} else {
		defer killLink.Close()
	}

	// 新增网络与文件跟踪点
	accept4Link, err := link.Tracepoint("syscalls", "sys_enter_accept4", coll.Programs["trace_accept4"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 accept4 跟踪点: %v", err)
		accept4Link = nil
	} else {
		defer accept4Link.Close()
	}

	acceptLink, err := link.Tracepoint("syscalls", "sys_enter_accept", coll.Programs["trace_accept"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 accept 跟踪点: %v", err)
		acceptLink = nil
	} else {
		defer acceptLink.Close()
	}

	sendtoLink, err := link.Tracepoint("syscalls", "sys_enter_sendto", coll.Programs["trace_sendto"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 sendto 跟踪点: %v", err)
		sendtoLink = nil
	} else {
		defer sendtoLink.Close()
	}

	recvfromLink, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", coll.Programs["trace_recvfrom"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 recvfrom 跟踪点: %v", err)
		recvfromLink = nil
	} else {
		defer recvfromLink.Close()
	}

	readLink, err := link.Tracepoint("syscalls", "sys_exit_read", coll.Programs["trace_read"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 read 跟踪点: %v", err)
		readLink = nil
	} else {
		defer readLink.Close()
	}

	writeLink, err := link.Tracepoint("syscalls", "sys_exit_write", coll.Programs["trace_write"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 write 跟踪点: %v", err)
		writeLink = nil
	} else {
		defer writeLink.Close()
	}

	chownLink, err := link.Tracepoint("syscalls", "sys_enter_fchownat", coll.Programs["trace_chown"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 fchownat 跟踪点: %v", err)
		chownLink = nil
	} else {
		defer chownLink.Close()
	}

	renameLink, err := link.Tracepoint("syscalls", "sys_enter_renameat2", coll.Programs["trace_rename"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 renameat2 跟踪点: %v", err)
		renameLink = nil
	} else {
		defer renameLink.Close()
	}

	// 新增权限/系统/内存跟踪点
	socketLink, err := link.Tracepoint("syscalls", "sys_enter_socket", coll.Programs["trace_socket"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 socket 跟踪点: %v", err)
		socketLink = nil
	} else {
		defer socketLink.Close()
	}

	shutdownLink, err := link.Tracepoint("syscalls", "sys_enter_shutdown", coll.Programs["trace_shutdown"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 shutdown 跟踪点: %v", err)
		shutdownLink = nil
	} else {
		defer shutdownLink.Close()
	}

	execveatLink, err := link.Tracepoint("syscalls", "sys_enter_execveat", coll.Programs["trace_execveat"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 execveat 跟踪点: %v", err)
		execveatLink = nil
	} else {
		defer execveatLink.Close()
	}

	setuidLink, err := link.Tracepoint("syscalls", "sys_enter_setuid", coll.Programs["trace_setuid"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 setuid 跟踪点: %v", err)
		setuidLink = nil
	} else {
		defer setuidLink.Close()
	}

	setgidLink, err := link.Tracepoint("syscalls", "sys_enter_setgid", coll.Programs["trace_setgid"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 setgid 跟踪点: %v", err)
		setgidLink = nil
	} else {
		defer setgidLink.Close()
	}

	setreuidLink, err := link.Tracepoint("syscalls", "sys_enter_setreuid", coll.Programs["trace_setreuid"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 setreuid 跟踪点: %v", err)
		setreuidLink = nil
	} else {
		defer setreuidLink.Close()
	}

	setregidLink, err := link.Tracepoint("syscalls", "sys_enter_setregid", coll.Programs["trace_setregid"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 setregid 跟踪点: %v", err)
		setregidLink = nil
	} else {
		defer setregidLink.Close()
	}

	setresuidLink, err := link.Tracepoint("syscalls", "sys_enter_setresuid", coll.Programs["trace_setresuid"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 setresuid 跟踪点: %v", err)
		setresuidLink = nil
	} else {
		defer setresuidLink.Close()
	}

	setresgidLink, err := link.Tracepoint("syscalls", "sys_enter_setresgid", coll.Programs["trace_setresgid"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 setresgid 跟踪点: %v", err)
		setresgidLink = nil
	} else {
		defer setresgidLink.Close()
	}

	munmapLink, err := link.Tracepoint("syscalls", "sys_enter_munmap", coll.Programs["trace_munmap"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 munmap 跟踪点: %v", err)
		munmapLink = nil
	} else {
		defer munmapLink.Close()
	}

	mountLink, err := link.Tracepoint("syscalls", "sys_enter_mount", coll.Programs["trace_mount"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 mount 跟踪点: %v", err)
		mountLink = nil
	} else {
		defer mountLink.Close()
	}

	umountLink, err := link.Tracepoint("syscalls", "sys_enter_umount2", coll.Programs["trace_umount"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 umount 跟踪点: %v", err)
		umountLink = nil
	} else {
		defer umountLink.Close()
	}

	initModuleLink, err := link.Tracepoint("syscalls", "sys_enter_init_module", coll.Programs["trace_init_module"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 init_module 跟踪点: %v", err)
		initModuleLink = nil
	} else {
		defer initModuleLink.Close()
	}

	deleteModuleLink, err := link.Tracepoint("syscalls", "sys_enter_delete_module", coll.Programs["trace_delete_module"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 delete_module 跟踪点: %v", err)
		deleteModuleLink = nil
	} else {
		defer deleteModuleLink.Close()
	}

	mremapLink, err := link.Tracepoint("syscalls", "sys_enter_mremap", coll.Programs["trace_mremap"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 mremap 跟踪点: %v", err)
		mremapLink = nil
	} else {
		defer mremapLink.Close()
	}

	setnsLink, err := link.Tracepoint("syscalls", "sys_enter_setns", coll.Programs["trace_setns"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 setns 跟踪点: %v", err)
		setnsLink = nil
	} else {
		defer setnsLink.Close()
	}

	unshareLink, err := link.Tracepoint("syscalls", "sys_enter_unshare", coll.Programs["trace_unshare"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 unshare 跟踪点: %v", err)
		unshareLink = nil
	} else {
		defer unshareLink.Close()
	}

	prctlLink, err := link.Tracepoint("syscalls", "sys_enter_prctl", coll.Programs["trace_prctl"], nil)
	if err != nil {
		log.Printf("警告: 无法附加到 prctl 跟踪点: %v", err)
		prctlLink = nil
	} else {
		defer prctlLink.Close()
	}

	// 打开Ring Buffer
	rd, err := ringbuf.NewReader(coll.Maps["rb"])
	if err != nil {
		log.Fatalf("创建环形缓冲区读取器失败: %v", err)
	}
	defer rd.Close()

	// 检查附加状态并报告
	attachedCount := 0
	if execLink != nil {
		attachedCount++
		log.Println("[+] execve 跟踪点已成功附加")
	}
	if exitLink != nil {
		attachedCount++
		log.Println("[+] exit 跟踪点已成功附加")
	}
	if netLink != nil {
		attachedCount++
		log.Println("[+] connect 跟踪点已成功附加")
	}
	if bindLink != nil {
		attachedCount++
		log.Println("[+] bind 跟踪点已成功附加")
	}
	if listenLink != nil {
		attachedCount++
		log.Println("[+] listen 跟踪点已成功附加")
	}
	if accept4Link != nil {
		attachedCount++
		log.Println("[+] accept4 跟踪点已成功附加")
	}
	if acceptLink != nil {
		attachedCount++
		log.Println("[+] accept 跟踪点已成功附加")
	}
	if sendtoLink != nil {
		attachedCount++
		log.Println("[+] sendto 跟踪点已成功附加")
	}
	if recvfromLink != nil {
		attachedCount++
		log.Println("[+] recvfrom 跟踪点已成功附加")
	}
	if openLink != nil {
		attachedCount++
		log.Println("[+] openat 跟踪点已成功附加")
	}
	if closeLink != nil {
		attachedCount++
		log.Println("[+] close 跟踪点已成功附加")
	}
	if unlinkLink != nil {
		attachedCount++
		log.Println("[+] unlinkat 跟踪点已成功附加")
	}
	if chmodLink != nil {
		attachedCount++
		log.Println("[+] fchmodat 跟踪点已成功附加")
	}
	if renameLink != nil {
		attachedCount++
		log.Println("[+] renameat2 跟踪点已成功附加")
	}
	if readLink != nil {
		attachedCount++
		log.Println("[+] read 跟踪点已成功附加")
	}
	if writeLink != nil {
		attachedCount++
		log.Println("[+] write 跟踪点已成功附加")
	}
	if chownLink != nil {
		attachedCount++
		log.Println("[+] fchownat 跟踪点已成功附加")
	}
	if mmapLink != nil {
		attachedCount++
		log.Println("[+] mmap 跟踪点已成功附加")
	}
	if mprotectLink != nil {
		attachedCount++
		log.Println("[+] mprotect 跟踪点已成功附加")
	}
	if mremapLink != nil {
		attachedCount++
		log.Println("[+] mremap 跟踪点已成功附加")
	}
	if munmapLink != nil {
		attachedCount++
		log.Println("[+] munmap 跟踪点已成功附加")
	}
	if ptraceLink != nil {
		attachedCount++
		log.Println("[+] ptrace 跟踪点已成功附加")
	}
	if killLink != nil {
		attachedCount++
		log.Println("[+] kill 跟踪点已成功附加")
	}
	if socketLink != nil {
		attachedCount++
		log.Println("[+] socket 跟踪点已成功附加")
	}
	if shutdownLink != nil {
		attachedCount++
		log.Println("[+] shutdown 跟踪点已成功附加")
	}
	if execveatLink != nil {
		attachedCount++
		log.Println("[+] execveat 跟踪点已成功附加")
	}
	if setnsLink != nil {
		attachedCount++
		log.Println("[+] setns 跟踪点已成功附加")
	}
	if unshareLink != nil {
		attachedCount++
		log.Println("[+] unshare 跟踪点已成功附加")
	}
	if prctlLink != nil {
		attachedCount++
		log.Println("[+] prctl 跟踪点已成功附加")
	}
	if setuidLink != nil {
		attachedCount++
		log.Println("[+] setuid 跟踪点已成功附加")
	}
	if setgidLink != nil {
		attachedCount++
		log.Println("[+] setgid 跟踪点已成功附加")
	}
	if setreuidLink != nil {
		attachedCount++
		log.Println("[+] setreuid 跟踪点已成功附加")
	}
	if setregidLink != nil {
		attachedCount++
		log.Println("[+] setregid 跟踪点已成功附加")
	}
	if setresuidLink != nil {
		attachedCount++
		log.Println("[+] setresuid 跟踪点已成功附加")
	}
	if setresgidLink != nil {
		attachedCount++
		log.Println("[+] setresgid 跟踪点已成功附加")
	}
	if mountLink != nil {
		attachedCount++
		log.Println("[+] mount 跟踪点已成功附加")
	}
	if umountLink != nil {
		attachedCount++
		log.Println("[+] umount 跟踪点已成功附加")
	}
	if initModuleLink != nil {
		attachedCount++
		log.Println("[+] init_module 跟踪点已成功附加")
	}
	if deleteModuleLink != nil {
		attachedCount++
		log.Println("[+] delete_module 跟踪点已成功附加")
	}

	if attachedCount == 0 {
		log.Println("警告: 没有成功附加任何跟踪点，程序将继续运行但可能无法捕获事件")
	} else {
		log.Printf("eTracee 已启动，成功附加了 %d 个跟踪点，正在监控安全事件...", attachedCount)
	}

	// 处理信号和优雅关闭
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 统计信息
	var eventCount uint64
	startTime := time.Now()

	// 初始化Dashboard（如果启用）
	var dashboardInstance *Dashboard
	if *dashboard {
		dashboardInstance = NewDashboard()
		go dashboardInstance.Start()
		log.Println("[+] 命令行Dashboard已启动")
	}

	var wg sync.WaitGroup

	// 信号处理
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
		sig := <-c
		log.Printf("接收到信号 %v，正在优雅关闭程序...", sig)
		cancel()
		_ = rd.Close()
		wg.Wait()

		duration := time.Since(startTime)
		log.Printf("程序运行时间: %v", duration.Round(time.Second))
		log.Printf("总共处理事件: %d", eventCount)
		if duration.Seconds() > 0 {
			log.Printf("平均事件处理速率: %.2f 事件/秒", float64(eventCount)/duration.Seconds())
		}
		if alertAPI != nil {
			_ = alertAPI.Stop()
		}
	}()

	log.Println("程序正在运行，按 Ctrl+C 退出...")

	// 事件处理循环
	eventChan := make(chan ringbuf.Record, 10)
	errorChan := make(chan error, 1)

	// 启动读取goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(eventChan)
		defer close(errorChan)

		for {
			record, err := rd.Read()
			if err != nil {
				select {
				case errorChan <- err:
				case <-ctx.Done():
					return
				}
				return
			}

			select {
			case eventChan <- record:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("程序已安全退出")
			return

		case err, ok := <-errorChan:
			if !ok {
				continue
			}
			if err == ringbuf.ErrClosed {
				log.Println("环形缓冲区已关闭，程序退出")
				return
			}
			if err != nil {
				log.Printf("从环形缓冲区读取数据时出错: %v", err)
				return
			}

		case record, ok := <-eventChan:
			if !ok {
				continue
			}
			if len(record.RawSample) == 0 {
				continue
			}
			eventStartTime := time.Now()

			// 解析事件
			rawEvent, err := parseRawEvent(record.RawSample)
			if err != nil {
				log.Printf("解析事件数据时出错: %v", err)
				perfMonitor.RecordError("event_parsing")
				continue
			}

			// 增加事件计数
			eventCount++

			// 转换为JSON格式
			event := convertToJSON(rawEvent)
			// 进程事件补充命令行（Linux）
			enrichEventCmdline(event)

			// 应用过滤条件
			if *pidMin > 0 && event.PID < uint32(*pidMin) {
				continue
			}
			if *pidMax > 0 && event.PID > uint32(*pidMax) {
				continue
			}
			if *uidMin > 0 && event.UID < uint32(*uidMin) {
				continue
			}
			if *uidMax > 0 && event.UID > uint32(*uidMax) {
				continue
			}

			// 事件流仅通过HTTP分页拉取，移除WebSocket原始事件推送

			// 应用增强安全规则引擎
			alerts := ruleEngine.MatchRules(event)

			// 更新事件上下文（用于攻击链重建）
			eventContext.UpdateProcessContext(event)

			// 根据事件类型更新相应的上下文
			switch event.EventType {
			case "connect", "bind", "listen", "accept", "sendto", "recvfrom", "socket", "shutdown":
				eventContext.UpdateNetworkContext(event)
			case "openat", "close", "read", "write", "unlink", "rename", "chmod", "chown":
				if event.Filename != "" {
					eventContext.UpdateFileContext(event)
				}
			}

			// 处理告警事件并检测攻击链
			for _, alert := range alerts {
				// 创建AlertEvent结构体
				alertEvent := &AlertEvent{
					RuleName:    alert.RuleName,
					Description: alert.Description,
					Severity:    alert.Severity,
					Category:    alert.Category,
					Timestamp:   time.Now(),
				}

				// 检测攻击链
				eventContext.DetectAttackChain(event, alertEvent)
			}

			// 无告警事件：如果存在相关攻击链则更新（不新建），以避免评分停滞
			if len(alerts) == 0 {
				eventContext.DetectAttackChain(event, nil)
			}

			// 获取并显示攻击链（仅输出本次事件更新的链，避免重复噪声）
			if attackChains := eventContext.GetAttackChains(); len(attackChains) > 0 {
				for _, chain := range attackChains {
					if chain.LastUpdate.After(eventStartTime) || chain.LastUpdate.Equal(eventStartTime) {
						log.Printf("[*] 检测到攻击链: ID=%s, 阶段=%s, 风险级别=%s, 危害评分=%.2f",
							chain.ID, chain.CurrentStage, chain.RiskLevel, chain.ImpactScore)
					}
				}
			}

			// 记录事件处理性能
			eventProcessingTime := time.Since(eventStartTime)
			perfMonitor.RecordEvent(eventProcessingTime)

			// 处理告警事件
			for _, alert := range alerts {
				// 更新事件的告警信息
				event.Severity = alert.Severity
				event.RuleMatched = alert.RuleName

				// 记录告警性能
				perfMonitor.RecordAlert(alert.RuleName, eventProcessingTime)

				// 使用告警管理器处理告警
				managedAlert, err := alertManager.ProcessAlert(alert)
				if err != nil {
					log.Printf("告警处理失败: %v", err)
					perfMonitor.RecordError("alert_processing")
					continue
				}

				// 记录详细的告警信息
				log.Printf("[!] 安全告警已处理: ID=%s, 规则=%s, 严重级别=%s, 状态=%s",
					managedAlert.ID, managedAlert.RuleName, managedAlert.Severity, managedAlert.Status)

				// WebSocket实时推送
				if alertAPI != nil {
					alertAPI.BroadcastAlert(managedAlert)
				}
			}

			// 更新Dashboard统计（如果启用）
			if dashboardInstance != nil {
				dashboardInstance.UpdateStats(event)
			}

			// 存储事件（如果启用存储）
			if storage != nil {
				if err := storage.SaveEvent(event); err != nil {
					log.Printf("保存事件失败: %v", err)
				}
			}

			// 告警生成由规则引擎与告警管理器统一处理，移除重复路径

			// 输出JSON
			if jsonData, err := json.Marshal(event); err == nil {
				if !*dashboard {
					fmt.Println(string(jsonData))
				}
			}
		}
	}
}

func boolToUint64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
