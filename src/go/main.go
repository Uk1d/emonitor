package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
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
	EventExecve EventType = 1
	EventFork   EventType = 2
	EventClone  EventType = 3
	EventExit   EventType = 4

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

	// 权限相关事件
	EventSetuid    EventType = 30
	EventSetgid    EventType = 31
	EventSetreuid  EventType = 32
	EventSetregid  EventType = 33
	EventSetresuid EventType = 34
	EventSetresgid EventType = 35

	// 内存相关事件
	EventMmap     EventType = 40
	EventMprotect EventType = 41
	EventMunmap   EventType = 42

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
	Port   uint16 `json:"port"`
	IP     string `json:"ip"`
}

// 安全规则配置
type SecurityConfig struct {
	Global struct {
		EnableFileEvents       bool `yaml:"enable_file_events"`
		EnableNetworkEvents    bool `yaml:"enable_network_events"`
		EnableProcessEvents    bool `yaml:"enable_process_events"`
		EnablePermissionEvents bool `yaml:"enable_permission_events"`
		EnableMemoryEvents     bool `yaml:"enable_memory_events"`
		MinUIDFilter           uint `yaml:"min_uid_filter"`
		MaxUIDFilter           uint `yaml:"max_uid_filter"`
	} `yaml:"global"`
	DetectionRules map[string][]DetectionRule `yaml:"detection_rules"`
	Whitelist      struct {
		Processes []string `yaml:"processes"`
		Files     []string `yaml:"files"`
		Networks  []string `yaml:"networks"`
	} `yaml:"whitelist"`
}

type DetectionRule struct {
	Name          string                   `yaml:"name"`
	Description   string                   `yaml:"description"`
	Conditions    []map[string]interface{} `yaml:"conditions"`
	Severity      string                   `yaml:"severity"`
	FreqThreshold int                      `yaml:"frequency_threshold"`
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
	// 内存相关
	case EventMmap:
		return "mmap"
	case EventMprotect:
		return "mprotect"
	case EventMunmap:
		return "munmap"
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
	case 2:
		return "AF_INET"
	case 10:
		return "AF_INET6"
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
		Port:   ntohs(addr.Port), // 网络字节序转主机字节序
	}

	if addr.Family == 2 { // AF_INET
		// IPv4地址存储在前4个字节中
		ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
		result.IP = ip.String()
	} else if addr.Family == 10 { // AF_INET6
		result.IP = net.IP(addr.Addr[:]).String()
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

	// 网络地址
	if srcAddr := addrToString(raw.SrcAddr); srcAddr != nil {
		event.SrcAddr = srcAddr
	}
	if dstAddr := addrToString(raw.DstAddr); dstAddr != nil {
		event.DstAddr = dstAddr
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

// 加载安全配置
func loadSecurityConfig(configPath string) (*SecurityConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config SecurityConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// 简单的规则匹配引擎
func matchSecurityRules(event *EventJSON, config *SecurityConfig) {
	for category, rules := range config.DetectionRules {
		for _, rule := range rules {
			if matchRule(event, rule) {
				event.Severity = rule.Severity
				event.RuleMatched = fmt.Sprintf("%s:%s", category, rule.Name)
				log.Printf("SECURITY ALERT: %s - %s (PID: %d, Comm: %s)",
					rule.Name, rule.Description, event.PID, event.Comm)
				break
			}
		}
	}
}

// 规则匹配逻辑
func matchRule(event *EventJSON, rule DetectionRule) bool {
	for _, condition := range rule.Conditions {
		if !matchCondition(event, condition) {
			return false
		}
	}
	return true
}

// 条件匹配逻辑
func matchCondition(event *EventJSON, condition map[string]interface{}) bool {
	if eventType, ok := condition["event_type"].(string); ok {
		if event.EventType != eventType {
			return false
		}
	}

	if filename, ok := condition["filename"].([]interface{}); ok {
		found := false
		for _, f := range filename {
			if strings.Contains(event.Filename, f.(string)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// 可以添加更多条件匹配逻辑
	return true
}

func main() {
	// 命令行参数解析
	var (
		configPath = flag.String("config", "config/security_rules.yaml", "安全规则配置文件路径")
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

	// 加载安全配置
	config, err := loadSecurityConfig(*configPath)
	if err != nil {
		log.Printf("Warning: Failed to load security config: %v", err)
		config = &SecurityConfig{} // 使用默认配置
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
		configMap.Put(uint32(0), uint64(boolToUint64(config.Global.EnableFileEvents)))
		configMap.Put(uint32(1), uint64(boolToUint64(config.Global.EnableNetworkEvents)))
		configMap.Put(uint32(2), uint64(boolToUint64(config.Global.EnableProcessEvents)))
		configMap.Put(uint32(3), uint64(boolToUint64(config.Global.EnablePermissionEvents)))
		configMap.Put(uint32(4), uint64(boolToUint64(config.Global.EnableMemoryEvents)))
		configMap.Put(uint32(5), uint64(config.Global.MinUIDFilter))
		configMap.Put(uint32(6), uint64(config.Global.MaxUIDFilter))
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
		log.Println("✓ execve 跟踪点已成功附加")
	}
	if exitLink != nil {
		attachedCount++
		log.Println("✓ exit 跟踪点已成功附加")
	}
	if netLink != nil {
		attachedCount++
		log.Println("✓ connect 跟踪点已成功附加")
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
		log.Println("✓ 命令行Dashboard已启动")
	}

	// 信号处理
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
		sig := <-c
		log.Printf("接收到信号 %v，正在优雅关闭程序...", sig)

		// 显示统计信息
		duration := time.Since(startTime)
		log.Printf("程序运行时间: %v", duration.Round(time.Second))
		log.Printf("总共处理事件: %d", eventCount)
		if duration.Seconds() > 0 {
			log.Printf("平均事件处理速率: %.2f 事件/秒", float64(eventCount)/duration.Seconds())
		}

		cancel()
	}()

	log.Println("程序正在运行，按 Ctrl+C 退出...")

	// 事件处理循环
	eventChan := make(chan ringbuf.Record, 10)
	errorChan := make(chan error, 1)

	// 启动读取goroutine
	go func() {
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

		case err := <-errorChan:
			if err == ringbuf.ErrClosed {
				log.Println("环形缓冲区已关闭，程序退出")
				return
			}
			log.Printf("从环形缓冲区读取数据时出错: %v", err)
			return

		case record := <-eventChan:
			// 解析事件
			var rawEvent RawEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &rawEvent); err != nil {
				log.Printf("解析事件数据时出错: %v", err)
				continue
			}

			// 增加事件计数
			eventCount++

			// 转换为JSON格式
			event := convertToJSON(&rawEvent)

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

			// 应用安全规则
			matchSecurityRules(event, config)

			// 更新Dashboard统计（如果启用）
			if dashboardInstance != nil {
				dashboardInstance.UpdateStats(event)
			}

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
