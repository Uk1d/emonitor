/*
 * eTracee - eBPF Security Monitoring System
 * Main eBPF program that includes all tracing modules
 * 
 * 设计思路：
 * 1. 采用模块化设计，将不同类型的跟踪功能分离到独立文件中
 * 2. 使用统一的事件结构和处理流程，确保一致性
 * 3. 通过配置映射实现动态开关，提高性能和灵活性
 * 4. 使用宏定义减少重复代码，提高维护性
 * 
 * 运行机制：
 * 1. eBPF程序加载到内核后，会在指定的跟踪点上挂载
 * 2. 当系统调用或内核事件触发时，相应的跟踪函数被调用
 * 3. 跟踪函数收集事件信息，经过过滤后通过ring buffer发送到用户空间
 * 4. 用户空间程序读取事件并进行分析处理
 * 
 * 程序逻辑：
 * - 事件过滤：支持PID过滤和UID范围过滤
 * - 配置管理：通过eBPF映射实现动态配置
 * - 内存管理：使用ring buffer进行高效的内核-用户空间通信
 * - 模块化：将不同类型的跟踪逻辑分离到独立模块中
 */

#include "vmlinux.h"          // 内核数据结构定义
#include <bpf/bpf_helpers.h>  // eBPF辅助函数
#include <bpf/bpf_core_read.h> // CO-RE读取宏
#include <bpf/bpf_tracing.h>  // 跟踪相关宏
#include "etracee.h"          // 项目自定义头文件

// 网络地址族定义 - 用于网络事件处理
#define AF_INET 2

// eBPF程序许可证声明 - GPL许可证允许使用所有eBPF功能
char LICENSE[] SEC("license") = "GPL";

// ========== eBPF Maps 定义 ==========
// eBPF映射是内核空间和用户空间之间共享数据的机制

/*
 * Ring Buffer映射 - 用于高效的事件传输
 * 
 * 设计原理：
 * - Ring buffer是一种无锁的环形缓冲区，支持多生产者单消费者模式
 * - 相比传统的perf buffer，ring buffer具有更好的性能和更低的延迟
 * - 256KB的大小可以缓存大量事件，避免事件丢失
 * 
 * 使用场景：
 * - 所有跟踪事件都通过此ring buffer发送到用户空间
 * - 用户空间程序通过轮询或阻塞方式读取事件
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB缓冲区
} rb SEC(".maps");

/*
 * PID过滤映射 - 用于过滤特定进程
 * 
 * 设计原理：
 * - 哈希表结构，键为PID，值为标志位
 * - 存在于此映射中的PID将被过滤掉，不产生事件
 * - 用于排除系统进程或不感兴趣的进程
 * 
 * 使用场景：
 * - 过滤掉eTracee自身的进程，避免递归监控
 * - 过滤掉系统关键进程，减少噪音
 * - 动态添加/删除需要过滤的进程
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);        // 最多支持1024个过滤PID
    __type(key, u32);                 // PID作为键
    __type(value, u8);                // 简单标志位作为值
} pid_filter SEC(".maps");

/*
 * 配置映射 - 用于动态配置系统行为
 * 
 * 设计原理：
 * - 数组映射，索引为配置项ID，值为配置值
 * - 支持运行时动态修改配置，无需重新加载eBPF程序
 * - 用户空间程序可以通过此映射控制监控行为
 * 
 * 使用场景：
 * - 开关不同类型的事件监控
 * - 设置UID过滤范围
 * - 调整监控参数
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);          // 支持64个配置项
    __type(key, u32);                 // 配置项ID
    __type(value, u64);               // 配置值
} etracee_config SEC(".maps");

// ========== 配置键定义 ==========
// 这些常量定义了配置映射中各个配置项的索引

#define CONFIG_ENABLE_FILE_EVENTS    0  // 文件系统事件开关
#define CONFIG_ENABLE_NET_EVENTS     1  // 网络事件开关
#define CONFIG_ENABLE_PROC_EVENTS    2  // 进程事件开关
#define CONFIG_ENABLE_PERM_EVENTS    3  // 权限事件开关
#define CONFIG_ENABLE_MEM_EVENTS     4  // 内存事件开关
#define CONFIG_MIN_UID_FILTER        5  // UID过滤最小值
#define CONFIG_MAX_UID_FILTER        6  // UID过滤最大值

// ========== 辅助函数 ==========
// 这些函数提供了通用的功能，被各个跟踪模块使用

/*
 * 检查配置项是否启用
 * 
 * 参数：config_key - 配置项键值
 * 返回：true表示启用，false表示禁用
 * 
 * 实现逻辑：
 * 1. 从配置映射中查找指定的配置项
 * 2. 如果找到且值非零，则返回true
 * 3. 否则返回false
 */
static inline bool is_config_enabled(u32 config_key) {
    u64 *value = bpf_map_lookup_elem(&etracee_config, &config_key);
    return value && *value;
}

/*
 * 检查PID是否应该被过滤
 * 
 * 参数：pid - 进程ID
 * 返回：true表示应该过滤，false表示不过滤
 * 
 * 实现逻辑：
 * 1. 在PID过滤映射中查找指定PID
 * 2. 如果找到，说明该PID在过滤列表中，返回true
 * 3. 否则返回false
 */
static inline bool should_filter_pid(u32 pid) {
    return bpf_map_lookup_elem(&pid_filter, &pid) != NULL;
}

/*
 * 检查UID是否在允许的范围内
 * 
 * 参数：uid - 用户ID
 * 返回：true表示在范围内，false表示超出范围
 * 
 * 实现逻辑：
 * 1. 从配置映射中获取UID的最小值和最大值
 * 2. 如果配置不存在，默认允许所有UID
 * 3. 检查给定UID是否在[min_uid, max_uid]范围内
 */
static inline bool is_uid_in_range(u32 uid) {
    u32 min_key = CONFIG_MIN_UID_FILTER, max_key = CONFIG_MAX_UID_FILTER;
    u64 *min_uid = bpf_map_lookup_elem(&etracee_config, &min_key);
    u64 *max_uid = bpf_map_lookup_elem(&etracee_config, &max_key);
    
    // 如果没有配置UID范围，则允许所有UID
    if (!min_uid || !max_uid) return true;
    return uid >= *min_uid && uid <= *max_uid;
}

/*
 * 初始化事件基础信息
 * 
 * 参数：e - 事件结构体指针
 *      event_type - 事件类型
 * 
 * 功能：填充所有事件共有的基础字段
 * 
 * 实现逻辑：
 * 1. 获取当前进程的PID和TID
 * 2. 获取当前时间戳
 * 3. 获取当前进程的UID和GID
 * 4. 获取当前进程的命令名
 * 5. 设置事件类型
 * 
 * 设计考虑：
 * - 使用内联函数提高性能
 * - 统一事件初始化逻辑，确保一致性
 * - 预留PPID字段，可在需要时通过task结构获取
 */
static inline void init_event_base(struct event *e, u32 event_type) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;  // 高32位是PID
    
    e->timestamp = bpf_ktime_get_ns();                              // 纳秒级时间戳
    e->event_type = event_type;                                     // 事件类型
    e->pid = pid;                                                   // 进程ID
    // 通过CO-RE读取父进程ID，提升事件父子关联的准确性
    // 注意：在某些早期内核或特殊场景下real_parent可能不可用，保留安全回退为0
    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        u32 ppid = 0;
        if (task) {
            ppid = BPF_CORE_READ(task, real_parent, tgid);
        }
        e->ppid = ppid;
    }
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;               // 用户ID（低32位）
    e->gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;       // 组ID（高32位）
    bpf_get_current_comm(&e->comm, sizeof(e->comm));               // 进程命令名
}

// ========== 通用跟踪宏，减少代码重复 ==========

/*
 * 通用事件跟踪宏
 * 
 * 设计目的：
 * - 消除各个跟踪函数中的重复代码
 * - 统一事件处理流程，确保一致性
 * - 简化新跟踪函数的开发
 * 
 * 参数：
 * - config_key: 配置项键，用于检查该类事件是否启用
 * - event_type: 事件类型，用于标识事件
 * - ctx: 跟踪点上下文，包含系统调用信息
 * - custom_code: 自定义代码块，用于设置特定事件的字段
 * 
 * 执行流程：
 * 1. 检查配置是否启用，如果禁用则直接返回
 * 2. 从ring buffer预留空间用于事件
 * 3. 初始化事件基础信息
 * 4. 设置系统调用ID
 * 5. 执行自定义代码（设置特定字段）
 * 6. 应用过滤规则（PID过滤和UID范围检查）
 * 7. 提交事件到ring buffer或丢弃
 * 
 * 优势：
 * - 代码复用：避免在每个跟踪函数中重复相同逻辑
 * - 一致性：确保所有事件都经过相同的处理流程
 * - 维护性：修改通用逻辑只需要修改一处
 * - 性能：内联展开，无函数调用开销
 */
#define TRACE_EVENT_COMMON(config_key, event_type, ctx, custom_code) \
    do { \
        /* 检查该类事件是否启用 */ \
        if (!is_config_enabled(config_key)) return 0; \
        \
        /* 从ring buffer预留事件空间 */ \
        struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0); \
        if (!e) return 0; \
        \
        /* 清零事件结构，避免未设置字段残留随机值 */ \
        __builtin_memset(e, 0, sizeof(*e)); \
        \
        /* 初始化事件基础信息 */ \
        init_event_base(e, event_type); \
        e->syscall_id = ctx->id; \
        \
        /* 执行自定义代码设置特定字段 */ \
        custom_code \
        \
        /* 应用过滤规则 */ \
        if (should_filter_pid(e->pid) || !is_uid_in_range(e->uid)) { \
            bpf_ringbuf_discard(e, 0);  /* 丢弃被过滤的事件 */ \
            return 0; \
        } \
        \
        /* 提交事件到用户空间 */ \
        bpf_ringbuf_submit(e, 0); \
        return 0; \
    } while(0)

// ========== 包含各个跟踪模块 ==========
// 采用模块化设计，将不同类型的跟踪逻辑分离到独立文件中
// 这样做的好处：
// 1. 代码组织清晰，便于维护
// 2. 功能模块化，便于扩展
// 3. 编译时包含，性能无损失

#include "execve_trace.c"      // 进程执行相关事件跟踪
#include "filesystem_trace.c"  // 文件系统相关事件跟踪
#include "network_trace.c"     // 网络相关事件跟踪
#include "security_trace.c"    // 安全相关事件跟踪