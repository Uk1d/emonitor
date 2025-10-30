// eTracee - eBPF Security Monitoring System
// Main eBPF program that includes all tracing modules
// 
// This is the main entry point that combines all individual
// tracing modules into a single eBPF program.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "etracee.h"

// 网络地址族定义
#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

// ========== eBPF Maps 定义 ==========

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// PID filter map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} pid_filter SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u64);
} etracee_config SEC(".maps");

// ========== 配置键定义 ==========
#define CONFIG_ENABLE_FILE_EVENTS    0
#define CONFIG_ENABLE_NET_EVENTS     1
#define CONFIG_ENABLE_PROC_EVENTS    2
#define CONFIG_ENABLE_PERM_EVENTS    3
#define CONFIG_ENABLE_MEM_EVENTS     4
#define CONFIG_MIN_UID_FILTER        5
#define CONFIG_MAX_UID_FILTER        6

// ========== 辅助函数 ==========

static inline bool is_config_enabled(u32 config_key) {
    u64 *value = bpf_map_lookup_elem(&etracee_config, &config_key);
    return value && *value;
}

static inline bool should_filter_pid(u32 pid) {
    return bpf_map_lookup_elem(&pid_filter, &pid) != NULL;
}

static inline bool is_uid_in_range(u32 uid) {
    u32 min_key = CONFIG_MIN_UID_FILTER, max_key = CONFIG_MAX_UID_FILTER;
    u64 *min_uid = bpf_map_lookup_elem(&etracee_config, &min_key);
    u64 *max_uid = bpf_map_lookup_elem(&etracee_config, &max_key);
    
    if (!min_uid || !max_uid) return true;
    return uid >= *min_uid && uid <= *max_uid;
}

static inline void init_event_base(struct event *e, u32 event_type) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = event_type;
    e->pid = pid;
    e->ppid = 0; // 需要时可以通过task结构获取
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// ========== 通用跟踪宏，减少代码重复 ==========

#define TRACE_EVENT_COMMON(config_key, event_type, ctx, custom_code) \
    do { \
        if (!is_config_enabled(config_key)) return 0; \
        \
        struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0); \
        if (!e) return 0; \
        \
        init_event_base(e, event_type); \
        e->syscall_id = ctx->id; \
        \
        custom_code \
        \
        if (should_filter_pid(e->pid) || !is_uid_in_range(e->uid)) { \
            bpf_ringbuf_discard(e, 0); \
            return 0; \
        } \
        \
        bpf_ringbuf_submit(e, 0); \
        return 0; \
    } while(0)

// ========== 包含各个跟踪模块 ==========

#include "execve_trace.c"
#include "filesystem_trace.c"
#include "network_trace.c"
#include "security_trace.c"