// eTracee - eBPF Security Monitoring System
// Security-related tracing module
// 
// This module handles tracing of security-related system calls,
// including permission changes, memory operations, and process control.

// ========== 权限相关事件跟踪 ==========

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_SETUID, ctx, {
        e->old_uid = e->uid;
        e->new_uid = (u32)ctx->args[0];
    });
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_SETGID, ctx, {
        e->old_gid = e->gid;
        e->new_gid = (u32)ctx->args[0];
    });
}

// ========== 内存相关事件跟踪 ==========

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_MEM_EVENTS, EVENT_MMAP, ctx, {
        e->addr = (u64)ctx->args[0];
        e->len = (u64)ctx->args[1];
        e->prot = (u32)ctx->args[2];
        e->flags = (u32)ctx->args[3];
    });
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_MEM_EVENTS, EVENT_MPROTECT, ctx, {
        e->addr = (u64)ctx->args[0];
        e->len = (u64)ctx->args[1];
        e->prot = (u32)ctx->args[2];
    });
}

// ========== 进程控制相关事件跟踪 ==========

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_PTRACE, ctx, {
        e->target_pid = (u32)ctx->args[1];
        e->flags = (u32)ctx->args[0]; // ptrace request
    });
}

SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_KILL, ctx, {
        e->target_pid = (u32)ctx->args[0];
        e->signal = (u32)ctx->args[1];
    });
}