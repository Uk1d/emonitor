// eTracee - eBPF Security Monitoring System
// Filesystem tracing module
// 
// This module handles tracing of filesystem-related system calls,
// including file operations like open, close, unlink, and chmod.

// ========== 文件系统相关事件跟踪 ==========

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_FILE_EVENTS, EVENT_OPENAT, ctx, {
        // 读取文件名
        const char *filename = (const char *)ctx->args[1];
        if (filename) {
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
        }
        e->flags = (u32)ctx->args[2];
        e->mode = (u32)ctx->args[3];
    });
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_FILE_EVENTS, EVENT_CLOSE, ctx, {
        // close只需要文件描述符，已在syscall_id中
    });
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlink(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_FILE_EVENTS, EVENT_UNLINK, ctx, {
        // 读取要删除的文件名
        const char *filename = (const char *)ctx->args[1];
        if (filename) {
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
        }
        e->flags = (u32)ctx->args[2];
    });
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_chmod(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_FILE_EVENTS, EVENT_CHMOD, ctx, {
        // 读取文件名
        const char *filename = (const char *)ctx->args[1];
        if (filename) {
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
        }
        e->mode = (u32)ctx->args[2];
        e->flags = (u32)ctx->args[3];
    });
}