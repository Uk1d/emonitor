// eTracee - eBPF Security Monitoring System
// Process execution (execve) tracing module
// 
// This module handles tracing of process execution events,
// including execve, fork, clone, and exit system calls.

// ========== 进程相关事件跟踪 ==========

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PROC_EVENTS, EVENT_EXECVE, ctx, {
        // execve特定逻辑可以在这里添加
    });
}

SEC("tracepoint/syscalls/sys_enter_fork")
int trace_fork(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PROC_EVENTS, EVENT_FORK, ctx, {
        // fork特定逻辑可以在这里添加
    });
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PROC_EVENTS, EVENT_CLONE, ctx, {
        // clone特定逻辑可以在这里添加
    });
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
    if (!is_config_enabled(CONFIG_ENABLE_PROC_EVENTS)) return 0;
    
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    
    init_event_base(e, EVENT_EXIT);
    // sched_process_exit跟踪点不提供退出码，设置为0
    e->ret_code = 0;
    
    if (should_filter_pid(e->pid) || !is_uid_in_range(e->uid)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}