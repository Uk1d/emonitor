// eTracee - eBPF Security Monitoring System
// Network tracing module
// 
// This module handles tracing of network-related system calls,
// including connect, bind, and listen operations.

// ========== 网络相关事件跟踪 ==========

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_CONNECT, ctx, {
        // 读取连接地址信息
        struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
        if (addr) {
            u16 family;
            bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
            e->dst_addr.family = family;
            
            if (family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                bpf_probe_read_user(&e->dst_addr.port, sizeof(e->dst_addr.port), &addr_in->sin_port);
                bpf_probe_read_user(&e->dst_addr.addr.ipv4, sizeof(e->dst_addr.addr.ipv4), &addr_in->sin_addr);
            }
        }
    });
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_BIND, ctx, {
        // 读取绑定地址信息
        struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
        if (addr) {
            u16 family;
            bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
            e->src_addr.family = family;
            
            if (family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                bpf_probe_read_user(&e->src_addr.port, sizeof(e->src_addr.port), &addr_in->sin_port);
                bpf_probe_read_user(&e->src_addr.addr.ipv4, sizeof(e->src_addr.addr.ipv4), &addr_in->sin_addr);
            }
        }
    });
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_LISTEN, ctx, {
        // listen的backlog参数
        e->flags = (u32)ctx->args[1];
    });
}