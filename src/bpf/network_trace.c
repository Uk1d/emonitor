/*
 * eTracee - eBPF Security Monitoring System
 * Network tracing module
 * 
 * 功能概述：
 * 本模块负责监控网络相关的系统调用，是网络安全监控的核心组件。
 * 网络活动是攻击行为的重要指标，包括恶意连接、后门通信、数据泄露、
 * 网络扫描、C&C通信等行为。
 * 
 * 监控的系统调用：
 * - connect: 客户端连接操作
 * - bind: 服务端绑定操作
 * - listen: 服务端监听操作
 * 
 * 设计思路：
 * 1. 重点监控网络连接的建立过程
 * 2. 提取关键的网络地址信息（IP、端口、协议族）
 * 3. 支持IPv4协议（可扩展IPv6）
 * 4. 利用TRACE_EVENT_COMMON宏统一处理流程
 * 5. 支持动态配置，可选择性启用网络监控
 * 
 * 安全意义：
 * - 检测恶意网络连接（C&C通信、数据泄露）
 * - 监控异常的网络服务（后门、代理等）
 * - 发现网络扫描和探测行为
 * - 追踪攻击者的网络活动轨迹
 * - 检测横向移动和内网渗透
 * - 监控数据外泄通道
 */

// ========== 网络相关事件跟踪 ==========

/*
 * connect系统调用跟踪函数
 * 
 * 功能：监控客户端网络连接操作
 * 跟踪点：syscalls/sys_enter_connect
 * 
 * 安全意义：
 * - connect是最重要的网络安全监控点
 * - 可以检测恶意外联行为（C&C通信）
 * - 监控数据泄露通道（异常连接目标）
 * - 发现网络扫描和探测活动
 * - 追踪横向移动和内网渗透
 * - 检测反向shell和后门通信
 * 
 * 参数解析：
 * - args[0]: sockfd - 套接字文件描述符
 * - args[1]: addr - 目标地址结构指针
 * - args[2]: addrlen - 地址结构长度
 * 
 * 实现逻辑：
 * 1. 检查网络事件监控是否启用
 * 2. 解析目标地址信息（IP、端口、协议族）
 * 3. 根据协议族提取相应的地址信息
 * 4. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - 使用bpf_probe_read_user安全读取用户空间数据
 * - 支持IPv4协议，可扩展IPv6
 * - 地址信息存储在dst_addr字段（目标地址）
 * - 端口号以网络字节序存储
 * 
 * 安全考虑：
 * - 外联连接是重要的安全指标
 * - 异常的目标IP和端口需要重点关注
 * - 可以建立IP/端口白名单和黑名单
 * - 连接频率和模式分析有助于检测攻击
 * 
 * 扩展可能：
 * - 添加IPv6支持
 * - 添加域名解析监控
 * - 添加连接状态跟踪
 * - 添加流量统计功能
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_CONNECT, ctx, {
        struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
        if (addr) {
            u16 family;
            bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
            e->dst_addr.family = family;
            if (family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                bpf_probe_read_user(&e->dst_addr.port, sizeof(e->dst_addr.port), &addr_in->sin_port);
                bpf_probe_read_user(&e->dst_addr.addr.ipv4, sizeof(e->dst_addr.addr.ipv4), &addr_in->sin_addr);
            } else if (family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
                bpf_probe_read_user(&e->dst_addr.port, sizeof(e->dst_addr.port), &addr_in6->sin6_port);
                bpf_probe_read_user(&e->dst_addr.addr.ipv6, sizeof(e->dst_addr.addr.ipv6), &addr_in6->sin6_addr);
            }
        }
    });
}

/*
 * bind系统调用跟踪函数
 * 
 * 功能：监控服务端网络绑定操作
 * 跟踪点：syscalls/sys_enter_bind
 * 
 * 安全意义：
 * - 检测恶意网络服务（后门、代理、木马等）
 * - 监控异常的端口绑定行为
 * - 发现权限提升后的服务创建
 * - 追踪攻击者建立的持久化机制
 * - 检测内网代理和跳板服务
 * - 监控异常的监听端口
 * 
 * 参数解析：
 * - args[0]: sockfd - 套接字文件描述符
 * - args[1]: addr - 绑定地址结构指针
 * - args[2]: addrlen - 地址结构长度
 * 
 * 实现逻辑：
 * 1. 检查网络事件监控是否启用
 * 2. 解析绑定地址信息（IP、端口、协议族）
 * 3. 根据协议族提取相应的地址信息
 * 4. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - 地址信息存储在src_addr字段（源地址/本地地址）
 * - bind通常绑定本地地址和端口
 * - 0.0.0.0表示绑定所有接口
 * - 特定IP表示只绑定特定接口
 * 
 * 安全考虑：
 * - 异常端口的绑定需要重点关注
 * - 高权限端口（<1024）的绑定更加敏感
 * - 绑定所有接口（0.0.0.0）风险更高
 * - 可以建立端口使用的基线和异常检测
 * 
 * 应用场景：
 * - 检测后门服务
 * - 监控代理和跳板
 * - 发现异常的网络服务
 * - 追踪攻击者的持久化手段
 */
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_BIND, ctx, {
        struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
        if (addr) {
            u16 family;
            bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
            e->src_addr.family = family;
            if (family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                bpf_probe_read_user(&e->src_addr.port, sizeof(e->src_addr.port), &addr_in->sin_port);
                bpf_probe_read_user(&e->src_addr.addr.ipv4, sizeof(e->src_addr.addr.ipv4), &addr_in->sin_addr);
            } else if (family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
                bpf_probe_read_user(&e->src_addr.port, sizeof(e->src_addr.port), &addr_in6->sin6_port);
                bpf_probe_read_user(&e->src_addr.addr.ipv6, sizeof(e->src_addr.addr.ipv6), &addr_in6->sin6_addr);
            }
        }
    });
}

/*
 * listen系统调用跟踪函数
 * 
 * 功能：监控服务端网络监听操作
 * 跟踪点：syscalls/sys_enter_listen
 * 
 * 安全意义：
 * - 配合bind监控，完整追踪服务创建过程
 * - 检测服务正式开始接受连接的时刻
 * - 监控服务的连接队列配置
 * - 发现异常的网络服务行为
 * - 追踪攻击者服务的激活过程
 * 
 * 参数解析：
 * - args[0]: sockfd - 套接字文件描述符
 * - args[1]: backlog - 连接队列最大长度
 * 
 * 实现逻辑：
 * 1. 检查网络事件监控是否启用
 * 2. 记录backlog参数（连接队列长度）
 * 3. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - listen使套接字进入被动监听状态
 * - backlog参数控制连接队列大小
 * - 必须在bind之后调用
 * - 是服务正式启动的标志
 * 
 * 安全考虑：
 * - listen标志着服务正式可用
 * - 大的backlog值可能表明高并发服务
 * - 配合bind事件可以完整追踪服务创建
 * - 异常的listen行为需要关注
 * 
 * 应用场景：
 * - 确认恶意服务已经启动
 * - 监控服务的配置参数
 * - 分析攻击者的服务策略
 * - 检测服务的异常行为模式
 * 
 * 设计考虑：
 * - listen事件相对较少，但很重要
 * - 需要与bind事件关联分析
 * - backlog值可以反映服务的预期负载
 */
SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_LISTEN, ctx, {
        e->flags = (u32)ctx->args[1];
    });
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_ACCEPT, ctx, {
        struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
        if (addr) {
            u16 family;
            bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
            e->src_addr.family = family;
            if (family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                bpf_probe_read_user(&e->src_addr.port, sizeof(e->src_addr.port), &addr_in->sin_port);
                bpf_probe_read_user(&e->src_addr.addr.ipv4, sizeof(e->src_addr.addr.ipv4), &addr_in->sin_addr);
            } else if (family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
                bpf_probe_read_user(&e->src_addr.port, sizeof(e->src_addr.port), &addr_in6->sin6_port);
                bpf_probe_read_user(&e->src_addr.addr.ipv6, sizeof(e->src_addr.addr.ipv6), &addr_in6->sin6_addr);
            }
        }
        e->flags = (u32)ctx->args[3];
    });
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_ACCEPT, ctx, {
        struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
        if (addr) {
            u16 family;
            bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
            e->src_addr.family = family;
            if (family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                bpf_probe_read_user(&e->src_addr.port, sizeof(e->src_addr.port), &addr_in->sin_port);
                bpf_probe_read_user(&e->src_addr.addr.ipv4, sizeof(e->src_addr.addr.ipv4), &addr_in->sin_addr);
            } else if (family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
                bpf_probe_read_user(&e->src_addr.port, sizeof(e->src_addr.port), &addr_in6->sin6_port);
                bpf_probe_read_user(&e->src_addr.addr.ipv6, sizeof(e->src_addr.addr.ipv6), &addr_in6->sin6_addr);
            }
        }
    });
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_SENDTO, ctx, {
        struct sockaddr *addr = (struct sockaddr *)ctx->args[4];
        if (addr) {
            u16 family;
            bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
            e->dst_addr.family = family;
            if (family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                bpf_probe_read_user(&e->dst_addr.port, sizeof(e->dst_addr.port), &addr_in->sin_port);
                bpf_probe_read_user(&e->dst_addr.addr.ipv4, sizeof(e->dst_addr.addr.ipv4), &addr_in->sin_addr);
            } else if (family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
                bpf_probe_read_user(&e->dst_addr.port, sizeof(e->dst_addr.port), &addr_in6->sin6_port);
                bpf_probe_read_user(&e->dst_addr.addr.ipv6, sizeof(e->dst_addr.addr.ipv6), &addr_in6->sin6_addr);
            }
        }
        e->size = (u64)ctx->args[2];
        e->flags = (u32)ctx->args[3];
    });
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_RECVFROM, ctx, {
        struct sockaddr *addr = (struct sockaddr *)ctx->args[4];
        if (addr) {
            u16 family;
            bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
            e->src_addr.family = family;
            if (family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                bpf_probe_read_user(&e->src_addr.port, sizeof(e->src_addr.port), &addr_in->sin_port);
                bpf_probe_read_user(&e->src_addr.addr.ipv4, sizeof(e->src_addr.addr.ipv4), &addr_in->sin_addr);
            } else if (family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
                bpf_probe_read_user(&e->src_addr.port, sizeof(e->src_addr.port), &addr_in6->sin6_port);
                bpf_probe_read_user(&e->src_addr.addr.ipv6, sizeof(e->src_addr.addr.ipv6), &addr_in6->sin6_addr);
            }
        }
        e->size = (u64)ctx->args[2];
        e->flags = (u32)ctx->args[3];
    });
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_SOCKET, ctx, {
        e->src_addr.family = (u16)ctx->args[0];
        e->flags = (u32)ctx->args[1];
        e->size = (u64)ctx->args[2];
    });
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int trace_shutdown(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_NET_EVENTS, EVENT_SHUTDOWN, ctx, {
        e->flags = (u32)ctx->args[1];
    });
}