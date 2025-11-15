/*
 * eTracee - eBPF Security Monitoring System
 * Process execution (execve) tracing module
 * 
 * 功能概述：
 * 本模块负责跟踪进程生命周期相关的系统调用，包括进程创建、执行和退出。
 * 这些事件是安全监控的核心，可以帮助检测恶意进程执行、进程注入等攻击行为。
 * 
 * 监控的系统调用：
 * - execve: 进程执行新程序
 * - fork: 创建子进程
 * - clone: 创建线程或进程
 * - exit: 进程退出
 * 
 * 设计思路：
 * 1. 使用跟踪点（tracepoint）而非kprobe，提供更稳定的接口
 * 2. 利用通用宏TRACE_EVENT_COMMON减少代码重复
 * 3. 针对不同的跟踪点使用不同的处理策略
 * 4. 支持动态配置开关，可以选择性启用/禁用监控
 * 
 * 安全意义：
 * - 检测恶意程序执行
 * - 监控进程创建链
 * - 发现异常的进程行为模式
 * - 追踪攻击者的活动轨迹
 */

// ========== 进程相关事件跟踪 ==========

/*
 * execve系统调用跟踪函数
 * 
 * 功能：监控进程执行新程序的行为
 * 跟踪点：syscalls/sys_enter_execve
 * 
 * 安全意义：
 * - execve是最重要的安全监控点之一
 * - 可以检测恶意程序的执行
 * - 监控程序替换和代码注入
 * - 追踪攻击者使用的工具和技术
 * 
 * 实现逻辑：
 * 1. 检查进程事件监控是否启用
 * 2. 收集基础进程信息（PID、UID、进程名等）
 * 3. 应用过滤规则（PID过滤、UID范围检查）
 * 4. 将事件发送到用户空间进行分析
 * 
 * 扩展可能：
 * - 可以添加参数解析，获取执行的命令行
 * - 可以添加文件路径解析，获取执行的程序路径
 * - 可以添加环境变量监控
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PROC_EVENTS, EVENT_EXECVE, ctx, {
        // execve特定逻辑可以在这里添加
        // 例如：解析命令行参数、获取可执行文件路径等
        // 当前使用通用处理逻辑，收集基础进程信息
    });
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PROC_EVENTS, EVENT_EXECVEAT, ctx, {
        const char *pathname = (const char *)ctx->args[1];
        if (pathname) {
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), pathname);
        }
        e->flags = (u32)ctx->args[4];
    });
}

/*
 * fork系统调用跟踪函数
 * 
 * 功能：监控进程创建行为
 * 跟踪点：syscalls/sys_enter_fork
 * 
 * 安全意义：
 * - 监控进程创建模式，检测异常的进程繁殖
 * - 发现fork炸弹等拒绝服务攻击
 * - 追踪进程家族树，了解攻击传播路径
 * - 检测进程注入前的准备阶段
 * 
 * 实现逻辑：
 * 1. 在fork系统调用入口点进行拦截
 * 2. 记录父进程信息
 * 3. 为后续的子进程监控做准备
 * 
 * 技术细节：
 * - fork创建的是完全相同的进程副本
 * - 父子进程只有PID不同
 * - 可以通过返回值区分父子进程（但在enter点无法获取）
 */
SEC("tracepoint/syscalls/sys_enter_fork")
int trace_fork(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PROC_EVENTS, EVENT_FORK, ctx, {
        // fork特定逻辑可以在这里添加
        // 例如：记录父进程信息、设置进程关系等
        // 当前使用通用处理逻辑
    });
}

/*
 * clone系统调用跟踪函数
 * 
 * 功能：监控线程/进程创建行为
 * 跟踪点：syscalls/sys_enter_clone
 * 
 * 安全意义：
 * - clone是更通用的进程/线程创建接口
 * - 可以创建共享内存空间的线程或独立的进程
 * - 监控多线程恶意程序的行为
 * - 检测利用clone进行的权限提升攻击
 * 
 * 实现逻辑：
 * 1. 拦截clone系统调用
 * 2. 记录创建参数和标志位
 * 3. 区分线程创建和进程创建
 * 
 * 技术细节：
 * - clone的flags参数决定了共享哪些资源
 * - CLONE_VM表示共享内存空间（线程）
 * - 不同的flags组合有不同的安全含义
 * 
 * 扩展可能：
 * - 解析clone的flags参数
 * - 根据flags判断创建类型（进程vs线程）
 * - 监控特殊的clone用法
 */
SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PROC_EVENTS, EVENT_CLONE, ctx, {
        // clone特定逻辑可以在这里添加
        // 例如：解析clone flags、判断创建类型等
        // 当前使用通用处理逻辑
    });
}

/*
 * 进程退出事件跟踪函数
 * 
 * 功能：监控进程退出行为
 * 跟踪点：sched/sched_process_exit
 * 
 * 安全意义：
 * - 监控进程异常退出
 * - 检测进程被强制终止的情况
 * - 分析进程生命周期，发现异常模式
 * - 配合进程创建事件，完整追踪进程活动
 * 
 * 实现逻辑：
 * 1. 使用调度器跟踪点而非系统调用跟踪点
 * 2. 在进程实际退出时触发，而非exit系统调用时
 * 3. 记录退出时的进程状态信息
 * 
 * 技术细节：
 * - sched_process_exit在进程真正退出时触发
 * - 比sys_exit更可靠，因为进程可能通过其他方式退出
 * - 上下文结构与系统调用跟踪点不同
 * - 无法直接获取退出码，需要其他方式获取
 * 
 * 设计考虑：
 * - 不使用TRACE_EVENT_COMMON宏，因为上下文结构不同
 * - 手动实现事件处理流程，保持与其他事件的一致性
 * - 退出码设置为0，因为跟踪点不提供此信息
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
    // 检查进程事件监控是否启用
    if (!is_config_enabled(CONFIG_ENABLE_PROC_EVENTS)) return 0;
    
    // 从ring buffer预留事件空间
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    
    // 清零事件结构，避免随机字段污染（如dst_addr/src_addr残留）
    __builtin_memset(e, 0, sizeof(*e));
    
    // 初始化事件基础信息
    init_event_base(e, EVENT_EXIT);
    
    // sched_process_exit跟踪点不提供退出码，设置为0
    // 如果需要真实退出码，需要通过其他方式获取，如：
    // - 使用task_struct结构体
    // - 结合sys_exit跟踪点
    // - 使用kprobe on do_exit函数
    e->ret_code = 0;
    
    // 应用过滤规则：PID过滤和UID范围检查
    if (should_filter_pid(e->pid) || !is_uid_in_range(e->uid)) {
        bpf_ringbuf_discard(e, 0);  // 丢弃被过滤的事件
        return 0;
    }
    
    // 提交事件到用户空间
    bpf_ringbuf_submit(e, 0);
    return 0;
}