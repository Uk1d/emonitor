/*
 * eTracee - eBPF Security Monitoring System
 * Security-related tracing module
 * 
 * 功能概述：
 * 本模块负责监控安全相关的系统调用，是安全监控系统的核心组件之一。
 * 这些系统调用通常与权限提升、进程控制、内存操作等高风险行为相关，
 * 是检测攻击行为和异常活动的重要指标。
 * 
 * 监控的系统调用类别：
 * 1. 权限相关：setuid, setgid, ptrace, kill
 * 2. 内存相关：mmap, mprotect
 * 3. 进程控制：ptrace, kill
 * 
 * 设计思路：
 * 1. 重点监控可能被攻击者利用的系统调用
 * 2. 提取关键的安全参数（UID/GID变化、内存权限、目标进程等）
 * 3. 支持分类配置，可以选择性启用不同类型的监控
 * 4. 利用TRACE_EVENT_COMMON宏统一处理流程
 * 
 * 安全意义：
 * - 检测权限提升攻击（UID/GID变化）
 * - 监控进程注入和调试行为（ptrace）
 * - 发现内存保护绕过（mmap/mprotect）
 * - 追踪恶意进程终止行为（kill）
 * - 检测代码注入和ROP/JOP攻击
 */

// ========== 权限相关事件跟踪 ==========

/*
 * setuid系统调用跟踪函数
 * 
 * 功能：监控用户ID变更操作
 * 跟踪点：syscalls/sys_enter_setuid
 * 
 * 安全意义：
 * - setuid是权限提升攻击的核心系统调用
 * - 可以检测特权升级行为（切换到root用户）
 * - 监控用户身份切换，发现异常的权限变化
 * - 追踪攻击者获取高权限后的行为
 * - 检测SUID程序的滥用
 * 
 * 参数解析：
 * - args[0]: uid - 目标用户ID
 * 
 * 实现逻辑：
 * 1. 检查权限事件监控是否启用
 * 2. 记录当前UID（old_uid）和目标UID（new_uid）
 * 3. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - 记录UID变化的完整信息
 * - old_uid来自当前进程上下文
 * - new_uid来自系统调用参数
 * - UID 0 表示root权限，需要特别关注
 * 
 * 安全考虑：
 * - 切换到UID 0（root）是高风险操作
 * - 异常的UID切换模式需要告警
 * - 可以建立UID切换的基线和异常检测
 * - 配合其他事件分析权限提升攻击链
 * 
 * 攻击场景：
 * - 利用SUID程序提权
 * - 内核漏洞提权后的UID切换
 * - 恶意程序获取root权限
 * - 横向移动中的身份切换
 */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_SETUID, ctx, {
        // 记录UID变化信息 - 权限提升检测的关键数据
        // 这些信息可以帮助识别权限提升攻击和异常的身份切换
        e->old_uid = e->uid;  // 当前UID（来自进程上下文）
        e->new_uid = (u32)ctx->args[0];  // 目标UID（系统调用参数）
        
        // 特别关注：
        // - old_uid != 0 && new_uid == 0：普通用户提升到root
        // - 频繁的UID切换可能表明异常行为
        // - 异常的UID值需要进一步分析
    });
}

/*
 * setgid系统调用跟踪函数
 * 
 * 功能：监控组ID变更操作
 * 跟踪点：syscalls/sys_enter_setgid
 * 
 * 安全意义：
 * - 配合setuid监控，完整追踪权限变化
 * - 检测组权限的异常变更
 * - 监控特权组的成员变化
 * - 发现权限提升攻击的组权限部分
 * - 追踪攻击者的权限操作策略
 * 
 * 参数解析：
 * - args[0]: gid - 目标组ID
 * 
 * 实现逻辑：
 * 1. 检查权限事件监控是否启用
 * 2. 记录当前GID（old_gid）和目标GID（new_gid）
 * 3. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - 记录GID变化的完整信息
 * - old_gid来自当前进程上下文
 * - new_gid来自系统调用参数
 * - GID 0 通常表示root组或wheel组
 * 
 * 安全考虑：
 * - 切换到特权组（如GID 0）需要关注
 * - 异常的GID切换模式需要分析
 * - 与setuid事件结合分析更有效
 * - 可以检测SGID程序的滥用
 */
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_SETGID, ctx, {
        e->old_gid = e->gid;
        e->new_gid = (u32)ctx->args[0];
    });
}

// ========== 内存相关事件跟踪 ==========

/*
 * mmap系统调用跟踪函数
 * 
 * 功能：监控内存映射操作
 * 跟踪点：syscalls/sys_enter_mmap
 * 
 * 安全意义：
 * - mmap是内存攻击的重要工具
 * - 可以检测代码注入和ROP/JOP攻击准备
 * - 监控可执行内存的分配
 * - 发现内存布局操作和ASLR绕过
 * - 追踪shellcode加载和动态代码生成
 * - 检测内存喷射攻击
 * 
 * 参数解析：
 * - args[0]: addr - 映射地址（NULL表示由系统选择）
 * - args[1]: length - 映射长度
 * - args[2]: prot - 内存保护标志（PROT_READ/WRITE/EXEC）
 * - args[3]: flags - 映射标志（MAP_PRIVATE/SHARED/ANONYMOUS等）
 * 
 * 实现逻辑：
 * 1. 检查内存事件监控是否启用
 * 2. 记录映射地址、长度、保护标志和映射标志
 * 3. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - addr为0表示由系统选择地址
 * - prot包含读写执行权限信息
 * - flags控制映射的行为和属性
 * - 可执行权限（PROT_EXEC）需要特别关注
 * 
 * 安全考虑：
 * - PROT_EXEC标志表明可执行内存，高风险
 * - MAP_ANONYMOUS + PROT_EXEC常用于shellcode
 * - 大量内存映射可能表明内存喷射
 * - 特定地址的映射可能表明ASLR绕过
 * 
 * 攻击场景：
 * - shellcode注入和执行
 * - ROP/JOP gadget准备
 * - 内存布局操作
 * - 动态代码生成
 * - 内存喷射攻击
 */
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_MEM_EVENTS, EVENT_MMAP, ctx, {
        // 记录内存映射的关键参数 - 内存攻击检测的核心数据
        e->addr = (u64)ctx->args[0];    // 映射地址
        e->len = (u64)ctx->args[1];     // 映射长度
        e->prot = (u32)ctx->args[2];    // 保护标志（重点关注PROT_EXEC）
        e->flags = (u32)ctx->args[3];   // 映射标志
        
        // 高风险组合：
        // - prot & PROT_EXEC：可执行内存（shellcode风险）
        // - flags & MAP_ANONYMOUS：匿名映射（常用于攻击）
        // - 大的len值：可能的内存喷射
        // - 特定的addr值：可能的ASLR绕过
    });
}

/*
 * mprotect系统调用跟踪函数
 * 
 * 功能：监控内存保护属性修改操作
 * 跟踪点：syscalls/sys_enter_mprotect
 * 
 * 安全意义：
 * - mprotect是绕过内存保护的关键系统调用
 * - 可以检测W^X保护的绕过（写后执行）
 * - 监控内存权限的动态变更
 * - 发现代码注入攻击的执行阶段
 * - 追踪JIT编译和动态代码修改
 * - 检测ROP/JOP攻击中的内存操作
 * 
 * 参数解析：
 * - args[0]: addr - 内存区域起始地址
 * - args[1]: len - 内存区域长度
 * - args[2]: prot - 新的保护标志
 * 
 * 实现逻辑：
 * 1. 检查内存事件监控是否启用
 * 2. 记录内存地址、长度和新的保护标志
 * 3. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - addr必须是页对齐的地址
 * - len必须是页大小的倍数
 * - prot包含新的读写执行权限
 * - 权限变更是原子操作
 * 
 * 安全考虑：
 * - 添加PROT_EXEC权限是高风险操作
 * - W^X绕过：先写入代码，再设置执行权限
 * - 频繁的权限变更可能表明攻击
 * - 特定内存区域的权限变更需要关注
 * 
 * 攻击场景：
 * - 代码注入后设置执行权限
 * - JIT喷射攻击
 * - ROP/JOP攻击中的内存准备
 * - 动态代码修改和执行
 * - DEP/NX保护绕过
 */
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_MEM_EVENTS, EVENT_MPROTECT, ctx, {
        e->addr = (u64)ctx->args[0];
        e->len = (u64)ctx->args[1];
        e->prot = (u32)ctx->args[2];
    });
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int trace_setreuid(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_SETREUID, ctx, {
        e->old_uid = e->uid;
        e->new_uid = (u32)ctx->args[1];
    });
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int trace_setregid(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_SETREGID, ctx, {
        e->old_gid = e->gid;
        e->new_gid = (u32)ctx->args[1];
    });
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_setresuid(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_SETRESUID, ctx, {
        e->old_uid = e->uid;
        e->new_uid = (u32)ctx->args[1];
    });
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_setresgid(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_SETRESGID, ctx, {
        e->old_gid = e->gid;
        e->new_gid = (u32)ctx->args[1];
    });
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_MEM_EVENTS, EVENT_MUNMAP, ctx, {
        e->addr = (u64)ctx->args[0];
        e->len = (u64)ctx->args[1];
    });
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_INIT_MODULE, ctx, {
        e->size = (u64)ctx->args[1];
    });
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int trace_delete_module(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_DELETE_MODULE, ctx, {
        const char *name = (const char *)ctx->args[0];
        if (name) {
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), name);
        }
        e->flags = (u32)ctx->args[1];
    });
}

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_mount(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_MOUNT, ctx, {
        const char *target = (const char *)ctx->args[1];
        if (target) {
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), target);
        }
        e->flags = (u32)ctx->args[3];
    });
}

SEC("tracepoint/syscalls/sys_enter_umount2")
int trace_umount(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_UMOUNT, ctx, {
        const char *target = (const char *)ctx->args[0];
        if (target) {
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), target);
        }
        e->flags = (u32)ctx->args[1];
    });
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_SETNS, ctx, {
        e->flags = (u32)ctx->args[1];
    });
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_UNSHARE, ctx, {
        e->flags = (u32)ctx->args[0];
    });
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_PRCTL, ctx, {
        e->flags = (u32)ctx->args[0];
    });
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int trace_mremap(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_MEM_EVENTS, EVENT_MREMAP, ctx, {
        e->addr = (u64)ctx->args[0];
        e->len = (u64)ctx->args[2];
        e->flags = (u32)ctx->args[3];
    });
}

// ========== 进程控制相关事件跟踪 ==========

/*
 * ptrace系统调用跟踪函数
 * 
 * 功能：监控进程调试和控制操作
 * 跟踪点：syscalls/sys_enter_ptrace
 * 
 * 安全意义：
 * - ptrace是进程注入攻击的主要工具
 * - 可以检测调试器附加和代码注入
 * - 监控进程内存的恶意访问
 * - 发现反调试绕过和分析工具
 * - 追踪进程劫持和控制行为
 * - 检测恶意调试和逆向工程
 * 
 * 参数解析：
 * - args[0]: request - ptrace请求类型（PTRACE_ATTACH等）
 * - args[1]: pid - 目标进程ID
 * - args[2]: addr - 地址参数（依赖于请求类型）
 * - args[3]: data - 数据参数（依赖于请求类型）
 * 
 * 实现逻辑：
 * 1. 检查权限事件监控是否启用
 * 2. 记录目标进程ID和ptrace请求类型
 * 3. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - request字段包含ptrace操作类型
 * - PTRACE_ATTACH用于附加到进程
 * - PTRACE_POKETEXT/POKEDATA用于内存写入
 * - PTRACE_GETREGS/SETREGS用于寄存器操作
 * 
 * 安全考虑：
 * - PTRACE_ATTACH是进程注入的第一步
 * - 内存写入操作（POKE*）高风险
 * - 跨用户的ptrace操作需要特别关注
 * - 可以检测调试器和分析工具的使用
 * 
 * 攻击场景：
 * - 进程注入和代码注入
 * - 内存dump和敏感信息窃取
 * - 进程劫持和控制
 * - 反调试检测绕过
 * - 恶意调试和逆向分析
 */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_PTRACE, ctx, {
        // 记录ptrace操作的关键信息 - 进程注入检测的核心
        e->target_pid = (u32)ctx->args[1];  // 目标进程ID
        e->flags = (u32)ctx->args[0];       // ptrace请求类型
        
        // 高风险操作：
        // - PTRACE_ATTACH：附加到进程（注入第一步）
        // - PTRACE_POKETEXT/POKEDATA：内存写入（代码注入）
        // - 跨用户的ptrace操作
        // - 对系统进程的ptrace操作
    });
}

/*
 * kill系统调用跟踪函数
 * 
 * 功能：监控进程信号发送操作
 * 跟踪点：syscalls/sys_enter_kill
 * 
 * 安全意义：
 * - 检测恶意进程终止行为
 * - 监控攻击者的清理和反取证活动
 * - 发现拒绝服务攻击
 * - 追踪进程间的恶意交互
 * - 检测防护软件的终止行为
 * - 监控异常的信号发送模式
 * 
 * 参数解析：
 * - args[0]: pid - 目标进程ID（或进程组）
 * - args[1]: sig - 信号编号
 * 
 * 实现逻辑：
 * 1. 检查权限事件监控是否启用
 * 2. 记录目标进程ID和信号编号
 * 3. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - pid > 0：发送给特定进程
 * - pid == 0：发送给当前进程组
 * - pid < -1：发送给进程组
 * - sig == 0：测试进程是否存在
 * 
 * 安全考虑：
 * - SIGKILL（9）和SIGTERM（15）是终止信号
 * - 跨用户的kill操作需要特别关注
 * - 对系统进程的kill操作高风险
 * - 批量kill操作可能表明攻击
 * 
 * 攻击场景：
 * - 终止安全软件和监控工具
 * - 清理攻击痕迹和相关进程
 * - 拒绝服务攻击
 * - 进程劫持前的目标清理
 * - 反取证和痕迹清除
 */
SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_PERM_EVENTS, EVENT_KILL, ctx, {
        // 记录kill操作的关键信息 - 恶意进程终止检测的核心
        e->target_pid = (u32)ctx->args[0];  // 目标进程ID
        e->signal = (u32)ctx->args[1];      // 信号编号
        
        // 高风险操作：
        // - signal == SIGKILL(9) 或 SIGTERM(15)：进程终止
        // - 跨用户的kill操作
        // - 对系统关键进程的kill操作
        // - 批量或频繁的kill操作
    });
}