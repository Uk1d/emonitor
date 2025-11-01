/*
 * eTracee - eBPF Security Monitoring System
 * Filesystem tracing module
 * 
 * 功能概述：
 * 本模块负责监控文件系统相关的系统调用，是安全监控的重要组成部分。
 * 文件系统操作往往是攻击行为的重要指标，包括恶意文件创建、敏感文件访问、
 * 权限修改、文件删除等行为。
 * 
 * 监控的系统调用：
 * - openat: 文件打开操作（包括创建）
 * - close: 文件关闭操作
 * - unlinkat: 文件删除操作
 * - fchmodat: 文件权限修改操作
 * 
 * 设计思路：
 * 1. 使用现代化的*at系列系统调用，支持相对路径和绝对路径
 * 2. 重点关注文件名、权限、标志位等关键信息
 * 3. 利用TRACE_EVENT_COMMON宏统一处理流程
 * 4. 支持动态配置，可选择性监控文件事件
 * 
 * 安全意义：
 * - 检测恶意文件操作（创建后门、删除日志等）
 * - 监控敏感文件访问（配置文件、密钥文件等）
 * - 发现权限提升攻击（修改关键文件权限）
 * - 追踪数据泄露行为（异常文件访问模式）
 * - 检测勒索软件行为（大量文件操作）
 */

// ========== 文件系统相关事件跟踪 ==========

/*
 * openat系统调用跟踪函数
 * 
 * 功能：监控文件打开和创建操作
 * 跟踪点：syscalls/sys_enter_openat
 * 
 * 安全意义：
 * - openat是最重要的文件系统监控点
 * - 可以检测恶意文件创建（后门、木马等）
 * - 监控敏感文件访问（配置、密钥、日志等）
 * - 发现异常的文件访问模式
 * - 检测数据窃取行为
 * 
 * 参数解析：
 * - args[0]: dirfd - 目录文件描述符
 * - args[1]: pathname - 文件路径名
 * - args[2]: flags - 打开标志位（O_RDONLY, O_WRONLY, O_CREAT等）
 * - args[3]: mode - 文件权限模式（仅在创建时有效）
 * 
 * 实现逻辑：
 * 1. 检查文件事件监控是否启用
 * 2. 提取文件路径名到事件结构
 * 3. 记录打开标志位和权限模式
 * 4. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - 使用bpf_probe_read_user_str安全读取用户空间字符串
 * - flags字段包含重要的操作意图信息
 * - mode字段在文件创建时特别重要
 * 
 * 扩展可能：
 * - 可以添加文件类型检测
 * - 可以添加路径白名单/黑名单过滤
 * - 可以添加文件大小监控
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_FILE_EVENTS, EVENT_OPENAT, ctx, {
        // 读取文件名 - 这是最重要的信息
        // 文件名可以帮助识别攻击目标和攻击类型
        const char *filename = (const char *)ctx->args[1];
        if (filename) {
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
        }
        
        // 记录打开标志位 - 包含操作意图信息
        // O_CREAT: 创建文件, O_WRONLY: 写入, O_APPEND: 追加等
        e->flags = (u32)ctx->args[2];
        
        // 记录文件权限模式 - 在创建文件时使用
        // 异常的权限设置可能表明恶意行为
        e->mode = (u32)ctx->args[3];
    });
}

/*
 * close系统调用跟踪函数
 * 
 * 功能：监控文件关闭操作
 * 跟踪点：syscalls/sys_enter_close
 * 
 * 安全意义：
 * - 配合openat监控，完整追踪文件操作生命周期
 * - 检测异常的文件操作模式（频繁开关文件）
 * - 监控文件描述符泄露问题
 * - 分析程序的文件使用行为
 * 
 * 参数解析：
 * - args[0]: fd - 要关闭的文件描述符
 * 
 * 实现逻辑：
 * 1. 检查文件事件监控是否启用
 * 2. 记录文件描述符信息（已在syscall_id中）
 * 3. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - close操作相对简单，主要记录文件描述符
 * - 可以与openat事件关联，分析文件操作模式
 * - 对于检测文件操作异常很有价值
 * 
 * 设计考虑：
 * - close事件数量可能很大，需要合理的过滤策略
 * - 可以考虑只监控特定类型的文件描述符
 * - 与openat事件结合分析更有意义
 */
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_FILE_EVENTS, EVENT_CLOSE, ctx, {
        // close只需要文件描述符，已在syscall_id中记录
        // 文件描述符信息足以标识关闭的文件
        // 可以通过与openat事件关联来获取完整的文件操作链
    });
}

/*
 * unlinkat系统调用跟踪函数
 * 
 * 功能：监控文件删除操作
 * 跟踪点：syscalls/sys_enter_unlinkat
 * 
 * 安全意义：
 * - 检测恶意文件删除行为（删除日志、证据销毁）
 * - 监控勒索软件行为（大量文件删除）
 * - 发现数据破坏攻击
 * - 追踪攻击者的清理行为
 * - 检测系统文件被恶意删除
 * 
 * 参数解析：
 * - args[0]: dirfd - 目录文件描述符
 * - args[1]: pathname - 要删除的文件路径
 * - args[2]: flags - 删除标志位（AT_REMOVEDIR等）
 * 
 * 实现逻辑：
 * 1. 检查文件事件监控是否启用
 * 2. 提取要删除的文件路径名
 * 3. 记录删除操作的标志位
 * 4. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - unlinkat是现代的文件删除接口
 * - flags可以指示删除目录还是文件
 * - 文件名信息对于安全分析至关重要
 * 
 * 安全考虑：
 * - 删除操作通常是不可逆的，需要重点监控
 * - 系统关键文件的删除应该触发高优先级告警
 * - 批量删除操作可能表明勒索软件活动
 */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlink(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_FILE_EVENTS, EVENT_UNLINK, ctx, {
        // 读取要删除的文件名 - 这是最关键的信息
        // 文件名可以帮助识别攻击目标和破坏范围
        const char *filename = (const char *)ctx->args[1];
        if (filename) {
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
        }
        
        // 记录删除标志位
        // AT_REMOVEDIR: 删除目录, 0: 删除文件
        e->flags = (u32)ctx->args[2];
    });
}

/*
 * fchmodat系统调用跟踪函数
 * 
 * 功能：监控文件权限修改操作
 * 跟踪点：syscalls/sys_enter_fchmodat
 * 
 * 安全意义：
 * - 检测权限提升攻击（修改关键文件权限）
 * - 监控后门创建（设置可执行权限）
 * - 发现配置篡改（修改配置文件权限）
 * - 追踪攻击者的权限操作
 * - 检测异常的权限修改模式
 * 
 * 参数解析：
 * - args[0]: dirfd - 目录文件描述符
 * - args[1]: pathname - 文件路径名
 * - args[2]: mode - 新的权限模式
 * - args[3]: flags - 操作标志位
 * 
 * 实现逻辑：
 * 1. 检查文件事件监控是否启用
 * 2. 提取文件路径名
 * 3. 记录新的权限模式和操作标志
 * 4. 应用过滤规则并提交事件
 * 
 * 技术细节：
 * - fchmodat是现代的权限修改接口
 * - mode字段包含完整的权限信息（rwx for owner/group/other）
 * - flags可以控制符号链接的处理方式
 * 
 * 安全考虑：
 * - 权限修改可能是攻击的关键步骤
 * - 特别关注添加执行权限的操作
 * - 系统文件权限修改应该触发告警
 * - 可以通过权限变化模式检测攻击类型
 */
SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_chmod(struct trace_event_raw_sys_enter *ctx) {
    TRACE_EVENT_COMMON(CONFIG_ENABLE_FILE_EVENTS, EVENT_CHMOD, ctx, {
        // 读取文件名 - 标识权限修改的目标
        const char *filename = (const char *)ctx->args[1];
        if (filename) {
            bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
        }
        
        // 记录新的权限模式 - 这是最重要的信息
        // 权限变化可以揭示攻击意图
        e->mode = (u32)ctx->args[2];
        
        // 记录操作标志位
        // AT_SYMLINK_NOFOLLOW: 不跟随符号链接等
        e->flags = (u32)ctx->args[3];
    });
}