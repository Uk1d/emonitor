// eTracee - eBPF Security Monitoring System
// Header file defining event structures and constants
// 
// This header contains the shared data structures between
// the eBPF kernel program and the Go userspace program.
// It defines event types, data structures, and constants
// used for security monitoring and event processing.

#ifndef __ETRACEE_H__
#define __ETRACEE_H__

// 事件类型定义 - 覆盖全安全场景
enum event_type {
    // 进程相关事件
    EVENT_EXECVE = 1,           // 进程执行
    EVENT_FORK = 2,             // 进程创建
    EVENT_CLONE = 3,            // 线程/进程克隆
    EVENT_EXIT = 4,             // 进程退出
    EVENT_EXECVEAT = 5,         // execveat
    
    // 文件系统相关事件
    EVENT_OPENAT = 10,          // 文件打开
    EVENT_CLOSE = 11,           // 文件关闭
    EVENT_READ = 12,            // 文件读取
    EVENT_WRITE = 13,           // 文件写入
    EVENT_UNLINK = 14,          // 文件删除
    EVENT_RENAME = 15,          // 文件重命名
    EVENT_CHMOD = 16,           // 文件权限修改
    EVENT_CHOWN = 17,           // 文件所有者修改
    
    // 网络相关事件
    EVENT_CONNECT = 20,         // 网络连接
    EVENT_BIND = 21,            // 网络绑定
    EVENT_LISTEN = 22,          // 网络监听
    EVENT_ACCEPT = 23,          // 接受连接
    EVENT_SENDTO = 24,          // 发送数据
    EVENT_RECVFROM = 25,        // 接收数据
    EVENT_SOCKET = 26,          // 创建套接字
    EVENT_SHUTDOWN = 27,        // 关闭套接字方向
    
    // 权限相关事件
    EVENT_SETUID = 30,          // 设置用户ID
    EVENT_SETGID = 31,          // 设置组ID
    EVENT_SETREUID = 32,        // 设置真实用户ID
    EVENT_SETREGID = 33,        // 设置真实组ID
    EVENT_SETRESUID = 34,       // 设置有效用户ID
    EVENT_SETRESGID = 35,       // 设置有效组ID
    EVENT_SETNS = 36,           // 进入命名空间
    EVENT_UNSHARE = 37,         // 解绑命名空间
    EVENT_PRCTL = 38,           // 进程控制
    
    // 内存相关事件
    EVENT_MMAP = 40,            // 内存映射
    EVENT_MPROTECT = 41,        // 内存保护修改
    EVENT_MUNMAP = 42,          // 内存解映射
    EVENT_MREMAP = 43,          // 内存重新映射
    
    // 模块相关事件
    EVENT_INIT_MODULE = 50,     // 加载内核模块
    EVENT_DELETE_MODULE = 51,   // 删除内核模块
    
    // 系统调用相关
    EVENT_PTRACE = 60,          // 进程跟踪
    EVENT_KILL = 61,            // 发送信号
    EVENT_MOUNT = 62,           // 文件系统挂载
    EVENT_UMOUNT = 63,          // 文件系统卸载
};

// 网络地址结构
struct network_addr {
    __u16 family;               // 地址族 (AF_INET, AF_INET6)
    __u16 port;                 // 端口号
    union {
        __u32 ipv4;             // IPv4 地址
        __u8 ipv6[16];          // IPv6 地址
    } addr;
};

// 事件数据结构 - 扩展字段
struct event {
    __u64 timestamp;            // 时间戳
    __u32 pid;                  // 进程ID
    __u32 ppid;                 // 父进程ID
    __u32 uid;                  // 用户ID
    __u32 gid;                  // 组ID
    __u32 syscall_id;           // 系统调用号
    __u32 event_type;           // 事件类型
    __s32 ret_code;             // 返回值
    
    char comm[16];              // 进程名
    char filename[256];         // 文件名/路径
    
    // 扩展字段
    __u32 mode;                 // 文件权限/模式
    __u64 size;                 // 文件大小/数据长度
    __u32 flags;                // 标志位
    
    struct network_addr src_addr;   // 源地址
    struct network_addr dst_addr;   // 目标地址
    
    // 权限相关
    __u32 old_uid;              // 原用户ID
    __u32 old_gid;              // 原组ID
    __u32 new_uid;              // 新用户ID
    __u32 new_gid;              // 新组ID
    
    // 内存相关
    __u64 addr;                 // 内存地址
    __u64 len;                  // 内存长度
    __u32 prot;                 // 内存保护标志
    
    char target_comm[16];       // 目标进程名（用于kill等）
    __u32 target_pid;           // 目标进程ID
    __u32 signal;               // 信号号
};

// 辅助函数：将事件类型转换为字符串
static inline const char* event_type_to_string(enum event_type type) {
    switch (type) {
        // 进程相关
        case EVENT_EXECVE: return "execve";
        case EVENT_FORK: return "fork";
        case EVENT_CLONE: return "clone";
        case EVENT_EXIT: return "exit";
        case EVENT_EXECVEAT: return "execveat";
        
        // 文件系统相关
        case EVENT_OPENAT: return "openat";
        case EVENT_CLOSE: return "close";
        case EVENT_READ: return "read";
        case EVENT_WRITE: return "write";
        case EVENT_UNLINK: return "unlink";
        case EVENT_RENAME: return "rename";
        case EVENT_CHMOD: return "chmod";
        case EVENT_CHOWN: return "chown";
        
        // 网络相关
        case EVENT_CONNECT: return "connect";
        case EVENT_BIND: return "bind";
        case EVENT_LISTEN: return "listen";
        case EVENT_ACCEPT: return "accept";
        case EVENT_SENDTO: return "sendto";
        case EVENT_RECVFROM: return "recvfrom";
        case EVENT_SOCKET: return "socket";
        case EVENT_SHUTDOWN: return "shutdown";
        
        // 权限相关
        case EVENT_SETUID: return "setuid";
        case EVENT_SETGID: return "setgid";
        case EVENT_SETREUID: return "setreuid";
        case EVENT_SETREGID: return "setregid";
        case EVENT_SETRESUID: return "setresuid";
        case EVENT_SETRESGID: return "setresgid";
        case EVENT_SETNS: return "setns";
        case EVENT_UNSHARE: return "unshare";
        case EVENT_PRCTL: return "prctl";
        
        // 内存相关
        case EVENT_MMAP: return "mmap";
        case EVENT_MPROTECT: return "mprotect";
        case EVENT_MUNMAP: return "munmap";
        case EVENT_MREMAP: return "mremap";
        
        // 模块相关
        case EVENT_INIT_MODULE: return "init_module";
        case EVENT_DELETE_MODULE: return "delete_module";
        
        // 系统调用相关
        case EVENT_PTRACE: return "ptrace";
        case EVENT_KILL: return "kill";
        case EVENT_MOUNT: return "mount";
        case EVENT_UMOUNT: return "umount";
        
        default: return "unknown";
    }
}

#endif // __ETRACEE_H