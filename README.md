# eTracee - 增强型 eBPF 安全监控系统

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-green.svg)](https://ebpf.io)

eTracee 是一个基于 eBPF 技术的高性能安全监控系统，专为 openEuler 25.09 设计，提供全面的系统调用监控和安全事件检测能力。

## 🚀 项目特性

### 核心功能
- **全面监控**: 覆盖进程、文件系统、网络、权限、内存等多个安全维度
- **实时检测**: 基于 eBPF Ring Buffer 的低延迟事件传输
- **智能过滤**: 支持 PID、UID 范围过滤和事件类型选择
- **规则引擎**: 灵活的 YAML 配置和安全规则匹配
- **高性能**: CO-RE 技术确保跨内核版本兼容性

### 监控能力
- **进程监控**: execve, fork, clone, exit 等进程生命周期事件
- **文件系统**: openat, close, unlinkat, fchmodat 等文件操作
- **网络活动**: connect, bind, listen 等网络连接事件
- **权限变更**: setuid, setgid 等权限提升操作
- **内存操作**: mmap, mprotect 等内存管理事件
- **危险调用**: ptrace, kill 等潜在恶意操作

## 第一周开发成果

### ✅ 已完成功能

1. **环境搭建脚本** (`setup.sh`)
   - 自动安装 eBPF 开发环境
   - 配置 Go 语言和 Python 环境
   - 验证内核 BTF 支持

2. **eBPF 内核态程序** (`src/bpf/etracee.bpf.c`)
   - 使用 libbpf 和 CO-RE 技术
   - 捕获关键系统调用：execve, openat, connect, exit
   - Ring Buffer 高效数据传输
   - 进程过滤机制

3. **Go 用户态程序** (`src/go/main.go`)
   - 接收 eBPF 事件数据
   - JSON 格式输出
   - 实时事件处理
   - 优雅的信号处理

4. **构建系统** (`Makefile`)
   - 自动化编译流程
   - 环境检查功能
   - 测试和清理目标

5. **测试工具** (`test/bpftrace_test.bt`)
   - bpftrace 验证脚本
   - 系统调用监控测试

## 项目结构

```
eTracee/
├── setup.sh                 # 环境搭建脚本
├── Makefile                 # 构建系统
├── README.md               # 项目说明
├── src/
│   ├── bpf/                # eBPF 内核态程序
│   │   ├── etracee.bpf.c   # 主程序
│   │   ├── etracee.h       # 共享头文件
│   │   └── vmlinux.h       # 内核类型定义（自动生成）
│   ├── go/                 # Go 用户态程序
│   │   ├── main.go         # 主程序
│   │   ├── go.mod          # Go 模块定义
│   │   └── go.sum          # 依赖锁定文件
│   └── python/             # Python AI 模块（待开发）
├── build/                  # 构建输出目录
├── test/                   # 测试脚本
│   └── bpftrace_test.bt    # bpftrace 测试
├── config/                 # 配置文件目录
└── logs/                   # 日志目录
```

## 快速开始

### 1. 环境搭建

```bash
# 以 root 权限运行环境搭建脚本
sudo ./setup.sh

# 使环境变量生效
source /etc/profile
```

### 2. 编译项目

```bash
# 检查编译环境
make check-env

# 编译所有组件
make all
```

### 3. 运行程序

```bash
# 运行 eTracee（需要 root 权限）
sudo make run

# 或者手动运行
cd build
sudo ./etracee
```

### 4. 测试验证

```bash
# 运行 bpftrace 测试
sudo make test-bpftrace

# 或者手动运行测试脚本
sudo bpftrace test/bpftrace_test.bt
```

## 技术特性

### eBPF 程序特性
- **CO-RE 兼容性**: 一次编译，跨内核版本运行
- **高效数据传输**: Ring Buffer 机制，低延迟
- **精确事件捕获**: 捕获 PID、PPID、UID、GID、命令名等关键信息
- **智能过滤**: 支持进程级别的事件过滤

### 用户态程序特性
- **实时处理**: 异步事件处理，高吞吐量
- **JSON 输出**: 结构化数据格式，便于后续处理
- **时间戳转换**: 纳秒精度时间戳和人类可读时间
- **优雅退出**: 信号处理和资源清理

## 监控的系统调用

| 系统调用 | 描述 | 安全意义 |
|---------|------|----------|
| execve | 程序执行 | 检测恶意程序启动 |
| openat | 文件打开 | 监控敏感文件访问 |
| connect | 网络连接 | 发现异常网络行为 |
| exit | 进程退出 | 跟踪进程生命周期 |

## 输出格式示例

```json
{
  "timestamp": "1703123456789012345",
  "pid": 1234,
  "ppid": 1000,
  "uid": 0,
  "gid": 0,
  "syscall_id": 59,
  "type": "execve",
  "comm": "bash",
  "filename": "/bin/ls",
  "human_time": "2023-12-21 10:30:56.789"
}
```

## 开发计划

### 第二周计划
- [ ] 事件存储与索引设计（SQLite）
- [ ] 后端数据流与 WebSocket
- [ ] 关系图谱模型构建
- [ ] 前端可视化 PoC

### 第三周计划
- [ ] 可视化交互增强
- [ ] 轻量 AI 异常检测
- [ ] AI 与规则引擎联动

### 第四周计划
- [ ] 自动化报告生成
- [ ] 整合测试与优化
- [ ] 最终交付

## 故障排除

### 常见问题

1. **权限不足**
   ```bash
   # 确保以 root 权限运行
   sudo make run
   ```

2. **内核不支持 BTF**
   ```bash
   # 检查 BTF 支持
   ls /sys/kernel/btf/vmlinux
   ```

3. **依赖缺失**
   ```bash
   # 重新运行环境搭建
   sudo ./setup.sh
   ```

## 贡献指南

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 发起 Pull Request

## 许可证

本项目采用 GPL 许可证。

## 联系方式

如有问题或建议，请提交 Issue 或联系开发团队。