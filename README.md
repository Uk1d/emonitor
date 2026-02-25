# eTracee - 基于 eBPF 的 Linux 主机入侵检测系统

eTracee 是一个基于 eBPF 的轻量级安全监控与攻击链可视化系统，专为国产操作系统（如 openEuler）优化设计。核心功能包括：内核级事件采集、用户态规则匹配、Web 实时展示与攻击链图谱推演。

## 特性

- **eBPF 内核监控**：使用 CO-RE 技术实现跨内核版本兼容
- **实时威胁检测**：基于 Falco/Tracee 风格的规则引擎
- **攻击链可视化**：D3.js 力导向图展示攻击路径
- **轻量级设计**：SQLite 嵌入式存储，无外部依赖
- **MITRE ATT&CK 映射**：规则与 ATT&CK 战术/技术关联

## 快速开始

### 环境要求

- Linux 内核 5.8+（推荐 5.15+）
- BTF 支持
- Go 1.21+
- Clang/LLVM 11+

### 一键构建

```bash
# 检查环境并安装依赖
./setup.sh --all

# 构建项目
make all

# 启动（需要 root 权限）
sudo ./start.sh
```

### 手动构建

```bash
# 1. 安装系统依赖
# Ubuntu/Debian
sudo apt install -y build-essential clang llvm libbpf-dev linux-headers-$(uname -r)

# 2. 构建 eBPF
make bpf

# 3. 构建用户态程序
make build

# 4. 运行
sudo ./bin/etracee -config ./config/enhanced_security_config.yaml
```

## 项目结构

```
etracee/
├── src/
│   ├── bpf/                    # eBPF 内核程序
│   │   ├── etracee.h           # 事件结构定义
│   │   ├── etracee_main.c      # 主程序
│   │   ├── execve_trace.c      # 进程跟踪
│   │   ├── filesystem_trace.c  # 文件系统跟踪
│   │   ├── network_trace.c     # 网络跟踪
│   │   └── security_trace.c    # 安全事件跟踪
│   └── go/                     # Go 用户态程序
│       ├── main.go             # 入口
│       ├── rule_engine.go      # 规则引擎
│       ├── alert_api.go        # API 服务
│       └── internal/           # 内部模块
├── config/
│   ├── enhanced_security_config.yaml  # 安全规则配置
│   └── storage.yaml                   # 存储配置
├── docs/                       # 文档
├── scripts/                    # 辅助脚本
├── Makefile                    # 构建脚本
├── setup.sh                    # 环境设置脚本
└── start.sh                    # 快速启动脚本
```

## 安全规则

规则配置文件位于 `config/enhanced_security_config.yaml`，已包含以下检测类别：

| 类别 | 规则数 | 示例 |
|------|--------|------|
| 文件系统 | 10+ | 敏感文件读取、SSH 密钥访问、日志篡改 |
| 网络 | 7+ | 反弹 Shell、可疑端口连接、端口扫描 |
| 进程 | 12+ | 权限提升、Web Shell、可疑脚本执行 |
| 权限 | 5+ | PTRACE 注入、文件权限修改 |
| 内存 | 3+ | RWX 内存映射、无文件执行 |
| 系统 | 8+ | 内核模块加载、用户管理操作 |

### 规则示例

```yaml
- name: Reverse shell detected
  description: 检测反弹 Shell 行为
  conditions:
    - event_type: connect
    - comm: "regex:^(bash|sh|zsh|fish|dash|ksh)$"
  severity: critical
  tags:
    - mitre_execution
    - T1059.004
  enabled: true
```

## 使用指南

### 命令行参数

```bash
sudo ./bin/etracee [选项]

选项:
  -config string    规则配置文件路径 (默认 "config/enhanced_security_config.yaml")
  -dashboard        启用命令行 Dashboard
  -pid-min int      过滤 PID 最小值
  -pid-max int      过滤 PID 最大值
  -uid-min int      过滤 UID 最小值
  -uid-max int      过滤 UID 最大值
```

### 环境变量

```bash
# 服务配置
export ETRACEE_BIND_ADDR=0.0.0.0:8888
export ETRACEE_API_TOKEN=your-secret-token

# 事件开关
export ETRACEE_ENABLE_FILE=true
export ETRACEE_ENABLE_NETWORK=true

# Webhook 通知
export ETRACEE_WEBHOOK_URL=https://your-webhook/alerts
```

### Web 界面

启动后访问 `http://localhost:8888` 查看：
- 实时事件流
- 安全告警
- 攻击链图谱
- 统计仪表盘

## 测试

### 攻击模拟

```bash
# 运行所有测试
sudo ./scripts/attack_simulation.sh -a

# 运行特定类别测试
sudo ./scripts/attack_simulation.sh -f    # 文件系统
sudo ./scripts/attack_simulation.sh -n    # 网络
sudo ./scripts/attack_simulation.sh -p    # 进程
```

### 规则测试

```bash
# 运行规则测试
make test-rules

# 或使用二进制
./bin/etracee test -config ./config/enhanced_security_config.yaml -verbose
```

## 开发文档

详细的开发指南请参阅：

- [DEVELOPMENT.md](DEVELOPMENT.md) - 开发调试指南
- [USAGE.md](USAGE.md) - 使用说明

## Makefile 命令

```bash
make help          # 显示所有命令
make all           # 完整构建
make bpf           # 构建 eBPF
make build         # 构建用户态
make run           # 启动程序
make test          # 运行测试
make clean         # 清理构建
make install       # 安装到系统
```

## 参考资源

- [Falco 规则库](https://github.com/falcosecurity/rules)
- [Tracee 项目](https://github.com/aquasecurity/tracee)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [eBPF 文档](https://ebpf.io/)

## 许可证

Apache License 2.0
