# eTracee - 基于 eBPF 的 Linux 主机入侵检测系统

eTracee 是一个基于 eBPF 的轻量级安全监控与攻击链可视化系统，专为国产操作系统（如 openEuler）优化设计。核心功能包括：内核级事件采集、用户态规则匹配、Web 实时展示与攻击链图谱推演。

![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Platform](https://img.shields.io/badge/platform-Linux%205.8+-orange)

## 特性

- **eBPF 内核监控**：使用 CO-RE 技术实现跨内核版本兼容，零侵入式监控
- **实时威胁检测**：基于 Falco/Tracee 风格的规则引擎，支持 MITRE ATT&CK 映射
- **AI 异常检测**：使用 Python 实现的统计方法检测异常行为（Beta）
- **AI 应急响应助手**：支持多种 AI 服务商，提供实时安全分析和排查建议
- **多格式报告导出**：支持 JSON/CSV/HTML 三种报告格式
- **攻击链可视化**：力导向图展示攻击路径，帮助理解攻击者行为
- **分离架构设计**：Web 服务可独立运行，无需 root 权限
- **MySQL 分库存储**：监控数据与用户认证分离存储，提高安全性

## 架构设计

eTracee 支持多种运行模式：

### AI 增强模式（推荐）

监控程序以 root 权限运行 eBPF 监控，Web 服务提供 API，独立的 Python 服务提供 AI 检测和报告导出功能。

```
┌─────────────────────────────────────────────────────────────────┐
│                     用户浏览器 (http://localhost:8888)            │
└─────────────────────────────────────┬───────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    监控程序 (root 权限)                           │
│  ┌─────────────┐    ┌────────────────┐    ┌──────────────────┐  │
│  │  eBPF 监控  │───>│  规则引擎      │───>│ WebSocket:8889   │  │
│  │ (内核态)    │    │  (规则匹配)    │    │ (数据推送)       │  │
│  └─────────────┘    └────────────────┘    └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                      │
                                      │ WebSocket
                                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Web 服务 (普通用户权限)                        │
│  ┌─────────────┐    ┌────────────────┐    ┌──────────────────┐  │
│  │ 认证中间件  │    │  HTTP :8888    │    │  MySQL 存储      │  │
│  │ (JWT 认证)  │    │ (静态资源/API) │    │ (事件/告警/用户) │  │
│  └─────────────┘    └────────────────┘    └──────────────────┘  │
└─────────────────────────────────────┬───────────────────────────┘
                                      │
                                      │ HTTP
                                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Python AI 服务 (端口 9900)                     │
│  ┌─────────────────────┐    ┌────────────────────────────────┐  │
│  │ AI 异常检测器       │    │ 报告生成器                     │  │
│  │ (进程/网络/文件)    │    │ (JSON/CSV/HTML)               │  │
│  └─────────────────────┘    └────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 分离模式

监控程序以 root 权限运行，Web 服务以普通用户权限运行，通过 WebSocket 通信。

```
┌─────────────────────────────────────────┐
│      监控程序 (root 权限)                │
│  ┌─────────────┐    ┌────────────────┐  │
│  │  eBPF 监控  │───>│ WebSocket:8889 │  │
│  └─────────────┘    └────────────────┘  │
└─────────────────────────┬───────────────┘
                          │ WebSocket
                          ▼
┌─────────────────────────────────────────┐
│      Web 服务 (普通用户权限)             │
│  ┌─────────────┐    ┌────────────────┐  │
│  │ 认证中间件  │    │  HTTP :8888    │  │
│  │ (MySQL)     │    │  静态资源/API  │  │
│  └─────────────┘    └────────────────┘  │
└─────────────────────────────────────────┘
```

### 集成模式（传统）

监控程序和 Web 服务在同一个进程中运行，需要 root 权限。

```
┌─────────────────────────────────────────┐
│         eTracee 主程序 (root)            │
│  ┌─────────────┐    ┌────────────────┐  │
│  │  eBPF 监控  │───>│  Web 服务:8888 │  │
│  └─────────────┘    └────────────────┘  │
└─────────────────────────────────────────┘
```

## 数据流架构

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   eBPF 程序  │────>│  规则引擎    │────>│  告警管理器  │
│  (内核采集)  │     │  (规则匹配)  │     │  (告警处理)  │
└──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │
       │                    ▼                    ▼
       │            ┌──────────────┐     ┌──────────────┐
       │            │  攻击链检测  │     │  通知渠道    │
       │            │  (上下文关联)│     │  (Webhook等) │
       │            └──────────────┘     └──────────────┘
       │                    │
       ▼                    ▼
┌──────────────┐     ┌──────────────┐
│  Ring Buffer │────>│  WebSocket   │
│  (事件传输)  │     │  (实时推送)  │
└──────────────┘     └──────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │  Web 前端    │
                    │  (可视化)    │
                    └──────────────┘
```

## 数据库设计

| 数据库 | 用途 | 存储内容 |
|--------|------|----------|
| `etracee_events` | 监控程序数据库 | 事件、告警、攻击链 |
| `etracee_web` | Web 服务数据库 | 用户、会话、权限 |

## 快速开始

### 环境要求

- Linux 内核 5.8+（推荐 5.15+，openEuler 22.03+ 测试通过）
- BTF 支持（`/sys/kernel/btf/vmlinux`）
- Go 1.21+
- Clang/LLVM 11+
- MySQL 8.0+
- Python 3.11+（可选，用于 AI 检测和报告导出）

### 配置文件

eTracee 使用 YAML 配置文件管理所有设置：

#### 数据库配置 (`config/database.yaml`)

```yaml
# 监控程序数据库 - 存储事件和告警数据
monitor_database:
  host: localhost
  port: 3306
  user: etracee_monitor
  password: "your_password"
  database: etracee_events

# Web 服务数据库 - 存储用户和会话数据
web_database:
  host: localhost
  port: 3306
  user: etracee_web
  password: "your_password"
  database: etracee_web

# 管理员账户
admin:
  username: admin
  password: your_admin_password

# JWT 配置
jwt:
  secret: your_jwt_secret_key
  expiry_hours: 24
```

#### 安全规则配置 (`config/enhanced_security_config.yaml`)

```yaml
global:
  enable_file_events: true
  enable_network_events: true
  enable_process_events: true
  enable_permission_events: true
  enable_memory_events: true
  min_uid_filter: 0
  max_uid_filter: 65535
  max_events_per_second: 10000
  log_level: info

detection_rules:
  file:
    - name: Read sensitive file untrusted
      description: 检测对敏感文件的访问
      conditions:
        - event_type: file_open
        - filename: "regex:/etc/(passwd|shadow)"
        - uid: ">1000"
      severity: medium
      tags:
        - T1005
      enabled: true

  network:
    - name: Reverse shell detected
      description: 检测反弹 Shell 行为
      conditions:
        - event_type: connect
        - comm: "regex:^(bash|sh|zsh|fish)$"
      severity: critical
      tags:
        - T1059.004
      enabled: true
```

> **安全提示**：配置文件包含敏感信息，请确保文件权限为 `600`。生产环境建议使用环境变量覆盖敏感配置。

### 一键构建

```bash
# 检查环境并安装依赖
./setup.sh --all

# 构建所有组件
make build-all
```

### 启动方式

#### 方式一：AI 增强模式（推荐）

包含完整的 AI 检测和报告导出功能：

```bash
# 终端 1: 启动 Python AI 服务
cd src/python && ./start.sh

# 终端 2: 启动监控程序（需要 root）
sudo ./bin/etracee -monitor-only

# 终端 3: 启动 Web 服务
./bin/webserver
```

#### 方式二：分离模式

监控程序和 Web 服务分离运行：

```bash
# 使用启动脚本
./start.sh --split

# 或分别启动
# 终端 1: 启动监控程序（需要 root）
sudo ./bin/etracee -monitor-only

# 终端 2: 启动 Web 服务（无需 root）
./bin/webserver
```

#### 方式三：集成模式（简单）

监控程序和 Web 服务在同一个进程中运行：

```bash
# 启动（需要 root 权限）
sudo ./start.sh

# 或直接运行
sudo ./bin/etracee
```

#### 使用环境变量覆盖配置

敏感配置可通过环境变量覆盖：

```bash
# 覆盖数据库密码
export MYSQL_EVENTS_PASSWORD=secure_password
export MYSQL_WEB_PASSWORD=secure_password

# 覆盖管理员密码
export ADMIN_PASSWORD=secure_admin_password

# 覆盖 JWT 密钥
export JWT_SECRET=your_jwt_secret

# 启动
sudo ./bin/etracee
```

## Web 界面功能

启动后访问 `http://localhost:8888` 查看：

### 主要功能模块

| 模块 | 功能 |
|------|------|
| **告警列表** | 实时显示安全告警，支持按严重级别过滤 |
| **事件流** | 实时显示系统事件，支持搜索和过滤 |
| **攻击链图谱** | 可视化展示攻击路径和关联关系 |
| **AI 检测** | AI 异常检测结果（Beta） |
| **报告导出** | 生成 JSON/CSV/HTML 格式报告 |
| **AI 对话** | 应急响应 AI 助手，支持实时分析 |

### AI 对话功能

AI 对话功能支持多种 AI 服务商：

- OpenAI (GPT-3.5/4/4o)
- Anthropic (Claude 3/3.5)
- Moonshot (Kimi)
- Google (Gemini)
- DeepSeek
- 智谱 AI (GLM-4)
- 阿里云 (通义千问)
- 百度 (文心一言)
- 硅基流动 (SiliconFlow)
- 本地模型 (Ollama)

**使用方式**：
1. 点击右下角 AI 助手按钮
2. 在配置中设置 API 地址和密钥
3. 选择 AI 模型
4. 开始对话

AI 助手会自动读取当前告警和事件数据，提供实时安全分析和排查建议。

### 连接状态说明

Web 界面顶部状态指示器会动态显示监控程序状态：

| 状态 | 含义 |
|------|------|
| 已连接(等待监控) | Web 服务已连接，但监控程序未运行或未发送数据 |
| 监控运行中 | 监控程序正在运行并实时推送数据 |
| 监控未运行 | 超过 10 秒未收到监控数据 |
| 连接断开 | WebSocket 连接已断开 |

### 告警状态管理

告警支持以下状态：
- **新建 (new)**：新产生的告警
- **已确认 (acknowledged)**：已确认的告警
- **处理中 (in_progress)**：正在处理的告警
- **已解决 (resolved)**：已处理的告警
- **误报 (false_positive)**：标记为误报的告警

## 项目结构

```
etracee/
├── bin/                        # 构建输出
│   ├── etracee                 # 监控程序主程序
│   └── webserver               # 独立 Web 服务
├── build/                      # 构建中间产物
│   └── etracee.bpf.o           # eBPF 对象文件
├── config/
│   ├── database.yaml           # 数据库配置（包含敏感信息）
│   └── enhanced_security_config.yaml  # 安全规则配置
├── data/                       # 运行数据目录
├── docs/                       # 文档
│   ├── 文档汇总.md             # 文档索引
│   ├── database_config.md      # 数据库配置说明
│   └── auth_config.md          # 认证配置说明
├── scripts/                    # 辅助脚本
│   └── attack_simulation.sh    # 攻击模拟脚本
├── src/
│   ├── bpf/                    # eBPF 内核程序
│   │   ├── etracee.h           # 事件结构定义
│   │   ├── etracee_main.c      # eBPF 主程序
│   │   ├── execve_trace.c      # 进程跟踪
│   │   ├── filesystem_trace.c  # 文件系统跟踪
│   │   ├── network_trace.c     # 网络跟踪
│   │   └── security_trace.c    # 安全事件跟踪
│   ├── go/                     # Go 用户态程序
│   │   ├── main.go             # 主入口
│   │   ├── rule_engine.go      # 规则引擎
│   │   ├── alert_manager.go    # 告警管理器
│   │   ├── alert_api.go        # API 服务
│   │   ├── event_context.go    # 事件上下文
│   │   ├── storage_mysql.go    # MySQL 存储
│   │   ├── cmd/webserver/      # 独立 Web 服务
│   │   │   └── main.go
│   │   └── internal/
│   │       ├── auth/           # 认证服务
│   │       ├── dbconfig/       # 数据库配置
│   │       └── web/static/     # Web 前端资源
│   │           └── index.html  # 单页应用
│   └── python/                 # Python AI 服务
│       ├── service.py          # Flask 服务
│       ├── ai_detector/        # AI 异常检测
│       ├── report_generator/   # 报告生成器
│       ├── requirements.txt    # Python 依赖
│       └── start.sh            # 启动脚本
├── test_data/                  # 测试数据
├── Makefile                    # 构建脚本
├── setup.sh                    # 环境设置脚本
├── start.sh                    # 快速启动脚本
├── README.md                   # 项目说明
├── DEVELOPMENT.md              # 开发指南
└── USAGE.md                    # 使用说明
```

## 安全规则

规则配置文件位于 `config/enhanced_security_config.yaml`，支持以下检测类别：

| 类别 | 检测内容 | 示例规则 |
|------|----------|----------|
| 文件系统 | 敏感文件访问、SSH 密钥、日志篡改 | `/etc/passwd` 读取、SSH 私钥访问 |
| 网络 | 反弹 Shell、可疑端口、端口扫描 | bash 连接外部、非常规端口连接 |
| 进程 | 权限提升、Web Shell、可疑脚本 | Web 服务器启动 Shell、SUID 提权 |
| 权限 | PTRACE 注入、文件权限修改 | ptrace 附加、chmod 777 |
| 内存 | RWX 内存映射、无文件执行 | 可执行内存分配、内存注入 |
| 系统 | 内核模块加载、用户管理操作 | insmod、useradd |

### 规则示例

```yaml
- name: Suspicious shell execution
  description: 检测可疑的 Shell 执行
  conditions:
    - event_type: execve
    - comm: "regex:^(bash|sh|zsh|dash|ksh|fish)$"
    - cmdline: "regex:(curl|wget|nc|ncat|netcat)"
  severity: high
  tags:
    - T1059.004
    - command_execution
  enabled: true
```

## 命令行参数

```bash
sudo ./bin/etracee [选项]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-config` | `config/enhanced_security_config.yaml` | 安全规则配置文件路径 |
| `-dashboard` | `false` | 启用命令行 Dashboard |
| `-monitor-only` | `false` | 仅启动监控程序（分离模式） |
| `-web-port` | `8888` | Web 服务端口 |
| `-ws-port` | `8889` | WebSocket 服务端口 |
| `-pid-min` / `-pid-max` | `0` | PID 过滤范围 |
| `-uid-min` / `-uid-max` | `0` | UID 过滤范围 |

## Makefile 命令

```bash
# 查看帮助
make help

# 构建
make all           # 完整构建（检查环境 + 构建 eBPF + 构建 Go）
make build         # 仅构建 Go 用户态程序
make build-web     # 构建独立 Web 服务
make build-all     # 构建所有组件
make bpf           # 仅构建 eBPF 程序

# 运行
make run           # 启动 eTracee（集成模式，需要 root）
make run-monitor   # 仅启动监控程序（需要 root）
make run-web       # 仅启动 Web 服务（无需 root）
make run-split     # 同时启动监控程序和 Web 服务

# 测试
make test          # 运行单元测试
make test-rules    # 运行规则测试

# 清理
make clean         # 清理构建产物
make clean-all     # 清理所有生成文件

# 安装
make install       # 安装到系统
make uninstall     # 从系统卸载
```

## 测试

### 攻击模拟

```bash
# 运行所有攻击模拟测试
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
- [docs/database_config.md](docs/database_config.md) - 数据库配置
- [docs/auth_config.md](docs/auth_config.md) - 认证配置

## 参考资源

- [Falco 规则库](https://github.com/falcosecurity/rules)
- [Tracee 项目](https://github.com/aquasecurity/tracee)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [eBPF 文档](https://ebpf.io/)
- [Cilium eBPF](https://cilium.io/)

## 许可证

Apache License 2.0

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

- GitHub: [https://github.com/Uk1d/emonitor](https://github.com/Uk1d/emonitor)
