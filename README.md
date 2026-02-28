# eTracee - 基于 eBPF 的 Linux 主机入侵检测系统

eTracee 是一个基于 eBPF 的轻量级安全监控与攻击链可视化系统，专为国产操作系统（如 openEuler）优化设计。核心功能包括：内核级事件采集、用户态规则匹配、Web 实时展示与攻击链图谱推演。

## 特性

- **eBPF 内核监控**：使用 CO-RE 技术实现跨内核版本兼容
- **实时威胁检测**：基于 Falco/Tracee 风格的规则引擎
- **攻击链可视化**：D3.js 力导向图展示攻击路径
- **分离架构设计**：Web 服务可独立运行，无需 root 权限
- **MySQL 分库存储**：监控数据与用户认证分离存储
- **MITRE ATT&CK 映射**：规则与 ATT&CK 战术/技术关联

## 架构设计

eTracee 支持两种运行模式：

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

### 分离模式（推荐）

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

## 数据库设计

| 数据库 | 用途 | 存储内容 |
|--------|------|----------|
| `etracee_events` | 监控程序数据库 | 事件、告警 |
| `etracee_web` | Web 服务数据库 | 用户、会话 |

## 快速开始

### 环境要求

- Linux 内核 5.8+（推荐 5.15+）
- BTF 支持
- Go 1.21+
- Clang/LLVM 11+
- MySQL 8.0+（用于认证和数据存储）

### 配置文件

eTracee 使用 YAML 配置文件管理所有设置，无需记忆复杂的环境变量：

#### 数据库配置 (`config/database.yaml`)

```yaml
# 监控程序数据库 - 存储事件和告警数据
monitor_database:
  host: localhost
  port: 3306
  user: root
  password: "your_password"
  database: etracee_events

# Web 服务数据库 - 存储用户和会话数据
web_database:
  host: localhost
  port: 3306
  user: root
  password: "your_password"
  database: etracee_web

# 管理员账户
admin:
  username: admin
  password: admin123
```

#### 安全规则配置 (`config/enhanced_security_config.yaml`)

```yaml
global:
  enable_file_events: true
  enable_network_events: true
  enable_process_events: true
  min_uid_filter: 0
  max_uid_filter: 65535
  log_level: info

detection_rules:
  file:
    - name: Read sensitive file untrusted
      conditions:
        - event_type: file_open
        - filename: "regex:/etc/(passwd|shadow)"
      severity: medium
      enabled: true
```

> **安全提示**：配置文件包含敏感信息（数据库密码、管理员密码），请确保文件权限为 `600`，避免泄露。生产环境建议使用环境变量覆盖敏感配置。

### 一键构建

```bash
# 检查环境并安装依赖
./setup.sh --all

# 构建所有组件
make build-all
```

### 启动方式

#### 方式一：集成模式（简单）

监控程序和 Web 服务在同一个进程中运行，需要 root 权限：

```bash
# 启动（使用默认配置文件）
sudo ./start.sh

# 或直接运行二进制
sudo ./bin/etracee
```

#### 方式二：分离模式（推荐）

监控程序以 root 权限运行，Web 服务以普通用户权限运行：

```bash
# 使用启动脚本
./start.sh --split

# 或分别启动
# 终端 1: 启动监控程序（需要 root）
sudo ./bin/etracee -monitor-only

# 终端 2: 启动 Web 服务（无需 root）
./bin/webserver
```

#### 方式三：使用环境变量覆盖配置

敏感配置可通过环境变量覆盖，避免硬编码在配置文件中：

```bash
# 覆盖数据库密码
export MYSQL_EVENTS_PASSWORD=secure_password
export MYSQL_WEB_PASSWORD=secure_password

# 覆盖管理员密码
export ADMIN_PASSWORD=secure_admin_password

# 启动
sudo ./bin/etracee
```

### 环境变量参考

完整的环境变量列表请参阅 [USAGE.md](USAGE.md)，主要配置项：

| 类别 | 环境变量 | 说明 |
|------|----------|------|
| 监控数据库 | `MYSQL_EVENTS_HOST` | 监控数据库主机 |
| 监控数据库 | `MYSQL_EVENTS_PASSWORD` | 监控数据库密码 |
| Web 数据库 | `MYSQL_WEB_HOST` | Web 数据库主机 |
| Web 数据库 | `MYSQL_WEB_PASSWORD` | Web 数据库密码 |
| 管理员 | `ADMIN_USERNAME` | 管理员用户名 |
| 管理员 | `ADMIN_PASSWORD` | 管理员密码 |
| 服务 | `ETRACEE_BIND_ADDR` | 绑定地址 |
| Webhook | `ETRACEE_WEBHOOK_URL` | 告警推送地址 |

## 项目结构

```
etracee/
├── bin/                        # 构建输出
│   ├── etracee                 # 监控程序主程序
│   └── webserver               # 独立 Web 服务
├── src/
│   ├── bpf/                    # eBPF 内核程序
│   │   ├── etracee.h           # 事件结构定义
│   │   ├── etracee_main.c      # 主程序
│   │   ├── execve_trace.c      # 进程跟踪
│   │   ├── filesystem_trace.c  # 文件系统跟踪
│   │   ├── network_trace.c     # 网络跟踪
│   │   └── security_trace.c    # 安全事件跟踪
│   └── go/                     # Go 用户态程序
│       ├── main.go             # 主入口
│       ├── cmd/webserver/      # 独立 Web 服务
│       ├── internal/           # 内部模块
│       │   ├── auth/           # 认证服务
│       │   ├── dbconfig/       # 数据库配置
│       │   ├── web/            # Web 静态资源
│       │   ├── api/            # API 相关
│       │   └── engine/         # 规则引擎
│       └── tools/              # 工具程序
├── config/
│   ├── database.yaml           # 数据库配置
│   ├── enhanced_security_config.yaml  # 安全规则配置
│   └── archive/                # 归档配置
├── docs/                       # 文档
│   ├── database_config.md      # 数据库配置说明
│   ├── auth_config.md          # 认证配置说明
│   └── design/                 # 设计文档
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
| `-ws-port` | `8889` | WebSocket 服务端口（供独立 Web 服务连接） |
| `-pid-min` / `-pid-max` | `0` | PID 过滤范围 |
| `-uid-min` / `-uid-max` | `0` | UID 过滤范围 |

> **提示**：大多数配置已内置在配置文件中，命令行参数主要用于特殊情况覆盖。

## Web 界面

启动后访问 `http://localhost:8888` 查看：
- 登录页面（需先配置 MySQL）
- 实时事件流
- 安全告警
- 攻击链图谱
- 统计仪表盘

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

刷新页面后，所有活跃状态的告警都会正确显示，不会丢失状态信息。

## Makefile 命令

```bash
make help          # 显示所有命令

# 构建
make all           # 完整构建
make build         # 构建监控程序
make build-web     # 构建独立 Web 服务
make build-all     # 构建所有组件
make bpf           # 仅构建 eBPF

# 运行（集成模式）
make run           # 启动监控程序
make run-dashboard # 启动并显示 Dashboard

# 运行（分离模式 - 推荐）
make run-monitor   # 仅启动监控程序（需要 root）
make run-web       # 仅启动 Web 服务（无需 root）
make run-split     # 同时启动监控程序和 Web 服务

# 其他
make test          # 运行测试
make clean         # 清理构建
make install       # 安装到系统
```

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
- [docs/database_config.md](docs/database_config.md) - 数据库配置
- [docs/auth_config.md](docs/auth_config.md) - 认证配置

## 参考资源

- [Falco 规则库](https://github.com/falcosecurity/rules)
- [Tracee 项目](https://github.com/aquasecurity/tracee)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [eBPF 文档](https://ebpf.io/)

## 许可证

Apache License 2.0
