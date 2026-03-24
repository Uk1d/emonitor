# eTracee 开发指南

本文档面向开发者，介绍如何构建、调试和贡献代码。

## 开发环境要求

### 系统要求

- Linux 内核 5.8+（推荐 5.15+，openEuler 22.03+ 测试通过）
- BTF 支持（检查 `/sys/kernel/btf/vmlinux` 是否存在）
- Go 1.21+
- Clang/LLVM 11+
- Python 3.11+（可选，用于 AI 服务开发）
- MySQL 8.0+

### 系统依赖安装

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential clang llvm gcc-multilib libbpf-dev linux-headers-$(uname -r)

# CentOS/RHEL/openEuler
sudo yum groupinstall -y 'Development Tools'
sudo yum install -y clang llvm libbpf-devel kernel-devel-$(uname -r)

# Fedora
sudo dnf groupinstall -y 'Development Tools'
sudo dnf install -y clang llvm libbpf-devel kernel-devel-$(uname -r)
```

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
├── src/
│   ├── bpf/                    # eBPF 内核程序
│   │   ├── etracee.h           # 事件结构定义
│   │   ├── etracee_main.c      # 主程序
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
│       ├── service.py          # Flask 服务入口
│       ├── ai_detector/        # AI 异常检测模块
│       │   └── detector.py
│       ├── report_generator/   # 报告生成器模块
│       ├── requirements.txt    # Python 依赖
│       └── start.sh            # 启动脚本
├── docs/                       # 文档
├── scripts/                    # 辅助脚本
├── Makefile                    # 构建脚本
├── setup.sh                    # 环境设置脚本
└── start.sh                    # 快速启动脚本
```

## 构建指南

### 快速构建

```bash
# 一键构建（检查环境 + 构建 eBPF + 构建 Go）
make all

# 构建所有组件
make build-all
```

### 分步构建

```bash
# 1. 安装 Go 依赖
make deps

# 2. 检查构建环境
make check-env

# 3. 构建 eBPF 程序
make bpf

# 4. 构建监控程序
make build

# 5. 构建独立 Web 服务
make build-web
```

### Python 服务构建

```bash
# 安装 Python 依赖
cd src/python
pip install -r requirements.txt

# 或使用虚拟环境
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 调试构建

```bash
# 构建调试版本
make build-debug

# 开发模式（清理 + 完整构建）
make dev
```

## 运行指南

### AI 增强模式（推荐开发模式）

包含完整的 AI 检测和报告导出功能：

```bash
# 终端 1: 启动 Python AI 服务
cd src/python && ./start.sh

# 终端 2: 启动监控程序（需要 root）
sudo ./bin/etracee -monitor-only

# 终端 3: 启动 Web 服务
./bin/webserver
```

### 分离模式

```bash
# 终端 1: 启动监控程序（需要 root）
sudo ./bin/etracee -monitor-only

# 终端 2: 启动 Web 服务（无需 root）
./bin/webserver
```

### 集成模式

```bash
# 需要 root 权限
sudo ./bin/etracee -config ./config/enhanced_security_config.yaml

# 启用 Dashboard
sudo ./bin/etracee -config ./config/enhanced_security_config.yaml -dashboard
```

## 数据库配置

### 创建数据库

```bash
mysql -u root -p

CREATE DATABASE etracee_events CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE etracee_web CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

# 创建专用用户（推荐）
CREATE USER 'etracee_monitor'@'localhost' IDENTIFIED BY 'your_password';
CREATE USER 'etracee_web'@'localhost' IDENTIFIED BY 'your_password';

GRANT ALL PRIVILEGES ON etracee_events.* TO 'etracee_monitor'@'localhost';
GRANT ALL PRIVILEGES ON etracee_web.* TO 'etracee_web'@'localhost';

FLUSH PRIVILEGES;
```

### 配置文件

编辑 `config/database.yaml`：

```yaml
monitor_database:
  host: localhost
  port: 3306
  user: etracee_monitor
  password: your_password
  database: etracee_events

web_database:
  host: localhost
  port: 3306
  user: etracee_web
  password: your_password
  database: etracee_web

admin:
  username: admin
  password: admin123

jwt:
  secret: your_jwt_secret_key
  expiry_hours: 24
```

## 测试

### 单元测试

```bash
make test
```

### 规则测试

```bash
make test-rules
```

### 攻击模拟

```bash
sudo ./scripts/attack_simulation.sh -a

# 运行特定类别测试
sudo ./scripts/attack_simulation.sh -f    # 文件系统
sudo ./scripts/attack_simulation.sh -n    # 网络
sudo ./scripts/attack_simulation.sh -p    # 进程
```

## 代码规范

### Go 代码

```bash
# 格式化代码
make fmt

# 代码检查
make lint
```

### eBPF 代码

遵循 Linux 内核编码风格。

### Python 代码

```bash
# 使用 black 格式化
pip install black
black src/python/

# 使用 flake8 检查
pip install flake8
flake8 src/python/
```

## 调试技巧

### 查看 eBPF 日志

```bash
# 查看 trace 消息
cat /sys/kernel/debug/tracing/trace_pipe
```

### 性能分析

```bash
# 查看 eBPF 程序状态
bpftool prog list

# 查看 map 状态
bpftool map list
```

### Go 调试

```bash
# 使用 delve
dlve exec ./bin/etracee -- -config ./config/enhanced_security_config.yaml
```

### Python 调试

```bash
# 使用 pdb
python -m pdb src/python/service.py

# 使用 VSCode 调试配置
# 添加 .vscode/launch.json
```

## 架构说明

### 数据流

1. **eBPF 程序**：在内核中捕获系统调用事件
2. **Ring Buffer**：高效的内核-用户态数据传输
3. **Go 用户态程序**：
   - 解析原始事件
   - 应用安全规则
   - 检测攻击链
   - 存储到 MySQL
   - 推送到 WebSocket
4. **Web 前端**：实时展示告警、事件、攻击链
5. **Python AI 服务**：异常检测和报告生成

### WebSocket 通信

- 监控程序 (端口 8889)：推送事件和告警到独立 Web 服务
- Web 服务 (端口 8888)：接收数据并转发到浏览器

### 认证流程

1. 用户登录获取 JWT Token
2. Token 用于后续 API 请求
3. Token 过期后需要重新登录

## 常见问题

1. **BTF 不支持**: 升级内核到 5.15+ 或手动生成 vmlinux.h
2. **权限不足**: 监控程序需要 root 权限
3. **数据库连接失败**: 检查 MySQL 服务和配置
4. **WebSocket 连接失败**: 检查端口是否被占用
5. **Python 服务启动失败**: 检查依赖是否安装完整

## 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/your-feature`)
3. 提交代码 (`git commit -m 'Add your feature'`)
4. 推送到分支 (`git push origin feature/your-feature`)
5. 创建 Pull Request

### 提交规范

- `feat`: 新功能
- `fix`: 修复 bug
- `docs`: 文档更新
- `style`: 代码格式调整
- `refactor`: 重构
- `test`: 测试相关
- `chore`: 构建/工具相关

## 相关资源

- [eBPF 文档](https://ebpf.io/)
- [Cilium eBPF](https://cilium.io/)
- [Falco 规则库](https://github.com/falcosecurity/rules)
- [Tracee 项目](https://github.com/aquasecurity/tracee)
- [MITRE ATT&CK](https://attack.mitre.org/)
