# eTracee 开发调试指南

本文档提供 eTracee 项目的本地开发、调试和测试指南。

## 目录

- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [构建项目](#构建项目)
- [运行与调试](#运行与调试)
- [规则配置](#规则配置)
- [测试](#测试)
- [常见问题](#常见问题)

## 环境要求

### 系统要求

- Linux 内核 5.8+（推荐 5.15+）
- 支持 BTF（BPF Type Format）
- root 权限（运行 eBPF 程序需要）

### 检查 BTF 支持

```bash
# 检查内核是否支持 BTF
ls -la /sys/kernel/btf/vmlinux

# 如果文件存在，表示内核支持 BTF
```

### 必需软件

| 软件 | 最低版本 | 安装命令（Ubuntu/Debian） |
|------|----------|---------------------------|
| Go | 1.21+ | `sudo apt install golang-go` |
| Clang/LLVM | 11+ | `sudo apt install clang llvm` |
| libbpf | 0.8+ | `sudo apt install libbpf-dev` |
| Linux Headers | 当前内核 | `sudo apt install linux-headers-$(uname -r)` |
| bpftool | 最新 | `sudo apt install bpftool` |

### 安装系统依赖

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y build-essential clang llvm gcc-multilib \
    libbpf-dev linux-headers-$(uname -r) golang-go
```

**CentOS/RHEL/openEuler:**
```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y clang llvm libbpf-devel \
    kernel-devel-$(uname -r) golang
```

**Fedora:**
```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y clang llvm libbpf-devel \
    kernel-devel-$(uname -r) golang
```

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/your-org/etracee.git
cd etracee
```

### 2. 检查环境

```bash
make check-env
```

### 3. 构建项目

```bash
# 完整构建（包括 eBPF 和用户态程序）
make all

# 或者分步构建
make bpf     # 仅构建 eBPF
make build   # 仅构建用户态程序
```

### 4. 运行

```bash
# 需要 root 权限
sudo make run
```

## 构建项目

### Makefile 常用命令

```bash
# 显示所有可用命令
make help

# 完整构建
make all

# 仅构建 eBPF 程序
make bpf

# 仅构建 Go 用户态程序
make build

# 构建调试版本（包含调试信息）
make build-debug

# 构建工具程序
make build-tools

# 清理构建产物
make clean

# 清理所有生成文件
make clean-all
```

### 手动构建步骤

如果需要手动构建，可以按以下步骤操作：

```bash
# 1. 生成 vmlinux.h（需要 BTF 支持）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h

# 2. 编译 eBPF 程序
mkdir -p build
clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I./src/bpf \
    -I/usr/include \
    -I/usr/include/bpf \
    -c ./src/bpf/etracee_main.c \
    -o ./build/etracee.bpf.o

# 3. 编译 Go 用户态程序
cd src/go
go build -o ../../bin/etracee .
```

### 交叉编译

```bash
# 编译 ARM64 版本
GOARCH=arm64 make build

# 编译 AMD64 版本
GOARCH=amd64 make build
```

## 运行与调试

### 基本运行

```bash
# 使用默认配置运行
sudo ./bin/etracee

# 指定配置文件
sudo ./bin/etracee -config ./config/enhanced_security_config.yaml

# 启用命令行 Dashboard
sudo ./bin/etracee -dashboard
```

### 运行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-config` | 规则配置文件路径 | `config/enhanced_security_config.yaml` |
| `-dashboard` | 启用命令行 Dashboard | `false` |
| `-pid-min` | 过滤 PID 最小值 | `0`（不过滤） |
| `-pid-max` | 过滤 PID 最大值 | `0`（不过滤） |
| `-uid-min` | 过滤 UID 最小值 | `0`（不过滤） |
| `-uid-max` | 过滤 UID 最大值 | `0`（不过滤） |

### 环境变量

```bash
# 设置绑定地址
export ETRACEE_BIND_ADDR=0.0.0.0:8888

# 设置 API Token（启用鉴权）
export ETRACEE_API_TOKEN=your-secret-token

# 设置 CORS 白名单
export ETRACEE_ALLOWED_ORIGINS="https://example.com,https://localhost"

# 设置 WebSocket 队列大小
export ETRACEE_WS_QUEUE_SIZE=2048

# 事件类别开关
export ETRACEE_ENABLE_FILE=true
export ETRACEE_ENABLE_NETWORK=true
export ETRACEE_ENABLE_PROCESS=true
export ETRACEE_ENABLE_PERMISSION=true
export ETRACEE_ENABLE_MEMORY=true

# Webhook 通知
export ETRACEE_WEBHOOK_URL=https://your-webhook.example.com/alerts
export ETRACEE_WEBHOOK_TIMEOUT=10s
export ETRACEE_WEBHOOK_SECRET=your-webhook-secret
```

### 调试模式

```bash
# 构建调试版本
make build-debug

# 设置日志级别
export ETRACEE_LOG_LEVEL=debug

# 运行
sudo ./bin/etracee -dashboard
```

### Web 界面

启动后，访问 `http://localhost:8888` 查看 Web 界面。

```bash
# 如果需要远程访问，设置绑定地址
export ETRACEE_BIND_ADDR=0.0.0.0:8888
sudo ./bin/etracee
```

## 规则配置

### 规则文件结构

规则配置文件使用 YAML 格式，主要包含以下部分：

```yaml
# 全局配置
global:
  enable_file_events: true
  enable_network_events: true
  # ...

# 检测规则
detection_rules:
  file:
    - name: Read sensitive file untrusted
      description: 非特权用户尝试读取敏感文件
      conditions:
        - event_type: file_open
        - filename: "regex:/etc/(passwd|shadow)"
        - uid: ">=1000"
      severity: medium
      enabled: true
      # ...

  network:
    # 网络相关规则...

  process:
    # 进程相关规则...

# 白名单配置
whitelist:
  processes:
    - systemd
    - sshd
  # ...

# 响应动作
response_actions:
  critical_severity:
    - log
    - alert
  # ...
```

### 规则字段说明

| 字段 | 说明 | 必填 |
|------|------|------|
| `name` | 规则名称 | 是 |
| `description` | 规则描述 | 否 |
| `conditions` | 触发条件列表 | 是 |
| `severity` | 严重级别（critical/high/medium/low） | 是 |
| `logic_operator` | 条件逻辑（AND/OR/NOT） | 否，默认 AND |
| `tags` | 标签列表 | 否 |
| `enabled` | 是否启用 | 否，默认 true |
| `throttle_seconds` | 告警节流时间（秒） | 否，默认 0 |
| `actions` | 触发后的动作 | 否 |
| `category` | 规则类别 | 否 |

### 条件操作符

| 操作符 | 说明 | 示例 |
|--------|------|------|
| 精确匹配 | 直接值 | `comm: "bash"` |
| `regex:` | 正则匹配 | `filename: "regex:/etc/.*"` |
| `>=` | 大于等于 | `uid: ">=1000"` |
| `<=` | 小于等于 | `uid: "<=65535"` |
| `>` | 大于 | `pid: ">100"` |
| `<` | 小于 | `pid: "<1000"` |
| `!=` | 不等于 | `uid: "!=0"` |
| `in:` | 在列表中 | `dst_addr.port: "in:[22,80,443]"` |
| `notin:` | 不在列表中 | `dst_addr.port: "notin:[22]"` |

### 导入外部规则

使用 `rule_importer` 工具导入 Falco 或 Tracee 格式的规则：

```bash
# 导入 Falco 规则
./bin/rule_importer \
    -input ./falco_rules.yaml \
    -format falco \
    -output ./config/imported_rules.yaml

# 导入 Tracee 规则
./bin/rule_importer \
    -input ./tracee_rules.json \
    -format tracee \
    -output ./config/imported_rules.yaml
```

### 自定义规则示例

```yaml
# 添加自定义规则到 detection_rules 部分
detection_rules:
  process:
    - name: Custom suspicious command
      description: 检测可疑命令执行
      conditions:
        - event_type: process_create
        - cmdline: "regex:.*(curl|wget).*\\|.*bash.*"
      severity: critical
      logic_operator: AND
      tags:
        - custom
        - mitre_execution
      enabled: true
      throttle_seconds: 10
      actions:
        - log
      category: process
```

## 测试

### 单元测试

```bash
# 运行所有单元测试
make test

# 或直接使用 go test
cd src/go
go test -v ./...
```

### 规则测试

```bash
# 运行规则测试
make test-rules

# 指定测试数据和报告目录
./bin/etracee test \
    -config ./config/enhanced_security_config.yaml \
    -test-data ./test_data \
    -report ./test_reports \
    -verbose
```

### 集成测试

```bash
# 运行集成测试
make test-integration
```

### 性能测试

```bash
# 运行性能测试
./bin/etracee test -benchmark

# 使用 pprof 分析性能
cd src/go
go test -bench=. -benchmem -cpuprofile=cpu.prof ./...
go tool pprof cpu.prof
```

## 常见问题

### Q: eBPF 程序加载失败

**症状：** `failed to load BPF object`

**解决方案：**
1. 确认内核版本 >= 5.8
2. 检查 BTF 支持：`ls /sys/kernel/btf/vmlinux`
3. 确认以 root 权限运行
4. 检查内核配置是否启用 BPF

### Q: 无法捕获事件

**症状：** 运行后没有看到任何事件

**解决方案：**
1. 检查 UID 过滤范围是否正确
2. 确认事件类别开关已启用
3. 检查规则文件是否正确加载
4. 查看日志输出确认 eBPF 程序是否正常运行

### Q: 规则不生效

**症状：** 预期触发告警但没有触发

**解决方案：**
1. 检查规则 `enabled` 字段是否为 `true`
2. 检查条件是否正确匹配事件字段
3. 检查白名单是否意外过滤了该进程
4. 检查节流设置，可能被节流

### Q: Web 界面无法访问

**症状：** 浏览器显示无法连接

**解决方案：**
1. 确认服务已启动
2. 检查 `ETRACEE_BIND_ADDR` 设置
3. 检查防火墙规则
4. 检查端口是否被占用

### Q: D3.js 加载失败

**症状：** Web 界面显示"连接中"

**解决方案：**
1. 检查网络是否能访问外部 CDN
2. 程序已内置 D3 缺失容错，应能自动降级

### Q: 内存占用过高

**解决方案：**
1. 调整 `max_events_per_second` 限制事件速率
2. 调整 `max_alert_history` 限制告警历史
3. 收窄 UID 过滤范围
4. 禁用不需要的事件类别

## 开发建议

### 代码风格

```bash
# 格式化代码
make fmt

# 运行代码检查
make lint
```

### 添加新的 eBPF 探针

1. 在 `src/bpf/` 下创建新的 `.c` 文件
2. 在 `etracee_main.c` 中包含并注册
3. 更新 `etracee.h` 中的事件类型定义
4. 在 Go 用户态添加对应的事件解析逻辑

### 添加新的检测规则

1. 在 `config/enhanced_security_config.yaml` 中添加规则
2. 参考现有规则格式
3. 使用 `make test-rules` 验证规则

## 参考资源

- [eBPF 官方文档](https://ebpf.io/)
- [Cilium eBPF 库](https://github.com/cilium/ebpf)
- [Falco 规则](https://github.com/falcosecurity/rules)
- [Tracee 项目](https://github.com/aquasecurity/tracee)
- [MITRE ATT&CK 框架](https://attack.mitre.org/)
