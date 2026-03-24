# eTracee 使用说明

本文档面向"使用者/运维/研发"，覆盖：

- 主程序与工具的所有命令行参数及用途
- 运行期环境变量开关
- Web 界面使用说明
- AI 对话功能配置

## 1. 主程序（etracee）

### 1.1 用法

从仓库根目录运行（推荐），确保能找到 `build/etracee.bpf.o`：

```bash
sudo ./bin/etracee [参数]
```

### 1.2 参数列表

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-config <路径>` | `config/enhanced_security_config.yaml` | 安全规则配置文件路径 |
| `-dashboard` | `false` | 启用命令行 Dashboard |
| `-monitor-only` | `false` | 仅运行监控模式（用于分离架构） |
| `-web-port <端口>` | `8888` | Web 服务端口 |
| `-ws-port <端口>` | `8889` | WebSocket 服务端口 |
| `-pid-min <整数>` | `0` | 过滤 PID 最小值 |
| `-pid-max <整数>` | `0` | 过滤 PID 最大值 |
| `-uid-min <整数>` | `0` | 过滤 UID 最小值 |
| `-uid-max <整数>` | `0` | 过滤 UID 最大值 |

### 1.3 子命令

- `etracee test`：规则测试工具
- `etracee integration-test`：集成测试

## 2. 规则测试工具（etracee test）

```bash
./bin/etracee test [参数]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-config <路径>` | `./config/enhanced_security_config.yaml` | 规则配置文件路径 |
| `-test-data <路径>` | `./test_data` | 测试数据目录路径 |
| `-report <路径>` | `./test_reports` | 测试报告输出目录 |
| `-verbose` | `false` | 详细输出模式 |
| `-benchmark` | `true` | 启用性能测试 |

## 3. 规则导入工具（rule_importer）

用于把其他项目的规则（Falco YAML / Tracee JSON）转换为 eTracee 的格式。

```bash
# 直接运行
go run ./src/go/tools/rule_importer/main.go -input <输入文件> -output <输出文件>

# 或编译后运行
go build -o ./bin/rule_importer ./src/go/tools/rule_importer
./bin/rule_importer -input <输入文件> -output <输出文件>
```

| 参数 | 说明 |
|------|------|
| `-input <路径>` | 输入规则文件路径（必填） |
| `-format <falco\|tracee>` | 规则格式 |
| `-output <路径>` | 输出规则文件路径（必填） |
| `-default-category <字符串>` | 默认类别（默认：general） |
| `-default-severity <字符串>` | 默认严重级别（默认：medium） |
| `-enable <true\|false>` | 是否启用导入的规则 |

## 4. 运行期环境变量

### 4.1 数据库配置

| 环境变量 | 说明 |
|----------|------|
| `MYSQL_EVENTS_HOST` | 监控数据库主机 |
| `MYSQL_EVENTS_PORT` | 监控数据库端口 |
| `MYSQL_EVENTS_USER` | 监控数据库用户 |
| `MYSQL_EVENTS_PASSWORD` | 监控数据库密码 |
| `MYSQL_WEB_HOST` | Web 数据库主机 |
| `MYSQL_WEB_PORT` | Web 数据库端口 |
| `MYSQL_WEB_USER` | Web 数据库用户 |
| `MYSQL_WEB_PASSWORD` | Web 数据库密码 |

### 4.2 管理员配置

| 环境变量 | 说明 |
|----------|------|
| `ADMIN_USERNAME` | 管理员用户名 |
| `ADMIN_PASSWORD` | 管理员密码 |
| `JWT_SECRET` | JWT 密钥 |

### 4.3 Web/API 服务

| 环境变量 | 说明 |
|----------|------|
| `ETRACEE_BIND_ADDR` | 绑定地址（默认 0.0.0.0） |
| `ETRACEE_API_TOKEN` | API/WS 鉴权令牌 |
| `ETRACEE_ALLOWED_ORIGINS` | CORS 白名单 |
| `ETRACEE_WS_QUEUE_SIZE` | WebSocket 客户端队列长度 |

### 4.4 事件与规则引擎

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `ETRACEE_ENABLE_FILE` | true | 文件事件开关 |
| `ETRACEE_ENABLE_NETWORK` | true | 网络事件开关 |
| `ETRACEE_ENABLE_PROCESS` | true | 进程事件开关 |
| `ETRACEE_ENABLE_PERMISSION` | true | 权限事件开关 |
| `ETRACEE_ENABLE_MEMORY` | true | 内存事件开关 |
| `ETRACEE_UID_MIN` | 0 | 最小 UID |
| `ETRACEE_UID_MAX` | 65535 | 最大 UID |
| `ETRACEE_MAX_EPS` | 10000 | 最大每秒事件数 |
| `ETRACEE_LOG_LEVEL` | info | 日志级别 |

### 4.5 Webhook 通知

| 环境变量 | 说明 |
|----------|------|
| `ETRACEE_WEBHOOK_URL` | Webhook 地址 |
| `ETRACEE_WEBHOOK_TIMEOUT` | 超时（如 `10s`） |
| `ETRACEE_WEBHOOK_RETRY` | 重试次数 |
| `ETRACEE_WEBHOOK_SECRET` | 签名密钥 |

## 5. Web 界面使用说明

### 5.1 访问方式

启动后访问 `http://localhost:8888`，使用管理员账户登录。

### 5.2 功能模块

#### 告警列表

- 实时显示安全告警
- 支持按严重级别（严重/高危/中危/低危）过滤
- 点击告警可查看详情
- 支持告警状态管理（确认/处理/解决/标记误报）

#### 事件流

- 实时显示系统事件
- 支持搜索过滤
- 显示时间、事件类型、进程ID、进程名、目标等信息

#### 攻击链图谱

- 可视化展示攻击路径
- 支持节点拖拽
- 显示攻击阶段和关联关系

#### AI 检测（Beta）

- 显示 AI 异常检测结果
- 支持按类型和级别过滤

#### 报告导出

- 支持 JSON/CSV/HTML 三种格式
- 可选择包含的数据类型

### 5.3 连接状态说明

| 状态 | 含义 |
|------|------|
| 已连接(等待监控) | Web 服务已连接，监控程序未运行 |
| 监控运行中 | 监控程序正在运行并推送数据 |
| 监控未运行 | 超过 10 秒未收到数据 |
| 连接断开 | WebSocket 连接已断开 |

### 5.4 告警状态

| 状态 | 说明 |
|------|------|
| 新建 | 新产生的告警 |
| 已确认 | 运维人员已确认 |
| 处理中 | 正在处理 |
| 已解决 | 告警已处理完成 |
| 误报 | 标记为误报 |

## 6. AI 对话功能

### 6.1 功能说明

AI 对话功能支持与多种 AI 服务商对接，提供实时安全分析和排查建议。

### 6.2 支持的 AI 服务商

| 服务商 | API 地址 | 说明 |
|--------|----------|------|
| OpenAI | `https://api.openai.com/v1` | GPT-3.5/4/4o |
| Anthropic | `https://api.anthropic.com/v1` | Claude 3/3.5 |
| Moonshot | `https://api.moonshot.cn/v1` | Kimi |
| Google | `https://generativelanguage.googleapis.com/v1beta` | Gemini |
| DeepSeek | `https://api.deepseek.com/v1` | DeepSeek Chat |
| 智谱 AI | `https://open.bigmodel.cn/api/paas/v4` | GLM-4 |
| 阿里云 | `https://dashscope.aliyuncs.com/compatible-mode/v1` | 通义千问 |
| 百度 | `https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop` | 文心一言 |
| 硅基流动 | `https://api.siliconflow.cn/v1` | 多种开源模型 |
| Ollama | `http://localhost:11434/v1` | 本地部署模型 |

### 6.3 配置步骤

1. 点击页面右下角 AI 助手按钮
2. 点击配置按钮（⚙️）
3. 选择服务商
4. 输入 API Key
5. 选择模型
6. 点击"保存配置"

### 6.4 使用方式

- **快速问题**：点击预设的快捷问题按钮
- **自定义问题**：在输入框中输入问题
- **上下文分析**：AI 会自动读取当前告警和事件数据

### 6.5 常用命令示例

- "分析最近的安全告警"
- "检查是否有异常进程行为"
- "分析网络连接异常"
- "提供安全加固建议"
- "检查是否存在反弹 shell"

## 7. 编译期参数

### 7.1 Go 程序构建

```bash
cd ./src/go
go build -o ../../bin/etracee .
```

常用参数：
- `GOOS`/`GOARCH`：交叉编译
- `CGO_ENABLED`：是否启用 CGO
- `-ldflags "-s -w"`：减小体积

### 7.2 eBPF 对象构建

```bash
# 生成 vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./src/bpf/vmlinux.h

# 编译 eBPF 对象
clang -O2 -g -target bpf \
  -D__TARGET_ARCH_x86 \
  -I./src/bpf \
  -I/usr/include \
  -I/usr/include/bpf \
  -c ./src/bpf/etracee_main.c \
  -o ./build/etracee.bpf.o
```

## 8. 配置文件路径

| 文件 | 说明 |
|------|------|
| `config/database.yaml` | 数据库配置（包含敏感信息） |
| `config/enhanced_security_config.yaml` | 安全规则配置 |
| `build/etracee.bpf.o` | eBPF 对象文件 |

> **安全提示**：`config/database.yaml` 包含敏感信息，请确保文件权限为 `600`。
