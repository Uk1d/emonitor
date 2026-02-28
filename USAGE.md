# eTracee 使用说明

本文档面向“使用者/运维/研发”，覆盖：

- 主程序与工具的所有命令行参数及用途
- 运行期环境变量开关
- 编译期参数（Go 与 eBPF）

## 1. 主程序（etracee）

### 1.1 用法

从仓库根目录运行（推荐），确保能找到 `build/etracee.bpf.o`：

```bash
sudo ./bin/etracee [参数]
```

### 1.2 参数列表

- `-config <路径>`：安全规则配置文件路径  
  - 默认：`config/enhanced_security_config.yaml`
  - 用途：加载规则、全局开关（事件类别开关/UID 范围等）、白名单与响应动作。
- `-dashboard`：启用命令行 Dashboard  
  - 默认：`false`
  - 用途：在终端输出聚合统计与 Top 进程等信息。
- `-pid-min <整数>`：过滤 PID 最小值  
  - 默认：`0`（不启用过滤）
  - 用途：丢弃 PID 小于该值的事件。
- `-pid-max <整数>`：过滤 PID 最大值  
  - 默认：`0`（不启用过滤）
  - 用途：丢弃 PID 大于该值的事件。
- `-uid-min <整数>`：过滤 UID 最小值  
  - 默认：`0`（不启用过滤）
  - 用途：丢弃 UID 小于该值的事件。
- `-uid-max <整数>`：过滤 UID 最大值  
  - 默认：`0`（不启用过滤）
  - 用途：丢弃 UID 大于该值的事件。

### 1.3 子命令

主程序在 `etracee` 后支持两个子命令：

- `etracee test`：规则测试工具（参数见第 2 节）
- `etracee integration-test`：集成测试（无参数）

## 2. 规则测试工具（etracee test）

### 2.1 用法

```bash
./bin/etracee test [参数]
```

### 2.2 参数列表

- `-config <路径>`：规则配置文件路径  
  - 默认：`./config/enhanced_security_config.yaml`
- `-test-data <路径>`：测试数据目录路径  
  - 默认：`./test_data`
- `-report <路径>`：测试报告输出目录  
  - 默认：`./test_reports`
- `-verbose`：详细输出模式  
  - 默认：`false`
- `-benchmark`：启用性能测试  
  - 默认：`true`

说明：该命令用于规则验证与报告生成，行为由 [test_runner.go](file:///e:/bs/eTracee/src/go/test_runner.go) 定义。

## 3. 规则导入工具（rule_importer）

该工具用于把其他项目的规则（Falco YAML / Tracee JSON）转换为 eTracee 的 `enhanced_security_config.yaml` 结构。

### 3.1 用法

直接运行：

```bash
go run ./src/go/tools/rule_importer/main.go -input <输入文件> -output <输出文件> [其他参数]
```

或自行编译后运行：

```bash
go build -o ./bin/rule_importer ./src/go/tools/rule_importer
./bin/rule_importer -input <输入文件> -output <输出文件> [其他参数]
```

### 3.2 参数列表

- `-input <路径>`：输入规则文件路径（必填）
- `-format <falco|tracee>`：规则格式（可选）  
  - 为空时：若输入看起来像 JSON（或扩展名为 `.json`）则按 `tracee` 处理，否则按 `falco` 处理
- `-output <路径>`：输出规则文件路径（必填）
- `-default-category <字符串>`：默认类别（可选；默认：`general`）
- `-default-severity <字符串>`：默认严重级别（可选；默认：`medium`）
- `-enable <true|false>`：是否启用导入的规则（默认：`true`）  
  - 用途：统一控制导入后规则的 `enabled` 字段
- `-allow-partial <true|false>`：允许存在未映射字段的规则启用（默认：`false`）  
  - 用途：当 Falco 条件字段无法完整映射时，仍允许“部分条件可用”的规则处于启用态
- `-field-map <JSON>`：字段映射 JSON 字符串（可选）  
  - 用途：覆盖/追加默认字段映射
- `-field-map-file <路径>`：字段映射 JSON 文件路径（可选）  
  - 用途：从文件加载映射，覆盖/追加默认字段映射

说明：导出文件会写入 `global` 默认值，以避免“程序运行但无事件”的情况（见 [rule_importer/main.go](file:///e:/bs/eTracee/src/go/tools/rule_importer/main.go)）。

## 4. 运行期环境变量

### 4.1 Web/API 服务与安全

- `ETRACEE_BIND_ADDR`：绑定地址  
  - 为空时默认 `0.0.0.0`，端口固定为 `8888`
  - 若值包含 `:`（例如 `127.0.0.1:8888`），则按“完整地址”使用
- `ETRACEE_API_TOKEN`：API/WS 鉴权令牌  
  - 为空：不启用鉴权
  - 非空：启用鉴权（HTTP 与 WebSocket 一致）
- `ETRACEE_ALLOWED_ORIGINS`：CORS 白名单（逗号分隔）
- `ETRACEE_WS_QUEUE_SIZE`：WebSocket 客户端队列长度（默认 1024，上限 8192）

### 4.2 事件与规则引擎开关

当加载 `-config` 失败时，主程序会从环境变量回退构造 `global` 配置：

- `ETRACEE_ENABLE_FILE`：文件事件开关（默认 true）
- `ETRACEE_ENABLE_NETWORK`：网络事件开关（默认 true）
- `ETRACEE_ENABLE_PROCESS`：进程事件开关（默认 true）
- `ETRACEE_ENABLE_PERMISSION`：权限事件开关（默认 true）
- `ETRACEE_ENABLE_MEMORY`：内存事件开关（默认 true）
- `ETRACEE_UID_MIN`：最小 UID（默认 0）
- `ETRACEE_UID_MAX`：最大 UID（默认 65535）
- `ETRACEE_MAX_EPS`：最大每秒事件数（默认 10000）
- `ETRACEE_ALERT_THROTTLE`：告警节流秒数（默认 60）
- `ETRACEE_MAX_ALERT_HISTORY`：告警历史上限（默认 1000）
- `ETRACEE_ENABLE_RULE_STATS`：规则统计开关（默认 true）
- `ETRACEE_LOG_LEVEL`：日志级别（默认 info）

### 4.3 Webhook 通知

- `ETRACEE_WEBHOOK_URL`：Webhook 地址（为空则不启用）
- `ETRACEE_WEBHOOK_TIMEOUT`：超时（Go `time.ParseDuration` 格式，例如 `10s`）
- `ETRACEE_WEBHOOK_RETRY`：重试次数（整数，默认 0）
- `ETRACEE_WEBHOOK_SECRET`：签名密钥（启用后会发送 HMAC-SHA256 签名头）

## 5. 编译期参数（构建期）

### 5.1 Go 用户态程序构建

仓库使用 Go module（`src/go/go.mod`）。常见构建方式：

```bash
cd ./src/go
go build -o ../../bin/etracee .
```

常见编译期环境变量与用途：

- `GOOS`/`GOARCH`：交叉编译目标系统与架构
- `CGO_ENABLED`：是否启用 CGO（本项目 SQLite 驱动为纯 Go，实现上通常不依赖 CGO）
- `-ldflags`：链接参数（如 `-s -w` 缩小体积）

说明：运行时会从相对路径加载 `build/etracee.bpf.o`，因此推荐从仓库根目录运行 `./bin/etracee`。

### 5.2 eBPF 对象构建（build/etracee.bpf.o）

该项目 eBPF 程序源代码在 `src/bpf/`，用户态默认加载 `build/etracee.bpf.o`。

构建前置条件（Linux 环境）：

- Clang/LLVM（用于 `-target bpf` 编译）
- `bpftool`（用于从 BTF 生成 `vmlinux.h`）
- 具备 BTF 的内核（通常存在 `/sys/kernel/btf/vmlinux`）
- 系统头文件与 libbpf 头文件（提供 `<bpf/bpf_helpers.h>` 等）

常用构建步骤（示例）：

```bash
# 1) 生成 vmlinux.h（放在 src/bpf/ 以满足 #include "vmlinux.h"）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./src/bpf/vmlinux.h

# 2) 编译 eBPF 对象到 build/etracee.bpf.o
mkdir -p ./build
clang -O2 -g -target bpf \
  -D__TARGET_ARCH_x86 \
  -I./src/bpf \
  -I/usr/include \
  -I/usr/include/bpf \
  -c ./src/bpf/etracee_main.c \
  -o ./build/etracee.bpf.o
```

常见编译期参数与用途：

- `-target bpf`：输出 eBPF 字节码
- `-O2`：优化等级（常用）
- `-g`：保留调试信息（便于排障与验证）
- `-D__TARGET_ARCH_x86`：目标架构宏（按实际机器改为 `arm64` 等）
- `-I...`：头文件搜索路径（确保能找到 `vmlinux.h` 与 libbpf 头文件）

## 6. 配置文件路径约定

- 安全规则配置：由 `-config` 指定，默认 `config/enhanced_security_config.yaml`
- 存储配置：固定读取 `config/storage.yaml`（不存在则回退默认 SQLite：`data/etracee.db`）

## 7. Web 界面状态说明

### 7.1 连接状态指示器

Web 界面顶部的状态指示器会根据监控程序运行状态动态变化：

| 显示文本 | 状态颜色 | 含义 |
|----------|----------|------|
| 已连接(等待监控) | 黄色 | Web 服务已连接，监控程序未运行或尚未发送数据 |
| 监控运行中 | 绿色 | 监控程序正在运行，实时接收事件/告警数据 |
| 监控未运行 | 黄色 | 超过 10 秒未收到监控数据，监控程序可能已停止 |
| 连接断开 | 红色 | WebSocket 连接已断开，正在尝试重连 |

状态判断逻辑：
- 当收到事件 (`event`) 或告警 (`alert`) 消息时，立即更新为"监控运行中"
- 超过 10 秒未收到数据时，状态变为"监控未运行"
- 每 3 秒检查一次监控活跃状态

### 7.2 告警状态管理

告警支持以下状态，刷新页面后状态信息不会丢失：

| 状态 | 英文标识 | 说明 |
|------|----------|------|
| 新建 | `new` | 新产生的告警，尚未处理 |
| 已确认 | `acknowledged` | 运维人员已确认该告警 |
| 处理中 | `in_progress` | 正在处理该告警 |
| 已解决 | `resolved` | 告警已处理完成 |
| 误报 | `false_positive` | 标记为误报的告警 |

告警数据持久化：
- 所有告警状态变更会实时写入 MySQL 数据库
- 刷新页面时，WebSocket 会推送所有活跃状态（new/acknowledged/in_progress）的告警
- 前端使用告警 ID 去重，同一告警的状态更新不会产生重复记录

