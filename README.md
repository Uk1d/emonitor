# eTracee 项目说明

eTracee 是一个基于 eBPF 的轻量级安全监控与攻击链可视化系统，核心包括：内核侧事件采集、用户态事件解析与规则匹配、Web 实时展示与图谱推演。项目强调“清晰的职责划分、低耦合、可配置与可观察”。

## 架构概览

- 内核侧（eBPF）：在关键 `tracepoint` 上采集事件，通过 `ringbuf` 高效传输到用户态
- 用户态（Go）：解析原始事件、应用过滤与规则、推送 `WebSocket` 消息、计算攻击链与统计
- 前端（内置 HTML）：展示统计、事件流与图谱（D3 可选，缺失时自动降级）

## 目录结构

- `src/bpf/`：eBPF 程序
  - 事件结构与宏：`etracee.h`、`etracee_main.c`
  - 模块化探针：`execve_trace.c`、`filesystem_trace.c`、`network_trace.c`、`security_trace.c`
- `src/go/`：用户态与前端
  - 路由：`internal/api/http/router.go`
  - 中间件：`internal/api/middleware/cors.go`
  - 配置：`internal/common/config/config.go`
  - 前端静态页：`internal/web/static/index.html`（内嵌并提供 D3 容错与节流）
  - 服务核心：`alert_api.go`（WS、REST、客户端管理）、`main.go`（启动与 eBPF 附加）
  - 规则与图谱：`rule_engine.go`、`event_context.go`、`graph_model.go`、`graph_stream.go`
- `config/`：规则与存储配置（默认与回退）
- `docs/`：保留 PDF 与 HTML 文档、汇总文档
- `data/`：运行数据（默认仅 `.gitkeep`）

## 关键工作流

- 事件采集与传输：
  - `ringbuf` 定义：`src/bpf/etracee_main.c:52-54`
  - 配置映射：`src/bpf/etracee_main.c:89-95`（事件开关与 UID 范围）
  - 通用跟踪宏（统一流程）：`src/bpf/etracee_main.c:235-263`
  - UID/GID 与基础字段填充：`src/bpf/etracee_main.c:182-202`

- 用户态解析与广播：
  - 加载 eBPF 对象：`src/go/main.go:724-736`
  - 写入配置映射：`src/go/main.go:705-706`
  - 周期统计推送：`src/go/main.go:641-651`
  - 事件推送与图谱增量：`src/go/main.go:1000-1004`
  - WS 广播（统一入队策略）：`src/go/alert_api.go:607-615, 758-771`

- 前端展示：
  - 连接 `ws://<host>:8888/ws` 并处理四类消息：`stats/event/alert/graph_update`
  - 事件表滚动与行数限制，避免页面无限拉长：`src/go/internal/web/static/index.html:22, 61, 79, 158-162`
  - 图谱节流、中心力与边界约束：`src/go/internal/web/static/index.html:123-126, 139-146, 163`
  - D3 缺失容错：`src/go/internal/web/static/index.html:118-127`

## 配置与运行

- 主程序参数（`etracee`）：
  - `-config`：安全规则配置文件路径（默认：`config/enhanced_security_config.yaml`）
  - `-dashboard`：启用命令行 Dashboard（默认：`false`）
  - `-pid-min`：过滤 PID 最小值（默认：`0`，不启用）
  - `-pid-max`：过滤 PID 最大值（默认：`0`，不启用）
  - `-uid-min`：过滤 UID 最小值（默认：`0`，不启用）
  - `-uid-max`：过滤 UID 最大值（默认：`0`，不启用）
- 子命令：
  - `etracee test`：规则测试工具（参数见下）
  - `etracee integration-test`：集成测试（无参数）
- 规则测试工具参数（`etracee test`）：
  - `-config`：规则配置文件路径（默认：`./config/enhanced_security_config.yaml`）
  - `-test-data`：测试数据目录路径（默认：`./test_data`）
  - `-report`：测试报告输出目录（默认：`./test_reports`）
  - `-verbose`：详细输出模式（默认：`false`）
  - `-benchmark`：启用性能测试（默认：`true`）
- 规则导入工具参数（`src/go/tools/rule_importer/main.go`）：
  - `-input`：输入规则文件路径（必填）
  - `-format`：规则格式：`falco` 或 `tracee`（可选；为空时自动推断）
  - `-output`：输出规则文件路径（必填）
  - `-default-category`：默认类别（默认：`general`）
  - `-default-severity`：默认严重级别（默认：`medium`）
  - `-enable`：是否启用导入的规则（默认：`true`）
  - `-allow-partial`：允许存在未映射字段的规则启用（默认：`false`）
  - `-field-map`：字段映射 JSON 字符串（可选）
  - `-field-map-file`：字段映射 JSON 文件路径（可选）

- 绑定地址：`ETRACEE_BIND_ADDR`，默认 `0.0.0.0:8888`（`src/go/alert_api.go:60-67`）
- 鉴权：设置 `ETRACEE_API_TOKEN` 后自动启用（WebSocket 子协议与 HTTP 统一校验），未设置则不启用
- CORS 来源白名单：`ETRACEE_ALLOWED_ORIGINS`（逗号分隔）
- WebSocket 队列：`ETRACEE_WS_QUEUE_SIZE`，默认 `1024`，上限 `8192`
- 事件类别开关：`ETRACEE_ENABLE_FILE`、`ETRACEE_ENABLE_NETWORK`、`ETRACEE_ENABLE_PROCESS`、`ETRACEE_ENABLE_PERMISSION`、`ETRACEE_ENABLE_MEMORY`（默认均启用，读取位置 `src/go/main.go:654-676`）
- UID 过滤范围：`ETRACEE_UID_MIN`（默认 `0`）、`ETRACEE_UID_MAX`（默认 `65535`）
- 其他：`ETRACEE_MAX_EPS`、`ETRACEE_ALERT_THROTTLE`、`ETRACEE_MAX_ALERT_HISTORY`、`ETRACEE_ENABLE_RULE_STATS`、`ETRACEE_LOG_LEVEL`
- Webhook：`ETRACEE_WEBHOOK_URL`（可选 `ETRACEE_WEBHOOK_TIMEOUT`、`ETRACEE_WEBHOOK_RETRY`、`ETRACEE_WEBHOOK_SECRET`）
- 存储配置：默认读取 `config/storage.yaml`（不存在则回退到 SQLite：`data/etracee.db`）

## 编译参数（构建期）

- Go 构建（用户态程序）：
  - 常用：`go build`、`go run`
  - 常用环境变量：`GOOS`、`GOARCH`、`CGO_ENABLED`、`GOMODCACHE`
  - 常用链接参数：`-ldflags`（例如裁剪符号：`-s -w`）
- eBPF 构建（内核侧对象 `build/etracee.bpf.o`）：
  - 需要生成 `src/bpf/vmlinux.h`（基于 BTF）
  - 常用 Clang/LLVM 参数：`-target bpf`、`-O2`、`-g`、`-D__TARGET_ARCH_x86`（或 `arm64` 等）、`-I` 头文件路径

更完整的编译与运行说明见 [USAGE.md](file:///e:/bs/eTracee/USAGE.md)。

## 事件模型（JSON）

- 核心字段：`timestamp`、`pid`、`ppid`、`uid`、`gid`、`syscall_id`、`event_type`、`ret_code`、`comm`
- 事件类型示例：`openat`、`close`、`connect`、`bind`、`listen`、`mmap`、`mprotect`、`ptrace`、`kill`
- 解析与转换：`src/go/main.go:969-980`（`RawEvent` → `EventJSON`，含 Linux 进程命令行补充）

## Web API 与消息

- WebSocket `/ws`：
  - `stats`：统计数据（总告警、活跃告警、已处理、误报）
  - `event`：原始事件（用于“最新事件流”）
  - `alert`：规则触发告警
  - `graph_update`：图谱增量（前端节流合并渲染）
- REST 示例（路由注册）：`src/go/internal/api/http/router.go:22`
  - `/api/alerts`、`/api/alert-stats`、`/api/attack-chains`

## 性能与稳定性

- WS 写泵含 Ping/Pong 心跳与写超时：`src/go/alert_api.go:132-155, 665-672`
- 客户端队列满丢弃最旧，保护实时性：`src/go/alert_api.go:758-771`
- 周期统计推送与事件流限高滚动，减少前端压力：`src/go/main.go:641-651` 与前端样式限制
- 前端图谱节流（500ms）与边界钳制，防止越界与抖动：`src/go/internal/web/static/index.html:123-126, 139-146`

## 常见问题与定位

- 一直“连接中”：多半为外部 CDN（D3）阻断导致脚本中断；已提供 D3 缺失容错。也请确认服务未退出、绑定地址可达。
- `ERR_CONNECTION_REFUSED`：检查 `ETRACEE_BIND_ADDR` 是否为对外地址（默认已是 `0.0.0.0`）。
- UID/GID 多为 1000：并非错误，属于事件分布偏态（用户会话进程事件占比高）。可通过 `ETRACEE_UID_MIN/MAX` 收窄范围验证。
- `syscall_id=0`：仅见于非系统调用入口事件（如 `sched_process_exit`），属设计预期；已增加更多 `sys_enter_*` 跟踪点降低比例。

## 安全注意

- 默认关闭鉴权以便调试；生产使用建议启用令牌并限制绑定地址。
- 避免在公开环境暴露无鉴权的接口；遵循最小暴露原则与网络访问控制。

## 开发与扩展建议

- 探针扩展：按 `TRACE_EVENT_COMMON` 模板新增系统调用入口探针，并在 `router.go` 注册必要的 REST 端点。
- 规则扩展：在 `config/enhanced_security_config.yaml` 增加规则，或回退到 `config/security_rules.yaml`。编译与匹配路径见 `src/go/rule_engine.go`。
- 统计与可视化：可在后端聚合 `graph_update`，再推送以进一步降低前端刷新频率。

## 版本与清理

- 文档：保留 PDF 与 HTML，其他内容整合到 `docs/文档汇总.md`
- `.gitignore`：忽略运行产物、数据与本地覆盖配置，保留核心 YAML 默认配置

如需进一步增强 README（例如分平台构建与打包说明、CI/CD 配置范式、示例规则集），请告知要求，我将继续完善与补充。
