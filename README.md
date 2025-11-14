# eTracee

轻量级 eBPF 安全监控与攻击链可视化系统。当前项目提供：

- eBPF 事件采集（文件、网络、进程、权限、内存）
- Go 用户态服务（事件解析、规则匹配、告警与图谱）
- 内置 Web 前端与 WebSocket 实时推送

## 目录结构

- `src/bpf/`：eBPF 程序与事件结构
- `src/go/`：用户态服务与 Web API、规则引擎、前端静态资源
- `config/`：规则与存储配置（可按需扩展本地覆盖）
- `docs/`：保留 PDF 与 HTML 文档，其他说明见 `docs/文档汇总.md`
- `data/`：运行时数据（默认只保留 `.gitkeep`）

## 运行与访问

- 服务默认绑定 `0.0.0.0:8888`，打开浏览器访问 `http://<主机IP>:8888/`
- WebSocket 路径：`ws://<主机IP>:8888/ws`
- 目前鉴权默认关闭；如需开启可在中间件启用令牌校验

## 环境变量

- `ETRACEE_BIND_ADDR`：HTTP/WS 绑定地址，默认 `0.0.0.0:8888`
- `ETRACEE_WS_QUEUE_SIZE`：WS 客户端队列，默认 `1024`，上限 `8192`
- 事件类别开关：
  - `ETRACEE_ENABLE_FILE`（默认 `true`）
  - `ETRACEE_ENABLE_NETWORK`（默认 `true`）
  - `ETRACEE_ENABLE_PROCESS`（默认 `true`）
  - `ETRACEE_ENABLE_PERMISSION`（默认 `true`）
  - `ETRACEE_ENABLE_MEMORY`（默认 `true`）
- UID 过滤范围：
  - `ETRACEE_UID_MIN`（默认 `0`）
  - `ETRACEE_UID_MAX`（默认 `65535`）
- 其他：
  - `ETRACEE_MAX_EPS`（默认 `10000`）
  - `ETRACEE_ALERT_THROTTLE`（默认 `60`）
  - `ETRACEE_MAX_ALERT_HISTORY`（默认 `1000`）
  - `ETRACEE_ENABLE_RULE_STATS`（默认 `true`）
  - `ETRACEE_LOG_LEVEL`（默认 `info`）

## 关键端点

- WebSocket：`/ws`，消息类型包括 `stats`、`event`、`alert`、`graph_update`
- REST 示例：`/api/alerts`、`/api/alert-stats`、`/api/attack-chains`

## 注意事项

- 高吞吐环境建议通过环境变量收窄事件类别或 UID 范围，并适当增大 `ETRACEE_WS_QUEUE_SIZE`
- 若前端无法加载外部 CDN（D3），系统会自动降级，仍可建立 WS 并展示事件与告警
- eBPF 探针编译与挂载需要在 Linux 上进行；Windows 环境下仅运行用户态与前端

## 变更摘要（与旧文档对齐）

- 路由、配置、静态资源拆分；默认对外绑定；鉴权可按需开启
- 前端添加节流与边界约束，避免图谱越界与持续抖动
- 配置集中化：通过环境变量驱动默认值，避免代码内硬编码