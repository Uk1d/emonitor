## 目标与约束
- 保持现有功能100%可用，所有 API/WS 行为不变
- 面向分层与模块化，确保向后兼容与性能不降
- 单元与集成测试覆盖率≥85%，完成回归测试
- 交付源代码、技术文档、设计说明、测试报告与部署指南

## 现状速览
- 技术栈：Go 1.21（主），eBPF（C），SQLite（嵌入），`net/http` + `gorilla/websocket`
- 入口与服务：`src/go/main.go` 启动核心与 Web；`src/go/alert_api.go` 提供 HTTP/WS 与简易页面
- 存储：`Storage` 接口 + SQLite 实现；配置来源 YAML + 环境变量 + flags
- 测试：Shell/bpftrace 为主，缺少 Go 原生 `*_test.go`
- 构建：`Makefile` 驱动；未见 Docker/CI；无前端工程化工具

## 目标架构与目录布局
- 分层模块（Go 标准化布局，兼顾命名与可维护性）：
  - `cmd/etracee`：核心二进制入口（加载 eBPF、规则引擎、聚合/告警）
  - `cmd/etracee-api`：Web/API/WS 独立入口
  - `internal/core/`：核心领域模型与业务流程（事件模型、规则引擎、聚合、告警管理、图谱）
  - `internal/services/`：用例服务（查询、统计、订阅、推送）
  - `internal/repositories/`：存储接口与实现（`sqlite/`），抽象 `Storage`
  - `internal/api/`：HTTP/WS 层（路由、DTO、序列化、鉴权、CORS）
  - `internal/common/`：公共组件（日志、错误、中间件、工具、并发/队列）
  - `configs/`：YAML 等静态配置（迁移自 `config/`，保留兼容路径）
  - `bpf/`：eBPF 源码与构建产物（迁移自 `src/bpf/`）
  - `docs/`：架构与接口文档、部署指南
  - `scripts/`：运维与测试脚本
  - `web/`（新增）：前端工程（Vite + TS + D3/Chart），与后端完全分离
- 兼容层：在 `internal/api/compat` 提供旧路由与 `/ws` 行为的适配，确保原有页面/端点不破坏

## 重构分阶段计划
### Phase 1：架构骨架与迁移框架
1. 建立新目录布局与 `cmd/` 双入口
2. 将 `Storage` 接口与 SQLite 实现迁移至 `internal/repositories/`
3. 提取核心模型与规则引擎到 `internal/core/`
4. 构建 `internal/services/` 封装查询/统计/订阅逻辑
5. 在 `internal/api/` 重写路由注册（保留旧端点），`cmd/etracee-api` 启动 HTTP/WS
6. `main.go` 中仅保留核心启动与对外事件总线，移除直接 Web 依赖

### Phase 2：Web 服务解耦与前后端分离
1. 将 `alert_api.go` 拆分为 `api/http`（REST）与 `api/ws`（WebSocket）
2. 引入鉴权/CORS 中间件至 `internal/api/middleware`
3. 新建 `web/` 前端工程：Vite + TS + D3；用环境变量对接 API（不再内嵌页面）
4. 构建静态化部署方案（Nginx/静态托管），后端仅暴露 API/WS

### Phase 3：测试体系与质量保障
1. 为 `repositories/sqlite`、`services`、`api` 编写 Go 单测，覆盖 CRUD、分页、统计、WS 推送
2. 使用 `SQLite :memory:` 与 fakes/stubs 隔离依赖；用 `httptest` 验证路由与鉴权
3. 迁移 Shell/bpftrace 集成测试到 `make test-integration`，整合覆盖率统计
4. 覆盖率门槛：在 CI 中设置 `go test ./... -cover` ≥85%，生成报告

### Phase 4：性能与回归
1. 建立基准测试（`services` 查询/统计、WS 写入、SQLite 复杂查询）
2. 对比重构前后性能（QPS、p95/p99 延迟、内存/CPU）
3. 完整回归：端到端事件采集→存储→规则→告警→API/WS→前端订阅
4. 修正差异并锁定基线指标

## 代码映射与拆分建议
- `src/go/alert_api.go` → `internal/api/http/router.go