# eTracee Python 服务

这是 eTracee 项目的 Python 后端服务，提供 AI 异常检测和报告导出功能。

## 目录结构

```
python/
├── ai_detector/          # AI 异常检测模块
│   ├── __init__.py
│   └── detector.py      # 核心检测逻辑
├── report_generator/     # 报告生成模块
│   ├── __init__.py
│   └── generator.py     # 报告生成逻辑
├── requirements.txt      # Python 依赖
├── service.py          # HTTP API 服务
└── start.sh           # 启动脚本
```

## 功能

### AI 异常检测

- **进程行为检测**：检测异常的执行模式、可疑进程名、高执行速率
- **网络活动检测**：检测过多连接、连接可疑端口
- **文件活动检测**：检测敏感文件访问、频繁删除文件
- **权限变更检测**：检测权限提升行为

### 报告导出

- **JSON 格式**：结构化数据，适合程序处理
- **CSV 格式**：表格数据，适合 Excel 等工具导入
- **HTML 格式**：完整的可视化报告，包含样式和图表

## 安装

```bash
cd src/python
pip3 install -r requirements.txt
```

## 启动

```bash
# 使用启动脚本
./start.sh

# 或直接运行
python3 service.py
```

服务默认监听端口 `9900`。

## API 端点

### 健康检查

```
GET /health
```

返回服务状态和组件可用性。

### AI 检测

```
POST /api/ai/detect
```

发送事件进行异常检测。

### 获取异常列表

```
GET /api/ai/anomalies?limit=100&severity=high&type=process_behavior
```

获取 AI 检测到的异常列表。

### 生成报告

```
GET /api/reports/generate?format=json|csv|html
```

生成并下载安全报告。

### 接收批量事件

```
POST /api/data/events
```

接收批量事件数据用于填充报告。

## 与 Go 服务的集成

Python 服务通过 HTTP API 与 Go 服务通信：

1. Go 主程序启动时会创建 `PythonServiceClient` 连接 Python 服务
2. 事件处理时，Go 程序异步调用 Python 服务的 `/api/ai/detect` 端点
3. Web 界面请求报告时，Go 程序代理请求到 Python 服务

## 配置

服务端口可通过环境变量配置：

```bash
export PYTHON_SERVICE_PORT=9900
python3 service.py
```

## 依赖

- Python 3.11 或 3.12
- Flask 3.0.0
- Flask-CORS 4.0.0
- NumPy 1.24.3
