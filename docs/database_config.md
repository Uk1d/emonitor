# eTracee MySQL 数据库配置说明

## 概述

eTracee 使用 MySQL 作为主要数据存储，采用双数据库架构：

| 数据库 | 用途 | 默认名称 | 使用者 |
|--------|------|----------|--------|
| 监控程序数据库 | 存储 eBPF 事件和告警数据 | `etracee_events` | 监控程序 (root) |
| Web 服务数据库 | 存储 Web 认证用户和会话 | `etracee_web` | Web 服务 (普通用户) |

## 自动初始化

**数据库和表会自动创建，无需手动操作！**

程序首次启动时会：
1. 自动创建数据库（如果不存在）
2. 自动创建所需的表结构（如果不存在）
3. 自动创建默认管理员账户（用户名: `admin`，密码: `admin123`）

**你只需要**：
1. 确保 MySQL 服务运行
2. 配置 `config/database.yaml` 中的连接信息
3. 启动程序

## 配置文件

编辑 `config/database.yaml`：

```yaml
# 监控程序数据库 - 存储事件和告警
monitor_database:
  host: localhost
  port: 3306
  user: root
  password: "your_password"          # 请修改为实际密码
  database: etracee_events
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime_seconds: 3600

# Web 服务数据库 - 存储用户和会话
web_database:
  host: localhost
  port: 3306
  user: root
  password: "your_password"          # 请修改为实际密码
  database: etracee_web
  max_open_conns: 10
  max_idle_conns: 5
  conn_max_lifetime_seconds: 3600

# 管理员账户（首次启动自动创建）
admin:
  username: admin
  password: admin123                 # 请及时修改

# JWT 配置
jwt:
  secret: ""                         # 留空自动生成
  expiry_hours: 24

# 数据保留策略
retention_days: 30
```

## 快速启动

### 1. 安装 MySQL

```bash
# Ubuntu/Debian
sudo apt install -y mysql-server

# CentOS/RHEL/openEuler
sudo yum install -y mysql-server

# 启动 MySQL 服务
sudo systemctl start mysqld
sudo systemctl enable mysqld
```

### 2. 配置数据库连接

编辑 `config/database.yaml`，填写 MySQL 连接信息。

### 3. 启动服务

```bash
# 方式一：使用启动脚本（推荐）
./start.sh --split

# 方式二：分别启动
# 终端 1: 启动监控程序（需要 root）
sudo ./bin/etracee -monitor-only

# 终端 2: 启动 Web 服务（无需 root）
./bin/webserver
```

### 4. 访问 Web 界面

打开浏览器访问 `http://localhost:8888`

默认登录账户：
- 用户名: `admin`
- 密码: `admin123`

**登录后请立即修改密码！**

## Docker Compose 示例

```yaml
version: '3.8'
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: your_root_password
    volumes:
      - mysql_data:/var/lib/mysql
    ports:
      - "3306:3306"
    command: --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci

  monitor:
    build: .
    environment:
      # 监控程序数据库
      MYSQL_EVENTS_HOST: mysql
      MYSQL_EVENTS_USER: root
      MYSQL_EVENTS_PASSWORD: your_root_password
      MYSQL_EVENTS_DATABASE: etracee_events
    depends_on:
      - mysql
    privileged: true
    command: ["./etracee", "-monitor-only"]

  webserver:
    build: .
    environment:
      # Web 服务数据库
      MYSQL_WEB_HOST: mysql
      MYSQL_WEB_USER: root
      MYSQL_WEB_PASSWORD: your_root_password
      MYSQL_WEB_DATABASE: etracee_web
      # 管理员账户
      ADMIN_USERNAME: admin
      ADMIN_PASSWORD: your_secure_password
      JWT_SECRET: your_random_secret_key_here
      # 监控程序连接
      MONITOR_URL: ws://monitor:8889/ws
    depends_on:
      - mysql
      - monitor
    ports:
      - "8888:8888"
    command: ["./webserver"]

volumes:
  mysql_data:
```

## 数据保留策略

系统支持自动清理过期数据：

- 默认保留 30 天的数据
- 通过 `ETRACEE_RETENTION_DAYS` 环境变量配置
- 设置为 0 表示永久保留（不推荐）

## 性能优化建议

### 事件表优化

对于高负载场景，建议对 `events` 表进行分区：

```sql
-- 按日期分区（每月一个分区）
ALTER TABLE events PARTITION BY RANGE (TO_DAYS(timestamp)) (
    PARTITION p_default VALUES LESS THAN MAXVALUE
);

-- 定期添加新分区
ALTER TABLE events ADD PARTITION (
    PARTITION p_202603 VALUES LESS THAN (TO_DAYS('2026-04-01'))
);
```

### 索引优化

```sql
-- 复合索引优化常用查询
CREATE INDEX idx_events_type_time ON events(event_type, timestamp);
CREATE INDEX idx_alerts_status_time ON alerts(status, created_at);
```

## 生产环境建议

1. **安全配置**
   - 修改默认管理员密码
   - 设置强密码策略
   - 配置固定的 JWT_SECRET
   - 为监控程序和 Web 服务使用不同的数据库账户
   - 启用 TLS 加密

2. **高可用配置**
   - 配置 MySQL 主从复制
   - 使用连接池
   - 设置合理的连接超时

3. **监控与备份**
   - 配置 MySQL 慢查询日志
   - 定期备份数据库
   - 监控磁盘空间使用

## 故障排除

### 连接失败

1. 检查 MySQL 服务状态
2. 验证用户名密码是否正确
3. 确认防火墙规则允许连接
4. 检查 MySQL 是否允许远程连接

### 认证服务不可用

如果看到 `认证服务未启用` 提示：

1. 确认已设置 `MYSQL_WEB_HOST` 等环境变量
2. 确认 `etracee_web` 数据库已创建
3. 检查 Web 服务日志中的错误信息

### 性能问题

1. 检查索引是否正确创建
2. 调整连接池大小
3. 考虑分区表策略
4. 监控慢查询日志
