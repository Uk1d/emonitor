# eTracee MySQL 数据库配置说明

## 概述

eTracee 使用 MySQL 作为主要数据存储，采用双数据库架构：

| 数据库 | 用途 | 默认名称 | 使用者 |
|--------|------|----------|--------|
| 监控程序数据库 | 存储 eBPF 事件和告警数据 | `etracee_events` | 监控程序 (root) |
| Web 服务数据库 | 存储 Web 认证用户和会话 | `etracee_web` | Web 服务 (普通用户) |

这种分离架构有以下优势：
- **安全隔离**：Web 服务无需 root 权限，认证数据与监控数据物理分离
- **性能隔离**：高频事件写入不影响认证服务
- **独立扩展**：可根据负载情况独立优化各数据库
- **权限分离**：监控程序和 Web 服务可使用不同的数据库账户

## 数据库表结构

### 监控程序数据库 (etracee_events)

```sql
-- 事件表
CREATE TABLE events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME(3) NOT NULL,
    pid INT UNSIGNED,
    uid INT UNSIGNED,
    comm VARCHAR(255),
    event_type VARCHAR(64) NOT NULL,
    filename VARCHAR(512),
    severity VARCHAR(32),
    rule_matched VARCHAR(255),
    raw_json JSON,
    INDEX idx_events_timestamp (timestamp),
    INDEX idx_events_event_type (event_type)
);

-- 告警表
CREATE TABLE alerts (
    id VARCHAR(64) PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    category VARCHAR(64),
    description TEXT,
    pid INT UNSIGNED,
    uid INT UNSIGNED,
    comm VARCHAR(255),
    filename VARCHAR(512),
    status VARCHAR(32) DEFAULT 'new',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_alerts_created_at (created_at),
    INDEX idx_alerts_severity (severity),
    INDEX idx_alerts_status (status)
);
```

### Web 服务数据库 (etracee_web)

```sql
-- 用户表
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 会话表
CREATE TABLE sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id INT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sessions_user_id (user_id),
    INDEX idx_sessions_expires (expires_at)
);
```

## 环境变量配置

### 监控程序数据库配置

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `MYSQL_EVENTS_HOST` | 事件数据库主机 | 使用 `MYSQL_HOST` |
| `MYSQL_EVENTS_PORT` | 事件数据库端口 | `3306` |
| `MYSQL_EVENTS_USER` | 事件数据库用户名 | 使用 `MYSQL_USER` |
| `MYSQL_EVENTS_PASSWORD` | 事件数据库密码 | 使用 `MYSQL_PASSWORD` |
| `MYSQL_EVENTS_DATABASE` | 事件数据库名称 | `etracee_events` |
| `MYSQL_MAX_OPEN_CONNS` | 最大连接数 | `50` |
| `MYSQL_MAX_IDLE_CONNS` | 最大空闲连接数 | `10` |
| `MYSQL_CONN_MAX_LIFETIME` | 连接最大生命周期(秒) | `3600` |

### Web 服务数据库配置

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `MYSQL_WEB_HOST` | Web 数据库主机 | 使用 `MYSQL_HOST` |
| `MYSQL_WEB_PORT` | Web 数据库端口 | `3306` |
| `MYSQL_WEB_USER` | Web 数据库用户名 | 使用 `MYSQL_USER` |
| `MYSQL_WEB_PASSWORD` | Web 数据库密码 | 使用 `MYSQL_PASSWORD` |
| `MYSQL_WEB_DATABASE` | Web 数据库名称 | `etracee_web` |
| `ADMIN_USERNAME` | 管理员用户名 | `admin` |
| `ADMIN_PASSWORD` | 管理员密码 | `admin123` |
| `JWT_SECRET` | JWT 签名密钥 | (随机生成) |

### 通用 MySQL 配置（可被上面覆盖）

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `MYSQL_HOST` | MySQL 主机 | `localhost` |
| `MYSQL_PORT` | MySQL 端口 | `3306` |
| `MYSQL_USER` | MySQL 用户名 | `root` |
| `MYSQL_PASSWORD` | MySQL 密码 | (空) |

## 配置文件

### config/storage.yaml

```yaml
storage:
  backend: mysql

  # 监控程序数据库
  mysql:
    host: localhost
    port: 3306
    user: root
    password: ""
    database: etracee_events
    max_open_conns: 50
    max_idle_conns: 10
    conn_max_lifetime_seconds: 3600

  # 数据保留策略
  retention_days: 30
```

## 快速启动

### 1. 安装 MySQL

确保系统已安装 MySQL Community Server 8.0+。

```bash
# Ubuntu/Debian
sudo apt install -y mysql-server

# CentOS/RHEL
sudo yum install -y mysql-server
```

### 2. 创建数据库

```bash
# 登录 MySQL
mysql -u root -p

# 创建数据库和用户
CREATE DATABASE etracee_events CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE etracee_web CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

# 创建专用用户（推荐）
CREATE USER 'etracee_events'@'localhost' IDENTIFIED BY 'your_password';
CREATE USER 'etracee_web'@'localhost' IDENTIFIED BY 'your_password';

GRANT ALL PRIVILEGES ON etracee_events.* TO 'etracee_events'@'localhost';
GRANT ALL PRIVILEGES ON etracee_web.* TO 'etracee_web'@'localhost';
FLUSH PRIVILEGES;
```

### 3. 配置环境变量

```bash
# 监控程序数据库
export MYSQL_EVENTS_HOST=localhost
export MYSQL_EVENTS_USER=etracee_events
export MYSQL_EVENTS_PASSWORD=your_password

# Web 服务数据库
export MYSQL_WEB_HOST=localhost
export MYSQL_WEB_USER=etracee_web
export MYSQL_WEB_PASSWORD=your_password

# 管理员账户
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=your_secure_password

# JWT 密钥（生产环境必填）
export JWT_SECRET=your_random_secret_key_here
```

### 4. 启动服务

```bash
# 分离模式（推荐）
# 终端 1: 启动监控程序（需要 root）
sudo ./bin/etracee -monitor-only

# 终端 2: 启动 Web 服务（无需 root）
./bin/webserver
```

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
