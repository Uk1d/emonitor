# eTracee MySQL 数据库配置说明

## 概述

eTracee 使用 MySQL 作为主要数据存储，采用双数据库架构：

| 数据库 | 用途 | 默认名称 |
|--------|------|----------|
| 事件流数据库 | 存储 eBPF 事件和告警数据 | `etracee_events` |
| 认证数据库 | 存储 Web 认证用户和会话 | `etracee_auth` |

这种分离架构有以下优势：
- **性能隔离**：高频事件写入不影响认证服务
- **安全隔离**：认证数据与业务数据物理分离
- **独立扩展**：可根据负载情况独立优化各数据库

## 环境变量配置

### 事件流数据库配置

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `MYSQL_EVENTS_HOST` | 事件数据库主机 | `localhost` |
| `MYSQL_EVENTS_PORT` | 事件数据库端口 | `3306` |
| `MYSQL_EVENTS_USER` | 事件数据库用户名 | `root` |
| `MYSQL_EVENTS_PASSWORD` | 事件数据库密码 | (空) |
| `MYSQL_EVENTS_DATABASE` | 事件数据库名称 | `etracee_events` |
| `MYSQL_MAX_OPEN_CONNS` | 最大连接数 | `50` |
| `MYSQL_MAX_IDLE_CONNS` | 最大空闲连接数 | `10` |
| `MYSQL_CONN_MAX_LIFETIME` | 连接最大生命周期(秒) | `3600` |

### 认证数据库配置

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `MYSQL_AUTH_HOST` | 认证数据库主机 | 使用 `MYSQL_HOST` |
| `MYSQL_AUTH_PORT` | 认证数据库端口 | `3306` |
| `MYSQL_AUTH_USER` | 认证数据库用户名 | 使用 `MYSQL_USER` |
| `MYSQL_AUTH_PASSWORD` | 认证数据库密码 | 使用 `MYSQL_PASSWORD` |
| `MYSQL_AUTH_DATABASE` | 认证数据库名称 | `etracee_auth` |
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

### 其他配置

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `ETRACEE_RETENTION_DAYS` | 数据保留天数 | `30` |
| `ETRACEE_STORAGE_BACKEND` | 存储后端 | `mysql` |

## 快速启动

### 1. 安装 MySQL

确保系统已安装 MySQL Community Server 8.0+。

### 2. 创建数据库

```bash
# 登录 MySQL
mysql -u root -p

# 执行初始化脚本
source scripts/init_db.sql
```

### 3. 配置环境变量

```bash
# MySQL 连接配置
export MYSQL_HOST=localhost
export MYSQL_PORT=3306
export MYSQL_USER=root
export MYSQL_PASSWORD=your_password

# 管理员账户
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=your_secure_password

# JWT 密钥（生产环境必填）
export JWT_SECRET=your_random_secret_key_here
```

### 4. 启动服务

```bash
./etracee
```

### 5. 访问 Web 界面

打开浏览器访问 `http://localhost:8888`

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
      - ./scripts/init_db.sql:/docker-entrypoint-initdb.d/init_db.sql
    ports:
      - "3306:3306"
    command: --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci

  etracee:
    build: .
    environment:
      # MySQL 配置
      MYSQL_HOST: mysql
      MYSQL_PORT: 3306
      MYSQL_USER: root
      MYSQL_PASSWORD: your_root_password

      # 管理员账户
      ADMIN_USERNAME: admin
      ADMIN_PASSWORD: your_secure_password
      JWT_SECRET: your_random_secret_key_here

      # 数据保留
      ETRACEE_RETENTION_DAYS: 30
    depends_on:
      - mysql
    ports:
      - "8888:8888"
    privileged: true

volumes:
  mysql_data:
```

## YAML 配置文件

可以在 `config/storage.yaml` 中配置存储：

```yaml
storage:
  backend: mysql
  retention_days: 30
  mysql:
    host: localhost
    port: 3306
    user: root
    password: your_password
    database: etracee_events
    max_open_conns: 50
    max_idle_conns: 10
    conn_max_lifetime_seconds: 3600
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

### 性能问题

1. 检查索引是否正确创建
2. 调整连接池大小
3. 考虑分区表策略
4. 监控慢查询日志

### 磁盘空间

1. 调整数据保留天数
2. 定期清理过期数据
3. 考虑使用压缩表
