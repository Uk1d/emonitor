# eTracee Web 认证配置说明

## 概述

eTracee Web 界面支持基于 MySQL 的用户认证功能。认证服务使用独立的数据库 (`etracee_web`)，与监控数据分离，可以独立运行在普通用户权限下。

## 架构说明

```
┌─────────────────────────────────────────┐
│      Web 服务 (普通用户权限)             │
│  ┌─────────────┐    ┌────────────────┐  │
│  │ 认证中间件  │    │  HTTP :8888    │  │
│  │             │    │  登录页面/API  │  │
│  └──────┬──────┘    └────────────────┘  │
│         │                                │
└─────────┼────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────┐
│         MySQL: etracee_web              │
│  ┌─────────────┐    ┌────────────────┐  │
│  │ users 表    │    │ sessions 表    │  │
│  │ (用户信息)  │    │ (会话信息)     │  │
│  └─────────────┘    └────────────────┘  │
└─────────────────────────────────────────┘
```

## 环境变量配置

认证服务通过以下环境变量进行配置：

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

### 通用 MySQL 配置

如果未设置专用环境变量，将使用通用配置：

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `MYSQL_HOST` | MySQL 服务器地址 | `localhost` |
| `MYSQL_PORT` | MySQL 端口 | `3306` |
| `MYSQL_USER` | MySQL 用户名 | `root` |
| `MYSQL_PASSWORD` | MySQL 密码 | (空) |

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

# 创建 Web 服务数据库
CREATE DATABASE IF NOT EXISTS etracee_web CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

# 创建专用用户（推荐）
CREATE USER 'etracee_web'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON etracee_web.* TO 'etracee_web'@'localhost';
FLUSH PRIVILEGES;
```

### 3. 配置环境变量

```bash
# Web 服务数据库配置
export MYSQL_WEB_HOST=localhost
export MYSQL_WEB_USER=etracee_web
export MYSQL_WEB_PASSWORD=your_password
export MYSQL_WEB_DATABASE=etracee_web

# 管理员账户
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=your_secure_password

# JWT 密钥（生产环境必填）
export JWT_SECRET=your_random_secret_key_here
```

### 4. 启动服务

**分离模式（推荐）**:

```bash
# 终端 1: 启动监控程序（需要 root）
sudo ./bin/etracee -monitor-only

# 终端 2: 启动 Web 服务（无需 root）
./bin/webserver
```

**集成模式**:

```bash
# 同时启动监控程序和 Web 服务（需要 root）
sudo ./bin/etracee
```

### 5. 访问 Web 界面

打开浏览器访问 `http://localhost:8888`，使用配置的账户登录：

- 用户名: 默认 `admin`
- 密码: 默认 `admin123`

## 用户角色

系统支持以下用户角色：

| 角色 | 权限 |
|------|------|
| `admin` | 完全访问权限，可管理用户和系统配置 |
| `user` | 标准用户，可查看事件和告警 |

## 会话管理

- 会话默认有效期: 24 小时
- 支持"记住登录"功能，有效期延长至 7 天
- JWT 密钥用于签名验证，服务重启后会话保持有效（需配置固定的 `JWT_SECRET`）

## 安全最佳实践

### 1. 修改默认密码

首次部署后立即修改默认管理员密码：

```bash
export ADMIN_PASSWORD=your_secure_password
```

### 2. 设置固定 JWT 密钥

配置固定的 JWT 密钥，确保服务重启后会话保持有效：

```bash
# 生成随机密钥
openssl rand -hex 32

# 设置环境变量
export JWT_SECRET=生成的随机密钥
```

### 3. 使用专用数据库用户

为 Web 服务创建专用的数据库用户，限制权限范围：

```sql
CREATE USER 'etracee_web'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON etracee_web.* TO 'etracee_web'@'localhost';
FLUSH PRIVILEGES;
```

### 4. 启用 HTTPS

在生产环境中配置 TLS 加密：

```bash
# 使用反向代理（如 Nginx）
# 或配置 Web 服务的 TLS 证书
```

### 5. 限制网络访问

通过防火墙限制数据库和 Web 端口的访问：

```bash
# 仅允许本地访问 MySQL
sudo ufw allow from 127.0.0.1 to any port 3306

# 限制 Web 端口访问
sudo ufw allow from 192.168.1.0/24 to any port 8888
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
    command: --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci

  monitor:
    build: .
    environment:
      MYSQL_EVENTS_HOST: mysql
      MYSQL_EVENTS_USER: root
      MYSQL_EVENTS_PASSWORD: your_root_password
    privileged: true
    command: ["./etracee", "-monitor-only"]

  webserver:
    build: .
    environment:
      MYSQL_WEB_HOST: mysql
      MYSQL_WEB_USER: root
      MYSQL_WEB_PASSWORD: your_root_password
      MYSQL_WEB_DATABASE: etracee_web
      ADMIN_USERNAME: admin
      ADMIN_PASSWORD: your_secure_password
      JWT_SECRET: your_random_secret_key_here
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

## 故障排除

### 认证服务初始化失败

检查以下项目：
1. MySQL 服务是否正在运行
2. 数据库连接参数是否正确
3. 数据库用户是否有足够的权限
4. 网络连接是否正常

查看日志输出中的错误信息，通常会显示具体的失败原因。

### 登录失败

1. 确认用户名和密码正确
2. 检查浏览器控制台是否有错误
3. 查看服务端日志获取详细错误信息
4. 确认 `etracee_web` 数据库中 `users` 表是否有数据

### 会话过期过快

1. 确认配置了固定的 `JWT_SECRET`
2. 检查系统时间是否正确
3. 清除浏览器缓存后重新登录

### 显示"认证服务未启用"

这表示 Web 服务无法连接到 MySQL 数据库。请：
1. 确认已设置 `MYSQL_WEB_HOST` 等环境变量
2. 确认 MySQL 服务正在运行
3. 确认 `etracee_web` 数据库已创建
4. 检查数据库用户权限

## API 端点

认证相关的 API 端点：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/login` | POST | 用户登录 |
| `/api/logout` | POST | 用户登出 |
| `/api/check-auth` | GET | 检查认证状态 |
| `/login` | GET | 登录页面 |

### 登录请求示例

```bash
curl -X POST http://localhost:8888/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}'
```

响应：
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires": "2026-02-28T12:00:00Z"
}
```
