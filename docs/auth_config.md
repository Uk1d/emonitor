# eTracee Web 认证配置说明

## 概述

eTracee Web 界面支持基于 MySQL 的用户认证功能。默认配置下，系统会创建一个管理员账户。

## 环境变量配置

认证服务通过以下环境变量进行配置：

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `MYSQL_HOST` | MySQL 服务器地址 | `localhost` |
| `MYSQL_PORT` | MySQL 端口 | `3306` |
| `MYSQL_USER` | MySQL 用户名 | `root` |
| `MYSQL_PASSWORD` | MySQL 密码 | (空) |
| `MYSQL_DATABASE` | 数据库名称 | `etracee` |
| `ADMIN_USERNAME` | 管理员用户名 | `admin` |
| `ADMIN_PASSWORD` | 管理员密码 | `admin123` |
| `JWT_SECRET` | JWT 签名密钥 | (随机生成) |

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

或者手动创建：

```sql
CREATE DATABASE IF NOT EXISTS etracee CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 3. 配置环境变量

```bash
export MYSQL_HOST=localhost
export MYSQL_PORT=3306
export MYSQL_USER=root
export MYSQL_PASSWORD=your_password
export MYSQL_DATABASE=etracee
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=admin123
```

### 4. 启动服务

```bash
./etracee
```

### 5. 访问 Web 界面

打开浏览器访问 `http://localhost:8888`，使用默认账户登录：

- 用户名: `admin`
- 密码: `admin123`

## 生产环境建议

1. **修改默认密码**：首次登录后立即修改默认密码
2. **设置强密码**：使用复杂的密码组合
3. **配置 JWT_SECRET**：设置固定的 JWT 密钥以便服务重启后会话保持有效
4. **启用 TLS**：在生产环境中配置 HTTPS
5. **限制访问**：通过防火墙限制数据库和 Web 端口的访问

## Docker Compose 示例

```yaml
version: '3.8'
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: your_root_password
      MYSQL_DATABASE: etracee
    volumes:
      - mysql_data:/var/lib/mysql
      - ./scripts/init_db.sql:/docker-entrypoint-initdb.d/init_db.sql
    ports:
      - "3306:3306"

  etracee:
    build: .
    environment:
      MYSQL_HOST: mysql
      MYSQL_PORT: 3306
      MYSQL_USER: root
      MYSQL_PASSWORD: your_root_password
      MYSQL_DATABASE: etracee
      ADMIN_USERNAME: admin
      ADMIN_PASSWORD: your_secure_password
      JWT_SECRET: your_random_secret_key_here
    depends_on:
      - mysql
    ports:
      - "8888:8888"
    privileged: true

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

### 登录失败

1. 确认用户名和密码正确
2. 检查浏览器控制台是否有错误
3. 查看服务端日志获取详细错误信息

### 会话过期

默认会话有效期为 24 小时。可以在代码中修改 `TokenExpiry` 配置。
