-- eTracee 认证数据库初始化脚本
-- 数据库名: etracee (需先创建或通过环境变量配置)

-- 如果数据库不存在则创建
CREATE DATABASE IF NOT EXISTS etracee CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE etracee;

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 会话表（可选，用于持久化会话）
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) NOT NULL UNIQUE,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 注意：管理员账户由程序自动创建
-- 默认账户: admin / admin123
-- 请在生产环境中修改默认密码！
