package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// User 用户模型
type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
	Expires int64  `json:"expires,omitempty"`
}

// Session 会话信息
type Session struct {
	Token     string
	UserID    int
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuthService 认证服务
type AuthService struct {
	db            *sql.DB
	sessions      map[string]*Session
	sessionsMutex sync.RWMutex
	jwtSecret     []byte
	tokenExpiry   time.Duration
	adminUsername string
	adminPassword string
	initialized   bool
}

// Config 认证配置
type Config struct {
	MySQLHost     string
	MySQLPort     int
	MySQLUser     string
	MySQLPassword string
	MySQLDatabase string
	AdminUsername string
	AdminPassword string
	JWTSecret     string
	TokenExpiry   time.Duration
}

var (
	authService *AuthService
	authOnce    sync.Once
)

// InitAuth 初始化认证服务
func InitAuth(cfg *Config) (*AuthService, error) {
	var initErr error
	authOnce.Do(func() {
		// 先尝试创建数据库（如果不存在）
		dsnWithoutDB := fmt.Sprintf("%s:%s@tcp(%s:%d)/?parseTime=true&charset=utf8mb4",
			cfg.MySQLUser,
			cfg.MySQLPassword,
			cfg.MySQLHost,
			cfg.MySQLPort,
		)

		tmpDB, err := sql.Open("mysql", dsnWithoutDB)
		if err != nil {
			initErr = fmt.Errorf("连接MySQL失败: %w", err)
			return
		}

		// 创建数据库（如果不存在）
		_, err = tmpDB.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", cfg.MySQLDatabase))
		if err != nil {
			tmpDB.Close()
			initErr = fmt.Errorf("创建数据库失败: %w", err)
			return
		}
		tmpDB.Close()
		log.Printf("[+] 数据库 '%s' 已就绪", cfg.MySQLDatabase)

		// 连接到目标数据库
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4",
			cfg.MySQLUser,
			cfg.MySQLPassword,
			cfg.MySQLHost,
			cfg.MySQLPort,
			cfg.MySQLDatabase,
		)

		db, err := sql.Open("mysql", dsn)
		if err != nil {
			initErr = fmt.Errorf("连接MySQL失败: %w", err)
			return
		}

		// 设置连接池
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(time.Hour)

		// 测试连接
		if err := db.Ping(); err != nil {
			db.Close()
			initErr = fmt.Errorf("MySQL连接测试失败: %w", err)
			return
		}

		// 生成或使用JWT密钥
		jwtSecret := []byte(cfg.JWTSecret)
		if len(jwtSecret) == 0 {
			jwtSecret = generateSecret()
		}

		// 创建临时服务对象进行初始化
		svc := &AuthService{
			db:            db,
			sessions:      make(map[string]*Session),
			jwtSecret:     jwtSecret,
			tokenExpiry:   cfg.TokenExpiry,
			adminUsername: cfg.AdminUsername,
			adminPassword: cfg.AdminPassword,
		}

		// 初始化数据库表
		if err := svc.initTables(); err != nil {
			db.Close()
			initErr = fmt.Errorf("初始化数据库表失败: %w", err)
			return
		}

		// 初始化管理员账户
		if err := svc.initAdminUser(); err != nil {
			db.Close()
			initErr = fmt.Errorf("初始化管理员账户失败: %w", err)
			return
		}

		svc.initialized = true
		authService = svc
		log.Println("[*] 认证服务初始化完成")
	})

	return authService, initErr
}

// GetAuthService 获取认证服务实例
func GetAuthService() *AuthService {
	return authService
}

// initTables 初始化数据库表
func (a *AuthService) initTables() error {
	// 创建用户表
	_, err := a.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
	`)
	if err != nil {
		return err
	}

	// 创建会话表（用于持久化会话，可选）
	_, err = a.db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id INT AUTO_INCREMENT PRIMARY KEY,
			token VARCHAR(64) NOT NULL UNIQUE,
			user_id INT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
	`)
	return err
}

// initAdminUser 初始化管理员用户
func (a *AuthService) initAdminUser() error {
	// 检查管理员是否存在
	var count int
	err := a.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", a.adminUsername).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("[*] 管理员账户 '%s' 已存在", a.adminUsername)
		return nil
	}

	// 创建管理员账户
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(a.adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = a.db.Exec(
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		a.adminUsername, string(passwordHash),
	)
	if err != nil {
		return err
	}

	log.Printf("[*] 管理员账户 '%s' 创建成功", a.adminUsername)
	return nil
}

// Login 用户登录
func (a *AuthService) Login(username, password string) (*LoginResponse, error) {
	// 查询用户
	var user User
	var lastLoginNull sql.NullTime // 处理可能为 NULL 的 last_login 字段
	err := a.db.QueryRow(
		"SELECT id, username, password_hash, created_at, last_login FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &lastLoginNull)

	if err == sql.ErrNoRows {
		return &LoginResponse{
			Success: false,
			Message: "用户名或密码错误",
		}, nil
	}
	if err != nil {
		log.Printf("[!] 查询用户失败 (username=%s): %v", username, err)
		return nil, fmt.Errorf("数据库查询失败: %w", err)
	}

	// 处理 NULL 值
	if lastLoginNull.Valid {
		user.LastLogin = lastLoginNull.Time
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return &LoginResponse{
			Success: false,
			Message: "用户名或密码错误",
		}, nil
	}

	// 生成令牌
	token := generateToken()
	expiresAt := time.Now().Add(a.tokenExpiry)

	// 创建会话
	session := &Session{
		Token:     token,
		UserID:    user.ID,
		Username:  user.Username,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	// 存储会话
	a.sessionsMutex.Lock()
	a.sessions[token] = session
	a.sessionsMutex.Unlock()

	// 更新最后登录时间
	go a.db.Exec("UPDATE users SET last_login = NOW() WHERE id = ?", user.ID)

	return &LoginResponse{
		Success: true,
		Token:   token,
		Message: "登录成功",
		Expires: expiresAt.Unix(),
	}, nil
}

// Logout 用户登出
func (a *AuthService) Logout(token string) error {
	a.sessionsMutex.Lock()
	delete(a.sessions, token)
	a.sessionsMutex.Unlock()
	return nil
}

// ValidateToken 验证令牌
func (a *AuthService) ValidateToken(token string) (*Session, error) {
	a.sessionsMutex.RLock()
	session, exists := a.sessions[token]
	a.sessionsMutex.RUnlock()

	if !exists {
		return nil, errors.New("无效的令牌")
	}

	if time.Now().After(session.ExpiresAt) {
		a.sessionsMutex.Lock()
		delete(a.sessions, token)
		a.sessionsMutex.Unlock()
		return nil, errors.New("令牌已过期")
	}

	return session, nil
}

// CleanExpiredSessions 清理过期会话
func (a *AuthService) CleanExpiredSessions() {
	a.sessionsMutex.Lock()
	defer a.sessionsMutex.Unlock()

	now := time.Now()
	for token, session := range a.sessions {
		if now.After(session.ExpiresAt) {
			delete(a.sessions, token)
		}
	}
}

// HandleLogin 处理登录请求
func (a *AuthService) HandleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "方法不允许",
		})
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "无效的请求",
		})
		return
	}

	resp, err := a.Login(req.Username, req.Password)
	if err != nil {
		log.Printf("[!] 登录处理错误: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "服务器内部错误，请稍后重试",
		})
		return
	}

	json.NewEncoder(w).Encode(resp)
}

// HandleLogout 处理登出请求
func (a *AuthService) HandleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token != "" {
		a.Logout(token)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// HandleCheckAuth 检查认证状态
func (a *AuthService) HandleCheckAuth(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
			"message":       "未提供令牌",
		})
		return
	}

	session, err := a.ValidateToken(token)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
			"message":       err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      session.Username,
		"expires":       session.ExpiresAt.Unix(),
	})
}

// Middleware 认证中间件
func (a *AuthService) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 跳过登录相关路径
		if r.URL.Path == "/api/login" ||
			r.URL.Path == "/api/logout" ||
			r.URL.Path == "/api/check-auth" ||
			r.URL.Path == "/login" ||
			strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		// 对于 HTML 页面请求，放行让前端 JavaScript 处理认证检查
		// 这避免了浏览器请求 HTML 时不带 Authorization header 导致的重定向循环
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			next.ServeHTTP(w, r)
			return
		}

		// 对于 API 请求，需要验证 token
		token := extractToken(r)
		if token == "" {
			http.Error(w, `{"error": "未授权访问"}`, http.StatusUnauthorized)
			return
		}

		session, err := a.ValidateToken(token)
		if err != nil {
			http.Error(w, `{"error": "令牌无效或已过期"}`, http.StatusUnauthorized)
			return
		}

		// 将用户信息添加到请求上下文
		r.Header.Set("X-User-ID", fmt.Sprintf("%d", session.UserID))
		r.Header.Set("X-Username", session.Username)

		next.ServeHTTP(w, r)
	})
}

// extractToken 从请求中提取令牌
func extractToken(r *http.Request) string {
	// 从Authorization头提取
	auth := r.Header.Get("Authorization")
	if auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
		return auth
	}

	// 从Cookie提取
	if cookie, err := r.Cookie("auth_token"); err == nil {
		return cookie.Value
	}

	// 从URL参数提取
	return r.URL.Query().Get("token")
}

// generateToken 生成随机令牌
func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateSecret 生成随机密钥
func generateSecret() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

// Close 关闭认证服务
func (a *AuthService) Close() error {
	if a.db != nil {
		return a.db.Close()
	}
	return nil
}

// GetAuthFromEnv 从环境变量获取认证配置
// 使用独立的 Web 数据库 (etracee_web) 存储用户和会话信息
func GetAuthFromEnv() *Config {
	return &Config{
		MySQLHost:     getEnv("MYSQL_WEB_HOST", getEnv("MYSQL_HOST", "localhost")),
		MySQLPort:     3306,
		MySQLUser:     getEnv("MYSQL_WEB_USER", getEnv("MYSQL_USER", "root")),
		MySQLPassword: getEnv("MYSQL_WEB_PASSWORD", getEnv("MYSQL_PASSWORD", "")),
		MySQLDatabase: getEnv("MYSQL_WEB_DATABASE", "etracee_web"),
		AdminUsername: getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword: getEnv("ADMIN_PASSWORD", "admin123"),
		JWTSecret:     getEnv("JWT_SECRET", ""),
		TokenExpiry:   24 * time.Hour,
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
