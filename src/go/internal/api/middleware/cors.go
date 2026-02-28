// Package middleware 提供 HTTP 中间件功能
// 包含 CORS 跨域处理和 API 认证等中间件
package middleware

import (
	"net/http"
	"net/url"
	"strings"
)

// CORSMiddleware CORS 跨域中间件
// 处理跨域请求、预检请求和 API 认证
type CORSMiddleware struct {
	AllowedOrigins map[string]struct{} // 允许的来源域名集合
	APIToken       string              // API 认证令牌
	RequireAuth    bool                // 是否需要认证
}

// NewCORSMiddleware 创建 CORS 中间件实例
// 参数 allowedOrigins 为允许跨域访问的域名集合
// 参数 apiToken 为 API 认证令牌，空字符串表示无需认证
func NewCORSMiddleware(allowedOrigins map[string]struct{}, apiToken string) *CORSMiddleware {
	return &CORSMiddleware{
		AllowedOrigins: allowedOrigins,
		APIToken:       strings.TrimSpace(apiToken),
		RequireAuth:    strings.TrimSpace(apiToken) != "",
	}
}

// Wrap 包装 HTTP Handler，添加 CORS 和认证功能
// 处理流程：
//  1. 检查请求来源是否在白名单中
//  2. 设置 CORS 响应头
//  3. 处理 OPTIONS 预检请求
//  4. 验证 API 认证令牌（如果需要）
func (m *CORSMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if m.isOriginAllowed(origin, r) {
				// 来源允许，设置 CORS 头
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			} else {
				// 来源不允许
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if m.isProtectedPath(r.URL.Path) {
					http.Error(w, "禁止访问：来源域名未被授权", http.StatusForbidden)
					return
				}
			}
		}

		// 设置 CORS 允许的方法和头部
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Sec-WebSocket-Protocol")

		// 处理 OPTIONS 预检请求
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// 验证认证令牌（如果需要）
		if m.RequireAuth && m.isProtectedPath(r.URL.Path) && !m.isAuthorized(r) {
			http.Error(w, "未授权：请提供有效的认证令牌", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CheckOrigin 检查请求来源是否被允许
// 用于 WebSocket 连接的来源验证
func (m *CORSMiddleware) CheckOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return m.isOriginAllowed(origin, r)
}

// isOriginAllowed 检查指定来源是否在允许列表中
// 允许规则：
//   - 空来源直接允许
//   - 在白名单中的域名
//   - 与请求主机相同的域名
//   - 本地开发环境（127.0.0.1 或 localhost）
func (m *CORSMiddleware) isOriginAllowed(origin string, r *http.Request) bool {
	if origin == "" {
		return true
	}

	// 检查白名单
	if m.AllowedOrigins != nil {
		if _, ok := m.AllowedOrigins[origin]; ok {
			return true
		}
	}

	// 解析来源 URL 并检查主机
	if u, err := url.Parse(origin); err == nil {
		host := u.Host

		// 与请求主机完全匹配
		if host == r.Host {
			return true
		}

		// 去除端口后比较主机名
		requestHost := r.Host
		if strings.Contains(requestHost, ":") {
			requestHost = strings.Split(requestHost, ":")[0]
		}
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		if host == requestHost {
			return true
		}

		// 允许本地开发环境
		if host == "127.0.0.1" || host == "localhost" {
			return true
		}
	}
	return false
}

// isProtectedPath 检查路径是否为受保护的 API 路径
// 受保护的路径包括：/api/* 等
// 注意：/ws 路径使用 JWT 认证系统，不在此处检查
func (m *CORSMiddleware) isProtectedPath(path string) bool {
	if strings.HasPrefix(path, "/api/") || path == "/api" {
		return true
	}
	return false
}

// isAuthorized 检查请求是否已授权
// 支持多种认证方式：
//   - Authorization: Bearer <token>
//   - URL 查询参数: ?token=<token>
//   - WebSocket 子协议: Sec-WebSocket-Protocol 头部
func (m *CORSMiddleware) isAuthorized(r *http.Request) bool {
	if !m.RequireAuth {
		return true
	}

	// 方式一：Authorization Bearer Token
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		t := strings.TrimSpace(auth[7:])
		if t == m.APIToken {
			return true
		}
	}

	// 方式二：URL 查询参数 token
	if t := strings.TrimSpace(r.URL.Query().Get("token")); t != "" && t == m.APIToken {
		return true
	}

	// 方式三：WebSocket 子协议认证
	if sp := r.Header.Get("Sec-WebSocket-Protocol"); sp != "" {
		for _, part := range strings.Split(sp, ",") {
			p := strings.TrimSpace(part)
			// 直接匹配令牌
			if strings.EqualFold(p, m.APIToken) {
				return true
			}
			// Bearer 格式令牌
			if strings.HasPrefix(strings.ToLower(p), "bearer ") {
				t := strings.TrimSpace(p[7:])
				if t == m.APIToken {
					return true
				}
			}
		}
	}
	return false
}
