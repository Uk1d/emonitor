package middleware

import (
    "net/http"
    "net/url"
    "strings"
)

type CORSMiddleware struct {
    AllowedOrigins map[string]struct{}
    APIToken       string
    RequireAuth    bool
}

func NewCORSMiddleware(allowedOrigins map[string]struct{}, apiToken string) *CORSMiddleware {
    return &CORSMiddleware{
        AllowedOrigins: allowedOrigins,
        APIToken:       strings.TrimSpace(apiToken),
        RequireAuth:    strings.TrimSpace(apiToken) != "",
    }
}

func (m *CORSMiddleware) Wrap(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        if origin != "" {
            if m.isOriginAllowed(origin, r) {
                w.Header().Set("Access-Control-Allow-Origin", origin)
                w.Header().Set("Vary", "Origin")
            } else {
                if r.Method == http.MethodOptions {
                    w.WriteHeader(http.StatusNoContent)
                    return
                }
                if m.isProtectedPath(r.URL.Path) {
                    http.Error(w, "Forbidden origin", http.StatusForbidden)
                    return
                }
            }
        }

        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Sec-WebSocket-Protocol")

        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }

        if m.RequireAuth && m.isProtectedPath(r.URL.Path) && !m.isAuthorized(r) {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func (m *CORSMiddleware) CheckOrigin(r *http.Request) bool {
    origin := r.Header.Get("Origin")
    if origin == "" {
        return true
    }
    return m.isOriginAllowed(origin, r)
}

func (m *CORSMiddleware) isOriginAllowed(origin string, r *http.Request) bool {
    if origin == "" {
        return true
    }
    if m.AllowedOrigins != nil {
        if _, ok := m.AllowedOrigins[origin]; ok {
            return true
        }
    }
    if u, err := url.Parse(origin); err == nil {
        host := u.Host
        if host == r.Host {
            return true
        }
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
        if host == "127.0.0.1" || host == "localhost" {
            return true
        }
    }
    return false
}

func (m *CORSMiddleware) isProtectedPath(path string) bool {
    if path == "/ws" {
        return true
    }
    if strings.HasPrefix(path, "/api/") || path == "/api" {
        return true
    }
    return false
}

func (m *CORSMiddleware) isAuthorized(r *http.Request) bool {
    if !m.RequireAuth {
        return true
    }
    auth := strings.TrimSpace(r.Header.Get("Authorization"))
    if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
        t := strings.TrimSpace(auth[7:])
        if t == m.APIToken {
            return true
        }
    }
    if t := strings.TrimSpace(r.URL.Query().Get("token")); t != "" && t == m.APIToken {
        return true
    }
    if sp := r.Header.Get("Sec-WebSocket-Protocol"); sp != "" {
        for _, part := range strings.Split(sp, ",") {
            p := strings.TrimSpace(part)
            if strings.EqualFold(p, m.APIToken) {
                return true
            }
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
