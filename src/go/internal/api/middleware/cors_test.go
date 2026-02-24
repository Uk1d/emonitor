package middleware

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestCORSAllowSameOrigin(t *testing.T) {
    mw := NewCORSMiddleware(map[string]struct{}{}, "")
    h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
    req := httptest.NewRequest("GET", "http://example.com/api/alerts", nil)
    req.Header.Set("Origin", "http://example.com")
    rr := httptest.NewRecorder()
    h.ServeHTTP(rr, req)
    if rr.Code != 200 {
        t.Fatalf("expected 200, got %d", rr.Code)
    }
    if rr.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
        t.Fatalf("missing allow origin header")
    }
}

func TestCORSForbiddenOriginProtectedPath(t *testing.T) {
    mw := NewCORSMiddleware(map[string]struct{}{}, "")
    h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
    req := httptest.NewRequest("GET", "http://server.local/api/alerts", nil)
    req.Header.Set("Origin", "http://evil.com")
    rr := httptest.NewRecorder()
    h.ServeHTTP(rr, req)
    if rr.Code != http.StatusForbidden {
        t.Fatalf("expected 403, got %d", rr.Code)
    }
}

func TestAuthRequired(t *testing.T) {
    mw := NewCORSMiddleware(map[string]struct{}{}, "secret")
    h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
    req := httptest.NewRequest("GET", "http://server.local/api/alerts", nil)
    rr := httptest.NewRecorder()
    h.ServeHTTP(rr, req)
    if rr.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d", rr.Code)
    }

    req2 := httptest.NewRequest("GET", "http://server.local/api/alerts", nil)
    req2.Header.Set("Authorization", "Bearer secret")
    rr2 := httptest.NewRecorder()
    h.ServeHTTP(rr2, req2)
    if rr2.Code != 200 {
        t.Fatalf("expected 200, got %d", rr2.Code)
    }
}

