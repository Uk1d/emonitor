package web

import (
    "embed"
    "io/fs"
    "mime"
    "net/http"
    "path"
    "strings"
)

//go:embed static/*
var staticFS embed.FS

var rooted fs.FS

func init() {
    sub, err := fs.Sub(staticFS, "static")
    if err == nil {
        rooted = sub
    } else {
        rooted = staticFS
    }
}

func Handler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        p := r.URL.Path
        for strings.Contains(p, "//") { p = strings.ReplaceAll(p, "//", "/") }
        p = strings.TrimPrefix(p, "/")
        if p == "" || p == "/" { p = "index.html" }
        if strings.HasSuffix(p, "/") { p = "index.html" }
        if !strings.Contains(p, ".") { p = "index.html" }
        f := path.Clean(p)
        b, err := fs.ReadFile(rooted, f)
        if err != nil {
            f = "index.html"
            b, _ = fs.ReadFile(rooted, f)
        }
        if ct := mime.TypeByExtension(path.Ext(f)); ct != "" {
            w.Header().Set("Content-Type", ct)
        } else {
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
        }
        w.Write(b)
    })
}