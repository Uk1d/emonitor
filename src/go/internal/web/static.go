// Package web 提供 Web 静态资源服务
// 该包使用 Go 1.16+ 的 embed 功能将静态文件嵌入到二进制文件中
package web

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// staticFS 通过 go:embed 指令将 static 目录下的所有文件嵌入到二进制文件中
// 这样在部署时无需额外携带静态文件，简化了分发和部署流程
//
//go:embed static/*
var staticFS embed.FS

// rooted 是剥离了 "static" 前缀后的文件系统
// 便于直接通过文件名访问资源，而无需每次都处理前缀
var rooted fs.FS

// init 初始化函数，在包加载时自动执行
// 主要职责是从嵌入的文件系统中提取静态资源子目录
func init() {
	// 从 staticFS 中提取 "static" 子目录
	// 这样访问 "index.html" 就可以直接用 rooted.Open("index.html")
	// 而不是 rooted.Open("static/index.html")
	sub, err := fs.Sub(staticFS, "static")
	if err == nil {
		rooted = sub
	} else {
		// 如果提取失败，回退使用原始文件系统
		// 这种情况理论上不应该发生，除非 embed 配置有问题
		rooted = staticFS
	}
}

// Handler 返回一个处理静态资源请求的 HTTP Handler
// 该 Handler 实现了单页应用(SPA)的路由策略：
//   - 所有静态文件请求（有扩展名）直接返回文件内容
//   - 所有路由请求（无扩展名）返回 index.html，由前端路由处理
//   - 自动规范化 URL 路径，处理重复斜杠等情况
//
// 使用示例：
//
//	mux := http.NewServeMux()
//	mux.Handle("/", web.Handler())
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 获取请求路径
		p := r.URL.Path

		// 规范化路径：移除重复的斜杠
		// 例如 "//api//users" -> "/api/users"
		for strings.Contains(p, "//") {
			p = strings.ReplaceAll(p, "//", "/")
		}

		// 移除前导斜杠，便于后续处理
		p = strings.TrimPrefix(p, "/")

		// 处理空路径和根路径
		if p == "" || p == "/" {
			p = "index.html"
		}

		// 移除尾部斜杠
		if strings.HasSuffix(p, "/") {
			p = "index.html"
		}

		// 单页应用路由策略：
		// 如果路径中没有点号(扩展名)，说明是前端路由，返回 index.html
		// 例如 "/dashboard"、"/alerts/123" 等都返回 index.html
		if !strings.Contains(p, ".") {
			p = "index.html"
		}

		// 清理路径，防止目录遍历攻击
		// path.Clean 会处理 ".." 等危险路径组件
		f := path.Clean(p)

		// 尝试读取请求的文件
		b, err := fs.ReadFile(rooted, f)
		if err != nil {
			// 文件不存在时，回退到 index.html
			// 这是单页应用的标准做法，确保前端路由可以正常工作
			f = "index.html"
			b, _ = fs.ReadFile(rooted, f)
		}

		// 设置正确的 Content-Type 响应头
		// 根据文件扩展名自动推断 MIME 类型
		if ct := mime.TypeByExtension(path.Ext(f)); ct != "" {
			w.Header().Set("Content-Type", ct)
		} else {
			// 无法推断时，默认使用 HTML 类型
			// 并显式指定 UTF-8 编码，确保中文正确显示
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}

		// 写入响应内容
		w.Write(b)
	})
}
