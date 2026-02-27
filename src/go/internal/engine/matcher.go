package engine

import (
	"strings"
	"sync"
	"time"
)

// Matcher 条件匹配器
// 负责执行规则与事件的匹配，包含缓存优化
type Matcher struct {
	cache     map[string]bool // 匹配结果缓存
	cacheMu   sync.RWMutex    // 缓存读写锁
	cacheSize int             // 缓存大小限制
}

// NewMatcher 创建新的匹配器实例
func NewMatcher() *Matcher {
	return &Matcher{
		cache:     make(map[string]bool),
		cacheSize: 10000,
	}
}

// Match 对事件执行规则匹配
// 参数 event 为待匹配的事件数据
// 参数 rules 为已编译的规则列表
// 返回所有匹配的结果列表
func (m *Matcher) Match(event map[string]interface{}, rules []*CompiledRule) []*MatchResult {
	results := make([]*MatchResult, 0)

	for _, compiled := range rules {
		// 跳过无效或禁用的规则
		if compiled.ConditionAST == nil || !compiled.Original.Enabled {
			continue
		}

		// 执行条件匹配
		if compiled.ConditionAST.Evaluate(event) {
			results = append(results, &MatchResult{
				Rule:      compiled.Original,
				Timestamp: time.Now(),
				Event:     event,
			})
		}
	}

	return results
}

// GetCacheStats 获取缓存统计信息
// 返回缓存命中数和未命中数
func (m *Matcher) GetCacheStats() (hits, misses int) {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	return len(m.cache), 0
}

// ClearCache 清空匹配缓存
func (m *Matcher) ClearCache() {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	m.cache = make(map[string]bool)
}

// MatchResult 匹配结果
// 包含匹配的规则、时间戳和事件数据
type MatchResult struct {
	Rule      *UnifiedRule              // 匹配的规则
	Timestamp time.Time                 // 匹配时间戳
	Event     map[string]interface{}    // 匹配的事件数据
}

// WhitelistMatcher 白名单匹配器
// 用于快速排除不需要检测的事件
type WhitelistMatcher struct {
	processes map[string]bool // 进程白名单
	users     map[string]bool // 用户白名单
	files     map[string]bool // 文件路径白名单
	networks  map[string]bool // 网络地址白名单
}

// NewWhitelistMatcher 创建白名单匹配器
func NewWhitelistMatcher() *WhitelistMatcher {
	return &WhitelistMatcher{
		processes: make(map[string]bool),
		users:     make(map[string]bool),
		files:     make(map[string]bool),
		networks:  make(map[string]bool),
	}
}

// AddProcess 添加进程到白名单
// 参数 name 为进程名称（不区分大小写）
func (w *WhitelistMatcher) AddProcess(name string) {
	if name != "" {
		w.processes[strings.ToLower(name)] = true
	}
}

// AddUser 添加用户到白名单
// 参数 name 为用户名
func (w *WhitelistMatcher) AddUser(name string) {
	if name != "" {
		w.users[name] = true
	}
}

// AddFile 添加文件路径到白名单
// 参数 path 为文件路径
func (w *WhitelistMatcher) AddFile(path string) {
	if path != "" {
		w.files[path] = true
	}
}

// AddNetwork 添加网络地址到白名单
// 参数 network 为网络地址（格式：IP 或 IP:端口）
func (w *WhitelistMatcher) AddNetwork(network string) {
	if network != "" {
		w.networks[network] = true
	}
}

// IsWhitelisted 检查事件是否在白名单中
// 白名单中的事件将被跳过，不进行规则匹配
func (w *WhitelistMatcher) IsWhitelisted(event map[string]interface{}) bool {
	// 检查进程白名单
	if comm, ok := event["comm"].(string); ok {
		if w.processes[strings.ToLower(comm)] {
			return true
		}
	}

	// 检查文件路径白名单
	if filename, ok := event["filename"].(string); ok {
		for path := range w.files {
			if strings.Contains(filename, path) {
				return true
			}
		}
	}

	return false
}

// Clear 清空所有白名单
func (w *WhitelistMatcher) Clear() {
	w.processes = make(map[string]bool)
	w.users = make(map[string]bool)
	w.files = make(map[string]bool)
	w.networks = make(map[string]bool)
}
