package rule

import (
	"strings"
	"sync"
	"time"
)

type Matcher struct {
	cache     map[string]bool
	cacheMu   sync.RWMutex
	cacheSize int
}

func NewMatcher() *Matcher {
	return &Matcher{
		cache:     make(map[string]bool),
		cacheSize: 10000,
	}
}

func (m *Matcher) Match(event map[string]interface{}, rules []*CompiledRule) []*MatchResult {
	results := make([]*MatchResult, 0)

	for _, compiled := range rules {
		if compiled.ConditionAST == nil || !compiled.Original.Enabled {
			continue
		}

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

func (m *Matcher) GetCacheStats() (hits, misses int) {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	return len(m.cache), 0
}

func (m *Matcher) ClearCache() {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	m.cache = make(map[string]bool)
}

type MatchResult struct {
	Rule      *UnifiedRule
	Timestamp time.Time
	Event     map[string]interface{}
}

type WhitelistMatcher struct {
	processes map[string]bool
	users     map[string]bool
	files     map[string]bool
	networks  map[string]bool
}

func NewWhitelistMatcher() *WhitelistMatcher {
	return &WhitelistMatcher{
		processes: make(map[string]bool),
		users:     make(map[string]bool),
		files:     make(map[string]bool),
		networks:  make(map[string]bool),
	}
}

func (w *WhitelistMatcher) AddProcess(name string) {
	if name != "" {
		w.processes[strings.ToLower(name)] = true
	}
}

func (w *WhitelistMatcher) AddUser(name string) {
	if name != "" {
		w.users[name] = true
	}
}

func (w *WhitelistMatcher) AddFile(path string) {
	if path != "" {
		w.files[path] = true
	}
}

func (w *WhitelistMatcher) AddNetwork(network string) {
	if network != "" {
		w.networks[network] = true
	}
}

func (w *WhitelistMatcher) IsWhitelisted(event map[string]interface{}) bool {
	if comm, ok := event["comm"].(string); ok {
		if w.processes[strings.ToLower(comm)] {
			return true
		}
	}

	if filename, ok := event["filename"].(string); ok {
		for path := range w.files {
			if strings.Contains(filename, path) {
				return true
			}
		}
	}

	return false
}

func (w *WhitelistMatcher) Clear() {
	w.processes = make(map[string]bool)
	w.users = make(map[string]bool)
	w.files = make(map[string]bool)
	w.networks = make(map[string]bool)
}
