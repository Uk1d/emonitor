package rule

import (
	"log"
	"sync"
	"time"
)

type Engine struct {
	mu            sync.RWMutex
	ruleSets      map[string]*RuleSet
	compiledRules []*CompiledRule
	index         *RuleIndex
	matcher       *Matcher
	whitelist     *WhitelistMatcher
	stats         *EngineStats
	config        *EngineConfig
}

type EngineConfig struct {
	EnableStats     bool
	MaxHistory      int
	DefaultThrottle time.Duration
}

type EngineStats struct {
	mu              sync.RWMutex
	TotalMatches    uint64
	SuccessfulMatch uint64
	RuleHits        map[string]uint64
	AvgMatchTime    time.Duration
}

func NewEngine(config *EngineConfig) *Engine {
	if config == nil {
		config = &EngineConfig{
			EnableStats:     true,
			MaxHistory:      1000,
			DefaultThrottle: 60 * time.Second,
		}
	}

	return &Engine{
		ruleSets:  make(map[string]*RuleSet),
		matcher:   NewMatcher(),
		whitelist: NewWhitelistMatcher(),
		stats: &EngineStats{
			RuleHits: make(map[string]uint64),
		},
		config: config,
	}
}

func (e *Engine) LoadRuleSet(rs *RuleSet) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.ruleSets[rs.Name] = rs
	e.rebuildIndex()

	log.Printf("Loaded rule set '%s' with %d rules", rs.Name, len(rs.Rules))
	return nil
}

func (e *Engine) LoadRulesFromSource(source RuleSource, data []byte) error {
	switch source {
	case SourceFalco:
		return e.loadFalcoRules(data)
	case SourceTracee:
		return e.loadTraceeRules(data)
	default:
		return e.loadNativeRules(data)
	}
}

func (e *Engine) loadFalcoRules(data []byte) error {
	return nil
}

func (e *Engine) loadTraceeRules(data []byte) error {
	return nil
}

func (e *Engine) loadNativeRules(data []byte) error {
	return nil
}

func (e *Engine) rebuildIndex() {
	allRules := make([]*UnifiedRule, 0)
	for _, rs := range e.ruleSets {
		allRules = append(allRules, rs.GetEnabledRules()...)
	}

	e.compiledRules = make([]*CompiledRule, 0, len(allRules))
	for _, r := range allRules {
		compiled, err := r.Compile()
		if err != nil {
			log.Printf("Failed to compile rule %s: %v", r.Name, err)
			continue
		}
		e.compiledRules = append(e.compiledRules, compiled)
	}

	e.index = BuildRuleIndex(allRules)
	log.Printf("Rebuilt rule index with %d compiled rules", len(e.compiledRules))
}

func (e *Engine) Match(event map[string]interface{}) []*MatchResult {
	startTime := time.Now()
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.whitelist.IsWhitelisted(event) {
		return nil
	}

	results := make([]*MatchResult, 0)

	for _, compiled := range e.compiledRules {
		if compiled.ConditionAST == nil || !compiled.Original.Enabled {
			continue
		}

		if e.isThrottled(compiled) {
			continue
		}

		if compiled.ConditionAST.Evaluate(event) {
			compiled.TriggerCount++
			compiled.LastTriggered = time.Now()

			results = append(results, &MatchResult{
				Rule:      compiled.Original,
				Timestamp: time.Now(),
				Event:     event,
			})

			if e.config.EnableStats {
				e.recordMatch(compiled.Original.Name, time.Since(startTime))
			}
		}
	}

	return results
}

func (e *Engine) isThrottled(compiled *CompiledRule) bool {
	if compiled.Original.Throttle == 0 {
		return false
	}
	return time.Since(compiled.LastTriggered) < compiled.Original.Throttle
}

func (e *Engine) recordMatch(ruleName string, duration time.Duration) {
	e.stats.mu.Lock()
	defer e.stats.mu.Unlock()

	e.stats.TotalMatches++
	e.stats.SuccessfulMatch++
	e.stats.RuleHits[ruleName]++

	if e.stats.TotalMatches == 1 {
		e.stats.AvgMatchTime = duration
	} else {
		total := int64(e.stats.AvgMatchTime) * int64(e.stats.TotalMatches-1)
		e.stats.AvgMatchTime = time.Duration((total + int64(duration)) / int64(e.stats.TotalMatches))
	}
}

func (e *Engine) GetStats() *EngineStats {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()

	return &EngineStats{
		TotalMatches:    e.stats.TotalMatches,
		SuccessfulMatch: e.stats.SuccessfulMatch,
		RuleHits:        e.stats.RuleHits,
		AvgMatchTime:    e.stats.AvgMatchTime,
	}
}

func (e *Engine) GetRules() []*UnifiedRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]*UnifiedRule, 0, len(e.compiledRules))
	for _, compiled := range e.compiledRules {
		rules = append(rules, compiled.Original)
	}
	return rules
}

func (e *Engine) GetRuleByID(id string) *UnifiedRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, compiled := range e.compiledRules {
		if compiled.Original.ID == id {
			return compiled.Original
		}
	}
	return nil
}

func (e *Engine) EnableRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, compiled := range e.compiledRules {
		if compiled.Original.ID == id {
			compiled.Original.Enabled = true
			return true
		}
	}
	return false
}

func (e *Engine) DisableRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, compiled := range e.compiledRules {
		if compiled.Original.ID == id {
			compiled.Original.Enabled = false
			return true
		}
	}
	return false
}

func (e *Engine) GetWhitelist() *WhitelistMatcher {
	return e.whitelist
}
