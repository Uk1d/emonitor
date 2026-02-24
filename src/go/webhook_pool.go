package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type WebhookConfig struct {
	URL           string
	Method        string
	Headers       map[string]string
	Timeout       time.Duration
	Secret        string
	Retry         int
	MaxConcurrent int
	BufferSize    int
}

type WebhookPool struct {
	config   *WebhookConfig
	client   *http.Client
	queue    chan *WebhookTask
	wg       sync.WaitGroup
	stopOnce sync.Once
	stopChan chan struct{}
	stats    WebhookStats
}

type WebhookTask struct {
	Alert     *ManagedAlert
	Timestamp time.Time
	Retry     int
}

type WebhookStats struct {
	Sent     uint64
	Failed   uint64
	Retried  uint64
	Dropped  uint64
	AvgLatMs uint64
}

type WebhookPayload struct {
	AlertID     string                 `json:"alert_id"`
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	Description string                 `json:"description"`
	Timestamp   string                 `json:"timestamp"`
	Event       map[string]interface{} `json:"event,omitempty"`
	MitreAttack *MITRETechnique        `json:"mitre_attack,omitempty"`
	Actions     []string               `json:"actions,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func NewWebhookPool(config *WebhookConfig) *WebhookPool {
	if config == nil {
		return nil
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 5
	}
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	if config.Method == "" {
		config.Method = "POST"
	}

	pool := &WebhookPool{
		config:   config,
		client:   &http.Client{Timeout: config.Timeout},
		queue:    make(chan *WebhookTask, config.BufferSize),
		stopChan: make(chan struct{}),
	}

	for i := 0; i < config.MaxConcurrent; i++ {
		pool.wg.Add(1)
		go pool.worker()
	}

	log.Printf("[Webhook] Pool initialized: URL=%s, workers=%d, buffer=%d",
		config.URL, config.MaxConcurrent, config.BufferSize)

	return pool
}

func (p *WebhookPool) worker() {
	defer p.wg.Done()

	for {
		select {
		case task := <-p.queue:
			p.sendWithRetry(task)
		case <-p.stopChan:
			return
		}
	}
}

func (p *WebhookPool) Send(alert *ManagedAlert) bool {
	if p == nil || alert == nil {
		return false
	}

	task := &WebhookTask{
		Alert:     alert,
		Timestamp: time.Now(),
		Retry:     0,
	}

	select {
	case p.queue <- task:
		return true
	default:
		atomic.AddUint64(&p.stats.Dropped, 1)
		log.Printf("[Webhook] Queue full, dropping alert: %s", alert.ID)
		return false
	}
}

func (p *WebhookPool) sendWithRetry(task *WebhookTask) {
	start := time.Now()
	payload := p.buildPayload(task.Alert)
	data, err := json.Marshal(payload)
	if err != nil {
		atomic.AddUint64(&p.stats.Failed, 1)
		log.Printf("[Webhook] Failed to marshal payload: %v", err)
		return
	}

	maxAttempts := p.config.Retry + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if p.sendOnce(data, task.Alert.ID) {
			atomic.AddUint64(&p.stats.Sent, 1)
			latency := uint64(time.Since(start).Milliseconds())
			atomic.AddUint64(&p.stats.AvgLatMs, latency)
			if attempt > 1 {
				atomic.AddUint64(&p.stats.Retried, 1)
			}
			return
		}

		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
	}

	atomic.AddUint64(&p.stats.Failed, 1)
	log.Printf("[Webhook] Failed after %d attempts: alert=%s", maxAttempts, task.Alert.ID)
}

func (p *WebhookPool) sendOnce(data []byte, alertID string) bool {
	req, err := http.NewRequest(p.config.Method, p.config.URL, bytes.NewReader(data))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Alert-ID", alertID)
	req.Header.Set("X-eTracee-Timestamp", time.Now().Format(time.RFC3339))

	for k, v := range p.config.Headers {
		req.Header.Set(k, v)
	}

	if p.config.Secret != "" {
		mac := hmac.New(sha256.New, []byte(p.config.Secret))
		mac.Write(data)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-eTracee-Signature", "sha256="+sig)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (p *WebhookPool) buildPayload(alert *ManagedAlert) *WebhookPayload {
	if alert == nil {
		return nil
	}

	payload := &WebhookPayload{
		AlertID:     alert.ID,
		RuleName:    alert.RuleName,
		Severity:    alert.Severity,
		Category:    alert.Category,
		Description: alert.Description,
		Timestamp:   alert.CreatedAt.Format(time.RFC3339),
		MitreAttack: alert.MitreAttack,
		Actions:     alert.Actions,
		Tags:        alert.Tags,
	}

	if alert.Event != nil {
		payload.Event = map[string]interface{}{
			"timestamp":  alert.Event.Timestamp,
			"pid":        alert.Event.PID,
			"ppid":       alert.Event.PPID,
			"uid":        alert.Event.UID,
			"gid":        alert.Event.GID,
			"event_type": alert.Event.EventType,
			"comm":       alert.Event.Comm,
			"cmdline":    alert.Event.Cmdline,
			"filename":   alert.Event.Filename,
			"ret_code":   alert.Event.RetCode,
		}
		if alert.Event.SrcAddr != nil {
			payload.Event["src_addr"] = map[string]interface{}{
				"ip":   alert.Event.SrcAddr.IP,
				"port": alert.Event.SrcAddr.Port,
			}
		}
		if alert.Event.DstAddr != nil {
			payload.Event["dst_addr"] = map[string]interface{}{
				"ip":   alert.Event.DstAddr.IP,
				"port": alert.Event.DstAddr.Port,
			}
		}
	}

	return payload
}

func (p *WebhookPool) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopChan)
		p.wg.Wait()
		log.Printf("[Webhook] Pool stopped")
	})
}

func (p *WebhookPool) GetStats() WebhookStats {
	return WebhookStats{
		Sent:     atomic.LoadUint64(&p.stats.Sent),
		Failed:   atomic.LoadUint64(&p.stats.Failed),
		Retried:  atomic.LoadUint64(&p.stats.Retried),
		Dropped:  atomic.LoadUint64(&p.stats.Dropped),
		AvgLatMs: atomic.LoadUint64(&p.stats.AvgLatMs),
	}
}

type MultiWebhookPool struct {
	pools []*WebhookPool
	mu    sync.RWMutex
}

func NewMultiWebhookPool() *MultiWebhookPool {
	return &MultiWebhookPool{
		pools: make([]*WebhookPool, 0),
	}
}

func (m *MultiWebhookPool) AddWebhook(config *WebhookConfig) {
	if config == nil || config.URL == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pools = append(m.pools, NewWebhookPool(config))
}

func (m *MultiWebhookPool) Send(alert *ManagedAlert) {
	m.mu.RLock()
	pools := make([]*WebhookPool, len(m.pools))
	copy(pools, m.pools)
	m.mu.RUnlock()

	for _, pool := range pools {
		if pool != nil {
			pool.Send(alert)
		}
	}
}

func (m *MultiWebhookPool) Stop() {
	m.mu.RLock()
	pools := make([]*WebhookPool, len(m.pools))
	copy(pools, m.pools)
	m.mu.RUnlock()

	for _, pool := range pools {
		if pool != nil {
			pool.Stop()
		}
	}
}

func (m *MultiWebhookPool) GetStats() []WebhookStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make([]WebhookStats, len(m.pools))
	for i, pool := range m.pools {
		if pool != nil {
			stats[i] = pool.GetStats()
		}
	}
	return stats
}
