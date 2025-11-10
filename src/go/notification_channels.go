package main

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "time"
)

// LogNotificationChannel 日志通知渠道
type LogNotificationChannel struct{}

func (c *LogNotificationChannel) SendNotification(alert *ManagedAlert) error {
	// 根据严重级别使用不同的日志格式
    switch alert.Severity {
    case "critical":
        log.Printf("[!] [CRITICAL] %s: %s (PID: %d, UID: %d)", 
            alert.RuleName, alert.Description, alert.Event.PID, alert.Event.UID)
    case "high":
        log.Printf("[!] [HIGH] %s: %s (PID: %d, UID: %d)", 
            alert.RuleName, alert.Description, alert.Event.PID, alert.Event.UID)
    case "medium":
        log.Printf("[*] [MEDIUM] %s: %s (PID: %d, UID: %d)", 
            alert.RuleName, alert.Description, alert.Event.PID, alert.Event.UID)
    case "low":
        log.Printf("[*] [LOW] %s: %s (PID: %d, UID: %d)", 
            alert.RuleName, alert.Description, alert.Event.PID, alert.Event.UID)
    default:
        log.Printf("[*] [INFO] %s: %s (PID: %d, UID: %d)", 
            alert.RuleName, alert.Description, alert.Event.PID, alert.Event.UID)
    }
	
	return nil
}

func (c *LogNotificationChannel) GetChannelName() string {
	return "log"
}

// FileNotificationChannel 文件通知渠道
type FileNotificationChannel struct {
	Path string
}

func (c *FileNotificationChannel) SendNotification(alert *ManagedAlert) error {
	if c.Path == "" {
		c.Path = "data/notifications"
	}
	
	// 确保目录存在
	if err := os.MkdirAll(c.Path, 0755); err != nil {
		return fmt.Errorf("创建通知目录失败: %v", err)
	}
	
	// 生成通知文件
	filename := fmt.Sprintf("notification_%s_%s.json", 
		alert.CreatedAt.Format("20060102_150405"), alert.ID)
	filepath := filepath.Join(c.Path, filename)
	
	// 创建通知内容
	notification := map[string]interface{}{
		"timestamp":    time.Now().Format("2006-01-02 15:04:05"),
		"alert_id":     alert.ID,
		"severity":     alert.Severity,
		"rule_name":    alert.RuleName,
		"description":  alert.Description,
		"category":     alert.Category,
		"event": map[string]interface{}{
			"pid":      alert.Event.PID,
			"uid":      alert.Event.UID,
			"comm":     alert.Event.Comm,
			"filename": alert.Event.Filename,
		},
		"actions":      alert.Actions,
		"mitre_attack": alert.MitreAttack,
		"status":       alert.Status,
		"created_at":   alert.CreatedAt,
	}
	
	// 序列化并写入文件
	data, err := json.MarshalIndent(notification, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化通知失败: %v", err)
	}
	
	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("写入通知文件失败: %v", err)
	}
	
	log.Printf("通知已保存到文件: %s", filepath)
	return nil
}

func (c *FileNotificationChannel) GetChannelName() string {
	return "file"
}

// ConsoleNotificationChannel 控制台通知渠道
type ConsoleNotificationChannel struct {
	EnableColors bool
}

func (c *ConsoleNotificationChannel) SendNotification(alert *ManagedAlert) error {
	var colorCode, resetCode string
	
	if c.EnableColors {
		switch alert.Severity {
		case "critical":
			colorCode = "\033[1;31m" // 红色加粗
		case "high":
			colorCode = "\033[1;33m" // 黄色加粗
		case "medium":
			colorCode = "\033[1;36m" // 青色加粗
		case "low":
			colorCode = "\033[1;32m" // 绿色加粗
		default:
			colorCode = "\033[1;37m" // 白色加粗
		}
		resetCode = "\033[0m"
	}
	
    // 打印格式化的告警信息（纯ASCII，无框线/emoji）
    fmt.Printf("%s[!] 安全告警通知%s\n", colorCode, resetCode)
    fmt.Printf("%s- 告警ID:     %s%s\n", colorCode, alert.ID, resetCode)
    fmt.Printf("%s- 规则名称:   %s%s\n", colorCode, alert.RuleName, resetCode)
    fmt.Printf("%s- 严重级别:   %s%s\n", colorCode, alert.Severity, resetCode)
    fmt.Printf("%s- 分类:       %s%s\n", colorCode, alert.Category, resetCode)
    fmt.Printf("%s- 描述:       %s%s\n", colorCode, alert.Description, resetCode)
    fmt.Printf("%s- 进程ID:     %d%s\n", colorCode, alert.Event.PID, resetCode)
    fmt.Printf("%s- 用户ID:     %d%s\n", colorCode, alert.Event.UID, resetCode)
    fmt.Printf("%s- 进程名:     %s%s\n", colorCode, alert.Event.Comm, resetCode)
    if alert.Event.Filename != "" {
        fmt.Printf("%s- 文件名:     %s%s\n", colorCode, alert.Event.Filename, resetCode)
    }
    if alert.MitreAttack != nil {
        fmt.Printf("%s- MITRE技术:  %s%s\n", colorCode, alert.MitreAttack.TechniqueID, resetCode)
        fmt.Printf("%s- 战术:       %s%s\n", colorCode, alert.MitreAttack.Tactic, resetCode)
    }
    fmt.Printf("%s- 时间:       %s%s\n", colorCode, alert.CreatedAt.Format("2006-01-02 15:04:05"), resetCode)
	
	return nil
}

func (c *ConsoleNotificationChannel) GetChannelName() string {
	return "console"
}

// EmailNotificationChannel 邮件通知渠道（模拟实现）
type EmailNotificationChannel struct {
	SMTPServer   string
	SMTPPort     int
	Username     string
	Password     string
	FromAddress  string
	ToAddresses  []string
	EnableTLS    bool
}

func (c *EmailNotificationChannel) SendNotification(alert *ManagedAlert) error {
	// 这里是邮件发送的模拟实现
	// 在实际环境中，需要使用真实的SMTP库
	
	subject := fmt.Sprintf("[eTracee Alert] %s - %s", alert.Severity, alert.RuleName)
	
	body := fmt.Sprintf(`
安全告警通知

告警详情:
- 告警ID: %s
- 规则名称: %s
- 严重级别: %s
- 分类: %s
- 描述: %s

事件信息:
- 进程ID: %d
- 用户ID: %d
- 进程名: %s
- 文件名: %s

时间: %s

请及时处理此告警。

---
eTracee 安全监控系统
`, 
		alert.ID,
		alert.RuleName,
		alert.Severity,
		alert.Category,
		alert.Description,
		alert.Event.PID,
		alert.Event.UID,
		alert.Event.Comm,
		alert.Event.Filename,
		alert.CreatedAt.Format("2006-01-02 15:04:05"),
	)
	
	// 模拟邮件发送
    log.Printf("[*] [模拟邮件发送] 收件人: %v, 主题: %s", c.ToAddresses, subject)
    log.Printf("[*] [邮件内容预览] %s", body[:100]+"...")
	
	return nil
}

func (c *EmailNotificationChannel) GetChannelName() string {
	return "email"
}

// WebhookNotificationChannel Webhook通知渠道
type WebhookNotificationChannel struct {
    URL     string
    Method  string
    Headers map[string]string
    Timeout time.Duration
    // 可选签名密钥（若配置则生成 HMAC-SHA256 签名）
    Secret  string
    // 重试次数（默认 0，表示不重试）
    Retry   int
}

func (c *WebhookNotificationChannel) SendNotification(alert *ManagedAlert) error {
    // 准备Webhook负载
    payload := map[string]interface{}{
		"alert_id":     alert.ID,
		"rule_name":    alert.RuleName,
		"severity":     alert.Severity,
		"category":     alert.Category,
		"description":  alert.Description,
		"timestamp":    alert.CreatedAt.Format(time.RFC3339),
		"event": map[string]interface{}{
			"pid":      alert.Event.PID,
			"uid":      alert.Event.UID,
			"comm":     alert.Event.Comm,
			"filename": alert.Event.Filename,
		},
		"mitre_attack": alert.MitreAttack,
		"actions":      alert.Actions,
	}
	
    // 序列化负载
    data, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("序列化Webhook负载失败: %v", err)
    }

    if c.URL == "" {
        return fmt.Errorf("Webhook URL 未配置")
    }

    method := c.Method
    if method == "" {
        method = "POST"
    }

    // 构造请求
    req, err := http.NewRequest(method, c.URL, bytes.NewReader(data))
    if err != nil {
        return fmt.Errorf("创建Webhook请求失败: %v", err)
    }
    // 设置默认与自定义头
    req.Header.Set("Content-Type", "application/json")
    for k, v := range c.Headers {
        req.Header.Set(k, v)
    }
    // 可选签名
    if c.Secret != "" {
        mac := hmac.New(sha256.New, []byte(c.Secret))
        mac.Write(data)
        sig := hex.EncodeToString(mac.Sum(nil))
        req.Header.Set("X-eTracee-Signature", "sha256="+sig)
        req.Header.Set("X-eTracee-Timestamp", time.Now().Format(time.RFC3339))
    }

    // 发送请求（含简单重试）
    timeout := c.Timeout
    if timeout == 0 {
        timeout = 10 * time.Second
    }
    client := &http.Client{Timeout: timeout}

    attempts := c.Retry + 1
    var lastErr error
    for i := 1; i <= attempts; i++ {
        resp, err := client.Do(req)
        if err != nil {
            lastErr = err
            log.Printf("[!] Webhook 发送失败（第 %d/%d 次）: %v", i, attempts, err)
        } else {
            // 读取并关闭响应体
            _ = resp.Body.Close()
            if resp.StatusCode >= 200 && resp.StatusCode < 300 {
                log.Printf("[+] Webhook 发送成功: %s %s (status=%d)", method, c.URL, resp.StatusCode)
                return nil
            }
            lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
            log.Printf("[!] Webhook 返回非成功状态（第 %d/%d 次）: %v", i, attempts, lastErr)
        }
        // 简单退避
        if i < attempts {
            time.Sleep(time.Duration(i) * 500 * time.Millisecond)
        }
    }
    return fmt.Errorf("Webhook 发送失败: %v", lastErr)
}

func (c *WebhookNotificationChannel) GetChannelName() string {
	return "webhook"
}

// SlackNotificationChannel Slack通知渠道（模拟实现）
type SlackNotificationChannel struct {
	WebhookURL string
	Channel    string
	Username   string
}

func (c *SlackNotificationChannel) SendNotification(alert *ManagedAlert) error {
	// 根据严重级别选择颜色
	var color string
	switch alert.Severity {
	case "critical":
		color = "danger"
	case "high":
		color = "warning"
	case "medium":
		color = "#36a64f"
	case "low":
		color = "good"
	default:
		color = "#764FA5"
	}
	
	// 构建Slack消息
	message := map[string]interface{}{
		"channel":  c.Channel,
		"username": c.Username,
		"attachments": []map[string]interface{}{
			{
				"color":      color,
    "title":      fmt.Sprintf("[!] 安全告警: %s", alert.RuleName),
				"title_link": fmt.Sprintf("http://localhost:8080/alerts/%s", alert.ID),
				"text":       alert.Description,
				"fields": []map[string]interface{}{
					{
						"title": "严重级别",
						"value": alert.Severity,
						"short": true,
					},
					{
						"title": "分类",
						"value": alert.Category,
						"short": true,
					},
					{
						"title": "进程",
						"value": fmt.Sprintf("%s (PID: %d)", alert.Event.Comm, alert.Event.PID),
						"short": true,
					},
					{
						"title": "用户",
						"value": fmt.Sprintf("UID: %d", alert.Event.UID),
						"short": true,
					},
				},
				"footer": "eTracee Security Monitor",
				"ts":     alert.CreatedAt.Unix(),
			},
		},
	}
	
	// 序列化消息
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("序列化Slack消息失败: %v", err)
	}
	
	// 模拟发送到Slack
	log.Printf("💬 [模拟Slack通知] Channel: %s", c.Channel)
	log.Printf("💬 [Slack消息] %s", string(data))
	
	return nil
}

func (c *SlackNotificationChannel) GetChannelName() string {
	return "slack"
}

// SyslogNotificationChannel Syslog通知渠道
type SyslogNotificationChannel struct {
	Server   string
	Port     int
	Protocol string // "udp" or "tcp"
	Facility int
	Tag      string
}

func (c *SyslogNotificationChannel) SendNotification(alert *ManagedAlert) error {
	// 构建syslog消息
	priority := c.calculatePriority(alert.Severity)
	timestamp := alert.CreatedAt.Format("Jan 02 15:04:05")
	hostname := "eTracee-host"
	
	message := fmt.Sprintf("<%d>%s %s %s: [%s] %s - %s (PID: %d, UID: %d)",
		priority,
		timestamp,
		hostname,
		c.Tag,
		alert.Severity,
		alert.RuleName,
		alert.Description,
		alert.Event.PID,
		alert.Event.UID,
	)
	
	// 模拟发送syslog
	log.Printf("📡 [模拟Syslog] Server: %s:%d, Protocol: %s", c.Server, c.Port, c.Protocol)
	log.Printf("📡 [Syslog消息] %s", message)
	
	return nil
}

func (c *SyslogNotificationChannel) calculatePriority(severity string) int {
	// Syslog优先级 = 设施 * 8 + 严重级别
	var level int
	switch severity {
	case "critical":
		level = 2 // Critical
	case "high":
		level = 3 // Error
	case "medium":
		level = 4 // Warning
	case "low":
		level = 5 // Notice
	default:
		level = 6 // Info
	}
	
	return c.Facility*8 + level
}

func (c *SyslogNotificationChannel) GetChannelName() string {
	return "syslog"
}

// DatabaseNotificationChannel 数据库通知渠道（模拟实现）
type DatabaseNotificationChannel struct {
	ConnectionString string
	TableName        string
}

func (c *DatabaseNotificationChannel) SendNotification(alert *ManagedAlert) error {
	// 模拟数据库插入
	insertSQL := fmt.Sprintf(`
INSERT INTO %s (
    alert_id, rule_name, severity, category, description,
    pid, uid, comm, filename, created_at, mitre_technique
) VALUES (
    '%s', '%s', '%s', '%s', '%s',
    %d, %d, '%s', '%s', '%s', '%s'
)`,
		c.TableName,
		alert.ID,
		alert.RuleName,
		alert.Severity,
		alert.Category,
		alert.Description,
		alert.Event.PID,
		alert.Event.UID,
		alert.Event.Comm,
		alert.Event.Filename,
		alert.CreatedAt.Format("2006-01-02 15:04:05"),
		func() string {
			if alert.MitreAttack != nil {
				return alert.MitreAttack.TechniqueID
			}
			return ""
		}(),
	)
	
    log.Printf("[+] [模拟数据库插入] %s", insertSQL)
	
	return nil
}

func (c *DatabaseNotificationChannel) GetChannelName() string {
	return "database"
}