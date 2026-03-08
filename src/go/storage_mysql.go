package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLStorage MySQL存储实现
// 用于存储事件流和告警数据
type MySQLStorage struct {
	DB       *sql.DB
	Host     string
	Port     int
	User     string
	Password string
	Database string

	// 连接池配置
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// MySQLStorageConfig MySQL存储配置
type MySQLStorageConfig struct {
	Host            string `yaml:"host"`
	Port            int    `yaml:"port"`
	User            string `yaml:"user"`
	Password        string `yaml:"password"`
	Database        string `yaml:"database"`
	MaxOpenConns    int    `yaml:"max_open_conns"`
	MaxIdleConns    int    `yaml:"max_idle_conns"`
	ConnMaxLifetime int    `yaml:"conn_max_lifetime_seconds"`
}

// NewMySQLStorage 创建MySQL存储实例
func NewMySQLStorage(cfg *MySQLStorageConfig) *MySQLStorage {
	if cfg == nil {
		cfg = &MySQLStorageConfig{}
	}
	return &MySQLStorage{
		Host:            cfg.Host,
		Port:            cfg.Port,
		User:            cfg.User,
		Password:        cfg.Password,
		Database:        cfg.Database,
		MaxOpenConns:    cfg.MaxOpenConns,
		MaxIdleConns:    cfg.MaxIdleConns,
		ConnMaxLifetime: time.Duration(cfg.ConnMaxLifetime) * time.Second,
	}
}

// Init 初始化MySQL连接和表结构
func (s *MySQLStorage) Init() error {
	// 设置默认值
	if s.Host == "" {
		s.Host = "localhost"
	}
	if s.Port == 0 {
		s.Port = 3306
	}
	if s.Database == "" {
		s.Database = "etracee_events"
	}
	if s.MaxOpenConns == 0 {
		s.MaxOpenConns = 50
	}
	if s.MaxIdleConns == 0 {
		s.MaxIdleConns = 10
	}
	if s.ConnMaxLifetime == 0 {
		s.ConnMaxLifetime = time.Hour
	}

	// 构建DSN
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4&loc=Local",
		s.User,
		s.Password,
		s.Host,
		s.Port,
		s.Database,
	)

	// 先尝试连接数据库（不指定数据库名），用于创建数据库
	dsnWithoutDB := fmt.Sprintf("%s:%s@tcp(%s:%d)/?parseTime=true&charset=utf8mb4&loc=Local",
		s.User,
		s.Password,
		s.Host,
		s.Port,
	)

	// 创建数据库（如果不存在）
	tmpDB, err := sql.Open("mysql", dsnWithoutDB)
	if err != nil {
		return fmt.Errorf("连接MySQL失败: %w", err)
	}
	defer tmpDB.Close()

	_, err = tmpDB.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", s.Database))
	if err != nil {
		return fmt.Errorf("创建数据库失败: %w", err)
	}
	tmpDB.Close()

	// 连接到目标数据库
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("连接数据库失败: %w", err)
	}

	// 配置连接池
	db.SetMaxOpenConns(s.MaxOpenConns)
	db.SetMaxIdleConns(s.MaxIdleConns)
	db.SetConnMaxLifetime(s.ConnMaxLifetime)

	// 测试连接
	if err := db.Ping(); err != nil {
		return fmt.Errorf("数据库连接测试失败: %w", err)
	}

	s.DB = db
	log.Printf("[+] MySQL存储初始化成功: %s@%s:%d/%s", s.User, s.Host, s.Port, s.Database)

	return s.initSchema()
}

// initSchema 初始化表结构
func (s *MySQLStorage) initSchema() error {
	stmts := []string{
		// 告警表
		`CREATE TABLE IF NOT EXISTS alerts (
			id VARCHAR(64) PRIMARY KEY,
			rule_name VARCHAR(255) NOT NULL,
			severity VARCHAR(32) NOT NULL,
			category VARCHAR(64),
			description TEXT,
			pid INT UNSIGNED,
			uid INT UNSIGNED,
			comm VARCHAR(255),
			filename VARCHAR(512),
			status VARCHAR(32) DEFAULT 'new',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_alerts_created_at (created_at),
			INDEX idx_alerts_severity (severity),
			INDEX idx_alerts_rule_name (rule_name),
			INDEX idx_alerts_status (status),
			INDEX idx_alerts_category (category)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

		// 事件表 - 分区表设计，按日期分区以支持大数据量
		`CREATE TABLE IF NOT EXISTS events (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			timestamp DATETIME(3) NOT NULL,
			pid INT UNSIGNED,
			uid INT UNSIGNED,
			comm VARCHAR(255),
			event_type VARCHAR(64) NOT NULL,
			filename VARCHAR(512),
			severity VARCHAR(32),
			rule_matched VARCHAR(255),
			raw_json JSON,
			INDEX idx_events_timestamp (timestamp),
			INDEX idx_events_event_type (event_type),
			INDEX idx_events_pid (pid),
			INDEX idx_events_uid (uid)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

		// 事件表分区事件表（可选，用于大数据量场景）
		// 注意：分区表需要在运行时动态创建，这里先创建基础表
	}

	for _, stmt := range stmts {
		if _, err := s.DB.Exec(stmt); err != nil {
			return fmt.Errorf("初始化表结构失败: %w", err)
		}
	}

	return nil
}

// Close 关闭数据库连接
func (s *MySQLStorage) Close() error {
	if s.DB != nil {
		return s.DB.Close()
	}
	return nil
}

// SaveAlert 保存告警
func (s *MySQLStorage) SaveAlert(alert *ManagedAlert) error {
	if s.DB == nil || alert == nil {
		return nil
	}

	// 从嵌入的事件中提取进程相关字段
	var pid uint32
	var uid uint32
	var comm string
	var filename string
	if alert.Event != nil {
		pid = alert.Event.PID
		uid = alert.Event.UID
		comm = alert.Event.Comm
		filename = alert.Event.Filename
	}

	query := `INSERT INTO alerts (
		id, rule_name, severity, category, description, pid, uid, comm, filename, status, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON DUPLICATE KEY UPDATE
		rule_name = VALUES(rule_name),
		severity = VALUES(severity),
		category = VALUES(category),
		description = VALUES(description),
		pid = VALUES(pid),
		uid = VALUES(uid),
		comm = VALUES(comm),
		filename = VALUES(filename),
		status = VALUES(status),
		updated_at = VALUES(updated_at)`

	_, err := s.DB.Exec(query,
		alert.ID,
		alert.RuleName,
		alert.Severity,
		alert.Category,
		alert.Description,
		pid,
		uid,
		comm,
		filename,
		alert.Status,
		alert.CreatedAt,
		alert.UpdatedAt,
	)
	return err
}

// QueryAlerts 查询告警
func (s *MySQLStorage) QueryAlerts(filters map[string]interface{}, page, pageSize int) ([]*ManagedAlert, int, error) {
	if s.DB == nil {
		return nil, 0, nil
	}

	where := []string{}
	args := []interface{}{}

	if v, ok := filters["severity"].(string); ok && v != "" {
		where = append(where, "severity = ?")
		args = append(args, v)
	}
	if v, ok := filters["category"].(string); ok && v != "" {
		where = append(where, "category = ?")
		args = append(args, v)
	}
	if v, ok := filters["status"].(string); ok && v != "" {
		where = append(where, "status = ?")
		args = append(args, v)
	}
	if v, ok := filters["rule_name"].(string); ok && v != "" {
		where = append(where, "rule_name = ?")
		args = append(args, v)
	}
	if v, ok := filters["since"].(string); ok && v != "" {
		where = append(where, "created_at >= ?")
		args = append(args, v)
	}
	if v, ok := filters["until"].(string); ok && v != "" {
		where = append(where, "created_at <= ?")
		args = append(args, v)
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}

	// 统计总数
	var total int
	countSQL := fmt.Sprintf("SELECT COUNT(1) FROM alerts %s", whereSQL)
	if err := s.DB.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	querySQL := fmt.Sprintf(`SELECT id, rule_name, severity, category, description, pid, uid, comm, filename, status, created_at, updated_at FROM alerts %s ORDER BY created_at DESC LIMIT ? OFFSET ?`, whereSQL)
	rows, err := s.DB.Query(querySQL, append(args, pageSize, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	results := []*ManagedAlert{}
	for rows.Next() {
		var a ManagedAlert
		var pid, uid int
		var comm, filename sql.NullString
		var category, description sql.NullString
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&a.ID, &a.RuleName, &a.Severity, &category, &description, &pid, &uid, &comm, &filename, &a.Status, &createdAt, &updatedAt); err != nil {
			return nil, 0, err
		}

		a.Category = category.String
		a.Description = description.String
		a.CreatedAt = createdAt
		a.UpdatedAt = updatedAt

		// 构造事件字段
		a.Event = &EventJSON{
			PID:      uint32(pid),
			UID:      uint32(uid),
			Comm:     comm.String,
			Filename: filename.String,
		}
		results = append(results, &a)
	}
	return results, total, nil
}

// SaveEvent 保存事件
func (s *MySQLStorage) SaveEvent(event *EventJSON) error {
	if s.DB == nil || event == nil {
		return nil
	}

	raw, _ := json.Marshal(event)

	// 解析时间戳
	var timestamp time.Time
	var err error
	if event.Timestamp != "" {
		timestamp, err = time.Parse(time.RFC3339Nano, event.Timestamp)
		if err != nil {
			timestamp = time.Now()
		}
	} else {
		timestamp = time.Now()
	}

	query := `INSERT INTO events (timestamp, pid, uid, comm, event_type, filename, severity, rule_matched, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.DB.Exec(query,
		timestamp,
		event.PID,
		event.UID,
		event.Comm,
		event.EventType,
		event.Filename,
		event.Severity,
		event.RuleMatched,
		string(raw),
	)
	return err
}

// QueryEvents 查询事件
func (s *MySQLStorage) QueryEvents(filters map[string]interface{}, page, pageSize int) ([]*EventJSON, int, error) {
	if s.DB == nil {
		return nil, 0, nil
	}

	where := []string{}
	args := []interface{}{}

	if v, ok := filters["event_type"].(string); ok && v != "" {
		where = append(where, "event_type = ?")
		args = append(args, v)
	}
	if v, ok := filters["pid"].(int); ok && v > 0 {
		where = append(where, "pid = ?")
		args = append(args, v)
	}
	if v, ok := filters["uid"].(int); ok && v > 0 {
		where = append(where, "uid = ?")
		args = append(args, v)
	}
	if v, ok := filters["since"].(string); ok && v != "" {
		where = append(where, "timestamp >= ?")
		args = append(args, v)
	}
	if v, ok := filters["until"].(string); ok && v != "" {
		where = append(where, "timestamp <= ?")
		args = append(args, v)
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}

	// 统计总数
	var total int
	countSQL := fmt.Sprintf("SELECT COUNT(1) FROM events %s", whereSQL)
	if err := s.DB.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// 限制查询窗口
	windowTotal := total
	if windowTotal > 100000 {
		windowTotal = 100000
	}

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	if offset >= windowTotal {
		return []*EventJSON{}, windowTotal, nil
	}

	// 使用子查询限制窗口大小
	innerSQL := fmt.Sprintf("SELECT raw_json FROM events %s ORDER BY timestamp DESC LIMIT 100000", whereSQL)
	querySQL := fmt.Sprintf("SELECT raw_json FROM (%s) AS sub LIMIT ? OFFSET ?", innerSQL)
	rows, err := s.DB.Query(querySQL, append(args, pageSize, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	results := []*EventJSON{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		var e EventJSON
		if err := json.Unmarshal([]byte(raw), &e); err == nil {
			results = append(results, &e)
		}
	}
	return results, windowTotal, nil
}

// CleanupOldEvents 清理旧事件数据（数据保留策略）
func (s *MySQLStorage) CleanupOldEvents(retentionDays int) error {
	if s.DB == nil || retentionDays <= 0 {
		return nil
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	result, err := s.DB.Exec("DELETE FROM events WHERE timestamp < ?", cutoff)
	if err != nil {
		return err
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		log.Printf("[*] 清理了 %d 条过期事件数据 (保留 %d 天)", affected, retentionDays)
	}

	return nil
}

// CleanupOldAlerts 清理旧告警数据
func (s *MySQLStorage) CleanupOldAlerts(retentionDays int) error {
	if s.DB == nil || retentionDays <= 0 {
		return nil
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	result, err := s.DB.Exec("DELETE FROM alerts WHERE created_at < ? AND status = 'resolved'", cutoff)
	if err != nil {
		return err
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		log.Printf("[*] 清理了 %d 条已解决的过期告警 (保留 %d 天)", affected, retentionDays)
	}

	return nil
}

// GetStats 获取存储统计信息
func (s *MySQLStorage) GetStats() (map[string]interface{}, error) {
	if s.DB == nil {
		return nil, nil
	}

	stats := make(map[string]interface{})

	// 事件统计
	var eventCount int64
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&eventCount); err == nil {
		stats["event_count"] = eventCount
	}

	// 告警统计
	var alertCount int64
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alertCount); err == nil {
		stats["alert_count"] = alertCount
	}

	// 按严重级别统计告警
	rows, err := s.DB.Query("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
	if err == nil {
		defer rows.Close()
		severityStats := make(map[string]int64)
		for rows.Next() {
			var severity string
			var count int64
			if err := rows.Scan(&severity, &count); err == nil {
				severityStats[severity] = count
			}
		}
		stats["alerts_by_severity"] = severityStats
	}

	// 数据库大小估算
	var dbSize int64
	if err := s.DB.QueryRow("SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = ?", s.Database).Scan(&dbSize); err == nil {
		stats["database_size_bytes"] = dbSize
	}

	return stats, nil
}

// GetAlertStats 获取告警详细统计（用于 Web 展示）
// 参数 since 为零值时表示统计所有告警，否则统计指定时间之后的告警
func (s *MySQLStorage) GetAlertStats(since time.Time) (active, resolved, falsePositives, total uint64, severityDist, categoryDist map[string]uint64, avgResolution time.Duration, err error) {
	if s.DB == nil {
		return 0, 0, 0, 0, nil, nil, 0, nil
	}

	// 构建时间条件：如果 since 是零值，则不限制时间
	useTimeFilter := !since.IsZero()
	var sinceStr string
	if useTimeFilter {
		sinceStr = since.Format("2006-01-02 15:04:05")
	}

	// 辅助函数：构建带时间条件的查询
	buildQuery := func(baseQuery string) string {
		if useTimeFilter {
			return baseQuery + " AND created_at >= ?"
		}
		return baseQuery
	}

	// 活跃告警（new, acknowledged, in_progress）
	activeStatuses := []string{"new", "acknowledged", "in_progress"}
	for _, status := range activeStatuses {
		var count int64
		query := buildQuery("SELECT COUNT(*) FROM alerts WHERE status = ?")
		if useTimeFilter {
			if e := s.DB.QueryRow(query, status, sinceStr).Scan(&count); e == nil {
				active += uint64(count)
			}
		} else {
			if e := s.DB.QueryRow(query, status).Scan(&count); e == nil {
				active += uint64(count)
			}
		}
	}

	// 已解决告警
	resolvedQuery := buildQuery("SELECT COUNT(*) FROM alerts WHERE status = 'resolved'")
	if useTimeFilter {
		s.DB.QueryRow(resolvedQuery, sinceStr).Scan(&resolved)
	} else {
		s.DB.QueryRow(resolvedQuery).Scan(&resolved)
	}

	// 误报告警
	falsePositiveQuery := buildQuery("SELECT COUNT(*) FROM alerts WHERE status = 'false_positive'")
	if useTimeFilter {
		s.DB.QueryRow(falsePositiveQuery, sinceStr).Scan(&falsePositives)
	} else {
		s.DB.QueryRow(falsePositiveQuery).Scan(&falsePositives)
	}

	// 总告警数
	totalQuery := buildQuery("SELECT COUNT(*) FROM alerts")
	if useTimeFilter {
		s.DB.QueryRow(totalQuery, sinceStr).Scan(&total)
	} else {
		s.DB.QueryRow(totalQuery).Scan(&total)
	}

	// 严重级别分布
	severityDist = make(map[string]uint64)
	severityQuery := buildQuery("SELECT severity, COUNT(*) FROM alerts WHERE severity IS NOT NULL AND severity != '' GROUP BY severity")
	var rows *sql.Rows
	if useTimeFilter {
		rows, err = s.DB.Query(severityQuery, sinceStr)
	} else {
		rows, err = s.DB.Query(severityQuery)
	}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var count int64
			if rows.Scan(&sev, &count) == nil {
				severityDist[sev] = uint64(count)
			}
		}
	}

	// 类别分布
	categoryDist = make(map[string]uint64)
	categoryQuery := buildQuery("SELECT category, COUNT(*) FROM alerts WHERE category IS NOT NULL AND category != '' GROUP BY category")
	if useTimeFilter {
		rows2, e := s.DB.Query(categoryQuery, sinceStr)
		if e == nil {
			defer rows2.Close()
			for rows2.Next() {
				var cat string
				var count int64
				if rows2.Scan(&cat, &count) == nil {
					categoryDist[cat] = uint64(count)
				}
			}
		}
	} else {
		rows2, e := s.DB.Query(categoryQuery)
		if e == nil {
			defer rows2.Close()
			for rows2.Next() {
				var cat string
				var count int64
				if rows2.Scan(&cat, &count) == nil {
					categoryDist[cat] = uint64(count)
				}
			}
		}
	}

	// 平均解决时间
	resolutionQuery := buildQuery("SELECT created_at, updated_at FROM alerts WHERE status = 'resolved' AND created_at IS NOT NULL AND updated_at IS NOT NULL")
	if useTimeFilter {
		rows3, e := s.DB.Query(resolutionQuery, sinceStr)
		if e == nil {
			defer rows3.Close()
			var totalDur time.Duration
			var count int
			for rows3.Next() {
				var created, updated time.Time
				if rows3.Scan(&created, &updated) == nil {
					if updated.After(created) {
						totalDur += updated.Sub(created)
						count++
					}
				}
			}
			if count > 0 {
				avgResolution = totalDur / time.Duration(count)
			}
		}
	} else {
		rows3, e := s.DB.Query(resolutionQuery)
		if e == nil {
			defer rows3.Close()
			var totalDur time.Duration
			var count int
			for rows3.Next() {
				var created, updated time.Time
				if rows3.Scan(&created, &updated) == nil {
					if updated.After(created) {
						totalDur += updated.Sub(created)
						count++
					}
				}
			}
			if count > 0 {
				avgResolution = totalDur / time.Duration(count)
			}
		}
	}

	return active, resolved, falsePositives, total, severityDist, categoryDist, avgResolution, nil
}
