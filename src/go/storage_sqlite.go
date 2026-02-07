package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// SQLiteStorage 采用内嵌SQLite作为轻量级事件/告警存储
type SQLiteStorage struct {
	DB          *sql.DB
	Path        string
	JournalMode string
	Synchronous string
}

func (s *SQLiteStorage) Init() error {
	if s.Path == "" {
		s.Path = "data/etracee.db"
	}
	// 确保数据库目录存在
	if dir := filepath.Dir(s.Path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("创建数据库目录失败: %v", err)
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(%s)&_pragma=synchronous(%s)",
		s.Path,
		defaultIfEmpty(s.JournalMode, "WAL"),
		defaultIfEmpty(s.Synchronous, "NORMAL"),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		log.Printf("启用外键失败: %v", err)
	}
	s.DB = db
	return s.initSchema()
}

func (s *SQLiteStorage) Close() error {
	if s.DB != nil {
		return s.DB.Close()
	}
	return nil
}

func (s *SQLiteStorage) initSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            rule_name TEXT,
            severity TEXT,
            category TEXT,
            description TEXT,
            pid INTEGER,
            uid INTEGER,
            comm TEXT,
            filename TEXT,
            status TEXT,
            created_at TEXT,
            updated_at TEXT
        );`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_name);`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);`,
		`CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            pid INTEGER,
            uid INTEGER,
            comm TEXT,
            event_type TEXT,
            filename TEXT,
            severity TEXT,
            rule_matched TEXT,
            raw_json TEXT
        );`,
		`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);`,
		`CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);`,
		`CREATE INDEX IF NOT EXISTS idx_events_uid ON events(uid);`,
	}
	for _, st := range stmts {
		if _, err := s.DB.Exec(st); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStorage) SaveAlert(alert *ManagedAlert) error {
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
	_, err := s.DB.Exec(`INSERT INTO alerts (
        id, rule_name, severity, category, description, pid, uid, comm, filename, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET 
        rule_name=excluded.rule_name,
        severity=excluded.severity,
        category=excluded.category,
        description=excluded.description,
        pid=excluded.pid,
        uid=excluded.uid,
        comm=excluded.comm,
        filename=excluded.filename,
        status=excluded.status,
        created_at=excluded.created_at,
        updated_at=excluded.updated_at`,
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
		alert.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		alert.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	)
	return err
}

func (s *SQLiteStorage) QueryAlerts(filters map[string]interface{}, page, pageSize int) ([]*ManagedAlert, int, error) {
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
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}

	// count
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

	querySQL := fmt.Sprintf("SELECT id, rule_name, severity, category, description, pid, uid, comm, filename, status, created_at, updated_at FROM alerts %s ORDER BY created_at DESC LIMIT ? OFFSET ?", whereSQL)
	rows, err := s.DB.Query(querySQL, append(args, pageSize, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	results := []*ManagedAlert{}
	for rows.Next() {
		var a ManagedAlert
		var created, updated string
		var pid, uid int
		var comm, filename string
		if err := rows.Scan(&a.ID, &a.RuleName, &a.Severity, &a.Category, &a.Description, &pid, &uid, &comm, &filename, &a.Status, &created, &updated); err != nil {
			return nil, 0, err
		}
		// 构造事件字段
		a.Event = &EventJSON{
			PID:      uint32(pid),
			UID:      uint32(uid),
			Comm:     comm,
			Filename: filename,
		}
		// 时间解析留给上层，字符串即可
		results = append(results, &a)
	}
	return results, total, nil
}

func (s *SQLiteStorage) SaveEvent(event *EventJSON) error {
	if s.DB == nil || event == nil {
		return nil
	}
	raw, _ := json.Marshal(event)
	_, err := s.DB.Exec(`INSERT INTO events (
        timestamp, pid, uid, comm, event_type, filename, severity, rule_matched, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp,
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

func (s *SQLiteStorage) QueryEvents(filters map[string]interface{}, page, pageSize int) ([]*EventJSON, int, error) {
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
	var total int
	countSQL := fmt.Sprintf("SELECT COUNT(1) FROM events %s", whereSQL)
	if err := s.DB.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
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
	innerSQL := fmt.Sprintf("SELECT raw_json FROM events %s ORDER BY timestamp DESC LIMIT 100000", whereSQL)
	querySQL := fmt.Sprintf("SELECT raw_json FROM (%s) LIMIT ? OFFSET ?", innerSQL)
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
		_ = json.Unmarshal([]byte(raw), &e)
		results = append(results, &e)
	}
	return results, windowTotal, nil
}

func defaultIfEmpty(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
