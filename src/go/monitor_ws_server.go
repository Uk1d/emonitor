// Copyright 2026 Uk1d
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// MonitorWSServer WebSocket 服务端
// 供独立的 Web 服务连接获取监控数据
type MonitorWSServer struct {
	port         int
	alertManager *AlertManager
	storage      Storage
	eventContext *EventContext

	// WebSocket 客户端
	clients   map[*WSClientConn]struct{}
	clientsMu sync.Mutex

	// WebSocket 升级器
	upgrader websocket.Upgrader

	// 事件广播
	eventChan chan *EventJSON
}

// WSClientConn WebSocket 客户端连接
type WSClientConn struct {
	conn     *websocket.Conn
	send     chan []byte
	closeOnce sync.Once
}

// NewMonitorWSServer 创建 WebSocket 服务端
func NewMonitorWSServer(port int, alertManager *AlertManager, storage Storage, eventContext *EventContext) *MonitorWSServer {
	return &MonitorWSServer{
		port:         port,
		alertManager: alertManager,
		storage:      storage,
		eventContext: eventContext,
		clients:      make(map[*WSClientConn]struct{}),
		eventChan:    make(chan *EventJSON, 10000),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许所有来源（生产环境应限制）
			},
		},
	}
}

// Start 启动服务
func (s *MonitorWSServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/health", s.handleHealth)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
	}

	return server.ListenAndServe()
}

// handleWebSocket 处理 WebSocket 连接
func (s *MonitorWSServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket 升级失败: %v", err)
		return
	}

	client := &WSClientConn{
		conn: conn,
		send: make(chan []byte, 1024),
	}

	s.clientsMu.Lock()
	s.clients[client] = struct{}{}
	clientCount := len(s.clients)
	s.clientsMu.Unlock()

	log.Printf("[+] Web 服务已连接 (当前连接数: %d)", clientCount)

	// 发送初始状态
	s.sendInitialState(client)

	// 启动写入协程
	go s.writePump(client)

	// 读取客户端消息（保持连接）
	s.readPump(client)
}

// handleHealth 健康检查
func (s *MonitorWSServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// sendInitialState 发送初始状态
func (s *MonitorWSServer) sendInitialState(client *WSClientConn) {
	// 发送当前统计
	stats := s.alertManager.GetAlertStats()
	msg := map[string]interface{}{
		"type": "stats",
		"data": stats,
		"ts":   time.Now().Format(time.RFC3339),
	}
	if data, err := json.Marshal(msg); err == nil {
		select {
		case client.send <- data:
		default:
		}
	}
}

// writePump 写入协程
func (s *MonitorWSServer) writePump(client *WSClientConn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case msg, ok := <-client.send:
			if !ok {
				return
			}
			client.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := client.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				s.removeClient(client)
				return
			}
		case <-ticker.C:
			client.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := client.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				s.removeClient(client)
				return
			}
		}
	}
}

// readPump 读取协程
func (s *MonitorWSServer) readPump(client *WSClientConn) {
	defer s.removeClient(client)

	client.conn.SetReadLimit(1024)
	client.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	client.conn.SetPongHandler(func(string) error {
		client.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		return nil
	})

	for {
		_, _, err := client.conn.ReadMessage()
		if err != nil {
			return
		}
	}
}

// removeClient 移除客户端
func (s *MonitorWSServer) removeClient(client *WSClientConn) {
	s.clientsMu.Lock()
	delete(s.clients, client)
	clientCount := len(s.clients)
	s.clientsMu.Unlock()

	client.closeOnce.Do(func() {
		close(client.send)
		client.conn.Close()
	})

	log.Printf("[*] Web 服务已断开 (当前连接数: %d)", clientCount)
}

// BroadcastEvent 广播事件
func (s *MonitorWSServer) BroadcastEvent(event *EventJSON) {
	msg := map[string]interface{}{
		"type": "event",
		"data": event,
		"ts":   time.Now().Format(time.RFC3339),
	}
	s.broadcast(msg)
}

// BroadcastAlert 广播告警
func (s *MonitorWSServer) BroadcastAlert(alert *ManagedAlert) {
	msg := map[string]interface{}{
		"type": "alert",
		"data": alert,
		"ts":   time.Now().Format(time.RFC3339),
	}
	s.broadcast(msg)
}

// BroadcastStats 广播统计
func (s *MonitorWSServer) BroadcastStats(stats *AlertStats) {
	msg := map[string]interface{}{
		"type": "stats",
		"data": stats,
		"ts":   time.Now().Format(time.RFC3339),
	}
	s.broadcast(msg)
}

// broadcast 广播消息给所有客户端
func (s *MonitorWSServer) broadcast(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	s.clientsMu.Lock()
	clients := make([]*WSClientConn, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.clientsMu.Unlock()

	for _, client := range clients {
		select {
		case client.send <- data:
		default:
			// 发送队列满，跳过
		}
	}
}
