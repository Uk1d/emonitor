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


// Package httpapi 提供 HTTP API 路由注册功能
// 定义了所有 API 端点及其对应的处理函数接口
package httpapi

import "net/http"

// Handlers 定义了所有 HTTP API 处理函数的接口
// 实现此接口的类型可以处理告警、事件和 WebSocket 相关的请求
type Handlers interface {
	// HandleAlerts 处理告警列表请求
	// GET /api/alerts - 获取告警列表，支持分页和过滤
	HandleAlerts(http.ResponseWriter, *http.Request)

	// HandleAlertDetail 处理单个告警详情请求
	// GET /api/alerts/{id} - 获取指定 ID 的告警详情
	HandleAlertDetail(http.ResponseWriter, *http.Request)

	// HandleAlertStats 处理告警统计请求
	// GET /api/alerts/stats - 获取告警统计数据
	HandleAlertStats(http.ResponseWriter, *http.Request)

	// HandleAttackChains 处理攻击链列表请求
	// GET /api/attack-chains - 获取攻击链列表
	HandleAttackChains(http.ResponseWriter, *http.Request)

	// HandleAttackChainGraph 处理攻击链图谱请求
	// GET /api/attack-chains/graph - 获取攻击链可视化图谱数据
	HandleAttackChainGraph(http.ResponseWriter, *http.Request)

	// HandleEvents 处理事件列表请求
	// GET /api/events - 获取事件列表，支持分页和过滤
	HandleEvents(http.ResponseWriter, *http.Request)

	// HandleWebSocket 处理 WebSocket 连接请求
	// GET /ws - 建立 WebSocket 连接，用于实时推送告警和事件
	HandleWebSocket(http.ResponseWriter, *http.Request)
}

// Register 将所有 API 路由注册到指定的 ServeMux
// 参数 mux 为 HTTP 路由复用器
// 参数 h 为实现了 Handlers 接口的处理器
//
// 注册的路由包括：
//   - /api/alerts          - 告警列表
//   - /api/alerts/{id}     - 告警详情
//   - /api/alerts/stats    - 告警统计
//   - /api/attack-chains   - 攻击链列表
//   - /api/attack-chains/graph - 攻击链图谱
//   - /api/events          - 事件列表
//   - /ws                  - WebSocket 连接
func Register(mux *http.ServeMux, h Handlers) {
	mux.HandleFunc("/api/alerts", h.HandleAlerts)
	mux.HandleFunc("/api/alerts/", h.HandleAlertDetail)
	mux.HandleFunc("/api/alerts/stats", h.HandleAlertStats)
	mux.HandleFunc("/api/attack-chains", h.HandleAttackChains)
	mux.HandleFunc("/api/attack-chains/graph", h.HandleAttackChainGraph)
	mux.HandleFunc("/api/events", h.HandleEvents)
	mux.HandleFunc("/ws", h.HandleWebSocket)
}
