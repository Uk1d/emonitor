package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// PythonServiceClient Python 服务客户端
type PythonServiceClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewPythonServiceClient 创建 Python 服务客户端
func NewPythonServiceClient(host string, port int) *PythonServiceClient {
	return &PythonServiceClient{
		baseURL: fmt.Sprintf("http://%s:%d", host, port),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// DetectEvent 发送事件到 Python 服务进行异常检测
func (c *PythonServiceClient) DetectEvent(event *EventJSON) (*map[string]interface{}, error) {
	// 转换事件格式
	pyEvent := map[string]interface{}{
		"pid":         event.PID,
		"comm":        event.Comm,
		"event_type":  event.EventType,
		"timestamp":   event.Timestamp,
		"uid":         event.UID,
		"gid":         event.GID,
		"ret_code":    event.RetCode,
	}

	if event.Filename != "" {
		pyEvent["filename"] = event.Filename
	}

	if event.DstAddr != nil {
		pyEvent["dst_addr"] = map[string]interface{}{
			"ip":   event.DstAddr.IP,
			"port": event.DstAddr.Port,
		}
	}

	body, err := json.Marshal(pyEvent)
	if err != nil {
		return nil, fmt.Errorf("序列化事件失败: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/ai/detect",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, fmt.Errorf("请求 Python 服务失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Python 服务返回错误状态: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	return &result, nil
}

// GetAnomalies 获取 AI 检测到的异常列表
func (c *PythonServiceClient) GetAnomalies(limit int) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/ai/anomalies?limit=%d", c.baseURL, limit)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求 Python 服务失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Python 服务返回错误状态: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	anomalies, ok := result["anomalies"].([]interface{})
	if !ok {
		return []map[string]interface{}{}, nil
	}

	resultAnomalies := make([]map[string]interface{}, len(anomalies))
	for i, a := range anomalies {
		resultAnomalies[i] = a.(map[string]interface{})
	}

	return resultAnomalies, nil
}

// GenerateReport 生成安全报告
func (c *PythonServiceClient) GenerateReport(format string) ([]byte, string, error) {
	url := fmt.Sprintf("%s/api/reports/generate?format=%s", c.baseURL, format)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, "", fmt.Errorf("请求 Python 服务失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("Python 服务返回错误: %d - %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取响应失败: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")

	return data, contentType, nil
}

// UpdateBaselines 更新 Python AI 检测器的基线
func (c *PythonServiceClient) UpdateBaselines() error {
	resp, err := c.httpClient.Post(
		c.baseURL+"/api/ai/baselines/update",
		"application/json",
		nil,
	)
	if err != nil {
		return fmt.Errorf("请求 Python 服务失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Python 服务返回错误状态: %d", resp.StatusCode)
	}

	return nil
}

// SendEvents 批量发送事件到 Python 服务
func (c *PythonServiceClient) SendEvents(events []*EventJSON) error {
	// 转换事件格式
	pyEvents := make([]map[string]interface{}, len(events))
	for i, event := range events {
		pyEvents[i] = map[string]interface{}{
			"pid":        event.PID,
			"comm":       event.Comm,
			"event_type": event.EventType,
			"timestamp":  event.Timestamp,
			"uid":        event.UID,
			"gid":        event.GID,
			"ret_code":   event.RetCode,
		}

		if event.Filename != "" {
			pyEvents[i]["filename"] = event.Filename
		}

		if event.DstAddr != nil {
			pyEvents[i]["dst_addr"] = map[string]interface{}{
				"ip":   event.DstAddr.IP,
				"port": event.DstAddr.Port,
			}
		}
	}

	reqBody := map[string]interface{}{
		"events": pyEvents,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("序列化事件失败: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/data/events",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return fmt.Errorf("请求 Python 服务失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Python 服务返回错误状态: %d", resp.StatusCode)
	}

	return nil
}

// SendAlert 发送告警到 Python 服务
func (c *PythonServiceClient) SendAlert(alert *AlertEvent) error {
	pyAlert := map[string]interface{}{
		"rule_name":   alert.RuleName,
		"severity":    alert.Severity,
		"description": alert.Description,
		"category":    alert.Category,
		"timestamp":   alert.Timestamp.Format(time.RFC3339),
		"status":      "new", // 添加状态字段
	}

	if alert.Event != nil {
		pyAlert["pid"] = alert.Event.PID
		pyAlert["comm"] = alert.Event.Comm
		pyAlert["uid"] = alert.Event.UID
		pyAlert["filename"] = alert.Event.Filename
	}

	reqBody := map[string]interface{}{
		"alerts": []map[string]interface{}{pyAlert},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("序列化告警失败: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/data/events",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return fmt.Errorf("请求 Python 服务失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Python 服务返回错误状态: %d, 响应: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// HealthCheck 检查 Python 服务健康状态
func (c *PythonServiceClient) HealthCheck() bool {
	resp, err := c.httpClient.Get(c.baseURL + "/health")
	if err != nil {
		log.Printf("[!] Python 服务健康检查失败: %v", err)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// ClearOldData 清理 Python 服务的旧数据
func (c *PythonServiceClient) ClearOldData() error {
	resp, err := c.httpClient.Post(
		c.baseURL+"/api/ai/clear",
		"application/json",
		nil,
	)
	if err != nil {
		return fmt.Errorf("请求 Python 服务失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Python 服务返回错误状态: %d", resp.StatusCode)
	}

	return nil
}
