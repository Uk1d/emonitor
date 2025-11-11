package main

import (
    "fmt"
    "time"
)

// GraphUpdate 用于通过 WebSocket 实时推送图谱增量（节点/边）
type GraphUpdate struct {
    Nodes []GraphNode `json:"nodes"`
    Edges []GraphEdge `json:"edges"`
    Stats struct {
        NodeCount int `json:"node_count"`
        EdgeCount int `json:"edge_count"`
    } `json:"stats"`
}

// BuildGraphUpdateFromEvent 根据单条事件构建图谱增量
// 注意：该函数只产生与事件直接相关的最小增量，前端自行去重并整合到全局图中。
func BuildGraphUpdateFromEvent(ec *EventContext, e *EventJSON) *GraphUpdate {
    if e == nil {
        return nil
    }
    u := &GraphUpdate{Nodes: make([]GraphNode, 0, 4), Edges: make([]GraphEdge, 0, 6)}
    now := time.Now()

    // 进程节点
    procID := fmt.Sprintf("proc:%d", e.PID)
    label := fmt.Sprintf("%s(%d)", e.Comm, e.PID)
    nodeMeta := map[string]string{}
    if e.Cmdline != "" { nodeMeta["cmdline"] = e.Cmdline }
    u.Nodes = append(u.Nodes, GraphNode{ID: procID, Label: label, Type: NodeProcess, Timestamp: &now, Metadata: nodeMeta})

    // 父子关系（execve/fork/clone/exit）
    switch e.EventType {
    case "execve", "fork", "clone":
        if e.PPID != 0 {
            ppidID := fmt.Sprintf("proc:%d", e.PPID)
            u.Nodes = append(u.Nodes, GraphNode{ID: ppidID, Label: fmt.Sprintf("PID %d", e.PPID), Type: NodeProcess})
            u.Edges = append(u.Edges, GraphEdge{Source: ppidID, Target: procID, Type: EdgeSpawn, Timestamp: &now})
        }
    }

    // 文件行为
    switch e.EventType {
    case "openat", "read", "write", "unlink", "rename", "chmod", "chown":
        if e.Filename != "" {
            fileID := fmt.Sprintf("file:%s", e.Filename)
            u.Nodes = append(u.Nodes, GraphNode{ID: fileID, Label: e.Filename, Type: NodeFile})
            edgeType := EdgeFileRead
            if e.EventType == "write" || e.EventType == "rename" || e.EventType == "unlink" || e.EventType == "chmod" || e.EventType == "chown" {
                edgeType = EdgeFileWrite
            }
            u.Edges = append(u.Edges, GraphEdge{Source: procID, Target: fileID, Type: edgeType, Timestamp: &now})
        }
    }

    // 网络行为
    switch e.EventType {
    case "connect", "bind", "listen", "accept":
        // 优先使用目标地址（connect 常见），否则使用源地址（bind 常见）
        var ip string
        var port uint16
        if e.DstAddr != nil && e.DstAddr.IP != "" {
            ip = e.DstAddr.IP; port = e.DstAddr.Port
        } else if e.SrcAddr != nil && e.SrcAddr.IP != "" {
            ip = e.SrcAddr.IP; port = e.SrcAddr.Port
        }
        if ip != "" {
            netLabel := fmt.Sprintf("%s:%d", ip, port)
            netID := fmt.Sprintf("net:%s", netLabel)
            u.Nodes = append(u.Nodes, GraphNode{ID: netID, Label: netLabel, Type: NodeNetwork})
            edgeType := EdgeConnect
            switch e.EventType {
            case "bind": edgeType = EdgeBind
            case "listen": edgeType = EdgeListen
            case "accept": edgeType = EdgeAccept
            }
            u.Edges = append(u.Edges, GraphEdge{Source: procID, Target: netID, Type: edgeType, Timestamp: &now})
        }
    }

    u.Stats.NodeCount = len(u.Nodes)
    u.Stats.EdgeCount = len(u.Edges)
    if u.Stats.NodeCount == 0 && u.Stats.EdgeCount == 0 {
        return nil
    }
    return u
}