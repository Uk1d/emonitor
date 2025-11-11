package main

import (
    "fmt"
    "time"
)

// 图谱节点类型
type GraphNodeType string

const (
    NodeProcess GraphNodeType = "process"
    NodeFile    GraphNodeType = "file"
    NodeNetwork GraphNodeType = "network"
    NodeAlert   GraphNodeType = "alert"
    NodeChain   GraphNodeType = "attack_chain"
)

// 图谱边类型
type GraphEdgeType string

const (
    EdgeExec       GraphEdgeType = "exec"
    EdgeFileRead   GraphEdgeType = "file_read"
    EdgeFileWrite  GraphEdgeType = "file_write"
    EdgeConnect    GraphEdgeType = "connect"
    EdgeBind       GraphEdgeType = "bind"
    EdgeListen     GraphEdgeType = "listen"
    EdgeAccept     GraphEdgeType = "accept"
    EdgeAlert      GraphEdgeType = "alert"
    EdgeChainAssoc GraphEdgeType = "chain_assoc"
    EdgeSpawn      GraphEdgeType = "spawn"
)

// 图谱节点
type GraphNode struct {
    ID        string            `json:"id"`
    Label     string            `json:"label"`
    Type      GraphNodeType     `json:"type"`
    Severity  string            `json:"severity,omitempty"`
    Timestamp *time.Time        `json:"timestamp,omitempty"`
    Metadata  map[string]string `json:"metadata,omitempty"`
}

// 图谱边
type GraphEdge struct {
    Source    string         `json:"source"`
    Target    string         `json:"target"`
    Type      GraphEdgeType  `json:"type"`
    Timestamp *time.Time     `json:"timestamp,omitempty"`
    Metadata  map[string]string `json:"metadata,omitempty"`
}

// 子图
type Subgraph struct {
    Nodes []GraphNode `json:"nodes"`
    Edges []GraphEdge `json:"edges"`
    Stats struct {
        NodeCount int `json:"node_count"`
        EdgeCount int `json:"edge_count"`
    } `json:"stats"`
}

// 子图构建选项
type SubgraphOptions struct {
    Since     *time.Time
    Until     *time.Time
    MaxNodes  int
}

func (g *Subgraph) finalize() {
    g.Stats.NodeCount = len(g.Nodes)
    g.Stats.EdgeCount = len(g.Edges)
}

// 通过 PID 构建子图
func BuildSubgraphByPID(ec *EventContext, pid uint32, opts SubgraphOptions) *Subgraph {
    g := &Subgraph{Nodes: make([]GraphNode, 0, 64), Edges: make([]GraphEdge, 0, 128)}
    if ec == nil {
        g.finalize(); return g
    }

    pc := ec.GetProcessContext(pid)
    if pc == nil {
        // 尝试用最小信息构建一个进程节点
        g.Nodes = append(g.Nodes, GraphNode{ID: fmt.Sprintf("proc:%d", pid), Label: fmt.Sprintf("PID %d", pid), Type: NodeProcess})
        g.finalize();
        return g
    }

    // 进程与父子关系
    procID := fmt.Sprintf("proc:%d", pc.PID)
    g.Nodes = append(g.Nodes, GraphNode{ID: procID, Label: fmt.Sprintf("%s(%d)", pc.Comm, pc.PID), Type: NodeProcess, Metadata: map[string]string{"cmdline": pc.Cmdline}})
    if pc.PPID != 0 {
        ppidID := fmt.Sprintf("proc:%d", pc.PPID)
        g.Nodes = append(g.Nodes, GraphNode{ID: ppidID, Label: fmt.Sprintf("PPID %d", pc.PPID), Type: NodeProcess})
        g.Edges = append(g.Edges, GraphEdge{Source: ppidID, Target: procID, Type: EdgeSpawn})
    }
    for _, child := range pc.ChildProcesses {
        childID := fmt.Sprintf("proc:%d", child)
        g.Nodes = append(g.Nodes, GraphNode{ID: childID, Label: fmt.Sprintf("PID %d", child), Type: NodeProcess})
        g.Edges = append(g.Edges, GraphEdge{Source: procID, Target: childID, Type: EdgeSpawn})
    }

    // 文件操作 → 节点与边
    for _, op := range pc.FileOperations {
        if !inTimeRange(op.Timestamp, opts) { continue }
        fileID := fmt.Sprintf("file:%s", op.FilePath)
        g.Nodes = appendIfMissingNode(g.Nodes, GraphNode{ID: fileID, Label: op.FilePath, Type: NodeFile})
        edgeType := EdgeFileRead
        if op.Operation == "write" || op.Operation == "rename" || op.Operation == "unlink" || op.Operation == "chmod" || op.Operation == "chown" {
            edgeType = EdgeFileWrite
        }
        ts := op.Timestamp
        g.Edges = append(g.Edges, GraphEdge{Source: procID, Target: fileID, Type: edgeType, Timestamp: &ts})
        if limitReached(len(g.Nodes), opts) { break }
    }

    // 网络活动 → 节点与边
    for _, na := range pc.NetworkActivity {
        if !inTimeRange(na.Timestamp, opts) { continue }
        netLabel := fmt.Sprintf("%s:%d", na.RemoteAddr, na.RemotePort)
        netID := fmt.Sprintf("net:%s", netLabel)
        g.Nodes = appendIfMissingNode(g.Nodes, GraphNode{ID: netID, Label: netLabel, Type: NodeNetwork})
        ts := na.Timestamp
        edgeType := EdgeConnect
        switch na.Activity {
        case "bind": edgeType = EdgeBind
        case "listen": edgeType = EdgeListen
        case "accept": edgeType = EdgeAccept
        }
        g.Edges = append(g.Edges, GraphEdge{Source: procID, Target: netID, Type: edgeType, Timestamp: &ts})
        if limitReached(len(g.Nodes), opts) { break }
    }

    g.finalize()
    return g
}

// 通过攻击链ID构建子图
func BuildSubgraphByChainID(ec *EventContext, chainID string, opts SubgraphOptions) *Subgraph {
    g := &Subgraph{Nodes: make([]GraphNode, 0, 64), Edges: make([]GraphEdge, 0, 128)}
    if ec == nil || chainID == "" { g.finalize(); return g }

    chains := ec.GetAttackChains()
    var chain *AttackChain
    for _, c := range chains {
        if c.ChainID == chainID || c.ID == chainID {
            chain = c; break
        }
    }
    if chain == nil { g.finalize(); return g }

    // 链节点
    chainNodeID := fmt.Sprintf("chain:%s", chain.ChainID)
    g.Nodes = append(g.Nodes, GraphNode{ID: chainNodeID, Label: chain.ChainID, Type: NodeChain, Severity: chain.Severity})

    // 进程
    for _, pid := range chain.InvolvedProcesses {
        pidID := fmt.Sprintf("proc:%d", pid)
        pc := ec.GetProcessContext(pid)
        label := pidID
        if pc != nil && pc.Comm != "" { label = fmt.Sprintf("%s(%d)", pc.Comm, pid) }
        g.Nodes = appendIfMissingNode(g.Nodes, GraphNode{ID: pidID, Label: label, Type: NodeProcess})
        g.Edges = append(g.Edges, GraphEdge{Source: chainNodeID, Target: pidID, Type: EdgeChainAssoc})
        if pc != nil {
            // 文件
            for _, f := range pc.FileOperations {
                if !inTimeRange(f.Timestamp, opts) { continue }
                fileID := fmt.Sprintf("file:%s", f.FilePath)
                g.Nodes = appendIfMissingNode(g.Nodes, GraphNode{ID: fileID, Label: f.FilePath, Type: NodeFile})
                ts := f.Timestamp
                edgeType := EdgeFileRead
                if f.Operation == "write" || f.Operation == "rename" || f.Operation == "unlink" || f.Operation == "chmod" || f.Operation == "chown" {
                    edgeType = EdgeFileWrite
                }
                g.Edges = append(g.Edges, GraphEdge{Source: pidID, Target: fileID, Type: edgeType, Timestamp: &ts})
                if limitReached(len(g.Nodes), opts) { break }
            }
            // 网络
            for _, na := range pc.NetworkActivity {
                if !inTimeRange(na.Timestamp, opts) { continue }
                netLabel := fmt.Sprintf("%s:%d", na.RemoteAddr, na.RemotePort)
                netID := fmt.Sprintf("net:%s", netLabel)
                g.Nodes = appendIfMissingNode(g.Nodes, GraphNode{ID: netID, Label: netLabel, Type: NodeNetwork})
                ts := na.Timestamp
                edgeType := EdgeConnect
                switch na.Activity {
                case "bind": edgeType = EdgeBind
                case "listen": edgeType = EdgeListen
                case "accept": edgeType = EdgeAccept
                }
                g.Edges = append(g.Edges, GraphEdge{Source: pidID, Target: netID, Type: edgeType, Timestamp: &ts})
                if limitReached(len(g.Nodes), opts) { break }
            }
        }
    }

    // 文件（链级别涉及）
    for _, fp := range chain.InvolvedFiles {
        fileID := fmt.Sprintf("file:%s", fp)
        g.Nodes = appendIfMissingNode(g.Nodes, GraphNode{ID: fileID, Label: fp, Type: NodeFile})
        g.Edges = append(g.Edges, GraphEdge{Source: chainNodeID, Target: fileID, Type: EdgeChainAssoc})
        if limitReached(len(g.Nodes), opts) { break }
    }

    // 网络（链级别涉及）
    for _, net := range chain.InvolvedNetworks {
        netID := fmt.Sprintf("net:%s", net)
        g.Nodes = appendIfMissingNode(g.Nodes, GraphNode{ID: netID, Label: net, Type: NodeNetwork})
        g.Edges = append(g.Edges, GraphEdge{Source: chainNodeID, Target: netID, Type: EdgeChainAssoc})
        if limitReached(len(g.Nodes), opts) { break }
    }

    g.finalize()
    return g
}

// 工具函数
func appendIfMissingNode(nodes []GraphNode, n GraphNode) []GraphNode {
    for _, existing := range nodes {
        if existing.ID == n.ID {
            return nodes
        }
    }
    return append(nodes, n)
}

func inTimeRange(ts time.Time, opts SubgraphOptions) bool {
    if opts.Since != nil && ts.Before(*opts.Since) {
        return false
    }
    if opts.Until != nil && ts.After(*opts.Until) {
        return false
    }
    return true
}

func limitReached(current int, opts SubgraphOptions) bool {
    if opts.MaxNodes > 0 && current >= opts.MaxNodes {
        return true
    }
    return false
}