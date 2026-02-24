# 规则引擎重写实施计划

## 概述

重写 eTracee 规则引擎，使其完全兼容主流开源项目 Tracee 和 Falco 的规则格式，支持直接导入和使用这些项目的规则集。

## 当前问题分析

### 现有规则引擎问题

1. **规则格式不兼容**：现有 YAML 规则格式与 Falco/Tracee 标准格式差异较大
2. **字段映射不完整**：部分 Falco/Tracee 字段无法正确映射到 eTracee 事件字段
3. **条件解析器能力有限**：不支持复杂的 Falco 条件表达式（如宏展开、列表引用）
4. **缺少规则来源追踪**：无法区分规则来源和版本
5. **导入工具功能有限**：rule_importer 转换不完整，大量规则 conditions 为空

### 兼容性需求

1. **Falco 规则兼容**：支持 Falco 原生规则格式（YAML）
2. **Tracee 规则兼容**：支持 Tracee 签名格式（JSON）
3. **字段映射**：完整映射 Falco/Tracee 字段到 eTracee 事件模型
4. **条件表达式**：支持 AND/OR/NOT 逻辑运算和复杂条件

## 技术设计

### 新架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    Rule Engine Core                          │
├─────────────────────────────────────────────────────────────┤
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐   │
│  │ Falco Parser  │  │Tracee Parser  │  │ Native Parser │   │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘   │
│          │                  │                  │            │
│          └──────────────────┼──────────────────┘            │
│                             ▼                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Unified Rule Model                      │   │
│  │  - RuleID, Name, Description, Severity               │   │
│  │  - Source (falco/tracee/native)                      │   │
│  │  - Conditions (compiled)                              │   │
│  │  - Tags, MITRE Mapping                                │   │
│  └─────────────────────────────────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           Condition Matcher Engine                   │   │
│  │  - Expression Evaluator                              │   │
│  │  - Field Resolver                                    │   │
│  │  - Cache Layer                                       │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 核心模块

1. **规则解析器 (Rule Parser)**
   - FalcoParser: 解析 Falco YAML 规则
   - TraceeParser: 解析 Tracee JSON 签名
   - NativeParser: 解析原生 YAML 规则

2. **统一规则模型 (Unified Rule Model)**
   - 统一的规则数据结构
   - 条件表达式抽象语法树 (AST)
   - 编译后的规则缓存

3. **条件匹配引擎 (Condition Matcher)**
   - 表达式求值器
   - 字段解析器
   - 性能优化缓存

4. **字段映射层 (Field Mapper)**
   - Falco 字段映射表
   - Tracee 字段映射表
   - 动态映射扩展

### 字段映射设计

```go
var FalcoFieldMapping = map[string]string{
    // 进程相关
    "proc.name":     "comm",
    "proc.exe":      "filename",
    "proc.pid":      "pid",
    "proc.ppid":     "ppid",
    "proc.cmdline":  "cmdline",
    "proc.args":     "cmdline",
    "proc.pname":    "parent_comm",
    "proc.pexe":     "parent_filename",
    
    // 用户相关
    "user.uid":      "uid",
    "user.name":     "username",
    "user.gid":      "gid",
    "group.gid":     "gid",
    
    // 文件相关
    "fd.name":       "filename",
    "fd.directory":  "directory",
    "fd.filename":   "basename",
    "fd.type":       "fd_type",
    "fd.l4proto":    "protocol",
    
    // 网络相关
    "fd.sip":        "dst_addr.ip",
    "fd.sport":      "src_addr.port",
    "fd.cip":        "dst_addr.ip",
    "fd.cport":      "dst_addr.port",
    
    // 事件相关
    "evt.type":      "event_type",
    "evt.res":       "ret_code",
    "evt.severity":  "severity",
}
```

### 条件表达式 AST

```go
type ConditionExpr interface {
    Evaluate(event *EventJSON) bool
}

type BinaryExpr struct {
    Op    string        // AND, OR
    Left  ConditionExpr
    Right ConditionExpr
}

type UnaryExpr struct {
    Op    string        // NOT
    Expr  ConditionExpr
}

type ComparisonExpr struct {
    Field    string
    Operator string      // =, !=, contains, regex, in, etc.
    Value    interface{}
}

type ExistsExpr struct {
    Field string
}
```
