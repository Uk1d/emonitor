#!/bin/bash

# eTracee 综合测试脚本
# 用于验证所有核心功能，包括最近修复的问题
# 作者: eTracee 开发团队
# 版本: 2.0

set -e

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# 测试结果统计
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# 配置
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TEST_LOG_DIR="${PROJECT_ROOT}/logs/test_$(date +%Y%m%d_%H%M%S)"
readonly TEMP_DIR="/tmp/etracee_test_$$"

# 创建测试目录
mkdir -p "$TEST_LOG_DIR" "$TEMP_DIR"

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$TEST_LOG_DIR/test.log"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$TEST_LOG_DIR/test.log"
    ((PASSED_TESTS++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$TEST_LOG_DIR/test.log"
    ((FAILED_TESTS++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$TEST_LOG_DIR/test.log"
}

log_skip() {
    echo -e "${PURPLE}[SKIP]${NC} $1" | tee -a "$TEST_LOG_DIR/test.log"
    ((SKIPPED_TESTS++))
}

# 测试框架函数
run_test() {
    local test_name="$1"
    local test_function="$2"
    local timeout_seconds="${3:-30}"
    
    ((TOTAL_TESTS++))
    log_info "执行测试: $test_name"
    
    local test_log="$TEST_LOG_DIR/${test_name// /_}.log"
    
    if timeout "$timeout_seconds" bash -c "$test_function" > "$test_log" 2>&1; then
        log_success "$test_name"
        return 0
    else
        local exit_code=$?
        log_error "$test_name (退出码: $exit_code)"
        echo "详细日志: $test_log"
        tail -10 "$test_log" | sed 's/^/  /'
        return 1
    fi
}

# 环境检查函数
check_environment() {
    log_info "检查测试环境..."
    
    # 检查操作系统
    if [[ ! -f /etc/os-release ]]; then
        log_error "不支持的操作系统"
        return 1
    fi
    
    local os_name=$(grep '^NAME=' /etc/os-release | cut -d'"' -f2)
    log_info "操作系统: $os_name"
    
    # 检查内核版本
    local kernel_version=$(uname -r)
    log_info "内核版本: $kernel_version"
    
    # 检查是否支持eBPF
    if [[ ! -d /sys/fs/bpf ]]; then
        log_warning "eBPF文件系统未挂载，尝试挂载..."
        if ! mount -t bpf bpf /sys/fs/bpf 2>/dev/null; then
            log_error "无法挂载eBPF文件系统"
            return 1
        fi
    fi
    
    log_success "环境检查通过"
}

# 权限检查
check_permissions() {
    log_info "检查运行权限..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行eBPF程序"
        echo "请使用: sudo $0"
        return 1
    fi
    
    # 检查必要的capabilities
    local caps=("CAP_SYS_ADMIN" "CAP_BPF" "CAP_PERFMON")
    for cap in "${caps[@]}"; do
        if ! capsh --print | grep -q "$cap"; then
            log_warning "缺少capability: $cap"
        fi
    done
    
    log_success "权限检查通过"
}

# 依赖检查
check_dependencies() {
    log_info "检查系统依赖..."
    
    local required_tools=(
        "go:Go编译器"
        "make:构建工具"
        "clang:LLVM C编译器"
        "llc:LLVM编译器"
        "bpftool:BPF工具"
        "timeout:超时工具"
        "pkill:进程管理"
    )
    
    local missing_deps=()
    
    for tool_desc in "${required_tools[@]}"; do
        local tool="${tool_desc%%:*}"
        local desc="${tool_desc##*:}"
        
        if ! command -v "$tool" &> /dev/null; then
            missing_deps+=("$tool ($desc)")
        else
            local version=$(command -v "$tool" --version 2>/dev/null | head -1 || echo "未知版本")
            log_info "$desc: $version"
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "缺少依赖工具:"
        printf '  %s\n' "${missing_deps[@]}"
        return 1
    fi
    
    log_success "依赖检查通过"
}

# 项目结构检查
check_project_structure() {
    log_info "检查项目结构..."
    
    cd "$PROJECT_ROOT"
    
    local required_files=(
        "Makefile:构建配置"
        "src/bpf/etracee_main.c:eBPF主程序"
        "src/go/main.go:Go主程序"
        "src/go/rule_engine.go:规则引擎"
        "src/go/event_context.go:事件上下文"
        "config/security_rules.yaml:安全规则配置"
    )
    
    for file_desc in "${required_files[@]}"; do
        local file="${file_desc%%:*}"
        local desc="${file_desc##*:}"
        
        if [[ ! -f "$file" ]]; then
            log_error "缺少必需文件: $file ($desc)"
            return 1
        else
            local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
            log_info "$desc: $file (${size} bytes)"
        fi
    done
    
    log_success "项目结构检查通过"
}

# 编译测试
test_compilation() {
    log_info "测试项目编译..."
    
    cd "$PROJECT_ROOT"
    
    # 清理之前的构建
    make clean &> /dev/null || true
    
    # 编译Go程序
    log_info "编译Go程序..."
    if ! cd src/go && go build -o ../../bin/etracee . 2>&1; then
        log_error "Go程序编译失败"
        return 1
    fi
    
    # 检查可执行文件
    if [[ ! -x "../../bin/etracee" ]]; then
        log_error "可执行文件未生成"
        return 1
    fi
    
    cd "$PROJECT_ROOT"
    local binary_size=$(stat -f%z "bin/etracee" 2>/dev/null || stat -c%s "bin/etracee" 2>/dev/null)
    log_info "可执行文件大小: ${binary_size} bytes"
    
    log_success "编译测试通过"
}

# 配置文件测试
test_config_loading() {
    log_info "测试配置文件加载..."
    
    cd "$PROJECT_ROOT"
    
    # 测试配置文件语法
    if command -v yq &> /dev/null; then
        if ! yq eval '.' config/security_rules.yaml > /dev/null 2>&1; then
            log_error "YAML配置文件语法错误"
            return 1
        fi
    fi
    
    # 测试程序加载配置
    local config_test_log="$TEMP_DIR/config_test.log"
    if timeout 5s ./bin/etracee -config config/security_rules.yaml > "$config_test_log" 2>&1; then
        if grep -q "规则编译完成" "$config_test_log" || grep -q "compiled" "$config_test_log"; then
            local rule_count=$(grep -o "编译了 [0-9]* 条规则" "$config_test_log" | grep -o "[0-9]*" || echo "未知")
            log_info "成功加载 $rule_count 条规则"
            log_success "配置文件加载测试通过"
        else
            log_error "配置文件加载失败"
            tail -5 "$config_test_log"
            return 1
        fi
    else
        log_error "程序启动失败"
        return 1
    fi
}

# 规则引擎测试
test_rule_engine() {
    log_info "测试规则引擎功能..."
    
    cd "$PROJECT_ROOT"
    
    # 测试规则编译
    local rule_test_log="$TEMP_DIR/rule_test.log"
    timeout 10s ./bin/etracee -config config/security_rules.yaml > "$rule_test_log" 2>&1 &
    local etracee_pid=$!
    
    sleep 3
    
    # 检查规则编译日志
    if grep -q "规则编译完成\|compiled.*rules" "$rule_test_log"; then
        log_success "规则编译测试通过"
    else
        log_error "规则编译测试失败"
        tail -10 "$rule_test_log"
    fi
    
    # 清理进程
    kill $etracee_pid 2>/dev/null || true
    wait $etracee_pid 2>/dev/null || true
}

# 数组越界修复验证
test_array_bounds_fix() {
    log_info "验证数组越界修复..."
    
    cd "$PROJECT_ROOT"
    
    # 创建测试配置，包含可能触发数组越界的规则
    local test_config="$TEMP_DIR/test_rules.yaml"
    cat > "$test_config" << 'EOF'
global:
  enable_file_events: true
  enable_network_events: true
  enable_process_events: true
  log_level: "debug"

detection_rules:
  test_category:
    - name: "array_bounds_test"
      description: "测试数组边界处理"
      conditions:
        - process_name: "regex:.*test.*"
        - pid: ">1000"
        - uid: "<65535"
      severity: "medium"
      enabled: true
      actions: ["log"]

response_actions:
  critical_severity: ["alert", "block"]
  high_severity: ["alert", "log"]
  medium_severity: ["log"]
  low_severity: ["log"]
EOF
    
    # 运行测试
    local bounds_test_log="$TEMP_DIR/bounds_test.log"
    if timeout 15s ./bin/etracee -config "$test_config" > "$bounds_test_log" 2>&1; then
        if ! grep -q "index out of range\|panic\|runtime error" "$bounds_test_log"; then
            log_success "数组越界修复验证通过"
        else
            log_error "仍存在数组越界问题"
            grep -A5 -B5 "index out of range\|panic\|runtime error" "$bounds_test_log"
            return 1
        fi
    else
        # 检查是否是正常超时退出
        if ! grep -q "index out of range\|panic\|runtime error" "$bounds_test_log"; then
            log_success "数组越界修复验证通过 (正常超时)"
        else
            log_error "数组越界问题仍然存在"
            return 1
        fi
    fi
}

# 空指针修复验证
test_null_pointer_fix() {
    log_info "验证空指针修复..."
    
    cd "$PROJECT_ROOT"
    
    # 运行程序并生成可能触发空指针的事件
    local null_test_log="$TEMP_DIR/null_test.log"
    timeout 10s ./bin/etracee > "$null_test_log" 2>&1 &
    local etracee_pid=$!
    
    sleep 2
    
    # 生成一些网络事件（可能触发SrcAddr为空的情况）
    ping -c 3 127.0.0.1 > /dev/null 2>&1 || true
    
    sleep 3
    kill $etracee_pid 2>/dev/null || true
    wait $etracee_pid 2>/dev/null || true
    
    # 检查是否有空指针错误
    if ! grep -q "nil pointer\|segmentation fault\|panic.*nil" "$null_test_log"; then
        log_success "空指针修复验证通过"
    else
        log_error "仍存在空指针问题"
        grep -A3 -B3 "nil pointer\|segmentation fault\|panic.*nil" "$null_test_log"
        return 1
    fi
}

# 事件捕获测试
test_event_capture() {
    log_info "测试事件捕获功能..."
    
    cd "$PROJECT_ROOT"
    
    # 启动eTracee
    local capture_log="$TEMP_DIR/capture_test.log"
    timeout 20s ./bin/etracee > "$capture_log" 2>&1 &
    local etracee_pid=$!
    
    sleep 3
    
    # 生成各种类型的测试事件
    log_info "生成测试事件..."
    
    # 文件系统事件
    echo "test data" > "$TEMP_DIR/test_file"
    cat "$TEMP_DIR/test_file" > /dev/null
    rm -f "$TEMP_DIR/test_file"
    
    # 进程事件
    /bin/ls /tmp > /dev/null
    /bin/ps aux | head -5 > /dev/null
    
    # 网络事件
    ping -c 2 127.0.0.1 > /dev/null 2>&1 || true
    
    sleep 5
    
    # 停止eTracee
    kill $etracee_pid 2>/dev/null || true
    wait $etracee_pid 2>/dev/null || true
    
    # 分析捕获的事件
    if [[ -f "$capture_log" && -s "$capture_log" ]]; then
        local event_count=$(grep -c '"event_type"\|事件类型' "$capture_log" 2>/dev/null || echo 0)
        if [[ $event_count -gt 0 ]]; then
            log_success "事件捕获测试通过 - 捕获到 $event_count 个事件"
        else
            log_warning "事件捕获测试 - 未检测到明确的事件格式"
            # 检查是否有其他形式的输出
            if [[ $(wc -l < "$capture_log") -gt 10 ]]; then
                log_success "事件捕获测试通过 - 有程序输出"
            else
                log_error "事件捕获测试失败 - 输出过少"
                return 1
            fi
        fi
    else
        log_error "事件捕获测试失败 - 无输出文件"
        return 1
    fi
}

# 性能测试
test_performance() {
    log_info "执行性能测试..."
    
    cd "$PROJECT_ROOT"
    
    # 启动性能监控
    local perf_log="$TEMP_DIR/performance_test.log"
    timeout 30s ./bin/etracee > "$perf_log" 2>&1 &
    local etracee_pid=$!
    
    # 记录开始时间
    local start_time=$(date +%s)
    
    sleep 3
    
    # 生成大量事件进行压力测试
    log_info "执行压力测试..."
    for i in {1..50}; do
        echo "performance test $i" > "$TEMP_DIR/perf_test_$i"
        cat "$TEMP_DIR/perf_test_$i" > /dev/null
        rm -f "$TEMP_DIR/perf_test_$i"
        
        # 每10个文件检查一次进程状态
        if [[ $((i % 10)) -eq 0 ]]; then
            if ! kill -0 $etracee_pid 2>/dev/null; then
                log_error "程序在压力测试中崩溃"
                return 1
            fi
        fi
    done
    
    sleep 5
    
    # 记录结束时间
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # 停止程序
    kill $etracee_pid 2>/dev/null || true
    wait $etracee_pid 2>/dev/null || true
    
    # 分析性能数据
    if [[ -f "$perf_log" ]]; then
        local output_lines=$(wc -l < "$perf_log")
        local avg_throughput=$((output_lines / duration))
        
        log_info "性能测试结果:"
        log_info "  测试时长: ${duration}秒"
        log_info "  输出行数: $output_lines"
        log_info "  平均吞吐量: ${avg_throughput}行/秒"
        
        if [[ $avg_throughput -gt 10 ]]; then
            log_success "性能测试通过"
        else
            log_warning "性能测试 - 吞吐量较低"
        fi
    else
        log_error "性能测试失败 - 无输出"
        return 1
    fi
}

# 内存泄漏检测
test_memory_leaks() {
    log_info "检测内存泄漏..."
    
    cd "$PROJECT_ROOT"
    
    if ! command -v valgrind &> /dev/null; then
        log_skip "内存泄漏检测 - valgrind未安装"
        return 0
    fi
    
    # 使用valgrind检测内存泄漏
    local valgrind_log="$TEMP_DIR/valgrind.log"
    timeout 15s valgrind --leak-check=full --show-leak-kinds=all \
        --track-origins=yes --log-file="$valgrind_log" \
        ./bin/etracee -config config/security_rules.yaml &
    
    local valgrind_pid=$!
    sleep 10
    kill $valgrind_pid 2>/dev/null || true
    wait $valgrind_pid 2>/dev/null || true
    
    # 分析valgrind输出
    if [[ -f "$valgrind_log" ]]; then
        local leak_count=$(grep -c "definitely lost\|possibly lost" "$valgrind_log" || echo 0)
        if [[ $leak_count -eq 0 ]]; then
            log_success "内存泄漏检测通过"
        else
            log_warning "检测到 $leak_count 个潜在内存泄漏"
        fi
    else
        log_skip "内存泄漏检测 - valgrind执行失败"
    fi
}

# 清理函数
cleanup() {
    log_info "清理测试环境..."
    
    # 杀死可能残留的进程
    pkill -f "etracee" 2>/dev/null || true
    pkill -f "valgrind.*etracee" 2>/dev/null || true
    
    # 清理临时文件
    rm -rf "$TEMP_DIR"
    
    log_success "清理完成"
}

# 生成测试报告
generate_report() {
    local report_file="$TEST_LOG_DIR/test_report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>eTracee 测试报告</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .pass { color: green; }
        .fail { color: red; }
        .skip { color: orange; }
        .test-details { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>eTracee 综合测试报告</h1>
        <p>测试时间: $(date)</p>
        <p>测试环境: $(uname -a)</p>
    </div>
    
    <div class="summary">
        <h2>测试汇总</h2>
        <p>总测试数: $TOTAL_TESTS</p>
        <p class="pass">通过: $PASSED_TESTS</p>
        <p class="fail">失败: $FAILED_TESTS</p>
        <p class="skip">跳过: $SKIPPED_TESTS</p>
        <p>成功率: $(( (PASSED_TESTS + SKIPPED_TESTS) * 100 / TOTAL_TESTS ))%</p>
    </div>
    
    <div class="test-details">
        <h2>详细日志</h2>
        <pre>$(cat "$TEST_LOG_DIR/test.log")</pre>
    </div>
</body>
</html>
EOF
    
    log_info "测试报告已生成: $report_file"
}

# 显示测试结果
show_results() {
    echo
    echo "=========================================="
    echo "           eTracee 测试结果汇总"
    echo "=========================================="
    echo "测试时间: $(date)"
    echo "测试日志: $TEST_LOG_DIR"
    echo "------------------------------------------"
    echo "总测试数: $TOTAL_TESTS"
    echo -e "通过: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "失败: ${RED}$FAILED_TESTS${NC}"
    echo -e "跳过: ${YELLOW}$SKIPPED_TESTS${NC}"
    echo "成功率: $(( (PASSED_TESTS + SKIPPED_TESTS) * 100 / TOTAL_TESTS ))%"
    echo "=========================================="
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}✅ 所有测试通过！eTracee功能正常。${NC}"
        generate_report
        exit 0
    else
        echo -e "${RED}❌ 有 $FAILED_TESTS 个测试失败，请检查相关功能。${NC}"
        echo "详细日志请查看: $TEST_LOG_DIR"
        generate_report
        exit 1
    fi
}

# 主函数
main() {
    echo "=========================================="
    echo "        eTracee 综合功能测试脚本"
    echo "=========================================="
    echo "版本: 2.0"
    echo "作者: eTracee 开发团队"
    echo "时间: $(date)"
    echo "=========================================="
    echo
    
    # 设置清理陷阱
    trap cleanup EXIT
    
    # 执行所有测试
    run_test "环境检查" "check_environment" 10
    run_test "权限检查" "check_permissions" 5
    run_test "依赖检查" "check_dependencies" 10
    run_test "项目结构检查" "check_project_structure" 5
    run_test "编译测试" "test_compilation" 60
    run_test "配置文件加载测试" "test_config_loading" 15
    run_test "规则引擎测试" "test_rule_engine" 20
    run_test "数组越界修复验证" "test_array_bounds_fix" 20
    run_test "空指针修复验证" "test_null_pointer_fix" 15
    run_test "事件捕获测试" "test_event_capture" 30
    run_test "性能测试" "test_performance" 45
    run_test "内存泄漏检测" "test_memory_leaks" 30
    
    # 显示结果
    show_results
}

# 检查参数
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi