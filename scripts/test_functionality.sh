#!/bin/bash

# eTracee 功能测试脚本
# 用于验证各项功能是否正常工作

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 测试结果统计
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    ((PASSED_TESTS++))
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ((FAILED_TESTS++))
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# 测试函数
test_function() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    local timeout_seconds="${4:-10}"
    
    ((TOTAL_TESTS++))
    log_info "测试: $test_name"
    
    # 创建临时文件存储输出
    local temp_output=$(mktemp)
    local temp_error=$(mktemp)
    
    # 运行测试命令
    if timeout $timeout_seconds bash -c "$test_command" > "$temp_output" 2> "$temp_error"; then
        if [[ -n "$expected_pattern" ]]; then
            if grep -q "$expected_pattern" "$temp_output" || grep -q "$expected_pattern" "$temp_error"; then
                log_success "$test_name - 通过"
            else
                log_error "$test_name - 未找到预期输出: $expected_pattern"
                echo "实际输出:"
                cat "$temp_output" "$temp_error" | head -10
            fi
        else
            log_success "$test_name - 通过"
        fi
    else
        log_error "$test_name - 命令执行失败"
        echo "错误输出:"
        cat "$temp_error" | head -10
    fi
    
    # 清理临时文件
    rm -f "$temp_output" "$temp_error"
    echo
}

# 检查权限
check_permissions() {
    log_info "检查运行权限..."
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        echo "请使用: sudo $0"
        exit 1
    fi
    log_success "权限检查通过"
    echo
}

# 检查依赖
check_dependencies() {
    log_info "检查系统依赖..."
    
    local deps=("make" "go" "clang" "llvm" "bpftool")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "缺少依赖: ${missing_deps[*]}"
        return 1
    fi
    
    log_success "依赖检查通过"
    echo
}

# 检查项目结构
check_project_structure() {
    log_info "检查项目结构..."
    
    local required_files=(
        "Makefile"
        "src/bpf/etracee_main.c"
        "src/go/main.go"
        "src/go/dashboard.go"
        "src/go/aggregator.go"
        "config/security_rules.yaml"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "缺少必需文件: $file"
            return 1
        fi
    done
    
    log_success "项目结构检查通过"
    echo
}

# 测试编译
test_compilation() {
    log_info "测试项目编译..."
    
    # 清理之前的构建
    make clean &> /dev/null || true
    
    # 编译项目
    if make all &> /dev/null; then
        log_success "编译测试通过"
    else
        log_error "编译失败"
        make all
        return 1
    fi
    echo
}

# 测试基本功能
test_basic_functionality() {
    log_info "开始基本功能测试..."
    
    # 测试帮助信息
    test_function "帮助信息显示" \
        "./bin/etracee -h" \
        "Usage of"
    
    # 测试配置文件加载
    test_function "配置文件加载" \
        "timeout 3s ./bin/etracee -config config/security_rules.yaml" \
        ""
    
    # 测试Dashboard模式
    test_function "Dashboard模式启动" \
        "timeout 3s ./bin/etracee -dashboard" \
        ""
    
    # 测试PID过滤
    test_function "PID过滤功能" \
        "timeout 3s ./bin/etracee -pid-min 1000 -pid-max 2000" \
        ""
    
    # 测试UID过滤
    test_function "UID过滤功能" \
        "timeout 3s ./bin/etracee -uid-min 1000 -uid-max 2000" \
        ""
}

# 测试事件捕获
test_event_capture() {
    log_info "测试事件捕获功能..."
    
    # 在后台启动eTracee
    timeout 10s ./bin/etracee > /tmp/etracee_test.log 2>&1 &
    local etracee_pid=$!
    
    # 等待启动
    sleep 2
    
    # 生成一些测试事件
    ls /tmp > /dev/null
    echo "test" > /tmp/etracee_test_file
    rm -f /tmp/etracee_test_file
    
    # 等待事件处理
    sleep 3
    
    # 停止eTracee
    kill $etracee_pid 2>/dev/null || true
    wait $etracee_pid 2>/dev/null || true
    
    # 检查是否捕获到事件
    if [[ -f /tmp/etracee_test.log ]] && [[ -s /tmp/etracee_test.log ]]; then
        local event_count=$(grep -c '"event_type"' /tmp/etracee_test.log 2>/dev/null || echo 0)
        if [[ $event_count -gt 0 ]]; then
            log_success "事件捕获测试通过 - 捕获到 $event_count 个事件"
        else
            log_error "事件捕获测试失败 - 未捕获到事件"
        fi
    else
        log_error "事件捕获测试失败 - 无输出文件"
    fi
    
    # 清理
    rm -f /tmp/etracee_test.log
    echo
}

# 测试安全规则
test_security_rules() {
    log_info "测试安全规则功能..."
    
    # 检查配置文件
    if [[ -f "config/security_rules.yaml" ]]; then
        local rule_count=$(grep -c "name:" config/security_rules.yaml 2>/dev/null || echo 0)
        if [[ $rule_count -gt 0 ]]; then
            log_success "安全规则配置检查通过 - 发现 $rule_count 条规则"
        else
            log_error "安全规则配置检查失败 - 未发现规则"
        fi
    else
        log_error "安全规则配置文件不存在"
    fi
    echo
}

# 测试Dashboard功能
test_dashboard_functionality() {
    log_info "测试Dashboard功能..."
    
    # 启动Dashboard模式并快速停止
    timeout 5s ./bin/etracee -dashboard > /tmp/dashboard_test.log 2>&1 &
    local dashboard_pid=$!
    
    sleep 3
    kill $dashboard_pid 2>/dev/null || true
    wait $dashboard_pid 2>/dev/null || true
    
    # 检查Dashboard是否正常启动
    if [[ -f /tmp/dashboard_test.log ]]; then
        if grep -q "eTracee" /tmp/dashboard_test.log 2>/dev/null; then
            log_success "Dashboard功能测试通过"
        else
            log_error "Dashboard功能测试失败"
        fi
    else
        log_error "Dashboard功能测试失败 - 无输出"
    fi
    
    rm -f /tmp/dashboard_test.log
    echo
}

# 性能测试
test_performance() {
    log_info "进行性能测试..."
    
    # 启动eTracee并运行一段时间
    timeout 30s ./bin/etracee > /tmp/perf_test.log 2>&1 &
    local perf_pid=$!
    
    # 生成大量事件
    for i in {1..100}; do
        ls /tmp > /dev/null 2>&1
        echo "test$i" > /tmp/perf_test_$i
        rm -f /tmp/perf_test_$i
    done
    
    sleep 5
    kill $perf_pid 2>/dev/null || true
    wait $perf_pid 2>/dev/null || true
    
    if [[ -f /tmp/perf_test.log ]]; then
        local event_count=$(grep -c '"event_type"' /tmp/perf_test.log 2>/dev/null || echo 0)
        if [[ $event_count -gt 50 ]]; then
            log_success "性能测试通过 - 处理了 $event_count 个事件"
        else
            log_warning "性能测试 - 事件数量较少: $event_count"
        fi
    else
        log_error "性能测试失败"
    fi
    
    rm -f /tmp/perf_test.log
    echo
}

# 清理函数
cleanup() {
    log_info "清理测试环境..."
    
    # 杀死可能残留的进程
    pkill -f "etracee" 2>/dev/null || true
    
    # 清理临时文件
    rm -f /tmp/etracee_test* /tmp/dashboard_test* /tmp/perf_test*
    
    log_success "清理完成"
}

# 显示测试结果
show_results() {
    echo
    echo "=================================="
    echo "           测试结果汇总"
    echo "=================================="
    echo "总测试数: $TOTAL_TESTS"
    echo -e "通过: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "失败: ${RED}$FAILED_TESTS${NC}"
    echo "成功率: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
    echo "=================================="
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}所有测试通过！eTracee功能正常。${NC}"
        exit 0
    else
        echo -e "${RED}有 $FAILED_TESTS 个测试失败，请检查相关功能。${NC}"
        exit 1
    fi
}

# 主函数
main() {
    echo "=================================="
    echo "      eTracee 功能测试脚本"
    echo "=================================="
    echo
    
    # 设置清理陷阱
    trap cleanup EXIT
    
    # 执行测试
    check_permissions
    check_dependencies
    check_project_structure
    test_compilation
    test_basic_functionality
    test_event_capture
    test_security_rules
    test_dashboard_functionality
    test_performance
    
    # 显示结果
    show_results
}

# 运行主函数
main "$@"