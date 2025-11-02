#!/bin/bash

# eTracee 快速验证脚本
# 用于开发过程中的快速功能验证
# 专注于核心功能和最近修复的问题

set -e

# 颜色定义
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# 配置
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TEMP_DIR="/tmp/etracee_quick_$$"

# 创建临时目录
mkdir -p "$TEMP_DIR"

# 日志函数
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# 清理函数
cleanup() {
    pkill -f "etracee" 2>/dev/null || true
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# 快速编译测试
quick_compile_test() {
    log_info "快速编译测试..."
    cd "$PROJECT_ROOT/src/go"
    
    if go build -o ../../bin/etracee . 2>&1; then
        log_success "编译成功"
        return 0
    else
        log_error "编译失败"
        return 1
    fi
}

# 配置加载测试
quick_config_test() {
    log_info "配置加载测试..."
    cd "$PROJECT_ROOT"
    
    local config_log="$TEMP_DIR/config.log"
    if timeout 5s ./bin/etracee -config config/security_rules.yaml > "$config_log" 2>&1; then
        if grep -q "规则编译完成\|compiled.*rules\|categories compiled" "$config_log"; then
            log_success "配置加载成功"
            return 0
        else
            log_warning "配置加载 - 未检测到规则编译信息"
            return 1
        fi
    else
        log_error "配置加载失败"
        tail -3 "$config_log"
        return 1
    fi
}

# 数组越界修复验证
quick_bounds_test() {
    log_info "数组越界修复验证..."
    cd "$PROJECT_ROOT"
    
    local bounds_log="$TEMP_DIR/bounds.log"
    timeout 8s ./bin/etracee > "$bounds_log" 2>&1 &
    local pid=$!
    
    sleep 3
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    
    if grep -q "index out of range\|panic.*runtime error" "$bounds_log"; then
        log_error "仍存在数组越界问题"
        grep -A2 -B2 "index out of range\|panic" "$bounds_log"
        return 1
    else
        log_success "数组越界修复验证通过"
        return 0
    fi
}

# 空指针修复验证
quick_null_test() {
    log_info "空指针修复验证..."
    cd "$PROJECT_ROOT"
    
    local null_log="$TEMP_DIR/null.log"
    timeout 8s ./bin/etracee > "$null_log" 2>&1 &
    local pid=$!
    
    sleep 3
    # 生成一些可能触发空指针的事件
    ping -c 2 127.0.0.1 > /dev/null 2>&1 || true
    
    sleep 2
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    
    if grep -q "nil pointer\|segmentation fault\|panic.*nil" "$null_log"; then
        log_error "仍存在空指针问题"
        grep -A2 -B2 "nil pointer\|segmentation fault" "$null_log"
        return 1
    else
        log_success "空指针修复验证通过"
        return 0
    fi
}

# 基本功能测试
quick_functionality_test() {
    log_info "基本功能测试..."
    cd "$PROJECT_ROOT"
    
    local func_log="$TEMP_DIR/func.log"
    timeout 10s ./bin/etracee > "$func_log" 2>&1 &
    local pid=$!
    
    sleep 2
    
    # 生成一些测试事件
    echo "test" > "$TEMP_DIR/test_file"
    cat "$TEMP_DIR/test_file" > /dev/null
    rm -f "$TEMP_DIR/test_file"
    
    sleep 3
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    
    if [[ -s "$func_log" ]]; then
        local lines=$(wc -l < "$func_log")
        if [[ $lines -gt 5 ]]; then
            log_success "基本功能测试通过 ($lines 行输出)"
            return 0
        else
            log_warning "基本功能测试 - 输出较少 ($lines 行)"
            return 1
        fi
    else
        log_error "基本功能测试失败 - 无输出"
        return 1
    fi
}

# 主函数
main() {
    echo "========================================"
    echo "       eTracee 快速验证脚本"
    echo "========================================"
    echo "时间: $(date)"
    echo
    
    local tests_passed=0
    local total_tests=5
    
    # 执行快速测试
    quick_compile_test && ((tests_passed++))
    quick_config_test && ((tests_passed++))
    quick_bounds_test && ((tests_passed++))
    quick_null_test && ((tests_passed++))
    quick_functionality_test && ((tests_passed++))
    
    echo
    echo "========================================"
    echo "           快速验证结果"
    echo "========================================"
    echo "通过测试: $tests_passed/$total_tests"
    
    if [[ $tests_passed -eq $total_tests ]]; then
        echo -e "${GREEN}✅ 所有快速测试通过！${NC}"
        echo "eTracee 核心功能正常，可以继续开发。"
        exit 0
    else
        echo -e "${RED}❌ 有 $((total_tests - tests_passed)) 个测试失败${NC}"
        echo "建议运行完整测试脚本进行详细检查。"
        exit 1
    fi
}

# 运行主函数
main "$@"