#!/bin/bash

# eTracee 测试运行器
# 提供交互式测试选择界面

set -e

# 颜色定义
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# 脚本目录
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 显示菜单
show_menu() {
    echo -e "${CYAN}========================================"
    echo "       eTracee 测试运行器"
    echo -e "========================================${NC}"
    echo
    echo "请选择测试模式："
    echo
    echo -e "${GREEN}1)${NC} 快速验证 (推荐用于日常开发)"
    echo "   - 编译测试"
    echo "   - 配置加载"
    echo "   - 漏洞修复验证"
    echo "   - 基本功能测试"
    echo "   预计时间: 1-2 分钟"
    echo
    echo -e "${YELLOW}2)${NC} 完整测试 (推荐用于发布前)"
    echo "   - 环境和依赖检查"
    echo "   - 全面功能测试"
    echo "   - 安全漏洞验证"
    echo "   - 性能和内存测试"
    echo "   - HTML报告生成"
    echo "   预计时间: 5-10 分钟"
    echo
    echo -e "${BLUE}3)${NC} 原有功能测试"
    echo "   - 基础功能验证"
    echo "   预计时间: 2-3 分钟"
    echo
    echo -e "${RED}4)${NC} 退出"
    echo
}

# 检查权限
check_permissions() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 需要 root 权限运行测试${NC}"
        echo "请使用: sudo $0"
        exit 1
    fi
}

# 运行快速验证
run_quick_test() {
    echo -e "${GREEN}启动快速验证测试...${NC}"
    echo
    
    if [[ -f "$SCRIPT_DIR/quick_validation.sh" ]]; then
        chmod +x "$SCRIPT_DIR/quick_validation.sh"
        "$SCRIPT_DIR/quick_validation.sh"
    else
        echo -e "${RED}错误: 找不到快速验证脚本${NC}"
        exit 1
    fi
}

# 运行完整测试
run_comprehensive_test() {
    echo -e "${GREEN}启动完整测试...${NC}"
    echo -e "${YELLOW}注意: 完整测试可能需要 5-10 分钟${NC}"
    echo
    
    read -p "是否继续? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ -f "$SCRIPT_DIR/comprehensive_test.sh" ]]; then
            chmod +x "$SCRIPT_DIR/comprehensive_test.sh"
            "$SCRIPT_DIR/comprehensive_test.sh"
        else
            echo -e "${RED}错误: 找不到完整测试脚本${NC}"
            exit 1
        fi
    else
        echo "测试已取消"
        exit 0
    fi
}

# 运行原有功能测试
run_functionality_test() {
    echo -e "${GREEN}启动原有功能测试...${NC}"
    echo
    
    if [[ -f "$SCRIPT_DIR/test_functionality.sh" ]]; then
        chmod +x "$SCRIPT_DIR/test_functionality.sh"
        "$SCRIPT_DIR/test_functionality.sh"
    else
        echo -e "${RED}错误: 找不到功能测试脚本${NC}"
        exit 1
    fi
}

# 主函数
main() {
    # 检查权限
    check_permissions
    
    # 显示菜单并获取用户选择
    while true; do
        show_menu
        read -p "请输入选择 (1-4): " choice
        echo
        
        case $choice in
            1)
                run_quick_test
                break
                ;;
            2)
                run_comprehensive_test
                break
                ;;
            3)
                run_functionality_test
                break
                ;;
            4)
                echo "退出测试运行器"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-4${NC}"
                echo
                sleep 1
                ;;
        esac
    done
}

# 处理命令行参数
if [[ $# -gt 0 ]]; then
    case $1 in
        --quick|-q)
            check_permissions
            run_quick_test
            ;;
        --comprehensive|-c)
            check_permissions
            run_comprehensive_test
            ;;
        --functionality|-f)
            check_permissions
            run_functionality_test
            ;;
        --help|-h)
            echo "用法: $0 [选项]"
            echo
            echo "选项:"
            echo "  --quick, -q           运行快速验证测试"
            echo "  --comprehensive, -c   运行完整测试"
            echo "  --functionality, -f   运行原有功能测试"
            echo "  --help, -h           显示此帮助信息"
            echo
            echo "不带参数运行将显示交互式菜单"
            exit 0
            ;;
        *)
            echo -e "${RED}未知选项: $1${NC}"
            echo "使用 --help 查看可用选项"
            exit 1
            ;;
    esac
else
    main
fi