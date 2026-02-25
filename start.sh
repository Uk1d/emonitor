#!/bin/bash
# eTracee 快速启动脚本
# 用于快速启动 eTracee 进行测试和调试

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 默认配置
CONFIG_FILE="${PROJECT_ROOT}/config/enhanced_security_config.yaml"
BINARY="${PROJECT_ROOT}/bin/etracee"
DASHBOARD=false
VERBOSE=false

# 帮助信息
show_help() {
    echo ""
    echo -e "${BLUE}eTracee 快速启动脚本${NC}"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help       显示帮助信息"
    echo "  -b, --build      启动前重新构建"
    echo "  -d, --dashboard  启用命令行 Dashboard"
    echo "  -v, --verbose    详细输出模式"
    echo "  -c, --config     指定配置文件路径"
    echo ""
    echo "示例:"
    echo "  $0                    # 直接启动"
    echo "  $0 -b                 # 构建后启动"
    echo "  $0 -d                 # 启用 Dashboard"
    echo "  $0 -b -d -v           # 构建后启动，启用 Dashboard 和详细输出"
    echo ""
}

# 检查 root 权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 需要 root 权限运行 eTracee${NC}"
        echo "请使用: sudo $0 $@"
        exit 1
    fi
}

# 检查依赖
check_dependencies() {
    echo -e "${BLUE}检查依赖...${NC}"

    # 检查二进制文件
    if [ ! -f "$BINARY" ]; then
        echo -e "${YELLOW}二进制文件不存在，需要先构建${NC}"
        return 1
    fi

    # 检查配置文件
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}错误: 配置文件不存在: $CONFIG_FILE${NC}"
        exit 1
    fi

    # 检查 eBPF 对象文件
    if [ ! -f "${PROJECT_ROOT}/build/etracee.bpf.o" ]; then
        echo -e "${YELLOW}警告: eBPF 对象文件不存在，可能需要构建${NC}"
    fi

    echo -e "${GREEN}依赖检查通过${NC}"
    return 0
}

# 构建项目
build_project() {
    echo -e "${BLUE}构建项目...${NC}"
    cd "$PROJECT_ROOT"
    make all
    echo -e "${GREEN}构建完成${NC}"
}

# 启动 eTracee
start_etracee() {
    echo -e "${BLUE}启动 eTracee...${NC}"

    # 构建参数
    ARGS="-config $CONFIG_FILE"

    if [ "$DASHBOARD" = true ]; then
        ARGS="$ARGS -dashboard"
    fi

    # 设置环境变量（可选）
    export ETRACEE_LOG_LEVEL="${LOG_LEVEL:-info}"

    echo -e "${GREEN}运行命令: $BINARY $ARGS${NC}"
    echo ""

    # 启动
    exec "$BINARY" $ARGS
}

# 解析参数
BUILD=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -b|--build)
            BUILD=true
            shift
            ;;
        -d|--dashboard)
            DASHBOARD=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            export ETRACEE_LOG_LEVEL=debug
            shift
            ;;
        -c|--config)
            CONFIG_FILE="$2"
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
echo -e "${BLUE}  eTracee - eBPF 入侵检测系统${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 如果指定构建或二进制不存在，则构建
if [ "$BUILD" = true ] || [ ! -f "$BINARY" ]; then
    build_project
fi

# 检查依赖
check_dependencies

# 检查 root 权限
check_root "$@"

# 启动
start_etracee
