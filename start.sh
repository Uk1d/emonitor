#!/bin/bash
# eTracee 快速启动脚本
# 支持集成模式和分离模式

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
WEBSERVER_BINARY="${PROJECT_ROOT}/bin/webserver"
DASHBOARD=false
VERBOSE=false
MODE="integrated"  # integrated, monitor, web, split

# 帮助信息
show_help() {
    echo ""
    echo -e "${BLUE}eTracee 快速启动脚本${NC}"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "运行模式:"
    echo "  --integrated      集成模式（默认）：监控程序和 Web 服务一起运行"
    echo "  --monitor         分离模式：仅启动监控程序（需要 root）"
    echo "  --web             分离模式：仅启动 Web 服务（无需 root）"
    echo "  --split           分离模式：同时启动监控程序和 Web 服务"
    echo ""
    echo "选项:"
    echo "  -h, --help        显示帮助信息"
    echo "  -b, --build       启动前重新构建"
    echo "  -d, --dashboard   启用命令行 Dashboard"
    echo "  -v, --verbose     详细输出模式"
    echo "  -c, --config      指定配置文件路径"
    echo ""
    echo "环境变量（Web 服务认证）:"
    echo "  MYSQL_WEB_HOST      MySQL 主机地址"
    echo "  MYSQL_WEB_USER      MySQL 用户名"
    echo "  MYSQL_WEB_PASSWORD  MySQL 密码"
    echo "  ADMIN_USERNAME      管理员用户名（默认: admin）"
    echo "  ADMIN_PASSWORD      管理员密码（默认: admin123）"
    echo ""
    echo "示例:"
    echo "  $0                          # 集成模式启动"
    echo "  $0 -b                       # 构建后集成模式启动"
    echo "  $0 --monitor                # 仅启动监控程序"
    echo "  $0 --web                    # 仅启动 Web 服务"
    echo "  $0 --split                  # 分离模式启动"
    echo ""
}

# 检查 root 权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 需要 root 权限运行监控程序${NC}"
        echo "请使用: sudo $0 $@"
        exit 1
    fi
}

# 检查依赖
check_dependencies() {
    echo -e "${BLUE}检查依赖...${NC}"

    # 检查二进制文件
    if [ ! -f "$BINARY" ]; then
        echo -e "${YELLOW}监控程序二进制文件不存在，需要先构建${NC}"
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

# 检查 Web 服务依赖
check_web_dependencies() {
    echo -e "${BLUE}检查 Web 服务依赖...${NC}"

    if [ ! -f "$WEBSERVER_BINARY" ]; then
        echo -e "${YELLOW}Web 服务二进制文件不存在，需要先构建${NC}"
        return 1
    fi

    echo -e "${GREEN}Web 服务依赖检查通过${NC}"
    return 0
}

# 构建项目
build_project() {
    echo -e "${BLUE}构建项目...${NC}"
    cd "$PROJECT_ROOT"
    make build-all
    echo -e "${GREEN}构建完成${NC}"
}

# 启动集成模式
start_integrated() {
    echo -e "${BLUE}启动 eTracee（集成模式）...${NC}"

    ARGS="-config $CONFIG_FILE"
    if [ "$DASHBOARD" = true ]; then
        ARGS="$ARGS -dashboard"
    fi

    export ETRACEE_LOG_LEVEL="${LOG_LEVEL:-info}"
    echo -e "${GREEN}运行命令: $BINARY $ARGS${NC}"
    echo ""

    exec "$BINARY" $ARGS
}

# 启动监控程序（分离模式）
start_monitor() {
    echo -e "${BLUE}启动监控程序（分离模式）...${NC}"

    ARGS="-config $CONFIG_FILE -monitor-only"

    export ETRACEE_LOG_LEVEL="${LOG_LEVEL:-info}"
    echo -e "${GREEN}运行命令: $BINARY $ARGS${NC}"
    echo -e "${YELLOW}Web 服务连接地址: ws://localhost:8889/ws${NC}"
    echo ""

    exec "$BINARY" $ARGS
}

# 启动 Web 服务（分离模式）
start_web() {
    echo -e "${BLUE}启动 Web 服务（分离模式）...${NC}"

    # 检查 MySQL 环境变量
    if [ -z "$MYSQL_WEB_HOST" ]; then
        echo -e "${YELLOW}警告: MYSQL_WEB_HOST 未设置，认证功能可能不可用${NC}"
        echo -e "${YELLOW}请设置以下环境变量以启用登录功能:${NC}"
        echo "  MYSQL_WEB_HOST=localhost"
        echo "  MYSQL_WEB_USER=root"
        echo "  MYSQL_WEB_PASSWORD=your_password"
        echo ""
    fi

    export WEB_PORT="${WEB_PORT:-8888}"
    export MONITOR_URL="${MONITOR_URL:-ws://localhost:8889/ws}"

    echo -e "${GREEN}Web 界面: http://localhost:${WEB_PORT}${NC}"
    echo -e "${GREEN}监控程序地址: ${MONITOR_URL}${NC}"
    echo ""

    exec "$WEBSERVER_BINARY"
}

# 启动分离模式（同时启动监控程序和 Web 服务）
start_split() {
    echo -e "${BLUE}启动分离模式（监控程序 + Web 服务）...${NC}"

    # 启动监控程序（后台）
    echo -e "${GREEN}启动监控程序...${NC}"
    ARGS="-config $CONFIG_FILE -monitor-only"
    sudo "$BINARY" $ARGS &
    MONITOR_PID=$!

    # 等待监控程序启动
    sleep 2

    # 检查监控程序是否运行
    if ! kill -0 $MONITOR_PID 2>/dev/null; then
        echo -e "${RED}监控程序启动失败${NC}"
        exit 1
    fi

    # 启动 Web 服务（前台）
    echo -e "${GREEN}启动 Web 服务...${NC}"
    export WEB_PORT="${WEB_PORT:-8888}"
    export MONITOR_URL="${MONITOR_URL:-ws://localhost:8889/ws}"

    echo -e "${GREEN}Web 界面: http://localhost:${WEB_PORT}${NC}"
    echo ""

    # 捕获退出信号
    trap "echo -e '${YELLOW}正在停止服务...${NC}'; sudo kill $MONITOR_PID 2>/dev/null; exit 0" SIGINT SIGTERM

    # 运行 Web 服务
    "$WEBSERVER_BINARY"
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
        --integrated)
            MODE="integrated"
            shift
            ;;
        --monitor)
            MODE="monitor"
            shift
            ;;
        --web)
            MODE="web"
            shift
            ;;
        --split)
            MODE="split"
            shift
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

# 根据模式检查和构建
case $MODE in
    integrated)
        if [ "$BUILD" = true ] || [ ! -f "$BINARY" ]; then
            build_project
        fi
        check_dependencies
        check_root "$@"
        start_integrated
        ;;
    monitor)
        if [ "$BUILD" = true ] || [ ! -f "$BINARY" ]; then
            build_project
        fi
        check_dependencies
        check_root "$@"
        start_monitor
        ;;
    web)
        if [ "$BUILD" = true ] || [ ! -f "$WEBSERVER_BINARY" ]; then
            build_project
        fi
        check_web_dependencies
        start_web
        ;;
    split)
        if [ "$BUILD" = true ] || [ ! -f "$BINARY" ] || [ ! -f "$WEBSERVER_BINARY" ]; then
            build_project
        fi
        check_dependencies
        check_web_dependencies
        start_split
        ;;
esac
