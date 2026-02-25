#!/bin/bash
# eTracee 环境设置脚本
# 用于安装系统依赖和初始化开发环境

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# 检测发行版
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
echo -e "${BLUE}检测到发行版: $DISTRO${NC}"

# 显示帮助
show_help() {
    echo ""
    echo -e "${BLUE}eTracee 环境设置脚本${NC}"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help       显示帮助信息"
    echo "  -d, --deps       安装系统依赖"
    echo "  -g, --go         安装 Go（如果未安装）"
    echo "  -b, --btf        检查 BTF 支持"
    echo "  -a, --all        执行所有设置步骤"
    echo "  -c, --check      仅检查环境，不安装"
    echo ""
}

# 检查 BTF 支持
check_btf() {
    echo -e "${BLUE}检查 BTF 支持...${NC}"
    if [ -f /sys/kernel/btf/vmlinux ]; then
        echo -e "${GREEN}BTF 支持正常${NC}"
        return 0
    else
        echo -e "${YELLOW}警告: 内核不支持 BTF${NC}"
        echo "您可以尝试:"
        echo "  1. 升级内核到 5.8+"
        echo "  2. 使用 BTFGen 生成 BTF 文件"
        return 1
    fi
}

# 检查内核版本
check_kernel() {
    echo -e "${BLUE}检查内核版本...${NC}"
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    REQUIRED_VERSION="5.8"

    # 版本比较
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$KERNEL_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
        echo -e "${GREEN}内核版本满足要求: $KERNEL_VERSION >= $REQUIRED_VERSION${NC}"
        return 0
    else
        echo -e "${RED}内核版本过低: $KERNEL_VERSION < $REQUIRED_VERSION${NC}"
        echo "请升级内核到 5.8 或更高版本"
        return 1
    fi
}

# 检查命令是否存在
check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}$1 已安装: $(command -v $1)${NC}"
        return 0
    else
        echo -e "${YELLOW}$1 未安装${NC}"
        return 1
    fi
}

# 检查环境
check_environment() {
    echo ""
    echo -e "${BLUE}=== 检查开发环境 ===${NC}"
    echo ""

    local all_ok=true

    # 检查内核
    check_kernel || all_ok=false
    echo ""

    # 检查 BTF
    check_btf || true  # BTF 不是必须的，只是警告
    echo ""

    # 检查 Go
    echo -e "${BLUE}检查 Go...${NC}"
    if check_command go; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        echo "  版本: $GO_VERSION"
    else
        all_ok=false
    fi
    echo ""

    # 检查 Clang
    echo -e "${BLUE}检查 Clang...${NC}"
    if check_command clang; then
        CLANG_VERSION=$(clang --version | head -1)
        echo "  版本: $CLANG_VERSION"
    else
        all_ok=false
    fi
    echo ""

    # 检查 LLVM
    echo -e "${BLUE}检查 LLVM...${NC}"
    if check_command llc; then
        LLVM_VERSION=$(llc --version | head -1)
        echo "  版本: $LLVM_VERSION"
    else
        all_ok=false
    fi
    echo ""

    # 检查 bpftool
    echo -e "${BLUE}检查 bpftool...${NC}"
    if check_command bpftool; then
        BPFTOOL_VERSION=$(bpftool version 2>&1 | head -1)
        echo "  版本: $BPFTOOL_VERSION"
    else
        echo -e "${YELLOW}bpftool 未安装（可选，用于生成 vmlinux.h）${NC}"
    fi
    echo ""

    # 检查 libbpf
    echo -e "${BLUE}检查 libbpf...${NC}"
    if [ -f /usr/include/bpf/bpf.h ] || [ -f /usr/include/bpf/libbpf.h ]; then
        echo -e "${GREEN}libbpf 头文件已安装${NC}"
    else
        echo -e "${YELLOW}libbpf 头文件未找到${NC}"
        all_ok=false
    fi
    echo ""

    # 检查内核头文件
    echo -e "${BLUE}检查内核头文件...${NC}"
    KERNEL_VERSION=$(uname -r)
    if [ -d "/lib/modules/$KERNEL_VERSION/build" ]; then
        echo -e "${GREEN}内核头文件已安装${NC}"
    else
        echo -e "${YELLOW}内核头文件未找到${NC}"
        all_ok=false
    fi
    echo ""

    if [ "$all_ok" = true ]; then
        echo -e "${GREEN}=== 环境检查通过 ===${NC}"
        return 0
    else
        echo -e "${YELLOW}=== 环境检查完成，部分依赖缺失 ===${NC}"
        return 1
    fi
}

# 安装系统依赖
install_deps() {
    echo -e "${BLUE}安装系统依赖...${NC}"

    case $DISTRO in
        ubuntu|debian)
            echo -e "${BLUE}使用 apt 安装依赖...${NC}"
            sudo apt update
            sudo apt install -y \
                build-essential \
                clang \
                llvm \
                gcc-multilib \
                libbpf-dev \
                linux-headers-$(uname -r) \
                pkg-config
            ;;
        centos|rhel|ol|openeuler)
            echo -e "${BLUE}使用 yum 安装依赖...${NC}"
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                clang \
                llvm \
                libbpf-devel \
                kernel-devel-$(uname -r) \
                pkgconfig
            ;;
        fedora)
            echo -e "${BLUE}使用 dnf 安装依赖...${NC}"
            sudo dnf groupinstall -y "Development Tools"
            sudo dnf install -y \
                clang \
                llvm \
                libbpf-devel \
                kernel-devel-$(uname -r) \
                pkgconfig
            ;;
        arch|manjaro)
            echo -e "${BLUE}使用 pacman 安装依赖...${NC}"
            sudo pacman -S --needed \
                base-devel \
                clang \
                llvm \
                libbpf \
                linux-headers
            ;;
        *)
            echo -e "${RED}不支持的发行版: $DISTRO${NC}"
            echo "请手动安装以下依赖:"
            echo "  - build-essential / Development Tools"
            echo "  - clang"
            echo "  - llvm"
            echo "  - libbpf-dev / libbpf-devel"
            echo "  - linux-headers"
            return 1
            ;;
    esac

    echo -e "${GREEN}系统依赖安装完成${NC}"
}

# 安装 Go
install_go() {
    if command -v go &> /dev/null; then
        echo -e "${GREEN}Go 已安装: $(go version)${NC}"
        return 0
    fi

    echo -e "${BLUE}安装 Go...${NC}"

    # 检测最新 Go 版本
    GO_VERSION="1.21.5"
    GO_ARCH=$(uname -m)
    case $GO_ARCH in
        x86_64) GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
    esac

    GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TARBALL}"

    echo "下载 Go $GO_VERSION..."
    wget -q "$GO_URL" -O "/tmp/$GO_TARBALL"

    echo "安装 Go..."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/$GO_TARBALL"

    # 添加到 PATH
    if ! grep -q '/usr/local/go/bin' ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi
    export PATH=$PATH:/usr/local/go/bin

    rm "/tmp/$GO_TARBALL"

    echo -e "${GREEN}Go 安装完成: $(go version)${NC}"
}

# 生成 vmlinux.h
generate_vmlinux_h() {
    echo -e "${BLUE}生成 vmlinux.h...${NC}"

    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        echo -e "${RED}错误: 内核不支持 BTF，无法生成 vmlinux.h${NC}"
        return 1
    fi

    if ! command -v bpftool &> /dev/null; then
        echo -e "${RED}错误: bpftool 未安装${NC}"
        return 1
    fi

    bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
    echo -e "${GREEN}vmlinux.h 生成完成${NC}"
}

# 解析参数
INSTALL_DEPS=false
INSTALL_GO=false
CHECK_BTF=false
CHECK_ONLY=false
GENERATE_VMLINUX=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--deps)
            INSTALL_DEPS=true
            shift
            ;;
        -g|--go)
            INSTALL_GO=true
            shift
            ;;
        -b|--btf)
            CHECK_BTF=true
            GENERATE_VMLINUX=true
            shift
            ;;
        -a|--all)
            INSTALL_DEPS=true
            INSTALL_GO=true
            CHECK_BTF=true
            GENERATE_VMLINUX=true
            shift
            ;;
        -c|--check)
            CHECK_ONLY=true
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
echo -e "${BLUE}  eTracee 开发环境设置${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ "$CHECK_ONLY" = true ]; then
    check_environment
    exit $?
fi

# 默认检查环境
check_environment || true
echo ""

if [ "$INSTALL_DEPS" = true ]; then
    install_deps
    echo ""
fi

if [ "$INSTALL_GO" = true ]; then
    install_go
    echo ""
fi

if [ "$CHECK_BTF" = true ]; then
    check_btf
    echo ""
fi

if [ "$GENERATE_VMLINUX" = true ]; then
    generate_vmlinux_h || true
    echo ""
fi

echo -e "${GREEN}=== 设置完成 ===${NC}"
echo ""
echo "下一步:"
echo "  1. 运行 'make all' 构建项目"
echo "  2. 运行 'sudo ./start.sh' 启动 eTracee"
echo ""
