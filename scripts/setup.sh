#!/bin/bash

# eTracee 项目环境搭建脚本
# 适用于 openEuler 25.09 系统

set -e

echo "=== eTracee 环境搭建开始 ==="

# 检查是否为 root 用户
if [ "$EUID" -ne 0 ]; then
    echo "请使用 root 权限运行此脚本"
    exit 1
fi

# 更新系统包
echo "更新系统包..."
dnf update -y

# 安装基础开发工具
echo "安装基础开发工具..."
dnf groupinstall -y "Development Tools"
dnf install -y git wget curl vim htop tree

# 安装 eBPF 相关依赖
echo "安装 eBPF 开发环境..."
dnf install -y \
    kernel-devel \
    kernel-headers \
    clang \
    llvm \
    libbpf-devel \
    bpftool \
    bpftrace \
    elfutils-libelf-devel \
    zlib-devel \
    make \
    cmake

# 安装 Go 语言环境
echo "安装 Go 语言环境..."
GO_VERSION="1.21.5"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"

if [ ! -d "/usr/local/go" ]; then
    cd /tmp
    wget "https://golang.org/dl/${GO_TARBALL}"
    tar -C /usr/local -xzf "${GO_TARBALL}"
    rm -f "${GO_TARBALL}"
    
    # 配置 Go 环境变量
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo 'export GOPATH=/root/go' >> /etc/profile
    echo 'export GOPROXY=https://goproxy.cn,direct' >> /etc/profile
fi

# 安装 Python 3 和相关依赖
echo "安装 Python 3 环境..."
dnf install -y python3 python3-pip python3-devel

# 安装 Python 包
pip3 install --upgrade pip
pip3 install numpy pandas scikit-learn flask redis pyyaml requests

# 验证内核 BTF 支持
echo "验证内核 BTF 支持..."
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "✓ 内核 BTF 支持已启用"
else
    echo "⚠ 警告: 内核 BTF 支持未启用，可能影响 CO-RE 功能"
fi

# 验证 eBPF 功能
echo "验证 eBPF 功能..."
if bpftool prog list > /dev/null 2>&1; then
    echo "✓ eBPF 功能正常"
else
    echo "⚠ 警告: eBPF 功能可能存在问题"
fi

# 创建项目目录结构
echo "创建项目目录结构..."
PROJECT_DIR="/opt/etracee"
mkdir -p ${PROJECT_DIR}/{src/{bpf,go,python},build,bin,config,logs,test,docs}

echo "=== 环境搭建完成 ==="
echo "请运行 'source /etc/profile' 来加载环境变量"
echo "项目目录: ${PROJECT_DIR}"