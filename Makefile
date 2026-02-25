# eTracee Makefile
# eBPF-based Linux Host Intrusion Detection System
# https://github.com/etracee

# ==================== 变量定义 ====================
SHELL := /bin/bash

# 项目根目录
PROJECT_ROOT := $(shell pwd)

# 目录定义
BIN_DIR := $(PROJECT_ROOT)/bin
BUILD_DIR := $(PROJECT_ROOT)/build
SRC_DIR := $(PROJECT_ROOT)/src
GO_SRC_DIR := $(SRC_DIR)/go
BPF_SRC_DIR := $(SRC_DIR)/bpf
CONFIG_DIR := $(PROJECT_ROOT)/config
DATA_DIR := $(PROJECT_ROOT)/data
TEST_DATA_DIR := $(PROJECT_ROOT)/test_data
TEST_REPORT_DIR := $(PROJECT_ROOT)/test_reports

# Go 相关
GO := go
GO_VERSION := $(shell go version 2>/dev/null | awk '{print $$3}' | sed 's/go//')
GO_FLAGS := -v
GO_BUILD_FLAGS := -ldflags "-s -w"
GO_MODULE := etracee
GO_MAIN := $(GO_SRC_DIR)/main.go

# eBPF 相关
CLANG := clang
LLVM_STRIP := llvm-strip
BPF_TARGET_ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH)
BPF_INCLUDES := -I$(BPF_SRC_DIR) -I/usr/include -I/usr/include/bpf
BPF_SRC_FILES := $(wildcard $(BPF_SRC_DIR)/*.c)
BPF_OBJ := $(BUILD_DIR)/etracee.bpf.o

# bpftool
BPFTOOL := bpftool
VMLINUX_H := $(BPF_SRC_DIR)/vmlinux.h

# 输出二进制
MAIN_BINARY := $(BIN_DIR)/etracee
TEST_BINARY := $(BIN_DIR)/etracee_test
IMPORTER_BINARY := $(BIN_DIR)/rule_importer

# 配置文件
DEFAULT_CONFIG := $(CONFIG_DIR)/enhanced_security_config.yaml
STORAGE_CONFIG := $(CONFIG_DIR)/storage.yaml

# 颜色输出
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
BLUE := \033[0;34m
NC := \033[0m

# ==================== 默认目标 ====================
.PHONY: all
all: deps check-env bpf build

# ==================== 环境检查 ====================
.PHONY: check-env
check-env:
	@echo "$(BLUE)=== 检查构建环境 ===$(NC)"
	@echo -n "检查 Go... "
	@$(GO) version > /dev/null 2>&1 && echo "$(GREEN)OK$(NC)" || (echo "$(RED)未安装$(NC)"; exit 1)
	@echo -n "检查 Clang... "
	@$(CLANG) --version > /dev/null 2>&1 && echo "$(GREEN)OK$(NC)" || (echo "$(RED)未安装$(NC)"; exit 1)
	@echo -n "检查 bpftool... "
	@$(BPFTOOL) version > /dev/null 2>&1 && echo "$(GREEN)OK$(NC)" || (echo "$(YELLOW)未安装（可选）$(NC)")
	@echo -n "检查 BTF 支持... "
	@test -f /sys/kernel/btf/vmlinux && echo "$(GREEN)OK$(NC)" || echo "$(YELLOW)警告：内核不支持BTF，可能需要手动生成vmlinux.h$(NC)"
	@echo "$(GREEN)环境检查完成$(NC)"

# ==================== 依赖安装 ====================
.PHONY: deps
deps:
	@echo "$(BLUE)=== 安装 Go 依赖 ===$(NC)"
	cd $(GO_SRC_DIR) && $(GO) mod download
	@echo "$(GREEN)Go 依赖安装完成$(NC)"

.PHONY: deps-system
deps-system:
	@echo "$(BLUE)=== 安装系统依赖（需要 root 权限） ===$(NC)"
	@echo "请根据您的发行版运行以下命令："
	@echo ""
	@echo "# Debian/Ubuntu:"
	@echo "sudo apt-get update"
	@echo "sudo apt-get install -y build-essential clang llvm gcc-multilib libbpf-dev linux-headers-$$(uname -r)"
	@echo ""
	@echo "# CentOS/RHEL/openEuler:"
	@echo "sudo yum groupinstall -y 'Development Tools'"
	@echo "sudo yum install -y clang llvm libbpf-devel kernel-devel-$$(uname -r)"
	@echo ""
	@echo "# Fedora:"
	@echo "sudo dnf groupinstall -y 'Development Tools'"
	@echo "sudo dnf install -y clang llvm libbpf-devel kernel-devel-$$(uname -r)"
	@echo ""
	@echo "# Arch Linux:"
	@echo "sudo pacman -S --needed base-devel clang llvm libbpf linux-headers"

# ==================== eBPF 构建 ====================
.PHONY: bpf
bpf: $(BUILD_DIR) $(VMLINUX_H) $(BPF_OBJ)
	@echo "$(GREEN)eBPF 对象构建完成: $(BPF_OBJ)$(NC)"

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(VMLINUX_H):
	@echo "$(BLUE)=== 生成 vmlinux.h ===$(NC)"
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H); \
		echo "$(GREEN)vmlinux.h 生成完成$(NC)"; \
	else \
		echo "$(YELLOW)警告：内核不支持BTF，尝试使用系统头文件$(NC)"; \
		touch $(VMLINUX_H); \
	fi

$(BPF_OBJ): $(BPF_SRC_FILES) $(VMLINUX_H)
	@echo "$(BLUE)=== 编译 eBPF 程序 ===$(NC)"
	@mkdir -p $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) \
		-c $(BPF_SRC_DIR)/etracee_main.c \
		-o $(BPF_OBJ)
	@if command -v $(LLVM_STRIP) > /dev/null 2>&1; then \
		$(LLVM_STRIP) -g $(BPF_OBJ); \
	fi
	@echo "$(GREEN)eBPF 编译完成: $(BPF_OBJ)$(NC)"

# ==================== Go 构建 ====================
.PHONY: build
build: $(BIN_DIR) $(BPF_OBJ)
	@echo "$(BLUE)=== 构建 Go 用户态程序 ===$(NC)"
	cd $(GO_SRC_DIR) && $(GO) build $(GO_BUILD_FLAGS) -o $(MAIN_BINARY) .
	@echo "$(GREEN)主程序构建完成: $(MAIN_BINARY)$(NC)"

.PHONY: build-debug
build-debug: $(BIN_DIR) $(BPF_OBJ)
	@echo "$(BLUE)=== 构建 Go 用户态程序（调试模式） ===$(NC)"
	cd $(GO_SRC_DIR) && $(GO) build $(GO_FLAGS) -o $(MAIN_BINARY) .
	@echo "$(GREEN)调试版主程序构建完成: $(MAIN_BINARY)$(NC)"

.PHONY: build-tools
build-tools: $(BIN_DIR)
	@echo "$(BLUE)=== 构建工具程序 ===$(NC)"
	cd $(GO_SRC_DIR)/tools/rule_importer && $(GO) build $(GO_BUILD_FLAGS) -o $(IMPORTER_BINARY) .
	@echo "$(GREEN)工具程序构建完成$(NC)"

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# ==================== 测试 ====================
.PHONY: test
test: build
	@echo "$(BLUE)=== 运行测试 ===$(NC)"
	cd $(GO_SRC_DIR) && $(GO) test -v ./...

.PHONY: test-rules
test-rules: build
	@echo "$(BLUE)=== 运行规则测试 ===$(NC)"
	@mkdir -p $(TEST_REPORT_DIR)
	$(MAIN_BINARY) test -config $(DEFAULT_CONFIG) -test-data $(TEST_DATA_DIR) -report $(TEST_REPORT_DIR) -verbose

.PHONY: test-integration
test-integration: build
	@echo "$(BLUE)=== 运行集成测试 ===$(NC)"
	$(MAIN_BINARY) integration-test

# ==================== 运行 ====================
.PHONY: run
run: build
	@echo "$(BLUE)=== 启动 eTracee（需要 root 权限） ===$(NC)"
	sudo $(MAIN_BINARY) -config $(DEFAULT_CONFIG)

.PHONY: run-dashboard
run-dashboard: build
	@echo "$(BLUE)=== 启动 eTracee（带 Dashboard，需要 root 权限） ===$(NC)"
	sudo $(MAIN_BINARY) -config $(DEFAULT_CONFIG) -dashboard

.PHONY: run-dev
run-dev: build-debug
	@echo "$(BLUE)=== 启动 eTracee 开发模式（需要 root 权限） ===$(NC)"
	sudo $(MAIN_BINARY) -config $(DEFAULT_CONFIG) -dashboard

# ==================== 清理 ====================
.PHONY: clean
clean:
	@echo "$(YELLOW)=== 清理构建产物 ===$(NC)"
	rm -rf $(BIN_DIR)
	rm -rf $(BUILD_DIR)
	rm -f $(VMLINUX_H)
	@echo "$(GREEN)清理完成$(NC)"

.PHONY: clean-all
clean-all: clean
	@echo "$(YELLOW)=== 清理所有生成文件 ===$(NC)"
	rm -rf $(TEST_REPORT_DIR)
	rm -f $(PROJECT_ROOT)/*.log
	rm -f $(DATA_DIR)/*.db
	@echo "$(GREEN)全部清理完成$(NC)"

# ==================== 安装 ====================
.PHONY: install
install: build
	@echo "$(BLUE)=== 安装 eTracee ===$(NC)"
	sudo install -m 755 $(MAIN_BINARY) /usr/local/bin/etracee
	sudo mkdir -p /etc/etracee
	sudo install -m 644 $(DEFAULT_CONFIG) /etc/etracee/config.yaml
	sudo install -m 644 $(STORAGE_CONFIG) /etc/etracee/storage.yaml
	sudo mkdir -p /var/lib/etracee
	sudo install -m 644 $(BPF_OBJ) /var/lib/etracee/etracee.bpf.o
	@echo "$(GREEN)安装完成$(NC)"
	@echo "配置文件位置: /etc/etracee/"
	@echo "数据目录: /var/lib/etracee/"

.PHONY: uninstall
uninstall:
	@echo "$(YELLOW)=== 卸载 eTracee ===$(NC)"
	sudo rm -f /usr/local/bin/etracee
	sudo rm -rf /etc/etracee
	sudo rm -rf /var/lib/etracee
	@echo "$(GREEN)卸载完成$(NC)"

# ==================== 开发辅助 ====================
.PHONY: lint
lint:
	@echo "$(BLUE)=== 运行代码检查 ===$(NC)"
	cd $(GO_SRC_DIR) && $(GO) fmt ./...
	@command -v golint > /dev/null 2>&1 && cd $(GO_SRC_DIR) && golint ./... || echo "$(YELLOW)golint 未安装，跳过$(NC)"
	@command -v staticcheck > /dev/null 2>&1 && cd $(GO_SRC_DIR) && staticcheck ./... || echo "$(YELLOW)staticcheck 未安装，跳过$(NC)"

.PHONY: fmt
fmt:
	@echo "$(BLUE)=== 格式化代码 ===$(NC)"
	cd $(GO_SRC_DIR) && $(GO) fmt ./...
	@command -v clang-format > /dev/null 2>&1 && clang-format -i $(BPF_SRC_DIR)/*.c $(BPF_SRC_DIR)/*.h || true
	@echo "$(GREEN)代码格式化完成$(NC)"

.PHONY: check
check: lint test
	@echo "$(GREEN)检查完成$(NC)"

# ==================== Docker 支持 ====================
.PHONY: docker-build
docker-build:
	@echo "$(BLUE)=== 构建 Docker 镜像 ===$(NC)"
	docker build -t etracee:latest .
	@echo "$(GREEN)Docker 镜像构建完成$(NC)"

.PHONY: docker-run
docker-run:
	@echo "$(BLUE)=== 运行 Docker 容器 ===$(NC)"
	docker run --rm -it --privileged \
		-v /sys/kernel/debug:/sys/kernel/debug:ro \
		-v /sys/kernel/btf:/sys/kernel/btf:ro \
		etracee:latest

# ==================== 帮助 ====================
.PHONY: help
help:
	@echo ""
	@echo "$(BLUE)eTracee - 基于 eBPF 的 Linux 主机入侵检测系统$(NC)"
	@echo ""
	@echo "$(GREEN)主要构建命令:$(NC)"
	@echo "  make all           - 完整构建（检查环境 + 构建 eBPF + 构建 Go）"
	@echo "  make build         - 仅构建 Go 用户态程序（需要先构建 eBPF）"
	@echo "  make bpf           - 仅构建 eBPF 程序"
	@echo "  make clean         - 清理构建产物"
	@echo ""
	@echo "$(GREEN)运行命令:$(NC)"
	@echo "  make run           - 启动 eTracee（需要 root 权限）"
	@echo "  make run-dashboard - 启动 eTracee 并显示 Dashboard"
	@echo "  make run-dev       - 启动开发调试模式"
	@echo ""
	@echo "$(GREEN)测试命令:$(NC)"
	@echo "  make test          - 运行单元测试"
	@echo "  make test-rules    - 运行规则测试"
	@echo "  make test-integration - 运行集成测试"
	@echo ""
	@echo "$(GREEN)开发命令:$(NC)"
	@echo "  make deps          - 安装 Go 依赖"
	@echo "  make deps-system   - 显示系统依赖安装命令"
	@echo "  make lint          - 运行代码检查"
	@echo "  make fmt           - 格式化代码"
	@echo "  make check-env     - 检查构建环境"
	@echo ""
	@echo "$(GREEN)安装命令:$(NC)"
	@echo "  make install       - 安装到系统"
	@echo "  make uninstall     - 从系统卸载"
	@echo ""
	@echo "$(GREEN)Docker 命令:$(NC)"
	@echo "  make docker-build  - 构建 Docker 镜像"
	@echo "  make docker-run    - 运行 Docker 容器"
	@echo ""

# ==================== 快速开发命令 ====================
.PHONY: dev
dev: clean all
	@echo "$(GREEN)开发构建完成$(NC)"

.PHONY: quick
quick: build
	@echo "$(GREEN)快速构建完成（跳过 eBPF 构建）$(NC)"

# ==================== 配置文件生成 ====================
.PHONY: config-example
config-example:
	@echo "$(BLUE)=== 生成示例配置文件 ===$(NC)"
	@cp $(DEFAULT_CONFIG) $(CONFIG_DIR)/config.example.yaml
	@echo "$(GREEN)示例配置文件已生成: $(CONFIG_DIR)/config.example.yaml$(NC)"

# ==================== 版本信息 ====================
.PHONY: version
version:
	@echo "eTracee Version: $(shell git describe --tags --always --dirty 2>/dev/null || echo 'dev')"
	@echo "Go Version: $(GO_VERSION)"
	@echo "Target Arch: $(BPF_TARGET_ARCH)"
	@echo "Build Time: $(shell date -u '+%Y-%m-%d %H:%M:%S UTC')"
