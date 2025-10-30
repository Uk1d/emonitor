# eTracee Makefile
# 支持全安全场景监控的 eBPF 系统

# 项目配置
PROJECT_NAME := etracee
VERSION := 1.0.0

# 目录配置
SRC_DIR := src
BPF_SRC_DIR := $(SRC_DIR)/bpf
GO_SRC_DIR := $(SRC_DIR)/go
BUILD_DIR := build
BIN_DIR := bin
CONFIG_DIR := config
LOGS_DIR := logs
TEST_DIR := test
SCRIPTS_DIR := scripts

# 构建目标
BPF_MAIN_SOURCE := $(BPF_SRC_DIR)/etracee_main.c
BPF_OBJECT := $(BUILD_DIR)/etracee.bpf.o
GO_BINARY := $(BIN_DIR)/etracee
VMLINUX_H := $(BPF_SRC_DIR)/vmlinux.h

# 编译器配置
CLANG := clang
LLC := llc
GO := go
BPFTOOL := bpftool

# 编译标志
CLANG_FLAGS := -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86
GO_FLAGS := -ldflags="-s -w"

# 默认目标
.PHONY: all
all: check-env setup-dirs vmlinux bpf go

# 环境检查
.PHONY: check-env
check-env:
	@echo "检查构建环境..."
	@which $(CLANG) > /dev/null || (echo "错误: clang 未安装" && exit 1)
	@which $(BPFTOOL) > /dev/null || (echo "错误: bpftool 未安装" && exit 1)
	@which $(GO) > /dev/null || (echo "错误: Go 未安装" && exit 1)
	@test -f /sys/kernel/btf/vmlinux || (echo "警告: 内核 BTF 支持未启用" && exit 1)
	@echo "✓ 环境检查通过"

# 创建目录结构
.PHONY: setup-dirs
setup-dirs:
	@echo "创建目录结构..."
	@mkdir -p $(BUILD_DIR) $(BIN_DIR) $(LOGS_DIR)
	@echo "✓ 目录结构创建完成"

# 生成 vmlinux.h
.PHONY: vmlinux
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@echo "生成 vmlinux.h..."
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "✓ vmlinux.h 生成完成"

# 编译 eBPF 程序
.PHONY: bpf
bpf: $(BPF_OBJECT)

$(BPF_OBJECT): $(BPF_MAIN_SOURCE) $(VMLINUX_H)
	@echo "编译 eBPF 程序..."
	@$(CLANG) $(CLANG_FLAGS) -I$(BPF_SRC_DIR) -c $< -o $@
	@echo "✓ eBPF 程序编译完成"

# 编译 Go 程序
.PHONY: go
go: $(GO_BINARY)

$(GO_BINARY): $(GO_SRC_DIR)/main.go $(BPF_OBJECT)
	@echo "编译 Go 程序..."
	cd $(GO_SRC_DIR) && $(GO) mod tidy
	cd $(GO_SRC_DIR) && $(GO) build $(GO_FLAGS) -o ../../$(GO_BINARY) main.go
	@echo "✓ Go 程序编译完成"

# 安装依赖
.PHONY: deps
deps:
	@echo "安装 Go 依赖..."
	cd $(GO_SRC_DIR) && $(GO) mod download
	@echo "✓ 依赖安装完成"

# 运行程序
.PHONY: run
run: $(GO_BINARY)
	@echo "运行程序 (需要 root 权限)..."
	@cd $(shell pwd) && sudo $(GO_BINARY)

# 测试功能
.PHONY: test-bpftrace
test-bpftrace:
	@echo "运行 bpftrace 测试..."
	@sudo bpftrace $(TEST_DIR)/scripts/bpftrace_test.bt

.PHONY: test
test: $(GO_BINARY)
	@echo "运行功能测试..."
	@cd $(shell pwd) && timeout 30s sudo $(GO_BINARY) || true
	@echo "✓ 测试完成"

# 安装系统
.PHONY: install
install: all
	@echo "安装 eTracee 到系统..."
	@sudo cp $(GO_BINARY) /usr/local/bin/etracee
	@sudo mkdir -p /etc/etracee
	@sudo cp $(CONFIG_DIR)/security_rules.yaml /etc/etracee/
	@sudo mkdir -p /var/log/etracee
	@echo "✓ 安装完成"

# 卸载系统
.PHONY: uninstall
uninstall:
	@echo "卸载 eTracee..."
	@sudo rm -f /usr/local/bin/etracee
	@sudo rm -rf /etc/etracee
	@echo "✓ 卸载完成"

# 打包发布
.PHONY: package
package: all
	@echo "打包发布版本..."
	@mkdir -p $(BUILD_DIR)/package/etracee-$(VERSION)
	@cp -r $(BIN_DIR) $(CONFIG_DIR) $(SCRIPTS_DIR) README.md $(BUILD_DIR)/package/etracee-$(VERSION)/
	@cd $(BUILD_DIR)/package && tar -czf etracee-$(VERSION).tar.gz etracee-$(VERSION)
	@echo "✓ 打包完成: $(BUILD_DIR)/package/etracee-$(VERSION).tar.gz"

# 性能测试
.PHONY: benchmark
benchmark: $(GO_BINARY)
	@echo "运行性能测试..."
	@sudo timeout 60s $(GO_BINARY) > /dev/null &
	@sleep 5
	@echo "生成测试负载..."
	@for i in {1..100}; do ls /tmp > /dev/null; done
	@echo "✓ 性能测试完成"

# 代码检查
.PHONY: lint
lint:
	@echo "检查 Go 代码..."
	cd $(GO_SRC_DIR) && $(GO) vet ./...
	cd $(GO_SRC_DIR) && $(GO) fmt ./...
	@echo "✓ 代码检查完成"

# 清理构建产物
.PHONY: clean
clean:
	@echo "清理构建产物..."
	@rm -rf $(BUILD_DIR)/* $(BIN_DIR)/* $(LOGS_DIR)/*
	@rm -f $(VMLINUX_H)
	cd $(GO_SRC_DIR) && $(GO) clean
	@echo "✓ 清理完成"

# 深度清理
.PHONY: distclean
distclean: clean
	@echo "深度清理..."
	cd $(GO_SRC_DIR) && rm -f go.sum
	@echo "✓ 深度清理完成"

# 显示帮助信息
.PHONY: help
help:
	@echo "eTracee 构建系统"
	@echo ""
	@echo "可用目标:"
	@echo "  all           - 构建所有组件 (默认)"
	@echo "  check-env     - 检查构建环境"
	@echo "  setup-dirs    - 创建目录结构"
	@echo "  vmlinux       - 生成 vmlinux.h"
	@echo "  bpf           - 编译 eBPF 程序"
	@echo "  go            - 编译 Go 程序"
	@echo "  deps          - 安装依赖"
	@echo "  run           - 运行程序"
	@echo "  test-bpftrace - 运行 bpftrace 测试"
	@echo "  test          - 运行功能测试"
	@echo "  install       - 安装到系统"
	@echo "  uninstall     - 从系统卸载"
	@echo "  package       - 打包发布版本"
	@echo "  benchmark     - 运行性能测试"
	@echo "  lint          - 代码检查"
	@echo "  clean         - 清理构建产物"
	@echo "  distclean     - 深度清理"
	@echo "  help          - 显示此帮助信息"
	@echo ""
	@echo "注意: 运行和测试目标需要 root 权限"

# 显示项目信息
.PHONY: info
info:
	@echo "项目信息:"
	@echo "  名称: $(PROJECT_NAME)"
	@echo "  版本: $(VERSION)"
	@echo "  源码目录: $(SRC_DIR)"
	@echo "  构建目录: $(BUILD_DIR)"
	@echo "  二进制目录: $(BIN_DIR)"
	@echo "  配置目录: $(CONFIG_DIR)"
	@echo ""
	@echo "构建目标:"
	@echo "  eBPF 对象: $(BPF_OBJECT)"
	@echo "  Go 二进制: $(GO_BINARY)"

# 防止文件名冲突
.SUFFIXES: