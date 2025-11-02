# eTracee 测试脚本使用说明

## 测试脚本概览

本项目提供了多个测试脚本，用于不同场景的功能验证：

### 1. comprehensive_test.sh - 完整测试脚本
**用途**: 全面的功能测试和安全验证
**适用场景**: 
- 发布前的完整验证
- 重大代码变更后的测试
- 安全审计和漏洞验证

**主要功能**:
- 环境检查 (OS, 内核, eBPF支持)
- 权限验证 (root权限, capabilities)
- 依赖检查 (Go, make, clang, bpftool)
- 项目结构验证
- 编译测试
- 配置加载测试
- 规则引擎功能测试
- 漏洞修复验证 (数组越界, 空指针)
- 事件捕获测试
- 性能测试
- 内存泄漏检测 (Valgrind)
- HTML报告生成

### 2. quick_validation.sh - 快速验证脚本
**用途**: 开发过程中的快速功能检查
**适用场景**:
- 日常开发中的快速验证
- 代码提交前的基本检查
- 核心功能的快速测试

**主要功能**:
- 快速编译测试
- 配置加载验证
- 数组越界修复验证
- 空指针修复验证
- 基本功能测试

### 3. test_functionality.sh - 原有功能测试脚本
**用途**: 基础功能测试
**适用场景**: 基本功能验证

## 使用方法

### 运行完整测试
```bash
cd eTracee/scripts
chmod +x comprehensive_test.sh
sudo ./comprehensive_test.sh
```

### 运行快速验证
```bash
cd eTracee/scripts
chmod +x quick_validation.sh
sudo ./quick_validation.sh
```

### 查看测试报告
完整测试会生成HTML报告：
```bash
# 报告位置
/tmp/etracee_test_*/test_report.html
```

## 测试要求

### 系统要求
- Linux 操作系统 (内核版本 >= 4.18)
- root 权限或适当的 capabilities
- eBPF 支持

### 依赖工具
- Go (>= 1.18)
- make
- clang
- bpftool
- Valgrind (可选，用于内存检测)

## 测试结果解读

### 退出码
- `0`: 所有测试通过
- `1`: 有测试失败
- `2`: 环境或依赖问题

### 日志级别
- `[INFO]`: 信息性消息
- `[PASS]`: 测试通过
- `[FAIL]`: 测试失败
- `[WARN]`: 警告信息

## 故障排除

### 常见问题

1. **权限不足**
   ```
   解决方案: 使用 sudo 运行测试脚本
   ```

2. **依赖缺失**
   ```
   解决方案: 安装缺失的依赖工具
   Ubuntu/Debian: apt-get install golang-go make clang bpftool
   CentOS/RHEL: yum install golang make clang bpftool
   ```

3. **eBPF 不支持**
   ```
   解决方案: 升级内核版本或启用 eBPF 支持
   ```

4. **编译失败**
   ```
   解决方案: 检查 Go 版本和项目依赖
   ```

### 调试模式
设置环境变量启用详细输出：
```bash
export DEBUG=1
./comprehensive_test.sh
```

## 测试覆盖范围

### 安全测试
- [x] 数组越界漏洞验证
- [x] 空指针解引用验证
- [x] 配置解析安全性
- [x] 输入验证测试

### 功能测试
- [x] 程序编译
- [x] 配置加载
- [x] 规则引擎
- [x] 事件捕获
- [x] 仪表板功能
- [x] 性能测试

### 稳定性测试
- [x] 内存泄漏检测
- [x] 长时间运行测试
- [x] 错误处理测试
- [x] 边界条件测试

## 贡献指南

添加新测试时，请遵循以下规范：

1. **测试函数命名**: `test_<功能名称>`
2. **日志格式**: 使用统一的日志函数
3. **错误处理**: 适当的错误检查和清理
4. **文档更新**: 更新本说明文档

## 联系信息

如有问题或建议，请通过项目 issue 反馈。