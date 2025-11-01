#!/bin/bash

# eTracee 快速功能测试脚本
# 快速验证核心功能是否正常

echo "=================================="
echo "    eTracee 快速功能测试"
echo "=================================="

# 检查权限
if [[ $EUID -ne 0 ]]; then
    echo "❌ 需要root权限运行"
    echo "请使用: sudo $0"
    exit 1
fi

echo "✅ 权限检查通过"

# 检查可执行文件
if [[ ! -f "./bin/etracee" ]]; then
    echo "❌ 找不到可执行文件 ./bin/etracee"
    echo "请先运行: make"
    exit 1
fi

echo "✅ 可执行文件存在"

# 测试1: 帮助信息
echo
echo "🔍 测试1: 帮助信息"
if ./bin/etracee -h 2>&1 | grep -q "Usage of"; then
    echo "✅ 帮助信息正常"
else
    echo "❌ 帮助信息异常"
fi

# 测试2: 参数解析
echo
echo "🔍 测试2: 命令行参数"
if ./bin/etracee -h 2>&1 | grep -q "uid-min"; then
    echo "✅ UID过滤参数存在"
else
    echo "❌ UID过滤参数缺失"
fi

if ./bin/etracee -h 2>&1 | grep -q "pid-min"; then
    echo "✅ PID过滤参数存在"
else
    echo "❌ PID过滤参数缺失"
fi

if ./bin/etracee -h 2>&1 | grep -q "dashboard"; then
    echo "✅ Dashboard参数存在"
else
    echo "❌ Dashboard参数缺失"
fi

# 测试3: 配置文件
echo
echo "🔍 测试3: 配置文件"
if [[ -f "config/security_rules.yaml" ]]; then
    echo "✅ 安全规则配置文件存在"
    rule_count=$(grep -c "name:" config/security_rules.yaml 2>/dev/null || echo 0)
    echo "📊 发现 $rule_count 条安全规则"
else
    echo "❌ 安全规则配置文件缺失"
fi

# 测试4: 基本启动测试
echo
echo "🔍 测试4: 基本启动测试"
echo "启动eTracee 3秒钟..."

timeout 3s ./bin/etracee > /tmp/etracee_quick_test.log 2>&1 &
etracee_pid=$!

sleep 1
if kill -0 $etracee_pid 2>/dev/null; then
    echo "✅ eTracee启动成功"
    
    # 生成一些测试事件
    ls /tmp > /dev/null
    echo "test" > /tmp/quick_test_file
    rm -f /tmp/quick_test_file
    
    sleep 2
    kill $etracee_pid 2>/dev/null || true
    wait $etracee_pid 2>/dev/null || true
    
    # 检查输出
    if [[ -f /tmp/etracee_quick_test.log ]] && [[ -s /tmp/etracee_quick_test.log ]]; then
        event_count=$(grep -c '"event_type"' /tmp/etracee_quick_test.log 2>/dev/null || echo 0)
        if [[ $event_count -gt 0 ]]; then
            echo "✅ 事件捕获正常 - 捕获到 $event_count 个事件"
        else
            echo "⚠️  未捕获到事件（可能正常，取决于系统活动）"
        fi
    else
        echo "⚠️  无输出日志"
    fi
else
    echo "❌ eTracee启动失败"
fi

# 测试5: Dashboard模式测试
echo
echo "🔍 测试5: Dashboard模式测试"
echo "启动Dashboard模式 3秒钟..."

timeout 3s ./bin/etracee -dashboard > /tmp/dashboard_quick_test.log 2>&1 &
dashboard_pid=$!

sleep 1
if kill -0 $dashboard_pid 2>/dev/null; then
    echo "✅ Dashboard模式启动成功"
    sleep 2
    kill $dashboard_pid 2>/dev/null || true
    wait $dashboard_pid 2>/dev/null || true
else
    echo "❌ Dashboard模式启动失败"
fi

# 测试6: 过滤参数测试
echo
echo "🔍 测试6: 过滤参数测试"
echo "测试UID过滤参数..."

timeout 2s ./bin/etracee -uid-min 1000 -uid-max 2000 > /tmp/filter_test.log 2>&1 &
filter_pid=$!

sleep 1
if kill -0 $filter_pid 2>/dev/null; then
    echo "✅ UID过滤参数工作正常"
    kill $filter_pid 2>/dev/null || true
    wait $filter_pid 2>/dev/null || true
else
    echo "❌ UID过滤参数异常"
fi

# 清理
rm -f /tmp/etracee_quick_test.log /tmp/dashboard_quick_test.log /tmp/filter_test.log

echo
echo "=================================="
echo "         快速测试完成"
echo "=================================="
echo
echo "💡 使用方法示例："
echo "   基本监控:     sudo ./bin/etracee"
echo "   Dashboard:    sudo ./bin/etracee -dashboard"
echo "   UID过滤:      sudo ./bin/etracee -uid-min 1000 -uid-max 2000"
echo "   PID过滤:      sudo ./bin/etracee -pid-min 1000 -pid-max 65535"
echo "   自定义配置:   sudo ./bin/etracee -config config/security_rules.yaml"
echo
echo "📚 完整测试:     sudo ./scripts/test_functionality.sh"