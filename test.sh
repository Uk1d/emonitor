#!/bin/bash

# eTracee 主测试脚本
# 提供多种测试选项

echo "=================================="
echo "       eTracee 测试工具"
echo "=================================="
echo

# 检查权限
if [[ $EUID -ne 0 ]]; then
echo "[-] 需要root权限运行测试"
    echo "请使用: sudo $0"
    exit 1
fi

# 检查可执行文件
if [[ ! -f "./bin/etracee" ]]; then
echo "[-] 找不到可执行文件 ./bin/etracee"
    echo "请先运行: make"
    exit 1
fi

echo "请选择测试类型："
echo
echo "1) 快速测试 (quick_test.sh)"
echo "   - 基本功能验证"
echo "   - 参数检查"
echo "   - 快速启动测试"
echo
echo "2) 修复验证 (verify_fixes.sh)"
echo "   - 验证PID/UID过滤功能"
echo "   - 验证新增命令行参数"
echo "   - 验证过滤逻辑"
echo
echo "3) 完整功能测试 (test_functionality.sh)"
echo "   - 全面的功能测试"
echo "   - 性能测试"
echo "   - 安全规则测试"
echo "   - Dashboard测试"
echo
echo "4) 显示使用示例"
echo
echo "5) 退出"
echo

read -p "请输入选择 (1-5): " choice

case $choice in
    1)
        echo
        echo "[*] 运行快速测试..."
        echo "=================================="
        if [[ -f "./scripts/quick_test.sh" ]]; then
            chmod +x ./scripts/quick_test.sh
            ./scripts/quick_test.sh
        else
echo "[-] 找不到 quick_test.sh"
        fi
        ;;
    2)
        echo
echo "[*] 运行修复验证..."
        echo "=================================="
        if [[ -f "./scripts/verify_fixes.sh" ]]; then
            chmod +x ./scripts/verify_fixes.sh
            ./scripts/verify_fixes.sh
        else
echo "[-] 找不到 verify_fixes.sh"
        fi
        ;;
    3)
        echo
        echo "[*] 运行完整功能测试..."
        echo "=================================="
        if [[ -f "./scripts/test_functionality.sh" ]]; then
            chmod +x ./scripts/test_functionality.sh
            ./scripts/test_functionality.sh
        else
echo "[-] 找不到 test_functionality.sh"
        fi
        ;;
    4)
        echo
        echo "eTracee 使用示例："
        echo "=================================="
        echo
        echo "基本监控："
        echo "  sudo ./bin/etracee"
        echo
        echo "启用Dashboard："
        echo "  sudo ./bin/etracee -dashboard"
        echo
        echo "UID过滤（监控指定用户范围）："
        echo "  sudo ./bin/etracee -uid-min 1000 -uid-max 2000"
        echo
        echo "PID过滤（监控指定进程范围）："
        echo "  sudo ./bin/etracee -pid-min 1000 -pid-max 65535"
        echo
        echo "组合使用："
        echo "  sudo ./bin/etracee -dashboard -uid-min 1000 -uid-max 2000"
        echo
        echo "自定义配置："
        echo "  sudo ./bin/etracee -config config/security_rules.yaml"
        echo
        echo "输出到文件："
        echo "  sudo ./bin/etracee > events.json"
        echo
        echo "后台运行："
        echo "  sudo nohup ./bin/etracee > events.log 2>&1 &"
        echo
        echo "停止后台进程："
        echo "  sudo pkill etracee"
        echo
        ;;
    5)
        echo "退出测试工具"
        exit 0
        ;;
    *)
echo "[-] 无效选择，请输入 1-5"
        exit 1
        ;;
esac

echo
echo "=================================="
echo "测试完成！"
echo
echo "[*] 提示："
echo "- 如需重新测试，请再次运行: sudo ./test.sh"
echo "- 查看详细日志，请检查 /tmp/ 目录下的测试日志文件"
echo "- 如有问题，请检查 README.md 中的故障排除部分"
echo "=================================="