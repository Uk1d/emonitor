#!/bin/bash
# eTracee Python 服务启动脚本

cd "$(dirname "$0")"

# 检查 Python 版本
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "[*] Python 版本: $PYTHON_VERSION"

# 检查依赖
echo "[*] 检查依赖..."
python3 -c "import flask, flask_cors, numpy" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[!] 缺少依赖，正在安装..."
    pip3 install -r requirements.txt
else
    echo "[+] 依赖已就绪"
fi

# 启动服务
echo "[*] 启动 eTracee Python 服务..."
PYTHON_SERVICE_PORT=9900 python3 service.py
