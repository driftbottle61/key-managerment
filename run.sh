#!/usr/bin/env bash
# ssh-web 启动脚本(本地/群晖 Python 运行)
set -e
cd "$(dirname "$0")"
# 依赖缺失时自动安装
if ! python3 -c "import flask, paramiko" >/dev/null 2>&1; then
  echo "[*] 安装依赖..."
  python3 -m pip install -r requirements.txt
fi
export SSHWEB_HOST="${SSHWEB_HOST:-0.0.0.0}"
export SSHWEB_PORT="${SSHWEB_PORT:-8080}"
exec python3 app.py
