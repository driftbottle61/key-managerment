#!/usr/bin/env bash
# =============================================================================
#  Key Managerment — 一键安装脚本
#  网页版 SSH 私钥生成与公钥部署工具
#
#  用法:
#    bash install.sh                  # 安装(默认端口 8080, 用户 admin)
#    SSHWEB_PORT=8800 bash install.sh # 自定义端口
#    bash install.sh v1.0.0           # 指定从 GitHub Release 下载的版本
#
#  来源自动选择:
#    - 若脚本旁边存在 app.py(即从源码包/仓库运行) -> 使用本地源码
#    - 否则从 GitHub Release 下载指定版本(或最新)的 tarball
# =============================================================================
set -euo pipefail

APP_NAME="key-managerment"
INSTALL_DIR="/opt/${APP_NAME}"
SERVICE_NAME="${APP_NAME}"
GITHUB_REPO="driftbottle61/key-managerment"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${1:-latest}"

# ---------------- 颜色 ----------------
c_ok=$'\e[32m'; c_warn=$'\e[33m'; c_err=$'\e[31m'; c_end=$'\e[0m'
info(){ echo "${c_ok}[*]${c_end} $*"; }
warn(){ echo "${c_warn}[!]${c_end} $*"; }
err(){  echo "${c_err}[x]${c_end} $*" >&2; }

# ---------------- 权限/系统检测 ----------------
if [ "$(id -u)" -ne 0 ]; then
  err "请以 root 运行: sudo bash install.sh"; exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  err "未检测到 systemd, 本脚本仅支持 systemd 的 Linux 发行版"; exit 1
fi

# ---------------- 准备源码目录 ----------------
if [ -f "$HERE/app.py" ]; then
  SRC_DIR="$HERE"
  info "使用本地源码目录: $SRC_DIR"
else
  SRC_DIR="$(mktemp -d)"
  if [ "$VERSION" = "latest" ]; then
    URL="https://github.com/${GITHUB_REPO}/releases/latest/download/${APP_NAME}-latest.tar.gz"
  else
    URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${APP_NAME}-${VERSION}.tar.gz"
  fi
  info "从 GitHub Release 下载: $URL"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 -o "$SRC_DIR/pkg.tar.gz" "$URL" || { err "下载失败: $URL"; exit 1; }
  else
    wget -q -O "$SRC_DIR/pkg.tar.gz" "$URL" || { err "下载失败(请先安装 curl 或 wget): $URL"; exit 1; }
  fi
  tar -xzf "$SRC_DIR/pkg.tar.gz" -C "$SRC_DIR"
  SRC_DIR="$(find "$SRC_DIR" -maxdepth 2 -name app.py -printf '%h\n' | head -n1)"
  [ -n "$SRC_DIR" ] || { err "下载的包中未找到 app.py"; exit 1; }
fi

# ---------------- 安装系统依赖 ----------------
need(){ command -v "$1" >/dev/null 2>&1 || { info "安装 $1 ..."; "$PKGM" "$@"; }; }
if command -v apt-get >/dev/null 2>&1; then
  PKGM="apt-get install -y"
  export DEBIAN_FRONTEND=noninteractive
  info "检测到 Debian/Ubuntu, 更新软件源..."
  apt-get update -y >/dev/null 2>&1 || true
  need python3; need python3-venv; need python3-pip; need curl; need openssl
elif command -v dnf >/dev/null 2>&1; then
  PKGM="dnf install -y"
  need python3; need python3-pip; need python3-virtualenv; need curl; need openssl
elif command -v yum >/dev/null 2>&1; then
  PKGM="yum install -y"
  need python3; need python3-pip; need python3-virtualenv; need curl; need openssl
else
  err "不支持的包管理器, 请手动安装 python3/pip/venv"; exit 1
fi

# ---------------- 部署到目标目录 ----------------
info "安装应用到 $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp -f "$SRC_DIR"/app.py "$SRC_DIR"/core.py "$SRC_DIR"/keystore.py "$SRC_DIR"/requirements.txt "$INSTALL_DIR/" 2>/dev/null || true
cp -rf "$SRC_DIR/templates" "$SRC_DIR/static" "$INSTALL_DIR/" 2>/dev/null || true
cp -f "$SRC_DIR/run.sh" "$INSTALL_DIR/" 2>/dev/null || true

# ---------------- Python 虚拟环境 ----------------
PYBIN="$(command -v python3)"
if [ ! -x "$INSTALL_DIR/.venv/bin/python" ]; then
  info "创建 Python 虚拟环境..."
  "$PYBIN" -m venv "$INSTALL_DIR/.venv"
fi
info "安装 Python 依赖..."
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# ---------------- 配置(端口/用户) ----------------
PORT="${SSHWEB_PORT:-8080}"
ADMIN_USER="${SSHWEB_ADMIN_USER:-admin}"

# ---------------- systemd 服务 ----------------
info "创建 systemd 服务 $SERVICE_NAME (开机自启)..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SVC
[Unit]
Description=Key Managerment - web SSH key generate & deploy
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
Environment=SSHWEB_PORT=${PORT}
Environment=SSHWEB_ADMIN_USER=${ADMIN_USER}
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
systemctl restart "${SERVICE_NAME}"

# 等待首次启动生成初始密码
sleep 2
PWFILE="$INSTALL_DIR/INITIAL_PASSWORD.txt"
if [ -f "$PWFILE" ]; then
  INIT_PW="$(grep -oE '[A-Za-z0-9_-]{8,}' "$PWFILE" | tail -n1 || true)"
fi

# ---------------- 完成 ----------------
status="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo inactive)"
echo
echo "================================================================"
echo "  安装完成"
echo "================================================================"
echo "  服务状态   : $status"
echo "  访问地址   : http://<本机IP>:${PORT}"
echo "  管理员账号 : ${ADMIN_USER}"
if [ -n "${INIT_PW:-}" ]; then
  echo "  初始密码   : ${INIT_PW}  (文件: ${PWFILE}, 首次登录后请修改并删除)"
else
  echo "  初始密码   : 见 ${PWFILE}"
fi
echo "  配置文件   : ${INSTALL_DIR}/config.json"
echo "  密钥库文件 : ${INSTALL_DIR}/keystore.json"
echo "  服务管理   : systemctl status ${SERVICE_NAME} | restart | stop"
echo "  日志       : journalctl -u ${SERVICE_NAME} -f"
echo "================================================================"
if [ "$status" != "active" ]; then
  warn "服务未正常运行, 请查看: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
  exit 1
fi
