#!/usr/bin/env bash
# 打包 Release 安装包: 生成 key-managerment-<VERSION>.tar.gz 与 latest 副本
set -euo pipefail
VERSION="${1:-v1.0.0}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="$HERE/dist"
PKG="key-managerment-${VERSION}"
mkdir -p "$OUTDIR/$PKG"
cd "$HERE"

cp -f app.py core.py keystore.py requirements.txt install.sh run.sh Dockerfile README.md "$OUTDIR/$PKG/"
cp -rf templates static "$OUTDIR/$PKG/"

cd "$OUTDIR"
tar -czf "${PKG}.tar.gz" "$PKG"
cp -f "${PKG}.tar.gz" "key-managerment-latest.tar.gz"
rm -rf "$PKG"

echo "生成:"
ls -lh "$OUTDIR"/*.tar.gz
