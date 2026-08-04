#!/usr/bin/env bash
# 07pack2theroot — CVE-2026-41651 PackageKit D-Bus TOCTOU（Python，无需编译）
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")"
mkdir -p "$OUT"
cp -f cve_2026_41651.py "$OUT/"
echo "[07pack2theroot] -> $OUT/cve_2026_41651.py"
