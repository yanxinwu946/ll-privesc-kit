#!/usr/bin/env bash
# 06chwoot — CVE-2025-32463 sudo -R 目录逃逸（脚本驱动，运行时生成并编译 .so）
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")"
mkdir -p "$OUT"
cp -f chwoot.sh "$OUT/"
cp -rf chwoot "$OUT/" 2>/dev/null || true
echo "[06chwoot] -> $OUT/chwoot.sh"
