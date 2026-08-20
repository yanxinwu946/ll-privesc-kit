#!/usr/bin/env bash
# 11dirty-clone — CVE-2026-43503 Dirty Clone（Python + C 混合）
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")"
mkdir -p "$OUT"
cp -f dirtyclone.py "$OUT/"
${CC:-gcc} -static -O2 -o "$OUT/dirtyclone" CVE-2026-43503.c || true
echo "[11dirty-clone] -> $OUT/dirtyclone.py + C exploit"
