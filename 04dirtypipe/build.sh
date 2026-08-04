#!/usr/bin/env bash
# 04dirtypipe — CVE-2022-0847 Dirty Pipe 任意文件写
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")/dirtypipe"
mkdir -p "$OUT"
${CC:-gcc} -static -O2 -o "$OUT/exploit" exploit.c
echo "[04dirtypipe] -> $OUT/exploit"
