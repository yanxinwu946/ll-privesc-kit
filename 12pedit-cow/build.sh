#!/usr/bin/env bash
# 12pedit-cow — CVE-2026-46331 act_pedit 页缓存损坏（含两个变体）
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")"

# 构建上游完整版本
cd CVE-2026-46331
mkdir -p "$OUT"
make clean >/dev/null 2>&1 || true
make CC="${CC:-gcc}"
cp -f packet_edit_meme "$OUT/"
cd ..

# 编译单文件变体
${CC:-gcc} -static -O2 -Wall -o "$OUT/poc" CVE-2026-46331.c

echo "[12pedit-cow] -> $OUT/{packet_edit_meme,poc}"