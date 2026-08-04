#!/usr/bin/env bash
# 09dirtyfrag — CVE-2026-43284 / CVE-2026-43500 Dirty Frag
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
LIBC="${2:-gnu}"
cd "$(dirname "$0")/dirtyfrag"
mkdir -p "$OUT"
LIBS="-lutil"
[ "$LIBC" = "musl" ] && LIBS=""   # musl 将 libutil 并入 libc
${CC:-gcc} -O0 -Wall -static -o "$OUT/dirtyfrag" exp.c $LIBS
echo "[09dirtyfrag] -> $OUT/dirtyfrag (${LIBC})"
