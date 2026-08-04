#!/usr/bin/env bash
# 10fragnesia — CVE-2026-46300 Fragnesia（ESP-in-TCP 页缓存损坏）
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")"
mkdir -p "$OUT"
${CC:-gcc} -static -O2 -o "$OUT/fragnesia" fragnesia.c
echo "[10fragnesia] -> $OUT/fragnesia"
