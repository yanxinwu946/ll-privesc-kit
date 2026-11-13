#!/usr/bin/env bash
# 16vghost — CVE-2026-74580 vhost stale IOTLB cache LPE
# 用法: build.sh [outdir] [gnu|musl]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$ROOT/bin}"
LIBC="${2:-gnu}"
CC="${CC:-gcc}"
mkdir -p "$OUT"
"$CC" -O2 -static -Wall -Wextra -o "$OUT/vghost" "$ROOT/src/poc.c"
echo "[16vghost] -> $OUT/vghost (${LIBC})"
