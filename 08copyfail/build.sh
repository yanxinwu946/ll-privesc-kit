#!/usr/bin/env bash
# 08copyfail — CVE-2026-31431 Copy Fail（AF_ALG 页缓存写入）
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
LIBC="${2:-gnu}"
cd "$(dirname "$0")/copy-fail-c"
mkdir -p "$OUT"
make clean >/dev/null 2>&1 || true
if [ "$LIBC" = "musl" ]; then
  make musl-static CC="${CC:-gcc}"
else
  make CC="${CC:-gcc}"
fi
cp -f exploit exploit-passwd vulnerable "$OUT/"
echo "[08copyfail] -> $OUT/{exploit,exploit-passwd,vulnerable} (${LIBC})"
