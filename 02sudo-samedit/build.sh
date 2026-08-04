#!/usr/bin/env bash
# 02sudo3165 — CVE-2021-3156 sudo Baron Samedit（Python 利用集，无需编译）
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")/CVE-2021-3156"
mkdir -p "$OUT"
cp -f *.py "$OUT/"
cp -f exploit_timestamp_race.c "$OUT/" 2>/dev/null || true
echo "[02sudo3165] -> $OUT/*.py"
