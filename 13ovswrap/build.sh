#!/usr/bin/env bash
# 13ovswrap — CVE-2026-64531 OVSwrap（Python + C 双版本）
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")"
mkdir -p "$OUT"

# 拷贝 Python 脚本
cp -f OVSwrap/ovswrap-poc.py "$OUT/"
cp -f CVE-2026-64531-SafeCheck.py "$OUT/"

# 编译 C 版本（静态）
${CC:-gcc} -static -O2 -Wall -Wextra -o "$OUT/ovswrap" ovswrap.c 2>/dev/null || \
  ${CC:-gcc} -O2 -Wall -Wextra -o "$OUT/ovswrap" ovswrap.c

echo "[13ovswrap] -> $OUT/{ovswrap-poc.py,CVE-2026-64531-SafeCheck.py,ovswrap}"