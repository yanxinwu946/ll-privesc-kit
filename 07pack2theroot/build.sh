#!/usr/bin/env bash
# 07pack2theroot — CVE-2026-41651 PackageKit D-Bus TOCTOU（Python + C 混合）
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")"
mkdir -p "$OUT"
cp -f cve_2026_41651.py "$OUT/"
make clean >/dev/null 2>&1 || true
make CC="${CC:-gcc}"
chmod +x cve-2026-41651
cp -f cve-2026-41651 "$OUT/" 2>/dev/null || true
echo "[07pack2theroot] -> $OUT/cve_2026_41651.py + C exploit"
