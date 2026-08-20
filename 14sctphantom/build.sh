#!/usr/bin/env bash
# 14sctphantom — CVE-2026-64564 SCTPhantom SCTP ASCONF DEL-IP UAF
# Usage: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
LIBC="${2:-gnu}"
cd "$(dirname "$0")/src"
mkdir -p "$OUT"
${CC:-gcc} -O2 -Wall -static -o "$OUT/sctphantom" CVE-2026-64564.c
echo "[14sctphantom] -> $OUT/sctphantom (${LIBC})"
