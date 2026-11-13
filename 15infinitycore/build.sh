#!/usr/bin/env bash
# 15infinitycore — InfinityCore core-kernel LPEs
# 用法: build.sh [outdir] [gnu|musl]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$ROOT/bin}"
LIBC="${2:-gnu}"
CC="${CC:-gcc}"
mkdir -p "$OUT"

build() {
  local name="$1" src="$2"
  echo "[15infinitycore] $name"
  "$CC" -O2 -static -pthread -Wall -o "$OUT/$name" "$ROOT/$src"
}

build cve-2026-98260 src/CVE-2026-98260-ubuntu.c
build cve-2026-98256 src/CVE-2026-98256-ubuntu.c
build cve-2026-89754 src/CVE-2026-89754-ubuntu.c
build cve-2026-80775 src/CVE-2026-80775-ubuntu.c
build cve-2026-98385 src/CVE-2026-98385-arch.c

echo "[15infinitycore] -> $OUT (${LIBC})"
