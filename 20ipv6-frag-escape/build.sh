#!/usr/bin/env bash
# 20ipv6-frag-escape — CVE-2026-53362 IPv6 fraggap container escape
# 用法: build.sh [outdir] [gnu|musl]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$ROOT/bin}"
LIBC="${2:-gnu}"
CXX="${CXX:-g++}"
mkdir -p "$OUT"

have_keyutils=0
if [ -f /usr/include/keyutils.h ]; then
  have_keyutils=1
elif echo '#include <keyutils.h>' | "$CXX" -E -x c++ - >/dev/null 2>&1; then
  have_keyutils=1
fi

if [ "$have_keyutils" -eq 1 ]; then
  ( cd "$ROOT/src" && "$CXX" -O2 -Wall -static -I libxdk-v0.1 -x c++ exploit.c \
      -o "$OUT/cve-2026-53362" -L libxdk-v0.1 -lkernelXDK -pthread )
  echo "[20ipv6-frag-escape] -> $OUT/cve-2026-53362 (${LIBC})"
else
  if [ ! -f "$ROOT/bin/cve-2026-53362" ]; then
    echo "[20ipv6-frag-escape] 需要 libkeyutils-dev 才能重新编译" >&2
    exit 1
  fi
  if [ "$(readlink -f "$ROOT/bin")" = "$(readlink -f "$OUT")" ]; then
    echo "[20ipv6-frag-escape] libkeyutils-dev 缺失，使用已提交的预编译二进制" >&2
  else
    cp -f "$ROOT/bin/cve-2026-53362" "$OUT/cve-2026-53362"
    echo "[20ipv6-frag-escape] libkeyutils-dev 缺失，复制预编译二进制 -> $OUT/cve-2026-53362" >&2
  fi
fi
