#!/usr/bin/env bash
# 05overlayfs — CVE-2023-0386 OverlayFS 文件复制上提权（FUSE）
# 依赖: libfuse-dev(libfuse2) + libcap-dev；musl 需静态 libfuse
# 用法: build.sh <outdir> [gnu|musl]
set -euo pipefail
OUT="${1:?usage: build.sh <outdir> [gnu|musl]}"
cd "$(dirname "$0")/CVE-2023-0386"
mkdir -p "$OUT"
make all
cp -f fuse exp gc "$OUT/"
echo "[05overlayfs] -> $OUT/{fuse,exp,gc}"
