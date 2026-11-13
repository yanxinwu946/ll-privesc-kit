#!/usr/bin/env bash
# 在 VPS/本地编译全部条目，并把编译产物回写到各条目的 bin/。
# 用法: ./build/sync-bin.sh [gnu|musl] [outdir]
#
# 只有含 ELF 产物的条目才保留 bin/；纯脚本条目（06chwoot、19lpe-quartet）
# 直接使用各自目录里的脚本，不再复制一份。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIBC="${1:-gnu}"
OUT="${2:-dist/$LIBC}"

"$ROOT/build/build.sh" "$LIBC" "$OUT"

cd "$ROOT"
for d in [0-9][0-9]*; do
  [ -d "$d" ] && rm -rf "$d/bin"
done

for src in "$OUT"/*/; do
  [ -d "$src" ] || continue
  name="$(basename "$src")"
  case "$name" in
    [0-9][0-9]*) ;;
    *) continue ;;
  esac
  [ -d "$name" ] || continue
  if ! find "$src" -type f -exec file {} + | grep 'ELF' >/dev/null; then
    echo "[skip] $name: no ELF output"
    continue
  fi
  mkdir -p "$name/bin"
  cp -a "$src". "$name/bin/"
done

echo "[+] 已回写 $OUT -> <entry>/bin/"
echo "    检查: git status --short"
echo "    提交: git add -A -- */bin && git commit -m 'chore: rebuild binaries'"
