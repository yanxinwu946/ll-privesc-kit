#!/usr/bin/env bash
# ll-privesc-kit 统一构建编排器
#
# 用法:
#   ./build/build.sh [gnu|musl] [输出目录]
#     第一个参数: libc 变体 (默认 gnu)
#     第二个参数: 输出目录 (默认 dist/<libc>)
#   环境变量 CC 可覆盖编译器 (如 musl 时 CC=musl-gcc, alpine 内 gcc 即 musl)
#
# 每个漏洞目录 (NNname/) 提供统一契约的 build.sh:
#   build.sh <outdir> [gnu|musl]
# 产物统一落入 <outdir>，供后续 zip 打包分发。
set -euo pipefail

LIBC="${1:-gnu}"
OUT="${2:-dist/$LIBC}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

case "$LIBC" in
  gnu|musl) ;;
  *) echo "用法: $0 [gnu|musl] [outdir]" >&2; exit 2 ;;
esac

echo "==> libc=$LIBC outdir=$OUT"
rm -rf "$OUT"
mkdir -p "$OUT"

FAIL=0
for d in "$ROOT"/[0-9][0-9]*; do
  [ -d "$d" ] || continue
  name="$(basename "$d")"
  if [ -x "$d/build.sh" ]; then
    echo
    echo "===== [$name] ====="
    if ( cd "$d" && ./build.sh "$ROOT/$OUT/$name" "$LIBC" ); then
      echo "===== [$name] OK ====="
    else
      echo "===== [$name] FAILED =====" >&2
      FAIL=1
    fi
  else
    echo "跳过 $name (无 build.sh)"
  fi
done

# 拷贝 tools/ 内置工具到输出根目录
if [ -d "$ROOT/tools" ]; then
  echo
  echo "===== [tools] ====="
  cp -r "$ROOT/tools"/* "$OUT/" 2>/dev/null || true
  echo "===== [tools] OK ====="
fi

echo
if [ "$FAIL" -ne 0 ]; then
  echo "[-] 存在构建失败的目录" >&2
  exit 1
fi
echo "[+] 全部构建完成 -> $OUT"
echo "    产物: $(find "$OUT" -maxdepth 1 -type f | wc -l) 个文件 + tools/ 目录"
