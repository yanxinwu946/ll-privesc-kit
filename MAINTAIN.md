# ll-privesc-kit 维护指南

## 编译规则

### 静态链接（必须）

所有 C 编译产物必须使用 `-static` 静态链接，确保在任意目标机器上无需依赖即可运行。

**规则：**
- Makefile 中必须包含 `-static` 标志
- build.sh 中直接调用 gcc 时必须包含 `-static`
- `.so` 共享库（如 pwnkit.so）例外，它们必须是动态链接的

**示例：**

Makefile:
```makefile
CC ?= gcc
CFLAGS = -Wall -O2 -static

all:
	$(CC) $(CFLAGS) exploit.c -o exploit
```

build.sh:
```bash
${CC:-gcc} -static -O2 -o "$OUT/exploit" exploit.c
```

### 编译器变量

所有 Makefile 必须使用 `$(CC)` 变量，允许通过 `CC=...` 覆盖编译器（如 musl 交叉编译）。

```makefile
CC ?= gcc
```

### Release zip 结构

Release zip 包含：
- 编译好的二进制文件（直接在 `0x` 目录下）
- 预编译工具（`tools/` 目录）

源码不包含在 zip 中，请从 GitHub 仓库获取。

```
ll-privesc-kit-gnu/
  01dirtycow/
    dirtyc0w          # 编译产物
  02sudo-samedit/
    sudo-hax-me-a-sandwich  # 编译产物
    ...
  tools/
    bash-static
    busybox
    socat
    strace
    pspy64
    ...
```

## CI 流程

### 构建

1. `build/build.sh gnu dist/gnu` — glibc 静态编译
2. `build/build.sh musl dist/musl` — musl 静态编译

### 发布

1. 打 tag `v*` 触发 CI
2. CI 自动编译 glibc 和 musl 版本
3. 自动发布 Release 并上传 zip

## 新增 Exploit

1. 创建 `NNname/` 目录（NN 为两位数字）
2. 提供 `build.sh <outdir> [gnu|musl]`
3. C 代码必须使用 `-static` 编译
4. build.sh 只负责编译，产物放到 `$OUT/`
5. 更新 `manifest.json`
6. 更新 `README.md`
