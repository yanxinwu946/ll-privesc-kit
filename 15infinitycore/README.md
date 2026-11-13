# 15infinitycore — InfinityCore 内核核心子系统提权合集

> 2026-10-16 公开的一组 Linux 内核核心子系统漏洞，共 6 个 CVE，其中 5 个提供可直接取得 root 的利用（另 1 个仅能触发内核 panic）。覆盖 exec/POSIX CPU timer、信号队列、页表遍历、futex 和调度器缓存统计；利用全部由普通用户态系统调用触发，不需要 user namespace、内核模块或特殊 capability，5 个提权利用同时可作为容器逃逸原语。

| CVE | 子系统 | 影响 | 测试目标 | 修复版本 |
|---|---|---|---|---|
| CVE-2026-98260 | exec / POSIX CPU timer | UAF；LPE、容器逃逸、Android LPE | Ubuntu 26.04 `7.0.0-30-generic` | 6.6.158 / 6.12.112 / 6.18.54 / 7.2.8 |
| CVE-2026-98256 | exec / 私有信号队列 | UAF；LPE、容器逃逸 | Ubuntu 26.04 `7.0.0-30-generic` | 6.18.54 / 7.2.8 |
| CVE-2026-89754 | mm / 页表遍历（mincore） | OOB write；LPE、容器逃逸 | Ubuntu 26.04 `7.0.0-30-generic` | 6.18.50 / 7.2.4 |
| CVE-2026-80775 | futex / 私有哈希 | UAF；LPE、容器逃逸 | Ubuntu 26.04 `7.0.0-30-generic` | 6.18.47 / 7.1.11 / 7.2.1 |
| CVE-2026-98385 | 调度器缓存统计 | UAF；LPE、容器逃逸 | Arch Linux `7.2.4-arch1-2` | 7.2.9 |
| CVE-2026-97941 | SLUB 分配器 | 仅内核 panic（未提供提权链） | Arch Linux `7.2.4-arch1-2` | 7.2.7 |

> CVE-2026-98385 仅在 `CONFIG_SCHED_CACHE=y`、运行时 `sched_cache_active` 打开、顶层 `SD_SHARE_LLC` 域含多个 CPU 且有更上层域、`sysctl_sched_cache_user` 非零时可达；PoC 假定 4 个 vCPU、CPU0/1 与 CPU2/3 分别共享一个 LLC。

## 目录结构

| 文件 | 说明 |
|---|---|
| `src/CVE-2026-98260-ubuntu.c` | timer UAF 利用（Ubuntu 目标） |
| `src/CVE-2026-98256-ubuntu.c` | signal UAF 利用（Ubuntu 目标） |
| `src/CVE-2026-89754-ubuntu.c` | mincore 页表 OOB write 利用 |
| `src/CVE-2026-80775-ubuntu.c` | futex 私有哈希 UAF 利用 |
| `src/CVE-2026-98385-arch.c` | 调度器缓存 UAF 利用（Arch 目标） |
| `docs/{timer,signal,mm,futex,sched}.md` | 上游逐漏洞技术分析 |
| `bin/cve-2026-*` | 预编译 x86_64 静态二进制（glibc） |
| `build.sh` | 统一构建脚本 |

## 编译

```bash
./build.sh                 # 默认输出到 bin/
./build.sh dist/gnu        # 或指定输出目录
CC=musl-gcc ./build.sh     # musl 静态构建
```

需要 `gcc`/`musl-gcc`，全部使用 `-O2 -static -pthread`。预编译二进制由 Ubuntu 24.04 / gcc 13.3 构建。

## 用法

```bash
# 以普通用户身份运行；目标内核必须匹配 PoC 硬编码的偏移/版本
./bin/cve-2026-98260       # Ubuntu 26.04 7.0.0-30
./bin/cve-2026-98256       # Ubuntu 26.04 7.0.0-30
./bin/cve-2026-89754       # Ubuntu 26.04 7.0.0-30
./bin/cve-2026-80775       # Ubuntu 26.04 7.0.0-30
./bin/cve-2026-98385       # Arch 7.2.4-arch1-2，4 vCPU
```

成功后会启动 root shell。每个 PoC 都可能改写页缓存或内核内存，**只能在一次性虚拟机/授权测试环境中运行**。

## 恢复/清理

- 升级到对应修复版本并重启，是唯一的彻底修复方式。
- 运行后建议直接丢弃虚拟机；若需保留，删除 PoC 生成的临时 setuid 文件并重启。
- futex/sched 变体通过页缓存改写 `/usr/bin/passwd`、`/usr/bin/newgrp`，重启后页缓存失效。

## 上游参考

- <https://github.com/V4bel/InfinityCore>
- [定时器技术分析](https://github.com/V4bel/InfinityCore/tree/main/timer)
- [CVE-2026-98260](https://nvd.nist.gov/vuln/detail/CVE-2026-98260) · [CVE-2026-98256](https://nvd.nist.gov/vuln/detail/CVE-2026-98256) · [CVE-2026-89754](https://nvd.nist.gov/vuln/detail/CVE-2026-89754) · [CVE-2026-80775](https://nvd.nist.gov/vuln/detail/CVE-2026-80775) · [CVE-2026-98385](https://nvd.nist.gov/vuln/detail/CVE-2026-98385)

> 上游仓库未声明开源许可证，此处按研究归档引用；再分发前请先联系上游作者。
