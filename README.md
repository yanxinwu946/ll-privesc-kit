# ll-privesc-kit

Linux Privilege Escalation Arsenal

[![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux-blue?style=flat-square)](#)
[![Kernel](https://img.shields.io/badge/Kernel-2.6~7.x-purple?style=flat-square)](#)
[![Language](https://img.shields.io/badge/C%20%7C%20Python%20%7C%20Bash-3776AB?style=flat-square)](#)
[![CTF](https://img.shields.io/badge/CTF%20%7C%20Pentest%20%7C%20Red--Team-critical?style=flat-square)](#)
[![CI](https://img.shields.io/badge/Build-gnu%20%7C%20musl%20static-brightgreen?style=flat-square)](#)

收集 2016 ~ 2026 年杀伤范围最广的 Linux 本地提权漏洞 PoC，按公开时间排序。覆盖内核、sudo、polkit、glibc、PackageKit、Open vSwitch 等攻击面。

- 官方原版源码 - 采用各 CVE 最优上游仓库，不改动任何 PoC 代码
- gnu / musl 静态编译 - CI 自动构建所有 C 漏洞的 glibc 与 musl 静态二进制
- 纯净 zip 工具包 - 每个 Release 附带编译好的 gnu/musl 双变体二进制 + 内置工具

## 免责声明

本工具集仅供授权渗透测试、安全研究及 CTF 竞赛使用。未经授权访问或破坏任何系统均属违法行为，使用者自行承担一切后果。

## Release 下载

在 [Releases](https://github.com/yanxinwu946/ll-privesc-kit/releases) 下载对应版本：

```
ll-privesc-kit-gnu-v1.0.0.zip    glibc 静态编译（通用兼容）
ll-privesc-kit-musl-v1.0.0.zip   musl 静态编译（跨发行版兼容性最佳）
```

Release zip 仅包含编译产物与内置工具，不包含 PoC 源码。如需源码请克隆仓库。

结构：

```
ll-privesc-kit-gnu/
├── 01dirtycow/dirtyc0w          # 编译产物
├── 03pwnkit/cve-2021-4034
├── 03pwnkit/pwnkit.so
├── ...
├── tools/                       # 内置工具
│   ├── linpeas.sh
│   ├── pspy32 / pspy64 / pspy64s
│   ├── busybox / socat / strace
│   └── ...
```

## 漏洞列表

| # | 目录 | CVE |
|---|------|-----|
| 01 | dirtycow | CVE-2016-5195 |
| 02 | sudo-samedit | CVE-2021-3156 |
| 03 | pwnkit | CVE-2021-4034 |
| 04 | dirtypipe | CVE-2022-0847 |
| 05 | overlayfs | CVE-2023-0386 |
| 06 | chwoot | CVE-2025-32463 |
| 07 | pack2theroot | CVE-2026-41651 |
| 08 | copyfail | CVE-2026-31431 |
| 09 | dirtyfrag | CVE-2026-43284 / CVE-2026-43500 |
| 10 | fragnesia | CVE-2026-46300 |
| 11 | dirty-clone | CVE-2026-43503 |
| 12 | pedit-cow | CVE-2026-46331 |
| 13 | ovswrap | CVE-2026-64531 |

每个目录的 README 含完整漏洞信息与用法。详细漏洞清单见 `manifest.json`。

## 本地构建

```bash
# glibc 静态
./build/build.sh gnu dist/gnu

# musl 静态（alpine 容器）
docker run --rm -v "$PWD":/src -w /src alpine:3.20 sh -c \
  "apk add build-base fuse-dev libcap-dev bash && ./build/build.sh musl dist/musl"
```

## 贡献

新增漏洞、修复错误或改进构建，请参考 `MAINTAIN.md` 中的规范：

- 按 CVE 公开时间排序插入目录
- 提供 `README.md` 与 `build.sh`（见模板）
- 不改动上游 PoC 源码
- 更新 `manifest.json` 与根目录 `README.md`

---

Maintained by [yanxinwu946](https://github.com/yanxinwu946)