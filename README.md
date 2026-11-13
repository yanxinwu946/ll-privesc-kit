# ll-privesc-kit

**Linux Privilege Escalation Arsenal**

[![清单检查](https://github.com/yanxinwu946/ll-privesc-kit/actions/workflows/check-catalog.yml/badge.svg?branch=main)](https://github.com/yanxinwu946/ll-privesc-kit/actions/workflows/check-catalog.yml)
[![平台 Linux](https://img.shields.io/badge/Platform-Linux-2F6B9A?logo=linux&logoColor=white)](manifest.json)
[![许可证 MIT](https://img.shields.io/badge/License-MIT-22863A)](LICENSE)

面向授权安全测试、研究和 CTF 的 Linux 本地提权工具包。收录 2016 年至今影响面较大的 Linux 本地提权 PoC，以及常用的提权辅助工具。源码、预编译静态二进制和工具都直接随 Git 仓库维护，不依赖 Release。

## 快速开始

完整克隆：

```bash
git clone https://github.com/yanxinwu946/ll-privesc-kit.git
cd ll-privesc-kit
```

在 [`manifest.json`](manifest.json) 中搜索 CVE 编号或漏洞名称，`id` 对应条目目录。每个条目目录的 `README.md` 说明适用内核/版本、前置条件和用法；包含 ELF 产物的条目在 `bin/` 下附带 x86_64 静态二进制。

```bash
# 按 CVE 查找条目
git grep -n -F 'CVE-2026-31431' -- manifest.json

# 运行预编译产物（以 Copy Fail 为例；先阅读条目 README）
./08copyfail/bin/exploit
```

纯 Python / Shell 条目（`06chwoot`、`19lpe-quartet`）没有 `bin/`，直接运行条目目录里的脚本。

## 只下载 tools

不需要完整仓库时，可以只取 [`tools/`](tools/)。

### 稀疏检出

```bash
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/yanxinwu946/ll-privesc-kit.git
cd ll-privesc-kit
git sparse-checkout set tools
```

### 单文件下载

把 URL 里的文件名换成 `tools/` 中的目标文件：

```bash
curl -fLO https://raw.githubusercontent.com/yanxinwu946/ll-privesc-kit/main/tools/linpeas.sh
chmod +x linpeas.sh
```

也可以在 GitHub 页面打开文件后点击 **Download raw file**。目标机器不能联网时，先在本地下载，再用 `scp`、`curl -T` 或靶场的文件上传点传上去。

## tools 一览

| 文件 | 用途 |
|---|---|
| `linpeas.sh` | LinPEAS 提权枚举 |
| `llpeas.sh` | 精简枚举脚本（Safe OSCP 版） |
| `pspy32` / `pspy64` / `pspy64s` | 无需 root 的进程监控；`pspy64s` 为静态版 |
| `busybox` / `bash-static` / `socat` / `strace` | 受限环境下的静态工具 |
| `sucrack` / `subrute.sh` | su 口令测试（编译版 / Shell 版） |
| `muban.key` / `generate_by_username.sh` | 按用户名生成候选口令列表 |
| `reverse.php` | PHP 反弹 shell（pentestmonkey），使用前修改其中的 IP 和端口 |

`generate_by_username.sh` 从当前目录读取 `muban.key`，所以要在 `tools/` 里运行：

```bash
cd tools
bash generate_by_username.sh alice > dict.txt
sh subrute.sh root dict.txt
```

## 构建与维护

仓库不发布 Release。预编译产物直接提交在各条目的 `bin/`；在 VPS 或本地重新构建并回写：

```bash
./build/sync-bin.sh gnu
```

脚本会编译全部条目，只给包含 ELF 产物的条目保留 `bin/`。清单格式和目录文档由 `Check CVE catalog` 工作流校验：

```bash
python3 .github/scripts/check_catalog.py
```

## 免责声明

本项目仅用于授权渗透测试、安全研究和 CTF。内核提权 PoC 可能破坏内核内存或页缓存，请只在一次性虚拟机或明确授权的环境中运行；未经授权使用后果自负。

## 贡献

请参阅[贡献指南](CONTRIBUTING.md)和[社区行为准则](CODE_OF_CONDUCT.md)。如果发现本仓库自身的安全问题，请按[安全政策](SECURITY.md)报告。

## 许可证

项目采用 [MIT 许可证](LICENSE)。第三方文件的许可见各自的上游声明。
