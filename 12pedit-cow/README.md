# 12pedit-cow — CVE-2026-46331 act_pedit 页缓存损坏

> `net/sched` act_pedit 在报文编辑时触发页缓存部分写时复制（partial COW）损坏。通过 tc + act_pedit 对页缓存中的只读文件做原位改写，进而在低权限下修改 setuid 二进制/关键文件实现提权。包含两个变体实现：`packet_edit_meme`（完整上游仓库）和 `CVE-2026-46331.c`（单文件变体）。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-46331 |
| 漏洞类型 | 内核页缓存部分 COW 损坏 |
| 影响内核 | Linux 5.18 ~ 7.1-rc6 |
| 公开时间 | 2026-06-16 |
| 官方上游 | [yanxinwu946/CVE-2026-46331](https://github.com/yanxinwu946/CVE-2026-46331) |
| 源码类型 | C（静态） |

## 目录结构
| 文件 | 说明 |
|---|---|
| `CVE-2026-46331/packet_edit_meme.c` | 利用主程序（完整上游） |
| `CVE-2026-46331/pedit_primitive.c/h` | act_pedit 原语封装 |
| `CVE-2026-46331/Makefile` | 构建（默认 `-static`） |
| `CVE-2026-46331.c` | 单文件变体（0xBlackash） |

## 编译
```bash
./build.sh <outdir> [gnu|musl]    # 构建 packet_edit_meme + 编译 CVE-2026-46331.c
```

## 用法
```bash
./packet_edit_meme      # 完整上游版本
./poc                   # 单文件变体
```

## 恢复/清理
- 升级内核至修复版本。

## 上游参考
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2026-46331)