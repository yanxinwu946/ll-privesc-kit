# 05overlayfs — CVE-2023-0386 OverlayFS 文件复制上提权

> OverlayFS 在 copy-up 时错误保留下层文件能力/属主。攻击者通过 FUSE 构造特制文件（含 file capability），触发 copy-up 后 setuid/capability 被继承，从而以 root 执行任意文件。

| 项 | 值 |
|---|---|
| CVE | CVE-2023-0386 |
| 漏洞类型 | OverlayFS 文件能力继承（copy-up） |
| 影响内核 | Linux 5.11 ~ 6.2（需 unprivileged userns + FUSE） |
| 公开时间 | 2023-01 |
| 官方上游 | [xkaneiki/CVE-2023-0386](https://github.com/xkaneiki/CVE-2023-0386) |
| 源码类型 | C |

## 目录结构
| 文件 | 说明 |
|---|---|
| `CVE-2023-0386/fuse.c` | FUSE 服务端（提供特制文件） |
| `CVE-2023-0386/exp.c` | 利用主程序（触发 copy-up） |
| `CVE-2023-0386/getshell.c` | 反弹/绑定 shell 载荷 |
| `CVE-2023-0386/Makefile` | `make all` 构建全部三件套 |

## 编译
```bash
# 依赖: libfuse-dev(libfuse2) + libcap-dev
./build.sh <outdir> [gnu|musl]
```

## 用法
```bash
./fuse &       # 先启动 FUSE（需 unprivileged userns）
./exp          # 触发 overlayfs copy-up 提权，得到 root shell
```

## 恢复/清理
- 升级内核至 ≥6.2 修复版本。

## 上游参考
- <https://www.openwall.com/lists/oss-security/2023/01/28/1>
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2023-0386)
