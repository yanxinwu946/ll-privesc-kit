# 03pwnkit — CVE-2021-4034 polkit pkexec PwnKit

> polkit `pkexec` 越界写。`pkexec` 未正确处理 argv 为空的情况，`argc==0` 时读取到越界环境变量 `GCONV_PATH`，可利用 glibc `gconv` 机制加载恶意共享库以 root 执行任意代码。

| 项 | 值 |
|---|---|
| CVE | CVE-2021-4034 |
| 漏洞类型 | 越界内存访问 / 任意代码执行（gconv 滥用） |
| 影响版本 | polkit pkexec 所有主流发行版（2009 ~ 2022 修复） |
| 公开时间 | 2022-01 |
| 官方上游 | [blasty/CVE-2021-4034](https://github.com/blasty/CVE-2021-4034) |
| 源码类型 | C |

## 目录结构
| 文件 | 说明 |
|---|---|
| `CVE-2021-4034/pwnkit.c` | 恶意 gconv 模块源码 |
| `CVE-2021-4034/cve-2021-4034.c` | 利用主程序 |
| `CVE-2021-4034/cve-2021-4034.sh` | 一键利用脚本（含 gconv 目录搭建） |
| `CVE-2021-4034/Makefile` | 构建（含 `dry-run` 检测目标） |

## 编译
```bash
./build.sh <outdir> [gnu|musl]    # 产物: cve-2021-4034, pwnkit.so, gconv-modules
```

## 用法
```bash
# 一键（脚本内部完成 GCONV_PATH 目录搭建）
./cve-2021-4034.sh

# 手动：执行二进制（需同目录存在 pwnkit.so 与 gconv-modules）
./cve-2021-4034
```

## 恢复/清理
- 升级 polkit 至 ≥0.120（各发行版已修复）。
- 清理当前目录生成的 `GCONV_PATH=.` 目录：`make clean`。

## 上游参考
- <https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034>
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2021-4034)
