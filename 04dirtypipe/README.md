# 04dirtypipe — CVE-2022-0847 Dirty Pipe

> Linux 内核管道缓冲区初始化缺陷导致任意文件写入。通过 splice 将文件页缓存与管道缓冲区混用，可向只读文件写入数据（不可改文件内容大小），从而覆写 `/etc/passwd`、setuid 二进制等提权。

| 项 | 值 |
|---|---|
| CVE | CVE-2022-0847 |
| 漏洞类型 | 内核任意文件写（未初始化标志） |
| 影响内核 | Linux 5.8 ~ 5.16.11（修复于 5.16.11 / 5.15.25 / 5.10.102） |
| 公开时间 | 2022-03 |
| 官方上游 | [Arinerron/CVE-2022-0847-DirtyPipe-Exploit](https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit) |
| 源码类型 | C |

## 目录结构
| 文件 | 说明 |
|---|---|
| `dirtypipe/exploit.c` | 完整利用（覆写 /etc/passwd 增加 root 用户） |
| `dirtypipe/compile.sh` | 官方动态编译脚本 |

## 编译
```bash
./build.sh <outdir> [gnu|musl]    # 产出静态 exploit
```

## 用法
```bash
./exploit    # 默认将 firefart:密码 追加到 /etc/passwd
su firefart  # 密码 pwned
```

## 恢复/清理
- 从 `/etc/passwd` 移除注入的用户，或重装受影响软件。

## 上游参考
- <https://dirtypipe.cm4all.com/>
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2022-0847)
