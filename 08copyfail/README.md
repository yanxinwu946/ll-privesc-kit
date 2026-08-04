# 08copyfail — CVE-2026-31431 Copy Fail（AF_ALG 页缓存写入）

> AF_ALG 套接字 + `splice()` 页缓存变异 LPE。通过 `AF_ALG` 的 `authencesn(hmac(sha256),cbc(aes))` 模板，让内核在 AEAD 解密时对 `splice()` 注入的页缓存页面做原位 4 字节 STORE。认证失败时写入已发生，页缓存修改永久保留。每次触发写入 4 字节，迭代覆盖 setuid 二进制实现提权。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-31431 |
| 漏洞类型 | 内核页缓存写入（AF_ALG in-place AEAD） |
| 影响内核 | 需 AF_ALG 套接字族 + `authencesn` 模板（几乎全版本） |
| 公开时间 | 2026-04-29 |
| 官方上游 | [tgies/copy-fail-c](https://github.com/tgies/copy-fail-c) |
| 源码类型 | C（nolibc 载荷） |

## 目录结构
| 文件 | 说明 |
|---|---|
| `copy-fail-c/exploit.c` | 主利用（setuid 二进制覆写） |
| `copy-fail-c/exploit-passwd.c` | `/etc/passwd` UID 翻转变体 |
| `copy-fail-c/vulnerable.c` | 漏洞自测程序 |
| `copy-fail-c/Makefile` | 构建（glibc / musl 多目标） |

## 编译
```bash
./build.sh <outdir> [gnu|musl]    # gnu: make；musl: make musl-static
```

## 用法
```bash
./exploit            # 默认注入 setuid 载荷提权
./exploit-passwd     # 直接向 /etc/passwd 写入 root 用户
./vulnerable         # 靶机存在性自测
```

## 恢复/清理
- 重启或 `echo 3 > /proc/sys/vm/drop_caches` 清除页缓存。

## 上游参考
- <https://copy.fail/>（官方分析报告）
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)