# 11dirty-clone — CVE-2026-43503 Dirty Clone

> Dirty 家族第四弹：克隆 socket buffer（`skb_clone`）在 ESP/GRO 路径导致的页缓存损坏。利用克隆缓冲区共享页帧，在用户命名空间内对只读页缓存任意写，覆写 setuid 文件提权。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-43503 |
| 漏洞类型 | 内核页缓存损坏（Dirty 家族） |
| 影响内核 | Linux 5.16+（需 userns/netns） |
| 公开时间 | 2026 |
| 源码类型 | Python + C 混合 |

## 目录结构
| 文件 | 说明 |
|---|---|
| `dirtyclone.py` | Python port（ctypes 直接发系统调用） |
| `CVE-2026-43503.c` | C 版本利用（0xBlackash 上游） |

## 编译
```bash
# Python 方案无需编译
# C 方案需要编译（build.sh 会自动处理）
./build.sh <outdir> [gnu|musl]

# 或手动编译 C 代码
gcc -o dirtyclone CVE-2026-43503.c
```

## 用法
```bash
python3 dirtyclone.py
# 默认向 /etc/passwd 注入 firefart:pwned 账户
su firefart

# C 方案（需要先编译）
./dirtyclone
```

## 恢复/清理
- 从 `/etc/passwd` 移除注入账户；升级内核。

## 上游参考
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2026-43503)
- [C PoC 上游](https://github.com/0xBlackash/CVE-2026-43503)
