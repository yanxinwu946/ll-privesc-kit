# 10fragnesia — CVE-2026-46300 Fragnesia（ESP-in-TCP 页缓存损坏）

> Fragnesia 是 Dirty Frag 漏洞类的独立变体，由 William Bowling（V12 团队）发现。利用 Linux XFRM ESP-in-TCP 子系统的逻辑缺陷：TCP socket 切换到 `espintcp` ULP 模式时，已通过 `splice()` 注入接收队列的文件页面被当作 ESP 密文处理，AES-GCM 密钥流字节直接 XOR 到页缓存页面。每次触发写入 1 字节，迭代覆写 setuid 二进制实现提权。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-46300 |
| 漏洞类型 | 内核页缓存损坏（ESP-in-TCP） |
| 影响内核 | 受 Dirty Frag 影响的内核（~2026-05-13 前） |
| 公开时间 | 2026-05-13 |
| 官方上游 | V12 团队 Fragnesia（[v12.sh](https://v12.sh)） |
| 源码类型 | C |

## 目录结构
| 文件 | 说明 |
|---|---|
| `fragnesia.c` | 利用源码（单文件，ESP-in-TCP splice + ULP 触发） |

## 编译
```bash
./build.sh <outdir> [gnu|musl]
```

## 用法
```bash
./fragnesia
# Ubuntu（AppArmor 干扰 userns）先执行：
# sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

## 恢复/清理
- 升级内核至修复版本（含 `skb_try_coalesce` SKBFL_SHARED_FRAG 传播补丁）。

## 上游参考
- <https://github.com/v12-security/pocs/tree/main/fragnesia>
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2026-46300)