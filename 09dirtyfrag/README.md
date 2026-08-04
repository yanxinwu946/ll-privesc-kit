# 09dirtyfrag — CVE-2026-43284 / CVE-2026-43500 Dirty Frag

> Dirty Frag 漏洞类：链式利用 xfrm-ESP 页缓存写入（CVE-2026-43284）与 RxRPC 页缓存写入（CVE-2026-43500）。`esp_input()` 在 in-place AEAD 解密时绕过 `skb_cow_data`，直接对 `splice()` 注入的页缓存页面做 4 字节 STORE；RxRPC 变体无需 userns 即可触发。确定性逻辑漏洞，无需竞态条件。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-43284（xfrm-ESP）+ CVE-2026-43500（RxRPC） |
| 漏洞类型 | 内核页缓存损坏（Dirty 家族） |
| 影响内核 | xfrm-ESP: 4.9 ~ 6.17（需 userns）；RxRPC: 5.19 ~ 6.17 |
| 公开时间 | 2026-05-07 |
| 官方上游 | [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) |
| 源码类型 | C |

## 目录结构
| 文件 | 说明 |
|---|---|
| `dirtyfrag/exp.c` | 利用源码（链式 ESP + RxRPC，需 `-lutil`） |
| `dirtyfrag/assets/write-up.md` | 完整技术分析报告 |

## 编译
```bash
./build.sh <outdir> [gnu|musl]    # gnu: -lutil；musl: libutil 并入 libc 自动处理
```

## 用法
```bash
./dirtyfrag
# 若 userns 受限（Ubuntu AppArmor）：
# sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

## 恢复/清理
- `echo 3 > /proc/sys/vm/drop_caches` 清除污染页缓存；升级内核。

## 上游参考
- <https://github.com/V4bel/dirtyfrag>
- [CVE-2026-43284 详情](https://nvd.nist.gov/vuln/detail/CVE-2026-43284)
- [CVE-2026-43500 详情](https://nvd.nist.gov/vuln/detail/CVE-2026-43500)