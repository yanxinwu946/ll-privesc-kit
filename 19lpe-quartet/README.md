# 19lpe-quartet — 2026 网络栈四连提权（DirtyAH6 / TUNderflow / PPPoEject / DiagSpill）

> 2026-09-18 公开的四个 Linux 内核网络栈本地提权漏洞，均由 Asim Manizada 发现并给出可用的 Python PoC。前三个需要非特权 user namespace 中的网络能力，DiagSpill 不需要任何特殊 capability；四个 PoC 都会直接破坏内核内存，只能在一次性虚拟机中运行。

| CVE | 代号 | 组件与类型 | 前置条件 | 测试目标 | 修复版本 |
|---|---|---|---|---|---|
| CVE-2026-80844 | DirtyAH6 | IPv6 AH6/XFRM 越界写 | userns + `CAP_NET_ADMIN`/`CAP_NET_RAW`；AH6/XFRM、ESP-in-UDP、IOAM6、netem、veth | Fedora 43 `7.1.3-100`；Ubuntu 24.04 `6.8.0-134` | 5.10.269 / 5.15.220 / 6.1.187 / 6.6.156 / 6.12.108 / 6.18.49 / 7.1.13 / 7.2.3 |
| CVE-2026-81000 | TUNderflow | TUN/TAP 越界写（OVS/netkit/VXLAN） | userns + `CAP_NET_ADMIN`；`/dev/net/tun`、TUN、OVS datapath、netkit、VXLAN | Fedora 44 `6.19.10-300`；Ubuntu 24.04.4 `6.17.0-40` | 5.10.270 / 5.15.221 / 6.1.188 / 6.6.157 / 6.12.109 / 6.18.50 / 7.2.4 |
| CVE-2026-68121 | PPPoEject | PPPoE 悬垂头指针 → fdtable 重定向 | userns + `CAP_NET_ADMIN`/`CAP_NET_RAW`；FUSE、PPPoE、IP6GRE、AF_PACKET TX ring、team/bonding | Fedora 44 `6.19.10-300`；Ubuntu 24.04 `6.8.0-124` / `6.8.0-136` | 5.10.265 / 5.15.216 / 6.1.183 / 6.6.148 / 6.12.101 / 6.18.42 / 7.1.6 |
| CVE-2026-74469 | DiagSpill | SCTP diag 回复越界写 → 页表覆写 | 无 userns/特殊 capability；SCTP + `sctp_diag`、THP、4 vCPU/4 GiB、`/etc/sudoers.d` | Ubuntu 24.04 `6.17.0-35`；Fedora 44 `6.19.10-300` | 5.10.265 / 5.15.216 / 6.1.183 / 6.6.151 / 6.12.103 / 6.18.44 / 7.1.8 |

## 利用概要

- **DirtyAH6**：构造 `segments_left` 超过地址数量的 IPv6 路由头，使 AH6 破坏相邻 skb 元数据；再让 ESP 把受控字节解密到 `/etc/pam.d/su` 的页缓存，把 `pam_rootok.so` 改成 `pam_permit.so`，最后 `su - root`。
- **TUNderflow**：TUN 包经过 OVS 的越界写把相邻 `pipe_buffer` 的 `PIPE_BUF_FLAG_CAN_MERGE` 置位；随后通过管道把 `pam_permit.so` 写入 `/etc/pam.d/su` 的页缓存，`su - root`。
- **PPPoEject**：PPPoE 发送路径在 `dev_hard_header()` 重新分配 skb 头后仍使用旧头指针；攻击者把 fdtable 项重定向到伪造的 `struct file`，在 close 时执行受控回调、安装 root cred，并打开 `/bin/sh -p`。
- **DiagSpill**：SCTP 关联的 peer 数量在 16 位字段中截断，`sock_diag` 按截断后的数量分配回复缓冲，而拷贝循环写出全部 81,920 个 transport，覆盖相邻页表；随后把 PMD 改成用户可读写映射，扫描并清零 cred 的 UID/GID，再写入临时 sudoers 规则取得 root。

## 目录结构

```
19lpe-quartet/
├── dirtyah6/     dirtyah6_root_repro.py + 上游 README
├── tunderflow/   tunderflow_root_repro.py + 上游 README
├── pppoeject/    pppoeject_root_repro.py + 上游 README
├── diagspill/    diagspill_root_repro.py + 上游 README
└── build.sh      无构建步骤（Python 脚本直接运行）
```

## 编译/运行

PoC 是自包含 Python 3 脚本，运行时按需编译内嵌的 C/helper，无需预先构建：

```bash
cd dirtyah6 && python3 dirtyah6_root_repro.py
cd ../tunderflow && python3 tunderflow_root_repro.py
cd ../pppoeject && python3 pppoeject_root_repro.py
cd ../diagspill && python3 diagspill_root_repro.py
```

各脚本会校验发行版/内核版本，不匹配时直接退出。具体依赖、CPU/内存/拓扑要求见各子目录的上游 README。`build.sh` 仅打印提示，不产生构建产物。

## 恢复/清理

- DirtyAH6 / TUNderflow 会无备份地修改 `/etc/pam.d/su`；测试后从发行版包恢复该文件，或直接丢弃虚拟机。
- DiagSpill 会留下持有损坏页表的 `diagspill_hold` 进程，运行后必须重启；直接 kill 该进程可能导致内核不稳定。
- 升级到包含四个修复的内核并重启是唯一彻底修复方式。

## 上游参考

- [LPE quartet 技术分析](https://heyitsas.im/posts/lpe-quartet)
- [DirtyAH6](https://github.com/manizada/DirtyAH6) · [TUNderflow](https://github.com/manizada/TUNderflow) · [PPPoEject](https://github.com/manizada/PPPoEject) · [DiagSpill](https://github.com/manizada/DiagSpill)
- [CVE-2026-80844](https://nvd.nist.gov/vuln/detail/CVE-2026-80844) · [CVE-2026-81000](https://nvd.nist.gov/vuln/detail/CVE-2026-81000) · [CVE-2026-68121](https://nvd.nist.gov/vuln/detail/CVE-2026-68121) · [CVE-2026-74469](https://nvd.nist.gov/vuln/detail/CVE-2026-74469)

> 上游仓库未声明开源许可证，此处按研究归档引用。
