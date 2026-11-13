# 20ipv6-frag-escape — CVE-2026-53362 IPv6 fraggap 容器逃逸

> `__ip6_append_data()` 在分页分配路径上没有把 `fraggap` 计入 `alloclen`，导致跨分片边界的 15 字节拷贝写到 skb 线性区末尾之外，落入 `skb_shared_info`。攻击者用两次 pipe→UDPv6 `splice()` 把 `nr_frags` 从 0 改成 1，同时保留 `frags[0]` 中指向源管道页的陈旧描述符；skb 释放时对该页多减一次引用，形成页 UAF。随后把该页回收为叶子 PTE 页，用脏页表（dirty pagetable）获得物理内存读写，改写 `core_pattern` 并在子进程崩溃时以 root 执行 memfd helper，从普通容器进程取得宿主 root。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-53362（IPv6；同根因的 IPv4 变体为 CVE-2026-53366） |
| 漏洞类型 | 内核 OOB write / 页 UAF / 容器逃逸 |
| 影响内核 | 6.1 起至 6.12.94（kernelCTF 目标 LTS 6.12.85） |
| 修复版本 | 6.1.190 / 6.6.159 / 6.12.113 / 6.18.56 / 7.2.10 |
| 公开时间 | 2026-07-20（oss-sec）；CISA KEV 2026-08-27 |
| 官方上游 | [qwerty-po/security-research — CVE-2026-53362_lts](https://github.com/qwerty-po/security-research/tree/cve-2026-53362/pocs/linux/kernelctf/CVE-2026-53362_lts)（Apache-2.0） |
| 源码类型 | C++（静态，链接 kernelXDK） |

## 目录结构

| 文件 | 说明 |
|---|---|
| `src/exploit.c` | 完整利用链；通过 `INCBIN` 内嵌 `target_db.kxdb` |
| `src/target_db.kxdb` | kernelXDK 目标数据库（`core_pattern` 物理地址等） |
| `src/libxdk-v0.1/` | kernelXDK 静态库与头文件 |
| `docs/exploit.md` | 上游逐阶段利用说明 |
| `docs/vulnerability.md` | 漏洞说明 |
| `docs/metadata.json` | kernelCTF 提交元数据（95% 稳定性） |
| `bin/cve-2026-53362` | 预编译 x86_64 静态二进制（glibc） |
| `build.sh` | 构建脚本 |
| `LICENSE` | 上游 Apache-2.0 许可证 |

## 编译

```bash
./build.sh                 # 默认输出到 bin/
./build.sh dist/gnu        # 或指定输出目录
```

需要 `g++`、`libkeyutils-dev` 和 Linux UAPI 头文件。`exploit.c` 使用 `INCBIN(target_db, "target_db.kxdb")`，因此编译必须在 `src/` 目录内进行（`build.sh` 已处理）。没有 `keyutils.h` 时，脚本会回退复制已提交的预编译二进制。

## 用法

```bash
# 目标：kernelCTF LTS 6.12.85；成功后打印 /flag
./bin/cve-2026-53362
```

- 普通本地用户即可运行；kernelCTF 元数据不要求 userns 或额外 capability，只需 `CONFIG_IPV6`、UDPv6 与 `splice()`。
- 二进制中的 `core_pattern` 物理地址、`target_db.kxdb` 与内核版本绑定；其他内核需要重新生成目标数据库并调整偏移。
- 上游在 LTS 6.12.85 上记录 20/20 次成功；kernelCTF 元数据标注 95% 稳定性。

## 恢复/清理

- 升级到 6.12.113 / 6.18.56 / 7.2.10 等修复版本并重启。
- 利用会留下被改写的 `core_pattern` 和脏页表映射；建议直接丢弃虚拟机。
- 临时缓解：限制非特权 user namespace（对依赖 userns 的变体有效），或禁用不需要的 IPv6；但不能替代内核补丁。

## 上游参考

- [CVE-2026-53362](https://nvd.nist.gov/vuln/detail/CVE-2026-53362) · [CVE-2026-53366](https://nvd.nist.gov/vuln/detail/CVE-2026-53366)
- [oss-sec 披露](https://seclists.org/oss-sec/2026/q3/215)
- [qwerty 技术博客](https://blog.qwerty.or.kr/en/posts/cdf3008a-c1a4-4eca-a373-aa3a2bcf1489/)
- 相关变体（无 CVE，RHEL/CentOS 10）：<https://github.com/sgkdev/ipv6_frag_escape>
