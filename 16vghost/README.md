# 16vghost — CVE-2026-74580 Vghost（vhost 陈旧 IOTLB 缓存）

> vhost 的 `vq->meta_iotlb[]` 缓存了 vring 元数据区域（`desc`/`avail`/`used`）对应的 IOTLB 映射，但 `VHOST_SET_VRING_ADDR` / `VHOST_SET_VRING_NUM` 不会失效该缓存。挂载 device IOTLB 后，普通用户可把 vring 重配到缓存未覆盖的地址，`vhost_vq_meta_fetch()` 无范围检查地把结果交给 `__copy_to_user()`/`__copy_from_user()`，形成内核任意读/写。PoC 先读 IDT 绕过 KASLR，再改写 `modprobe_path`，触发 `request_module()` 获得 root；同一缺陷在 vIOMMU 配置下还可作为客户机到宿主 QEMU 的逃逸向量（本 PoC 未包含）。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-74580（CVSS 8.8） |
| 漏洞类型 | vhost 越界读/写（陈旧 IOTLB 元数据缓存） |
| 影响内核 | 4.11 ~ 7.1.8 / 7.2-rc4 |
| 修复版本 | 5.10.265 / 5.15.216 / 6.1.183 / 6.6.152 / 6.12.104 / 6.18.45 / 7.1.9 / 7.2 |
| 公开时间 | 2026-10-12（完整分析与 PoC） |
| 官方上游 | [zhangutah/security-research](https://github.com/zhangutah/security-research)（镜像：[ABC00012345/CVE-2026-74580](https://github.com/ABC00012345/CVE-2026-74580)） |
| 源码类型 | C（静态） |

## 目录结构

| 文件 | 说明 |
|---|---|
| `src/poc.c` | 主机侧 x86_64 PoC，针对 `/dev/vhost-vsock` |
| `docs/upstream-readme.md` | 上游说明与预期输出 |
| `bin/vghost` | 预编译 x86_64 静态二进制（glibc） |
| `build.sh` | 构建脚本 |

## 编译

```bash
./build.sh                 # 默认输出到 bin/
./build.sh dist/gnu        # 或指定输出目录
```

## 用法

```bash
./bin/vghost
```

前置条件：

- 能打开 `/dev/vhost-vsock`（部分镜像为 `0666`，部分为 `0660 root:kvm`；也可尝试 `/dev/vhost-net`）
- 可读取 `$SYSTEM_MAP`、`/boot/System.map-$(uname -r)` 或 `/usr/lib/modules/$(uname -r)/build/System.map`
- 目标上存在 `gcc`：PoC 会把内嵌的提权 helper 写到 `/tmp/priv_escalation.c` 并在运行时编译为 `/tmp/pwn`
- 已在 Ubuntu 26.04 `7.0.0-28-generic`、RHEL 9.8 `5.14.0-687.5.3.el9_8`、Amazon Linux 2023 `6.1.180-225.360.amzn2023`、Azure Linux 3.0 `6.6.150.1-1.azl3`、Oracle Linux 10.2 `6.12.0-204.92.4.2.el10uek` 上验证

成功后会创建 setuid root 的 `/tmp/sh` 并打开 root shell。

## 恢复/清理

- 手动删除 `/tmp/sh`、`/tmp/pwn`、`/tmp/priv_escalation.c`。
- 升级到修复版本并重启；`/tmp` 下的 setuid 文件不会跨重启保留，但仍应主动清理。
- 无法立即打补丁时，可禁止加载 `vhost` 模块，或限制 `/dev/vhost-*` 的访问权限。

## 上游参考

- [Tencent Zhuque Lab — Vghost: Beyond the Privilege Boundary](https://matrix.tencent.com/en/2026/10/12/vghost-cve-2026-74580)
- [CVE-2026-74580](https://nvd.nist.gov/vuln/detail/CVE-2026-74580)
- 修复提交 `de845981da67`
- 原始 PoC 仓库：<https://github.com/zhangutah/security-research>

> 上游仓库未声明开源许可证，此处按研究归档引用。
