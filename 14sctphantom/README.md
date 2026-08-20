# 14sctphantom — CVE-2026-64564 SCTPhantom（SCTP ASCONF DEL-IP UAF）

> SCTPhantom 是 Linux 内核 SCTP（Stream Control Transmission Protocol）子系统中的一个使用后释放（UAF）漏洞，由腾讯玄武实验室与 Corvus AI 联合发现。通过向内核发送特制的 ASCONF（地址配置）chunk，包含特定的 DEL-IP（删除 IP 地址）参数，内核会错误释放 `struct sctp_transport` 结构体，同时保留悬空指针。利用该 UAF 条件，攻击者可进行堆喷射、绕过 KASLR、篡改 `struct cred` 并调用 `commit_creds()` 实现本地提权。该漏洞可从容器内逃逸至宿主机。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-64564 |
| 漏洞类型 | 内核使用后释放（SCTP ASCONF DEL-IP） |
| 影响内核 | < 6.12.101, < 6.6.148（SCTP ASCONF） |
| 公开时间 | 2026-08-06 |
| 官方上游 | [0xdeadroot/SCTPhantom-CVE-2026-64564](https://github.com/0xdeadroot/SCTPhantom-CVE-2026-64564) |
| 源码类型 | C |

## 目录结构
| 文件 | 说明 |
|---|---|
| `src/CVE-2026-64564.c` | 利用源码（840 行，SCTP UAF 触发 + KASLR 绕过 + commit_creds 提权） |
| `build.sh` | 构建脚本（`${CC:-gcc} -O2 -Wall -static`，无外部库依赖） |

## 编译
```bash
./build.sh <outdir> [gnu|musl]
```

## 用法
```bash
# 需要 SCTP 模块已加载
sudo modprobe sctp

# 运行利用（需 root 权限启动 SCTP 服务端，详见上游文档）
./sctphantom
```

**目标环境：** Debian 13（Trixie）内核 `6.12.95+deb13-amd64`（硬编码偏移量）。

> ⚠️ 该利用依赖特定内核版本的结构体偏移量，在其他内核版本上需手动重新校准。

## 前置条件
- 内核版本 < 6.12.101（未修补 SCTP ASCONF UAF）
- SCTP 模块已加载（`lsmod | grep sctp`）
- `CAP_NET_RAW` 权限（容器默认具备）

## 恢复/清理
- 升级内核至 6.12.101+ 或 6.6.148+
- 禁用 SCTP 模块：`sudo modprobe -r sctp`

## 上游参考
- <https://github.com/0xdeadroot/SCTPhantom-CVE-2026-64564>
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2026-64564)
- [腾讯玄武实验室分析](https://matrix.tencent.com/en/2026/08/06/sctphantom-CVE-2026-64564)
