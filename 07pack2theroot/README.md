# 07pack2theroot — CVE-2026-41651 PackageKit TOCTOU

> PackageKit D-Bus 事务处理存在 TOCTOU 竞态：同一事务可先以 `FLAG_SIMULATE` 触发授权检查，再立即以 `FLAG_NONE` 提交真实安装，绕过授权直接以 root 安装攻击者控制的包。修复于 PackageKit 1.3.5（`pk-transaction.c` 状态守卫）。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-41651 |
| 漏洞类型 | D-Bus TOCTOU 竞态 |
| 影响版本 | PackageKit < 1.3.5 |
| 公开时间 | 2026 |
| 源码类型 | Python + C 混合 |

## 目录结构
| 文件 | 说明 |
|---|---|
| `cve_2026_41651.py` | 利用脚本（dpkg-deb / rpmbuild 双方案） |
| `cve-2026-41651.c` | C 版本利用（独立实现，无 glib 依赖） |
| `Makefile` | C 代码编译脚本 |

## 编译
```bash
# Python 方案无需编译
# C 方案需要编译（build.sh 会自动处理）
./build.sh <outdir> [gnu|musl]

# 或手动编译 C 代码
make
```

## 用法
```bash
# Python 方案
python3 cve_2026_41651.py
# Debian/Ubuntu 用 dpkg-deb；RHEL/Fedora/SUSE 用 rpmbuild

# C 方案（无额外依赖，仅需 libc）
./cve-2026-41651
```

## 恢复/清理
- 升级 PackageKit ≥1.3.5。

## 上游参考
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2026-41651)
- [sick-pwn 实现](https://afflicted.sh)
