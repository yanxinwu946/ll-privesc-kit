# 07pack2theroot — CVE-2026-41651 PackageKit TOCTOU

> PackageKit D-Bus 事务处理存在 TOCTOU 竞态：同一事务可先以 `FLAG_SIMULATE` 触发授权检查，再立即以 `FLAG_NONE` 提交真实安装，绕过授权直接以 root 安装攻击者控制的包。修复于 PackageKit 1.3.5（`pk-transaction.c` 状态守卫）。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-41651 |
| 漏洞类型 | D-Bus TOCTOU 竞态 |
| 影响版本 | PackageKit < 1.3.5 |
| 公开时间 | 2026 |
| 源码类型 | Python（python3-gi） |

## 目录结构
| 文件 | 说明 |
|---|---|
| `cve_2026_41651.py` | 利用脚本（dpkg-deb / rpmbuild 双方案） |

## 编译
无需编译，`build.sh` 直接拷贝：
```bash
./build.sh <outdir> [gnu|musl]
```

## 用法
```bash
# 依赖: python3-gi（GObject introspection）
python3 cve_2026_41651.py
# Debian/Ubuntu 用 dpkg-deb；RHEL/Fedora/SUSE 用 rpmbuild
```

## 恢复/清理
- 升级 PackageKit ≥1.3.5。

## 上游参考
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2026-41651)
