# 06chwoot — CVE-2025-32463 sudo `-R` 目录逃逸

> sudo `-R`/`--chroot` 选项允许指定 NSS root 目录，攻击者可用受控目录构造恶意 `nsswitch.conf` 与 `libnss_*` 模块。sudo 在 chroot 内解析 NSS 时以 root 加载攻击者提供的共享库，实现 root 代码执行（"sudo woot"）。

| 项 | 值 |
|---|---|
| CVE | CVE-2025-32463 |
| 漏洞类型 | chroot 逃逸 / NSS 库加载 → root |
| 影响版本 | sudo 1.9.9p1 ~ 1.9.16（特定配置） |
| 公开时间 | 2025-04 |
| 官方上游 | [richmirch/CVE-2025-32463-Sudo-Root-Escalation](https://github.com/richmirch/CVE-2025-32463-Sudo-Root-Escalation) |
| 源码类型 | Shell（运行时生成并编译 .so） |

## 目录结构
| 文件 | 说明 |
|---|---|
| `chwoot.sh` | 一键利用脚本（生成 woot1337.c → 编译 .so → `sudo -R` 触发） |
| `chwoot/woot1337.c` | 参考 root shell 载荷源码 |

## 编译
```bash
./build.sh <outdir> [gnu|musl]    # 直接拷贝脚本，目标机上运行时编译
```

## 用法
```bash
./chwoot.sh                     # 默认起 /bin/bash root shell
./chwoot.sh id                  # 或执行任意命令
```

## 恢复/清理
- 升级 sudo；确认无 `-R` 场景或限制 NSS 目录权限。

## 上游参考
- <https://security.humanativaspa.it/cve-2025-32463-sudo-chroot-escape-via-argparse/>
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)
