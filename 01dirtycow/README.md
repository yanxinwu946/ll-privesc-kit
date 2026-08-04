# 01dirtycow — CVE-2016-5195 Dirty COW

> Linux 内核只读内存映射写时复制（COW）竞态漏洞。可对任意只读映射文件进行写入，从而篡改 `setuid` 文件实现提权。

| 项 | 值 |
|---|---|
| CVE | CVE-2016-5195 |
| 漏洞类型 | 内核竞态（race condition） |
| 影响内核 | Linux 2.6.22 ~ 4.8.3（修复于 4.8.3 / 4.4.26 / 3.16.36） |
| 公开时间 | 2016-10 |
| 官方上游 | [dirtycow/dirtycow.github.io](https://github.com/dirtycow/dirtycow.github.io) |
| 源码类型 | C |

## 目录结构
| 文件 | 说明 |
|---|---|
| `dirtyc0w/dirtyc0w.c` | 官方 PoC（只读映射写原语） |
| `dirtyc0w/pokemon.c` | 附加演示变体 |

## 编译
```bash
./build.sh <outdir> [gnu|musl]     # 默认 gnu 静态；musl 需 musl-gcc/alpine
```

## 用法
```bash
# 直接覆盖文件（任意只读文件，如 /etc/passwd 需配合 setuid 程序）
./dirtyc0w /etc/passwd <payload>

# 经典提权：用 dirtyc0w 覆写 /usr/bin/passwd，再执行触发 setuid root
./dirtyc0w /usr/bin/passwd <shellcode>
```

## 恢复/清理
- 被篡改的二进制/文件重新 `apt reinstall` 或从备份恢复。

## 上游参考
- <https://dirtycow.ninja>
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2016-5195)
