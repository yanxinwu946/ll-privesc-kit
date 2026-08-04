# 13ovswrap — CVE-2026-64531 OVSwrap

> Open vSwitch 内核 datapath 的嵌套 action 属性长度溢出。OVS 生成内部 action 流时，嵌套 CLONE/CT action 超过 65535 字节时 `nla_len` 被截断，导致后续 dump/teardown 解析出与验证时不同的 action 结构。攻击者可构造恶意 action 实现内核指针泄露、任意内核读取、credential 覆写，最终提权至 root。

| 项 | 值 |
|---|---|
| CVE | CVE-2026-64531 |
| 漏洞类型 | Netlink 属性长度溢出 / OVS 提权 |
| 影响版本 | Open vSwitch 内核 datapath（需 OVS + conntrack） |
| 公开时间 | 2026-07-27 |
| 官方上游 | [manizada/OVSwrap](https://github.com/manizada/OVSwrap)（PoC）；[0xBlackash/CVE-2026-64531](https://github.com/0xBlackash/CVE-2026-64531)（SafeCheck） |
| 源码类型 | Python + C |

## 目录结构
| 文件 | 说明 |
|---|---|
| `OVSwrap/ovswrap-poc.py` | 原始 Python PoC（GPL-2.0） |
| `CVE-2026-64531-SafeCheck.py` | 无害检测脚本（先跑确认是否受影响） |
| `ovswrap.c` | C 语言移植版（静态编译友好） |
| `records.inc` | 预编译内核偏移数据（~800 个内核构建） |

## 编译
```bash
./build.sh <outdir> [gnu|musl]    # 拷贝 Python 脚本 + 编译 C 版本
```

## 用法
```bash
# Python 版
python3 ovswrap-poc.py

# C 版（静态编译，推荐生产环境使用）
./ovswrap
```

## 恢复/清理
- 升级内核；卸载 openvswitch 模块；限制无特权 userns。

## 上游参考
- <https://heyitsas.im/posts/ovswrap>（完整技术分析）
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-2026-64531)