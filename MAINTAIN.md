# Maintainer Guide

## 新增漏洞流程

### 1. 确定序号

按 CVE **公开时间**插入到正确位置。当前列表见 `README.md`。

插入后，其后的目录序号全部 +1，并同步更新所有引用。

### 2. 创建目录

```
NNname/           # NN=两位数序号，name=小写短横线短名称
├── README.md     # 见下方模板
├── build.sh      # 见下方契约
└── ...           # 上游 PoC 源码（不改动）
```

### 3. README.md 模板

```markdown
# NNname — CVE-XXXX-XXXXX 名称

> 一句话描述。

| 项 | 值 |
|---|---|
| CVE | CVE-XXXX-XXXXX |
| 漏洞类型 | 类型 |
| 影响版本 | 范围 |
| 公开时间 | YYYY-MM |
| 官方上游 | [作者/仓库](链接) |
| 源码类型 | C / Python / Shell |

## 目录结构
| 文件 | 说明 |
|---|---|
| `xxx/exp.c` | 利用源码 |

## 编译
```bash
./build.sh <outdir> [gnu|musl]
```

## 用法
```bash
./exp
```

## 上游参考
- [CVE 详情](https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX)
```

### 4. build.sh 契约

```
build.sh <outdir> [gnu|musl]
```

- 产物必须落入 `$OUT/`
- 全局 `$CC` 可能被覆盖（musl 场景用 musl-gcc）
- Python/Shell 直接 `cp -f`

### 5. 更新清单

- `manifest.json`：`exploits` 数组按序号插入
- `README.md`：漏洞列表表格插入新行
- 所有被影响的目录 README.md 中的序号也要更新

## 原则

- **不改动上游 PoC 源码**
- 不提交 `.o` / 二进制到 git
- 新增前确认 CVE 编号和公开时间准确
