# 贡献指南

欢迎修正文档、CVE 编号、受影响范围、上游来源和目录索引。

## 提交 Issue

在 [Issues](https://github.com/yanxinwu946/ll-privesc-kit/issues) 搜索是否已有相关记录。反馈条目问题时，请提供 CVE 编号或文件路径、建议修正的内容，以及能支持修正的原始来源。普通仓库问题可使用「仓库问题」表单。

## 提交 Pull Request

1. 从 `main` 创建分支，将改动集中在一个问题上。
2. 条目信息变化时，同步更新 [manifest.json](manifest.json) 和对应目录的 `README.md`。保留第三方文件的版权声明和许可证。
3. 在仓库根目录运行以下命令，校验清单格式、重复条目和目录文档。

   ```bash
   python3 .github/scripts/check_catalog.py
   ```

4. 在 PR 中简述变更、来源和验证结果，并关联已有 Issue。
