# Speakeasy

Speakeasy 是一个 Windows 恶意软件模拟框架，它在模拟的 Windows 运行环境中执行二进制文件、驱动程序和 shellcode，而不是使用完整的虚拟机。它模拟 API、进程/线程行为、文件系统、注册表和网络活动，使样本能够通过真实的执行路径继续运行。您可以使用 `speakeasy` 命令行工具进行快速分类，或将其作为 Python 库嵌入并生成结构化的 JSON 报告。

背景信息：[Mandiant 概述文章](https://cloud.google.com/blog/topics/threat-intelligence/emulation-of-malicious-shellcode-with-speakeasy/)。

## 快速开始

从 PyPI 安装：

```console
python3 -m pip install speakeasy-emulator
```

运行样本并检查高级报告字段（将 `sample.dll` 替换为您的目标）：

```console
speakeasy -t sample.dll --no-mp -o report.json 2>/dev/null
jq '{sha256, arch, filetype, entry_points: (.entry_points | length)}' report.json
```

```json
{
  "sha256": "30ec092d122a90441a2560f6778ef8233c98079cd34b7633f7bbc2874c8d7a45",
  "arch": "x86",
  "filetype": "dll",
  "entry_points": 3
}
```

此代码片段的可执行证明：[doc/readme-quickstart-showboat.md](doc/readme-quickstart-showboat.md)。

## 文档导航

### 从这里开始

- [安装](doc/install.md)
- [Python 库用法](doc/library.md)
- [帮助和故障排除](doc/help.md)
- [文档索引](doc/index.md)

### 命令行用法

- [命令行参考](doc/cli-reference.md)
- [命令行分析示例](doc/cli-analysis-recipes.md)
- [命令行环境覆盖](doc/cli-environment-overrides.md)
- [命令行执行控制](doc/cli-execution-controls.md)
- [命令行帮助快照 (showboat)](doc/cli-help-showboat.md)

### 报告、配置和运行时行为

- [配置详解](doc/configuration.md)
- [报告详解](doc/reporting.md)
- [内存管理](doc/memory.md)
- [局限性](doc/limitations.md)

### 调试和扩展

- [GDB 调试参考](doc/gdb.md)
- [GDB 会话 (showboat)](doc/gdb-examples.md)
- [使用 `--volume` 挂载主机文件](doc/volumes.md)
- [添加 API 处理器](doc/api-handlers.md)
- [示例目录](examples/)
- [Speakeasy 2 详解大纲](doc/speakeasy2-walkthrough.md)

## 问题和帮助

请先查看 [doc/help.md](doc/help.md)。

如果您仍然需要帮助，请在 [github.com/mandiant/speakeasy/issues](https://github.com/mandiant/speakeasy/issues) 上提交问题。
