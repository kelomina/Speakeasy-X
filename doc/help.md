# 帮助和故障排除

当您遇到问题并需要最快路径找到合适的文档时，请使用本页面。

## 第一步：导航到正确的页面

- 不确定从哪里开始：从 [文档索引](index.md) 开始
- 安装/运行时设置：[install.md](install.md)
- 命令行标志和调用规则：[cli-reference.md](cli-reference.md)
- 环境配置和确定性：[cli-environment-overrides.md](cli-environment-overrides.md)
- 运行时控制和停止条件：[cli-execution-controls.md](cli-execution-controls.md)
- 报告模式和字段语义：[reporting.md](reporting.md)
- 交互式调试：[gdb.md](gdb.md)

## 常见问题

### 不支持的 API 错误

症状：
- 日志/报告中出现 `Unsupported API: <module>.<name>`

阅读：
- [limitations.md](limitations.md)
- [api-handlers.md](api-handlers.md)

### 样本过早退出或行为与预期不同

检查：
- [configuration.md](configuration.md)
- [cli-environment-overrides.md](cli-environment-overrides.md)

### 运行太慢或生成非常大的工件

检查：
- [cli-analysis-recipes.md](cli-analysis-recipes.md)
- [cli-execution-controls.md](cli-execution-controls.md)
- [cli-execution-controls.md#performance-and-telemetry-tuning](cli-execution-controls.md#performance-and-telemetry-tuning)

### 需要交互式单步执行

检查：
- [gdb.md](gdb.md)
- [gdb-examples.md](gdb-examples.md)

### 需要在模拟文件系统中挂载文件

检查：
- [volumes.md](volumes.md)
- [cli-reference.md](cli-reference.md)

## 提交问题之前

请包含以下信息以便其他人快速复现：

- Speakeasy 版本和安装方式
- 使用的完整命令行
- 配置覆盖（如果有）
- 目标类型（`exe`、`dll`、`sys`、原始 shellcode）
- 失败附近的 `--verbose` 日志摘录
- 报告摘录（`errors`、`entry_points[*].error`）

## 需要更多帮助

- 文档中心：[index.md](index.md)
- 项目主页：[../README.md](../README.md)
- 问题跟踪器：[github.com/mandiant/speakeasy/issues](https://github.com/mandiant/speakeasy/issues)
