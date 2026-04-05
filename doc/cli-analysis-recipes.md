# CLI analysis recipes | CLI 分析示例

This page focuses on practical flag combinations for common analysis outputs.

本页面专注于常见分析输出的实用标志组合。

<a id="recipe-memory-snapshots"></a>
## In-report memory snapshots (`--snapshot-memory-regions`) | 报告中内存快照

Command:

命令：

```bash
speakeasy -t sample.exe --snapshot-memory-regions -o report.json
```

Expected artifact:

预期产物：
- `entry_points[*].memory.layout[*].data_ref` populated with SHA-256 refs | 填充 SHA-256 引用
- top-level `data` populated with `base64(zlib(raw_bytes))` entries | 顶级 `data` 填充 `base64(zlib(raw_bytes))` 条目

Quick verification:

快速验证：

```bash
jq '.entry_points[].memory.layout[] | select(.data_ref != null) | .tag' report.json
```

Tradeoff:

权衡：
- report size increases, but repeated payloads deduplicate across runs | 报告大小增加，但重复的有效负载在运行间去重

<a id="recipe-analysis-coverage"></a>
## Coverage collection (`--analysis-coverage`) | 覆盖率收集

Command:

命令：

```bash
speakeasy -t sample.exe --analysis-coverage -o report.json
```

Expected artifact:

预期产物：
- `entry_points[*].coverage` contains executed instruction addresses | `entry_points[*].coverage` 包含执行的指令地址

Quick verification:

快速验证：

```bash
jq '.entry_points[] | {start_addr, coverage_count: (.coverage // [] | length)}' report.json
```

Tradeoff:

权衡：
- extra tracing overhead increases runtime | 额外的追踪开销增加运行时

<a id="recipe-memory-tracing"></a>
## Memory tracing (`--analysis-memory-tracing`) | 内存追踪

Command:

命令：

```bash
speakeasy -t sample.exe --analysis-memory-tracing -o report.json
```

Expected artifact:

预期产物：
- per-region access counters in `memory.layout[*].accesses` | `memory.layout[*].accesses` 中的每区域访问计数器
- symbol access summaries in `sym_accesses` | `sym_accesses` 中的符号访问摘要

Quick verification:

快速验证：

```bash
jq '.entry_points[] | {start_addr, sym_accesses: (.sym_accesses // [] | length)}' report.json
```

Tradeoff:

权衡：
- substantial runtime impact on memory-heavy samples | 对内存密集型样本有显著的运行时影响

<a id="recipe-analysis-strings"></a>
## String extraction controls (`--analysis-strings` / `--no-analysis-strings`) | 字符串提取控制

Enable:

启用：

```bash
speakeasy -t sample.exe --analysis-strings -o report.json
```

Disable:

禁用：

```bash
speakeasy -t sample.exe --no-analysis-strings -o report.json
```

Quick verification:

快速验证：

```bash
jq '.strings' report.json
```

Tradeoff:

权衡：
- disabling strings reduces report size and post-processing time | 禁用字符串可减少报告大小和后处理时间

<a id="recipe-dropped-files"></a>
## Dropped files archive (`--dropped-files-path`) | 丢弃文件归档

Command:

命令：

```bash
speakeasy -t sample.exe --dropped-files-path dropped.zip
```

Expected artifact:

预期产物：
- `dropped.zip` with files written during emulation and a manifest | `dropped.zip` 包含模拟期间写入的文件和清单

Quick verification:

快速验证：

```bash
unzip -l dropped.zip
```

Tradeoff:

权衡：
- captures useful payload artifacts but adds archive creation overhead | 捕获有用的有效负载产物但增加归档创建开销

<a id="recipe-combined-triage"></a>
## Combined triage profile | 综合分类配置

Command:

命令：

```bash
speakeasy -t sample.exe \
  --timeout 30 \
  --analysis-coverage \
  --analysis-memory-tracing \
  --snapshot-memory-regions \
  --dropped-files-path dropped.zip \
  -o report.json
```

Use this profile when you want broad telemetry and artifact capture in one run.

当您希望在一次运行中获得广泛的遥测和产物捕获时使用此配置。

## Related docs | 相关文档

- [Project README](../README.md) | [项目 README](../README.md)
- [Documentation index](index.md) | [文档索引](index.md)
- [CLI reference](cli-reference.md) | [CLI 参考](cli-reference.md)
- [CLI execution controls](cli-execution-controls.md) | [CLI 执行控制](cli-execution-controls.md)
- [Configuration walkthrough](configuration.md) | [配置详解](configuration.md)
- [Report walkthrough](reporting.md) | [报告详解](reporting.md)
- [Help and troubleshooting](help.md) | [帮助和故障排除](help.md)
