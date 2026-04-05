# CLI execution controls | CLI 执行控制

This page covers runtime limits, execution mode, and debugging controls.

本页面涵盖运行时限制、执行模式和调试控制。

## Stopping conditions | 停止条件

Primary flags:

主要标志：
- `--timeout`: wall-clock timeout in seconds | 挂钟超时（秒）
- `--max-api-count`: cap API calls per run | 每次运行的 API 调用上限
- `--max-instructions`: cap executed instructions per run | 每次运行的执行指令上限

Use these together to bound long-running or looping samples.

一起使用这些来限制长时间运行或循环的样本。

## Execution mode controls | 执行模式控制

Primary flags:

主要标志：
- `--raw`: emulate target as raw bytes | 将目标模拟为原始字节
- `--arch`: architecture override (`x86`, `amd64`) | 架构覆盖（`x86`, `amd64`）
- `--raw-offset`: raw-mode execution start offset (hex) | 原始模式执行起始偏移（十六进制）
- `--emulate-children`: emulate spawned child processes | 模拟生成的子进程
- `--no-mp`: run in current process instead of worker process | 在当前进程中运行而非工作进程

Example: raw shellcode run with bounded execution

示例：带有绑定执行的原始 shellcode 运行

```bash
speakeasy -t shellcode.bin \
  --raw --arch x86 --raw-offset 0x40 \
  --timeout 15 --max-api-count 3000 --max-instructions 500000 \
  -o report.json
```

## Debugging controls | 调试控制

Primary flags:

主要标志：
- `--verbose`: DEBUG logging | DEBUG 日志
- `--gdb`: start GDB stub and pause before first instruction | 启动 GDB stub 并在第一条指令前暂停
- `--gdb-port`: GDB stub port | GDB stub 端口

Notes:

注意：
- `--gdb` implies `--no-mp` automatically. | `--gdb` 自动隐含 `--no-mp`
- Use `gdb` or `gdb-multiarch` to connect to `localhost:<port>`. | 使用 `gdb` 或 `gdb-multiarch` 连接到 `localhost:<port>`

Example: debugger-first startup profile

示例：调试器优先启动配置

```bash
speakeasy -t sample.dll --gdb --gdb-port 1234 --verbose
```

## Profiles | 配置文件

### Anti-loop containment profile | 反循环遏制配置

```bash
speakeasy -t sample.exe \
  --timeout 20 \
  --max-api-count 4000 \
  --max-instructions 800000 \
  --no-analysis-memory-tracing \
  -o report.json
```

Use this as a fast triage baseline for samples that often spin in loops.

将此用作经常循环的样本的快速分类基线。

### Deep-debug profile | 深度调试配置

```bash
speakeasy -t sample.exe \
  --gdb --gdb-port 2345 \
  --no-mp \
  --analysis-coverage \
  --analysis-memory-tracing \
  --verbose \
  -o report.json
```

Use this when you want step control and richer telemetry during one run.

当您希望在一次运行中获得步骤控制和更丰富的遥测时使用此选项。

## Performance and telemetry tuning | 性能和遥测调优

Speakeasy is Python-based, so runtime is sensitive to telemetry scope and stop conditions.

Speakeasy 基于 Python，因此运行时对遥测范围和停止条件很敏感。

Practical tuning:

实用调优：

- disable heavy collectors unless needed: | 除非需要，否则禁用重型收集器：
  - `--no-analysis-memory-tracing`
  - `--no-analysis-coverage`
  - `--no-snapshot-memory-regions`
- set hard stop limits for unstable or looping samples: | 为不稳定或循环样本设置硬性限制：
  - `--timeout`
  - `--max-api-count`
  - `--max-instructions`
- run fast triage and deep telemetry as separate profiles | 将快速分类和深度遥测作为独立的配置运行

## Related docs | 相关文档

- [Project README](../README.md) | [项目 README](../README.md)
- [Documentation index](index.md) | [文档索引](index.md)
- [CLI reference](cli-reference.md) | [CLI 参考](cli-reference.md)
- [CLI analysis recipes](cli-analysis-recipes.md) | [CLI 分析示例](cli-analysis-recipes.md)
- [GDB debugging reference](gdb.md) | [GDB 调试参考](gdb.md)
- [Help and troubleshooting](help.md) | [帮助和故障排除](help.md)
