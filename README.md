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

## 项目结构

```
Speakeasy-X/
├── speakeasy/                 # 核心模拟框架
│   ├── engines/              # CPU模拟引擎
│   │   └── unicorn_eng.py    # Unicorn引擎实现
│   ├── resources/            # 模拟资源文件
│   │   ├── files/           # 默认文件资源
│   │   └── web/             # Web相关诱饵资源
│   ├── windows/              # Windows环境模拟
│   │   ├── kernel_mods/     # 内核驱动支持模块
│   │   ├── com.py           # COM组件模拟
│   │   ├── cryptman.py      # 加密管理
│   │   ├── driveman.py      # 驱动管理
│   │   ├── fileman.py       # 文件系统模拟
│   │   ├── ioman.py         # I/O管理
│   │   ├── kernel.py        # Windows内核模拟
│   │   ├── loaders.py       # PE/DLL加载器
│   │   ├── netman.py        # 网络管理
│   │   ├── regman.py        # 注册表模拟
│   │   ├── sessman.py       # 会话管理
│   │   └── winemu.py        # Win32模拟
│   ├── winenv/               # Windows环境完整模拟
│   │   ├── api/             # API实现
│   │   │   ├── kernelmode/  # 内核模式API (ntoskrnl, hal等)
│   │   │   └── usermode/    # 用户模式API (kernel32, ntdll等)
│   │   ├── decoys/          # 诱饵文件 (x86/amd64)
│   │   └── defs/            # Windows类型定义
│   ├── cli.py               # 命令行工具
│   ├── config.py            # 配置管理
│   ├── memmgr.py            # 内存管理
│   ├── profiler.py          # 性能分析
│   └── speakeasy.py         # 主入口
├── tests/                    # 测试套件
│   ├── bins/               # 测试二进制文件
│   ├── test_*.py           # 各功能测试
│   └── pma_*.py            # PMA样本测试
├── doc/                      # 详细文档
│   ├── api-handlers.md     # API处理器开发
│   ├── cli-reference.md    # CLI参考
│   ├── configuration.md    # 配置详解
│   ├── gdb.md              # GDB调试
│   ├── library.md          # 库使用指南
│   └── ...
├── pyproject.toml           # 项目配置
└── README.md                 # 本文件
```

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

## 命令行工具使用指南 | CLI Usage Guide

Speakeasy 提供功能丰富的命令行工具，用于恶意软件模拟和分析。以下是指令的完整参考。

Speakeasy provides a feature-rich command-line tool for malware emulation and analysis. Below is the complete reference.

### 基本用法 | Basic Usage

```bash
speakeasy --target <样本路径> [选项]
speakeasy --target <path-to-sample> [flags]
```

**必需参数 | Required Arguments:**
- `-t, --target`: 要模拟的输入文件路径 | Path to input file to emulate
- `--dump-default-config`: 打印内置默认配置 JSON 并退出（唯一不需要 `--target` 的模式）| Print built-in default config JSON and exit (the only mode that doesn't require `--target`)

### 运行时标志 | Runtime Flags

这些标志不在配置模式中生成，仅在运行时使用。

These flags are not generated from the config schema and are used only at runtime.

| 标志 | 说明 |
|------|------|
| `-t, --target` | 要模拟的输入文件 | Input file to emulate |
| `-o, --output` | 输出报告 JSON 路径 | Output report JSON path |
| `--argv` | 模拟进程的 argv 值（引号字符串，按 shell 规则解析）| Argv values for emulated process (quoted string, parsed with shell rules) |
| `-c, --config` | JSON 配置文件覆盖 | JSON config overlay file |
| `--raw` | 将输入视为原始字节/shellcode | Treat input as raw bytes/shellcode |
| `--raw-offset` | 原始执行起始偏移（十六进制）| Raw execution start offset (hex) |
| `--entry-point` | 用作入口点的 RVA（十六进制），替代 PE 默认值 | RVA (hex) to use as entry point instead of PE's default |
| `--arch` | 架构覆盖（`x86`, `amd64`；原始模式下接受 `x64`）| Architecture override (`x86`, `amd64`; `x64` accepted in raw mode) |
| `--dropped-files-path` | 丢弃文件的归档输出路径 | Dropped-files archive output path |
| `-k, --emulate-children` | 模拟样本生成的子进程 | Emulate child processes spawned by the sample |
| `--no-mp` | 在当前进程中运行而非工作进程 | Run in current process instead of worker process |
| `-v, --verbose` | DEBUG 日志 | DEBUG logging |
| `--gdb` | 启用 GDB stub 并在第一条指令前暂停 | Enable GDB stub and pause before first instruction |
| `--gdb-port` | GDB stub 端口（默认 `1234`）| GDB stub port (default `1234`) |
| `-V, --volume` | 主机路径:客户机路径映射（可重复）| Host_path:guest_path mapping (repeatable) |

**注意 | Notes:**
- `--gdb` 隐含 `--no-mp`；Speakeasy 会自动启用此功能 | `--gdb` implies `--no-mp`; Speakeasy enables this automatically
- `--raw-offset` 按十六进制（base-16）解析 | `--raw-offset` is parsed as base-16
- `--pseudocode-*` 系列选项用于生成简化的伪代码输出 | `--pseudocode-*` options generate simplified pseudocode output

### 配置派生标志 | Config-Derived Flags

大多数 `SpeakeasyConfig` 中的标量/切换/列表/映射字段都作为 CLI 标志公开。

Most scalar/toggle/list/mapping fields in `SpeakeasyConfig` are exposed as CLI flags.

**命名规则 | Naming Rules:**
- 配置路径 `a.b_c` 映射到 `--a-b-c`
- 布尔值使用双重形式：`--flag` 和 `--no-flag`
- 字典映射使用可重复的 `KEY=VALUE`
- 列表值使用可重复的 `VALUE`

#### 布尔切换 | Boolean Toggles

| 标志 | 默认值 | 说明 |
|------|--------|------|
| `--analysis-memory-tracing` / `--no-analysis-memory-tracing` | False | 在报告中启用内存访问追踪 | Enable memory access tracing in reports |
| `--analysis-strings` / `--no-analysis-strings` | True | 从输入和模拟内存中提取字符串 | Extract strings from input and emulated memory |
| `--analysis-coverage` / `--no-analysis-coverage` | False | 收集每个运行中执行的指令地址 | Collect executed instruction addresses per run |
| `--keep-memory-on-free` / `--no-keep-memory-on-free` | False | 保留释放的内存映射以供释放后检查 | Retain freed memory maps for post-free inspection |
| `--snapshot-memory-regions` / `--no-snapshot-memory-regions` | False | 在报告数据存储中包含运行结束时的内存区域快照 | Include run-end memory region snapshots in the report data store |
| `--exceptions-dispatch-handlers` / `--no-exceptions-dispatch-handlers` | True | 在故障时分派配置的异常处理程序 | Dispatch configured exception handlers during faults |
| `--user-is-admin` / `--no-user-is-admin` | True | 向管理员检查暴露提升的权限 | Expose elevated privileges to admin checks |
| `--api-hammering-enabled` / `--no-api-hammering-enabled` | False | 启用 API hammering 缓解 | Enable API hammering mitigation |
| `--modules-modules-always-exist` / `--no-modules-modules-always-exist` | False | 合成未知模块而非失败加载 | Synthesize unknown modules instead of failing loads |
| `--modules-functions-always-exist` / `--no-modules-functions-always-exist` | False | 将未解析的导入视为现有存根 | Treat unresolved imports as existing stubs |
| `--pseudocode-comments` / `--no-pseudocode-comments` | - | 在伪代码输出中包含汇编注释和解析的上下文 | Include assembly comments and resolved context in pseudocode output |
| `--pseudocode-keep-filtered-jumps` / `--no-pseudocode-keep-filtered-jumps` | - | 在伪代码输出中保留过滤的跳转指令作为仅注释行 | Keep filtered jump instructions as comment-only lines in pseudocode output |
| `--pseudocode-show-register-values` / `--no-pseudocode-show-register-values` | - | 在伪代码注释和 XML 输出中显示当前寄存器值 | Show current register values in pseudocode comments and XML output |
| `--pseudocode-enable-heuristics` / `--no-pseudocode-enable-heuristics` | - | 启用别名、函数名、内存抽象和折叠的启发式恢复 | Enable heuristic recovery for aliases, function names, memory abstraction and folding |

#### 标量值 | Scalars

| 标志 | 默认值 | 说明 |
|------|--------|------|
| `--timeout` | 60 | 模拟超时（秒）| Emulation timeout in seconds |
| `--max-api-count` | 10000 | 每次运行允许的最大 API 调用数 | Maximum API calls allowed per run |
| `--max-instructions` | -1 | 每次运行执行的最大指令数 | Maximum instructions to execute per run |
| `--stack-size` | 0 | 覆盖堆栈大小（字节）。0 使用 PE 头值或内置默认值 (0x12000) | Override stack size in bytes. 0 uses PE header value or built-in default (0x12000) |
| `--os-ver-major` | 6 | 模拟操作系统主版本 | Emulated OS major version |
| `--os-ver-minor` | 1 | 模拟操作系统次版本 | Emulated OS minor version |
| `--os-ver-release` | None | 可选的模拟操作系统发布号 | Optional emulated OS release number |
| `--os-ver-build` | 7601 | 模拟操作系统构建号 | Emulated OS build number |
| `--current-dir` | `C:\Windows\system32` | 模拟进程 API 的当前工作目录 | Current working directory for emulated process APIs |
| `--command-line` | `svchost.exe myarg1 myarg2` | 暴露给模拟进程 API 的命令行 | Command line exposed to emulated process APIs |
| `--domain` | `speakeasy_domain` | 域或工作组标识 | Domain or workgroup identity |
| `--hostname` | `speakeasy_host` | 暴露给模拟系统 API 的主机名 | Hostname exposed to emulated system APIs |
| `--user-name` | `speakeasy_user` | 暴露给账户和配置文件的用户名 | Username exposed to account and profile APIs |
| `--user-sid` | `S-1-5-21-1111111111-2222222222-3333333333-1001` | 模拟用户的可选显式 SID | Optional explicit SID for the emulated user |
| `--api-hammering-threshold` | 2000 | 触发缓解的重复阈值 | Repetition threshold that triggers mitigation |
| `--modules-module-directory-x86` | `$ROOT$/winenv/decoys/x86` | x86 诱饵模块的搜索路径 | Search path for x86 decoy modules |
| `--modules-module-directory-x64` | `$ROOT$/winenv/decoys/amd64` | x64 诱饵模块的搜索路径 | Search path for x64 decoy modules |
| `--pseudocode-string-encoding` | - | 伪代码输出的字符串解码模式：utf8 或 utf16 | String decoding mode for pseudocode output: utf8 or utf16 |

#### 映射/列表 | Mappings/Lists

| 标志 | 说明 |
|------|------|
| `--env KEY=VALUE` | 模拟进程可见的环境变量（可重复）| Environment variables visible to the emulated process (repeatable) |
| `--network-dns-names KEY=VALUE` | DNS 查找使用的域名到 IP 的映射（可重复）| Domain-to-IP mappings used by DNS lookups (repeatable) |
| `--api-hammering-allow-list VALUE` | 免于缓解的 API 名称（可重复）| API names exempt from mitigation (repeatable) |

### 配置优先级 | Config Precedence

活动运行时配置按以下顺序构建：

Active runtime config is built in this order:

1. 内置默认值（`SpeakeasyConfig`）| Built-in defaults (`SpeakeasyConfig`)
2. 可选的 `--config` JSON 覆盖 | Optional `--config` JSON overlay
3. 显式 CLI 覆盖 | Explicit CLI overrides

**覆盖语义 | Overlay Semantics:**
- 映射递归合并 | Mappings merge recursively
- 列表整体替换基线列表 | Lists replace the baseline list wholesale
- 省略的字段继承模型默认值 | Omitted fields inherit model defaults

**冲突示例 | Conflict Example:**

```bash
speakeasy --target sample.exe \
  --config profile.json \
  --timeout 20 \
  --no-analysis-strings \
  --output report.json
```

如果 `profile.json` 设置 `timeout=120` 和 `analysis.strings=true`，则有效运行时值为 `timeout=20` 和 `analysis.strings=false`。

If `profile.json` sets `timeout=120` and `analysis.strings=true`, effective runtime values are `timeout=20` and `analysis.strings=false`.

### 不支持的复杂字段 | Unsupported Complex Fields on CLI

以下字段仅限配置文件：

The following fields are config-file-only:

- 架构/元数据：`config_version`, `description`, `emu_engine`, `system`, `os_ver.name`
- 对象列表和嵌套结构：
  - `symlinks`, `drives`
  - `filesystem.files`
  - `registry.keys`
  - `network.adapters`, `network.dns.txt`, `network.http.responses`, `network.winsock.responses`
  - `processes`
  - `modules.user_modules`, `modules.System_modules`

**原因 | Rationale:** 这些是嵌套或大型结构，作为 CLI 参数不够便捷。

These are nested or large structures and are not ergonomic as CLI arguments.

### 实用示例 | Practical Examples

#### 简单 PE 运行 | Simple PE Run

```bash
speakeasy --target sample.exe --output report.json
```

#### 原始 shellcode 运行 | Raw Shellcode Run

```bash
speakeasy --target shellcode.bin --raw --arch x86 --raw-offset 0x20 --output report.json
```

#### 内存快照和丢弃文件归档 | Memory Snapshots and Dropped-Files Archive

```bash
speakeasy --target sample.exe --snapshot-memory-regions --dropped-files-path dropped.zip
```

#### 快速分类 | Quick Triage

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

#### 企业身份配置文件 | Enterprise Identity Profile

```bash
speakeasy -t sample.exe \
  --hostname WS-3471 \
  --domain CORP \
  --user-name jdoe \
  --user-sid S-1-5-21-1111111111-2222222222-3333333333-1107 \
  --no-user-is-admin \
  --os-ver-major 10 \
  --os-ver-minor 0 \
  --os-ver-build 19045 \
  -v -o report.json 2> run.log
```

#### 强制 DNS 解析 | Force DNS Resolutions

```bash
speakeasy -t sample.exe \
  --network-dns-names c2-a.example=203.0.113.10 \
  --network-dns-names c2-b.example=203.0.113.11 \
  -o report.json
```

#### 反循环遏制配置 | Anti-Loop Containment Profile

```bash
speakeasy -t sample.exe \
  --timeout 20 \
  --max-api-count 4000 \
  --max-instructions 800000 \
  --no-analysis-memory-tracing \
  -o report.json
```

#### 深度调试配置 | Deep-Debug Profile

```bash
speakeasy -t sample.exe \
  --gdb --gdb-port 2345 \
  --no-mp \
  --analysis-coverage \
  --analysis-memory-tracing \
  --verbose \
  -o report.json
```

#### 综合分类配置 | Combined Triage Profile

```bash
speakeasy -t sample.exe \
  --timeout 30 \
  --analysis-coverage \
  --analysis-memory-tracing \
  --snapshot-memory-regions \
  --dropped-files-path dropped.zip \
  -o report.json
```

### 性能和遥测调优 | Performance and Telemetry Tuning

Speakeasy 基于 Python，因此运行时对遥测范围和停止条件很敏感。

Speakeasy is Python-based, so runtime is sensitive to telemetry scope and stop conditions.

**实用调优建议 | Practical Tuning Tips:**

- 除非需要，否则禁用重型收集器 | Disable heavy collectors unless needed:
  - `--no-analysis-memory-tracing`
  - `--no-analysis-coverage`
  - `--no-snapshot-memory-regions`
- 为不稳定或循环样本设置硬性限制 | Set hard stop limits for unstable or looping samples:
  - `--timeout`
  - `--max-api-count`
  - `--max-instructions`
- 将快速分类和深度遥测作为独立的配置运行 | Run fast triage and deep telemetry as separate profiles

### 相关文档 | Related Docs

- [命令行分析示例](doc/cli-analysis-recipes.md) | [CLI Analysis Recipes](doc/cli-analysis-recipes.md)
- [命令行环境覆盖](doc/cli-environment-overrides.md) | [CLI Environment Overrides](doc/cli-environment-overrides.md)
- [命令行执行控制](doc/cli-execution-controls.md) | [CLI Execution Controls](doc/cli-execution-controls.md)
- [GDB 调试参考](doc/gdb.md) | [GDB Debugging Reference](doc/gdb.md)
- [配置详解](doc/configuration.md) | [Configuration Walkthrough](doc/configuration.md)
- [报告详解](doc/reporting.md) | [Report Walkthrough](doc/reporting.md)
- [帮助和故障排除](doc/help.md) | [Help and Troubleshooting](doc/help.md)

## 问题和帮助

请先查看 [doc/help.md](doc/help.md)。

如果您仍然需要帮助，请在 [github.com/kelomina/Speakeasy-X/issues](https://github.com/kelomina/Speakeasy-X/issues) 上提交问题。
