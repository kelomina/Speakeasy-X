# CLI reference | CLI 参考

## Invocation and required input | 调用和必需输入

Basic emulation invocation:

基本模拟调用：

```bash
speakeasy --target <path-to-sample> [flags]
speakeasy --target <样本路径> [选项]
```

Rules:

规则：
- `--target` is required for emulation runs. | 模拟运行时必需
- `--dump-default-config` is the only mode that does not require `--target`. | `--dump-default-config` 是唯一不需要 `--target` 的模式

Default config dump:

默认配置转储：

```bash
speakeasy --dump-default-config > default-config.json
```

## Runtime-only flags | 仅运行时标志

These flags are not generated from the config schema.

这些标志不在配置模式中生成。

- `-t, --target`: input file to emulate | 要模拟的输入文件
- `-o, --output`: output report JSON path | 输出报告 JSON 路径
- `--argv`: argv values for the emulated process (quoted string, parsed with shell rules) | 模拟进程的 argv 值（引号字符串，按 shell 规则解析）
- `-c, --config`: JSON config overlay file | JSON 配置文件覆盖
- `--dump-default-config`: print built-in default config and exit | 打印内置默认配置并退出
- `--raw`: treat input as raw bytes/shellcode | 将输入视为原始字节/shellcode
- `--raw-offset`: raw execution start offset (hex) | 原始执行起始偏移（十六进制）
- `--arch`: architecture override (`x86`, `amd64`; `x64` accepted in raw mode) | 架构覆盖（`x86`, `amd64`；原始模式下接受 `x64`）
- `--dropped-files-path`: dropped-files archive output path | 丢弃文件的归档输出路径
- `-k, --emulate-children`: emulate child processes spawned by the sample | 模拟样本生成的子进程
- `--no-mp`: run in current process instead of worker process | 在当前进程中运行而非工作进程
- `-v, --verbose`: DEBUG logging | DEBUG 日志
- `--gdb`: enable GDB stub and pause before first instruction | 启用 GDB stub 并在第一条指令前暂停
- `--gdb-port`: GDB stub port (default `1234`) | GDB stub 端口（默认 `1234`）
- `-V, --volume`: host_path:guest_path mapping (repeatable) | 主机路径:客户机路径映射（可重复）

Notes:

注意：
- `--gdb` implies `--no-mp`; Speakeasy enables this automatically. | `--gdb` 隐含 `--no-mp`；Speakeasy 会自动启用此功能
- `--raw-offset` is parsed as base-16. | `--raw-offset` 按十六进制（base-16）解析
- option abbreviations are disabled; pass full flag names. | 选项缩写已禁用；请传递完整标志名

## Schema-derived config flags | 配置派生标志

Most scalar/toggle/list/mapping fields in `SpeakeasyConfig` are exposed as CLI flags.

大多数 `SpeakeasyConfig` 中的标量/切换/列表/映射字段都作为 CLI 标志公开。

Naming rules:

命名规则：
- config path `a.b_c` maps to `--a-b-c` | 配置路径 `a.b_c` 映射到 `--a-b-c`
- booleans use dual form: `--flag` and `--no-flag` | 布尔值使用双重形式：`--flag` 和 `--no-flag`
- dict mappings use repeatable `KEY=VALUE` | 字典映射使用可重复的 `KEY=VALUE`
- list values use repeatable `VALUE` | 列表值使用可重复的 `VALUE`

### Current schema-derived flags (complete list) | 当前配置派生标志（完整列表）

Boolean toggles:

布尔切换：
- `--analysis-memory-tracing` / `--no-analysis-memory-tracing`: enable memory access tracing in reports | 在报告中启用内存访问追踪
- `--analysis-strings` / `--no-analysis-strings`: extract strings from input and emulated memory | 从输入和模拟内存中提取字符串
- `--analysis-coverage` / `--no-analysis-coverage`: collect executed instruction addresses per run | 收集每次运行执行的指令地址
- `--keep-memory-on-free` / `--no-keep-memory-on-free`: retain freed memory maps for post-free inspection | 保留释放的内存映射以供释放后检查
- `--snapshot-memory-regions` / `--no-snapshot-memory-regions`: include run-end memory region snapshots in the report data store | 在报告数据存储中包含运行结束时的内存区域快照
- `--exceptions-dispatch-handlers` / `--no-exceptions-dispatch-handlers`: dispatch configured exception handlers during faults | 在故障时分派配置的异常处理程序
- `--user-is-admin` / `--no-user-is-admin`: expose elevated privileges to admin checks | 向管理员检查暴露提升的权限
- `--api-hammering-enabled` / `--no-api-hammering-enabled`: enable API hammering mitigation | 启用 API hammering 缓解
- `--modules-modules-always-exist` / `--no-modules-modules-always-exist`: synthesize unknown modules instead of failing loads | 合成未知模块而非失败加载
- `--modules-functions-always-exist` / `--no-modules-functions-always-exist`: treat unresolved imports as existing stubs | 将未解析的导入视为现有存根

Scalars:

标量值：
- `--timeout`: emulation timeout in seconds (default: 60) | 模拟超时（秒，默认：60）
- `--max-api-count`: maximum API calls allowed per run (default: 10000) | 每次运行允许的最大 API 调用数（默认：10000）
- `--max-instructions`: maximum instructions to execute per run (default: -1, unlimited) | 每次运行执行的最大指令数（默认：-1，无限制）
- `--os-ver-major`: emulated OS major version (default: 6) | 模拟操作系统主版本（默认：6）
- `--os-ver-minor`: emulated OS minor version (default: 1) | 模拟操作系统次版本（默认：1）
- `--os-ver-release`: optional emulated OS release number | 可选的模拟操作系统发布号
- `--os-ver-build`: emulated OS build number (default: 7601) | 模拟操作系统构建号（默认：7601）
- `--current-dir`: current working directory for emulated process APIs (default: `C:\Windows\system32`) | 模拟进程 API 的当前工作目录（默认：`C:\Windows\system32`）
- `--command-line`: command line exposed to emulated process APIs (default: `svchost.exe myarg1 myarg2`) | 暴露给模拟进程 API 的命令行（默认：`svchost.exe myarg1 myarg2`）
- `--domain`: domain or workgroup identity (default: `speakeasy_domain`) | 域或工作组标识（默认：`speakeasy_domain`）
- `--hostname`: hostname exposed to emulated system APIs (default: `speakeasy_host`) | 暴露给模拟系统 API 的主机名（默认：`speakeasy_host`）
- `--user-name`: username exposed to account and profile APIs (default: `speakeasy_user`) | 暴露给账户和配置文件的用户名（默认：`speakeasy_user`）
- `--user-sid`: optional explicit SID for the emulated user (default: `S-1-5-21-1111111111-2222222222-3333333333-1001`) | 模拟用户的可选显式 SID（默认：`S-1-5-21-1111111111-2222222222-3333333333-1001`）
- `--api-hammering-threshold`: repetition threshold that triggers mitigation (default: 2000) | 触发缓解的重复阈值（默认：2000）
- `--modules-module-directory-x86`: search path for x86 decoy modules (default: `$ROOT$/winenv/decoys/x86`) | x86 诱饵模块的搜索路径（默认：`$ROOT$/winenv/decoys/x86`）
- `--modules-module-directory-x64`: search path for x64 decoy modules (default: `$ROOT$/winenv/decoys/amd64`) | x64 诱饵模块的搜索路径（默认：`$ROOT$/winenv/decoys/amd64`）

Mappings/lists:

映射/列表：
- `--env KEY=VALUE` (repeatable): environment variables visible to the emulated process | 模拟进程可见的环境变量（可重复）
- `--network-dns-names KEY=VALUE` (repeatable): domain-to-IP mappings used by DNS lookups | DNS 查找使用的域名到 IP 的映射（可重复）
- `--api-hammering-allow-list VALUE` (repeatable): API names exempt from mitigation | 免于缓解的 API 名称（可重复）

## Config precedence | 配置优先级

Active runtime config is built in this order:

活动运行时配置按以下顺序构建：

1. built-in defaults (`SpeakeasyConfig`) | 内置默认值（`SpeakeasyConfig`）
2. optional `--config` JSON overlay | 可选的 `--config` JSON 覆盖
3. explicit CLI overrides | 显式 CLI 覆盖

Overlay semantics:

覆盖语义：
- mappings merge recursively | 映射递归合并
- lists replace the baseline list wholesale | 列表整体替换基线列表
- omitted fields inherit model defaults | 省略的字段继承模型默认值

Speakeasy does not currently ship named built-in config profiles beyond the default baseline.

Speakeasy 目前除了默认基线外不提供命名的内置配置配置文件。

Conflict example:

冲突示例：

```bash
speakeasy --target sample.exe \
  --config profile.json \
  --timeout 20 \
  --no-analysis-strings \
  --output report.json
```

If `profile.json` sets `timeout=120` and `analysis.strings=true`, effective runtime values are `timeout=20` and `analysis.strings=false`.

如果 `profile.json` 设置 `timeout=120` 和 `analysis.strings=true`，则有效运行时值为 `timeout=20` 和 `analysis.strings=false`。

## Unsupported complex fields on CLI | CLI 不支持的复杂字段

The following fields are config-file-only:

以下字段仅限配置文件：

- schema/meta: `config_version`, `description`, `emu_engine`, `system`, `os_ver.name` | 架构/元数据
- object lists and nested structures: | 对象列表和嵌套结构：
  - `symlinks`, `drives`
  - `filesystem.files`
  - `registry.keys`
  - `network.adapters`, `network.dns.txt`, `network.http.responses`, `network.winsock.responses`
  - `processes`
  - `modules.user_modules`, `modules.system_modules`

Rationale: these are nested or large structures and are not ergonomic as CLI arguments.

原因：这些是嵌套或大型结构，作为 CLI 参数不够便捷。

## Concrete examples | 具体示例

Simple PE run:

简单 PE 运行：

```bash
speakeasy --target sample.exe --output report.json
```

Raw shellcode run:

原始 shellcode 运行：

```bash
speakeasy --target shellcode.bin --raw --arch x86 --raw-offset 0x20 --output report.json
```

Memory snapshots and dropped-files archive:

内存快照和丢弃文件归档：

```bash
speakeasy --target sample.exe --snapshot-memory-regions --dropped-files-path dropped.zip
```

## Related docs | 相关文档

- [Project README](../README.md) | [项目 README](../README.md)
- [Documentation index](index.md) | [文档索引](index.md)
- [CLI analysis recipes](cli-analysis-recipes.md) | [CLI 分析示例](cli-analysis-recipes.md)
- [CLI environment overrides](cli-environment-overrides.md) | [CLI 环境覆盖](cli-environment-overrides.md)
- [CLI execution controls](cli-execution-controls.md) | [CLI 执行控制](cli-execution-controls.md)
- [CLI help snapshot (showboat)](cli-help-showboat.md) | [CLI 帮助快照 (showboat)](cli-help-showboat.md)
- [Configuration walkthrough](configuration.md) | [配置详解](configuration.md)
- [Help and troubleshooting](help.md) | [帮助和故障排除](help.md)
