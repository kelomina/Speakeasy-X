# CLI environment overrides | CLI 环境覆盖

This page covers flags that shape the emulated host environment and behavior determinism.

本页面涵盖塑造模拟主机环境和行为确定性的标志。

## Host, user, and OS identity | 主机、用户和操作系统标识

Primary flags:

主要标志：
- `--hostname`
- `--domain`
- `--user-name`
- `--user-is-admin` / `--no-user-is-admin`
- `--user-sid`
- `--os-ver-major`, `--os-ver-minor`, `--os-ver-release`, `--os-ver-build`

Example: enterprise-like identity profile

示例：企业级身份配置文件

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

Quick verification:

快速验证：

```bash
rg "(hostname|domain|user\.name|user\.sid|user\.is_admin|os_ver\.)" run.log
```

## Process context and environment variables | 进程上下文和环境变量

Primary flags:

主要标志：
- `--current-dir`
- `--command-line`
- `--env KEY=VALUE` (repeatable) | 可重复

Example:

示例：

```bash
speakeasy -t sample.exe \
  --current-dir 'C:\\ProgramData\\Microsoft' \
  --command-line 'svchost.exe -k netsvcs -p' \
  --env TEMP=C:\\Windows\\Temp \
  --env APPDATA=C:\\Users\\jdoe\\AppData\\Roaming \
  --env COMPUTERNAME=WS-3471 \
  -v -o report.json 2> run.log
```

Quick verification:

快速验证：

```bash
rg "(current_dir|command_line|env =)" run.log
```

## DNS override mappings | DNS 覆盖映射

Primary flag:

主要标志：
- `--network-dns-names HOST=IP` (repeatable) | 可重复

Example: force known C2 host resolutions

示例：强制已知的 C2 主机解析

```bash
speakeasy -t sample.exe \
  --network-dns-names c2-a.example=203.0.113.10 \
  --network-dns-names c2-b.example=203.0.113.11 \
  -o report.json
```

Quick verification:

快速验证：

```bash
jq '.entry_points[].events[]? | select(.event == "net_dns") | {query, response}' report.json
```

## Module load policy and decoy module directories | 模块加载策略和诱饵模块目录

Some samples (especially shellcode) parse PE export tables directly to resolve API pointers. When expected modules or exports are missing, these controls let you choose strict or permissive behavior.

某些样本（尤其是 shellcode）直接解析 PE 导出表以解析 API 指针。当缺少预期的模块或导出时，这些控制允许您选择严格或宽松的行为。

Primary flags:

主要标志：
- `--modules-modules-always-exist` / `--no-modules-modules-always-exist`
- `--modules-functions-always-exist` / `--no-modules-functions-always-exist`
- `--modules-module-directory-x86`
- `--modules-module-directory-x64`

Example: relaxed unresolved-import policy with custom decoys

示例：带有自定义诱饵的宽松未解析导入策略

```bash
speakeasy -t sample.exe \
  --modules-modules-always-exist \
  --modules-functions-always-exist \
  --modules-module-directory-x86 /opt/decoys/x86 \
  --modules-module-directory-x64 /opt/decoys/x64 \
  -o report.json
```

Use this when triaging samples that otherwise stop early on missing modules/APIs.

当分类因缺少模块/API 而过早停止的样本时使用此选项。

## API hammering controls | API hammering 控制

Primary flags:

主要标志：
- `--api-hammering-enabled` / `--no-api-hammering-enabled`
- `--api-hammering-threshold`
- `--api-hammering-allow-list VALUE` (repeatable) | 可重复

Example:

示例：

```bash
speakeasy -t sample.exe \
  --api-hammering-enabled \
  --api-hammering-threshold 5000 \
  --api-hammering-allow-list kernel32.WriteFile \
  --api-hammering-allow-list kernel32.ReadFile \
  -o report.json
```

This is useful when balancing anti-loop containment with legitimate hot API usage.

这在平衡反循环遏制与合法的热门 API 使用时很有用。

## Related docs | 相关文档

- [Project README](../README.md) | [项目 README](../README.md)
- [Documentation index](index.md) | [文档索引](index.md)
- [CLI reference](cli-reference.md) | [CLI 参考](cli-reference.md)
- [Configuration walkthrough](configuration.md) | [配置详解](configuration.md)
- [Help and troubleshooting](help.md) | [帮助和故障排除](help.md)
