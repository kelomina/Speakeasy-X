# Limitations

Speakeasy does not delegate API calls, object management, or I/O to a real Windows kernel. Those behaviors are modeled by the emulator, so unsupported paths or environment mismatches can stop execution early.

## Unimplemented APIs

Samples call APIs with assumptions about arguments, return values, side effects, and stack behavior. If a required API handler is missing, the current run stops and records an error.

Expected error pattern:

- `Unsupported API: <module_name>.<api_name>`

Why execution stops:

- for unknown APIs, argument count/calling convention cannot be trusted
- continuing may corrupt stack state and generate misleading report data

Queued runs (for example additional entry points) can still execute.

## Generated API stubs

For common system DLLs (kernel32, kernelbase, ntdll, msvcrt, user32, shell32, advapi32, gdi32, ole32, oleaut32, rpcrt4, version, ...), exports without a real handler are covered by generated permissive stubs (see `speakeasy/winenv/api/generated.py` and `tools/gen_api_stubs.py`).

Many of the previously-uncovered exports now have real handlers with documented behavior:

- **msvcrt/ucrtbase** – math (double/float/long-double), ctype, string/memory ops, `strtol`/`atoi`/`_i64toa` conversion families, `sprintf_s`/`_vscprintf`/`sscanf_s` formatting, time functions, environment (`getenv`/`_putenv`/`_dupenv_s`), fd-based file I/O (`_open`/`_read`/`_write`/`_lseek`/`_stat`/`_findfirst`), stdio helpers (`fgets`/`feof`/`fgetpos`), temp names, aligned allocation, plus UCRT legacy aliases (`_o_X`) and locale variants (`_X_l`)
- **ntdll** – the native API surface: `NtAllocateVirtualMemory`/`NtProtectVirtualMemory`/`NtReadVirtualMemory`, `NtQuerySystemInformation`/`NtQueryInformationProcess` (incl. ProcessImageFileName), `NtCreateFile`/`NtQueryInformationFile`/`NtDeviceIoControlFile`, sync objects (`NtCreateEvent`/`NtCreateMutant`/`NtCreateSemaphore`), registry (`NtCreateKey`/`NtQueryValueKey`/`NtSetValueKey`), environment, ETW (no-op providers), loader basics (`LdrGetDllHandle`/`LdrGetDllFullName`), Rtl* time/zone/env helpers; `Zw*` aliases are registered alongside
- **kernelbase** – new `KernelBase` handler reusing all real kernel32 handlers (GetTickCount, GetModuleHandleW, CreateFileW, ...) plus kernelbase-specific functions (GetSystemTimePreciseAsFileTime, GetCurrentProcessId, GetDateFormat/GetNumberFormat/GetCurrencyFormat, GetPrivateProfileString, QueryFullProcessImageName, LCMapString, Fibers/TimerQueue/Threadpool handles, Fls*, AppPolicy*, GetPackage*, ...)
- **VERSION.dll** – full implementation parsing the file's VS_VERSION_INFO resource (GetFileVersionInfoW, VerQueryValueW, VerLanguageNameW, ...)
- **oleaut32** – BSTR, VARIANT (incl. VarAdd/VarSub/VarDiv/VarRound/VarCmp arithmetic and Var*FromStr conversions), VariantTime<->SystemTime, SafeArray, error-info store
- **ole32** – GUID helpers (CoCreateGuid, StringFromGUID2, CLSIDFromString, ...), CoTaskMemAlloc family, CoInitializeSecurity, structured storage/stream handles (StgCreateDocfile, CreateStreamOnHGlobal, ReadClassStm, ...)
- **advapi32** – the Reg* registry family, SID string conversion (ConvertSidToStringSid, CreateWellKnownSid), event log (RegisterEventSource/ReportEvent), credentials store (CredRead/CredWrite), cryptbase crypto (SystemFunction001/002 MD4, SystemFunction003 MD5, SystemFunction032/033 RC4), security descriptors/ACLs, LogonUser with token
- **rpcrt4** – UuidCreate/UuidFromString/UuidToString, RpcStringBindingCompose/Parse, RpcBinding* helpers
- **user32** – window class/text/prop/timer/clipboard stores, keyboard state, cursor, DC handles, menus, icons, message helpers
- **gdi32** – drawing/object helpers (MulDiv, GetStockObject, DC/brush/pen/font/region handles, BitBlt/TextOut/DrawText, viewport/transform state, wgl context stubs)
- **shell32** – the Str*/Path* string family (StrCmpW, PathFindFileNameW, PathCombineW, ...), CommandLineToArgvW, SHGetFolderPath, PathFileExists, ShellExecuteW, drag&drop query
- **sechost** – new `Sechost` handler reusing all real advapi32 handlers (service APIs); **shcore** – SHAnsiToUnicode/SHUnicodeToAnsi, DPI helpers
- api-ms-win contracts are folded to their redirect targets (`api-ms-win-service-*`→sechost, `api-ms-win-shcore-*`→shcore, `api-ms-win-security-*`/`api-ms-win-eventing-*`/`api-ms-win-downlevel-*`/`api-ms-win-stateseparation-*`→kernelbase), and A/W-suffixed imports fall back to the normalized handler

How stubs behave (functions that still have no real implementation):

- a stub always returns `0` (STATUS_SUCCESS / FALSE / NULL) and is logged like any other API call
- real handlers and user API hooks always take priority; a stub is only used when neither resolves the export
- on x86, argument counts are extracted from the x86 system DLLs (`ret imm16` analysis) so the stdcall stack stays balanced; unresolved functions use `argc=0`
- imports of CRT data exports (e.g. `msvcrt._iob`, `_errno`) resolve to zero-initialized memory slots

Because stubs return `0`, a sample that depends on the real return value of a long-tail API may continue with wrong data instead of stopping with an `unsupported_api` error. When a function matters, implement a real handler for it (see [Adding API handlers](api-handlers.md)) — the stub is ignored automatically. After adding handlers, regenerate the stub tables with `python tools/gen_api_stubs.py`.

## Environmental requirements

A sample may expect files, registry keys, network responses, loaded modules, or runtime structures that are not present in the active profile. These misses can look like anti-analysis behavior even when the issue is configuration drift.

Use config and CLI overrides to model the expected environment before concluding a sample is unsupported.

## Related docs

- [Project README](../README.md)
- [Documentation index](index.md)
- [Configuration walkthrough](configuration.md)
- [CLI environment overrides](cli-environment-overrides.md)
- [Adding API handlers](api-handlers.md)
- [Help and troubleshooting](help.md)
