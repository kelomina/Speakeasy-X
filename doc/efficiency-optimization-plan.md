# Speakeasy-X 效率优化计划文档（合并版）

> 范围：本项目除机器学习（`ml_engine/`）以外的全部模块
> 来源：V1（8 代理，2026-06-26）+ V2（16 代理，2026-06-27）共 24 个代理子会话并行深度分析
> 状态：本文档仅保留未完全实施建议；已完全实施建议已从正文中移除
> 说明：本文件由 `efficiency-optimization-plan.md`（V1）与 `efficiency-optimization-plan-v2.md`（V2）合并而成

---

## 一、执行摘要

### 1.1 分析规模

| 阶段 | 代理数 | 日期 | 识别点 | 去重合并 | 实施状态 |
|------|--------|------|--------|---------|---------|
| V1 | 8 | 2026-06-26 | 80+ | P0 17 项 | 已从本文档移除 |
| V2 | 16 | 2026-06-27 | 112 | 73 项独立建议 | 待实施 |
| 合并 | 24 | — | — | V2 73 + V1 遗留 24 = 97 项 | 仅保留未完全实施项 |

### 1.2 核心结论

**仍需推进的系统性病灶**：
1. **P0 已落地基础设施仍存在未激活的下游收益**：
   - `objman._handle_map` 主路径已就绪，但回退路径 O(n·m) 仍缺暖机短路（V2-5-7）
2. **dict / 索引化覆盖不完整**：仍有 ioman、driveman、fileman 部分目录枚举路径待推进
3. **跨 C 边界调用未完全批量化**：`reg_read_batch`/`context_save` API 已就绪，但 `winemu` 消费方待接入（V2-3-1/5）
4. **正则未预编译、循环内不变量未外提**：`pseudocode.py` 多处 `re.findall`/`re.sub` 即时编译

**隐藏正确性 bug 兼效率问题**（必须在效率优化前修复）：
- `hammer.py` 的 AMD64 分支为空 `# TODO: pass`，x64 样本 hammer 检测完全失效（V2-9-7）

**测试反馈循环可立即提速**：`pytest-xdist` 已安装但 `addopts` 未启用；4 个测试标记（slow/examples/pma/unit）已定义但零使用（V2-16-1/2）

### 1.3 预期总体收益

| 维度 | 当前 | 优化后预期 | 主要贡献项 |
|------|------|-----------|-----------|
| SEH 密集样本 | 基线 | 再降 30-50% | V2-3-1/5 寄存器批量 + context_save |
| 测试并行化 | 串行 | -n auto，2-4× | V2-16-1/2 xdist + 标记 |
| CLI 启动开销 | 基线 | 削减 | V2-15-3 延迟导入 |

---

## 二、跨模块横向主题

#### 主题 E：配置与依赖卫生（部分治理）

| 位置 | 问题 | 状态 |
|------|------|------|
| `__init__.py` 预导入 unicorn | `--help` 付秒级成本 | ❌ 未治理（V2-15-3，P2 待推进，`speakeasy/__init__.py:6-9` 仍顶层导入） |
| ruff/mypy `target-version=py310` vs `requires-python>=3.12` | 工具链不一致 | ❌ 未治理（V1-S-20，P3 待推进，`pyproject.toml:87/94` 仍为 py310） |

### 新增主题（V2 识别）

以下主题在 P0 之后浮现，跨多个模块重复出现，应作为统一治理方向：

#### 主题 F：dict / 索引化覆盖不完整（V2 重点）

P0 已为 `get_mod_from_addr`、`get_address_map`、`_handle_map` 等"地址类"查找建立了 bisect 区间表。但"名称类""ID 类"查找仍是 O(n) 线性：

| 位置 | 当前 | 优化目标 |
|------|------|---------|
| `regman.RegKey.get_value` | O(n) + 每次重算 `.lower()` | `dict[name.lower()]` O(1) |
| `fileman.find_matching_entries` | 每次目录枚举全表扫描 | `dict[dir_lower]` 预分组 |
| `ioman.dev_ioctl` 模块查找 | O(n) + 重复 lower | `dict[mod_name.lower()]` O(1) |
| `driveman.get_drive` | O(n) 线性 | `dict[root_path]` O(1) |

**统一方案**：在所有"管理器"类的 `__init__` 中预建索引 dict；增删对象时同步维护；查询统一走 dict 主路径 + 必要时 fnmatch/通配回退。

#### 主题 G：Pydantic 重复校验与构造

| 位置 | 问题 |
|------|------|
| `cli_config.py:62, 141` | 两次连续 `copy.deepcopy` 大嵌套配置 |
| `profiler.py:891-899` | 每事件 `to_dict()` + Pydantic `AnyEvent` union 双重转换 |
| `profiler_events.py:71-76` | `TracePosition._asdict()` 每事件分配新 dict |
| `speakeasy.py:205-238` | 每次 `load_module` 全量 `model_dump` + `model_validate` |

**统一方案**：缓存默认配置实例 + `model_dump` 返回全新 dict；消除双重校验（直接传模型实例）；报告生成阶段考虑 `model_construct` 跳过验证或完全绕过 Pydantic 用 `json.dumps` + 自定义 encoder。

#### 主题 H：跨 C 边界调用未批量化

| 位置 | 问题 |
|------|------|
| `winemu.get_thread_context`/`load_thread_context` | 8-20 次逐寄存器读写，尚未接入批量 API |
| `winemu` SEH/fiber 切换路径 | 尚未接入 `context_save`/`context_restore` |
| `unicorn_eng.mem_read/mem_write` | 单次直传，无批量与页级缓存 |
| `winemu.ensure_pe_import_hooks` | 每 thunk 一次 `mem_read` |
| `ntoskrnl.ZwQuerySystemInformation` | 循环内每次新建结构体 |

**统一方案**：让 `winemu` 消费方接入已存在的 `reg_read_batch`/`reg_write_batch`/`context_save`/`context_restore`；对相邻小读取合并为大块 `mem_read` + `struct.unpack`；对只读页引入 LRU 缓存。

#### 主题 I：循环内不变量与即时正则编译

| 位置 | 问题 |
|------|------|
| `binemu.get_ansi_strings`/`get_unicode_strings` | 每次 `re.compile` |
| `pseudocode._extract_global_alias_candidates` 等 | `re.findall`/`re.sub` 即时编译 |
| `pseudocode._classify_unknown_global_alias` | 每个 unknown 别名 `re.escape` + 编译 |
| `pseudocode._normalize_window_text` | 6 次 `re.sub` 在 O(N²) 路径被反复调用 |

**统一方案**：模块级 `re.compile` 预编译；循环不变量外提；`str.translate` 替代逐字符替换。

#### 主题 J：缓存失效点遗漏（一致性风险）

以下优化涉及缓存，必须在所有写入路径挂钩失效逻辑，否则会引入难以定位的 bug：

| 缓存项 | 失效点 |
|--------|--------|
| `unicorn_eng` 页级缓存 | `mem_write`/`mem_protect`/`mem_unmap` |

---

## 三、分模块详细优化点（V2 + V1 遗留补充）

每个优化点编号格式 `V2-<模块>-<序号>`（V2 代理识别）或 `V1-S-<序号>`（V1 遗留补充），属性包含：位置、问题、建议、收益（高/中/低）、复杂度（高/中/低）、风险（高/中/低）、优先级（P1/P2/P3）。

### 模块 1：核心模拟器引擎（binemu.py / speakeasy.py）

#### V2-1-3：`get_mem_strings` 去重 O(n²) → O(n)【P2】
- **位置**：`binemu.py:881-882`
- **问题**：`[ret_ansi.append(a) for a in ansi_strings if a not in ret_ansi]` 滥用列表推导做副作用 + list `in` O(n) 导致整体 O(n²)。
- **建议**：改为 `list(dict.fromkeys(ansi_strings))`（Python 3.7+ 保序，O(n)）。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-1-4：正则预编译 / lru_cache【P3】
- **位置**：`binemu.py:786-822`
- **问题**：`get_ansi_strings`/`get_unicode_strings` 每次调用 `re.compile(b"[\x20-\x7f]{%d,}" % min_len)`。
- **建议**：`@functools.lru_cache` 缓存 `(min_len,)` 编译结果。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-1-5：`mem_free` 全量重建代替增量删除【P2】
- **位置**：`memmgr.py:260-267`
- **问题**：`[self.maps.remove(mm) for mm in ml]` 每次 O(n) + `_rebuild_sorted_bases()` O(n log n) 全量重建。已存在 `_sorted_remove`（第 101 行）却未使用。
- **建议**：用 `self.maps = [m for m in self.maps if m not in freed_set]` 一次性重建 + 调用 `_sorted_remove` 增量维护。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-1-6：`Speakeasy._init_hooks` 用 `list.pop(0)` O(n²)【P3】
- **位置**：`speakeasy.py:139-173`
- **建议**：改为 `for h in self.api_hooks: ...` 后 `self.api_hooks.clear()`，或换 `collections.deque`。
- **收益**：低 / **复杂度**：低 / **风险**：低

#### V2-1-7：`_auto_mount_target_directory` 每次 load_module 全量校验配置【P3】
- **位置**：`speakeasy.py:205-238`
- **问题**：每次 `load_module` 重复执行完整 Pydantic 校验。
- **建议**：用标志位确保只挂载一次；若 `filesystem.files` 可变，直接切片赋值。
- **收益**：中 / **复杂度**：中 / **风险**：低

#### V2-1-8：批量样本多进程并行【P1（高收益高复杂度）】
- **位置**：`winemu.py:604-655` run_queue 串行
- **问题**：Unicorn 实例不可跨线程共享。
- **建议**：每样本 fork 独立 `Speakeasy` 实例（ProcessPoolExecutor），合并报告。`cli.py` 已有多进程骨架可复用。
- **收益**：高 / **复杂度**：高 / **风险**：高

#### V1-S-1：`set_func_args` 批量 `mem_write`【P2】
- **位置**：`binemu.py:344-350`
- **问题**：逐参数 `mem_write`，每次跨 C 边界。
- **建议**：合并相邻参数为单次 `mem_write` + `struct.pack`。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V1-S-2：`manifest_json` 字符串拼接改一次性 `json.dumps`【P2】
- **位置**：`speakeasy.py:745`
- **建议**：改为构造 dict 后单次 `json.dumps`。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

#### V1-S-3：跨进程配置缓存【P4】
- **位置**：`speakeasy.py` 多进程场景
- **问题**：每个子进程独立加载配置，批量分析时重复开销。
- **建议**：序列化到 `__pycache__`，子进程直接加载。收益有限，低优先。
- **收益**：低 / **复杂度**：中 / **风险**：中

### 模块 2：内存管理器（memmgr.py）

#### V2-2-2：`mem_free` 增量删除代替全量重建【P2】
- **位置**：`memmgr.py:260-267`
- **建议**：复用已存在的 `_sorted_remove`（第 101 行），删除时增量维护平行结构。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-2-3：`block_base` 反向索引【P2】
- **位置**：`memmgr.py:260`
- **问题**：每次释放都 O(n) 扫描找同 block 的子映射。Windows 堆模拟 `RtlFreeHeap`/`HeapFree` 高频调用。
- **建议**：维护 `self._block_index: dict[int, list[MemMap]]`。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-2-4：`_consume_free_range`/`_restore_free_range` 每次重建 bases 列表【P3】
- **位置**：`memmgr.py:159, 181`
- **建议**：维护平行 `self._free_range_bases: list[int]`。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-2-5：`MemMap.__init__` 标签净化低效【P3】
- **位置**：`memmgr.py:27-31`
- **建议**：`_TAG_BAD_CHARS = str.maketrans(...)`；`tag = tag.translate(_TAG_BAD_CHARS)`。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

#### V2-2-6：`mem_map_reserve` 对 `mem_reserves` 线性扫描【P4】
- **位置**：`memmgr.py:419-423`
- **建议**：用 `bisect.bisect_left(self._sorted_reserve_bases, mapped_base)`。
- **收益**：低 / **复杂度**：低 / **风险**：低

#### V2-2-7：`mem_read` 不必要的 `bytes()` 拷贝【P3】
- **位置**：`memmgr.py:317`
- **问题**：`bytes(bytearray)` 再分配并完整拷贝。
- **建议**：放宽返回类型为 `bytearray`；或大块用 `memoryview`。
- **收益**：低-中 / **复杂度**：低-中 / **风险**：中

#### V2-2-8：`is_address_valid` 串行两次二分【P5】
- **位置**：`memmgr.py:364-372`
- **建议**：仅当 profile 显示为热点再优化。
- **收益**：低 / **复杂度**：中 / **风险**：中

#### V1-S-4：小块分配器引入 slab free list 降低碎片【P2】
- **位置**：`memmgr.py:88-L115`
- **建议**：为小块分配引入 slab free list，降低内存碎片。
- **收益**：中 / **复杂度**：中 / **风险**：中

### 模块 3：Unicorn 引擎封装（engines/unicorn_eng.py）

#### V2-3-1：`reg_read`/`reg_write` 每次字典查找 + 单寄存器跨 C 边界【P1】
- **位置**：`unicorn_eng.py:194-206`
- **问题**：`winemu.get_thread_context` 连续读 8 个寄存器 = 8 次字典查找 + 8 次 C 边界跨越。Unicorn 原生 `uc_reg_read_batch`/`uc_reg_write_batch` 在本封装中 0 处使用。
- **建议**：暴露 `reg_read_batch(regs) -> list` 与 `reg_write_batch(pairs)`；为 `get_pc`/`get_stack_ptr` 缓存 Unicorn 常量。
- **收益**：高 / **复杂度**：中 / **风险**：中

> **2026-06-27 复核更新**：本项为 PARTIAL。主目标已达成，但部分子任务未实施（详见复核报告）。

#### V2-3-3：模块级 `hook_id` 共享可变全局状态【P2】
- **位置**：`unicorn_eng.py:29`
- **建议**：改为实例属性 `self._hook_id = uc_hook_h()`。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

#### V2-3-4：`hook_add` 中 `_uch` 重复属性访问 + `ct.cast` 未缓存【P3】
- **位置**：`unicorn_eng.py:233-255`
- **建议**：`init_engine` 末尾缓存 `self._uch`；`ct.cast` 用 `lru_cache`。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

#### V2-3-5：未封装 `uc_context_save`/`restore`【P1】
- **位置**：整体接口缺失
- **问题**：`winemu.get_thread_context` 用 8 次 `reg_read` 逐字段构造 `CONTEXT`；SEH 密集样本每线程切换都付 N 次 C 调用成本。
- **建议**：增加 `context_save() -> uc_context`、`context_restore(ctx)`、`context_update(ctx, reg, val)`。
- **收益**：中-高 / **复杂度**：中 / **风险**：中

> **2026-06-27 复核更新**：本项为 PARTIAL。主目标已达成，但部分子任务未实施（详见复核报告）。

#### V2-3-6：`mem_read`/`mem_write` 缺批量与页级缓存【P2】
- **位置**：`unicorn_eng.py:181-187`
- **建议**：提供 `mem_read_batch(pairs)`；可选页基址 LRU 缓存（key=`addr >> 12`），仅对只读页启用。
- **收益**：中 / **复杂度**：中-高 / **风险**：中-高

### 模块 4：Windows 模拟核心（windows/winemu.py）

#### V2-4-4：`log_api` 无条件 O(n²) 字符串拼接【P2】
- **位置**：`winemu.py:1715-1732`
- **建议**：前置 `if not logger.isEnabledFor(logging.INFO) and not self.profiler:` 短路；用 `", ".join(...)` 生成器。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-4-5：`handle_import_func` 每次分配闭包并重复取 PC/ret【P2】
- **位置**：`winemu.py:1740-1795`
- **建议**：hook 包装逻辑缓存；`imp_api` 只构造一次；`mm.tag` 存储时即小写。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-4-6：SEH 分发与线程上下文逐寄存器操作【P2】
- **位置**：`winemu.py:2594-2697`、`2480-2533`、`2534-2582`
- **建议**：①用 Unicorn 原生 `context_save`/`context_restore`（配合 V2-3-5）；②`get_arch()` 初始化后绑定具体方法；③日志/反汇编仅在 `isEnabledFor(INFO)` 或 profiler 开启时执行。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-4-7：`_resolve_region_info`/`_find_nearby_regions` 未复用 P0-4【P2】
- **位置**：`winemu.py:1549-1574`
- **问题**：P0-4 优化 `get_address_map` 的遗漏点。
- **建议**：`_resolve_region_info` 直接 `return self.get_address_map(addr)`；`_find_nearby_regions` 基于 `memmgr._sorted_bases` 做 bisect。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-4-8：`ensure_pe_import_hooks` 嵌套循环逐指针 `mem_read`【P3】
- **位置**：`winemu.py:1018-1081`
- **建议**：对每个 descriptor 一次性 `mem_read` 整个 thunk 数组，用 `struct.unpack` 批量解码。
- **收益**：中 / **复杂度**：中 / **风险**：低-中

#### V1-S-6：`setup_user_shared_data` 修复内核副本未填充【P2】
- **位置**：`winemu.py:504-517`
- **问题**：内核副本未填充，可能导致样本读取到错误数据。
- **建议**：确保 `setup_user_shared_data` 正确填充内核副本。
- **收益**：中（正确性） / **复杂度**：低 / **风险**：低

> **2026-06-27 子任务状态明细（⚠️ PARTIAL，1/3 已实施）**：
> - ✅ 已实施：用户态 KUSER_SHARED_DATA 副本填充（`winemu.py:522-523`，`mem_map(0x7FFE0000)` 后调用 `_populate_user_shared_data(0x7FFE0000)`）
> - ❌ 未实施：内核态 x86 副本填充（`winemu.py:516` 仅 `mem_map(0xFFDF0000)`，未调用 `_populate_user_shared_data`）
> - ❌ 未实施：内核态 AMD64 副本填充（`winemu.py:518` 仅 `mem_map(0xFFFFF78000000000)`，未调用 `_populate_user_shared_data`）

### 模块 5：对象管理器（windows/objman.py）

#### V2-5-2：`remove_object` 在已持有对象引用时仍 O(n) 全表扫描【P1】
- **位置**：`objman.py:879-893`
- **建议**：直接 `self.objects.pop(obj.address, None)`；`KernelObject.handles` 改 `set`。
- **收益**：中 / **复杂度**：低 / **风险**：低

> **2026-06-27 复核更新**：本项为 PARTIAL。主目标已达成，但部分子任务未实施（详见复核报告）。

#### V2-5-5：句柄永不复用 + `KernelObject.handles` list 的 `while...in...remove` O(m²)【P2】
- **位置**：`objman.py:78, 122-130, 905-911, 955-972`
- **建议**：①引入 `self._free_handles: list[int]` 栈式空闲池；②`KernelObject.handles` 改 `set` 或用 swap-pop。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-5-6：`add_object` 每次重注册对象所有已存在句柄【P2】
- **位置**：`objman.py:868-877`
- **建议**：加 `obj._handles_registered: bool` 标志，仅首次执行。
- **收益**：中 / **复杂度**：低 / **风险**：中

#### V2-5-7：`get_object_from_handle`/`close_handle` 回退扫描路径 O(n·m) 无暖机标志【P2】
- **位置**：`objman.py:942-953, 955-972`
- **建议**：加 `self._warm: bool` 标志，暖机后 `_handle_map.get` miss 直接返回 None。
- **收益**：中 / **复杂度**：低 / **风险**：中

> **2026-06-27 子任务状态明细（⚠️ PARTIAL，2/5 已实施）**：
> 主路径与补登记（P0-6 成果）已就绪，暖机标志及扫描短路未实施：
> - ✅ 已实施：`_handle_map` 反向字典主路径 O(1) 查找（`objman.py:944-946`）
> - ✅ 已实施：miss 时补登记到反向字典（`objman.py:950-951`，`self._handle_map[handle] = o`）
> - ❌ 未实施：`self._warm: bool` 暖机标志（无字段、无暖机阈值判定逻辑）
> - ❌ 未实施：暖机后 `_handle_map.get` miss 直接返回 None（无 warm-up 短路，miss 必走 O(n·m) 扫描）
> - ❌ 未实施：`close_handle` 回退路径同样无暖机短路（`objman.py:963-966` 每次仍 O(n·m) 扫描）

### 模块 6：文件·IO·驱动管理器（fileman.py / ioman.py / driveman.py）

#### V2-6-4：`find_matching_entries` 每次目录枚举全量扫描无目录索引【P2】
- **位置**：`fileman.py:263-289`
- **建议**：初始化时按父目录归组，构建 `self._dir_index: dict[str, list[(child, is_dir)]]`。
- **收益**：中 / **复杂度**：中 / **风险**：低

#### V2-6-5：`dev_ioctl` 每次 IRP 线性扫描 + 重复 `lower()`【P2】
- **位置**：`ioman.py:17-31`
- **建议**：构建 `self._mod_index: dict[str, KernelModule]`。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-6-6：`get_mapping_from_addr` 嵌套线性扫描无反向索引【P2】
- **位置**：`fileman.py:297-301`
- **建议**：维护 `self._view_index: dict[int, FileMap]`。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-6-7：`_get_kmods()` 反射扫描 + `DriveManager.get_drive` 线性扫描【P3】
- **位置**：`kernel_mods/__init__.py:8-21`、`driveman.py:23-30`
- **建议**：`_get_kmods()` 改为遍历 `__all__`；`DriveManager.__init__` 时预建 `self._by_root` 与 `self._by_guid`。
- **收益**：低 / **复杂度**：低 / **风险**：低

#### V1-S-8：`normalize_response_path` 抽公共模块 + 缓存 root【P2】
- **位置**：`fileman.py:19-27`、`netman.py:18-28`
- **问题**：两个文件中存在重复的路径归一化逻辑。
- **建议**：抽取到公共模块，缓存 root 路径。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

### 模块 7：注册表·网络·加密·会话管理器

#### V2-7-2：`regman` 路径规范化重复执行 + `get_key_from_config` 无缓存【P2】
- **位置**：`regman.py:183, 203, 122-123, 159-176`
- **建议**：入口处规范化一次后传给内部函数；为 `get_key_from_config` 加缓存。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-7-3：`regman.get_subkeys` 循环内不变量未外提【P2】
- **位置**：`regman.py:135-157`
- **建议**：把 `parent_lower = parent_path.lower()` 提到循环外；在 `RegKey` 上缓存其直接子键列表。
- **收益**：中 / **复杂度**：低-中 / **风险**：低

#### V2-7-4：`RegKey.get_value` O(n) + 每次重复 `lower()`【P2】
- **位置**：`regman.py:84-89`
- **建议**：`RegKey` 内部维护 `self._value_index: dict[str, RegValue]`；`base64` 编码延迟到 `get_data()` 被实际调用时。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-7-6：`netman.get_response` 每次读盘 + `get_response_size` 全量读入【P2】
- **位置**：`netman.py:183-229`、`176-181`、`54-63`
- **建议**：维护 `self._response_bytes_cache: dict[str, bytes]`；`get_response_size` 改用 `len(resp.getbuffer())` 零拷贝。
- **收益**：中 / **复杂度**：低 / **风险**：低

> **2026-06-27 子任务状态明细（⚠️ NOT IMPLEMENTED，4/4 未实施）**：
> - ❌ 未实施：`self._response_bytes_cache: dict[str, bytes]` 路径级缓存（`netman.py:218-219, 226-227` 每次 `open(path, "rb") as f: BytesIO(f.read())` 重新读盘）
> - ❌ 未实施：`get_response_size` 零拷贝优化（`netman.py:176-181` 仍 `len(resp.read())` 全量读入）
> - ❌ 未实施：`fill_recv_queue` 同样每次重新读盘（`netman.py:62-63` 未复用缓存）
> - ❌ 未实施：`get_response` 已存在 `self.response` 缓存（line 191-192）但只缓存首次解析结果，不缓存 path→bytes 映射

### 模块 8：内核模式模拟（kernel.py / kernel_mods/）

#### V2-8-1：设备栈遍历的 O(N²) 链表查找与 read_back/write_back 风暴【P2】
- **位置**：`kernel.py:337-354`
- **建议**：在 `Driver` 上维护尾指针；批量初始化设备时只对驱动对象做一次 read_back/write_back。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-8-2：`init_sys_modules` 嵌套线性查找 O(N×M) + 无条件全量初始化【P2】
- **位置**：`kernel.py:157-171`
- **建议**：预先构建 `sysmods` 的 `{m.name: m}` 字典；对 driver/device 对象引入惰性创建。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-8-3：`setup_msrs` 全 ntoskrnl 镜像读取与内核模块重复解析【P3】
- **位置**：`kernel.py:615-650`、`549-564`、`objman.py:803`
- **建议**：在 `setup_kernel_mode` 入口缓存 `self._kernel_mod`；用 `get_export_by_name` 的地址做小范围反向搜索。
- **收益**：中 / **复杂度**：中 / **风险**：中

### 模块 9：Win32·COM（win32.py / com.py / common.py / loaders.py / hammer.py）

#### V2-9-2：`_PeParser.get_exports` 每次重新构造列表 + `get_export_by_name` 线性扫描【P2】
- **位置**：`common.py:279-299`、`347-350`
- **建议**：`get_exports()` 直接 `return self.exports`；构建 `self._exports_by_name: dict[str, entry]`。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-9-4：COM `get_interface` 每次重建 vtable 布局，无缓存【P2】
- **位置**：`com.py:20-64`
- **建议**：按 `(name, ptr_size)` 缓存解析后的字段布局。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-9-5：`_hook_mem_unmapped` PEB 区域未命中时反复全量重建 PEB【P3】
- **位置**：`win32.py:611-621`、`475-498`、`500-521`
- **建议**：用 `proc.is_peb_active` 标志短路重复 `init_peb`。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

#### V2-9-6：`_capture_memory_layout` 每个 run 重复做大量字符串/路径处理【P3】
- **位置**：`win32.py:671-807`
- **建议**：在 `RuntimeModule`/`LoadedImage` 加载时一次性预计算 `display_name`、`prot_string`。
- **收益**：中 / **复杂度**：低-中 / **风险**：低

#### V2-9-7：`ApiHammer` 统计字典无界增长 + 字符串键拼接 + x64 路径未实现【P2】
- **位置**：`hammer.py:38, 70-72, 117-118`
- **问题**：`hammer_key = imp_api + f"{self.emu.get_ret_address():x}"` 每次字符串拼接；`api_stats` 是 `defaultdict(int)` 无上限；**ARCH_AMD64 分支是空 `# TODO: pass`**，x64 样本 hammer 检测完全失效。
- **建议**：键改为 `(imp_api, ret_addr)` 元组；`api_stats` 改 LRU；x64 路径要么实现要么在 `__init__` 按 arch 提前 `self.enabled=False` 并短路。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-9-8：`_PeParser.__init__` 即使 `fast_load=True` 也生成完整 `mapped_image`【P2】
- **位置**：`common.py:199`
- **建议**：将 `mapped_image` 改为惰性（`@property` 或显式 `ensure_mapped_image()`）。
- **收益**：中 / **复杂度**：低 / **风险**：中

### 模块 10：用户模式 API（winenv/api/usermode/）

#### V2-10-1：双重 Hook 属性扫描冗余（全模块 `__init__`）【P2】
- **位置**：`api.py:66-81` + `api.py:83-99` + 全部 36 个子模块 `__init__`
- **问题**：基类 `ApiHandler.__init__` 已执行完整 `for name in dir(self):` 扫描，每个子类 `__init__` 又显式调用 `super().__get_hook_attrs__(self)` 再做一次完全相同的扫描。
- **建议**：删除所有子模块 `__init__` 中的 `super().__get_hook_attrs__(self)` 调用。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-10-3：字符串参数读取样板代码重复（约 144 处）【P2】
- **位置**：典型模式遍布各文件
- **建议**：在 `ApiHandler` 增加批量辅助方法 `read_str_args(self, argv, indices, cw)`。
- **收益**：中 / **复杂度**：低-中 / **风险**：低

#### V2-10-4：静态 flag 字典字面量在每次调用时重建【P3】
- **位置**：`ntdll.py:103-115`、`kernel32.py:903-915`
- **建议**：将 `flags` 字典提升为模块级常量。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

#### V2-10-5：`to_bytes(self.get_ptr_size(), "little")` 重复方法调用（32+ 处）【P3】
- **位置**：跨 9 文件 32 处
- **建议**：在 `ApiHandler.__init__` 中缓存 `self._ptr_size`。
- **收益**：低 / **复杂度**：低 / **风险**：低

#### V2-10-6：winhttp / wininet 独立实例化 NetworkManager【P2】
- **位置**：`winhttp.py:38`、`wininet.py:38`
- **建议**：统一改为 `self.netman = emu.get_network_manager()`。
- **收益**：低-中 / **复杂度**：低 / **风险**：中

#### V2-10-7：跨模块句柄计数器起始值冲突【P2】
- **位置**：`advapi32.py:39`、`shell32.py:30`、`user32.py:44`、`gdi32.py:21`、`kernel32.py:66`
- **建议**：句柄分配收归 `emu`/`objman` 全局原子递增器；或为各模块分配互不重叠的句柄基址段。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V1-S-9：`win_perms_to_emu_perms`/`get_handle` 上移基类【P2】
- **位置**：`ntoskrnl.py:50-70`、`kernel32.py:137-154`
- **问题**：两个模块中存在重复的权限转换逻辑。
- **建议**：上移到 `ApiHandler` 基类。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

### 模块 11：内核模式 API（winenv/api/kernelmode/）

#### V2-11-3：`wdfldr.parse_usb_config` 在多个 API 中被重复解析【P2】
- **位置**：`wdfldr.py:174-195`；调用点 `:702`/`:722`/`:766`/`:812`
- **建议**：在 `WdfUsbInterface` 上增加 `parsed_interfaces` 缓存字段。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-11-4：`ZwQuerySystemInformation` 循环内反复分配结构体【P2】
- **位置**：`ntoskrnl.py:567-671`
- **建议**：循环外预创建模板结构体复用；消除"两遍循环"。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-11-6：`Wdfldr.set_func_table` 在每次 `WdfVersionBind` 都重新注册所有回调【P2】
- **位置**：`wdfldr.py:83-172`；调用点 `:225`
- **建议**：把 `set_func_table` 调用放进 `if not self.func_table_ptr:` 块内。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-11-7：`ApiHandler.__init__` 与子类 `__get_hook_attrs__(self)` 重复扫描 `dir()`（与 V2-10-1 同源）【P2】
- **位置**：基类 `api.py:51-99`；子类 `ntoskrnl.py:42`、`hal.py:28`、`ndis.py:39`、`fwpkclnt.py:48`、`netio.py:98`、`usbd.py:26`、`wdfldr.py:77`
- **建议**：见 V2-10-1。进阶：把 `funcs`/`data` 的构建做成年级缓存。
- **收益**：低-中 / **复杂度**：中 / **风险**：中

### 模块 12：API 框架·winenv（api.py / winapi.py / arch.py / defs/）

#### V2-12-1：`ApiHandler.__init__` + `__get_hook_attrs__` 双重反思注册（与 V2-10-1/7 同源）【P2】
- **位置**：`api.py:51-99`
- **建议**：用 `__init_subclass__` 或装饰器在类创建期一次性收集 hook 到类属性 `_hooks`。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-12-2：`get_max_int()` 每次调用重算字节【P1 快赢】
- **位置**：`api.py:279-281`
- **建议**：在 `ApiHandler.__init__` 中预计算 `self._max_int = (1 << (self.ptr_size * 8)) - 1`。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-12-4：`read_unicode_string`/`read_ansi_string` 每次构造新 EmuStruct【P2】
- **位置**：`api.py:169-181`
- **建议**：预建 `self._string_tmpl` 和 `self._unicode_tmpl`；或直接 `mem_read` + `struct.unpack` 解析。
- **收益**：中 / **复杂度**：中 / **风险**：低

#### V2-12-5：`WindowsApi.get_export_func_handler` 每次调用 `.lower()`【P1 快赢】
- **位置**：`winapi.py:55-71`
- **建议**：在 `WindowsApi` 上加 `_mod_name_cache: dict[str, str]`；或 `mods` 字典键全部预小写。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-12-6：`do_str_format` 字符级 Python 循环【P2】
- **位置**：`api.py:413-484`
- **建议**：用预编译正则一次性扫描；或先 `string.split("%")` 分段处理。
- **收益**：低-中 / **复杂度**：中 / **风险**：中

#### V2-12-7：`record_*_event` 8 个方法每次都构造 `TracePosition`【P2】
- **位置**：`api.py:223-278` + `_get_current_trace_position` (api.py:214-221)
- **建议**：提取 `_emit_event(kind, *args)` 单一入口；在 `__init__` 中缓存 `self._profiler`。
- **收益**：中 / **复杂度**：低-中 / **风险**：低

#### V1-S-11：`mem_cast` 结构体模板复用【P2】
- **位置**：`api.py:155-157`
- **建议**：缓存结构体模板，避免每次 `mem_cast` 都重新构造。
- **收益**：中 / **复杂度**：中 / **风险**：低

### 模块 13：Profiler·报告（profiler.py / profiler_events.py / report.py）

#### V2-13-4：`TracePosition._asdict()` 在每个事件上重复创建新 dict【P2】
- **位置**：`profiler_events.py:71-76`、`profiler_events.py:120-130`
- **建议**：在 `ApiEvent.to_dict()` 中内联构造 pos dict 避免 `_asdict()` 的额外 dict 拷贝。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-13-5：`record_file_access_event` 用 `reversed(run.events)` 线性扫描合并【P2】
- **位置**：`profiler.py:512-520`
- **建议**：在 `Run` 上增加 `file_events_by_path: dict[tuple[str, str], FileReadEvent | FileWriteEvent]`。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-13-6：`unique_apis` 用 list + `not in` 做去重，O(n²) 累积【P2】
- **位置**：`profiler.py:113`、`profiler.py:467-469`
- **建议**：增加 `unique_apis_set: set[str]` 用于 O(1) 查重。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-13-7：`get_report` 中 `to_dict()` + Pydantic `AnyEvent` union 双重转换【P2】
- **位置**：`profiler.py:891-899`、`profiler_events.py:567-591`
- **建议**：用 `EntryPoint.model_construct(events=events)` 跳过验证；长期方案：将所有事件 dataclass 化，报告生成时直接用 `json.dumps` + 自定义 encoder。
- **收益**：中 / **复杂度**：高 / **风险**：高

#### V1-S-12：NDJSON 流式事件输出【P4】
- **位置**：`profiler.py` 报告生成
- **建议**：每 entry_point 一行 NDJSON 输出，支持流式处理。
- **收益**：低-中 / **复杂度**：中 / **风险**：低

#### V1-S-13：版本号语义注释【P3】
- **位置**：`version.py`、`profiler.py:4`
- **建议**：明确 `__version__` vs `__report_version__` 的语义注释。
- **收益**：低 / **复杂度**：低 / **风险**：低

### 模块 14：结构·工件·伪代码·卷（struct.py / artifacts.py / pseudocode.py / volumes.py）

#### V2-14-3：`get_field_name` / `get_sub_field_name` 仍为 O(n) 线性扫描【P2】
- **位置**：`struct.py:315-335`
- **建议**：在 `create_struct` 首次构建时额外构建 `offset_to_name: dict[int, str]`。
- **收益**：中 / **复杂度**：中 / **风险**：低

#### V2-14-4：`_resolve_operand` 对同一内存地址重复读取 3-4 次【P2】
- **位置**：`pseudocode.py:279-351`
- **建议**：一次性读 `max(read_size, ptr_size)` 字节缓存到局部变量。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-14-5：别名恢复与窗口折叠中正则未预编译【P2】
- **位置**：`pseudocode.py:988-1019`、`1106-1118`、`1683-1691`、`1651-1675`
- **建议**：①模块级 `re.compile` 预编译所有静态 pattern；②`_normalize_window_text` 的 6 条 sub 合并为单次 `re.sub` 传函数 callback；③`_rename_alias_text` 改用一次 `re.sub` 配合字典回查。
- **收益**：中 / **复杂度**：中 / **风险**：低

#### V2-14-6：`create_struct` 缓存命中时仍递归重建 `__filtermap__`【P3】
- **位置**：`struct.py:205-227`
- **建议**：将 `filter_specs` 中每个 `_type(...)` 的构造结果也按 `(类, ptr_size, pack)` 缓存为"原型 EmuStruct 实例"，重建时用 `copy.copy(proto)`。
- **收益**：中 / **复杂度**：高 / **风险**：高

#### V2-14-7：`expand_volume_to_entries` 用 `rglob` + `sorted` + 逐文件 `is_file` 三重开销【P3】
- **位置**：`volumes.py:40-76`
- **建议**：用 `os.walk` + `os.scandir` 替代 `rglob`；移除 `sorted`。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

#### V1-S-16：`PseudocodeRenderer` 状态字典每 run 清理【P2】
- **位置**：`pseudocode.py:29-30`
- **建议**：每个 run 完成后清理状态字典，避免跨 run 状态泄漏。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

### 模块 15：CLI·配置·公共·错误（cli.py / cli_config.py / config.py / common.py / errors.py）

#### V2-15-3：`__init__.py` 重型导入副作用【P2】
- **位置**：`speakeasy/__init__.py:6-12`、`cli.py:15`
- **建议**：将 cli.py:15 的 `from speakeasy import Speakeasy` 改为在 `run_main` 内部延迟导入。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-15-4：`normalize_package_path` 高频调用且每次重定义嵌套函数【P3】
- **位置**：`common.py:38-50`、调用点 `winemu.py:2303`
- **建议**：模块级计算一次 `_SPEAKEASY_ROOT = os.path.dirname(__file__)`。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

#### V2-15-5：`merge_config_dicts` 与 `apply_config_cli_overrides` 串联 deepcopy【P2】
- **位置**：`cli_config.py:62-70`、`cli_config.py:136-151`
- **建议**：`apply_config_cli_overrides` 改为就地修改；或把合并为单次遍历只 deepcopy 一次。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-15-6：`setup_logging` 重复构造 Console/RichHandler【P3】
- **位置**：`cli.py:29-33`
- **建议**：用模块级单例 Console；`setup_logging` 增加幂等保护。
- **收益**：低 / **复杂度**：低 / **风险**：低

### 模块 16：测试·构建（tests/ + pyproject.toml）

#### V2-16-1：pytest-xdist 已安装但完全未启用，302 个测试串行执行【P1 快赢】
- **位置**：`pyproject.toml:38`、`pyproject.toml:83`
- **建议**：在 `addopts` 中加入 `-n auto`；需在 Windows + unicorn 下验证多进程稳定性。
- **收益**：高 / **复杂度**：低 / **风险**：中

#### V2-16-2：测试标记已定义但零使用，无法快速筛选慢测试【P1 快赢】
- **位置**：`pyproject.toml:77-82`
- **建议**：①在 `test_pma_samples.py` 顶部加 `pytestmark = pytest.mark.pma`；②在 `test_examples.py` 加 `pytestmark = pytest.mark.examples`；③对超时风险高的仿真测试加 `@pytest.mark.slow`。
- **收益**：高 / **复杂度**：低 / **风险**：低

#### V2-16-3：基线生成与校验脚本重复约 110 行代码且重复解压相同样本【P2】
- **位置**：`tests/baseline/_generate_baseline.py:22-115` 与 `tests/baseline/_verify_current.py:30-125`
- **建议**：抽取 `tests/baseline/_baseline_core.py` 共享模块。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-16-4：`_perf_compare.py` 全部基准代码在模块顶层执行且硬编码绝对路径【P3】
- **位置**：`tests/baseline/_perf_compare.py:8-149`
- **建议**：将全部代码包进 `def main(): ...`；`BASELINE_FILE` 改为 `Path(__file__).resolve().parent / "performance_baseline.json"`。
- **收益**：中 / **复杂度**：低 / **风险**：低

#### V2-16-5：PMA 同一样本的多个 case 变体重复从磁盘读取【P3】
- **位置**：`tests/pma_harness.py:80-102`
- **建议**：在 `pma_harness.py` 增加 `@cache` 装饰的 `read_sample_bytes`。
- **收益**：低-中 / **复杂度**：低 / **风险**：低

#### V2-16-6：只读断言类测试仍用 function 级 fixture，未复用 module 级共享模式【P2】
- **位置**：`tests/test_p0_bugfix_d.py:26-34`
- **建议**：对纯只读断言测试组，将加载型 fixture 提升为 `scope="module"`。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V2-16-7：基线生成/校验脚本串行跑 6 个完整仿真样本【P3】
- **位置**：`tests/baseline/_generate_baseline.py:123`、`_verify_current.py:191`
- **建议**：用 `concurrent.futures.ProcessPoolExecutor` 并行 6 个样本。
- **收益**：中 / **复杂度**：中 / **风险**：中

#### V1-S-17：capa-testfiles 缺失测试统一 `skipif` 守卫【P3】
- **位置**：`test_examples.py`、`test_kernel_bootstrap.py`、`test_map_view_of_file.py`
- **建议**：统一 skipif 守卫，避免缺失文件时测试失败。
- **收益**：低 / **复杂度**：低 / **风险**：低

#### V1-S-18：`get_api_calls` 辅助函数提取到 `tests/helpers.py`【P3】
- **位置**：`test_dlls.py:6` 等 4 处重复
- **建议**：提取到共享 helpers 模块。
- **收益**：低 / **复杂度**：低 / **风险**：低

#### V1-S-19：添加 CI 配置（GitHub Actions / 等）【P3】
- **建议**：分层运行 unit / slow / examples。
- **收益**：中 / **复杂度**：中 / **风险**：低

#### V1-S-20：统一 `target-version`/`python_version`/`requires-python` 为 py312【P3】
- **位置**：`pyproject.toml:15`、`#L73`、`#L80`
- **建议**：统一工具链版本。
- **收益**：低 / **复杂度**：低 / **风险**：低

#### V1-S-21：README 补充 `ml_engine/` 目录、测试运行说明【P3】
- **位置**：`README.md`
- **建议**：补充 `SPEAKEASY_PMA_FULL` 环境变量说明。
- **收益**：低 / **复杂度**：低 / **风险**：低

#### V1-S-22：文档 `command_line` 默认值与 test.json 对齐【P3】
- **位置**：`doc/configuration.md:89`
- **建议**：对齐或明确标注差异。
- **收益**：低 / **复杂度**：低 / **风险**：低

#### V1-S-23：`_reset_handle_counters` autouse 收窄或下沉到 `run_test`【P3】
- **位置**：`conftest.py:34-40`
- **建议**：收窄 autouse 范围，减少不必要的 fixture 执行。
- **收益**：低 / **复杂度**：低 / **风险**：低

---

## 五、实施路线图

### 阶段 2：必修正确性 bug + 立即快赢（1-2 周）

**P0 必修（必须先修复，否则后续优化建立在不稳定基础上）**：

| 编号 | 优化点 | 收益 | 复杂度 | 风险 |
|------|--------|------|--------|------|
| V2-9-7（部分） | `hammer.py` AMD64 分支空实现（bug） | 中 | 低 | 低 |

**立即快赢（低风险、低复杂度、高收益）**：

| 编号 | 优化点 | 收益 | 复杂度 | 风险 |
|------|--------|------|--------|------|
| V2-16-1 | 启用 pytest-xdist `-n auto` | 高 | 低 | 中 |
| V2-16-2 | 应用测试标记（pma/examples/slow/unit） | 高 | 低 | 低 |
| V2-12-2 | `get_max_int()` 预计算常量 | 中 | 低 | 低 |
| V2-12-5 | `WindowsApi` `_mod_name_cache` 缓存 | 中 | 低 | 低 |

### 阶段 3：热路径核心优化（P1，2-4 周）

**P1 优先级（高收益、中复杂度）**：

| 编号 | 优化点 | 收益 | 复杂度 | 风险 |
|------|--------|------|--------|------|
| V2-3-1 | `reg_read`/`reg_write` 批量化 | 高 | 中 | 中 |
| V2-3-5 | 封装 `uc_context_save`/`restore` | 中-高 | 中 | 中 |
| V2-5-2 | `remove_object` 直接 pop | 中 | 低 | 低 |
| V2-1-8 | 批量样本多进程并行（高复杂度高收益，可延后） | 高 | 高 | 高 |

### 阶段 4：补强与重构（P2，4-8 周）

**P2 优先级（中等收益，部分需配合 P1）**：

涵盖 V2-1-3/5/6/7、V2-2-2/3/4/7、V2-3-3/4/6、V2-4-4/5/6/7/8、V2-5-5/6/7、V2-6-4/5/6/7、V2-7-2/3/4/6、V2-8-1/2/3、V2-9-2/4/5/6/8、V2-10-1/3/4/6/7、V2-11-3/4/6/7、V2-12-1/4/6/7、V2-13-4/5/6/7、V2-14-3/4/5、V2-15-3/5、V2-16-3/6，以及 V1 遗留 V1-S-1/2/6/8/9/11/16 等。

### 阶段 5：微优化与测试基础设施（P3，按需）

**P3 优先级（低收益或局部优化）**：

涵盖 V2-1-4、V2-2-5/6/8、V2-8-3、V2-9-5/6、V2-10-5、V2-14-6/7、V2-15-4/6、V2-16-4/5/7，以及 V1 遗留 V1-S-13/17/18/19/20/21/22/23 等。

### 阶段 6：进阶能力（P4，可选）

- V1-S-3：跨进程配置缓存（收益有限，低优先）
- V1-S-12：NDJSON 流式事件输出（每 entry_point 一行）

---

## 六、风险控制与验证策略

### 6.1 兼容性边界

- **结构缓存一致性**：后续 V2-14-3/14-6 的进一步优化需继续使用包含模块限定名与指针宽度的缓存键，避免跨模块同名结构体冲突。
- **对象索引一致性**：后续 V2-5-5/6/7 的句柄路径优化需同步维护 `objman._handle_map` 与对象句柄集合。
- **报告序列化一致性**：V2-13-7 长期方案若绕过 Pydantic，需确保 `profiler.get_report` 与 `report.py` 输出 schema 不变。

### 6.2 回归测试基线

- **既有基线**：`tests/baseline/` 已有 6 个样本的 schema/counts/timing 基线，可作为行为等价性验证依据。
- **建议补充**：
  - 为每个 V2 优化点配套差分测试（改动前后对比 `counts_*.json` 除已知顺序字段外字节级一致）。
  - 对保留的 P1/P2/P3 项补充针对性单元测试覆盖原问题触发路径。
  - 引入性能基线对比（`tests/baseline/_perf_compare.py` 改造后）量化每项优化收益。

### 6.3 缓存一致性验证

对引入缓存的保留优化项（如 V2-2-3、V2-5-5/6/7、V2-7-4、V2-9-4、V2-12-5、V2-13-4/5/6/7、V2-15-3/5 等），必须：

1. 枚举所有缓存失效点（见主题 J 表格）；
2. 编写脏数据测试：在缓存命中后修改底层状态，验证缓存被正确失效；
3. 对绕过路径（如 `winemu` 直接调用 `emu_eng.mem_map` 绕过 `memmgr`）做显式失效调用或测试覆盖。

### 6.4 性能量化方法

- **微基准**：对每个优化点用 `timeit` 或 `pyperf` 测量单次调用开销变化。
- **样本基准**：在 6 个基线样本 + SchoolBoy 样本（项目记忆中已分析）上对比改动前后总耗时、内存峰值、事件数量。
- **tracing 模式专项**：开启 `--log-instructions` 对比 V2-3-1/5 接入前后的异常处理与上下文切换耗时。
- **长样本专项**：对触发 `EnumResourceTypesW` 中断的 SchoolBoy 样本，对比剩余 P2/P3 项实施前后的内存增长曲线。

### 6.5 依赖与版本兼容

- **Unicorn 版本**：V2-3-1/5 依赖 unicorn 提供 `reg_read_batch`/`uc_context_save`；建议先用 `python -c "import unicorn; print(unicorn.__version__)"` 确认版本后再定方案。
- **Pydantic 版本**：V2-13-7 长期方案绕过 Pydantic 需评估 v2 的 `model_construct` 行为。
- **Python 版本**：V1-S-20 需统一 `target-version` / `python_version` / `requires-python` 为 py312。

### 6.6 不建议改动的部分

- **页表翻译**：完全委托 Unicorn，Python 层不参与，设计合理，无需改动。
- **`Hook` 回调包装器的 try/except**：happy path 开销近零，仅建议收窄异常类型以提升可维护性。
- **`load_test_bin` 夹具**：session + `@cache` 双保险，设计优秀，保持原状。
- **PMA 测试声明式架构**（`pma_cases.py` + `pma_harness.py` + `pma_profiles.py`）：关注点分离清晰，保持原状。
- **`argparse.SUPPRESS` + `hasattr` 覆盖逻辑**：清晰无冗余，保持原状。
- **内存 read/write hook 仅在 `memory_tracing` 开启时安装**：避免每内存访问跨入 Python 的灾难性开销。
- **`get_symbol_from_address` 已用 dict O(1) 查找**。
- **API 分发主路径 `mods.get` + `funcs.get` 双字典 O(1)**。
- **`load_api_handler` 按需实例化 handler**。
- **`IoManager` 本身懒加载**。

### 6.7 性能验证清单

实施后建议用以下场景验证收益：

| 场景 | 关键指标 | 预期优化项 |
|------|---------|-----------|
| 伪代码模式跑长样本 | 每指令耗时、内存峰值 | V2-14-3/4/5/6/7 |
| 字符串密集样本（注册表/文件路径） | API 调用吞吐 | V2-7-2/3/4、V2-10-3 |
| 大导入表 PE（ntoskrnl decoy） | 加载时间 | V2-4-8、V2-9-8 |
| 多 run 用户态仿真 | run-dispatch 时间 | V2-1-8、V2-4-4/5/6/7 |
| 高频句柄操作样本 | ReadFile/CloseHandle 吞吐 | V2-5-2/5/6/7 |
| 长时运行样本 | 内存增长曲线 | V2-13-4/5/6/7、V1-S-12 |
| 批量样本分析 | 启动时间、吞吐 | V2-1-8、V2-15-3/5 |
| `speakeasy --help` | 启动延迟 | V2-15-3 |
| 测试套件全量 | 总耗时 | V2-16-1/2 |
| SEH 密集样本 | 异常处理吞吐 | V2-3-1/5 |

---

## 七、附录

### A. 当前保留项数量统计

| 优先级 | 项数 | 说明 |
|--------|------|------|
| P1 / P1 快赢 | 8 | V2-1-8、V2-3-1、V2-3-5、V2-5-2、V2-12-2、V2-12-5、V2-16-1、V2-16-2 |
| P2 | 50 | 中等收益、数据结构治理、反模式清理 |
| P3 | 28 | 微优化、测试基础设施、文档同步 |
| P4 | 2 | 进阶能力 |

### B. 关键文件路径索引

| 模块 | 主分析文件 |
|------|----------|
| 1 | `speakeasy\binemu.py`、`speakeasy\speakeasy.py` |
| 2 | `speakeasy\memmgr.py` |
| 3 | `speakeasy\engines\unicorn_eng.py` |
| 4 | `speakeasy\windows\winemu.py` |
| 5 | `speakeasy\windows\objman.py` |
| 6 | `speakeasy\windows\fileman.py`、`ioman.py`、`driveman.py` |
| 7 | `speakeasy\windows\regman.py`、`netman.py`、`cryptman.py`、`sessman.py` |
| 8 | `speakeasy\windows\kernel.py`、`kernel_mods\` |
| 9 | `speakeasy\windows\win32.py`、`com.py`、`common.py`、`loaders.py`、`hammer.py` |
| 10 | `speakeasy\winenv\api\usermode\`（kernel32.py 等 12 个高频模块） |
| 11 | `speakeasy\winenv\api\kernelmode\`（ntoskrnl.py 等 8 个模块） |
| 12 | `speakeasy\winenv\api\api.py`、`winapi.py`、`arch.py`、`defs\` |
| 13 | `speakeasy\profiler.py`、`profiler_events.py`、`report.py` |
| 14 | `speakeasy\struct.py`、`artifacts.py`、`pseudocode.py`、`volumes.py` |
| 15 | `speakeasy\cli.py`、`cli_config.py`、`config.py`、`common.py`、`errors.py` |
| 16 | `tests\`、`pyproject.toml` |

---

**文档结束**。建议按"阶段 2 → 阶段 3 → 阶段 4 → 阶段 5 → 阶段 6"顺序推进（阶段 1 已完成），每个阶段完成后跑一次完整基线对比（`tests/baseline/`）验证行为等价性，并量化性能收益。
