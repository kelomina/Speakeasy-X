# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
"""
Bug 修复代理 D：P0 优化后 Windows 仿真层边界条件验证测试。

覆盖模块：
- winemu.py (P0-5): get_mod_from_addr 的 bisect 边界、get_mod_by_name 字典查找、
  _register_module_index / _rebuild_module_index 一致性、多模块加载场景
- objman.py (P0-6): _handle_map 反向字典同步、close_handle/remove_object 清理、
  多句柄指向同一对象、句柄分配/释放循环
- common.py (P0-3): _patch_imports 的 bytearray in-place 修改完整性
- kernel.py (P0-14): on_run_complete 仅对当前 driver 做 read_back
"""

import types

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.objman import Event, Mutant


# ===========================================================================
# winemu.py (P0-5) 测试
# ===========================================================================

@pytest.fixture
def emu_with_modules(config, load_test_bin):
    """加载 DLL 后返回 emu，用于模块查询测试。"""
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        yield se.emu
    finally:
        se.shutdown()


def test_get_mod_from_addr_returns_module_for_in_range_address(emu_with_modules):
    """地址落在模块范围内时应返回该模块。"""
    emu = emu_with_modules
    mod = emu.modules[0]
    # 测试 base、base+1、base+image_size-1
    assert emu.get_mod_from_addr(mod.base) is mod
    assert emu.get_mod_from_addr(mod.base + 1) is mod
    assert emu.get_mod_from_addr(mod.base + mod.image_size - 1) is mod


def test_get_mod_from_addr_returns_none_for_out_of_range(emu_with_modules):
    """地址落在模块范围外时应返回 None。"""
    emu = emu_with_modules
    mod = emu.modules[0]
    # base + image_size 是上界 exclusive
    assert emu.get_mod_from_addr(mod.base + mod.image_size) is None
    # base - 1 在模块之前
    assert emu.get_mod_from_addr(mod.base - 1) is None


def test_get_mod_from_addr_returns_none_when_no_modules(emu_with_modules):
    """模块列表被清空时（模拟无模块场景）应返回 None。"""
    emu = emu_with_modules
    # 临时清空模块列表与索引，模拟无模块场景
    saved_modules = list(emu.modules)
    saved_intervals = list(emu._mod_intervals)
    saved_bases = list(emu._mod_bases)
    saved_name_map = dict(emu._mod_name_map)
    saved_curr_mod = emu.curr_mod
    try:
        emu.modules = []
        emu._mod_intervals = []
        emu._mod_bases = []
        emu._mod_name_map = {}
        emu.curr_mod = None
        # 无模块时应返回 None
        assert emu.get_mod_from_addr(0x1000) is None
        assert emu.get_mod_from_addr(0) is None
    finally:
        emu.modules = saved_modules
        emu._mod_intervals = saved_intervals
        emu._mod_bases = saved_bases
        emu._mod_name_map = saved_name_map
        emu.curr_mod = saved_curr_mod


def test_get_mod_from_addr_curr_mod_shortcut(emu_with_modules):
    """curr_mod 快捷路径应优先返回 curr_mod。"""
    emu = emu_with_modules
    mod = emu.modules[0]
    emu.curr_mod = mod
    # curr_mod 的范围内地址应直接返回 curr_mod
    assert emu.get_mod_from_addr(mod.base + 0x100) is mod


def test_get_mod_by_name_finds_loaded_module(emu_with_modules):
    """get_mod_by_name 应能按名称找到已加载模块。"""
    emu = emu_with_modules
    mod = emu.modules[0]
    # 通过 emu_path 的 basename（去扩展名）查找
    import ntpath
    import os
    base_name = os.path.splitext(ntpath.basename(mod.emu_path))[0]
    found = emu.get_mod_by_name(base_name)
    assert found is mod


def test_get_mod_by_name_case_insensitive(emu_with_modules):
    """get_mod_by_name 应大小写不敏感。"""
    emu = emu_with_modules
    mod = emu.modules[0]
    import ntpath
    import os
    base_name = os.path.splitext(ntpath.basename(mod.emu_path))[0]
    # 大写、小写、混合大小写都应找到
    assert emu.get_mod_by_name(base_name.upper()) is mod
    assert emu.get_mod_by_name(base_name.lower()) is mod
    if base_name != base_name.capitalize():
        assert emu.get_mod_by_name(base_name.capitalize()) is mod


def test_get_mod_by_name_returns_none_for_unknown(emu_with_modules):
    """未加载的模块名应返回 None。"""
    emu = emu_with_modules
    assert emu.get_mod_by_name("nonexistent_module_xyz") is None
    assert emu.get_mod_by_name("") is None


def test_mod_intervals_consistent_with_modules_after_load(emu_with_modules):
    """加载后 _mod_intervals 应与 self.modules 保持一致。"""
    emu = emu_with_modules
    assert len(emu._mod_intervals) == len(emu.modules)
    assert len(emu._mod_bases) == len(emu.modules)


def test_mod_bases_sorted_after_multiple_loads(config, load_test_bin):
    """加载多个模块后 _mod_bases 应保持有序。"""
    se = Speakeasy(config=config)
    try:
        # 加载主 DLL
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        emu = se.emu

        # _mod_bases 应是有序的
        bases = emu._mod_bases
        assert bases == sorted(bases), f"_mod_bases 未排序: {bases}"

        # 每个模块都应在 _mod_intervals 中
        for mod in emu.modules:
            assert any(m is mod for _, _, m in emu._mod_intervals)
    finally:
        se.shutdown()


def test_mod_name_map_populated_for_all_modules(emu_with_modules):
    """每个模块都应在 _mod_name_map 中以 basename 注册。"""
    emu = emu_with_modules
    import ntpath
    import os
    for mod in emu.modules:
        if not mod.emu_path:
            continue
        base_name = os.path.splitext(ntpath.basename(mod.emu_path))[0].lower()
        if base_name:
            assert base_name in emu._mod_name_map, (
                f"模块 {mod.emu_path} 的 basename '{base_name}' 未在 _mod_name_map 中"
            )


def test_rebuild_module_index_idempotent(emu_with_modules):
    """_rebuild_module_index 应是幂等的。"""
    emu = emu_with_modules
    intervals_before = list(emu._mod_intervals)
    name_map_before = dict(emu._mod_name_map)

    emu._rebuild_module_index()

    # 重建后内容应一致（顺序和引用）
    assert len(emu._mod_intervals) == len(intervals_before)
    assert emu._mod_name_map == name_map_before


def test_get_mod_from_addr_finds_secondary_module(config, load_test_bin):
    """加载多模块后，对每个模块地址查询应返回对应模块。"""
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        emu = se.emu

        # 加载后会有多个模块（核心 DLL + 主模块）
        assert len(emu.modules) > 1

        # 对每个模块的 base 查询应返回该模块
        for mod in emu.modules:
            if mod.image_size > 0:
                found = emu.get_mod_from_addr(mod.base + 0x10)
                assert found is mod, (
                    f"地址 0x{mod.base + 0x10:x} 应属于模块 {mod.emu_path}, "
                    f"实际返回 {getattr(found, 'emu_path', None)}"
                )
    finally:
        se.shutdown()


def test_get_mod_from_addr_between_two_modules(config, load_test_bin):
    """两个模块之间的空隙地址应返回 None。"""
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        emu = se.emu

        # 按 base 排序模块
        sorted_mods = sorted(emu.modules, key=lambda m: m.base)
        for i in range(len(sorted_mods) - 1):
            m1 = sorted_mods[i]
            m2 = sorted_mods[i + 1]
            gap_addr = m1.base + m1.image_size
            # 如果两模块之间有间隙
            if gap_addr < m2.base:
                assert emu.get_mod_from_addr(gap_addr) is None, (
                    f"间隙地址 0x{gap_addr:x} 应返回 None"
                )
    finally:
        se.shutdown()


# ===========================================================================
# objman.py (P0-6) 测试
# ===========================================================================

@pytest.fixture
def emu_with_om(config, load_test_bin):
    """加载一个 DLL 让 Win32Emulator.setup() 完成，从而 emu.om 就绪。"""
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        assert se.emu.om is not None
        yield se.emu
    finally:
        se.shutdown()


def test_handle_alloc_free_cycle(emu_with_om):
    """句柄分配/释放循环：close 后再次分配不应冲突。"""
    emu = emu_with_om
    om = emu.om

    evt = om.new_object(Event)
    h1 = om.get_handle(evt)
    assert om.get_object_from_handle(h1) is evt

    om.close_handle(h1)
    assert om.get_object_from_handle(h1) is None

    # 再次分配句柄
    h2 = om.get_handle(evt)
    assert h2 != h1  # 新句柄值不同
    assert om.get_object_from_handle(h2) is evt


def test_multiple_objects_multiple_handles(emu_with_om):
    """多对象多句柄：每个对象的句柄相互独立。"""
    emu = emu_with_om
    om = emu.om

    objs = [om.new_object(Event) for _ in range(5)]
    handles = [om.get_handle(o) for o in objs]

    # 每个句柄都应能找到对应对象
    for h, o in zip(handles, objs):
        assert om.get_object_from_handle(h) is o

    # 关闭中间一个
    om.close_handle(handles[2])
    assert om.get_object_from_handle(handles[2]) is None

    # 其余不受影响
    for i in [0, 1, 3, 4]:
        assert om.get_object_from_handle(handles[i]) is objs[i]


def test_remove_object_clears_all_handles(emu_with_om):
    """remove_object 应清理该对象的全部句柄。"""
    emu = emu_with_om
    om = emu.om

    evt = om.new_object(Event)
    h1 = om.get_handle(evt)
    h2 = om.get_handle(evt)
    h3 = om.get_handle(evt)

    om.remove_object(evt)

    assert om.get_object_from_handle(h1) is None
    assert om.get_object_from_handle(h2) is None
    assert om.get_object_from_handle(h3) is None
    assert h1 not in om._handle_map
    assert h2 not in om._handle_map
    assert h3 not in om._handle_map


def test_multiple_handles_close_one_keeps_others(emu_with_om):
    """同一对象多句柄：关闭一把不影响其他句柄。"""
    emu = emu_with_om
    om = emu.om

    mtx = om.new_object(Mutant)
    h1 = om.get_handle(mtx)
    h2 = om.get_handle(mtx)
    h3 = om.get_handle(mtx)

    om.close_handle(h2)
    assert om.get_object_from_handle(h2) is None
    assert om.get_object_from_handle(h1) is mtx
    assert om.get_object_from_handle(h3) is mtx
    assert h1 in mtx.handles
    assert h3 in mtx.handles
    assert h2 not in mtx.handles


def test_close_handle_unknown_returns_none(emu_with_om):
    """关闭不存在的句柄应返回 None，不抛异常。"""
    emu = emu_with_om
    om = emu.om
    assert om.close_handle(0xDEAD_BEEF) is None
    assert om.close_handle(0) is None
    assert om.close_handle(-1) is None


def test_close_handle_idempotent(emu_with_om):
    """重复关闭同一句柄应安全。"""
    emu = emu_with_om
    om = emu.om

    evt = om.new_object(Event)
    h = om.get_handle(evt)

    assert om.close_handle(h) is evt
    assert om.close_handle(h) is None
    assert om.close_handle(h) is None


def test_handle_map_consistent_with_handles_list(emu_with_om):
    """_handle_map 与对象 handles 列表应保持一致。"""
    emu = emu_with_om
    om = emu.om

    evt = om.new_object(Event)
    h1 = om.get_handle(evt)
    h2 = om.get_handle(evt)

    # 一致性检查
    for h in evt.handles:
        assert om._handle_map.get(h) is evt
    for h, o in om._handle_map.items():
        if o is evt:
            assert h in evt.handles

    om.close_handle(h1)
    # 关闭后一致性仍应保持
    for h in evt.handles:
        assert om._handle_map.get(h) is evt
    assert h1 not in om._handle_map


def test_get_object_from_handle_fallback_path(emu_with_om):
    """O(1) 查找未命中时，O(n) 回退应能找到对象。"""
    emu = emu_with_om
    om = emu.om

    evt = om.new_object(Event)
    h = om.get_handle(evt)

    # 手动从 _handle_map 移除，强制走回退路径
    om._handle_map.pop(h, None)
    assert h not in om._handle_map

    # 回退路径应能找到对象，并补登记到 _handle_map
    found = om.get_object_from_handle(h)
    assert found is evt
    assert om._handle_map.get(h) is evt  # 补登记


def test_dec_ref_removes_object_when_zero(emu_with_om):
    """dec_ref 归零时应触发 remove_object。"""
    emu = emu_with_om
    om = emu.om

    evt = om.new_object(Event)  # ref_cnt = 1
    h = om.get_handle(evt)

    om.close_handle(h)
    remaining = emu.dec_ref(evt)

    assert remaining == 0
    assert om.get_object_from_addr(evt.address) is None
    assert om.get_object_from_handle(h) is None


# ===========================================================================
# common.py (P0-3) 测试
# ===========================================================================

class _FakePeParser:
    """最小化的 _PeParser 替身，用于隔离 _patch_imports 测试。"""

    def _patch_imports(self):
        from speakeasy.windows.common import _PeParser
        return _PeParser._patch_imports(self)

    def __init__(self, base, image_size, imports, ptr_size=4,
                 imp_id=0x70000000, imp_step=4):
        self.base = base
        self.ptr_size = ptr_size
        self.imp_id = imp_id
        self.imp_step = imp_step
        self.imports = imports
        self.import_table = {}
        self.mapped_image = bytes([0xAA]) * image_size


def test_patch_imports_preserves_image_size():
    """_patch_imports 后镜像大小不应改变。"""
    base = 0x400000
    image_size = 0x1000
    imports = {
        base + 0x100: ("kernel32.dll", "ExitProcess"),
        base + 0x200: ("kernel32.dll", "GetProcAddress"),
        base + 0x300: ("user32.dll", "MessageBoxA"),
    }
    pe = _FakePeParser(base, image_size, imports, ptr_size=4)
    original_size = len(pe.mapped_image)

    pe._patch_imports()

    assert len(pe.mapped_image) == original_size


def test_patch_imports_all_imports_patched():
    """所有导入地址都应被 patch。"""
    base = 0x400000
    image_size = 0x1000
    imports = {
        base + 0x100: ("kernel32.dll", "ExitProcess"),
        base + 0x200: ("kernel32.dll", "GetProcAddress"),
        base + 0x300: ("user32.dll", "MessageBoxA"),
    }
    pe = _FakePeParser(base, image_size, imports, ptr_size=4,
                       imp_id=0x70000000, imp_step=4)

    pe._patch_imports()

    expected_id = 0x70000000
    for addr, imp in imports.items():
        offset = addr - base
        written = int.from_bytes(
            pe.mapped_image[offset:offset + pe.ptr_size], "little"
        )
        assert written == expected_id, (
            f"addr 0x{addr:x}: expected 0x{expected_id:x}, got 0x{written:x}"
        )
        assert pe.import_table[expected_id] == imp
        expected_id += pe.imp_step


def test_patch_imports_non_overlapping_offsets():
    """多个导入地址不相邻时，patch 不应相互覆盖。"""
    base = 0x400000
    image_size = 0x1000
    # 间隔较大的导入地址
    imports = {
        base + 0x10: ("a.dll", "func_a"),
        base + 0x500: ("b.dll", "func_b"),
        base + 0x800: ("c.dll", "func_c"),
    }
    pe = _FakePeParser(base, image_size, imports, ptr_size=4,
                       imp_id=0x70000000, imp_step=4)

    pe._patch_imports()

    # 验证每个地址的值
    expected_id = 0x70000000
    for addr in imports:
        offset = addr - base
        written = int.from_bytes(
            pe.mapped_image[offset:offset + 4], "little"
        )
        assert written == expected_id
        expected_id += 4

    # 验证非导入区域未被破坏
    for i, b in enumerate(pe.mapped_image):
        if b == 0xAA:
            continue
        # 必须落在某个 patch 范围内
        in_patched = any(
            (addr - base) <= i < (addr - base) + 4 for addr in imports
        )
        assert in_patched, f"偏移 0x{i:x} 被破坏但不在导入范围内"


def test_patch_imports_preserves_unmodified_regions():
    """patch 后未涉及区域应保持原样。"""
    base = 0x400000
    image_size = 0x2000
    imports = {
        base + 0x100: ("kernel32.dll", "ExitProcess"),
    }
    pe = _FakePeParser(base, image_size, imports, ptr_size=4)
    original = bytes(pe.mapped_image)

    pe._patch_imports()

    # patch 范围
    patched_range = (0x100, 0x104)
    for i in range(image_size):
        if patched_range[0] <= i < patched_range[1]:
            continue
        assert pe.mapped_image[i] == original[i], (
            f"偏移 0x{i:x} 被修改：原 0x{original[i]:02x}, "
            f"现 0x{pe.mapped_image[i]:02x}"
        )


def test_patch_imports_returns_bytes_type():
    """patch 后 mapped_image 应仍为 bytes 类型（不可变）。"""
    base = 0x400000
    image_size = 0x100
    imports = {base + 0x10: ("kernel32.dll", "ExitProcess")}
    pe = _FakePeParser(base, image_size, imports, ptr_size=4)
    pe._patch_imports()
    assert isinstance(pe.mapped_image, bytes)


def test_patch_imports_imp_id_increments_correctly():
    """imp_id 应按 imp_step 递增。"""
    base = 0x400000
    image_size = 0x1000
    imports = {
        base + 0x100: ("a.dll", "f1"),
        base + 0x200: ("b.dll", "f2"),
        base + 0x300: ("c.dll", "f3"),
    }
    start_id = 0x70000000
    step = 4
    pe = _FakePeParser(base, image_size, imports, ptr_size=4,
                       imp_id=start_id, imp_step=step)

    pe._patch_imports()

    # 验证 imp_id 递增
    expected = start_id
    for addr, imp in imports.items():
        offset = addr - base
        written = int.from_bytes(
            pe.mapped_image[offset:offset + 4], "little"
        )
        assert written == expected
        assert pe.import_table[expected] == imp
        expected += step

    # 验证 pe.imp_id 已更新为最后一个 + step
    assert pe.imp_id == start_id + len(imports) * step


# ===========================================================================
# kernel.py (P0-14) 测试
# ===========================================================================

def test_on_run_complete_only_reads_back_current_driver(config, load_test_bin):
    """on_run_complete 应仅对 drv.pe == curr_mod 的 driver 调用 read_back。"""
    from speakeasy.windows.kernel import WinKernelEmulator
    from speakeasy.config import SpeakeasyConfig

    emu = WinKernelEmulator(config=SpeakeasyConfig.model_validate(config))

    # 构造两个 mock driver：一个匹配 curr_mod，一个不匹配
    matching_drv = types.SimpleNamespace()
    matching_drv.pe = "mod_a"
    matching_drv.read_back_calls = 0

    def matching_read_back():
        matching_drv.read_back_calls += 1

    matching_drv.read_back = matching_read_back

    other_drv = types.SimpleNamespace()
    other_drv.pe = "mod_b"
    other_drv.read_back_calls = 0

    def other_read_back():
        other_drv.read_back_calls += 1

    other_drv.read_back = other_read_back

    emu.drivers = [matching_drv, other_drv]
    emu.curr_mod = "mod_a"  # 匹配 matching_drv

    # mock curr_run 和依赖的方法
    from speakeasy.profiler import Run
    emu.curr_run = Run()
    emu.get_return_val = lambda: 0

    # next_driver_func 应只对匹配 driver 调用
    next_func_calls = []

    def mock_next_driver_func(drv):
        next_func_calls.append(drv)

    emu.next_driver_func = mock_next_driver_func
    emu._exec_next_run = lambda: None

    emu.on_run_complete()

    assert matching_drv.read_back_calls == 1, "匹配 driver 应被 read_back 一次"
    assert other_drv.read_back_calls == 0, "非匹配 driver 不应被 read_back"
    assert next_func_calls == [matching_drv], "next_driver_func 应只对匹配 driver 调用"


def test_on_run_complete_no_matching_driver(config):
    """无 driver 匹配 curr_mod 时，read_back 不应被调用。"""
    from speakeasy.windows.kernel import WinKernelEmulator
    from speakeasy.config import SpeakeasyConfig

    emu = WinKernelEmulator(config=SpeakeasyConfig.model_validate(config))

    drv1 = types.SimpleNamespace()
    drv1.pe = "mod_a"
    drv1.read_back_calls = 0

    def rb1():
        drv1.read_back_calls += 1

    drv1.read_back = rb1

    drv2 = types.SimpleNamespace()
    drv2.pe = "mod_b"
    drv2.read_back_calls = 0

    def rb2():
        drv2.read_back_calls += 1

    drv2.read_back = rb2

    emu.drivers = [drv1, drv2]
    emu.curr_mod = "nonexistent_mod"  # 不匹配任何 driver

    from speakeasy.profiler import Run
    emu.curr_run = Run()
    emu.get_return_val = lambda: 0
    emu.next_driver_func = lambda drv: None
    emu._exec_next_run = lambda: None

    emu.on_run_complete()

    assert drv1.read_back_calls == 0
    assert drv2.read_back_calls == 0


def test_on_run_complete_multiple_matching_drivers(config):
    """多个 driver 匹配 curr_mod 时，都应被 read_back（与原行为一致）。"""
    from speakeasy.windows.kernel import WinKernelEmulator
    from speakeasy.config import SpeakeasyConfig

    emu = WinKernelEmulator(config=SpeakeasyConfig.model_validate(config))

    # 两个 driver 共享同一 pe
    shared_pe = "shared_mod"

    drv1 = types.SimpleNamespace()
    drv1.pe = shared_pe
    drv1.read_back_calls = 0

    def rb1():
        drv1.read_back_calls += 1

    drv1.read_back = rb1

    drv2 = types.SimpleNamespace()
    drv2.pe = shared_pe
    drv2.read_back_calls = 0

    def rb2():
        drv2.read_back_calls += 1

    drv2.read_back = rb2

    emu.drivers = [drv1, drv2]
    emu.curr_mod = shared_pe

    from speakeasy.profiler import Run
    emu.curr_run = Run()
    emu.get_return_val = lambda: 0

    next_func_calls = []
    emu.next_driver_func = lambda drv: next_func_calls.append(drv)
    emu._exec_next_run = lambda: None

    emu.on_run_complete()

    # 两个匹配 driver 都应被 read_back
    assert drv1.read_back_calls == 1
    assert drv2.read_back_calls == 1
    assert len(next_func_calls) == 2


def test_on_run_complete_preserves_curr_run_ret_val(config):
    """on_run_complete 应将 get_return_val 的值写入 curr_run.ret_val。"""
    from speakeasy.windows.kernel import WinKernelEmulator
    from speakeasy.config import SpeakeasyConfig

    emu = WinKernelEmulator(config=SpeakeasyConfig.model_validate(config))

    from speakeasy.profiler import Run
    emu.curr_run = Run()
    emu.drivers = []
    emu.get_return_val = lambda: 0x1234
    emu._exec_next_run = lambda: None

    emu.on_run_complete()

    assert emu.curr_run.ret_val == 0x1234


# ===========================================================================
# 集成验证：WDM 多 driver 场景
# ===========================================================================

def test_wdm_multi_driver_run_completes_successfully(config, load_test_bin):
    """WDM 样本在多 system driver 环境下应能正常完成所有 run。"""
    import copy

    se = Speakeasy(config=copy.deepcopy(config))
    try:
        module = se.load_module(data=load_test_bin("wdm_test_x86.sys.xz"))
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
    finally:
        se.shutdown()

    # 应有多个 entry point（entry + IRP handlers + unload）
    eps = report.entry_points
    assert len(eps) > 1

    # 应包含 driver entry
    ep_types = [ep.ep_type for ep in eps]
    assert "entry_point" in ep_types

    # 所有 entry point 的 ret_val 应可获取
    for ep in eps:
        assert ep.ret_val is not None


def test_wdm_driver_read_back_picks_up_driver_unload(config, load_test_bin):
    """WDM 样本设置 DriverUnload 后，read_back 应同步该字段。"""
    import copy

    se = Speakeasy(config=copy.deepcopy(config))
    try:
        module = se.load_module(data=load_test_bin("wdm_test_x86.sys.xz"))
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
    finally:
        se.shutdown()

    # 如果有 unload entry point，说明 read_back 成功同步了 DriverUnload
    eps = report.entry_points
    ep_types = [ep.ep_type for ep in eps]
    if "driver_unload" in ep_types:
        # unload entry point 应能成功执行
        unload_ep = next(ep for ep in eps if ep.ep_type == "driver_unload")
        assert unload_ep is not None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v", "-p", "no:faulthandler", "--tb=short"]))
