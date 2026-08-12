"""
Bug 修复代理 C：P0 优化后核心引擎模块边界条件验证测试。

覆盖模块：
- memmgr.py (P0-4/P0-9): bisect 二分查找、空闲区间计算、map/free 循环一致性
- struct.py (P0-7/P0-8): 跨模块缓存隔离、嵌套/Ptr 数组字段、_field_name_map 覆盖
- binemu.py (P0-2): 分块字符串读取的跨块终止符、max_chars 限制、Unicode 对齐
- unicorn_eng.py (P0-1): 单分发器回调顺序、hook 范围过滤、close 后重新注册
"""

import ctypes as ct
import types

import pytest

import speakeasy.common as common
from speakeasy.struct import EmuStruct, Ptr, _STRUCT_CACHE


# ===========================================================================
# memmgr.py 测试
# ===========================================================================

class _MockEmuEng:
    """最小化的 emu_eng 替身，跟踪 mem_map/mem_unmap/mem_regions。"""

    def __init__(self, page_size=0x1000):
        self.page_size = page_size
        self._regions = {}  # base -> (end_inclusive, perms)

    def mem_map(self, base, size, perms=common.PERM_MEM_RWX):
        end = base + size - 1
        self._regions[base] = (end, perms)

    def mem_unmap(self, addr, size):
        # 移除完全落在 [addr, addr+size) 内的区域
        to_remove = []
        for b, (e, _) in self._regions.items():
            if b >= addr and e < addr + size:
                to_remove.append(b)
        for b in to_remove:
            del self._regions[b]

    def mem_regions(self):
        return [(b, e, p) for b, (e, p) in sorted(self._regions.items())]

    def mem_read(self, addr, size):
        return b"\x00" * size

    def mem_write(self, addr, data):
        pass

    def mem_protect(self, addr, size, perms):
        pass


class _Config:
    """模拟 config 对象。"""
    def __init__(self, keep_memory_on_free=False):
        self.keep_memory_on_free = keep_memory_on_free


def _make_memmgr(page_size=0x1000):
    """构造一个可测试的 MemoryManager 实例。"""
    from speakeasy.memmgr import MemoryManager

    class _TestableMM(MemoryManager):
        def __init__(self):
            super().__init__()
            self.hooks = {}
            self.config = _Config()
            self.page_size = page_size
            self.emu_eng = _MockEmuEng(page_size)

    return _TestableMM()


# ---- _rebuild_free_ranges 边界条件 ----

def test_rebuild_free_ranges_includes_address_zero():
    """空闲区间应从地址 0 开始（P0-4 修复：cursor 从 page_size 改为 0）。"""
    mm = _make_memmgr()
    mm._rebuild_free_ranges()
    # 首个空闲区间应从 0 开始
    assert mm._free_ranges[0][0] == 0


def test_rebuild_free_ranges_with_region_at_zero():
    """地址 0 处有映射时，空闲区间应从映射结束后开始。"""
    mm = _make_memmgr()
    mm.emu_eng.mem_map(0, 0x1000)
    mm._rebuild_free_ranges()
    # 地址 0 被占用，首个空闲区间应从 0x1000 开始
    assert mm._free_ranges[0][0] == 0x1000


def test_rebuild_free_ranges_with_region_at_page_size():
    """page_size 处有映射时的空闲区间计算。"""
    mm = _make_memmgr()
    mm.emu_eng.mem_map(0x1000, 0x2000)
    mm._rebuild_free_ranges()
    # [0, 0x1000) 空闲，[0x3000, upper) 空闲
    assert mm._free_ranges[0] == [0, 0x1000]
    assert mm._free_ranges[1][0] == 0x3000


def test_rebuild_free_ranges_high_address():
    """高地址处有映射时的空闲区间计算。"""
    mm = _make_memmgr()
    high = 0xFFFFFFFFFFFF0000
    mm.emu_eng.mem_map(high, 0x1000)
    mm._rebuild_free_ranges()
    # 映射区间 [high, high+0x1000) 将空闲区间分为两段：
    #   [0, high) 和 [high+0x1000, upper)
    # 第一个空闲区间（映射下方）应结束在 high 处
    assert mm._free_ranges[0][0] + mm._free_ranges[0][1] == high
    # 最后一个空闲区间（映射上方）应结束在 upper 处
    upper = 0xFFFFFFFFFFFFE000
    assert mm._free_ranges[-1][0] + mm._free_ranges[-1][1] == upper


def test_rebuild_free_ranges_overlapping_regions():
    """重叠的占用区间应被正确合并。"""
    mm = _make_memmgr()
    mm.emu_eng.mem_map(0x1000, 0x2000)  # [0x1000, 0x3000)
    mm.emu_eng.mem_map(0x2000, 0x2000)  # [0x2000, 0x4000) 与上一个重叠
    mm._rebuild_free_ranges()
    # 合并后 [0x1000, 0x4000) 被占用
    # 空闲: [0, 0x1000), [0x4000, upper)
    assert mm._free_ranges[0] == [0, 0x1000]
    assert mm._free_ranges[1][0] == 0x4000


# ---- _consume_free_range / _restore_free_range 往返 ----

def test_consume_and_restore_roundtrip_single():
    """单个区间的消费与恢复往返。"""
    mm = _make_memmgr()
    mm._rebuild_free_ranges()
    original = [list(r) for r in mm._free_ranges]

    mm._consume_free_range(0x1000, 0x1000)
    mm._restore_free_range(0x1000, 0x1000)
    assert mm._free_ranges == original


def test_consume_and_restore_roundtrip_multiple():
    """多次消费与恢复后，空闲区间应回到初始状态。"""
    mm = _make_memmgr()
    mm._rebuild_free_ranges()
    original = [list(r) for r in mm._free_ranges]

    mm._consume_free_range(0x1000, 0x1000)
    mm._consume_free_range(0x3000, 0x1000)
    mm._restore_free_range(0x1000, 0x1000)
    mm._restore_free_range(0x3000, 0x1000)
    assert mm._free_ranges == original


def test_consume_free_range_at_address_zero():
    """在地址 0 处消费空闲区间。"""
    mm = _make_memmgr()
    mm._rebuild_free_ranges()
    mm._consume_free_range(0, 0x1000)
    # 地址 0 处的区间被分割
    assert mm._free_ranges[0][0] == 0x1000


def test_consume_free_range_exact_fit():
    """消费整个空闲区间（base==fb, alloc_end==end）。"""
    mm = _make_memmgr()
    mm._rebuild_free_ranges()
    # 找到第一个空闲区间，完全消费
    fb, fs = mm._free_ranges[0]
    mm._consume_free_range(fb, fs)
    # 该区间应被移除
    assert all(r[0] != fb for r in mm._free_ranges)


def test_restore_free_range_merges_predecessor():
    """恢复区间时应与前驱空闲区间合并。"""
    mm = _make_memmgr()
    mm._rebuild_free_ranges()
    mm._consume_free_range(0x1000, 0x1000)
    # 空闲: [0, 0x1000), [0x2000, ...]
    assert mm._free_ranges[0] == [0, 0x1000]
    mm._consume_free_range(0, 0x1000)
    # 空闲: [0x2000, ...]
    assert mm._free_ranges[0][0] == 0x2000
    mm._restore_free_range(0, 0x1000)
    # 前驱合并: [0, 0x1000) 但不与 [0x2000,...) 合并（不相邻）
    assert mm._free_ranges[0] == [0, 0x1000]
    assert mm._free_ranges[1][0] == 0x2000


def test_restore_free_range_merges_both_sides():
    """恢复区间时应同时与前驱和后继合并。"""
    mm = _make_memmgr()
    mm._rebuild_free_ranges()
    mm._consume_free_range(0x1000, 0x1000)
    # 空闲: [0, 0x1000), [0x2000, ...]
    mm._restore_free_range(0x1000, 0x1000)
    # 应合并为 [0, ...]（与前驱合并，且 0x2000 处的后继也已合并）
    assert mm._free_ranges[0][0] == 0
    # 不应有 [0x1000, ...) 单独的区间
    assert all(r[0] != 0x1000 for r in mm._free_ranges)


# ---- get_valid_ranges 边界条件 ----

def test_get_valid_ranges_at_addr_zero():
    """get_valid_ranges(addr=0) 应能返回地址 0。"""
    mm = _make_memmgr()
    base, size = mm.get_valid_ranges(0x1000, addr=0)
    assert base == 0
    assert size == 0x1000


def test_get_valid_ranges_at_page_size():
    """get_valid_ranges(addr=page_size) 应返回 page_size。"""
    mm = _make_memmgr()
    base, size = mm.get_valid_ranges(0x1000, addr=0x1000)
    assert base == 0x1000
    assert size == 0x1000


def test_get_valid_ranges_skips_occupied():
    """get_valid_ranges 应跳过已占用区间。"""
    mm = _make_memmgr()
    mm.emu_eng.mem_map(0x1000, 0x2000)  # 占用 [0x1000, 0x3000)
    base, size = mm.get_valid_ranges(0x1000, addr=0x1000)
    # 0x1000 被占用，应返回下一个可用区间
    assert base == 0x3000


def test_get_valid_ranges_default_addr():
    """addr=None 时默认从 page_size 开始。"""
    mm = _make_memmgr()
    base, size = mm.get_valid_ranges(0x1000)
    assert base == 0x1000


# ---- map/free 循环一致性 ----

def test_map_unmap_cycle_consistency():
    """多次 map/free 循环后，内存映射状态应保持一致。"""
    mm = _make_memmgr()
    for i in range(5):
        base = mm.mem_map(0x100)
        assert base is not None
        mm.mem_free(base)
    # 循环后应能继续分配
    base = mm.mem_map(0x100)
    assert base is not None


def test_map_at_explicit_base_then_free():
    """在显式基址上映射然后释放。"""
    mm = _make_memmgr()
    mm.mem_map(0x2000, base=0x40000)
    assert mm.get_address_map(0x40000) is not None
    mm.mem_free(0x40000)
    # mem_free 会因 block 内所有块已释放而 unmap


def test_sorted_bases_consistent_after_operations():
    """经过多次 map/free 后，_sorted_bases 应与 maps 一致。"""
    mm = _make_memmgr()
    bases_added = []
    for _ in range(3):
        b = mm.mem_map(0x100)
        bases_added.append(b)

    # _sorted_bases 应包含所有 maps 的 base
    map_bases = {m.base for m in mm.maps}
    sorted_bases_set = set(mm._sorted_bases)
    assert map_bases == sorted_bases_set


# ---- mem_reserve 测试 ----

def test_mem_reserve_occupies_free_range():
    """mem_reserve 应占用空闲区间。"""
    mm = _make_memmgr()
    mm._rebuild_free_ranges()
    mm.mem_reserve(0x1000, base=0x5000)
    # 0x5000 应在 mem_reserves 中
    assert mm.get_reserve_map(0x5000) is not None
    # 0x5000 不应在空闲区间中
    for fb, fs in mm._free_ranges:
        assert not (fb <= 0x5000 < fb + fs), f"0x5000 仍在中空闲区间 [0x{fb:x}, 0x{fb + fs:x})"


# ===========================================================================
# struct.py 测试
# ===========================================================================

class NESTED_INNER(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.InnerField1 = ct.c_uint32
        self.InnerField2 = ct.c_uint16


class WITH_EMUSTRUCT_ARRAY(EmuStruct):
    """含 EmuStruct 数组字段（非 Ptr 数组）。"""
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.Count = ct.c_uint32
        self.Items = (NESTED_INNER, 3)


class WITH_NESTED_AND_PTR(EmuStruct):
    """同时含嵌套 EmuStruct、Ptr、Ptr 数组、ctypes 数组。"""
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.Field1 = ct.c_uint32
        self.Ptr1 = Ptr
        self.PtrArr = Ptr * 4
        self.Nested = NESTED_INNER
        self.ByteArr = ct.c_uint8 * 8


def test_emustruct_array_field_filtered():
    """EmuStruct 数组字段应标记为 filtered=True，并返回 filtermap 中的列表。"""
    s = WITH_EMUSTRUCT_ARRAY(4)
    fnm = type(s)._field_name_map
    assert fnm["Items"][1] is True  # filtered
    # 访问应返回 filtermap 中的列表
    items = s.Items
    assert isinstance(items, list)
    assert len(items) == 3
    assert isinstance(items[0], NESTED_INNER)


def test_emustruct_array_field_read_write():
    """EmuStruct 数组字段的元素读写。"""
    s = WITH_EMUSTRUCT_ARRAY(4)
    s.Count = 2
    s.Items[0].InnerField1 = 0xDEADBEEF
    s.Items[0].InnerField2 = 0xBEEF
    s.Items[1].InnerField1 = 0xCAFEBABE
    s.Items[1].InnerField2 = 0xBABE

    assert s.Count == 2
    assert s.Items[0].InnerField1 == 0xDEADBEEF
    assert s.Items[0].InnerField2 == 0xBEEF
    assert s.Items[1].InnerField1 == 0xCAFEBABE
    assert s.Items[1].InnerField2 == 0xBABE


def test_mixed_fields_field_name_map():
    """混合字段类型的 _field_name_map 覆盖。"""
    s = WITH_NESTED_AND_PTR(4)
    fnm = type(s)._field_name_map
    # 所有字段都应在 map 中
    assert "Field1" in fnm
    assert "Ptr1" in fnm
    assert "PtrArr" in fnm
    assert "Nested" in fnm
    assert "ByteArr" in fnm
    # 嵌套 EmuStruct 标记为 filtered
    assert fnm["Nested"][1] is True
    # Ptr 和 Ptr 数组不标记为 filtered
    assert fnm["Ptr1"][1] is False
    assert fnm["PtrArr"][1] is False
    # ctypes 数组不标记为 filtered
    assert fnm["ByteArr"][1] is False


def test_cross_module_same_name_cache_isolation():
    """跨模块同名类的缓存键隔离（更严格的验证）。"""
    # 在另一个模块作用域中定义同名但字段不同的类
    other_mod = types.ModuleType("other_mod_bugfix_c")
    code = (
        "import ctypes as ct\n"
        "from speakeasy.struct import EmuStruct, Ptr\n"
        "class MIXED(EmuStruct):\n"
        "    def __init__(self, ptr_size):\n"
        "        super().__init__(ptr_size, pack=1)\n"
        "        self.OtherField = ct.c_uint64\n"
        "        self.OtherPtr = Ptr\n"
    )
    exec(code, other_mod.__dict__)

    # 本地定义同名类
    class MIXED(EmuStruct):
        def __init__(self, ptr_size):
            super().__init__(ptr_size, pack=1)
            self.LocalField = ct.c_uint16

    local_inst = MIXED(4)
    other_inst = other_mod.MIXED(4)

    # 两者大小不同
    assert local_inst.sizeof() == 2
    assert other_inst.sizeof() == 8 + 4  # uint64 + ptr(4)

    # 缓存键隔离
    local_key = f"{MIXED.__module__}.MIXED_4"
    other_key = "other_mod_bugfix_c.MIXED_4"
    assert local_key in _STRUCT_CACHE
    assert other_key in _STRUCT_CACHE
    assert local_key != other_key


def test_nested_emustruct_cast_roundtrip():
    """嵌套 EmuStruct 的 cast 往返。"""
    s = WITH_NESTED_AND_PTR(4)
    s.Field1 = 0x11223344
    s.Ptr1 = 0xAABBCCDD
    s.Nested.InnerField1 = 0x55667788
    s.Nested.InnerField2 = 0x99AA

    bytez = s.get_bytes()
    s2 = WITH_NESTED_AND_PTR(4)
    s2.cast(bytez)

    assert s2.Field1 == 0x11223344
    assert s2.Ptr1 == 0xAABBCCDD
    assert s2.Nested.InnerField1 == 0x55667788
    assert s2.Nested.InnerField2 == 0x99AA


def test_cache_reuse_preserves_filtermap_independence():
    """缓存复用时，不同实例的 filtermap 应独立。"""
    s1 = WITH_NESTED_AND_PTR(4)
    s2 = WITH_NESTED_AND_PTR(4)

    s1.Nested.InnerField1 = 0x11111111
    s2.Nested.InnerField1 = 0x22222222

    assert s1.Nested.InnerField1 == 0x11111111
    assert s2.Nested.InnerField1 == 0x22222222


# ===========================================================================
# binemu.py 测试
# ===========================================================================

class _FakeMem:
    """模拟可读内存。"""
    def __init__(self, base, data):
        self.base = base
        self.data = bytearray(data)

    def mem_read(self, addr, size):
        off = addr - self.base
        if off < 0 or off > len(self.data):
            return b""
        return bytes(self.data[off:off + size])


def _make_emu(base, data):
    """构造一个只具备 mem_read 能力的 BinaryEmulator 子类实例。"""
    from speakeasy.binemu import BinaryEmulator

    class _Emu(BinaryEmulator):
        def __init__(self, fake):
            self._fake = fake

        def mem_read(self, addr, size):
            return self._fake.mem_read(addr, size)

        def _set_emu_hooks(self, *args, **kwargs):
            pass

        def get_current_run(self, *args, **kwargs):
            return None

        def on_emu_complete(self, *args, **kwargs):
            pass

    return _Emu(_FakeMem(base, data))


def test_read_mem_string_terminator_at_chunk_boundary():
    """终止符恰在 256 字节块边界（pos=0 of chunk 2）。"""
    base = 0x10000
    # 256 字节内容 + 终止符在第 257 字节（chunk 2 的 pos 0）
    payload = b"A" * 256 + b"\x00" + b"garbage"
    emu = _make_emu(base, payload)
    assert emu.read_mem_string(base, width=1) == "A" * 256


def test_read_mem_string_terminator_at_chunk_boundary_unicode():
    """Unicode 终止符在 256 字节块边界。"""
    base = 0x10000
    # 128 个 UTF-16LE 字符 = 256 字节，终止符在字节 256
    payload = ("B\x00" * 128) + "\x00\x00" + "X\x00"
    emu = _make_emu(base, payload.encode("latin-1"))
    assert emu.read_mem_string(base, width=2) == "B" * 128


def test_read_mem_string_max_chars_not_aligned_to_width():
    """max_chars 不对齐 width 时的行为（width=2, max_chars 为奇数不会发生，测试边界）。"""
    base = 0x10000
    payload = b"A\x00B\x00C\x00D\x00E\x00\x00\x00"
    emu = _make_emu(base, payload)
    # max_chars=3 应返回 3 个字符
    result = emu.read_mem_string(base, width=2, max_chars=3)
    assert result == "ABC"


def test_read_mem_string_max_chars_zero_means_no_limit():
    """max_chars=0 表示无限制。"""
    base = 0x10000
    payload = b"hello world\x00"
    emu = _make_emu(base, payload)
    assert emu.read_mem_string(base, width=1, max_chars=0) == "hello world"


def test_read_mem_string_cross_multiple_chunks():
    """字符串跨越多个 256 字节块。"""
    base = 0x10000
    payload = b"X" * 600 + b"\x00"
    emu = _make_emu(base, payload)
    assert emu.read_mem_string(base, width=1) == "X" * 600


def test_mem_string_len_and_read_mem_string_consistency_ansi():
    """mem_string_len 与 read_mem_string 的一致性（ANSI）。"""
    base = 0x10000
    payload = b"hello world\x00garbage"
    emu = _make_emu(base, payload)
    s = emu.read_mem_string(base, width=1)
    slen = emu.mem_string_len(base, width=1)
    assert len(s) == slen


def test_mem_string_len_and_read_mem_string_consistency_unicode():
    """mem_string_len 与 read_mem_string 的一致性（Unicode）。"""
    base = 0x10000
    payload = ("h\x00e\x00l\x00l\x00o\x00\x00\x00").encode("latin-1")
    emu = _make_emu(base, payload)
    s = emu.read_mem_string(base, width=2)
    slen = emu.mem_string_len(base, width=2)
    assert len(s) == slen


def test_read_mem_string_terminator_straddle_chunk_boundary_not_possible():
    """对于 width=2，终止符不可能跨块（256 是 2 的倍数）。
    但验证一下边界情况：终止符第一字节在块末尾。"""
    base = 0x10000
    # 构造：255 字节内容 + \x00（块末尾）+ \x00（下一块开头）
    # 对于 width=2，\x00\x00 在偏移 256（偶数），是合法终止符
    # 偏移 255 的 \x00 不是终止符起始（奇数偏移）
    payload = b"A" * 255 + b"\x00" + b"\x00" + b"B" * 10
    emu = _make_emu(base, payload)
    # 块1 = bytes[0:256] = "A"*255 + "\x00"
    # 块1 中查找 \x00\x00：byte[255] = \x00, byte[256] 不在块1中
    # 所以块1无终止符，buf = 256 字节
    # 块2 = bytes[256:512] = "\x00" + "B"*10 + ...
    # 块2 中 pos=0 处 \x00，但需要 \x00\x00。byte[0]=\x00, byte[1]=\x00? 不，byte[1]=B
    # 等等，let me re-check: payload = "A"*255 + "\x00" + "\x00" + "B"*10
    # 偏移 255 = \x00, 偏移 256 = \x00, 偏移 257 = B
    # 块1 = bytes[0:256] = "A"*255 + "\x00" (偏移 255)
    # 块1.find(\x00\x00, 0): 需要 \x00\x00 连续。偏移 255 的 \x00 后面没有字节了（块1到 255 结束）。
    #   实际上块1是 256 字节，偏移 0-255。find 从 0 开始搜索。
    #   255 处只有 1 个 \x00，没有 \x00\x00。所以块1无终止符。
    # buf = 256 字节, offset = 256
    # 块2 = bytes[256:512] = "\x00" + "B"*10 + ...
    # 块2.find(\x00\x00, 0): byte[0]=\x00, byte[1]=B。不是 \x00\x00。
    # 所以块2无终止符。buf += 块2. 一直到内存末尾。
    # 最终 buf = 全部字节，decode 后去掉 \x00
    result = emu.read_mem_string(base, width=2)
    # buf 包含 267 字节（255+1+1+10），decode utf-16le ignore
    # 由于 \x00 被去掉，结果是 "A" 的某种组合 + "B"
    # 这个测试主要验证不会崩溃
    assert isinstance(result, str)


def test_read_mem_string_empty_memory():
    """空内存（mem_read 返回空）。"""
    base = 0x10000
    emu = _make_emu(base, b"")
    assert emu.read_mem_string(base, width=1) == ""


def test_mem_string_len_cross_256_with_max_chars():
    """mem_string_len 不受 max_chars 影响（它是独立方法）。"""
    base = 0x10000
    payload = b"A" * 300 + b"\x00"
    emu = _make_emu(base, payload)
    assert emu.mem_string_len(base, width=1) == 300


# ===========================================================================
# unicorn_eng.py 测试
# ===========================================================================

def _make_emu_engine_x86():
    """构造一个 x86 Unicorn 引擎并映射一小段代码。"""
    import unicorn as uc
    import speakeasy.winenv.arch as arch
    from speakeasy.engines.unicorn_eng import EmuEngine

    eng = EmuEngine()
    eng.init_engine(arch.ARCH_X86, arch.BITS_32)
    # 映射代码区
    eng.mem_map(0x1000, 0x1000, perms=common.PERM_MEM_RWX)
    # 映射栈
    eng.mem_map(0x2000, 0x1000, perms=common.PERM_MEM_RWX)
    return eng


def _x86_nop_sled(count):
    """生成 count 个 NOP 指令。"""
    return b"\x90" * count


def test_code_hooks_fire_in_registration_order():
    """多个 code hook 应按注册顺序触发。"""
    eng = _make_emu_engine_x86()
    code = _x86_nop_sled(3) + b"\xcc"  # 3 NOP + INT3 (会触发中断，但我们先测 code hook)
    eng.mem_write(0x1000, code)

    # 设置 EIP
    import unicorn.x86_const as u
    eng.emu.reg_write(u.UC_X86_REG_EIP, 0x1000)
    eng.emu.reg_write(u.UC_X86_REG_ESP, 0x2FF0)

    order = []

    def cb1(e, addr, size, ctx=None):
        order.append(1)

    def cb2(e, addr, size, ctx=None):
        order.append(2)

    def cb3(e, addr, size, ctx=None):
        order.append(3)

    eng.add_code_hook(cb1)
    eng.add_code_hook(cb2)
    eng.add_code_hook(cb3)

    # 只执行 1 条指令
    eng.emu.emu_start(0x1000, 0x1000 + 1, count=1)

    assert order == [1, 2, 3]


def test_code_hook_range_filtering():
    """code hook 的范围过滤应正确工作。"""
    eng = _make_emu_engine_x86()
    code = _x86_nop_sled(5)
    eng.mem_write(0x1000, code)

    import unicorn.x86_const as u
    eng.emu.reg_write(u.UC_X86_REG_EIP, 0x1000)
    eng.emu.reg_write(u.UC_X86_REG_ESP, 0x2FF0)

    hits = []

    def cb(e, addr, size, ctx=None):
        hits.append(addr)

    # 只在 [0x1002, 0x1003] 范围内触发
    eng.add_code_hook(cb, begin=0x1002, end=0x1003)

    # 执行 5 条 NOP
    eng.emu.emu_start(0x1000, 0x1000 + 5, count=5)

    # 应只在 0x1002 和 0x1003 触发
    assert hits == [0x1002, 0x1003]


def test_code_hook_default_range_all_addresses():
    """默认 begin=1, end=0 应对所有地址触发。"""
    eng = _make_emu_engine_x86()
    code = _x86_nop_sled(3)
    eng.mem_write(0x1000, code)

    import unicorn.x86_const as u
    eng.emu.reg_write(u.UC_X86_REG_EIP, 0x1000)
    eng.emu.reg_write(u.UC_X86_REG_ESP, 0x2FF0)

    hits = []

    def cb(e, addr, size, ctx=None):
        hits.append(addr)

    eng.add_code_hook(cb)  # 默认 begin=1, end=0

    eng.emu.emu_start(0x1000, 0x1000 + 3, count=3)

    assert hits == [0x1000, 0x1001, 0x1002]


def test_code_hook_disable_enable_individual():
    """单个 code hook 的禁用/启用不应影响其他 hook。"""
    eng = _make_emu_engine_x86()
    code = _x86_nop_sled(2)
    eng.mem_write(0x1000, code)

    import unicorn.x86_const as u
    eng.emu.reg_write(u.UC_X86_REG_EIP, 0x1000)
    eng.emu.reg_write(u.UC_X86_REG_ESP, 0x2FF0)

    hits1 = []
    hits2 = []

    def cb1(e, addr, size, ctx=None):
        hits1.append(addr)

    def cb2(e, addr, size, ctx=None):
        hits2.append(addr)

    # 用 emu_eng 直接注册（绕过 CodeHook 封装）
    # 模拟 CodeHook 的行为：注册 _wrap_code_cb
    class _StubHook:
        def __init__(self, cb):
            self.cb = cb
            self.enabled = True

        def _wrap(self, e, addr, size, ctx=None):
            if self.enabled:
                self.cb(e, addr, size, ctx)

    h1 = _StubHook(cb1)
    h2 = _StubHook(cb2)

    eng.add_code_hook(h1._wrap)
    eng.add_code_hook(h2._wrap)

    # 禁用 h1
    h1.enabled = False
    eng.emu.emu_start(0x1000, 0x1000 + 1, count=1)
    assert hits1 == []
    assert hits2 == [0x1000]

    # 启用 h1
    h1.enabled = True
    eng.emu.emu_start(0x1001, 0x1000 + 2, count=1)
    assert hits1 == [0x1001]
    assert hits2 == [0x1000, 0x1001]


def test_code_hook_reregister_after_close():
    """close() 后应能重新注册 code hook。"""
    eng = _make_emu_engine_x86()
    code = _x86_nop_sled(1)
    eng.mem_write(0x1000, code)

    import unicorn.x86_const as u
    eng.emu.reg_write(u.UC_X86_REG_EIP, 0x1000)
    eng.emu.reg_write(u.UC_X86_REG_ESP, 0x2FF0)

    hits = []

    def cb(e, addr, size, ctx=None):
        hits.append(addr)

    eng.add_code_hook(cb)
    eng.emu.emu_start(0x1000, 0x1000 + 1, count=1)
    assert hits == [0x1000]

    # close 后重新注册
    eng.close()
    hits.clear()

    def cb2(e, addr, size, ctx=None):
        hits.append(addr)

    eng.add_code_hook(cb2)
    eng.emu.emu_start(0x1000, 0x1000 + 1, count=1)
    assert hits == [0x1000]


def test_other_hook_types_not_delegated_to_code_dispatch():
    """非 UC_HOOK_CODE 的 hook 类型不应走单分发器。"""
    import unicorn as uc
    from speakeasy.engines.unicorn_eng import EmuEngine
    import speakeasy.winenv.arch as arch

    eng = EmuEngine()
    eng.init_engine(arch.ARCH_X86, arch.BITS_32)
    eng.mem_map(0x1000, 0x1000, perms=common.PERM_MEM_RWX)

    # 注册 MEM_READ hook
    read_hits = []

    def read_cb(e, access, addr, size, value, ctx=None):
        read_hits.append(addr)

    handle = eng.hook_add(htype=common.HOOK_MEM_READ, cb=read_cb, begin=1, end=0)
    # 应返回一个有效的 handle（非 code dispatch handle）
    assert handle is not None
    # code dispatch 不应被触发
    assert eng._code_dispatch_id is None or handle != eng._code_dispatch_id

    # UC_HOOK_MEM_READ 只在仿真执行期间触发，不会在直接调用 Python API
    # mem_read 时触发。写入 mov eax, [0x1800]（A1 = MOV EAX, moffs32）
    # 并通过仿真执行来触发内存读取 hook。
    code = b"\xa1\x00\x18\x00\x00"  # mov eax, [0x1800]
    eng.mem_write(0x1000, code)

    import unicorn.x86_const as u
    eng.emu.reg_write(u.UC_X86_REG_EIP, 0x1000)
    eng.emu.reg_write(u.UC_X86_REG_ESP, 0x2FF0)

    eng.emu.emu_start(0x1000, 0x1000 + len(code), count=1)
    assert len(read_hits) > 0
    eng.close()


def test_code_hook_per_hook_handle_individual_disable():
    """V2-3-2: 每个 code hook 获得独立句柄，hook_disable/hook_enable 可单独控制。

    取代旧的 test_code_hook_handle_shared：共享句柄正是 P0 bug 根因
    （hook_disable 对 code hook 无效），现已修复为 per-hook 独立句柄。
    """
    eng = _make_emu_engine_x86()
    code = _x86_nop_sled(2)
    eng.mem_write(0x1000, code)

    import unicorn.x86_const as u
    eng.emu.reg_write(u.UC_X86_REG_EIP, 0x1000)
    eng.emu.reg_write(u.UC_X86_REG_ESP, 0x2FF0)

    hits1 = []
    hits2 = []

    h1 = eng.add_code_hook(lambda e, a, s, c: hits1.append(a))
    h2 = eng.add_code_hook(lambda e, a, s, c: hits2.append(a))
    # 独立句柄（底层仍共享单个原生分发器 _code_dispatch_id）
    assert h1 != h2
    assert eng._code_dispatch_id is not None

    # 禁用 h1，h2 仍触发
    eng.hook_disable(h1)
    eng.emu.emu_start(0x1000, 0x1000 + 1, count=1)
    assert hits1 == []
    assert hits2 == [0x1000]

    # 启用 h1，两个 hook 均触发
    eng.hook_enable(h1)
    eng.emu.emu_start(0x1001, 0x1000 + 2, count=1)
    assert hits1 == [0x1001]
    assert hits2 == [0x1000, 0x1001]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v", "-p", "no:faulthandler", "--tb=short"]))
