# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
"""
P0 优化后的回归测试：
- P0-1: UC_HOOK_CODE 单分发器的范围过滤与回调顺序
- P0-10: pseudocode 批量反汇编 (_disasm_batch/_materialize_pending) 与即时路径的一致性
- close() 后单分发器状态重置
"""

import speakeasy.winenv.arch as e_arch
from speakeasy.engines.unicorn_eng import EmuEngine
from speakeasy.pseudocode import PseudocodeRenderer


# ---------------------------------------------------------------------------
# 辅助 mock：用于 pseudocode 批量反汇编测试（支持任意区间 mem_read）
# ---------------------------------------------------------------------------
class FlatMemoryEmulator:
    """以 (base, code) 模拟一段连续内存，mem_read 支持任意区间读取。"""

    def __init__(self, base=0x1000, code=b"", arch=e_arch.ARCH_AMD64):
        self.base = base
        self.code = code
        self._arch = arch
        self.import_table = {}
        self.curr_mod = None

    def get_arch(self):
        return self._arch

    def get_ptr_size(self):
        return 8 if self._arch == e_arch.ARCH_AMD64 else 4

    def mem_read(self, address, size):
        offset = address - self.base
        if offset < 0 or offset >= len(self.code):
            return b"\x00" * size
        end = min(offset + size, len(self.code))
        data = self.code[offset:end]
        if len(data) < size:
            data = data + b"\x00" * (size - len(data))
        return data

    def read_mem_string(self, address, width=1, max_chars=64):
        return ""

    def reg_read(self, reg_name):
        return 0

    def get_symbol_from_address(self, address):
        return None

    def get_address_tag(self, address):
        return None

    def get_mod_from_addr(self, address):
        return None


# ===========================================================================
# P0-1: 单分发器 _dispatch_code_hooks 范围过滤
# ===========================================================================

def test_dispatch_begin_greater_than_end_fires_for_all_addresses():
    """begin > end（如默认 begin=1, end=0）表示全部地址，所有 addr 都应触发。"""
    eng = EmuEngine()
    calls = []
    eng._code_hooks = [(lambda e, a, s, c: calls.append(a), 1, 0)]
    for addr in (0, 0x1000, 0xFFFFFFFF, 0x7FFFFFFF):
        eng._dispatch_code_hooks(None, addr, 4, None)
    assert calls == [0, 0x1000, 0xFFFFFFFF, 0x7FFFFFFF]


def test_dispatch_begin_equals_end_fires_only_for_exact_address():
    """begin == end 只对 addr == begin == end 触发。"""
    eng = EmuEngine()
    calls = []
    eng._code_hooks = [(lambda e, a, s, c: calls.append(a), 0x1005, 0x1005)]
    eng._dispatch_code_hooks(None, 0x1004, 4, None)
    eng._dispatch_code_hooks(None, 0x1005, 4, None)
    eng._dispatch_code_hooks(None, 0x1006, 4, None)
    assert calls == [0x1005]


def test_dispatch_begin_less_than_end_fires_for_inclusive_range():
    """begin < end 对 [begin, end] 闭区间触发（含两端）。"""
    eng = EmuEngine()
    calls = []
    eng._code_hooks = [(lambda e, a, s, c: calls.append(a), 0x1000, 0x100a)]
    eng._dispatch_code_hooks(None, 0x0FFF, 4, None)  # 下界外
    eng._dispatch_code_hooks(None, 0x1000, 4, None)  # 下界
    eng._dispatch_code_hooks(None, 0x1005, 4, None)  # 区间内
    eng._dispatch_code_hooks(None, 0x100a, 4, None)  # 上界
    eng._dispatch_code_hooks(None, 0x100b, 4, None)  # 上界外
    assert calls == [0x1000, 0x1005, 0x100a]


def test_dispatch_multiple_hooks_fire_in_registration_order():
    """多个 code hook 按注册顺序依次触发。"""
    eng = EmuEngine()
    order = []

    def hook_a(e, a, s, c):
        order.append("a")

    def hook_b(e, a, s, c):
        order.append("b")

    def hook_c(e, a, s, c):
        order.append("c")

    eng._code_hooks = [(hook_a, 1, 0), (hook_b, 1, 0), (hook_c, 1, 0)]
    eng._dispatch_code_hooks(None, 0x1000, 4, None)
    assert order == ["a", "b", "c"]


def test_dispatch_mixed_ranges_filter_independently():
    """不同 begin/end 的 hook 独立过滤：全地址 hook + 单地址 hook + 区间 hook。"""
    eng = EmuEngine()
    all_calls = []
    single_calls = []
    range_calls = []
    eng._code_hooks = [
        (lambda e, a, s, c: all_calls.append(a), 1, 0),            # 全地址
        (lambda e, a, s, c: single_calls.append(a), 0x1005, 0x1005),  # 单地址
        (lambda e, a, s, c: range_calls.append(a), 0x1000, 0x100a),   # 区间
    ]
    for addr in (0x1000, 0x1005, 0x100a, 0x100b):
        eng._dispatch_code_hooks(None, addr, 4, None)
    assert all_calls == [0x1000, 0x1005, 0x100a, 0x100b]
    assert single_calls == [0x1005]
    assert range_calls == [0x1000, 0x1005, 0x100a]


def test_dispatch_passes_ctx_to_callbacks():
    """分发器将 ctx 透传给回调。"""
    eng = EmuEngine()
    received = []
    eng._code_hooks = [(lambda e, a, s, c: received.append(c), 1, 0)]
    eng._dispatch_code_hooks(None, 0x1000, 4, "ctx-marker")
    assert received == ["ctx-marker"]


# ===========================================================================
# P0-1: 单分发器与真实 Unicorn 引擎的集成
# ===========================================================================

def test_dispatcher_integration_all_address_hook_fires_for_every_instruction():
    """真实 Unicorn 引擎：全地址 hook 对每条指令触发。"""
    eng = EmuEngine()
    eng.init_engine(e_arch.ARCH_X86, e_arch.BITS_32)
    eng.mem_map(0x1000, 0x1000)
    # mov eax, 1 ; mov eax, 2 ; mov eax, 3
    eng.mem_write(0x1000, b"\xb8\x01\x00\x00\x00\xb8\x02\x00\x00\x00\xb8\x03\x00\x00\x00")

    calls = []
    eng.add_code_hook(lambda e, a, s, c: calls.append(a))
    eng.start(0x1000, count=3)
    assert calls == [0x1000, 0x1005, 0x100a]


def test_dispatcher_integration_range_hook_only_fires_in_range():
    """真实 Unicorn 引擎：区间 hook 只在 [begin, end] 内触发。"""
    eng = EmuEngine()
    eng.init_engine(e_arch.ARCH_X86, e_arch.BITS_32)
    eng.mem_map(0x1000, 0x1000)
    eng.mem_write(0x1000, b"\xb8\x01\x00\x00\x00\xb8\x02\x00\x00\x00\xb8\x03\x00\x00\x00")

    calls = []
    eng.add_code_hook(lambda e, a, s, c: calls.append(a), begin=0x1005, end=0x1005)
    eng.start(0x1000, count=3)
    assert calls == [0x1005]


def test_dispatcher_integration_multiple_hooks_share_single_dispatch():
    """多个 code hook 共享同一分发器句柄，但各自独立触发。"""
    eng = EmuEngine()
    eng.init_engine(e_arch.ARCH_X86, e_arch.BITS_32)
    eng.mem_map(0x1000, 0x1000)
    eng.mem_write(0x1000, b"\xb8\x01\x00\x00\x00\xb8\x02\x00\x00\x00")

    calls_a = []
    calls_b = []
    h1 = eng.add_code_hook(lambda e, a, s, c: calls_a.append(a))
    h2 = eng.add_code_hook(lambda e, a, s, c: calls_b.append(a))
    # 共享同一分发器句柄
    assert h1 == h2
    eng.start(0x1000, count=2)
    assert calls_a == [0x1000, 0x1005]
    assert calls_b == [0x1000, 0x1005]


# ===========================================================================
# P0-1: close() 重置单分发器状态
# ===========================================================================

def test_close_resets_code_hook_dispatch_state():
    """close() 清空 _code_hooks/_code_dispatch_id/_code_dispatch_cb。"""
    eng = EmuEngine()
    eng.init_engine(e_arch.ARCH_X86, e_arch.BITS_32)
    eng.add_code_hook(lambda e, a, s, c: None)
    assert eng._code_hooks  # 非空
    assert eng._code_dispatch_id is not None
    assert eng._code_dispatch_cb is not None

    eng.close()
    assert eng._code_hooks == []
    assert eng._code_dispatch_id is None
    assert eng._code_dispatch_cb is None
    assert eng._callbacks == {}


# ===========================================================================
# P0-10: _disasm_batch 区间合并
# ===========================================================================

def test_disasm_batch_single_record_returns_one_insn():
    """单条记录：返回一个 insn。"""
    # mov ecx, 1 (b9 01 00 00 00)
    emu = FlatMemoryEmulator(base=0x1000, code=b"\xb9\x01\x00\x00\x00")
    renderer = PseudocodeRenderer(emu)
    result = renderer._disasm_batch([(0x1000, 5)])
    assert 0x1000 in result
    assert result[0x1000].mnemonic == "mov"


def test_disasm_batch_merges_contiguous_intervals():
    """连续记录合并为一段 chunk。"""
    # mov ecx, 1 ; mov ecx, 2
    code = b"\xb9\x01\x00\x00\x00\xb9\x02\x00\x00\x00"
    emu = FlatMemoryEmulator(base=0x1000, code=code)
    renderer = PseudocodeRenderer(emu)
    result = renderer._disasm_batch([(0x1000, 5), (0x1005, 5)])
    assert 0x1000 in result
    assert 0x1005 in result
    assert result[0x1000].mnemonic == "mov"
    assert result[0x1005].mnemonic == "mov"


def test_disasm_batch_merges_overlapping_intervals():
    """重叠记录合并为一段 chunk。"""
    # 10 字节代码
    code = b"\xb9\x01\x00\x00\x00\xb9\x02\x00\x00\x00"
    emu = FlatMemoryEmulator(base=0x1000, code=code)
    renderer = PseudocodeRenderer(emu)
    # (0x1000, 8) 与 (0x1005, 5) 重叠
    result = renderer._disasm_batch([(0x1000, 8), (0x1005, 5)])
    assert 0x1000 in result
    assert 0x1005 in result


def test_disasm_batch_merges_contained_intervals():
    """包含关系：小记录被大记录包含。"""
    code = b"\xb9\x01\x00\x00\x00\xb9\x02\x00\x00\x00"
    emu = FlatMemoryEmulator(base=0x1000, code=code)
    renderer = PseudocodeRenderer(emu)
    # (0x1000, 10) 包含 (0x1005, 5)
    result = renderer._disasm_batch([(0x1000, 10), (0x1005, 5)])
    assert 0x1000 in result
    assert 0x1005 in result


def test_disasm_batch_separates_gap_intervals():
    """有间隔的记录分属不同 chunk，但各自反汇编成功。"""
    # 0x1000: mov ecx,1 ; 0x1010: mov ecx,2
    code = b"\xb9\x01\x00\x00\x00" + b"\x90" * 11 + b"\xb9\x02\x00\x00\x00"
    emu = FlatMemoryEmulator(base=0x1000, code=code)
    renderer = PseudocodeRenderer(emu)
    result = renderer._disasm_batch([(0x1000, 5), (0x1010, 5)])
    assert 0x1000 in result
    assert 0x1010 in result
    assert result[0x1000].mnemonic == "mov"
    assert result[0x1010].mnemonic == "mov"


def test_disasm_batch_empty_input_returns_empty():
    """空输入返回空 dict。"""
    emu = FlatMemoryEmulator(base=0x1000, code=b"")
    renderer = PseudocodeRenderer(emu)
    assert renderer._disasm_batch([]) == {}


# ===========================================================================
# P0-10: _materialize_pending 与即时路径一致性
# ===========================================================================

def test_materialize_pending_no_pending_returns_unchanged():
    """无占位记录时直接返回原列表（快速路径）。"""
    emu = FlatMemoryEmulator(base=0x1000, code=b"\xb8\x01\x00\x00\x00")
    renderer = PseudocodeRenderer(emu)
    records = [
        {"address": "0x1000", "pseudocode": "eax = 0x1", "assembly": "mov eax, 1",
         "context": [], "filtered": False, "target_symbol": None,
         "string_value": None, "object_display": None,
         "register_values": {}, "variable_aliases": {}},
    ]
    result = renderer._materialize_pending(records)
    assert result is records  # 同一对象


def test_materialize_pending_produces_same_record_as_eager():
    """占位记录批量反汇编结果与即时反汇编一致。"""
    # mov ecx, 1 ; mov edx, 2
    code = b"\xb9\x01\x00\x00\x00\xba\x02\x00\x00\x00"
    emu = FlatMemoryEmulator(base=0x1000, code=code)
    renderer = PseudocodeRenderer(emu)

    eager_0 = renderer.render_instruction_record(0x1000, 5)
    eager_1 = renderer.render_instruction_record(0x1005, 5)
    assert eager_0 is not None
    assert eager_1 is not None

    pending_records = [
        {"_pending": True, "_addr": 0x1000, "_size": 5},
        {"_pending": True, "_addr": 0x1005, "_size": 5},
    ]
    materialized = renderer._materialize_pending(pending_records)
    assert len(materialized) == 2
    assert materialized[0]["pseudocode"] == eager_0["pseudocode"]
    assert materialized[0]["assembly"] == eager_0["assembly"]
    assert materialized[1]["pseudocode"] == eager_1["pseudocode"]
    assert materialized[1]["assembly"] == eager_1["assembly"]


def test_materialize_pending_falls_back_to_eager_when_batch_misses():
    """批量反汇编未命中时，回退到单条反汇编。"""
    # 0x1000: jmp 0x1002 (eb 00) + nop + nop + mov ecx,1
    # 0x1003 是指令中段（jmp 占 2 字节，0x1002 是 nop），批量线性反汇编不会在 0x1003 产生 insn
    code = b"\xeb\x00\x90\x90\xb9\x01\x00\x00\x00"
    emu = FlatMemoryEmulator(base=0x1000, code=code)
    renderer = PseudocodeRenderer(emu)

    eager = renderer.render_instruction_record(0x1003, 1)
    pending = [{"_pending": True, "_addr": 0x1003, "_size": 1}]
    materialized = renderer._materialize_pending(pending)
    # 即时路径与回退路径都应能反汇编 0x1003 处的字节
    if eager is not None:
        assert len(materialized) == 1
        assert materialized[0]["assembly"] == eager["assembly"]
    else:
        assert len(materialized) == 0


def test_materialize_pending_drops_nop_like_eager():
    """占位记录反汇编为 nop 时，与即时路径一样被丢弃。"""
    code = b"\x90"  # nop
    emu = FlatMemoryEmulator(base=0x1000, code=code)
    renderer = PseudocodeRenderer(emu)

    eager = renderer.render_instruction_record(0x1000, 1)
    assert eager is None  # 即时路径对 nop 返回 None

    pending = [{"_pending": True, "_addr": 0x1000, "_size": 1}]
    materialized = renderer._materialize_pending(pending)
    assert len(materialized) == 0  # 批量路径同样丢弃 nop


def test_materialize_pending_preserves_non_pending_records_order():
    """非占位记录保持原顺序，占位记录在原位置被替换。"""
    code = b"\xb9\x01\x00\x00\x00"  # mov ecx, 1
    emu = FlatMemoryEmulator(base=0x1000, code=code)
    renderer = PseudocodeRenderer(emu)

    records = [
        {"address": "0x500", "pseudocode": "pre", "assembly": "pre",
         "context": [], "filtered": False, "target_symbol": None,
         "string_value": None, "object_display": None,
         "register_values": {}, "variable_aliases": {}},
        {"_pending": True, "_addr": 0x1000, "_size": 5},
        {"address": "0x600", "pseudocode": "post", "assembly": "post",
         "context": [], "filtered": False, "target_symbol": None,
         "string_value": None, "object_display": None,
         "register_values": {}, "variable_aliases": {}},
    ]
    materialized = renderer._materialize_pending(records)
    assert len(materialized) == 3
    assert materialized[0]["pseudocode"] == "pre"
    assert materialized[1]["pseudocode"] is not None  # 占位被替换
    assert materialized[2]["pseudocode"] == "post"


def test_materialize_pending_mixed_pending_and_real_unaffected_by_compact():
    """compact_instruction_records 在无占位时行为不变（回归测试）。"""
    code = b"\xb9\x01\x00\x00\x00"
    emu = FlatMemoryEmulator(base=0x1000, code=code)
    renderer = PseudocodeRenderer(emu)

    records = [
        {"address": "0x1000", "pseudocode": "ecx = 0x1", "assembly": "mov ecx, 1",
         "context": [], "filtered": False, "target_symbol": None,
         "string_value": None, "object_display": None,
         "register_values": {}, "variable_aliases": {}},
    ]
    compacted = renderer.compact_instruction_records(records)
    assert len(compacted) == 1
    assert compacted[0]["pseudocode"] == "ecx = 0x1"
