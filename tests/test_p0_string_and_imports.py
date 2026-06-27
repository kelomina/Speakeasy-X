"""
P0 优化后的功能验证测试：
- 验证 read_mem_string / mem_string_len 在分块读取（256 字节）改造后保持原有功能
- 验证 _patch_imports 的 bytearray in-place 修改不破坏 PE 镜像

这些测试不依赖 unicorn 引擎，通过 mock mem_read 直接测试 BinaryEmulator 的字符串方法。
"""
import pytest

from speakeasy.binemu import BinaryEmulator


class _FakeMem:
    """模拟可读内存：内部用 bytearray 保存，按地址切片返回。

    用于测试 read_mem_string / mem_string_len，避免引入 unicorn 依赖。
    """

    def __init__(self, base, data):
        self.base = base
        self.data = bytearray(data)

    def mem_read(self, addr, size):
        off = addr - self.base
        if off < 0 or off > len(self.data):
            return b""
        return bytes(self.data[off:off + size])


def _make_emu(base, data):
    """构造一个只具备 mem_read 能力的 BinaryEmulator 子类实例。

    BinaryEmulator 是抽象类，需要实现其抽象方法才能实例化；这里 stub 掉与
    字符串读取无关的抽象方法。
    """

    class _Emu(BinaryEmulator):
        def __init__(self, fake):
            self._fake = fake

        def mem_read(self, addr, size):
            return self._fake.mem_read(addr, size)

        def _set_emu_hooks(self, *args, **kwargs):  # abstract stub
            pass

        def get_current_run(self, *args, **kwargs):  # abstract stub
            return None

        def on_emu_complete(self, *args, **kwargs):  # abstract stub
            pass

    return _Emu(_FakeMem(base, data))


# ---------------------------------------------------------------------------
# read_mem_string
# ---------------------------------------------------------------------------

def test_read_mem_string_empty_ansi():
    """空字符串（首字节即终止符）。"""
    base = 0x10000
    emu = _make_emu(base, b"\x00")
    assert emu.read_mem_string(base, width=1) == ""


def test_read_mem_string_empty_unicode():
    """空 Unicode 字符串。"""
    base = 0x10000
    emu = _make_emu(base, b"\x00\x00")
    assert emu.read_mem_string(base, width=2) == ""


def test_read_mem_string_short_ansi():
    base = 0x10000
    emu = _make_emu(base, b"hello\x00garbage")
    assert emu.read_mem_string(base, width=1) == "hello"


def test_read_mem_string_short_unicode():
    base = 0x10000
    emu = _make_emu(base, "h\x00e\x00l\x00l\x00o\x00\x00\x00g\x00".encode("latin-1"))
    assert emu.read_mem_string(base, width=2) == "hello"


def test_read_mem_string_exactly_256_bytes():
    """字符串主体长度恰为 256 字节倍数（边界 1）。"""
    base = 0x10000
    payload = b"A" * 256 + b"\x00"
    emu = _make_emu(base, payload)
    assert emu.read_mem_string(base, width=1) == "A" * 256


def test_read_mem_string_cross_256_boundary():
    """字符串跨 256 字节边界：主体在第二块中结束。"""
    base = 0x10000
    # 250 字节在第一块，10 字节在第二块，共 260 字节主体
    payload = b"B" * 260 + b"\x00"
    emu = _make_emu(base, payload)
    assert emu.read_mem_string(base, width=1) == "B" * 260


def test_read_mem_string_cross_256_boundary_unicode():
    """Unicode 字符串跨 256 字节边界。"""
    base = 0x10000
    # 130 个 Unicode 字符 = 260 字节，跨过 256 边界
    payload = ("C\x00" * 130) + "\x00\x00"
    emu = _make_emu(base, payload.encode("latin-1"))
    assert emu.read_mem_string(base, width=2) == "C" * 130


def test_read_mem_string_long_multi_chunk():
    """长字符串跨越多个 256 字节块。"""
    base = 0x10000
    payload = b"D" * 800 + b"\x00"
    emu = _make_emu(base, payload)
    assert emu.read_mem_string(base, width=1) == "D" * 800


def test_read_mem_string_with_max_chars():
    """max_chars 限制读取字符数。"""
    base = 0x10000
    payload = b"abcdefgh\x00"
    emu = _make_emu(base, payload)
    # 即使有终止符，max_chars 也应优先限制
    assert emu.read_mem_string(base, width=1, max_chars=4) == "abcd"


def test_read_mem_string_max_chars_at_chunk_boundary():
    """max_chars 恰好对齐 256 字节块边界。"""
    base = 0x10000
    payload = b"E" * 512 + b"\x00"
    emu = _make_emu(base, payload)
    assert emu.read_mem_string(base, width=1, max_chars=256) == "E" * 256


def test_read_mem_string_no_terminator_until_end():
    """无终止符，读到内存末尾应返回所有可读字节。"""
    base = 0x10000
    payload = b"no terminator here"
    emu = _make_emu(base, payload)
    # 没有 \x00，应返回全部（decode 后）
    assert emu.read_mem_string(base, width=1) == "no terminator here"


def test_read_mem_string_unaligned_unicode_terminator():
    """Unicode width=2，终止符不在 width 边界时跳过。

    构造数据：在偏移 1 处出现 \x00\x00，但偏移 1 不是 width=2 的边界，
    算法应继续向后查找，直到偏移 4 的位置（合法终止符）。
    """
    base = 0x10000
    # 偏移 0,1 = 'A\x00'（合法字符 'A'）
    # 偏移 2,3 = '\x00A'（合法字符 U+4100）
    # 偏移 4,5 = '\x00\x00'（合法终止符，offset 4 % 2 == 0）
    payload = b"A\x00\x00A\x00\x00X\x00X\x00\x00\x00"
    emu = _make_emu(base, payload)
    # 第一个合法的 width 边界终止符在偏移 4
    # buf 应为前 4 字节: b'A\x00\x00A' -> decode utf-16le -> 'A' + U+4100
    result = emu.read_mem_string(base, width=2)
    assert result == "A\u4100"


# ---------------------------------------------------------------------------
# mem_string_len
# ---------------------------------------------------------------------------

def test_mem_string_len_empty():
    base = 0x10000
    emu = _make_emu(base, b"\x00")
    assert emu.mem_string_len(base, width=1) == 0


def test_mem_string_len_short_ansi():
    base = 0x10000
    emu = _make_emu(base, b"hello\x00world")
    assert emu.mem_string_len(base, width=1) == 5


def test_mem_string_len_short_unicode():
    base = 0x10000
    payload = ("h\x00e\x00l\x00l\x00o\x00\x00\x00").encode("latin-1")
    emu = _make_emu(base, payload)
    assert emu.mem_string_len(base, width=2) == 5


def test_mem_string_len_exactly_256():
    base = 0x10000
    payload = b"A" * 256 + b"\x00"
    emu = _make_emu(base, payload)
    assert emu.mem_string_len(base, width=1) == 256


def test_mem_string_len_cross_256_boundary():
    base = 0x10000
    payload = b"B" * 300 + b"\x00"
    emu = _make_emu(base, payload)
    assert emu.mem_string_len(base, width=1) == 300


def test_mem_string_len_cross_256_unicode():
    base = 0x10000
    # 130 个 utf-16le 字符 = 260 字节，跨 256 边界
    payload = ("C\x00" * 130) + "\x00\x00"
    emu = _make_emu(base, payload.encode("latin-1"))
    assert emu.mem_string_len(base, width=2) == 130


def test_mem_string_len_no_terminator():
    """无终止符：长度为整块可读内存（按字符计）。"""
    base = 0x10000
    payload = b"abcdef"  # 6 字节，无 \x00
    emu = _make_emu(base, payload)
    assert emu.mem_string_len(base, width=1) == 6


# ---------------------------------------------------------------------------
# _patch_imports
# ---------------------------------------------------------------------------

class _FakePeParser:
    """最小化的 _PeParser 替身，用于隔离 _patch_imports 测试。

    只复刻 _patch_imports 所需的属性：base / mapped_image / imports /
    imp_id / imp_step / ptr_size / import_table。
    """

    # 复用 _PeParser._patch_imports 实现
    def _patch_imports(self):
        # 直接复用源文件中的实现，保证测试针对真实代码
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
        # 初始化镜像：每个字节都用 0xAA 填充，便于检测 in-place 修改是否破坏其他区域
        self.mapped_image = bytes([0xAA]) * image_size


def _patched_byte(emu, addr):
    """读取镜像中指定地址处的 ptr_size 字节（小端）。"""
    offset = addr - emu.base
    return emu.mapped_image[offset:offset + emu.ptr_size]


def _bytes_to_int(b):
    return int.from_bytes(b, "little")


def test_patch_imports_writes_correct_ids():
    """_patch_imports 应在每个导入地址处写入递增的 imp_id。"""
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
        written = _bytes_to_int(_patched_byte(pe, addr))
        assert written == expected_id, (
            f"addr 0x{addr:x}: expected id 0x{expected_id:x}, got 0x{written:x}"
        )
        assert pe.import_table[expected_id] == imp
        expected_id += 4


def test_patch_imports_preserves_other_bytes():
    """in-place 修改不应破坏未涉及导入的镜像区域。"""
    base = 0x400000
    image_size = 0x1000
    imports = {
        base + 0x100: ("kernel32.dll", "ExitProcess"),
        base + 0x200: ("kernel32.dll", "GetProcAddress"),
    }
    pe = _FakePeParser(base, image_size, imports, ptr_size=4)
    original = bytes(pe.mapped_image)

    pe._patch_imports()

    # 检查每个字节：要么是原始 0xAA，要么是被 patch 的导入地址范围
    patched_ranges = []
    expected_id = 0x70000000
    for addr in imports:
        off = addr - base
        patched_ranges.append((off, off + pe.ptr_size))
        expected_id += pe.imp_step

    corrupted = []
    for i, b in enumerate(pe.mapped_image):
        if b == 0xAA:
            continue
        # 必须落在某个 patch 范围内
        in_patched = any(lo <= i < hi for lo, hi in patched_ranges)
        if not in_patched:
            corrupted.append(i)
    assert not corrupted, f"非导入区域被破坏，偏移: {corrupted[:10]}"

    # 在 patch 范围内的字节必须正好是 imp_id 的 little-endian 编码
    expected_id = 0x70000000
    for addr in imports:
        off = addr - base
        expected_bytes = expected_id.to_bytes(pe.ptr_size, "little")
        actual = pe.mapped_image[off:off + pe.ptr_size]
        assert actual == expected_bytes, (
            f"addr 0x{addr:x}: expected {expected_bytes.hex()}, got {actual.hex()}"
        )
        expected_id += pe.imp_step


def test_patch_imports_empty_imports():
    """无导入时不应修改镜像。"""
    base = 0x400000
    image_size = 0x1000
    pe = _FakePeParser(base, image_size, {}, ptr_size=4)
    original = bytes(pe.mapped_image)
    pe._patch_imports()
    assert pe.mapped_image == original


def test_patch_imports_x64_ptr_size():
    """x64（ptr_size=8）下应写入 8 字节 imp_id。"""
    base = 0x180000000
    image_size = 0x2000
    imports = {
        base + 0x500: ("ntdll.dll", "NtCreateFile"),
    }
    pe = _FakePeParser(base, image_size, imports, ptr_size=8,
                       imp_id=0x7000000000000000, imp_step=8)
    pe._patch_imports()

    off = (base + 0x500) - base
    actual = pe.mapped_image[off:off + 8]
    assert actual == (0x7000000000000000).to_bytes(8, "little")
    # 其他字节保持不变
    for i, b in enumerate(pe.mapped_image):
        if i == 0x500:
            continue
        if 0x500 <= i < 0x508:
            continue
        assert b == 0xAA, f"非导入区域被破坏：偏移 0x{i:x}"


def test_patch_imports_image_type_is_bytes():
    """patch 后 mapped_image 仍应为不可变 bytes（循环末尾 bytes(ba)）。"""
    base = 0x400000
    image_size = 0x100
    imports = {base + 0x10: ("kernel32.dll", "ExitProcess")}
    pe = _FakePeParser(base, image_size, imports, ptr_size=4)
    pe._patch_imports()
    assert isinstance(pe.mapped_image, bytes), (
        f"mapped_image 应为 bytes，实际为 {type(pe.mapped_image)}"
    )
