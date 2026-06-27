"""
P0 优化后 struct.py 核心功能验证脚本。

覆盖项：
- P0-7: create_struct 字段列表类级缓存（缓存键含模块限定名）
- P0-8: __getattribute__/__setattr__ 改用 _field_name_map O(1) 字典查找
- create_struct 创建常见 Windows 结构体
- 字段读写正确（__getattribute__ 和 __setattr__）
- 不同指针大小（32位/64位）下结构体大小正确
- get_bytes() 返回正确的字节序列
- _deep_cast（cast）功能
- 嵌套结构体
- 指针数组字段
- 缓存复用（同 (类, ptr_size) 多次创建实例结果一致）
"""

import ctypes as ct

import pytest

from speakeasy.struct import EmuStruct, Ptr, _STRUCT_CACHE


# --------------------------------------------------------------------------
# 镜像 Windows PE 结构体定义（仅用于测试，不依赖 pefile）
# --------------------------------------------------------------------------

class IMAGE_DOS_HEADER(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.e_magic = ct.c_uint16
        self.e_cblp = ct.c_uint16
        self.e_cp = ct.c_uint16
        self.e_crlc = ct.c_uint16
        self.e_cparhdr = ct.c_uint16
        self.e_minalloc = ct.c_uint16
        self.e_maxalloc = ct.c_uint16
        self.e_ss = ct.c_uint16
        self.e_sp = ct.c_uint16
        self.e_csum = ct.c_uint16
        self.e_ip = ct.c_uint16
        self.e_cs = ct.c_uint16
        self.e_lfarlc = ct.c_uint16
        self.e_ovno = ct.c_uint16
        self.e_res = ct.c_uint16 * 4
        self.e_oemid = ct.c_uint16
        self.e_oeminfo = ct.c_uint16
        self.e_res2 = ct.c_uint16 * 10
        self.e_lfanew = ct.c_uint32


class IMAGE_FILE_HEADER(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.Machine = ct.c_uint16
        self.NumberOfSections = ct.c_uint16
        self.TimeDateStamp = ct.c_uint32
        self.PointerToSymbolTable = ct.c_uint32
        self.NumberOfSymbols = ct.c_uint32
        self.SizeOfOptionalHeader = ct.c_uint16
        self.Characteristics = ct.c_uint16


class IMAGE_OPTIONAL_HEADER32(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.Magic = ct.c_uint16
        self.MajorLinkerVersion = ct.c_uint8
        self.MinorLinkerVersion = ct.c_uint8
        self.SizeOfCode = ct.c_uint32
        self.AddressOfEntryPoint = ct.c_uint32
        self.ImageBase = ct.c_uint32
        self.SectionAlignment = ct.c_uint32
        self.SizeOfImage = ct.c_uint32


class IMAGE_OPTIONAL_HEADER64(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.Magic = ct.c_uint16
        self.MajorLinkerVersion = ct.c_uint8
        self.MinorLinkerVersion = ct.c_uint8
        self.SizeOfCode = ct.c_uint32
        self.AddressOfEntryPoint = ct.c_uint32
        self.ImageBase = ct.c_uint64
        self.SectionAlignment = ct.c_uint32
        self.SizeOfImage = ct.c_uint32


class IMAGE_NT_HEADERS32(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.Signature = ct.c_uint32
        self.FileHeader = IMAGE_FILE_HEADER
        self.OptionalHeader = IMAGE_OPTIONAL_HEADER32


class IMAGE_NT_HEADERS64(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.Signature = ct.c_uint32
        self.FileHeader = IMAGE_FILE_HEADER
        self.OptionalHeader = IMAGE_OPTIONAL_HEADER64


class POINTER_ARRAY_STRUCT(EmuStruct):
    """含 Ptr 数组字段，用于验证 P0 缓存路径对数组字段的重建"""
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.Count = ct.c_uint32
        self.Entries = Ptr * 4


# --------------------------------------------------------------------------
# 测试用例
# --------------------------------------------------------------------------

def test_image_dos_header_sizeof_32_and_64():
    """IMAGE_DOS_HEADER 在 32 位与 64 位下大小都应为 64 字节（pack=1，无指针字段）"""
    dos32 = IMAGE_DOS_HEADER(4)
    dos64 = IMAGE_DOS_HEADER(8)
    assert dos32.sizeof() == 64
    assert dos64.sizeof() == 64


def test_image_dos_header_field_read_write():
    """验证 __setattr__/__getattribute__ 对标量与数组字段的读写"""
    dos = IMAGE_DOS_HEADER(4)
    dos.e_magic = 0x5A4D          # "MZ"
    dos.e_lfanew = 0x000000F0
    dos.e_res = (0x1111, 0x2222, 0x3333, 0x4444)
    dos.e_res2 = (0,) * 10

    assert dos.e_magic == 0x5A4D
    assert dos.e_lfanew == 0x000000F0
    assert tuple(dos.e_res[i] for i in range(4)) == (0x1111, 0x2222, 0x3333, 0x4444)


def test_image_dos_header_get_bytes_roundtrip():
    """get_bytes() 应返回正确的字节序列，且 cast 回来后字段保持一致"""
    dos = IMAGE_DOS_HEADER(4)
    dos.e_magic = 0x5A4D
    dos.e_lfanew = 0x000000F0

    bytez = dos.get_bytes()
    assert len(bytez) == 64
    # MZ 是小端，应为 4D 5A
    assert bytez[:2] == b"\x4D\x5A"
    # e_lfanew 在偏移 0x3C（60），小端 F0 00 00 00
    assert bytez[60:64] == b"\xF0\x00\x00\x00"

    # cast 回来
    dos2 = IMAGE_DOS_HEADER(4)
    dos2.cast(bytez)
    assert dos2.e_magic == 0x5A4D
    assert dos2.e_lfanew == 0x000000F0


def test_image_nt_headers32_nested_field_access():
    """验证嵌套结构体的字段读写（FileHeader / OptionalHeader 都是 filter 类）"""
    nt = IMAGE_NT_HEADERS32(4)
    nt.Signature = 0x00004550  # "PE\0\0"
    nt.FileHeader.Machine = 0x014C            # IMAGE_FILE_MACHINE_I386
    nt.FileHeader.NumberOfSections = 3
    nt.OptionalHeader.Magic = 0x010B          # PE32
    nt.OptionalHeader.AddressOfEntryPoint = 0x1000
    nt.OptionalHeader.ImageBase = 0x00400000

    assert nt.Signature == 0x00004550
    assert nt.FileHeader.Machine == 0x014C
    assert nt.FileHeader.NumberOfSections == 3
    assert nt.OptionalHeader.Magic == 0x010B
    assert nt.OptionalHeader.AddressOfEntryPoint == 0x1000
    assert nt.OptionalHeader.ImageBase == 0x00400000


def test_image_nt_headers32_vs_64_sizeof():
    """32 位 NT 头小于 64 位 NT 头（OptionalHeader64 中 ImageBase 为 uint64）"""
    nt32 = IMAGE_NT_HEADERS32(4)
    nt64 = IMAGE_NT_HEADERS64(8)
    # PE32+ OptionalHeader 比 PE32 多 4 字节（ImageBase 32->64）
    assert nt64.sizeof() > nt32.sizeof()
    # 基本尺寸（pack=1）：
    #   Signature(4) + FileHeader(20) + OptionalHeader32(24) = 48
    #   Signature(4) + FileHeader(20) + OptionalHeader64(28) = 52
    assert nt32.sizeof() == 48
    assert nt64.sizeof() == 52


def test_image_nt_headers_get_bytes_and_cast():
    """嵌套结构体 get_bytes + cast 回环"""
    nt = IMAGE_NT_HEADERS32(4)
    nt.Signature = 0x00004550
    nt.FileHeader.Machine = 0x014C
    nt.FileHeader.NumberOfSections = 3
    nt.OptionalHeader.Magic = 0x010B
    nt.OptionalHeader.AddressOfEntryPoint = 0x1000

    bytez = nt.get_bytes()
    assert len(bytez) == 48
    # "PE\0\0"
    assert bytez[:4] == b"\x50\x45\x00\x00"

    nt2 = IMAGE_NT_HEADERS32(4)
    nt2.cast(bytez)
    assert nt2.Signature == 0x00004550
    assert nt2.FileHeader.Machine == 0x014C
    assert nt2.FileHeader.NumberOfSections == 3
    assert nt2.OptionalHeader.Magic == 0x010B
    assert nt2.OptionalHeader.AddressOfEntryPoint == 0x1000


def test_pointer_array_struct_32_and_64():
    """Ptr 数组字段在 32 位 / 64 位下大小不同"""
    s32 = POINTER_ARRAY_STRUCT(4)
    s64 = POINTER_ARRAY_STRUCT(8)
    # Count(4) + 4 * ptr_size
    assert s32.sizeof() == 4 + 4 * 4
    assert s64.sizeof() == 4 + 8 * 4

    s32.Count = 2
    s32.Entries[0] = 0xDEADBEEF
    s32.Entries[1] = 0xCAFEBABE
    assert s32.Count == 2
    assert s32.Entries[0] == 0xDEADBEEF
    assert s32.Entries[1] == 0xCAFEBABE

    bytez = s32.get_bytes()
    assert len(bytez) == 20
    # 第一个指针（偏移 4，4 字节，小端）
    assert bytez[4:8] == b"\xEF\xBE\xAD\xDE"


def test_struct_cache_reused_across_instances():
    """P0-7: 同 (类, ptr_size) 的多次实例化应复用缓存，且行为一致"""
    cache_key = f"{IMAGE_DOS_HEADER.__module__}.IMAGE_DOS_HEADER_4"
    # 清空缓存以测试首次构建
    if cache_key in _STRUCT_CACHE:
        del _STRUCT_CACHE[cache_key]

    dos_a = IMAGE_DOS_HEADER(4)
    assert cache_key in _STRUCT_CACHE
    cached_after_first = _STRUCT_CACHE[cache_key]

    dos_b = IMAGE_DOS_HEADER(4)
    # 缓存对象应被复用（同一个 namedtuple）
    assert _STRUCT_CACHE[cache_key] is cached_after_first

    # 两个实例行为应一致：写入不同值互不干扰（filtermap 是按实例重建的）
    dos_a.e_magic = 0x1111
    dos_b.e_magic = 0x2222
    assert dos_a.e_magic == 0x1111
    assert dos_b.e_magic == 0x2222


def test_field_name_map_populated_after_create():
    """P0-8: create_struct 后类级 _field_name_map 应被填充且包含所有字段"""
    dos = IMAGE_DOS_HEADER(4)
    fnm = type(dos)._field_name_map
    assert fnm is not None
    expected = {
        "e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc",
        "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc",
        "e_ovno", "e_res", "e_oemid", "e_oeminfo", "e_res2", "e_lfanew",
    }
    assert expected.issubset(set(fnm.keys()))


def test_field_name_map_for_nested_and_ptr_array():
    """P0-8: 嵌套字段标记 filtered=True，Ptr 数组字段 filtered=False"""
    nt = IMAGE_NT_HEADERS32(4)
    fnm = type(nt)._field_name_map
    # FileHeader / OptionalHeader 是嵌套 EmuStruct -> filtered=True
    assert fnm["FileHeader"][1] is True
    assert fnm["OptionalHeader"][1] is True
    # Signature 是普通 ctype -> filtered=False
    assert fnm["Signature"][1] is False

    s = POINTER_ARRAY_STRUCT(4)
    fnm2 = type(s)._field_name_map
    # Entries 是 Ptr 数组 -> filtered=False（不是 EmuStruct 数组）
    assert fnm2["Entries"][1] is False
    assert fnm2["Count"][1] is False


def test_setattr_with_bytes_for_array_field():
    """验证 bytes 赋值给字节数组字段（__setattr__ 中的 bytes 分支）。

    e_res 是 c_uint16 * 4（4 元素），按 struct.py 中 bytes 分支语义
    `barray[:len(value)] = value`，value 长度需等于元素数（每字节赋给一个元素）。
    """
    dos = IMAGE_DOS_HEADER(4)
    # 4 字节赋给 4 个 uint16 元素，每个元素取一字节值
    dos.e_res = b"\x11\x22\x33\x44"
    assert dos.e_res[0] == 0x0011
    assert dos.e_res[1] == 0x0022
    assert dos.e_res[2] == 0x0033
    assert dos.e_res[3] == 0x0044


def test_deep_cast_with_offset_advancement():
    """验证 _deep_cast 在含嵌套结构体时正确推进偏移。

    使用 IMAGE_NT_HEADERS64 以容纳 64 位 ImageBase（0x180000000 超出 uint32）。
    """
    nt = IMAGE_NT_HEADERS64(8)
    nt.Signature = 0x00004550
    nt.FileHeader.Machine = 0x8664
    nt.FileHeader.NumberOfSections = 7
    nt.OptionalHeader.Magic = 0x020B
    nt.OptionalHeader.ImageBase = 0x180000000

    bytez = nt.get_bytes()

    nt2 = IMAGE_NT_HEADERS64(8)
    nt2.cast(bytez)
    assert nt2.Signature == 0x00004550
    assert nt2.FileHeader.Machine == 0x8664
    assert nt2.FileHeader.NumberOfSections == 7
    assert nt2.OptionalHeader.Magic == 0x020B
    assert nt2.OptionalHeader.ImageBase == 0x180000000


def test_module_qualified_cache_key_isolation():
    """P0-7: 缓存键含模块限定名，避免跨模块同名类冲突"""
    # 在另一个模块作用域中定义同名类
    import types

    other_mod = types.ModuleType("other_mod_for_struct_test")
    code = (
        "import ctypes as ct\n"
        "from speakeasy.struct import EmuStruct\n"
        "class IMAGE_DOS_HEADER(EmuStruct):\n"
        "    def __init__(self, ptr_size):\n"
        "        super().__init__(ptr_size, pack=1)\n"
        "        self.e_magic = ct.c_uint16\n"
        "        self.e_lfanew = ct.c_uint32\n"
    )
    exec(code, other_mod.__dict__)

    other_cls = other_mod.IMAGE_DOS_HEADER
    # 此处定义的 IMAGE_DOS_HEADER 与本模块的属性不同（字段更少），缓存键必须隔离
    local_inst = IMAGE_DOS_HEADER(4)
    other_inst = other_cls(4)

    assert local_inst.sizeof() == 64
    assert other_inst.sizeof() == 6  # uint16 + uint32

    # 两个缓存键都存在
    local_key = f"{IMAGE_DOS_HEADER.__module__}.IMAGE_DOS_HEADER_4"
    other_key = "other_mod_for_struct_test.IMAGE_DOS_HEADER_4"
    assert local_key in _STRUCT_CACHE
    assert other_key in _STRUCT_CACHE


def test_get_field_name_returns_correct_field():
    """验证 get_field_name 在偏移定位上的正确性"""
    dos = IMAGE_DOS_HEADER(4)
    # e_magic 在偏移 0
    assert dos.get_field_name(0) == "e_magic"
    # e_lfanew 在偏移 0x3C（60）
    assert dos.get_field_name(60) == "e_lfanew"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v", "-p", "no:faulthandler", "--tb=short"]))
