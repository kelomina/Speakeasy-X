# Copyright (C) 2026 Speakeasy-X

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.api.generated as generated

ROOT = Path(__file__).resolve().parent.parent

# Imports that are NOT covered by any real API handler and must resolve to the
# generated stubs (each verified to exist in the generated tables).
SMOKE_IMPORTS = [
    ("kernelbase", "GetPackagePathByFullName"),
    ("ntdll", "RtlQueryWnfStateData"),
    ("user32", "IsMenu"),
    ("msvcrt", "_wcsicoll"),
    ("shell32", "SHGetFolderPathEx"),
    ("rpcrt4", "NdrClientCall3"),
    ("advapi32", "LsaOpenPolicy"),
    ("oleaut32", "VarFormat"),
    ("version", "GetFileVersionInfoSizeExW"),
    ("gdi32", "GetFontUnicodeRanges"),
    ("ole32", "BindMoniker"),
    # Data export: resolved to a zero-initialized slot at load time.
    ("msvcrt", "_iob"),
]

STUB_FUNC_IMPORTS = [i for i in SMOKE_IMPORTS if not (i[0] == "msvcrt" and i[1] == "_iob")]


@pytest.fixture(scope="session")
def gen_module():
    spec = importlib.util.spec_from_file_location(
        "gen_api_stubs", ROOT / "tools" / "gen_api_stubs.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gen_api_stubs"] = mod
    spec.loader.exec_module(mod)
    return mod


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def build_pe(bits, imports, get_argc, data_imports=()):
    """
    Build a minimal PE whose entry point calls each function import via its IAT
    slot and finally reads the data import (e.g. msvcrt._iob) into EAX/RAX so
    the entry point return value proves the data stub slot resolves to zero.
    Data imports must not be called as functions - their IAT slots hold data
    pointers, not code sentinels.

    The x86 code pushes `get_argc(dll, name)` dummy arguments per call so the
    stdcall stack stays balanced; the x64 code only reserves shadow space.
    """
    is64 = bits == 64
    ptr = 8 if is64 else 4
    image_base = 0x140000000 if is64 else 0x400000
    magic = 0x20B if is64 else 0x10B
    opt_size = 240 if is64 else 224
    machine = 0x8664 if is64 else 0x14C
    entry = 0x1000
    text_rva = 0x1000
    idata_rva = 0x2000
    text_raw = 0x200
    idata_raw = 0x400
    file_align = 0x200
    sect_align = 0x1000

    groups = []
    by_dll = {}
    for dll, name in imports:
        by_dll.setdefault(dll.lower(), []).append(name)
    for dll, names in by_dll.items():
        groups.append((dll, names))

    off = 0
    desc_off = []
    for _ in groups:
        desc_off.append(off)
        off += 20
    off += 20  # terminating null descriptor
    int_off, iat_off, hint_off, dll_off = [], [], [], []
    for _dll, names in groups:
        int_off.append(off)
        off += (len(names) + 1) * ptr
        iat_off.append(off)
        off += (len(names) + 1) * ptr
    for _dll, names in groups:
        hint_off.append(off)
        off += sum(2 + len(n) + 1 for n in names)
    for dll, _names in groups:
        dll_off.append(off)
        off += len(dll) + 8
    idata_size = _align(off, file_align)

    idata = bytearray(idata_size)
    for i, (dll, names) in enumerate(groups):
        struct.pack_into("<I", idata, desc_off[i] + 0, idata_rva + int_off[i])
        struct.pack_into("<I", idata, desc_off[i] + 12, idata_rva + dll_off[i])
        struct.pack_into("<I", idata, desc_off[i] + 16, idata_rva + iat_off[i])
        hoff = hint_off[i]
        for j, nm in enumerate(names):
            hnm_rva = idata_rva + hoff
            struct.pack_into("<H", idata, hoff, 0)
            hoff += 2
            idata[hoff : hoff + len(nm) + 1] = nm.encode("utf-8") + b"\x00"
            hoff += len(nm) + 1
            struct.pack_into("<I", idata, int_off[i] + j * ptr, hnm_rva)
            struct.pack_into("<I", idata, iat_off[i] + j * ptr, hnm_rva)
        doff = dll_off[i]
        idata[doff : doff + len(dll) + 1] = dll.encode("utf-8") + b"\x00"

    code = bytearray()
    if is64:
        code += b"\x48\x83\xEC\x28"  # sub rsp, 0x28 (shadow space)
    for i, (_dll, names) in enumerate(groups):
        for j, nm in enumerate(names):
            if (_dll, nm) in data_imports:
                continue  # data import: its IAT slot holds a data pointer, not code
            iat_va = image_base + idata_rva + iat_off[i] + j * ptr
            if is64:
                insn_va = image_base + entry + len(code)
                disp = iat_va - (insn_va + 6)
                code += b"\xFF\x15" + struct.pack("<i", disp)  # call [rip+disp]
            else:
                for _ in range(get_argc(_dll, nm)):
                    code += b"\x6A\x00"  # push 0
                code += b"\xFF\x15" + struct.pack("<I", iat_va)  # call [abs]
    # Read the data import slot: eax = [iat]; eax = [eax] -> 0 from stub slot.
    if is64:
        data_slot = None
        for i, (_dll, names) in enumerate(groups):
            for j, nm in enumerate(names):
                if _dll == "msvcrt" and nm == "_iob":
                    data_slot = image_base + idata_rva + iat_off[i] + j * ptr
        code += b"\x48\xA1" + struct.pack("<Q", data_slot)  # mov rax, [abs]
        code += b"\x8B\x00"  # mov eax, [rax]
        code += b"\x48\x83\xC4\x28"  # add rsp, 0x28
        code += b"\xC3"  # ret
    else:
        data_slot = None
        for i, (_dll, names) in enumerate(groups):
            for j, nm in enumerate(names):
                if _dll == "msvcrt" and nm == "_iob":
                    data_slot = image_base + idata_rva + iat_off[i] + j * ptr
        code += b"\xA1" + struct.pack("<I", data_slot)  # mov eax, [abs]
        code += b"\x8B\x00"  # mov eax, [eax]
        code += b"\xC3"  # ret
    text_size = _align(len(code), file_align)
    idata_raw_size = _align(len(idata), file_align)

    pe = bytearray(0x200)  # headers
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)  # e_lfanew
    struct.pack_into("<I", pe, 0x80, 0x4550)  # PE\0\0
    struct.pack_into("<H", pe, 0x84, machine)
    struct.pack_into("<H", pe, 0x86, 2)  # NumberOfSections
    struct.pack_into("<I", pe, 0x88, 0)  # TimeDateStamp
    struct.pack_into("<I", pe, 0x8C, 0)  # PointerToSymbolTable
    struct.pack_into("<I", pe, 0x90, 0)  # NumberOfSymbols
    struct.pack_into("<H", pe, 0x94, opt_size)
    struct.pack_into("<H", pe, 0x96, 0x0102)  # Characteristics (EXE)

    oh = 0x98  # optional header base
    struct.pack_into("<H", pe, oh + 0x00, magic)
    struct.pack_into("<B", pe, oh + 0x02, 0)  # MajorLinkerVersion
    struct.pack_into("<B", pe, oh + 0x03, 0)  # MinorLinkerVersion
    struct.pack_into("<I", pe, oh + 0x04, text_size)  # SizeOfCode
    struct.pack_into("<I", pe, oh + 0x08, idata_raw_size)  # SizeOfInitializedData
    struct.pack_into("<I", pe, oh + 0x0C, 0)  # SizeOfUninitializedData
    struct.pack_into("<I", pe, oh + 0x10, entry)  # AddressOfEntryPoint
    struct.pack_into("<I", pe, oh + 0x14, text_rva)  # BaseOfCode
    if is64:
        struct.pack_into("<Q", pe, oh + 0x18, image_base)
        sa, fa, sub = oh + 0x20, oh + 0x24, oh + 0x30
        soff, soh, checksum = oh + 0x38, oh + 0x3C, oh + 0x40
        sstack_r, sstack_c = oh + 0x48, oh + 0x50
        sheap_r, sheap_c = oh + 0x58, oh + 0x60
        nrv = oh + 0x6C
        dd = oh + 0x70
    else:
        struct.pack_into("<I", pe, oh + 0x18, 0x2000)  # BaseOfData
        struct.pack_into("<I", pe, oh + 0x1C, image_base)
        sa, fa, sub = oh + 0x20, oh + 0x24, oh + 0x30
        soff, soh, checksum = oh + 0x38, oh + 0x3C, oh + 0x40
        sstack_r, sstack_c = oh + 0x48, oh + 0x4C
        sheap_r, sheap_c = oh + 0x50, oh + 0x54
        nrv = oh + 0x5C
        dd = oh + 0x60
    struct.pack_into("<I", pe, sa, sect_align)
    struct.pack_into("<I", pe, fa, file_align)
    struct.pack_into("<H", pe, sub + 0, 6)  # MajorOperatingSystemVersion
    struct.pack_into("<H", pe, sub + 2, 0)  # MinorOperatingSystemVersion
    struct.pack_into("<H", pe, sub + 4, 6)  # MajorSubsystemVersion
    struct.pack_into("<H", pe, sub + 6, 0)  # MinorSubsystemVersion
    struct.pack_into("<I", pe, soff, 0x3000)  # SizeOfImage
    struct.pack_into("<I", pe, soh, 0x200)  # SizeOfHeaders
    struct.pack_into("<I", pe, checksum, 0)
    struct.pack_into("<H", pe, oh + 0x44, 2)  # Subsystem (GUI)
    struct.pack_into("<H", pe, oh + 0x46, 0)  # DllCharacteristics
    if is64:
        struct.pack_into("<Q", pe, sstack_r, 0x100000)
        struct.pack_into("<Q", pe, sstack_c, 0x1000)
        struct.pack_into("<Q", pe, sheap_r, 0x100000)
        struct.pack_into("<Q", pe, sheap_c, 0x1000)
    else:
        struct.pack_into("<I", pe, sstack_r, 0x100000)
        struct.pack_into("<I", pe, sstack_c, 0x1000)
        struct.pack_into("<I", pe, sheap_r, 0x100000)
        struct.pack_into("<I", pe, sheap_c, 0x1000)
    struct.pack_into("<I", pe, nrv, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<I", pe, dd + 8, idata_rva)  # DataDirectory[1].VirtualAddress (IMPORT)
    struct.pack_into("<I", pe, dd + 12, idata_size)  # DataDirectory[1].Size

    # Section headers
    sh = 0x98 + opt_size
    for idx, (name, rva, raw, size, vaddr, vsize, chars) in enumerate(
        [
            (b".text", text_rva, text_raw, text_size, text_rva, len(code), 0x60000020),
            (b".idata", idata_rva, idata_raw, idata_raw_size, idata_rva, len(idata), 0xC0000040),
        ]
    ):
        base = sh + idx * 40
        pe[base : base + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<I", pe, base + 8, vsize)  # VirtualSize
        struct.pack_into("<I", pe, base + 12, vaddr)  # VirtualAddress
        struct.pack_into("<I", pe, base + 16, size)  # SizeOfRawData
        struct.pack_into("<I", pe, base + 20, raw)  # PointerToRawData
        struct.pack_into("<I", pe, base + 24, 0)  # PointerToRelocations
        struct.pack_into("<I", pe, base + 28, 0)  # PointerToLinenumbers
        struct.pack_into("<H", pe, base + 32, 0)  # NumberOfRelocations
        struct.pack_into("<H", pe, base + 34, 0)  # NumberOfLinenumbers
        struct.pack_into("<I", pe, base + 36, chars)

    blob = bytes(pe) + bytes(code).ljust(text_size, b"\x00") + bytes(idata).ljust(idata_raw_size, b"\x00")
    return blob


def build_pe_calls(bits, calls, data_specs, tail_load=None, argc_map=None, cdecl=()):
    """
    Build a minimal PE that calls each entry in `calls` with integer arguments
    (absolute addresses / literal values) and returns with the result of the
    last call in EAX/RAX. `data_specs` maps labels to raw bytes placed in a
    read-write .data section; the returned dict maps labels to their virtual
    addresses. `tail_load` optionally loads [addr] into EAX/RAX just before
    returning. `argc_map` supplies (dll, name) -> argc used for x86 stdcall
    stack balancing; `cdecl` lists (dll, name) pairs whose stack args are
    cleaned by the caller on x86.
    """
    imports = [(dll, name) for dll, name, _args in calls]
    is64 = bits == 64
    ptr = 8 if is64 else 4
    image_base = 0x140000000 if is64 else 0x400000
    entry = 0x1000
    text_rva = 0x1000
    idata_rva = 0x2000
    data_rva = 0x3000
    text_raw = 0x200
    idata_raw = 0x400
    data_raw = 0x600
    file_align = 0x200
    sect_align = 0x1000
    magic = 0x20B if is64 else 0x10B
    opt_size = 240 if is64 else 224
    machine = 0x8664 if is64 else 0x14C

    groups = []
    by_dll = {}
    for dll, name in imports:
        by_dll.setdefault(dll.lower(), []).append(name)
    for dll, names in by_dll.items():
        groups.append((dll, names))

    off = 0
    desc_off = []
    for _ in groups:
        desc_off.append(off)
        off += 20
    off += 20
    int_off, iat_off, hint_off, dll_off = [], [], [], []
    for _dll, names in groups:
        int_off.append(off)
        off += (len(names) + 1) * ptr
        iat_off.append(off)
        off += (len(names) + 1) * ptr
    for _dll, names in groups:
        hint_off.append(off)
        off += sum(2 + len(n) + 1 for n in names)
    for dll, _names in groups:
        dll_off.append(off)
        off += len(dll) + 8
    idata_size = _align(off, file_align)

    idata = bytearray(idata_size)
    for i, (dll, names) in enumerate(groups):
        struct.pack_into("<I", idata, desc_off[i] + 0, idata_rva + int_off[i])
        struct.pack_into("<I", idata, desc_off[i] + 12, idata_rva + dll_off[i])
        struct.pack_into("<I", idata, desc_off[i] + 16, idata_rva + iat_off[i])
        hoff = hint_off[i]
        for j, nm in enumerate(names):
            hnm_rva = idata_rva + hoff
            struct.pack_into("<H", idata, hoff, 0)
            hoff += 2
            idata[hoff : hoff + len(nm) + 1] = nm.encode("utf-8") + b"\x00"
            hoff += len(nm) + 1
            struct.pack_into("<I", idata, int_off[i] + j * ptr, hnm_rva)
            struct.pack_into("<I", idata, iat_off[i] + j * ptr, hnm_rva)
        doff = dll_off[i]
        idata[doff : doff + len(dll) + 1] = dll.encode("utf-8") + b"\x00"

    data_blob = bytearray()
    addrs = {}
    for label, raw in data_specs.items():
        addrs[label] = image_base + data_rva + len(data_blob)
        data_blob += raw
    data_size = _align(len(data_blob), file_align)

    # resolve IAT slot for each call
    slot_va = {}
    for i, (_dll, names) in enumerate(groups):
        for j, nm in enumerate(names):
            slot_va[(_dll, nm)] = image_base + idata_rva + iat_off[i] + j * ptr

    code = bytearray()
    if is64:
        code += b"\x48\x83\xEC\x28"  # sub rsp, 0x28
    for dll, name, args in calls:
        iat_va = slot_va[(dll.lower(), name)]
        args = [addrs[a] if isinstance(a, str) else a for a in args]
        if is64:
            for val in reversed(args[:4]):
                code += b"\x48\xB8" + struct.pack("<Q", val)  # mov rax, imm64
                code += b"\x50"  # push rax
            # pop into rcx,rdx,r8,r9 in order
            regs = [b"\x59", b"\x5A", b"\x41\x58", b"\x41\x59"]  # pop rcx/rdx/r8/r9
            for k in range(min(len(args), 4)):
                code += regs[k]
            insn_va = image_base + entry + len(code)
            disp = iat_va - (insn_va + 6)
            code += b"\xFF\x15" + struct.pack("<i", disp)  # call [rip+disp]
        else:
            is_cdecl = (dll.lower(), name) in cdecl
            argc = len(args) if is_cdecl else (argc_map or {}).get((dll.lower(), name), len(args))
            for val in reversed(args):
                code += b"\x68" + struct.pack("<I", val & 0xFFFFFFFF)  # push imm32
            if not is_cdecl:
                for _ in range(max(argc - len(args), 0)):
                    code += b"\x6A\x00"  # push 0 padding
            code += b"\xFF\x15" + struct.pack("<I", iat_va)  # call [abs]
            if is_cdecl and len(args):
                code += b"\x83\xC4" + struct.pack("<B", 4 * len(args))  # add esp, n*4
        if tail_load is not None:
            tail_load = addrs[tail_load] if isinstance(tail_load, str) else tail_load
            if is64:
                code += b"\x48\xA1" + struct.pack("<Q", tail_load)  # mov rax, [imm64]
            else:
                code += b"\xA1" + struct.pack("<I", tail_load)  # mov eax, [imm32]
    if is64:
        code += b"\x48\x83\xC4\x28"  # add rsp, 0x28
        code += b"\xC3"
    else:
        code += b"\xC3"
    text_size = _align(len(code), file_align)
    idata_raw_size = _align(len(idata), file_align)

    pe = bytearray(0x200)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    struct.pack_into("<I", pe, 0x80, 0x4550)
    struct.pack_into("<H", pe, 0x84, machine)
    struct.pack_into("<H", pe, 0x86, 3)  # NumberOfSections
    struct.pack_into("<I", pe, 0x88, 0)
    struct.pack_into("<I", pe, 0x8C, 0)
    struct.pack_into("<I", pe, 0x90, 0)
    struct.pack_into("<H", pe, 0x94, opt_size)
    struct.pack_into("<H", pe, 0x96, 0x0102)

    oh = 0x98
    struct.pack_into("<H", pe, oh + 0x00, magic)
    struct.pack_into("<B", pe, oh + 0x02, 0)
    struct.pack_into("<B", pe, oh + 0x03, 0)
    struct.pack_into("<I", pe, oh + 0x04, text_size)
    struct.pack_into("<I", pe, oh + 0x08, idata_raw_size + data_size)
    struct.pack_into("<I", pe, oh + 0x0C, 0)
    struct.pack_into("<I", pe, oh + 0x10, entry)
    struct.pack_into("<I", pe, oh + 0x14, text_rva)
    if is64:
        struct.pack_into("<Q", pe, oh + 0x18, image_base)
        sa, fa, sub = oh + 0x20, oh + 0x24, oh + 0x30
        soff, soh, checksum = oh + 0x38, oh + 0x3C, oh + 0x40
        sstack_r, sstack_c = oh + 0x48, oh + 0x50
        sheap_r, sheap_c = oh + 0x58, oh + 0x60
        nrv = oh + 0x6C
        dd = oh + 0x70
    else:
        struct.pack_into("<I", pe, oh + 0x18, 0x2000)
        struct.pack_into("<I", pe, oh + 0x1C, image_base)
        sa, fa, sub = oh + 0x20, oh + 0x24, oh + 0x30
        soff, soh, checksum = oh + 0x38, oh + 0x3C, oh + 0x40
        sstack_r, sstack_c = oh + 0x48, oh + 0x4C
        sheap_r, sheap_c = oh + 0x50, oh + 0x54
        nrv = oh + 0x5C
        dd = oh + 0x60
    struct.pack_into("<I", pe, sa, sect_align)
    struct.pack_into("<I", pe, fa, file_align)
    struct.pack_into("<H", pe, sub + 0, 6)
    struct.pack_into("<H", pe, sub + 2, 0)
    struct.pack_into("<H", pe, sub + 4, 6)
    struct.pack_into("<H", pe, sub + 6, 0)
    struct.pack_into("<I", pe, soff, 0x4000)
    struct.pack_into("<I", pe, soh, 0x200)
    struct.pack_into("<I", pe, checksum, 0)
    struct.pack_into("<H", pe, oh + 0x44, 2)
    struct.pack_into("<H", pe, oh + 0x46, 0)
    if is64:
        struct.pack_into("<Q", pe, sstack_r, 0x100000)
        struct.pack_into("<Q", pe, sstack_c, 0x10000)
        struct.pack_into("<Q", pe, sheap_r, 0x100000)
        struct.pack_into("<Q", pe, sheap_c, 0x1000)
    else:
        struct.pack_into("<I", pe, sstack_r, 0x100000)
        struct.pack_into("<I", pe, sstack_c, 0x10000)
        struct.pack_into("<I", pe, sheap_r, 0x100000)
        struct.pack_into("<I", pe, sheap_c, 0x1000)
    struct.pack_into("<I", pe, nrv, 16)
    struct.pack_into("<I", pe, dd + 8, idata_rva)
    struct.pack_into("<I", pe, dd + 12, idata_size)

    sh = 0x98 + opt_size
    for idx, (name, rva, raw, size, vaddr, vsize, chars) in enumerate(
        [
            (b".text", text_rva, text_raw, text_size, text_rva, len(code), 0x60000020),
            (b".idata", idata_rva, idata_raw, idata_raw_size, idata_rva, len(idata), 0xC0000040),
            (b".data", data_rva, data_raw, data_size, data_rva, len(data_blob), 0xC0000040),
        ]
    ):
        base = sh + idx * 40
        pe[base : base + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<I", pe, base + 8, vsize)
        struct.pack_into("<I", pe, base + 12, vaddr)
        struct.pack_into("<I", pe, base + 16, size)
        struct.pack_into("<I", pe, base + 20, raw)
        struct.pack_into("<I", pe, base + 24, 0)
        struct.pack_into("<I", pe, base + 28, 0)
        struct.pack_into("<H", pe, base + 32, 0)
        struct.pack_into("<H", pe, base + 34, 0)
        struct.pack_into("<I", pe, base + 36, chars)

    blob = (
        bytes(pe)
        + bytes(code).ljust(text_size, b"\x00")
        + bytes(idata).ljust(idata_raw_size, b"\x00")
        + bytes(data_blob).ljust(data_size, b"\x00")
    )
    return blob, addrs


def _stub_argc(dll, name):
    attrs = generated.lookup_stub_func(dll, name)
    return attrs[2] if attrs else 0


def test_stub_tables_contain_only_uncovered_exports(gen_module):
    """The generated stub tables must only reference exports that no real
    handler covers; adding a real handler without regenerating fails this test."""
    funcs, ords, data = gen_module.get_handler_coverage()
    for line in generated.STUB_FUNCS_DATA.splitlines():
        dll, name, argc = line.split("\t")
        assert not gen_module.is_covered(funcs, ords, data, dll, name), (
            f"{dll}.{name} is now covered by a real handler; "
            "regenerate with tools/gen_api_stubs.py"
        )
        assert int(argc) >= 0
    for dll, name in generated.STUB_DATA:
        assert not gen_module.is_covered(funcs, ords, data, dll, name), (
            f"{dll}.{name} (data) is now covered by a real handler; "
            "regenerate with tools/gen_api_stubs.py"
        )
    for line in generated.STUB_ORDINALS_DATA.splitlines():
        dll, ordinal, argc = line.split("\t")
        assert not gen_module.is_ordinal_covered(ords, dll, int(ordinal)), (
            f"{dll} ordinal {ordinal} is now covered by a real handler; "
            "regenerate with tools/gen_api_stubs.py"
        )


def test_stub_lookup_contract():
    attrs = generated.lookup_stub_func("kernelbase", "GetPackagePathByFullName")
    assert attrs is not None
    name, func, argc, conv, ordinal = attrs
    assert name == "GetPackagePathByFullName"
    assert isinstance(argc, int)
    assert conv == e_arch.CALL_CONV_STDCALL
    assert func(None, None, []) == 0

    # Functions with real handlers must not resolve to stubs.
    for dll, name in [
        ("kernel32", "GetProcAddress"),
        ("kernelbase", "GetSystemTimePreciseAsFileTime"),
        ("kernelbase", "GetCurrentProcessId"),
        ("msvcrt", "strstr"),
        ("msvcrt", "acos"),
        ("msvcrt", "_vscprintf"),
        ("msvcrt", "strtol"),
        ("ntdll", "RtlGetLastWin32Error"),
        ("ntdll", "RtlQueryPerformanceCounter"),
        ("ntdll", "RtlRandom"),
        ("ntdll", "RtlAllocateHeap"),
        ("ntdll", "RtlImageNtHeader"),
        ("user32", "lstrlenW"),
        ("user32", "GetWindowTextLengthW"),
        ("shell32", "CommandLineToArgvW"),
        ("ole32", "CoCreateGuid"),
        ("ole32", "CoTaskMemAlloc"),
        ("version", "VerQueryValueW"),
        ("version", "GetFileVersionInfoW"),
        ("advapi32", "RegEnumValueW"),
        ("oleaut32", "SysAllocString"),
        ("oleaut32", "SysStringLen"),
        ("msvcrt", "_errno"),
    ]:
        assert generated.lookup_stub_func(dll, name) is None, f"{dll}.{name}"

    # Unknown modules never resolve.
    assert generated.lookup_stub_func("nonexistent_dll", "Foo") is None
    assert generated.lookup_stub_func("kernelbase", "NoSuchExport") is None

    # api-ms normalization folds into the same stub tables.
    assert generated.lookup_stub_func("api-ms-win-crt-string-l1-1-0", "_wcsicoll") is not None

    # Ordinal-only exports.
    assert generated.lookup_stub_func("ole32", "ordinal_800") is not None
    assert generated.lookup_stub_func("ole32", "ordinal_99999") is None

    # Data stubs.
    assert generated.lookup_stub_data("msvcrt", "_iob")
    assert not generated.lookup_stub_data("msvcrt", "strstr")


def test_smoke_pe_imports_are_parseable():
    """The synthetic PEs must be valid enough for pefile import parsing."""
    import pefile

    for bits in (32, 64):
        data = build_pe(bits, SMOKE_IMPORTS, _stub_argc)
        pe = pefile.PE(data=data)
        got = {
            (e.dll.decode().split(".")[0].lower(), i.name.decode())
            for e in pe.DIRECTORY_ENTRY_IMPORT
            for i in e.imports
        }
        assert got == set(SMOKE_IMPORTS), bits


@pytest.mark.parametrize("bits", [32, 64])
def test_stub_emulation_smoke(config, run_test, bits):
    """Samples importing previously-unsupported functions must complete without
    unsupported_api errors; stub calls return 0 and the data import resolves to
    a zero slot (visible via the entry point return value)."""
    data = build_pe(bits, SMOKE_IMPORTS, _stub_argc, data_imports={("msvcrt", "_iob")})
    for dll, name in STUB_FUNC_IMPORTS:
        assert generated.lookup_stub_func(dll, name) is not None, (
            f"{dll}.{name} is no longer a generated stub (covered by a real handler?); "
            "regenerate with tools/gen_api_stubs.py or update SMOKE_IMPORTS"
        )
    assert generated.lookup_stub_data("msvcrt", "_iob")
    report = run_test(config, data)
    eps = report.entry_points
    assert eps, "no entry point ran"

    for ep in eps:
        assert ep.error is None or ep.error.type != "unsupported_api", (
            f"unexpected error: {ep.error} (bits={bits})"
        )
        events = [evt for evt in (ep.events or []) if evt.event == "api"]
        api_names = [evt.api_name for evt in events]
        for dll, name in STUB_FUNC_IMPORTS:
            api = f"{dll}.{name}"
            hits = [evt for evt in events if evt.api_name == api and evt.ret_val == "0x0"]
            assert hits, f"{api} not called via stub returning 0 (bits={bits}); saw: {api_names}"

    # The final read of the `_iob` data-import slot returns 0.
    assert all(ep.ret_val == 0 for ep in eps), [ep.ret_val for ep in eps]


def _run_bits(config, run_test, bits, calls, data_specs, tail_load=None, argc_map=None):
    data, addrs = build_pe_calls(
        bits, calls, data_specs, tail_load=tail_load, argc_map=argc_map, cdecl=CRT_CDECL
    )
    report = run_test(config, data)
    eps = report.entry_points
    assert eps, "no entry point ran"
    for ep in eps:
        assert ep.error is None or ep.error.type != "unsupported_api", (
            f"unexpected error: {ep.error} (bits={bits})"
        )
    assert len(eps) == 1
    return eps[0], addrs


CRT_CDECL = {
    ("msvcrt", "atoi"),
    ("msvcrt", "strtol"),
    ("msvcrt", "strspn"),
    ("msvcrt", "_vscprintf"),
}


REAL_ARGC = {
    ("kernelbase", "GetSystemTimePreciseAsFileTime"): 1,
    ("kernelbase", "GetCurrentProcessId"): 0,
    ("msvcrt", "strtol"): 3,
    ("msvcrt", "_vscprintf"): 2,
    ("msvcrt", "strspn"): 2,
    ("msvcrt", "atoi"): 1,
    ("ntdll", "RtlQueryPerformanceCounter"): 1,
    ("ntdll", "RtlRandom"): 1,
    ("ntdll", "RtlCharToInteger"): 3,
    ("ntdll", "RtlImageNtHeader"): 1,
    ("ole32", "CoCreateGuid"): 1,
    ("user32", "lstrlenW"): 1,
    ("user32", "CharUpperW"): 1,
    ("shell32", "CommandLineToArgvW"): 2,
    ("oleaut32", "SysStringLen"): 1,
}


@pytest.mark.parametrize("bits", [32, 64])
def test_real_handlers_functional(config, run_test, bits):
    """Real handlers must actually perform their documented behavior."""
    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            # GetSystemTimePreciseAsFileTime writes a FILETIME to the output buffer.
            ("kernelbase", "GetSystemTimePreciseAsFileTime", ["buf"]),
        ],
        {"buf": b"\x00" * 8},
        tail_load="buf",
        argc_map=REAL_ARGC,
    )
    assert ep.ret_val != 0, "GetSystemTimePreciseAsFileTime did not write a FILETIME"

    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            ("kernelbase", "GetCurrentProcessId", []),
        ],
        {},
        argc_map=REAL_ARGC,
    )
    assert ep.ret_val != 0, "GetCurrentProcessId returned 0"

    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            ("msvcrt", "strtol", ["str", "endptr", 0x0a]),
        ],
        {"str": b"1234abc\x00", "endptr": b"\x00" * 8},
        argc_map=REAL_ARGC,
    )
    assert ep.ret_val == 1234, f"strtol returned {ep.ret_val}"

    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            ("msvcrt", "atoi", ["str"]),
        ],
        {"str": b"-42\x00"},
            argc_map=REAL_ARGC,
        )
    mask = (1 << (64 if bits == 64 else 32)) - 1
    assert ep.ret_val == (-42) & mask, f"atoi returned {ep.ret_val}"

    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            ("msvcrt", "strspn", ["str", "acc"]),
        ],
        {"str": b"aaabxyz\x00", "acc": b"ab\x00"},
        argc_map=REAL_ARGC,
    )
    assert ep.ret_val == 4, f"strspn returned {ep.ret_val}"

    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            ("ntdll", "RtlQueryPerformanceCounter", ["buf"]),
        ],
        {"buf": b"\x00" * 8},
        tail_load="buf",
        argc_map=REAL_ARGC,
    )
    assert ep.ret_val != 0, "RtlQueryPerformanceCounter did not write a counter"

    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            ("ntdll", "RtlCharToInteger", ["str", 0x0a, "out"]),
        ],
        {"str": b"77\x00", "out": b"\x00" * 4},
        tail_load="out",
        argc_map=REAL_ARGC,
    )
    assert ep.ret_val == 77, f"RtlCharToInteger wrote {ep.ret_val}"

    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            ("ole32", "CoCreateGuid", ["buf"]),
        ],
        {"buf": b"\x00" * 16},
        tail_load="buf",
        argc_map=REAL_ARGC,
    )
    assert ep.ret_val != 0, "CoCreateGuid did not write a GUID"

    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            ("user32", "lstrlenW", ["str"]),
        ],
        {"str": "hello".encode("utf-16le") + b"\x00\x00"},
        argc_map=REAL_ARGC,
    )
    assert ep.ret_val == 5, f"lstrlenW returned {ep.ret_val}"

    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            ("user32", "CharUpperW", ["str"]),
        ],
        {"str": "hello".encode("utf-16le") + b"\x00\x00"},
        tail_load="str",
        argc_map=REAL_ARGC,
    )
    assert (ep.ret_val & 0xFFFF) == ord("H"), f"CharUpperW result: {ep.ret_val:#x}"
    assert ((ep.ret_val >> 16) & 0xFFFF) == ord("E"), f"CharUpperW result: {ep.ret_val:#x}"

    ep, addrs = _run_bits(
        config,
        run_test,
        bits,
        [
            ("shell32", "CommandLineToArgvW", ["cmd", "argc"]),
        ],
        {"cmd": '"a b" c'.encode("utf-16le") + b"\x00\x00", "argc": b"\x00" * 4},
        tail_load="argc",
        argc_map=REAL_ARGC,
    )
    assert ep.ret_val == 2, f"CommandLineToArgvW argc: {ep.ret_val}"
