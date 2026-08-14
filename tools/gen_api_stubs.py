#!/usr/bin/env python3
# Copyright (C) 2026 Speakeasy-X
"""
Generate speakeasy/winenv/api/generated.py stub tables from a DLL collection.

The generated module provides permissive "return 0" stubs for exported functions
that the emulator's real API handlers do not cover, so emulation of samples that
import long-tail functions from common system DLLs does not abort with
"unsupported_api".

Usage:
    python tools/gen_api_stubs.py [collection_dir] [--no-argc] [--syswow64 DIR] [--out FILE]

Defaults:
    collection_dir : E:\\collected_dlls_merged
    syswow64      : C:\\Windows\\SysWOW64  (x86 DLLs used to extract real argc)
    out           : speakeasy/winenv/api/generated.py
"""

import argparse
import collections
import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import pefile  # noqa: E402

import speakeasy.windows.common as winemu  # noqa: E402
import speakeasy.winenv.api.winapi as winapi  # noqa: E402

EXECUTE_SECTION = 0x20000000  # IMAGE_SCN_MEM_EXECUTE
MAX_ARGC = 32
MAX_JMP_HOPS = 8
MAX_INSNS = 64


class _FakeEmu:
    """Minimal emu stand-in for instantiating handler classes."""

    def get_arch(self):
        return 64  # ARCH_AMD64

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)

        def _noop(*args, **kwargs):
            return None

        return _noop


def get_handler_coverage():
    """
    Collect the set of export names/ordinals/data handlers per handler class.

    Prefers a live instance (covers both @apihook methods and batch-registered
    handlers); falls back to a class scan when instantiation is not possible.
    """
    funcs = collections.defaultdict(set)
    ords = collections.defaultdict(set)
    data = collections.defaultdict(set)
    for dname, cls in winapi.API_HANDLERS:
        key = dname.lower()
        try:
            inst = cls(_FakeEmu())
            for name, (impname, func, argc, conv, ordinal) in inst.funcs.items():
                if isinstance(name, int):
                    ords[key].add(name)
                else:
                    funcs[key].add(name)
            for name in inst.data:
                data[key].add(name)
            continue
        except Exception:
            pass
        for attr in dir(cls):
            try:
                val = getattr(cls, attr, None)
            except Exception:
                continue
            if val is None:
                continue
            func_attrs = getattr(val, "__apihook__", None)
            if func_attrs:
                impname, _func, _argc, _conv, ordinal = func_attrs
                funcs[key].add(impname)
                if ordinal:
                    ords[key].add(ordinal)
                continue
            data_attrs = getattr(val, "__datahook__", None)
            if data_attrs:
                data[key].add(data_attrs[0])
    return funcs, ords, data


def is_covered(funcs, ords, data, dll, name):
    """Mirror the emulator's runtime resolution (winemu.normalize_import_miss)."""
    d = dll.lower()
    if name in funcs[d] or name in data[d]:
        return True
    alt = name[:-1] if name.endswith(("A", "W")) else ""
    if alt and (alt in funcs[d] or alt in data[d]):
        return True
    nd = winemu.normalize_dll_name(d)
    if nd != d:
        if name in funcs[nd] or name in data[nd]:
            return True
        if alt and (alt in funcs[nd] or alt in data[nd]):
            return True
    if d.startswith("ntdll"):
        nh = funcs.get("ntoskrnl", set())
        cands = {name, alt}
        if name.startswith(("Nt", "Zw")):
            cands.add(("Nt" if name.startswith("Zw") else "Zw") + name[2:])
        if cands & nh:
            return True
    return False


def is_ordinal_covered(ords, dll, ordinal):
    d = dll.lower()
    if ordinal in ords[d]:
        return True
    nd = winemu.normalize_dll_name(d)
    if nd != d and ordinal in ords[nd]:
        return True
    return False


def is_data_export(pe, rva):
    """An export is data when its RVA lives in a non-executable section."""
    for sect in pe.sections:
        size = max(sect.Misc_VirtualSize, sect.SizeOfRawData)
        if sect.VirtualAddress <= rva < sect.VirtualAddress + size:
            return not (sect.Characteristics & EXECUTE_SECTION)
    return False


def extract_argc(pe_x86, image, rva):
    """Disassemble an x86 export, follow jmp chains, resolve `ret imm16` -> argc."""
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    base = pe_x86.OPTIONAL_HEADER.ImageBase
    img_size = len(image)
    visited = set()
    for _hop in range(MAX_JMP_HOPS):
        if rva in visited or rva < 0 or rva >= img_size:
            return 0
        visited.add(rva)
        data = image[rva : rva + 0x400]
        insn_count = 0
        next_rva = None
        for insn in md.disasm(data, base + rva):
            insn_count += 1
            if insn_count > MAX_INSNS:
                return 0
            mnem = insn.mnemonic
            if mnem == "ret":
                op = insn.op_str.strip()
                if op and op.lower().startswith("0x"):
                    try:
                        n = int(op, 16) // 4
                    except ValueError:
                        n = 0
                    return min(max(n, 0), MAX_ARGC)
                return 0
            if mnem == "jmp":
                op = insn.op_str.strip()
                if op.lower().startswith("0x"):
                    next_rva = int(op, 16) - base
                break
        if next_rva is None:
            return 0
        rva = next_rva
    return 0


def collect_argc_map(syswow64_dir, target_bases):
    """Extract {dll: {name: argc}} from x86 system DLLs via `ret imm16` analysis."""
    import capstone  # noqa: F401  (fail fast if missing)

    argc_map = {}
    for tbase in sorted(target_bases):
        path = os.path.join(syswow64_dir, tbase + ".dll")
        if not os.path.exists(path):
            continue
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            )
        except Exception:
            continue
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            continue
        image = pe.get_memory_mapped_image()
        names = {}
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            nm = s.name.decode() if isinstance(s.name, bytes) else s.name
            if not nm or s.forwarder:
                continue
            argc = extract_argc(pe, image, s.address)
            if argc:
                names[nm] = argc
        argc_map[tbase.lower()] = names
        print(f"  [argc] {tbase}.dll: {len(names)} functions with extracted argc")
    return argc_map


def parse_collection(collection_dir):
    """Parse all DLLs. Returns list of (file, base_name, redirect_target, pe, symbols)."""
    parsed = []
    for fn in sorted(os.listdir(collection_dir)):
        if not fn.lower().endswith(".dll"):
            continue
        path = os.path.join(collection_dir, fn)
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            )
        except Exception as e:
            print(f"  [skip] {fn}: parse error {e}")
            continue
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT") or not pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"  [skip] {fn}: no exports")
            continue
        base = fn.split("__redirects_to__")[0].replace(".dll", "")
        target = fn.split("__redirects_to__")[1].replace(".dll", "") if "__redirects_to__" in fn else base
        parsed.append((fn, base, target, pe))
    return parsed


def main():
    ap = argparse.ArgumentParser(description="Generate API stub tables for speakeasy")
    ap.add_argument("collection_dir", nargs="?", default=r"E:\collected_dlls_merged")
    ap.add_argument("--syswow64", default=r"C:\Windows\SysWOW64")
    ap.add_argument("--no-argc", action="store_true", help="skip x86 argc extraction")
    ap.add_argument("--out", default=os.path.join(PROJECT_ROOT, "speakeasy", "winenv", "api", "generated.py"))
    args = ap.parse_args()

    funcs, ords, data = get_handler_coverage()
    print(f"handler classes: {len(winapi.API_HANDLERS)}, covered names: "
          f"{sum(len(v) for v in funcs.values())}")

    parsed = parse_collection(args.collection_dir)
    print(f"parsed {len(parsed)} dll files")

    argc_map = {}
    if not args.no_argc:
        targets = {t for _fn, _b, t, _pe in parsed}
        print(f"extracting argc from x86 dlls in {args.syswow64} ...")
        argc_map = collect_argc_map(args.syswow64, targets)

    stub_funcs = collections.defaultdict(dict)   # key -> {name: argc}
    stub_data = collections.defaultdict(set)
    stub_ordinals = collections.defaultdict(dict)  # key -> {ordinal: argc}
    stats = {}

    for fn, base, target, pe in parsed:
        base_key = winemu.normalize_dll_name(base).lower()
        target_key = winemu.normalize_dll_name(target).lower()
        keys = [base_key]
        if target_key != base_key:
            keys.append(target_key)
        argc_src = argc_map.get(target.lower(), {})
        n_func = n_data = n_ord = n_covered = 0
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            nm = s.name.decode() if isinstance(s.name, bytes) else s.name
            if s.forwarder:
                continue
            if nm is None:
                reg = 0
                for k in keys:
                    if is_ordinal_covered(ords, k, s.ordinal):
                        continue
                    stub_ordinals[k].setdefault(s.ordinal, 0)
                    reg += 1
                if reg:
                    n_ord += 1
                else:
                    n_covered += 1
                continue
            reg = 0
            for k in keys:
                if is_covered(funcs, ords, data, k, nm):
                    continue
                reg += 1
                argc = argc_src.get(nm, 0)
                if is_data_export(pe, s.address):
                    stub_data[k].add(nm)
                else:
                    stub_funcs[k].setdefault(nm, argc)
            if reg:
                if is_data_export(pe, s.address):
                    n_data += 1
                else:
                    n_func += 1
            else:
                n_covered += 1
        stats[fn] = (n_func, n_data, n_ord, n_covered)

    total_funcs = sum(len(v) for v in stub_funcs.values())
    total_data = sum(len(v) for v in stub_data.values())
    total_ords = sum(len(v) for v in stub_ordinals.values())

    out_dir = os.path.dirname(args.out)
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(GENERATED_HEADER.format(
            gen_time=time.strftime("%Y-%m-%d %H:%M:%S"),
            collection_dir=args.collection_dir,
            syswow64=args.syswow64 if not args.no_argc else "disabled",
            total_funcs=total_funcs,
            total_data=total_data,
            total_ords=total_ords,
        ))
        f.write("STUB_FUNCS_DATA = (\n")
        for k in sorted(stub_funcs):
            for nm in sorted(stub_funcs[k]):
                f.write(f'    "{k}\t{nm}\t{stub_funcs[k][nm]}\\n"\n')
        f.write(")\n\n")
        f.write("STUB_DATA = frozenset({\n")
        for k in sorted(stub_data):
            for nm in sorted(stub_data[k]):
                f.write(f"    ({k!r}, {nm!r}),\n")
        f.write("})\n\n")
        f.write("STUB_ORDINALS_DATA = (\n")
        for k in sorted(stub_ordinals):
            for ordn in sorted(stub_ordinals[k]):
                f.write(f'    "{k}\t{ordn}\t{stub_ordinals[k][ordn]}\\n"\n')
        f.write(")\n\n")
        f.write(GENERATED_RUNTIME)

    report = [f"=== API stub generation report {time.strftime('%Y-%m-%d %H:%M:%S')} ===",
              f"collection: {args.collection_dir}",
              f"files parsed: {len(parsed)}",
              f"total stub funcs: {total_funcs}",
              f"total stub data: {total_data}",
              f"total stub ordinals: {total_ords}",
              ""]
    print()
    print(f"stub funcs per key: {len(stub_funcs)}")
    for k in sorted(stub_funcs):
        print(f"  {k}: {len(stub_funcs[k])}")
        report.append(f"funcs {k}: {len(stub_funcs[k])}")
    print(f"stub data: {total_data}  stub ordinals: {total_ords}")
    print(f"per-file (funcs, data, ords, already-covered):")
    for fn, (a, b, c, d) in stats.items():
        print(f"  {fn}: funcs={a} data={b} ords={c} covered={d}")
        report.append(f"file {fn}: funcs={a} data={b} ords={c} covered={d}")
    report.append(f"generated: {args.out}")

    report_dir = os.path.join(PROJECT_ROOT, "reports")
    os.makedirs(report_dir, exist_ok=True)
    with open(os.path.join(report_dir, "api_stub_generation.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(report) + "\n")
    print(f"report: {os.path.join(report_dir, 'api_stub_generation.txt')}")


GENERATED_HEADER = """\
# Generated file - DO NOT EDIT.
# Generated by tools/gen_api_stubs.py at {gen_time}
# collection: {collection_dir}
# syswow64 argc source: {syswow64}
# counts: STUB_FUNCS_DATA={total_funcs} STUB_DATA={total_data} STUB_ORDINALS_DATA={total_ords}
#
# These tables provide permissive "return 0" stubs for exported functions of
# common system DLLs that have no real API handler yet. Real handlers always
# take priority at dispatch time; implement a function for real and regenerate
# (or simply add the handler - the stub lookup only runs on a miss).

import speakeasy.windows.common as _winemu
import speakeasy.winenv.arch as _arch

"""

GENERATED_RUNTIME = """\
_STUB_FUNCS = None
_STUB_ORDINALS = None


def _stub_func(self, emu, argv, ctx=None):
    \"\"\"Permissive no-op stub: always succeeds with 0.\"\"\"
    return 0


def _get_stub_funcs():
    global _STUB_FUNCS
    if _STUB_FUNCS is None:
        _STUB_FUNCS = {}
        for _line in STUB_FUNCS_DATA.splitlines():
            _dll, _name, _argc = _line.split("\\t")
            _STUB_FUNCS[(_dll, _name)] = int(_argc)
    return _STUB_FUNCS


def _get_stub_ordinals():
    global _STUB_ORDINALS
    if _STUB_ORDINALS is None:
        _STUB_ORDINALS = {}
        for _line in STUB_ORDINALS_DATA.splitlines():
            _dll, _ord, _argc = _line.split("\\t")
            _STUB_ORDINALS[(_dll, int(_ord))] = int(_argc)
    return _STUB_ORDINALS


def lookup_stub_func(mod_name, exp_name):
    \"\"\"
    Return (name, func, argc, conv, ordinal) for a generated stub, or None.
    \"\"\"
    key = (_winemu.normalize_dll_name(mod_name).lower(), exp_name)
    argc = _get_stub_funcs().get(key)
    if argc is None and exp_name.startswith("ordinal_"):
        try:
            argc = _get_stub_ordinals().get((key[0], int(exp_name.split("_")[1])))
        except (IndexError, ValueError):
            argc = None
    if argc is None:
        return None
    return (exp_name, _stub_func, argc, _arch.CALL_CONV_STDCALL, None)


def lookup_stub_data(mod_name, exp_name):
    \"\"\"Return True when a generated data stub exists for the export.\"\"\"
    key = (_winemu.normalize_dll_name(mod_name).lower(), exp_name)
    return key in STUB_DATA
"""


if __name__ == "__main__":
    main()
