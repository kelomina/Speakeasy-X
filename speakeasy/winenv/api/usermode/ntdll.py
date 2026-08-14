# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import binascii
import datetime
import os
import struct

import speakeasy.windows.common as winemu
import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.nt.ntoskrnl as ntos

from .. import api


class Ntdll(api.ApiHandler):
    """
    Implements exported native functions from ntdll.dll. If a function is not supported
    here, but is supported in the ntoskrnl handler (e.g. NtCreateFile) it will be handled by
    the kernel export handler.
    """

    name = "ntdll"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)

        self.funcs = {}
        self.data = {}

        super().__get_hook_attrs__(self)

        self._register_rtl_batch()
        self._register_nt_batch()

    def _register_rtl_batch(self):
        """
        Register real handlers for common ntdll Rtl* runtime functions using
        the same conventions as the rest of this module. Names with an
        existing real handler (or an ntoskrnl bridge) are left untouched.
        """
        ptr = self.get_ptr_size()
        cd = e_arch.CALL_CONV_CDECL
        sd = e_arch.CALL_CONV_STDCALL

        def reg(name, func, argc, conv=sd):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, conv, None)

        def _now_filetime():
            # 100ns intervals since 1601-01-01 UTC
            return 116444736000000000 + int(datetime.datetime.now(datetime.timezone.utc).timestamp()) * 10000000

        def RtlQueryPerformanceCounter_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                counter = self.emu.perf_counter if hasattr(self.emu, "perf_counter") else 0x5FD27D571F
                self.mem_write(out, struct.pack("<Q", counter))
            return True

        reg("RtlQueryPerformanceCounter", RtlQueryPerformanceCounter_impl, 1)

        def RtlQueryPerformanceFrequency_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, struct.pack("<Q", 10000000))
            return True

        reg("RtlQueryPerformanceFrequency", RtlQueryPerformanceFrequency_impl, 1)

        def RtlGetTickCount_impl(self, emu, argv, ctx=None):
            return 0x01234567

        reg("RtlGetTickCount", RtlGetTickCount_impl, 0)

        def RtlRandom_impl(self, emu, argv, ctx=None):
            seed_ptr = argv[0]
            seed = int.from_bytes(self.mem_read(seed_ptr, 4), "little") if seed_ptr else 1
            seed = (214013 * seed + 2531011) & 0xFFFFFFFF
            if seed_ptr:
                self.mem_write(seed_ptr, struct.pack("<I", seed))
            return (seed >> 16) & 0x7FFF

        reg("RtlRandom", RtlRandom_impl, 1)
        reg("RtlRandomEx", RtlRandom_impl, 1)

        def RtlTimeToSecondsSince1970_impl(self, emu, argv, ctx=None):
            lt, out = argv
            ft = int.from_bytes(self.mem_read(lt, 8), "little")
            secs = (ft - 116444736000000000) // 10000000
            if out:
                self.mem_write(out, struct.pack("<I", secs))
            return True

        reg("RtlTimeToSecondsSince1970", RtlTimeToSecondsSince1970_impl, 2)

        def RtlTimeToSecondsSince1980_impl(self, emu, argv, ctx=None):
            lt, out = argv
            ft = int.from_bytes(self.mem_read(lt, 8), "little")
            secs = (ft - 119600064000000000) // 10000000
            if out:
                self.mem_write(out, struct.pack("<I", secs))
            return True

        reg("RtlTimeToSecondsSince1980", RtlTimeToSecondsSince1980_impl, 2)

        def RtlSecondsSince1970ToTime_impl(self, emu, argv, ctx=None):
            secs, out = argv
            ft = 116444736000000000 + secs * 10000000
            if out:
                self.mem_write(out, struct.pack("<Q", ft))
            return True

        reg("RtlSecondsSince1970ToTime", RtlSecondsSince1970ToTime_impl, 2)

        def RtlSecondsSince1980ToTime_impl(self, emu, argv, ctx=None):
            secs, out = argv
            ft = 119600064000000000 + secs * 10000000
            if out:
                self.mem_write(out, struct.pack("<Q", ft))
            return True

        reg("RtlSecondsSince1980ToTime", RtlSecondsSince1980ToTime_impl, 2)

        def RtlTimeToTimeFields_impl(self, emu, argv, ctx=None):
            lt, fields = argv
            if not fields:
                return
            ft = int.from_bytes(self.mem_read(lt, 8), "little")
            epoch = ft // 10000000 - 11644473600
            dt = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
            wday = dt.weekday()
            self.mem_write(
                fields,
                struct.pack(
                    "<8H", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second,
                    (ft // 10000) % 1000, wday,
                ),
            )

        reg("RtlTimeToTimeFields", RtlTimeToTimeFields_impl, 2)

        def RtlTimeFieldsToTime_impl(self, emu, argv, ctx=None):
            fields, out = argv
            if not out:
                return 0
            year, month, day, hour, minute, second, ms, wday = struct.unpack("<8H", self.mem_read(fields, 16))
            try:
                dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
            except Exception:
                return 0
            ft = 116444736000000000 + int(dt.timestamp()) * 10000000 + ms * 10000
            self.mem_write(out, struct.pack("<Q", ft))
            return True

        reg("RtlTimeFieldsToTime", RtlTimeFieldsToTime_impl, 2)

        def RtlCharToInteger_impl(self, emu, argv, ctx=None):
            s, base, out = argv
            if not s or not out:
                return 0xC000000D  # STATUS_INVALID_PARAMETER
            txt = self.read_string(s)
            txt = txt.strip()
            if base == 0:
                base = 16 if txt[:2].lower() == "0x" else 10
            try:
                if txt[:2].lower() == "0x":
                    val = int(txt[2:], 16)
                elif txt[:1].lower() == "0" and base == 8:
                    val = int(txt[1:], 8)
                else:
                    val = int(txt, base)
            except Exception:
                return 0xC000000D
            self.mem_write(out, struct.pack("<I", val & 0xFFFFFFFF))
            return 0

        reg("RtlCharToInteger", RtlCharToInteger_impl, 3)

        def RtlUnicodeStringToInteger_impl(self, emu, argv, ctx=None):
            us, base, out = argv
            if not us or not out:
                return 0xC000000D
            string = self.read_unicode_string(us)
            txt = string.strip()
            if base == 0:
                base = 16 if txt[:2].lower() == "0x" else 10
            try:
                if txt[:2].lower() == "0x":
                    val = int(txt[2:], 16)
                else:
                    val = int(txt, base)
            except Exception:
                return 0xC000000D
            self.mem_write(out, struct.pack("<I", val & 0xFFFFFFFF))
            return 0

        reg("RtlUnicodeStringToInteger", RtlUnicodeStringToInteger_impl, 3)

        def RtlUpperChar_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFF
            return (c - 0x20) if 0x61 <= c <= 0x7A else c

        reg("RtlUpperChar", RtlUpperChar_impl, 1)

        def RtlLowerChar_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFF
            return (c + 0x20) if 0x41 <= c <= 0x5A else c

        reg("RtlLowerChar", RtlLowerChar_impl, 1)

        def RtlUpcaseUnicodeChar_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFFFF
            if 0x61 <= c <= 0x7A:
                return c - 0x20
            if c > 0x7F:
                try:
                    return ord(chr(c).upper())
                except Exception:
                    return c
            return c

        reg("RtlUpcaseUnicodeChar", RtlUpcaseUnicodeChar_impl, 1)

        def RtlDowncaseUnicodeChar_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFFFF
            if 0x41 <= c <= 0x5A:
                return c + 0x20
            if c > 0x7F:
                try:
                    return ord(chr(c).lower())
                except Exception:
                    return c
            return c

        reg("RtlDowncaseUnicodeChar", RtlDowncaseUnicodeChar_impl, 1)

        def _init_string(out, buffer, length):
            if not out:
                return
            if buffer:
                self.mem_write(out, struct.pack("<HH" + ("4x" if ptr == 8 else "") + "P", length, length, buffer))
            else:
                self.mem_write(out, b"\x00" * (8 if ptr == 8 else 8))

        def RtlInitAnsiString_impl(self, emu, argv, ctx=None):
            out, src = argv
            if src:
                length = len(self.read_string(src))
            else:
                length = 0
            _init_string(out, src, length)
            return

        reg("RtlInitAnsiString", RtlInitAnsiString_impl, 2)

        def RtlInitString_impl(self, emu, argv, ctx=None):
            return RtlInitAnsiString_impl(self, emu, argv, None)

        reg("RtlInitString", RtlInitString_impl, 2)

        def RtlInitUnicodeStringEx_impl(self, emu, argv, ctx=None):
            out, src = argv
            if src:
                length = len(self.read_wide_string(src)) * 2
            else:
                length = 0
            _init_string(out, src, length)
            return 0

        reg("RtlInitUnicodeStringEx", RtlInitUnicodeStringEx_impl, 2)

        def RtlCopyUnicodeString_impl(self, emu, argv, ctx=None):
            dst, src = argv
            if not dst:
                return
            if not src:
                self.mem_write(dst, b"\x00" * (8 if ptr == 8 else 8))
                return
            src_len = int.from_bytes(self.mem_read(src, 2), "little")
            max_len = int.from_bytes(self.mem_read(dst + 2, 2), "little")
            data = self.mem_read(int.from_bytes(self.mem_read(src + 8, ptr), "little"), min(src_len, max_len))
            self.mem_write(dst, struct.pack("<H", min(src_len, max_len)))
            self.mem_write(int.from_bytes(self.mem_read(dst + 8, ptr), "little"), data)

        reg("RtlCopyUnicodeString", RtlCopyUnicodeString_impl, 2)

        def RtlCompareUnicodeString_impl(self, emu, argv, ctx=None):
            a, b, ci = argv
            if not a or not b:
                return 0
            sa = self.read_unicode_string(a)
            sb = self.read_unicode_string(b)
            if ci:
                sa, sb = sa.lower(), sb.lower()
            if sa == sb:
                return 0
            return -1 if sa < sb else 1

        reg("RtlCompareUnicodeString", RtlCompareUnicodeString_impl, 3)

        def RtlEqualUnicodeString_impl(self, emu, argv, ctx=None):
            a, b, ci = argv
            if not a or not b:
                return False
            sa = self.read_unicode_string(a)
            sb = self.read_unicode_string(b)
            if ci:
                return sa.lower() == sb.lower()
            return sa == sb

        reg("RtlEqualUnicodeString", RtlEqualUnicodeString_impl, 3)

        def RtlCompareString_impl(self, emu, argv, ctx=None):
            a, b, ci = argv
            if not a or not b:
                return 0
            sa = self.read_ansi_string(a)
            sb = self.read_ansi_string(b)
            if ci:
                sa, sb = sa.lower(), sb.lower()
            if sa == sb:
                return 0
            return -1 if sa < sb else 1

        reg("RtlCompareString", RtlCompareString_impl, 3)

        def RtlEqualString_impl(self, emu, argv, ctx=None):
            a, b, ci = argv
            if not a or not b:
                return False
            sa = self.read_ansi_string(a)
            sb = self.read_ansi_string(b)
            if ci:
                return sa.lower() == sb.lower()
            return sa == sb

        reg("RtlEqualString", RtlEqualString_impl, 3)

        def RtlFillMemory_impl(self, emu, argv, ctx=None):
            dst, length, fill = argv
            if dst:
                self.mem_write(dst, bytes([fill & 0xFF]) * length)

        reg("RtlFillMemory", RtlFillMemory_impl, 3)

        def RtlCompareMemory_impl(self, emu, argv, ctx=None):
            a, b, length = argv
            if not a or not b:
                return 0
            ba = self.mem_read(a, length)
            bb = self.mem_read(b, length)
            n = 0
            for x, y in zip(ba, bb):
                if x != y:
                    break
                n += 1
            return n

        reg("RtlCompareMemory", RtlCompareMemory_impl, 3)

        def RtlSetLastWin32Error_impl(self, emu, argv, ctx=None):
            emu.set_last_error(argv[0])
            return

        reg("RtlSetLastWin32Error", RtlSetLastWin32Error_impl, 1)

        def RtlGetSystemTime_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, struct.pack("<Q", _now_filetime()))

        reg("RtlGetSystemTime", RtlGetSystemTime_impl, 1)
        reg("RtlQuerySystemTime", RtlGetSystemTime_impl, 1)

        def RtlQueryUnbiasedInterruptTime_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, struct.pack("<Q", 0x10000000))

        reg("RtlQueryUnbiasedInterruptTime", RtlQueryUnbiasedInterruptTime_impl, 1)

        def RtlConvertUlongToLargeInteger_impl(self, emu, argv, ctx=None):
            return argv[0] & 0xFFFFFFFF

        reg("RtlConvertUlongToLargeInteger", RtlConvertUlongToLargeInteger_impl, 1)

        def RtlUshortByteSwap_impl(self, emu, argv, ctx=None):
            return ((argv[0] & 0xFF) << 8) | ((argv[0] >> 8) & 0xFF)

        reg("RtlUshortByteSwap", RtlUshortByteSwap_impl, 1)

        def RtlUlongByteSwap_impl(self, emu, argv, ctx=None):
            v = argv[0] & 0xFFFFFFFF
            return int.from_bytes(v.to_bytes(4, "little"), "big")

        reg("RtlUlongByteSwap", RtlUlongByteSwap_impl, 1)

        def RtlUlonglongByteSwap_impl(self, emu, argv, ctx=None):
            return int.from_bytes(argv[0].to_bytes(8, "little"), "big")

        reg("RtlUlonglongByteSwap", RtlUlonglongByteSwap_impl, 1)

        # ---- heap ----
        self._heap_sizes = {}

        def RtlAllocateHeap_impl(self, emu, argv, ctx=None):
            heap, flags, size = argv
            chunk = self.heap_alloc(size, heap="RtlAllocateHeap")
            if chunk:
                self._heap_sizes[chunk] = size
            return chunk

        reg("RtlAllocateHeap", RtlAllocateHeap_impl, 3)

        def RtlFreeHeap_impl(self, emu, argv, ctx=None):
            heap, flags, base = argv
            if base:
                self._heap_sizes.pop(base, None)
                self.mem_free(base)
            return True

        reg("RtlFreeHeap", RtlFreeHeap_impl, 3)

        def RtlSizeHeap_impl(self, emu, argv, ctx=None):
            heap, flags, base = argv
            return self._heap_sizes.get(base, 0)

        reg("RtlSizeHeap", RtlSizeHeap_impl, 3)

        def RtlReAllocateHeap_impl(self, emu, argv, ctx=None):
            heap, flags, base, size = argv
            old_size = self._heap_sizes.get(base, 0)
            chunk = self.heap_alloc(size, heap="RtlAllocateHeap")
            if chunk and base:
                copy_len = min(old_size, size)
                try:
                    self.mem_write(chunk, self.mem_read(base, copy_len))
                except Exception:
                    pass
                self._heap_sizes.pop(base, None)
                self.mem_free(base)
            self._heap_sizes[chunk] = size
            return chunk

        reg("RtlReAllocateHeap", RtlReAllocateHeap_impl, 4)

        def RtlCreateHeap_impl(self, emu, argv, ctx=None):
            flags, base, reserve, commit = argv
            chunk = self.mem_alloc(reserve or 0x10000, tag="api.ntdll.heap")
            return chunk

        reg("RtlCreateHeap", RtlCreateHeap_impl, 4)

        def RtlDestroyHeap_impl(self, emu, argv, ctx=None):
            heap = argv[0]
            if heap:
                try:
                    self.mem_free(heap)
                except Exception:
                    pass
            return 0

        reg("RtlDestroyHeap", RtlDestroyHeap_impl, 1)

        # ---- PE image parsing ----
        def RtlImageNtHeader_impl(self, emu, argv, ctx=None):
            base = argv[0]
            if not base:
                return 0
            try:
                if self.mem_read(base, 2) != b"MZ":
                    return 0
                e_lfanew = int.from_bytes(self.mem_read(base + 0x3C, 4), "little")
                nt = base + e_lfanew
                if self.mem_read(nt, 4) != b"PE\x00\x00":
                    return 0
                return nt
            except Exception:
                return 0

        reg("RtlImageNtHeader", RtlImageNtHeader_impl, 1)

        def RtlImageDirectoryEntryToData_impl(self, emu, argv, ctx=None):
            base, mapped, directory, size_out = argv
            nt = RtlImageNtHeader_impl(self, emu, [base], None)
            if not nt:
                return 0
            try:
                if self.mem_read(nt + 0x18, 2) == b"\x0b\x02":
                    dd_base = nt + 0x70  # PE32+ data directory base... magic check first
                    magic = self.mem_read(nt + 0x18, 2)
                    is64 = magic == b"\x0b\x02"
                    dd_off = nt + (0x78 if is64 else 0x60)
                    entry_off = dd_off + directory * 8
                    rva = int.from_bytes(self.mem_read(entry_off, 4), "little")
                    size = int.from_bytes(self.mem_read(entry_off + 4, 4), "little")
                    if size_out:
                        self.mem_write(size_out, struct.pack("<I", size))
                    if rva:
                        return base + rva
            except Exception:
                pass
            return 0

        reg("RtlImageDirectoryEntryToData", RtlImageDirectoryEntryToData_impl, 4)

        def RtlImageRvaToVa_impl(self, emu, argv, ctx=None):
            nt, base, rva, last_rva = argv
            try:
                opt = nt + 0x18
                magic = int.from_bytes(self.mem_read(opt, 2), "little")
                if magic == 0x20B:
                    num_sections = int.from_bytes(self.mem_read(nt + 0x06, 2), "little")
                    sect_off = nt + 0x18 + 240
                else:
                    num_sections = int.from_bytes(self.mem_read(nt + 0x06, 2), "little")
                    sect_off = nt + 0x18 + 224
                for i in range(num_sections):
                    sh = sect_off + i * 40
                    va = int.from_bytes(self.mem_read(sh + 12, 4), "little")
                    vsize = int.from_bytes(self.mem_read(sh + 8, 4), "little")
                    if va <= rva < va + vsize:
                        return base + rva
            except Exception:
                pass
            return 0

        reg("RtlImageRvaToVa", RtlImageRvaToVa_impl, 4)

        def RtlGetCurrentProcessorNumber_impl(self, emu, argv, ctx=None):
            return 0

        reg("RtlGetCurrentProcessorNumber", RtlGetCurrentProcessorNumber_impl, 0)

        def RtlGetCurrentProcessorNumberEx_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, b"\x00" * 4)
            return 0

        reg("RtlGetCurrentProcessorNumberEx", RtlGetCurrentProcessorNumberEx_impl, 1)

    def _register_nt_batch(self):
        """
        Register real handlers for common ntdll Nt*/Zw* native API functions,
        using the emulator's file/registry/memory/object primitives.
        """
        ptr = self.get_ptr_size()
        sd = e_arch.CALL_CONV_STDCALL
        STATUS_SUCCESS = 0
        STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
        STATUS_VARIABLE_NOT_FOUND = 0xC0000100
        STATUS_INVALID_INFO_CLASS = 0xC0000003
        STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
        STATUS_ACCESS_DENIED = 0xC0000022
        STATUS_BUFFER_OVERFLOW = 0x80000005

        def reg(name, func, argc):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, sd, None)
            zw = "Zw" + name[2:]
            if zw not in self.funcs:
                self.funcs[zw] = (zw, func, argc, sd, None)

        def _read_oa_name(oa):
            """Read the ObjectName UNICODE_STRING from an OBJECT_ATTRIBUTES."""
            if not oa:
                return None
            # OBJECT_ATTRIBUTES: Length, RootDirectory, ObjectName, ...
            us_addr = int.from_bytes(self.mem_read(oa + ptr * 2, ptr), "little")
            if not us_addr:
                return None
            return self.read_unicode_string(us_addr)

        def _write_io_status(iosb, status, info=0):
            if not iosb:
                return
            if ptr == 8:
                self.mem_write(iosb, struct.pack("<QQ", status, info))
            else:
                self.mem_write(iosb, struct.pack("<II", status, info))

        def _write_us(out_us, string, extra_buf=None):
            """Write a UNICODE_STRING (and its buffer) at out_us."""
            data = string.encode("utf-16le")
            buf = extra_buf or self.mem_alloc(len(data) + 2, tag="api.ntdll.us")
            self.mem_write(buf, data + b"\x00\x00")
            self.mem_write(
                out_us,
                struct.pack("<HH" + ("4x" if ptr == 8 else ""), len(data), len(data) + 2)
                + buf.to_bytes(ptr, "little"),
            )
            return buf

        def NtAllocateVirtualMemory(self, emu, argv, ctx=None):
            proc, base_ptr, zero_bits, size_ptr, alloc_type, protect = argv
            if not base_ptr or not size_ptr:
                return STATUS_ACCESS_DENIED
            size = int.from_bytes(self.mem_read(size_ptr, ptr), "little")
            base = int.from_bytes(self.mem_read(base_ptr, ptr), "little")
            if not size:
                return STATUS_INVALID_INFO_CLASS
            if base:
                try:
                    self.emu.mem_map(size, base=base, tag="api.ntdll.valloc")
                except Exception:
                    return STATUS_ACCESS_DENIED
            else:
                base = self.emu.mem_map(size, base=None, tag="api.ntdll.valloc")
            self.mem_write(base_ptr, base.to_bytes(ptr, "little"))
            self.mem_write(size_ptr, size.to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtAllocateVirtualMemory", NtAllocateVirtualMemory, 6)

        def NtFreeVirtualMemory(self, emu, argv, ctx=None):
            proc, base_ptr, size_ptr, free_type = argv
            if not base_ptr:
                return STATUS_ACCESS_DENIED
            base = int.from_bytes(self.mem_read(base_ptr, ptr), "little")
            if base:
                try:
                    self.emu.mem_free(base)
                except Exception:
                    return STATUS_ACCESS_DENIED
            self.mem_write(base_ptr, b"\x00" * ptr)
            if size_ptr:
                self.mem_write(size_ptr, b"\x00" * ptr)
            return STATUS_SUCCESS

        reg("NtFreeVirtualMemory", NtFreeVirtualMemory, 4)

        def NtProtectVirtualMemory(self, emu, argv, ctx=None):
            proc, base_ptr, size_ptr, new_prot, old_prot = argv
            if not base_ptr or not size_ptr or not old_prot:
                return STATUS_ACCESS_DENIED
            base = int.from_bytes(self.mem_read(base_ptr, ptr), "little")
            size = int.from_bytes(self.mem_read(size_ptr, ptr), "little")
            try:
                self.emu.mem_protect(base, size, new_prot)
            except Exception:
                return STATUS_ACCESS_DENIED
            self.mem_write(old_prot, struct.pack("<I", new_prot))
            return STATUS_SUCCESS

        reg("NtProtectVirtualMemory", NtProtectVirtualMemory, 5)

        def NtReadVirtualMemory(self, emu, argv, ctx=None):
            proc, base, buffer, size, bytes_read = argv
            try:
                data = self.emu.mem_read(base, size)
            except Exception:
                return STATUS_ACCESS_DENIED
            if buffer:
                self.emu.mem_write(buffer, data)
            if bytes_read:
                self.mem_write(bytes_read, len(data).to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtReadVirtualMemory", NtReadVirtualMemory, 5)

        def NtWriteVirtualMemory(self, emu, argv, ctx=None):
            proc, base, buffer, size, bytes_written = argv
            try:
                data = self.emu.mem_read(buffer, size)
                self.emu.mem_write(base, data)
            except Exception:
                return STATUS_ACCESS_DENIED
            if bytes_written:
                self.mem_write(bytes_written, size.to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtWriteVirtualMemory", NtWriteVirtualMemory, 5)

        def NtQueryVirtualMemory(self, emu, argv, ctx=None):
            proc, base, info_class, info, length, ret_len = argv
            if info_class != 0:  # MemoryBasicInformation
                return STATUS_INVALID_INFO_CLASS
            if length < 48:
                return STATUS_INFO_LENGTH_MISMATCH
            mm = self.emu.get_address_map(base)
            region = mm.size if mm else 0x1000
            self.mem_write(
                info,
                struct.pack("<QQIII", base, base, 0x04, region, 0x1000)
                + struct.pack("<II", 0x04, 0x20000),
            )
            if ret_len:
                self.mem_write(ret_len, struct.pack("<I", 48))
            return STATUS_SUCCESS

        reg("NtQueryVirtualMemory", NtQueryVirtualMemory, 6)

        def NtQueryInformationProcess(self, emu, argv, ctx=None):
            proc, info_class, info, length, ret_len = argv
            proc_obj = self.emu.get_object_from_handle(proc) if proc else None
            if proc_obj is None:
                proc_obj = self.emu.get_current_process()
            if info_class == 0:  # ProcessBasicInformation
                if length < 48:
                    return STATUS_INFO_LENGTH_MISMATCH
                peb_addr = getattr(proc_obj.peb, "address", 0) if proc_obj else 0
                pid = proc_obj.id if proc_obj else 0
                self.mem_write(
                    info,
                    struct.pack("<QQQQQQQ", 0, peb_addr, 1, 8, pid, 4, 0),
                )
                if ret_len:
                    self.mem_write(ret_len, struct.pack("<I", 48))
                return STATUS_SUCCESS
            if info_class == 27:  # ProcessImageFileName
                img = getattr(proc_obj, "image", "") if proc_obj else ""
                _write_us(info, img or "sample.exe")
                if ret_len:
                    self.mem_write(ret_len, struct.pack("<I", 8))
                return STATUS_SUCCESS
            if info_class in (31, 36):  # ProcessDebugPort / ProcessDebugObjectHandle
                if length < ptr:
                    return STATUS_INFO_LENGTH_MISMATCH
                self.mem_write(info, b"\x00" * ptr)
                if ret_len:
                    self.mem_write(ret_len, struct.pack("<I", ptr))
                return STATUS_SUCCESS
            return STATUS_INVALID_INFO_CLASS

        reg("NtQueryInformationProcess", NtQueryInformationProcess, 5)

        def NtSetInformationProcess(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("NtSetInformationProcess", NtSetInformationProcess, 4)

        def NtQueryInformationThread(self, emu, argv, ctx=None):
            thread, info_class, info, length, ret_len = argv
            thread_obj = self.emu.get_object_from_handle(thread) if thread else None
            if info_class == 0:  # ThreadBasicInformation
                if length < 48:
                    return STATUS_INFO_LENGTH_MISMATCH
                tid = thread_obj.tid if thread_obj else 0
                self.mem_write(info, struct.pack("<QQQQQQQ", 0, 0, 0, tid, 0xFFFFFFFF, 0, 0))
                if ret_len:
                    self.mem_write(ret_len, struct.pack("<I", 48))
                return STATUS_SUCCESS
            return STATUS_INVALID_INFO_CLASS

        reg("NtQueryInformationThread", NtQueryInformationThread, 5)

        def NtSetInformationThread(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("NtSetInformationThread", NtSetInformationThread, 4)

        def NtSuspendThread(self, emu, argv, ctx=None):
            thread, prev_count = argv
            if prev_count:
                self.mem_write(prev_count, b"\x00\x00\x00\x00")
            return STATUS_SUCCESS

        reg("NtSuspendThread", NtSuspendThread, 2)

        def NtResumeThread(self, emu, argv, ctx=None):
            thread, prev_count = argv
            thread_obj = self.emu.get_object_from_handle(thread) if thread else None
            if thread_obj:
                try:
                    self.emu.resume_thread(thread_obj)
                except Exception:
                    pass
            if prev_count:
                self.mem_write(prev_count, b"\x00\x00\x00\x00")
            return STATUS_SUCCESS

        reg("NtResumeThread", NtResumeThread, 2)

        def NtTerminateProcess(self, emu, argv, ctx=None):
            self.emu.exit_process()
            return STATUS_SUCCESS

        reg("NtTerminateProcess", NtTerminateProcess, 2)

        def NtTerminateThread(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("NtTerminateThread", NtTerminateThread, 2)

        def NtGetContextThread(self, emu, argv, ctx=None):
            return STATUS_ACCESS_DENIED

        reg("NtGetContextThread", NtGetContextThread, 2)

        def NtSetContextThread(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("NtSetContextThread", NtSetContextThread, 2)

        def NtOpenProcess(self, emu, argv, ctx=None):
            proc_out, access, oa, client_id = argv
            proc = self.emu.get_current_process()
            if proc_out and proc:
                hnd = self.emu.get_object_handle(proc)
                self.mem_write(proc_out, hnd.to_bytes(ptr, "little"))
                return STATUS_SUCCESS
            return STATUS_ACCESS_DENIED

        reg("NtOpenProcess", NtOpenProcess, 4)

        def NtDuplicateObject(self, emu, argv, ctx=None):
            src, src_handle, dst, access, options, dup, handle_out = argv
            if handle_out:
                self.mem_write(handle_out, src_handle.to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtDuplicateObject", NtDuplicateObject, 7)

        def NtQuerySystemTime(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                ts = 116444736000000000 + int(datetime.datetime.now(datetime.timezone.utc).timestamp()) * 10000000
                self.mem_write(out, struct.pack("<Q", ts))
            return STATUS_SUCCESS

        reg("NtQuerySystemTime", NtQuerySystemTime, 1)

        def NtQueryPerformanceCounter(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, struct.pack("<Q", 0x5FD27D571F))
            return STATUS_SUCCESS

        reg("NtQueryPerformanceCounter", NtQueryPerformanceCounter, 1)

        def NtQueryPerformanceFrequency(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, struct.pack("<Q", 10000000))
            return STATUS_SUCCESS

        reg("NtQueryPerformanceFrequency", NtQueryPerformanceFrequency, 1)

        def NtDelayExecution(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("NtDelayExecution", NtDelayExecution, 2)

        def NtYieldExecution(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("NtYieldExecution", NtYieldExecution, 0)

        def NtQueryTimerResolution(self, emu, argv, ctx=None):
            mn, mx, cur = argv
            if mn:
                self.mem_write(mn, struct.pack("<I", 10000))
            if mx:
                self.mem_write(mx, struct.pack("<I", 156250))
            if cur:
                self.mem_write(cur, struct.pack("<I", 156250))
            return STATUS_SUCCESS

        reg("NtQueryTimerResolution", NtQueryTimerResolution, 3)

        def NtSetTimerResolution(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("NtSetTimerResolution", NtSetTimerResolution, 3)

        def NtQueryDefaultLocale(self, emu, argv, ctx=None):
            reserved, out = argv
            if out:
                self.mem_write(out, struct.pack("<I", 0x409))
            return STATUS_SUCCESS

        reg("NtQueryDefaultLocale", NtQueryDefaultLocale, 2)

        def NtQueryDefaultUILanguage(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, struct.pack("<H", 0x409))
            return STATUS_SUCCESS

        reg("NtQueryDefaultUILanguage", NtQueryDefaultUILanguage, 1)

        def NtFlushInstructionCache(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("NtFlushInstructionCache", NtFlushInstructionCache, 3)

        def NtQueryObject(self, emu, argv, ctx=None):
            handle, info_class, info, length, ret_len = argv
            if info_class == 0:  # ObjectBasicInformation
                if length < 20:
                    return STATUS_INFO_LENGTH_MISMATCH
                self.mem_write(info, struct.pack("<IHHIIII", 0, 0x1FFFFF, 1, 1, 0, 0))
                if ret_len:
                    self.mem_write(ret_len, struct.pack("<I", 20))
                return STATUS_SUCCESS
            return STATUS_INVALID_INFO_CLASS

        reg("NtQueryObject", NtQueryObject, 5)

        def NtCreateEvent(self, emu, argv, ctx=None):
            handle_out, access, oa, evt_type, initial_state = argv
            name = _read_oa_name(oa) or ""
            hnd, evt = self.emu.create_event(name)
            if handle_out:
                self.mem_write(handle_out, hnd.to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtCreateEvent", NtCreateEvent, 5)

        def NtOpenEvent(self, emu, argv, ctx=None):
            handle_out, access, oa = argv
            name = _read_oa_name(oa)
            hnd, evt = self.emu.create_event(name or "")
            if handle_out:
                self.mem_write(handle_out, hnd.to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtOpenEvent", NtOpenEvent, 3)

        def NtSetEvent(self, emu, argv, ctx=None):
            handle, prev_state = argv
            if prev_state:
                self.mem_write(prev_state, b"\x00\x00\x00\x00")
            return STATUS_SUCCESS

        reg("NtSetEvent", NtSetEvent, 2)

        def NtResetEvent(self, emu, argv, ctx=None):
            handle, prev_state = argv
            if prev_state:
                self.mem_write(prev_state, b"\x00\x00\x00\x00")
            return STATUS_SUCCESS

        reg("NtResetEvent", NtResetEvent, 2)

        def NtCreateMutant(self, emu, argv, ctx=None):
            handle_out, access, oa, initial_owned = argv
            name = _read_oa_name(oa) or ""
            hnd, mtx = self.emu.create_mutant(name)
            if handle_out:
                self.mem_write(handle_out, hnd.to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtCreateMutant", NtCreateMutant, 4)

        def NtOpenMutant(self, emu, argv, ctx=None):
            handle_out, access, oa = argv
            name = _read_oa_name(oa)
            hnd, mtx = self.emu.create_mutant(name or "")
            if handle_out:
                self.mem_write(handle_out, hnd.to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtOpenMutant", NtOpenMutant, 3)

        def NtReleaseMutant(self, emu, argv, ctx=None):
            handle, prev_count = argv
            if prev_count:
                self.mem_write(prev_count, struct.pack("<i", 1))
            return STATUS_SUCCESS

        reg("NtReleaseMutant", NtReleaseMutant, 2)

        def NtCreateSemaphore(self, emu, argv, ctx=None):
            handle_out, access, oa, initial, maximum = argv
            name = _read_oa_name(oa) or ""
            hnd, evt = self.emu.create_event(name)
            if handle_out:
                self.mem_write(handle_out, hnd.to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtCreateSemaphore", NtCreateSemaphore, 5)

        def NtOpenSemaphore(self, emu, argv, ctx=None):
            handle_out, access, oa = argv
            name = _read_oa_name(oa)
            hnd, evt = self.emu.create_event(name or "")
            if handle_out:
                self.mem_write(handle_out, hnd.to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtOpenSemaphore", NtOpenSemaphore, 3)

        def NtReleaseSemaphore(self, emu, argv, ctx=None):
            handle, release_count, prev_count = argv
            if prev_count:
                self.mem_write(prev_count, struct.pack("<I", 0))
            return STATUS_SUCCESS

        reg("NtReleaseSemaphore", NtReleaseSemaphore, 3)

        def NtClose(self, emu, argv, ctx=None):
            handle = argv[0]
            fman = getattr(self.emu, "fileman", None)
            if fman is not None:
                if fman.file_handles.pop(handle, None) is not None:
                    return STATUS_SUCCESS
                if fman.pipe_handles.pop(handle, None) is not None:
                    return STATUS_SUCCESS
                if fman.file_maps.pop(handle, None) is not None:
                    return STATUS_SUCCESS
            om = getattr(self.emu, "om", None)
            if om is not None:
                obj = om.close_handle(handle)
                if obj is not None:
                    if not getattr(obj, "handles", None):
                        self.emu.dec_ref(obj)
                    return STATUS_SUCCESS
            return 0xC0000008  # STATUS_INVALID_HANDLE

        reg("NtClose", NtClose, 1)

        def NtCreateFile(self, emu, argv, ctx=None):
            handle_out, access, oa, iosb, alloc_size, attrs, share, options, disposition, create_opts, ea, ea_len = argv
            if handle_out:
                self.mem_write(handle_out, b"\x00" * ptr)
            if iosb:
                _write_io_status(iosb, STATUS_OBJECT_NAME_NOT_FOUND)
            path = _read_oa_name(oa)
            if not path:
                return STATUS_OBJECT_NAME_NOT_FOUND
            argv[3] = path
            cd = ddk.get_create_disposition(disposition)
            if cd:
                argv[7] = cd
            ad = ddk.get_file_access_defines(access)
            if ad:
                argv[1] = " | ".join(ad)
            npath = path.removeprefix("\\??\\").rstrip("\\")
            create = disposition in (3, 4, 5, 6)
            truncate = disposition in (1, 5, 6)
            hnd = self.file_open(npath, create=False)
            if not hnd and create:
                hnd = self.file_open(npath, create=True, truncate=truncate)
            if not hnd:
                self.record_file_access_event(path, "file_open", disposition=cd, access=ad)
                return STATUS_OBJECT_NAME_NOT_FOUND
            if handle_out:
                self.mem_write(handle_out, hnd.to_bytes(ptr, "little"))
            if iosb:
                _write_io_status(iosb, STATUS_SUCCESS)
            self.record_file_access_event(path, "file_open", disposition=cd, access=ad)
            return STATUS_SUCCESS

        reg("NtCreateFile", NtCreateFile, 12)

        def NtOpenFile(self, emu, argv, ctx=None):
            handle_out, access, oa, iosb, share, options = argv
            if handle_out:
                self.mem_write(handle_out, b"\x00" * ptr)
            if iosb:
                _write_io_status(iosb, STATUS_OBJECT_NAME_NOT_FOUND)
            path = _read_oa_name(oa)
            if not path:
                return STATUS_OBJECT_NAME_NOT_FOUND
            hnd = self.file_open(path, create=False)
            if not hnd:
                return STATUS_OBJECT_NAME_NOT_FOUND
            if handle_out:
                self.mem_write(handle_out, hnd.to_bytes(ptr, "little"))
            if iosb:
                _write_io_status(iosb, STATUS_SUCCESS)
            return STATUS_SUCCESS

        reg("NtOpenFile", NtOpenFile, 6)

        def NtQueryInformationFile(self, emu, argv, ctx=None):
            handle, iosb, info, length, info_class = argv
            f = self.file_get(handle)
            if not f:
                if iosb:
                    _write_io_status(iosb, 0xC0000008)
                return 0xC0000008
            path = getattr(f, "path", "") or ""
            if info_class == 5:  # FileStandardInformation
                size = f.get_size()
                self.mem_write(info, struct.pack("<QQIIII", size, size, 1, 0, 0, 0))
                written = 40
            elif info_class == 4:  # FileBasicInformation
                self.mem_write(info, b"\x00" * 32 + struct.pack("<II", 0x80, 0))
                written = 40
            elif info_class == 9:  # FileNameInformation
                name = path.encode("utf-16le")
                self.mem_write(info, struct.pack("<I", len(name)) + name)
                written = 4 + len(name)
            elif info_class == 14:  # FilePositionInformation
                pos = f.tell() or 0
                self.mem_write(info, struct.pack("<Q", pos))
                written = 8
            else:
                if iosb:
                    _write_io_status(iosb, STATUS_INVALID_INFO_CLASS)
                return STATUS_INVALID_INFO_CLASS
            if iosb:
                _write_io_status(iosb, STATUS_SUCCESS, written)
            return STATUS_SUCCESS

        reg("NtQueryInformationFile", NtQueryInformationFile, 5)

        def NtSetInformationFile(self, emu, argv, ctx=None):
            handle, iosb, info, length, info_class = argv
            f = self.file_get(handle)
            if not f:
                if iosb:
                    _write_io_status(iosb, 0xC0000008)
                return 0xC0000008
            if info_class == 14:  # FilePositionInformation
                pos = int.from_bytes(self.mem_read(info, 8), "little")
                f.seek(pos, 0)
            if iosb:
                _write_io_status(iosb, STATUS_SUCCESS, length)
            return STATUS_SUCCESS

        reg("NtSetInformationFile", NtSetInformationFile, 5)

        def NtQueryVolumeInformationFile(self, emu, argv, ctx=None):
            handle, iosb, info, length, info_class = argv
            written = 0
            if info_class == 1:  # FileFsVolumeInformation
                label = b"C:"
                data = b"\x00" * 8 + struct.pack("<I", 0x4D4142) + struct.pack("<I", len(label))
                data += b"\x00\x00" + label
                self.mem_write(info, data[:length])
                written = min(length, len(data))
            if iosb:
                _write_io_status(iosb, STATUS_SUCCESS, written)
            return STATUS_SUCCESS

        reg("NtQueryVolumeInformationFile", NtQueryVolumeInformationFile, 5)

        def NtDeviceIoControlFile(self, emu, argv, ctx=None):
            handle, iosb, event, apc, apc_ctx, code, in_buf, in_len, out_buf, out_len = argv
            if iosb:
                _write_io_status(iosb, STATUS_SUCCESS)
            return STATUS_SUCCESS

        reg("NtDeviceIoControlFile", NtDeviceIoControlFile, 10)

        def NtQueryEnvironmentVariable(self, emu, argv, ctx=None):
            name_us, value_us = argv
            if not name_us or not value_us:
                return STATUS_VARIABLE_NOT_FOUND
            name = self.read_unicode_string(name_us)
            try:
                env = self.emu.get_env() or {}
                value = env.get(name.lower(), "") or ""
            except Exception:
                value = ""
            if not value:
                return STATUS_VARIABLE_NOT_FOUND
            _write_us(value_us, value)
            return STATUS_SUCCESS

        reg("NtQueryEnvironmentVariable", NtQueryEnvironmentVariable, 2)

        def NtSetEnvironmentVariable(self, emu, argv, ctx=None):
            name_us, value_us = argv
            if not name_us:
                return STATUS_VARIABLE_NOT_FOUND
            name = self.read_unicode_string(name_us)
            value = self.read_unicode_string(value_us) if value_us else ""
            try:
                self.emu.set_env(name, value)
            except Exception:
                pass
            return STATUS_SUCCESS

        reg("NtSetEnvironmentVariable", NtSetEnvironmentVariable, 2)

        def NtQuerySystemInformation(self, emu, argv, ctx=None):
            info_class, info, length, ret_len = argv

            def _done(written):
                if ret_len:
                    self.mem_write(ret_len, struct.pack("<I", written))
                return STATUS_SUCCESS

            if info_class == 0:  # SystemBasicInformation
                if length < 48:
                    return STATUS_INFO_LENGTH_MISMATCH
                is64 = self.get_ptr_size() == 8
                self.mem_write(
                    info,
                    struct.pack("<IIIIII", 0, 0x10000, 0x1000, 0x200000, 0x1000, 0x10000)
                    + struct.pack("<Q", 0x10000)
                    + struct.pack("<Q", 0x7FFFFFFEFFFF if is64 else 0x7FFEFFFF)
                    + struct.pack("<Q", 1)
                    + struct.pack("<B", 1)
                    + b"\x00" * 7,
                )
                return _done(48)
            if info_class == 5:  # SystemProcessorPerformanceInformation
                if length < 48:
                    return STATUS_INFO_LENGTH_MISMATCH
                self.mem_write(info, b"\x00" * 48)
                return _done(48)
            if info_class == 8:  # SystemTimeOfDayInformation
                if length < 48:
                    return STATUS_INFO_LENGTH_MISMATCH
                ts = 116444736000000000 + int(datetime.datetime.now(datetime.timezone.utc).timestamp()) * 10000000
                self.mem_write(info, struct.pack("<QQQI", ts - 3600000000000, ts, 0, 1) + b"\x00" * 20)
                return _done(48)
            if info_class == 129:  # SystemProcessorInformation
                if length < 24:
                    return STATUS_INFO_LENGTH_MISMATCH
                arch = 9 if self.get_ptr_size() == 8 else 0
                self.mem_write(info, struct.pack("<IHHII", arch, 6, 0, 0, 1) + b"\x00" * 8)
                return _done(24)
            return STATUS_INVALID_INFO_CLASS

        reg("NtQuerySystemInformation", NtQuerySystemInformation, 4)

        def NtCreateKey(self, emu, argv, ctx=None):
            handle_out, access, oa, title_index, class_name, create_opts, disposition = argv
            if handle_out:
                self.mem_write(handle_out, b"\x00" * ptr)
            path = _read_oa_name(oa)
            if not path:
                return STATUS_OBJECT_NAME_NOT_FOUND
            hnd = self.reg_open_key(path, create=True)
            if not hnd:
                return STATUS_OBJECT_NAME_NOT_FOUND
            if handle_out:
                self.mem_write(handle_out, hnd.to_bytes(ptr, "little"))
            if disposition:
                self.mem_write(disposition, struct.pack("<I", 1))  # REG_CREATED_NEW_KEY
            return STATUS_SUCCESS

        reg("NtCreateKey", NtCreateKey, 7)

        def NtOpenKey(self, emu, argv, ctx=None):
            handle_out, access, oa = argv
            if handle_out:
                self.mem_write(handle_out, b"\x00" * ptr)
            path = _read_oa_name(oa)
            if not path:
                return STATUS_OBJECT_NAME_NOT_FOUND
            hnd = self.reg_open_key(path, create=False)
            if not hnd:
                return STATUS_OBJECT_NAME_NOT_FOUND
            if handle_out:
                self.mem_write(handle_out, hnd.to_bytes(ptr, "little"))
            return STATUS_SUCCESS

        reg("NtOpenKey", NtOpenKey, 3)

        def NtQueryValueKey(self, emu, argv, ctx=None):
            handle, name_us, info_class, info, length, ret_len = argv
            key = self.reg_get_key(handle)
            if not key:
                return 0xC0000008
            name = self.read_unicode_string(name_us) if name_us else ""
            val = key.get_value(name)
            if not val:
                return 0xC0000034  # STATUS_OBJECT_NAME_NOT_FOUND
            if info_class == 2:  # KeyValueFullInformation
                typ = val.get_type()
                vtype = 1 if typ == "REG_SZ" else 4 if typ == "REG_DWORD" else 3
                data = val.get_data()
                if isinstance(data, str):
                    data = data.encode("utf-16le") + b"\x00\x00"
                elif isinstance(data, int):
                    data = data.to_bytes(4, "little")
                else:
                    data = bytes(data)
                name_b = name.encode("utf-16le")
                data_off = 0x18 + len(name_b)
                total = data_off + len(data)
                if length < total:
                    if ret_len:
                        self.mem_write(ret_len, struct.pack("<I", total))
                    return STATUS_BUFFER_OVERFLOW
                self.mem_write(info, struct.pack("<IIIII", 0, vtype, data_off, len(data), len(name_b)))
                self.mem_write(info + 0x18, name_b)
                self.mem_write(info + data_off, data)
                if ret_len:
                    self.mem_write(ret_len, struct.pack("<I", total))
                return STATUS_SUCCESS
            return STATUS_INVALID_INFO_CLASS

        reg("NtQueryValueKey", NtQueryValueKey, 6)

        def NtSetValueKey(self, emu, argv, ctx=None):
            handle, name_us, title_index, typ, data, data_len = argv
            key = self.reg_get_key(handle)
            if not key:
                return 0xC0000008
            name = self.read_unicode_string(name_us) if name_us else ""
            if typ == 4:  # REG_DWORD
                value = int.from_bytes(self.mem_read(data, 4), "little")
                type_name = "REG_DWORD"
            elif typ in (1, 2):
                value = self.read_unicode_string(data) if data else ""
                type_name = "REG_SZ"
            else:
                value = self.mem_read(data, data_len)
                type_name = "REG_BINARY"
            key.create_value(name, type_name, value)
            return STATUS_SUCCESS

        reg("NtSetValueKey", NtSetValueKey, 6)

        def NtDeleteValueKey(self, emu, argv, ctx=None):
            handle, name_us = argv
            key = self.reg_get_key(handle)
            if not key:
                return 0xC0000008
            name = self.read_unicode_string(name_us) if name_us else ""
            key.create_value(name, "REG_NONE", None)
            return STATUS_SUCCESS

        reg("NtDeleteValueKey", NtDeleteValueKey, 2)

        def NtDeleteKey(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("NtDeleteKey", NtDeleteKey, 1)

        def EtwEventRegister(self, emu, argv, ctx=None):
            provider_id, callback, context, handle_out = argv
            if handle_out:
                self.mem_write(handle_out, struct.pack("<Q", 0x1))
            return STATUS_SUCCESS

        reg("EtwEventRegister", EtwEventRegister, 4)

        def EtwEventUnregister(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("EtwEventUnregister", EtwEventUnregister, 1)

        def EtwEventEnabled(self, emu, argv, ctx=None):
            return 0

        reg("EtwEventEnabled", EtwEventEnabled, 3)

        def EtwEventWrite(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("EtwEventWrite", EtwEventWrite, 4)
        reg("EtwEventWriteEx", EtwEventWrite, 8)
        reg("EtwEventWriteFull", EtwEventWrite, 9)
        reg("EtwEventWriteString", EtwEventWrite, 5)
        reg("EtwEventWriteTransfer", EtwEventWrite, 6)
        reg("EtwEventWriteNoRegistration", EtwEventWrite, 5)
        reg("EtwEventWriteStartScenario", EtwEventWrite, 8)
        reg("EtwEventWriteEndScenario", EtwEventWrite, 8)

        def EtwEventSetInformation(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("EtwEventSetInformation", EtwEventSetInformation, 5)

        def EtwEventActivityIdControl(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("EtwEventActivityIdControl", EtwEventActivityIdControl, 2)

        def EtwGetTraceEnableFlags(self, emu, argv, ctx=None):
            return 0

        reg("EtwGetTraceEnableFlags", EtwGetTraceEnableFlags, 1)

        def EtwGetTraceEnableLevel(self, emu, argv, ctx=None):
            return 0

        reg("EtwGetTraceEnableLevel", EtwGetTraceEnableLevel, 1)

        def EtwGetTraceLoggerHandle(self, emu, argv, ctx=None):
            return 0xFFFFFFFFFFFFFFFF

        reg("EtwGetTraceLoggerHandle", EtwGetTraceLoggerHandle, 1)

        def EtwRegisterTraceGuidsW(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("EtwRegisterTraceGuidsW", EtwRegisterTraceGuidsW, 8)
        reg("EtwRegisterTraceGuidsA", EtwRegisterTraceGuidsW, 8)

        def EtwUnregisterTraceGuids(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("EtwUnregisterTraceGuids", EtwUnregisterTraceGuids, 1)

        def EtwTraceMessage(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("EtwTraceMessage", EtwTraceMessage, 6)
        reg("EtwTraceMessageVa", EtwTraceMessage, 6)

        def EtwTraceEventInstance(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("EtwTraceEventInstance", EtwTraceEventInstance, 4)

        def EtwGetCpuSpeed(self, emu, argv, ctx=None):
            return 0

        reg("EtwGetCpuSpeed", EtwGetCpuSpeed, 1)

        def EtwEnumerateProcessRegGuids(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("EtwEnumerateProcessRegGuids", EtwEnumerateProcessRegGuids, 5)

        def LdrGetDllHandle(self, emu, argv, ctx=None):
            base, name_us, handle_out = argv
            if handle_out:
                self.mem_write(handle_out, b"\x00" * ptr)
            if not name_us:
                return 0xC0000135  # STATUS_DLL_NOT_FOUND
            name = self.read_unicode_string(name_us)
            base_name = name.lower().replace(".dll", "")
            for mod in getattr(self.emu, "modules", []) or []:
                mod_name = (getattr(mod, "name", "") or "").lower()
                if mod_name == base_name or mod_name.startswith(base_name):
                    if handle_out:
                        self.mem_write(handle_out, mod.base.to_bytes(ptr, "little"))
                    return STATUS_SUCCESS
            return 0xC0000135

        reg("LdrGetDllHandle", LdrGetDllHandle, 3)
        reg("LdrGetDllHandleByName", LdrGetDllHandle, 4)
        reg("LdrGetDllHandleEx", LdrGetDllHandle, 6)

        def LdrGetDllFullName(self, emu, argv, ctx=None):
            module, name_us = argv
            if not name_us:
                return 0xC000000D
            name = "C:\\Windows\\system32\\unknown.dll"
            for mod in getattr(self.emu, "modules", []) or []:
                if mod.base == module:
                    name = f"C:\\Windows\\system32\\{(getattr(mod, 'name', '') or 'unknown')}.dll"
                    break
            _write_us(name_us, name)
            return STATUS_SUCCESS

        reg("LdrGetDllFullName", LdrGetDllFullName, 2)

        def LdrAddRefDll(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("LdrAddRefDll", LdrAddRefDll, 2)

        def LdrUnloadDll(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("LdrUnloadDll", LdrUnloadDll, 1)

        def LdrLockLoaderLock(self, emu, argv, ctx=None):
            flags, cookie, handle = argv
            if cookie:
                self.mem_write(cookie, struct.pack("<Q", 0x1234))
            return STATUS_SUCCESS

        reg("LdrLockLoaderLock", LdrLockLoaderLock, 3)

        def LdrUnlockLoaderLock(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("LdrUnlockLoaderLock", LdrUnlockLoaderLock, 2)

        def LdrFindEntryForAddress(self, emu, argv, ctx=None):
            addr, entry_out = argv
            if not entry_out:
                return 0xC000000D
            for mod in getattr(self.emu, "modules", []) or []:
                if mod.base <= addr < mod.base + mod.image_size:
                    self.mem_write(entry_out, (mod.base + 0x20).to_bytes(ptr, "little"))
                    return STATUS_SUCCESS
            return 0xC0000225  # STATUS_NOT_FOUND

        reg("LdrFindEntryForAddress", LdrFindEntryForAddress, 2)

        def LdrQueryProcessModuleInformation(self, emu, argv, ctx=None):
            info, size, needed = argv
            if needed:
                self.mem_write(needed, struct.pack("<I", 0))
            return STATUS_SUCCESS

        reg("LdrQueryProcessModuleInformation", LdrQueryProcessModuleInformation, 3)

        def LdrGetDllDirectory(self, emu, argv, ctx=None):
            name_us = argv[0]
            if not name_us:
                return 0xC000000D
            _write_us(name_us, "C:\\Windows\\system32")
            return STATUS_SUCCESS

        reg("LdrGetDllDirectory", LdrGetDllDirectory, 1)

        def LdrSetDllDirectory(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("LdrSetDllDirectory", LdrSetDllDirectory, 2)

        def LdrDisableThreadCalloutsForDll(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("LdrDisableThreadCalloutsForDll", LdrDisableThreadCalloutsForDll, 1)

        def LdrProcessInitializationComplete(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("LdrProcessInitializationComplete", LdrProcessInitializationComplete, 0)

        def LdrRegisterDllNotification(self, emu, argv, ctx=None):
            flags, callback, context, cookie = argv
            if cookie:
                self.mem_write(cookie, struct.pack("<Q", 1))
            return STATUS_SUCCESS

        reg("LdrRegisterDllNotification", LdrRegisterDllNotification, 4)

        def LdrUnregisterDllNotification(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("LdrUnregisterDllNotification", LdrUnregisterDllNotification, 1)

        def LdrFastFailInLoaderCallout(self, emu, argv, ctx=None):
            return 0xC0000409

        reg("LdrFastFailInLoaderCallout", LdrFastFailInLoaderCallout, 2)

        def LdrGetProcedureAddressEx(self, emu, argv, ctx=None):
            module, name, type_, out = argv
            if not out:
                return 0xC000000D
            self.mem_write(out, b"\x00" * ptr)
            return 0xC0000139  # STATUS_ENTRYPOINT_NOT_FOUND

        reg("LdrGetProcedureAddressEx", LdrGetProcedureAddressEx, 4)

        def RtlQueryTimeZoneInformation(self, emu, argv, ctx=None):
            tzi = argv[0]
            if not tzi:
                return 0xC000000D
            self.mem_write(tzi, struct.pack("<i", 0) + b"\x00" * 0xAC)
            return STATUS_SUCCESS

        reg("RtlQueryTimeZoneInformation", RtlQueryTimeZoneInformation, 1)

        def RtlSetTimeZoneInformation(self, emu, argv, ctx=None):
            return STATUS_SUCCESS

        reg("RtlSetTimeZoneInformation", RtlSetTimeZoneInformation, 1)

        def RtlQueryDynamicTimeZoneInformation(self, emu, argv, ctx=None):
            tzi = argv[0]
            if not tzi:
                return 0xC000000D
            self.mem_write(tzi, b"\x00" * 0xAC)
            return STATUS_SUCCESS

        reg("RtlQueryDynamicTimeZoneInformation", RtlQueryDynamicTimeZoneInformation, 1)

        def RtlQueryEnvironmentVariable(self, emu, argv, ctx=None):
            name_us, value_us = argv
            if not name_us or not value_us:
                return 0xC0000100
            name = self.read_unicode_string(name_us)
            try:
                env = self.emu.get_env() or {}
                value = env.get(name.lower(), "") or ""
            except Exception:
                value = ""
            if not value:
                return 0xC0000100
            _write_us(value_us, value)
            return STATUS_SUCCESS

        reg("RtlQueryEnvironmentVariable", RtlQueryEnvironmentVariable, 2)

        def RtlSetEnvironmentVariable(self, emu, argv, ctx=None):
            name_us, value_us = argv
            if not name_us:
                return 0xC0000100
            name = self.read_unicode_string(name_us)
            value = self.read_unicode_string(value_us) if value_us else ""
            try:
                self.emu.set_env(name, value)
            except Exception:
                pass
            return STATUS_SUCCESS

        reg("RtlSetEnvironmentVariable", RtlSetEnvironmentVariable, 2)

        def RtlGetNtProductType(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, struct.pack("<I", 1))  # NtProductWinNt
            return STATUS_SUCCESS

        reg("RtlGetNtProductType", RtlGetNtProductType, 1)

        def RtlGetSuiteMask(self, emu, argv, ctx=None):
            return 0

        reg("RtlGetSuiteMask", RtlGetSuiteMask, 0)

    @apihook("RtlGetLastWin32Error", argc=0)
    def RtlGetLastWin32Error(self, emu, argv, ctx: api.ApiContext = None):
        """DWORD RtlGetLastWin32Error();"""

        return emu.get_last_error()

    @apihook("RtlNtStatusToDosError", argc=1)
    def RtlNtStatusToDosError(self, emu, argv, ctx: api.ApiContext = None):
        """ULONG RtlNtStatusToDosError(NTSTATUS Status);"""
        return 0

    @apihook("RtlFlushSecureMemoryCache", argc=2)
    def RtlFlushSecureMemoryCache(self, emu, argv, ctx: api.ApiContext = None):
        """DWORD RtlFlushSecureMemoryCache(PVOID arg0, PVOID arg1);"""
        return True

    @apihook("RtlAddVectoredExceptionHandler", argc=2)
    def RtlAddVectoredExceptionHandler(self, emu, argv, ctx: api.ApiContext = None):
        """
        PVOID AddVectoredExceptionHandler(
            ULONG                       First,
            PVECTORED_EXCEPTION_HANDLER Handler
        );
        """
        First, Handler = argv

        emu.add_vectored_exception_handler(First, Handler)

        return Handler

    @apihook("NtYieldExecution", argc=0)
    def NtYieldExecution(self, emu, argv, ctx: api.ApiContext = None):
        """
        NtYieldExecution();
        """
        return 0

    @apihook("RtlRemoveVectoredExceptionHandler", argc=1)
    def RtlRemoveVectoredExceptionHandler(self, emu, argv, ctx: api.ApiContext = None):
        """
        ULONG RemoveVectoredExceptionHandler(
            PVOID Handle
        );
        """
        (Handler,) = argv

        emu.remove_vectored_exception_handler(Handler)

        return Handler

    @apihook("LdrLoadDll", argc=4)
    def LdrLoadDll(self, emu, argv, ctx: api.ApiContext = None):
        """NTSTATUS
        NTAPI
        LdrLoadDll(
        IN PWSTR SearchPath OPTIONAL,
        IN PULONG LoadFlags OPTIONAL,
        IN PUNICODE_STRING Name,
        OUT PVOID *BaseAddress OPTIONAL
        );"""

        SearchPath, LoadFlags, Name, BaseAddress = argv

        hmod = 0

        req_lib = self.read_unicode_string(Name)
        lib = winemu.normalize_dll_name(req_lib)

        hmod = emu.load_library(lib)

        flags = {
            0x1: "DONT_RESOLVE_DLL_REFERENCES",
            0x10: "LOAD_IGNORE_CODE_AUTHZ_LEVEL",
            0x2: "LOAD_LIBRARY_AS_DATAFILE",
            0x40: "LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE",
            0x20: "LOAD_LIBRARY_AS_IMAGE_RESOURCE",
            0x200: "LOAD_LIBRARY_SEARCH_APPLICATION_DIR",
            0x1000: "LOAD_LIBRARY_SEARCH_DEFAULT_DIRS",
            0x100: "LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR",
            0x800: "LOAD_LIBRARY_SEARCH_SYSTEM32",
            0x400: "LOAD_LIBRARY_SEARCH_USER_DIRS",
            0x8: "LOAD_WITH_ALTERED_SEARCH_PATH",
        }

        pretty_flags = " | ".join([name for bit, name in flags.items() if LoadFlags & bit])

        if SearchPath:
            argv[0] = self.read_mem_string(SearchPath, 2)

        argv[2] = req_lib
        argv[1] = pretty_flags

        if not hmod:
            STATUS_DLL_NOT_FOUND = 0xC0000135
            return STATUS_DLL_NOT_FOUND

        if BaseAddress:
            self.mem_write(BaseAddress, hmod.to_bytes(self.get_ptr_size(), "little"))

        return 0

    @apihook("LdrGetProcedureAddress", argc=4)
    def LdrGetProcedureAddress(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS LdrGetProcedureAddress(
            HMODULE ModuleHandle,
            PANSI_STRING FunctionName,
            WORD Oridinal,
            OUT PVOID *FunctionAddress
        );
        """

        hmod, proc_name, ordinal, func_addr = argv
        rv = ddk.STATUS_PROCEDURE_NOT_FOUND

        if proc_name:
            fn = ntos.STRING(emu.get_ptr_size())
            fn = self.mem_cast(fn, proc_name)

            proc = self.read_mem_string(fn.Buffer, 1, max_chars=fn.Length)
            argv[1] = proc

        elif ordinal:
            proc = f"ordinal_{proc_name}"

        mods = emu.get_peb_modules()
        for mod in mods:
            if mod.base == hmod:
                bn = mod.get_base_name()
                mname, _ = os.path.splitext(bn)
                addr = emu.get_proc(mname, proc)
                rv = ddk.STATUS_SUCCESS
                self.mem_write(func_addr, addr.to_bytes(self.get_ptr_size(), "little"))

        return rv

    @apihook("RtlZeroMemory", argc=2)
    def RtlZeroMemory(self, emu, argv, ctx: api.ApiContext = None):
        """
        void RtlZeroMemory(
            void*  Destination,
            size_t Length
        );
        """
        dest, length = argv
        buf = b"\x00" * length
        self.mem_write(dest, buf)

    @apihook("RtlMoveMemory", argc=3)
    def RtlMoveMemory(self, emu, argv, ctx: api.ApiContext = None):
        """
        void RtlMoveMemory(void* pvDest, const void *pSrc, size_t Length);
        """
        dest, source, length = argv
        buf = self.mem_read(source, length)
        self.mem_write(dest, buf)

    @apihook("NtSetInformationProcess", argc=4)
    def NtSetInformationProcess(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS
        NTAPI
        NtSetInformationProcess(
            _In_ HANDLE ProcessHandle,
            _In_ PROCESSINFOCLASS ProcessInformationClass,
            _In_ PVOID ProcessInformation,
            _In_ ULONG ProcessInformationLength
        );
        """
        return 0

    @apihook("RtlEncodePointer", argc=1)
    def RtlEncodePointer(self, emu, argv, ctx: api.ApiContext = None):
        """
        PVOID
        NTAPI
        RtlEncodePointer(IN PVOID Pointer)
        """
        (Ptr,) = argv
        # Just increment the pointer for now like kernel32.EncodePointer
        rv = Ptr + 1

        return rv

    @apihook("RtlDecodePointer", argc=1)
    def RtlDecodePointer(self, emu, argv, ctx: api.ApiContext = None):
        """
        PVOID
        NTAPI
        RtlDecodePointer(IN PVOID Pointer)
        """
        (Ptr,) = argv
        # Just decrement the pointer for now like kernel32.DecodePointer
        rv = Ptr - 1

        return rv

    @apihook("NtWaitForSingleObject", argc=3)
    def NtWaitForSingleObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSYSAPI
        NTSTATUS
        NtWaitForSingleObject(
            HANDLE         Handle,
            BOOLEAN        Alertable,
            PLARGE_INTEGER Timeout
        );
        """
        hHandle, alertable, timeout = argv

        # Other documented return status are:
        #      STATUS_TIMEOUT = 0x00000102
        #      STATUS_ACCESS_DENIED = 0xC0000022
        #      STATUS_ALERTED = 0x00000101
        #      STATUS_INVALID_HANDLE = 0xC0000008
        #      STATUS_USER_APC = 0x000000C0
        rv = ddk.STATUS_SUCCESS

        return rv

    @apihook("RtlComputeCrc32", argc=3)
    def RtlComputeCrc32(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD RtlComputeCrc32(
            DWORD       dwInitial,
            const BYTE* pData,
            INT         iLen
        )
        """
        dwInitial, pData, iLen = argv

        data_to_compute = self.mem_read(pData, iLen)
        dwInitial = binascii.crc32(data_to_compute)

        return dwInitial

    @apihook("LdrFindResource_U", argc=4)
    def LdrFindResource_U(self, emu, argv, ctx: api.ApiContext = None):
        """
        pub unsafe extern "system" fn LdrFindResource_U(
            DllHandle: PVOID,
            ResourceInfo: PLDR_RESOURCE_INFO,
            Level: ULONG,
            ResourceDataEntry: *mut PIMAGE_RESOURCE_DATA_ENTRY
        ) -> NTSTATUS

         typedef struct _LDR_RESOURCE_INFO
         {
             ULONG_PTR Type;
             ULONG_PTR Name;
             ULONG_PTR Language;
         } LDR_RESOURCE_INFO, *PLDR_RESOURCE_INFO;

         typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
           ULONG OffsetToData;
           ULONG Size;
           ULONG CodePage;
           ULONG Reserved;
         } IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;
        """
        DllHandle, ResourceInfo, Level, ResourceDataEntry = argv

        # Reusing some functions from kernel32 module that are used to
        # handle the very similar function FindResourceA
        k32 = emu.api.mods.get("kernel32")

        cw = 1  # Always ASCII for this function
        if DllHandle == 0:
            pe = emu.modules[0] if emu.modules else None
        else:
            pe = emu.get_mod_from_addr(DllHandle)
            if pe and DllHandle != pe.base:
                return ddk.STATUS_INVALID_HANDLE

        if not pe:
            return ddk.STATUS_INVALID_HANDLE

        type_ptr = emu.read_ptr(ResourceInfo)
        name_ptr = emu.read_ptr(ResourceInfo + emu.get_ptr_size())

        try:
            name = k32.normalize_res_identifier(emu, cw, name_ptr)
            _type = k32.normalize_res_identifier(emu, cw, type_ptr)
        except Exception:
            return ddk.STATUS_INVALID_PARAMETER

        res = k32.find_resource(pe, name, _type)
        if res is None:
            return ddk.STATUS_RESOURCE_DATA_NOT_FOUND

        struct_ptr = pe.base + res.entry_rva

        # Write the output parameter with the address of the data entry
        emu.write_ptr(ResourceDataEntry, struct_ptr)

        return ddk.STATUS_SUCCESS

    @apihook("NtUnmapViewOfSection", argc=2)
    def NtUnmapViewOfSection(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS NtUnmapViewOfSection(
            HANDLE ProcessHandle,
            PVOID  BaseAddress
        );
        """
        return ddk.STATUS_SUCCESS

    @apihook("LdrAccessResource", argc=4)
    def LdrAccessResource(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS NTAPI LdrAccessResource    (   _In_ PVOID      BaseAddress,
                _In_ PIMAGE_RESOURCE_DATA_ENTRY     ResourceDataEntry,
                _Out_opt_ PVOID *   Resource,
                _Out_opt_ PULONG    Size
            )
        """
        BaseAddress, ResourceDataEntry, Resource, Size = argv

        if ResourceDataEntry == 0:
            return ddk.STATUS_INVALID_PARAMETER

        offset = emu.read_mem_value(ResourceDataEntry, 4)
        size = emu.read_mem_value(ResourceDataEntry + 4, 4)

        if Size:
            emu.write_ptr(Size, size)

        if Resource:
            emu.write_ptr(Resource, BaseAddress + offset)

        return ddk.STATUS_SUCCESS

    @apihook("RtlGetNtVersionNumbers", argc=3)
    def RtlGetNtVersionNumbers(self, emu, argv, ctx={}):
        """
        void RtlGetNtVersionNumbers(
            DWORD *pNtMajorVersion,
            DWORD *pNtMinorVersion,
            DWORD *pNtBuildNumber
        );
        """
        pMajor, pMinor, pBuild = argv
        if pMajor:
            self.mem_write(pMajor, (10).to_bytes(4, "little"))
        if pMinor:
            self.mem_write(pMinor, (0).to_bytes(4, "little"))
        if pBuild:
            self.mem_write(pBuild, (0xF0004A61).to_bytes(4, "little"))

    @apihook("RtlGetCurrentPeb", argc=0)
    def RtlGetCurrentPeb(self, emu, argv, ctx={}):
        """
        PPEB RtlGetCurrentPeb();
        """
        proc = emu.get_current_process()
        if proc and proc.peb:
            return proc.peb.address
        return 0

    @apihook("RtlGetVersion", argc=1)
    def RtlGetVersion(self, emu, argv, ctx={}):
        """
        NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
        """
        (lpVersionInformation,) = argv
        # RTL_OSVERSIONINFOW: dwOSVersionInfoSize(4), dwMajorVersion(4),
        # dwMinorVersion(4), dwBuildNumber(4), dwPlatformId(4), szCSDVersion(256)
        import struct

        info = struct.pack("<IIIII", 276, 10, 0, 19041, 2)  # VER_PLATFORM_WIN32_NT=2
        info += b"\x00" * (276 - len(info))
        self.mem_write(lpVersionInformation, info)
        return 0  # STATUS_SUCCESS
