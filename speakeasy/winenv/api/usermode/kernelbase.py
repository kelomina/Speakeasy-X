# Copyright (C) 2026 Speakeasy-X

import datetime
import struct

import speakeasy.winenv.arch as _arch

from .kernel32 import Kernel32

from .. import api


class KernelBase(Kernel32):
    """
    Implements exported functions from kernelbase.dll.

    kernelbase.dll re-exports most of kernel32's API surface, so all real
    Kernel32 handlers are reused directly; only kernelbase-specific exports
    are implemented below.
    """

    name = "kernelbase"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self._register_kernelbase_batch()

    def _register_kernelbase_batch(self):
        """Register real handlers for common kernelbase-only exports."""
        sd = _arch.CALL_CONV_STDCALL
        ptr = self.get_ptr_size()

        def reg(name, func, argc):
            # Override inherited Kernel32 entries: the kernelbase batch is
            # authoritative for these names.
            self.funcs[name] = (name, func, argc, sd, None)

        def _config():
            return getattr(self.emu, "config", None)

        def _user_name():
            cfg = _config()
            if cfg is not None:
                user = getattr(cfg, "user", None)
                if user is not None:
                    return getattr(user, "name", "") or "user"
            return "user"

        def CharNext_impl(self, emu, argv, ctx=None):
            s = argv[0]
            if not s:
                return 0
            data = self.read_string(s)
            return s + 1 if data else s

        reg("CharNextA", CharNext_impl, 1)

        def CharNextW_impl(self, emu, argv, ctx=None):
            s = argv[0]
            if not s:
                return 0
            data = self.read_wide_string(s)
            return s + 2 if data else s

        reg("CharNextW", CharNextW_impl, 1)

        def CharPrev_impl(self, emu, argv, ctx=None):
            start, s = argv
            if not s or not start:
                return 0
            return s - 1 if s > start else s

        reg("CharPrevA", CharPrev_impl, 2)

        def CharPrevW_impl(self, emu, argv, ctx=None):
            start, s = argv
            if not s or not start:
                return 0
            return s - 2 if s > start else s

        reg("CharPrevW", CharPrevW_impl, 2)

        def ChrCmpI_impl(self, emu, argv, ctx=None):
            a, b = argv
            if not a or not b:
                return 2  # not equal
            sa = self.read_string(a).lower()
            sb = self.read_string(b).lower()
            if sa == sb:
                return 0
            return 1 if sa > sb else 2

        reg("ChrCmpIA", ChrCmpI_impl, 2)
        reg("ChrCmpIW", ChrCmpI_impl, 2)

        def CompareString_impl(self, emu, argv, ctx=None):
            locale, flags, a, alen, b, blen = argv
            if not a or not b:
                return 0  # ERROR
            sa = self.read_mem_string(a, 2 if alen == -1 else 2)
            sb = self.read_mem_string(b, 2)
            if flags & 0x00000001:  # NORM_IGNORECASE
                sa, sb = sa.lower(), sb.lower()
            if sa == sb:
                return 2  # CSTR_EQUAL
            return 1 if sa > sb else 3  # CSTR_GREATER_THAN / LESS_THAN

        reg("CompareStringW", CompareString_impl, 6)
        reg("CompareStringA", CompareString_impl, 6)
        reg("CompareStringEx", CompareString_impl, 7)
        reg("CompareStringOrdinal", CompareString_impl, 6)

        def CreateFile2_impl(self, emu, argv, ctx=None):
            path, access, share, create, extras = argv
            if not path:
                return 0xFFFFFFFFFFFFFFFF
            p = self.read_wide_string(path)
            create_disposition = create if create else 1
            create_flag = create_disposition in (2, 3, 4)
            truncate = create_disposition in (1, 4)
            hnd = self.file_open(p, create=create_flag, truncate=truncate)
            if not hnd:
                self.emu.set_last_error(2)  # ERROR_FILE_NOT_FOUND
                return 0xFFFFFFFFFFFFFFFF
            return hnd

        reg("CreateFile2", CreateFile2_impl, 5)

        def CreateEventEx_impl(self, emu, argv, ctx=None):
            attrs, name, flags, access = argv
            name_str = self.read_wide_string(name) if name else ""
            hnd, evt = self.emu.create_event(name_str)
            return hnd

        reg("CreateEventExW", CreateEventEx_impl, 4)
        reg("CreateEventExA", CreateEventEx_impl, 4)

        def CreateSemaphoreEx_impl(self, emu, argv, ctx=None):
            attrs, initial, maximum, name, reserved, access = argv
            name_str = self.read_wide_string(name) if name else ""
            hnd, evt = self.emu.create_event(name_str)
            return hnd

        reg("CreateSemaphoreExW", CreateSemaphoreEx_impl, 6)

        def CancelIo_impl(self, emu, argv, ctx=None):
            return True

        reg("CancelIo", CancelIo_impl, 1)
        reg("CancelIoEx", CancelIo_impl, 2)
        reg("CancelSynchronousIo", CancelIo_impl, 1)

        def CopyFileEx_impl(self, emu, argv, ctx=None):
            src, dst, progress, data, cancel, flags = argv
            if not src or not dst:
                return False
            sp = self.read_wide_string(src)
            dp = self.read_wide_string(dst)
            self.record_file_access_event(sp, "file_open")
            self.record_file_access_event(dp, "file_create")
            return True

        reg("CopyFileExW", CopyFileEx_impl, 6)
        reg("CopyFileExA", CopyFileEx_impl, 6)
        reg("CopyFile2", CopyFileEx_impl, 3)

        def CreateHardLink_impl(self, emu, argv, ctx=None):
            return True

        reg("CreateHardLinkW", CreateHardLink_impl, 3)
        reg("CreateHardLinkA", CreateHardLink_impl, 3)

        def CreateSymbolicLink_impl(self, emu, argv, ctx=None):
            return True

        reg("CreateSymbolicLinkW", CreateSymbolicLink_impl, 3)
        reg("CreateSymbolicLinkA", CreateSymbolicLink_impl, 3)

        def DebugBreak_impl(self, emu, argv, ctx=None):
            return

        reg("DebugBreak", DebugBreak_impl, 0)

        def DebugActiveProcess_impl(self, emu, argv, ctx=None):
            return True

        reg("DebugActiveProcess", DebugActiveProcess_impl, 1)
        reg("DebugActiveProcessStop", DebugActiveProcess_impl, 1)

        def ContinueDebugEvent_impl(self, emu, argv, ctx=None):
            return True

        reg("ContinueDebugEvent", ContinueDebugEvent_impl, 3)

        def AllocateLocallyUniqueId_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if not out:
                return False
            import uuid

            u = uuid.uuid4()
            self.mem_write(out, struct.pack("<QQ", u.time_low | (u.time_mid << 32), u.time_hi_version))
            return True

        reg("AllocateLocallyUniqueId", AllocateLocallyUniqueId_impl, 1)

        def CopySid_impl(self, emu, argv, ctx=None):
            dst_len, dst, src = argv
            if not dst or not src:
                return False
            sid_len = int.from_bytes(self.mem_read(src, 1), "little") * 4 + 8
            self.mem_write(dst, self.mem_read(src, sid_len))
            return True

        reg("CopySid", CopySid_impl, 3)

        def CreateWellKnownSid_impl(self, emu, argv, ctx=None):
            sid_type, domain, sid, sid_len = argv
            if not sid or not sid_len:
                return False
            cur = int.from_bytes(self.mem_read(sid_len, 4), "little")
            if cur < 20:
                self.mem_write(sid_len, b"\x14\x00\x00\x00")
                return False
            # S-1-5-18 (LocalSystem)
            self.mem_write(sid, b"\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00")
            return True

        reg("CreateWellKnownSid", CreateWellKnownSid_impl, 4)

        def CompareObjectHandles_impl(self, emu, argv, ctx=None):
            a, b = argv
            return a == b

        reg("CompareObjectHandles", CompareObjectHandles_impl, 2)

        def DiscardVirtualMemory_impl(self, emu, argv, ctx=None):
            return 0

        reg("DiscardVirtualMemory", DiscardVirtualMemory_impl, 2)

        def FlsAlloc_impl(self, emu, argv, ctx=None):
            if not hasattr(self, "_fls"):
                self._fls = {}
                self._fls_next = 1
            idx = self._fls_next
            self._fls_next += 1
            self._fls[idx] = 0
            return idx

        reg("FlsAlloc", FlsAlloc_impl, 1)

        def FlsFree_impl(self, emu, argv, ctx=None):
            idx = argv[0]
            if hasattr(self, "_fls"):
                self._fls.pop(idx, None)
            return True

        reg("FlsFree", FlsFree_impl, 1)

        def FlsGetValue_impl(self, emu, argv, ctx=None):
            idx = argv[0]
            if hasattr(self, "_fls") and idx in self._fls:
                return self._fls[idx]
            return 0

        reg("FlsGetValue", FlsGetValue_impl, 1)

        def FlsSetValue_impl(self, emu, argv, ctx=None):
            idx, value = argv
            if not hasattr(self, "_fls"):
                self._fls = {}
            self._fls[idx] = value
            return True

        reg("FlsSetValue", FlsSetValue_impl, 2)

        def GetCPInfoEx_impl(self, emu, argv, ctx=None):
            code_page, out = argv
            if not out:
                return False
            # CPINFOEXW: 0xE4 bytes
            self.mem_write(out, b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 0x20)
            return True

        reg("GetCPInfoExW", GetCPInfoEx_impl, 3)
        reg("GetCPInfoExA", GetCPInfoEx_impl, 3)
        reg("GetCPInfo", GetCPInfoEx_impl, 2)

        def GetDateFormat_impl(self, emu, argv, ctx=None):
            locale, flags, date, fmt, buf, size = argv
            if not buf:
                return 0
            now = datetime.datetime.now()
            s = now.strftime("%m/%d/%Y")
            if len(s) + 1 > size:
                return 0
            self.write_wide_string(s, buf)
            return len(s)

        reg("GetDateFormatW", GetDateFormat_impl, 6)
        reg("GetDateFormatA", GetDateFormat_impl, 6)
        reg("GetDateFormatEx", GetDateFormat_impl, 7)

        def GetNumberFormat_impl(self, emu, argv, ctx=None):
            locale, flags, value, fmt, buf, size = argv
            if not buf or not value:
                return 0
            txt = self.read_wide_string(value)
            s = txt
            if len(s) + 1 > size:
                return 0
            self.write_wide_string(s, buf)
            return len(s)

        reg("GetNumberFormatW", GetNumberFormat_impl, 6)
        reg("GetNumberFormatA", GetNumberFormat_impl, 6)
        reg("GetNumberFormatEx", GetNumberFormat_impl, 7)

        def GetCurrencyFormat_impl(self, emu, argv, ctx=None):
            locale, flags, value, fmt, buf, size = argv
            if not buf or not value:
                return 0
            txt = self.read_wide_string(value)
            s = "$" + txt
            if len(s) + 1 > size:
                return 0
            self.write_wide_string(s, buf)
            return len(s)

        reg("GetCurrencyFormatW", GetCurrencyFormat_impl, 6)
        reg("GetCurrencyFormatA", GetCurrencyFormat_impl, 6)
        reg("GetCurrencyFormatEx", GetCurrencyFormat_impl, 7)

        def GetFileInformationByHandleEx_impl(self, emu, argv, ctx=None):
            handle, info_class, info, size = argv
            if not info:
                return False
            if info_class == 1:  # FileBasicInfo
                self.mem_write(info, b"\x00" * 32 + struct.pack("<II", 0x80, 0))
                return True
            if info_class == 2:  # FileStandardInfo
                self.mem_write(info, struct.pack("<QQIIII", 0, 0, 1, 0, 0, 0))
                return True
            if info_class == 5:  # FileNameInfo
                f = self.file_get(handle)
                name = (getattr(f, "path", "") or "unknown").encode("utf-16le")
                self.mem_write(info, struct.pack("<I", len(name)) + name)
                return True
            if info_class == 6:  # FileRemoteProtocolInfo
                self.mem_write(info, b"\x00" * min(size, 32))
                return True
            return False

        reg("GetFileInformationByHandleEx", GetFileInformationByHandleEx_impl, 4)

        def GetFileType_impl(self, emu, argv, ctx=None):
            handle = argv[0]
            return 1  # FILE_TYPE_DISK

        reg("GetFileType", GetFileType_impl, 1)

        def GetFinalPathNameByHandle_impl(self, emu, argv, ctx=None):
            handle, buf, size, flags = argv
            if not buf:
                return 0
            f = self.file_get(handle)
            name = getattr(f, "path", "") or "C:\\unknown"
            if len(name) + 1 > size:
                return 0
            self.write_wide_string(name, buf)
            return len(name)

        reg("GetFinalPathNameByHandleW", GetFinalPathNameByHandle_impl, 4)
        reg("GetFinalPathNameByHandleA", GetFinalPathNameByHandle_impl, 4)

        def GetLogicalDrives_impl(self, emu, argv, ctx=None):
            return 0x0C  # A: + C:

        reg("GetLogicalDrives", GetLogicalDrives_impl, 0)

        def GetOverlappedResult_impl(self, emu, argv, ctx=None):
            handle, overlapped, bytes_out, wait = argv
            if bytes_out:
                self.mem_write(bytes_out, b"\x00\x00\x00\x00")
            return True

        reg("GetOverlappedResult", GetOverlappedResult_impl, 4)

        def GetProductInfo_impl(self, emu, argv, ctx=None):
            major, minor, build, sp, out = argv
            if out:
                self.mem_write(out, b"\x06\x00\x00\x00")  # PRODUCT_WORKSTATION
            return True

        reg("GetProductInfo", GetProductInfo_impl, 5)

        def _lcid_impl(self, emu, argv, ctx=None):
            return 0x409

        reg("GetSystemDefaultLCID", _lcid_impl, 0)
        reg("GetUserDefaultLCID", _lcid_impl, 0)

        def _langid_impl(self, emu, argv, ctx=None):
            return 0x409

        reg("GetSystemDefaultLangID", _langid_impl, 0)
        reg("GetUserDefaultLangID", _langid_impl, 0)

        def GetSystemDefaultLocaleName_impl(self, emu, argv, ctx=None):
            buf, size = argv
            if not buf or size < 6:
                return 0
            self.write_wide_string("en-US", buf)
            return 5

        reg("GetSystemDefaultLocaleName", GetSystemDefaultLocaleName_impl, 2)
        reg("GetUserDefaultLocaleName", GetSystemDefaultLocaleName_impl, 2)

        def GetUserPreferredUILanguages_impl(self, emu, argv, ctx=None):
            flags, langs_out, count_out, buf, size = argv
            if count_out:
                self.mem_write(count_out, b"\x01\x00\x00\x00")
            if not buf:
                return 0
            langs = "en-US"
            if len(langs) + 1 > size:
                return False
            self.write_wide_string(langs, buf)
            return True

        reg("GetUserPreferredUILanguages", GetUserPreferredUILanguages_impl, 5)
        reg("GetSystemPreferredUILanguages", GetUserPreferredUILanguages_impl, 5)

        def IsProcessorFeaturePresent_impl(self, emu, argv, ctx=None):
            feature = argv[0]
            if feature == 0x17:  # PF_ARM_V8_INSTRUCTIONS_AVAILABLE
                return False
            return True

        reg("IsProcessorFeaturePresent", IsProcessorFeaturePresent_impl, 1)

        def IsWow64Process2_impl(self, emu, argv, ctx=None):
            proc, machine, native = argv
            if machine:
                self.mem_write(machine, b"\x00\x00")
            if native:
                self.mem_write(native, b"\x64\x86" if self.get_ptr_size() == 8 else b"\x4c\x01")
            return False

        reg("IsWow64Process2", IsWow64Process2_impl, 3)

        def LCMapString_impl(self, emu, argv, ctx=None):
            locale, flags, src, src_len, dst, dst_len = argv
            if not src:
                return 0
            s = self.read_wide_string(src)
            if flags & 0x00000100:  # LCMAP_UPPERCASE
                s = s.upper()
            elif flags & 0x00000200:  # LCMAP_LOWERCASE
                s = s.lower()
            if not dst:
                return len(s)
            if len(s) > dst_len:
                return 0
            self.write_wide_string(s, dst)
            return len(s)

        reg("LCMapStringW", LCMapString_impl, 6)
        reg("LCMapStringA", LCMapString_impl, 6)
        reg("LCMapStringEx", LCMapString_impl, 7)

        def QueryFullProcessImageName_impl(self, emu, argv, ctx=None):
            proc, flags, buf, size = argv
            if not buf or not size:
                return False
            proc_obj = self.emu.get_object_from_handle(proc) if proc else None
            img = getattr(proc_obj, "image", "") if proc_obj else ""
            name = img or "C:\\Windows\\system32\\unknown.exe"
            maxlen = int.from_bytes(self.mem_read(size, 4), "little")
            if len(name) + 1 > maxlen:
                return False
            self.write_wide_string(name, buf)
            self.mem_write(size, (len(name) + 1).to_bytes(4, "little"))
            return True

        reg("QueryFullProcessImageNameW", QueryFullProcessImageName_impl, 4)
        reg("QueryFullProcessImageNameA", QueryFullProcessImageName_impl, 4)

        def SwitchToThread_impl(self, emu, argv, ctx=None):
            return False

        reg("SwitchToThread", SwitchToThread_impl, 0)

        def SystemTimeToTzSpecificLocalTime_impl(self, emu, argv, ctx=None):
            tz, utc, local = argv
            if not utc or not local:
                return False
            self.mem_write(local, self.mem_read(utc, 16))
            return True

        reg("SystemTimeToTzSpecificLocalTime", SystemTimeToTzSpecificLocalTime_impl, 3)
        reg("TzSpecificLocalTimeToSystemTime", SystemTimeToTzSpecificLocalTime_impl, 3)

        def TerminateThread_impl(self, emu, argv, ctx=None):
            return True

        reg("TerminateThread", TerminateThread_impl, 2)

        def GetSystemTimeAdjustment_impl(self, emu, argv, ctx=None):
            adj, inc, disabled = argv
            if adj:
                self.mem_write(adj, struct.pack("<I", 0))
            if inc:
                self.mem_write(inc, struct.pack("<I", 156250))
            if disabled:
                self.mem_write(disabled, b"\x01\x00\x00\x00")
            return True

        reg("GetSystemTimeAdjustment", GetSystemTimeAdjustment_impl, 3)

        def CreateTimerQueue_impl(self, emu, argv, ctx=None):
            return 0x1000

        reg("CreateTimerQueue", CreateTimerQueue_impl, 0)

        def CreateTimerQueueTimer_impl(self, emu, argv, ctx=None):
            out, queue, callback, param, due, period, flags = argv
            if out:
                self.mem_write(out, struct.pack("<Q", 0x2000))
            return True

        reg("CreateTimerQueueTimer", CreateTimerQueueTimer_impl, 7)

        def DeleteTimerQueueEx_impl(self, emu, argv, ctx=None):
            return True

        reg("DeleteTimerQueueEx", DeleteTimerQueueEx_impl, 2)

        def DeleteTimerQueueTimer_impl(self, emu, argv, ctx=None):
            return True

        reg("DeleteTimerQueueTimer", DeleteTimerQueueTimer_impl, 3)

        def ChangeTimerQueueTimer_impl(self, emu, argv, ctx=None):
            return True

        reg("ChangeTimerQueueTimer", ChangeTimerQueueTimer_impl, 4)

        def CreateThreadpool_impl(self, emu, argv, ctx=None):
            return 0x3000

        reg("CreateThreadpool", CreateThreadpool_impl, 1)

        def CloseThreadpool_impl(self, emu, argv, ctx=None):
            return

        reg("CloseThreadpool", CloseThreadpool_impl, 1)

        def CreateThreadpoolTimer_impl(self, emu, argv, ctx=None):
            callback, context, cleanup = argv
            return 0x4000

        reg("CreateThreadpoolTimer", CreateThreadpoolTimer_impl, 3)

        def SetThreadpoolTimer_impl(self, emu, argv, ctx=None):
            return

        reg("SetThreadpoolTimer", SetThreadpoolTimer_impl, 4)

        def WaitForThreadpoolTimerCallbacks_impl(self, emu, argv, ctx=None):
            return

        reg("WaitForThreadpoolTimerCallbacks", WaitForThreadpoolTimerCallbacks_impl, 2)

        def CloseThreadpoolTimer_impl(self, emu, argv, ctx=None):
            return

        reg("CloseThreadpoolTimer", CloseThreadpoolTimer_impl, 1)

        def IsThreadpoolTimerSet_impl(self, emu, argv, ctx=None):
            return False

        reg("IsThreadpoolTimerSet", IsThreadpoolTimerSet_impl, 1)

        def CreateThreadpoolWait_impl(self, emu, argv, ctx=None):
            callback, context, cleanup = argv
            return 0x5000

        reg("CreateThreadpoolWait", CreateThreadpoolWait_impl, 3)

        def SetThreadpoolWait_impl(self, emu, argv, ctx=None):
            return

        reg("SetThreadpoolWait", SetThreadpoolWait_impl, 3)

        def CloseThreadpoolWait_impl(self, emu, argv, ctx=None):
            return

        reg("CloseThreadpoolWait", CloseThreadpoolWait_impl, 1)

        def CreateThreadpoolWork_impl(self, emu, argv, ctx=None):
            callback, context, cleanup = argv
            return 0x6000

        reg("CreateThreadpoolWork", CreateThreadpoolWork_impl, 3)

        def SubmitThreadpoolWork_impl(self, emu, argv, ctx=None):
            return

        reg("SubmitThreadpoolWork", SubmitThreadpoolWork_impl, 1)

        def CloseThreadpoolWork_impl(self, emu, argv, ctx=None):
            return

        reg("CloseThreadpoolWork", CloseThreadpoolWork_impl, 1)

        def CreateThreadpoolIo_impl(self, emu, argv, ctx=None):
            file, callback, context, cleanup = argv
            return 0x7000

        reg("CreateThreadpoolIo", CreateThreadpoolIo_impl, 4)

        def CloseThreadpoolIo_impl(self, emu, argv, ctx=None):
            return

        reg("CloseThreadpoolIo", CloseThreadpoolIo_impl, 1)

        def StartThreadpoolIo_impl(self, emu, argv, ctx=None):
            return

        reg("StartThreadpoolIo", StartThreadpoolIo_impl, 1)

        def WaitForThreadpoolIoCallbacks_impl(self, emu, argv, ctx=None):
            return

        reg("WaitForThreadpoolIoCallbacks", WaitForThreadpoolIoCallbacks_impl, 2)

        def CreateThreadpoolCleanupGroup_impl(self, emu, argv, ctx=None):
            return 0x8000

        reg("CreateThreadpoolCleanupGroup", CreateThreadpoolCleanupGroup_impl, 0)

        def CloseThreadpoolCleanupGroupMembers_impl(self, emu, argv, ctx=None):
            return

        reg("CloseThreadpoolCleanupGroupMembers", CloseThreadpoolCleanupGroupMembers_impl, 3)

        def CloseThreadpoolCleanupGroup_impl(self, emu, argv, ctx=None):
            return

        reg("CloseThreadpoolCleanupGroup", CloseThreadpoolCleanupGroup_impl, 1)

        def CreatePrivateNamespace_impl(self, emu, argv, ctx=None):
            attrs, boundary, alias = argv
            if not alias:
                return 0
            return 0x9000

        reg("CreatePrivateNamespaceW", CreatePrivateNamespace_impl, 3)
        reg("CreatePrivateNamespaceA", CreatePrivateNamespace_impl, 3)

        def OpenPrivateNamespace_impl(self, emu, argv, ctx=None):
            boundary, alias = argv
            return 0x9000

        reg("OpenPrivateNamespaceW", OpenPrivateNamespace_impl, 2)
        reg("OpenPrivateNamespaceA", OpenPrivateNamespace_impl, 2)

        def ClosePrivateNamespace_impl(self, emu, argv, ctx=None):
            return True

        reg("ClosePrivateNamespace", ClosePrivateNamespace_impl, 2)

        def CreateBoundaryDescriptor_impl(self, emu, argv, ctx=None):
            name = argv[0]
            if not name:
                return 0
            return 0xA000

        reg("CreateBoundaryDescriptorW", CreateBoundaryDescriptor_impl, 2)
        reg("CreateBoundaryDescriptorA", CreateBoundaryDescriptor_impl, 2)

        def DeleteBoundaryDescriptor_impl(self, emu, argv, ctx=None):
            return

        reg("DeleteBoundaryDescriptor", DeleteBoundaryDescriptor_impl, 1)

        def AddSIDToBoundaryDescriptor_impl(self, emu, argv, ctx=None):
            return True

        reg("AddSIDToBoundaryDescriptor", AddSIDToBoundaryDescriptor_impl, 2)

        def GetSystemFirmwareTable_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetSystemFirmwareTable", GetSystemFirmwareTable_impl, 4)

        def GetFirmwareType_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, b"\x02\x00\x00\x00")  # FirmwareTypeUefi
            return True

        reg("GetFirmwareType", GetFirmwareType_impl, 1)

        def Beep_impl(self, emu, argv, ctx=None):
            return True

        reg("Beep", Beep_impl, 2)

        def GetConsoleAlias_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetConsoleAliasW", GetConsoleAlias_impl, 6)
        reg("GetConsoleAliasA", GetConsoleAlias_impl, 6)

        def GetNumaHighestNodeNumber_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00")
            return True

        reg("GetNumaHighestNodeNumber", GetNumaHighestNodeNumber_impl, 1)

        def GetNumaProcessorNode_impl(self, emu, argv, ctx=None):
            proc, out = argv
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00")
            return True

        reg("GetNumaProcessorNode", GetNumaProcessorNode_impl, 2)

        def SetThreadPreferredUILanguages_impl(self, emu, argv, ctx=None):
            flags, langs, num = argv
            if num:
                self.mem_write(num, b"\x01\x00\x00\x00")
            return True

        reg("SetThreadPreferredUILanguages", SetThreadPreferredUILanguages_impl, 3)
        reg("SetThreadPreferredUILanguages2", SetThreadPreferredUILanguages_impl, 4)
        reg("SetProcessPreferredUILanguages", SetThreadPreferredUILanguages_impl, 3)

        def GetThreadPreferredUILanguages_impl(self, emu, argv, ctx=None):
            flags, num, buf, size = argv
            if num:
                self.mem_write(num, b"\x01\x00\x00\x00")
            if buf:
                self.write_wide_string("en-US", buf)
                return True
            return False

        reg("GetThreadPreferredUILanguages", GetThreadPreferredUILanguages_impl, 4)

        def GetUILanguageInfo_impl(self, emu, argv, ctx=None):
            return 0x409

        reg("GetUILanguageInfo", GetUILanguageInfo_impl, 4)

        # ---- GetPrivateProfile* (INI store) ----
        if not hasattr(self, "_ini"):
            self._ini = {}

        def GetPrivateProfileString_impl(self, emu, argv, ctx=None):
            section, key, default, out, size, file = argv
            if not out or not size:
                return 0
            sec = self.read_wide_string(section) if section else ""
            k = self.read_wide_string(key) if key else ""
            value = self._ini.get((sec.lower(), k.lower()), "")
            if not value and default:
                value = self.read_wide_string(default)
            self.write_wide_string(value, out)
            return len(value)

        reg("GetPrivateProfileStringW", GetPrivateProfileString_impl, 6)
        reg("GetPrivateProfileStringA", GetPrivateProfileString_impl, 6)

        def WritePrivateProfileString_impl(self, emu, argv, ctx=None):
            section, key, value, file = argv
            if not section or not key:
                return False
            sec = self.read_wide_string(section)
            k = self.read_wide_string(key)
            v = self.read_wide_string(value) if value else ""
            self._ini[(sec.lower(), k.lower())] = v
            return True

        reg("WritePrivateProfileStringW", WritePrivateProfileString_impl, 4)
        reg("WritePrivateProfileStringA", WritePrivateProfileString_impl, 4)

        def GetPrivateProfileSection_impl(self, emu, argv, ctx=None):
            section, out, size, file = argv
            if not out or not size:
                return 0
            self.mem_write(out, b"\x00\x00")
            return 0

        reg("GetPrivateProfileSectionW", GetPrivateProfileSection_impl, 4)
        reg("GetPrivateProfileSectionA", GetPrivateProfileSection_impl, 4)

        def FlushPrivateProfileCache_impl(self, emu, argv, ctx=None):
            return True

        reg("FlushPrivateProfileCache", FlushPrivateProfileCache_impl, 0)

        def GetFirmwareEnvironmentVariable_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetFirmwareEnvironmentVariableW", GetFirmwareEnvironmentVariable_impl, 4)
        reg("GetFirmwareEnvironmentVariableA", GetFirmwareEnvironmentVariable_impl, 4)

        def SetFirmwareEnvironmentVariable_impl(self, emu, argv, ctx=None):
            return False

        reg("SetFirmwareEnvironmentVariableW", SetFirmwareEnvironmentVariable_impl, 4)
        reg("SetFirmwareEnvironmentVariableA", SetFirmwareEnvironmentVariable_impl, 4)

        def GetLocaleInfo_impl(self, emu, argv, ctx=None):
            locale, lctype, out, size = argv
            if not out or not size:
                return 0
            if lctype == 0x1:  # LOCALE_SABBREVLANGNAME
                s = "ENU"
            elif lctype == 0x2:  # LOCALE_SLANGUAGE
                s = "English (United States)"
            elif lctype == 0x3:  # LOCALE_SENGLANGUAGE
                s = "English"
            else:
                s = ""
            if len(s) + 1 > size:
                return 0
            self.write_wide_string(s, out)
            return len(s)

        reg("GetLocaleInfoW", GetLocaleInfo_impl, 4)
        reg("GetLocaleInfoA", GetLocaleInfo_impl, 4)
        reg("GetLocaleInfoEx", GetLocaleInfo_impl, 4)

        def GetUserDefaultUILanguage_impl(self, emu, argv, ctx=None):
            return 0x409

        reg("GetUserDefaultUILanguage", GetUserDefaultUILanguage_impl, 0)
        reg("GetSystemDefaultUILanguage", GetUserDefaultUILanguage_impl, 0)

        def SetLocaleInfo_impl(self, emu, argv, ctx=None):
            return False

        reg("SetLocaleInfoW", SetLocaleInfo_impl, 3)
        reg("SetLocaleInfoA", SetLocaleInfo_impl, 3)

        def GetGeoInfo_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetGeoInfoW", GetGeoInfo_impl, 5)
        reg("GetGeoInfoA", GetGeoInfo_impl, 5)

        def GetUserGeoID_impl(self, emu, argv, ctx=None):
            return 0x7F  # GEOID_NOT_AVAILABLE

        reg("GetUserGeoID", GetUserGeoID_impl, 1)

        def GetUserDefaultLCID_impl(self, emu, argv, ctx=None):
            return 0x409

        reg("GetUserDefaultLCID", GetUserDefaultLCID_impl, 0)

    @apihook("GetSystemTimePreciseAsFileTime", argc=1)
    def GetSystemTimePreciseAsFileTime(self, emu, argv, ctx: api.ApiContext = None):
        """
        void GetSystemTimePreciseAsFileTime(
            LPFILETIME lpSystemTimeAsFileTime
        );
        """
        (lpSystemTimeAsFileTime,) = argv
        ft = self.k32types.FILETIME(emu.get_ptr_size())

        timestamp = 116444736000000000 + int(datetime.datetime.now(datetime.timezone.utc).timestamp()) * 10000000
        ft.dwLowDateTime = 0xFFFFFFFF & timestamp
        ft.dwHighDateTime = timestamp >> 32

        self.mem_write(lpSystemTimeAsFileTime, self.get_bytes(ft))

        return

    @apihook("GetSystemTime", argc=1)
    def GetSystemTime(self, emu, argv, ctx: api.ApiContext = None):
        """
        void GetSystemTime(
            LPSYSTEMTIME lpSystemTime
        );
        """
        (lpSystemTime,) = argv
        return self.GetSystemTimeAsFileTime(emu, [lpSystemTime], ctx)

    @apihook("GetTickCount", argc=0)
    def GetTickCount(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GetTickCount();
        """
        self.tick_counter += 20
        return self.tick_counter & 0xFFFFFFFF

    @apihook("GetCurrentProcessId", argc=0)
    def GetCurrentProcessId(self, emu, argv, ctx: api.ApiContext = None):
        """DWORD GetCurrentProcessId();"""
        proc = emu.get_current_process()
        return proc.id if proc else 0

    @apihook("GetCurrentThreadId", argc=0)
    def GetCurrentThreadId(self, emu, argv, ctx: api.ApiContext = None):
        """DWORD GetCurrentThreadId();"""
        thread = emu.get_current_thread()
        return thread.tid if thread else 0

    @apihook("GetConsoleInputExeNameW", argc=2)
    def GetConsoleInputExeNameW(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetConsoleInputExeNameW(
            DWORD  nSize,
            LPWSTR lpBuffer
        );
        """
        nSize, lpBuffer = argv
        name = b"cmd.exe\x00"
        if nSize >= len(name) // 2 + 1:
            self.write_wide_string("cmd.exe", lpBuffer)
            return True
        return False

    @apihook("GetConsoleInputExeNameA", argc=2)
    def GetConsoleInputExeNameA(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetConsoleInputExeNameA(
            DWORD  nSize,
            LPSTR  lpBuffer
        );
        """
        nSize, lpBuffer = argv
        name = b"cmd.exe\x00"
        if nSize >= len(name):
            self.write_string("cmd.exe", lpBuffer)
            return True
        return False

    @apihook("CeipIsOptedIn", argc=0)
    def CeipIsOptedIn(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL CeipIsOptedIn();"""
        return False

    @apihook("GetCurrentPackageFullName", argc=2)
    def GetCurrentPackageFullName(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG GetCurrentPackageFullName(
            UINT32 *packageFullNameLength,
            PWSTR   packageFullName
        );
        """
        packageFullNameLength, packageFullName = argv
        if packageFullNameLength:
            self.mem_write(packageFullNameLength, b"\x00\x00\x00\x00")
        return 0x80073D54  # APPMODEL_ERROR_NO_PACKAGE

    @apihook("GetCurrentPackageFamilyName", argc=2)
    def GetCurrentPackageFamilyName(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG GetCurrentPackageFamilyName(
            UINT32 *packageFamilyNameLength,
            PWSTR   packageFamilyName
        );
        """
        packageFamilyNameLength, packageFamilyName = argv
        if packageFamilyNameLength:
            self.mem_write(packageFamilyNameLength, b"\x00\x00\x00\x00")
        return 0x80073D54  # APPMODEL_ERROR_NO_PACKAGE

    @apihook("GetCurrentPackageId", argc=2)
    def GetCurrentPackageId(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG GetCurrentPackageId(
            UINT32 *bufferLength,
            BYTE   *buffer
        );
        """
        bufferLength, buffer = argv
        if bufferLength:
            self.mem_write(bufferLength, b"\x00\x00\x00\x00")
        return 0x80073D54  # APPMODEL_ERROR_NO_PACKAGE

    @apihook("GetCurrentPackageInfo", argc=5)
    def GetCurrentPackageInfo(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG GetCurrentPackageInfo(
            UINT32             flags,
            UINT32            *bufferLength,
            BYTE              *buffer,
            UINT32            *count,
            PACKAGE_INFO_REFERENCE *packageInfoReference
        );
        """
        flags, bufferLength, buffer, count, packageInfoReference = argv
        if bufferLength:
            self.mem_write(bufferLength, b"\x00\x00\x00\x00")
        if count:
            self.mem_write(count, b"\x00\x00\x00\x00")
        return 0x80073D54  # APPMODEL_ERROR_NO_PACKAGE

    @apihook("AppPolicyGetWindowingModel", argc=2)
    def AppPolicyGetWindowingModel(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG AppPolicyGetWindowingModel(
            HANDLE               processToken,
            AppPolicyWindowingModel *policy
        );
        """
        processToken, policy = argv
        if policy:
            # APPMODEL_ERROR_NO_PACKAGE - no policy applies
            self.mem_write(policy, b"\x00\x00\x00\x00")
            return 0x80073D54
        return 0x57  # ERROR_INVALID_PARAMETER

    @apihook("AppPolicyGetProcessTerminationMethod", argc=2)
    def AppPolicyGetProcessTerminationMethod(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG AppPolicyGetProcessTerminationMethod(
            HANDLE                          processToken,
            AppPolicyProcessTerminationMethod *policy
        );
        """
        processToken, policy = argv
        if policy:
            # AppPolicyProcessTerminationMethod_Exit = 2
            self.mem_write(policy, b"\x02\x00\x00\x00")
            return 0
        return 0x57  # ERROR_INVALID_PARAMETER

    @apihook("AppPolicyGetThreadInitializationType", argc=2)
    def AppPolicyGetThreadInitializationType(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG AppPolicyGetThreadInitializationType(
            HANDLE                           processToken,
            AppPolicyThreadInitializationType *policy
        );
        """
        processToken, policy = argv
        if policy:
            # AppPolicyThreadInitializationType_InitializeWinRT = 1
            self.mem_write(policy, b"\x01\x00\x00\x00")
            return 0
        return 0x57  # ERROR_INVALID_PARAMETER

    @apihook("AppPolicyGetLifecycleManagement", argc=2)
    def AppPolicyGetLifecycleManagement(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG AppPolicyGetLifecycleManagement(
            HANDLE                   processToken,
            AppPolicyLifecycleManagement *policy
        );
        """
        processToken, policy = argv
        if policy:
            # AppPolicyLifecycleManagement_None = 0
            self.mem_write(policy, b"\x00\x00\x00\x00")
            return 0
        return 0x57  # ERROR_INVALID_PARAMETER

    @apihook("AppPolicyGetCreateFileAccess", argc=2)
    def AppPolicyGetCreateFileAccess(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG AppPolicyGetCreateFileAccess(
            HANDLE                processToken,
            AppPolicyCreateFileAccess *policy
        );
        """
        processToken, policy = argv
        if policy:
            # AppPolicyCreateFileAccess_Full = 1
            self.mem_write(policy, b"\x01\x00\x00\x00")
            return 0
        return 0x57  # ERROR_INVALID_PARAMETER

    @apihook("AppPolicyGetShowDeveloperDiagnostic", argc=2)
    def AppPolicyGetShowDeveloperDiagnostic(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG AppPolicyGetShowDeveloperDiagnostic(
            HANDLE                         processToken,
            AppPolicyShowDeveloperDiagnostic *policy
        );
        """
        processToken, policy = argv
        if policy:
            # AppPolicyShowDeveloperDiagnostic_None = 0
            self.mem_write(policy, b"\x00\x00\x00\x00")
            return 0
        return 0x57  # ERROR_INVALID_PARAMETER

    @apihook("AppPolicyGetMediaFoundationCodecLoading", argc=2)
    def AppPolicyGetMediaFoundationCodecLoading(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG AppPolicyGetMediaFoundationCodecLoading(
            HANDLE                              processToken,
            AppPolicyMediaFoundationCodecLoading *policy
        );
        """
        processToken, policy = argv
        if policy:
            # AppPolicyMediaFoundationCodecLoading_Compatible = 0
            self.mem_write(policy, b"\x00\x00\x00\x00")
            return 0
        return 0x57  # ERROR_INVALID_PARAMETER

    @apihook("AppPolicyGetClrCompat", argc=2)
    def AppPolicyGetClrCompat(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG AppPolicyGetClrCompat(
            HANDLE          processToken,
            AppPolicyClrCompat *policy
        );
        """
        processToken, policy = argv
        if policy:
            # AppPolicyClrCompat_Other = 0
            self.mem_write(policy, b"\x00\x00\x00\x00")
            return 0
        return 0x57  # ERROR_INVALID_PARAMETER
