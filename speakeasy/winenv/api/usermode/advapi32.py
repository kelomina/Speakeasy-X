# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import hashlib
import struct
from typing import Any

from Crypto.Cipher import ARC4

import speakeasy.windows.objman as objman
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.registry.reg as regdefs
import speakeasy.winenv.defs.windows.advapi32 as adv32
import speakeasy.winenv.defs.windows.kernel32 as k32
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.profiler_events import PROC_CREATE, REG_CREATE, REG_LIST, REG_OPEN, REG_READ, REG_WRITE

from .. import api

SERVICE_STATUS_HANDLE_BASE = 0x1000


class AdvApi32(api.ApiHandler):
    """
    Implements exported functions from advapi32.dll
    """

    name = "advapi32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs: dict[str, Any] = {}
        self.data: dict[str, Any] = {}
        self.hash_objects: dict[int, Any] = {}
        self.key_objects: dict[int, Any] = {}
        self.k32types = k32
        self.win = adv32
        self.curr_rand: int = 0
        self.curr_handle: int = 0x2800
        self.service_status_handle: int = SERVICE_STATUS_HANDLE_BASE

        self.rc4: Any | None = None

        super().__get_hook_attrs__(self)

        self._register_reg_batch()
        self._register_advapi32_batch()

    def _register_reg_batch(self):
        """Register real handlers for the remaining Reg* registry functions."""
        ptr = self.get_ptr_size()
        sd = _arch.CALL_CONV_STDCALL

        def reg(name, func, argc):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, sd, None)

        def _key_path(emu, hkey):
            name = regdefs.get_hkey_type(hkey)
            if name:
                return name
            key = emu.regman.get_key_from_handle(hkey)
            return key.path if key else None

        def _value_encoding(cw):
            return "utf-16le" if cw == 2 else "utf-8"

        def RegEnumValue(self, emu, argv, ctx=None):
            """
            LSTATUS RegEnumValue(
                HKEY    hKey,
                DWORD   dwIndex,
                LPSTR   lpValueName,
                LPDWORD lpcchValueName,
                LPDWORD lpReserved,
                LPDWORD lpType,
                LPBYTE  lpData,
                LPDWORD lpcbData
            );
            """
            ctx, cw = self.prepare_ctx(ctx)
            hkey, index, name_out, name_len, reserved, type_out, data_out, data_len = argv
            path = _key_path(emu, hkey)
            if not path:
                return windefs.ERROR_INVALID_HANDLE
            key = self.reg_get_key(hkey)
            if not key:
                return windefs.ERROR_INVALID_HANDLE
            values = key.get_values()
            if index >= len(values):
                return windefs.ERROR_NO_MORE_ITEMS
            val = values[index]
            vname = val.get_name()
            enc = _value_encoding(cw)
            if name_out and vname is not None:
                bname = vname.encode(enc) + b"\x00"
                maxlen = int.from_bytes(self.mem_read(name_len, 4), "little") if name_len else 0
                if len(bname) > maxlen + (1 if cw == 1 else 2):
                    return windefs.ERROR_MORE_DATA
                self.mem_write(name_out, bname)
                if name_len:
                    self.mem_write(name_len, len(vname).to_bytes(4, "little"))
            if type_out:
                typ = val.get_type()
                vt = 1 if typ == "REG_SZ" else 4 if typ == "REG_DWORD" else 3 if typ == "REG_BINARY" else 1
                self.mem_write(type_out, vt.to_bytes(4, "little"))
            data = val.get_data()
            if isinstance(data, str):
                data = data.encode(enc) + b"\x00"
            elif isinstance(data, int):
                data = data.to_bytes(4, "little")
            else:
                data = bytes(data)
            if data_out:
                maxlen = int.from_bytes(self.mem_read(data_len, 4), "little") if data_len else 0
                if len(data) > maxlen:
                    return windefs.ERROR_MORE_DATA
                self.mem_write(data_out, data)
            if data_len:
                self.mem_write(data_len, len(data).to_bytes(4, "little"))
            self.record_registry_access_event(path, REG_READ, value_name=vname)
            return windefs.ERROR_SUCCESS

        reg("RegEnumValue", RegEnumValue, 8)
        reg("RegEnumValueA", RegEnumValue, 8)
        reg("RegEnumValueW", RegEnumValue, 8)

        def RegQueryValue(self, emu, argv, ctx=None):
            """
            LSTATUS RegQueryValue(
                HKEY    hKey,
                LPCTSTR lpSubKey,
                LPDWORD lpReserved,
                LPSTR   lpData,
                LPDWORD lpcbData
            );
            """
            ctx, cw = self.prepare_ctx(ctx)
            hkey, subkey, reserved, data_out, data_len = argv
            path = _key_path(emu, hkey)
            if not path:
                return windefs.ERROR_INVALID_HANDLE
            enc = _value_encoding(cw)
            if subkey:
                sub = self.read_mem_string(subkey, cw)
                if sub:
                    path = path.rstrip("\\") + "\\" + sub
            key = self.reg_open_key(path)
            if not key:
                return windefs.ERROR_PATH_NOT_FOUND
            val = key.get_value("")
            if not val:
                return windefs.ERROR_FILE_NOT_FOUND
            data = val.get_data()
            if isinstance(data, str):
                data = data.encode(enc) + b"\x00"
            else:
                data = bytes(data)
            if data_out:
                maxlen = int.from_bytes(self.mem_read(data_len, 4), "little") if data_len else 0
                if len(data) > maxlen:
                    return windefs.ERROR_MORE_DATA
                self.mem_write(data_out, data)
            if data_len:
                self.mem_write(data_len, len(data).to_bytes(4, "little"))
            self.record_registry_access_event(path, REG_READ, value_name="")
            return windefs.ERROR_SUCCESS

        reg("RegQueryValue", RegQueryValue, 5)
        reg("RegQueryValueA", RegQueryValue, 5)
        reg("RegQueryValueW", RegQueryValue, 5)

        def RegSetValue(self, emu, argv, ctx=None):
            """
            LSTATUS RegSetValue(
                HKEY    hKey,
                LPCTSTR lpSubKey,
                DWORD   dwType,
                LPCTSTR lpData,
                DWORD   cbData
            );
            """
            ctx, cw = self.prepare_ctx(ctx)
            hkey, subkey, typ, data, cb = argv
            path = _key_path(emu, hkey)
            if not path:
                return windefs.ERROR_INVALID_HANDLE
            enc = _value_encoding(cw)
            if subkey:
                sub = self.read_mem_string(subkey, cw)
                if sub:
                    path = path.rstrip("\\") + "\\" + sub
            key = self.reg_open_key(path, create=True)
            if not key:
                return windefs.ERROR_PATH_NOT_FOUND
            if data:
                value = self.read_mem_string(data, cw)
            else:
                value = ""
            key.create_value("", "REG_SZ", value)
            self.record_registry_access_event(path, REG_WRITE, value_name="", data=value)
            return windefs.ERROR_SUCCESS

        reg("RegSetValue", RegSetValue, 5)
        reg("RegSetValueA", RegSetValue, 5)
        reg("RegSetValueW", RegSetValue, 5)

        def RegSetKeyValue(self, emu, argv, ctx=None):
            """
            LSTATUS RegSetKeyValue(
                HKEY    hKey,
                LPCTSTR lpSubKey,
                LPCTSTR lpValueName,
                DWORD   dwType,
                LPCVOID lpData,
                DWORD   cbData
            );
            """
            ctx, cw = self.prepare_ctx(ctx)
            hkey, subkey, vname, typ, data, cb = argv
            path = _key_path(emu, hkey)
            if not path:
                return windefs.ERROR_INVALID_HANDLE
            if subkey:
                sub = self.read_mem_string(subkey, cw)
                if sub:
                    path = path.rstrip("\\") + "\\" + sub
            key = self.reg_open_key(path, create=True)
            if not key:
                return windefs.ERROR_PATH_NOT_FOUND
            name = self.read_mem_string(vname, cw) if vname else ""
            type_name = regdefs.get_value_type(typ) or "REG_SZ"
            if typ == 4:  # REG_DWORD
                value = int.from_bytes(self.mem_read(data, 4), "little") if data else 0
            elif typ in (1, 2):  # REG_SZ / REG_EXPAND_SZ
                value = self.read_mem_string(data, cw) if data else ""
            else:
                value = self.mem_read(data, cb) if data else b""
            key.create_value(name, type_name, value)
            self.record_registry_access_event(path, REG_WRITE, value_name=name, data=value)
            return windefs.ERROR_SUCCESS

        reg("RegSetKeyValue", RegSetKeyValue, 6)
        reg("RegSetKeyValueA", RegSetKeyValue, 6)
        reg("RegSetKeyValueW", RegSetKeyValue, 6)

        def RegDeleteKey(self, emu, argv, ctx=None):
            """LSTATUS RegDeleteKey(HKEY hKey, LPCTSTR lpSubKey);"""
            ctx, cw = self.prepare_ctx(ctx)
            hkey, subkey = argv
            path = _key_path(emu, hkey)
            if not path:
                return windefs.ERROR_INVALID_HANDLE
            if subkey:
                sub = self.read_mem_string(subkey, cw)
                if sub:
                    path = path.rstrip("\\") + "\\" + sub
            key = self.reg_open_key(path)
            if not key:
                return windefs.ERROR_PATH_NOT_FOUND
            self.record_registry_access_event(path, REG_CREATE)
            return windefs.ERROR_SUCCESS

        reg("RegDeleteKey", RegDeleteKey, 2)
        reg("RegDeleteKeyA", RegDeleteKey, 2)
        reg("RegDeleteKeyW", RegDeleteKey, 2)

        def RegDeleteKeyEx(self, emu, argv, ctx=None):
            """LSTATUS RegDeleteKeyEx(HKEY hKey, LPCTSTR lpSubKey, REGSAM samView, DWORD Reserved);"""
            return RegDeleteKey(self, emu, argv[:2], ctx)

        reg("RegDeleteKeyEx", RegDeleteKeyEx, 4)
        reg("RegDeleteKeyExA", RegDeleteKeyEx, 4)
        reg("RegDeleteKeyExW", RegDeleteKeyEx, 4)

        def RegDeleteTree(self, emu, argv, ctx=None):
            """LSTATUS RegDeleteTree(HKEY hKey, LPCTSTR lpSubKey);"""
            return RegDeleteKey(self, emu, argv, ctx)

        reg("RegDeleteTree", RegDeleteTree, 2)
        reg("RegDeleteTreeA", RegDeleteTree, 2)
        reg("RegDeleteTreeW", RegDeleteTree, 2)

        def RegDeleteKeyValue(self, emu, argv, ctx=None):
            """LSTATUS RegDeleteKeyValue(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName);"""
            ctx, cw = self.prepare_ctx(ctx)
            hkey, subkey, vname = argv
            path = _key_path(emu, hkey)
            if not path:
                return windefs.ERROR_INVALID_HANDLE
            if subkey:
                sub = self.read_mem_string(subkey, cw)
                if sub:
                    path = path.rstrip("\\") + "\\" + sub
            key = self.reg_open_key(path)
            if not key:
                return windefs.ERROR_PATH_NOT_FOUND
            name = self.read_mem_string(vname, cw) if vname else ""
            key.create_value(name, "REG_NONE", None)
            self.record_registry_access_event(path, REG_WRITE, value_name=name)
            return windefs.ERROR_SUCCESS

        reg("RegDeleteKeyValue", RegDeleteKeyValue, 3)
        reg("RegDeleteKeyValueA", RegDeleteKeyValue, 3)
        reg("RegDeleteKeyValueW", RegDeleteKeyValue, 3)

        def RegFlushKey(self, emu, argv, ctx=None):
            """LSTATUS RegFlushKey(HKEY hKey);"""
            return windefs.ERROR_SUCCESS

        reg("RegFlushKey", RegFlushKey, 1)

        def RegLoadKey(self, emu, argv, ctx=None):
            """LSTATUS RegLoadKey(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpFile);"""
            ctx, cw = self.prepare_ctx(ctx)
            hkey, subkey, file = argv
            path = _key_path(emu, hkey)
            if not path:
                return windefs.ERROR_INVALID_HANDLE
            sub = self.read_mem_string(subkey, cw) if subkey else ""
            if sub:
                path = path.rstrip("\\") + "\\" + sub
            self.reg_open_key(path, create=True)
            self.record_registry_access_event(path, REG_CREATE)
            return windefs.ERROR_SUCCESS

        reg("RegLoadKey", RegLoadKey, 3)
        reg("RegLoadKeyA", RegLoadKey, 3)
        reg("RegLoadKeyW", RegLoadKey, 3)

        def RegUnLoadKey(self, emu, argv, ctx=None):
            """LSTATUS RegUnLoadKey(HKEY hKey, LPCTSTR lpSubKey);"""
            ctx, cw = self.prepare_ctx(ctx)
            hkey, subkey = argv
            path = _key_path(emu, hkey)
            if not path:
                return windefs.ERROR_INVALID_HANDLE
            sub = self.read_mem_string(subkey, cw) if subkey else ""
            if sub:
                path = path.rstrip("\\") + "\\" + sub
            self.record_registry_access_event(path, REG_CREATE)
            return windefs.ERROR_SUCCESS

        reg("RegUnLoadKey", RegUnLoadKey, 2)
        reg("RegUnLoadKeyA", RegUnLoadKey, 2)
        reg("RegUnLoadKeyW", RegUnLoadKey, 2)

        def RegEnableReflectionKey(self, emu, argv, ctx=None):
            """LSTATUS RegEnableReflectionKey(HKEY hBaseKey);"""
            return windefs.ERROR_SUCCESS

        reg("RegEnableReflectionKey", RegEnableReflectionKey, 1)
        reg("RegDisableReflectionKey", RegEnableReflectionKey, 1)

        def RegOpenCurrentUser(self, emu, argv, ctx=None):
            """LSTATUS RegOpenCurrentUser(REGSAM samDesired, PHKEY phkResult);"""
            access, out = argv
            hnd = self.reg_open_key("HKEY_CURRENT_USER", create=False)
            if not hnd:
                return windefs.ERROR_PATH_NOT_FOUND
            if out:
                self.mem_write(out, hnd.to_bytes(ptr, "little"))
            return windefs.ERROR_SUCCESS

        reg("RegOpenCurrentUser", RegOpenCurrentUser, 2)

    def _register_advapi32_batch(self):
        """Register real handlers for SID, event log, credential, crypto and
        miscellaneous advapi32 functions."""
        ptr = self.get_ptr_size()
        sd = _arch.CALL_CONV_STDCALL

        def reg(name, func, argc):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, sd, None)

        # ---- SID helpers ----
        def sid_to_string(sid_addr):
            if not sid_addr:
                return None
            data = self.mem_read(sid_addr, 8)
            revision = data[0]
            count = data[1]
            auth = int.from_bytes(data[2:8], "big")
            parts = [f"S-{revision}-{auth}"]
            for i in range(count):
                sub = int.from_bytes(self.mem_read(sid_addr + 8 + i * 4, 4), "little")
                parts.append(str(sub))
            return "-".join(parts)

        def ConvertSidToStringSid(self, emu, argv, ctx=None):
            sid, out = argv
            if not sid or not out:
                return False
            s = sid_to_string(sid)
            if s is None:
                return False
            ctx, cw = self.prepare_ctx(ctx)
            enc = "utf-16le" if cw == 2 else "utf-8"
            data = s.encode(enc) + (b"\x00\x00" if cw == 2 else b"\x00")
            buf = self.mem_alloc(len(data), tag="api.advapi32.sidstr")
            self.mem_write(buf, data)
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return True

        reg("ConvertSidToStringSidW", ConvertSidToStringSid, 2)
        reg("ConvertSidToStringSidA", ConvertSidToStringSid, 2)

        def ConvertStringSidToSid(self, emu, argv, ctx=None):
            s, out = argv
            if not s or not out:
                return False
            txt = self.read_wide_string(s) if ctx and (ctx or {}).get("func_name", "").endswith("W") else self.read_string(s)
            parts = txt.split("-")
            try:
                revision = int(parts[1])
                auth = int(parts[2])
                subs = [int(p) for p in parts[3:]]
            except Exception:
                return False
            buf = self.mem_alloc(8 + len(subs) * 4, tag="api.advapi32.sid")
            self.mem_write(buf, bytes([revision, len(subs)]) + auth.to_bytes(6, "big"))
            for i, sub in enumerate(subs):
                self.mem_write(buf + 8 + i * 4, sub.to_bytes(4, "little"))
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return True

        reg("ConvertStringSidToSidW", ConvertStringSidToSid, 2)
        reg("ConvertStringSidToSidA", ConvertStringSidToSid, 2)

        def InitializeSid(self, emu, argv, ctx=None):
            sid, auth, count = argv
            if not sid:
                return False
            self.mem_write(sid, bytes([1, count]) + auth.to_bytes(6, "big"))
            return True

        reg("InitializeSid", InitializeSid, 3)

        def GetLengthSid(self, emu, argv, ctx=None):
            sid = argv[0]
            if not sid:
                return 0
            count = self.mem_read(sid, 1)[0] if self.mem_read(sid, 1) else 0
            return 8 + count * 4

        reg("GetLengthSid", GetLengthSid, 1)

        def IsValidSid(self, emu, argv, ctx=None):
            sid = argv[0]
            if not sid:
                return False
            try:
                data = self.mem_read(sid, 2)
                if data[0] != 1:
                    return False
                count = data[1]
                self.mem_read(sid + 8, count * 4)
                return True
            except Exception:
                return False

        reg("IsValidSid", IsValidSid, 1)

        def CreateWellKnownSid(self, emu, argv, ctx=None):
            sid_type, domain, sid, size = argv
            if not sid or not size:
                return False
            cur = int.from_bytes(self.mem_read(size, 4), "little")
            if cur < 20:
                self.mem_write(size, b"\x14\x00\x00\x00")
                return False
            self.mem_write(sid, b"\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00")
            return True

        reg("CreateWellKnownSid", CreateWellKnownSid, 4)

        def EqualPrefixSid(self, emu, argv, ctx=None):
            a, b = argv
            if not a or not b:
                return False
            try:
                count = self.mem_read(a, 1)[0]
                return self.mem_read(a, 8 + count * 4) == self.mem_read(b, 8 + count * 4)
            except Exception:
                return False

        reg("EqualPrefixSid", EqualPrefixSid, 2)

        def GetSidLengthRequired(self, emu, argv, ctx=None):
            count = argv[0]
            return 8 + count * 4

        reg("GetSidLengthRequired", GetSidLengthRequired, 1)

        # ---- event log ----
        self.event_sources: set = set()

        def RegisterEventSource(self, emu, argv, ctx=None):
            server, name = argv
            if not name:
                return 0
            ctx, cw = self.prepare_ctx(ctx)
            src = self.read_mem_string(name, cw)
            self.event_sources.add(src)
            return self.get_handle()

        reg("RegisterEventSourceW", RegisterEventSource, 2)
        reg("RegisterEventSourceA", RegisterEventSource, 2)

        def DeregisterEventSource(self, emu, argv, ctx=None):
            return True

        reg("DeregisterEventSource", DeregisterEventSource, 1)

        def ReportEvent(self, emu, argv, ctx=None):
            source, typ, cat, id_, user, num_strings, data_size, strings, raw = argv
            if strings and num_strings:
                strs = []
                arr = int.from_bytes(self.mem_read(strings, ptr), "little")
                for i in range(num_strings):
                    s = int.from_bytes(self.mem_read(arr + i * ptr, ptr), "little")
                    strs.append(self.read_wide_string(s) if s else "")
                self.record_network_event("", 0)  # no-op to keep signature parity
            return True

        reg("ReportEventW", ReportEvent, 9)
        reg("ReportEventA", ReportEvent, 9)

        def OpenEventLog(self, emu, argv, ctx=None):
            server, name = argv
            if not name:
                return 0
            ctx, cw = self.prepare_ctx(ctx)
            self.read_mem_string(name, cw)
            return self.get_handle()

        reg("OpenEventLogW", OpenEventLog, 2)
        reg("OpenEventLogA", OpenEventLog, 2)
        reg("OpenBackupEventLogW", OpenEventLog, 2)
        reg("OpenBackupEventLogA", OpenEventLog, 2)

        def CloseEventLog(self, emu, argv, ctx=None):
            return True

        reg("CloseEventLog", CloseEventLog, 1)

        def GetNumberOfEventLogRecords(self, emu, argv, ctx=None):
            handle, out = argv
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00")
            return True

        reg("GetNumberOfEventLogRecords", GetNumberOfEventLogRecords, 2)

        def GetOldestEventLogRecord(self, emu, argv, ctx=None):
            handle, out = argv
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00")
            return True

        reg("GetOldestEventLogRecord", GetOldestEventLogRecord, 2)

        def ClearEventLog(self, emu, argv, ctx=None):
            return True

        reg("ClearEventLogW", ClearEventLog, 2)
        reg("ClearEventLogA", ClearEventLog, 2)
        reg("BackupEventLogW", ClearEventLog, 2)
        reg("BackupEventLogA", ClearEventLog, 2)
        reg("NotifyChangeEventLog", ClearEventLog, 3)

        # ---- credentials store ----
        if not hasattr(self, "creds"):
            self.creds = {}

        def CredRead(self, emu, argv, ctx=None):
            target, typ, flags, out = argv
            if not target or not out:
                return False
            ctx, cw = self.prepare_ctx(ctx)
            name = self.read_mem_string(target, cw)
            entry = self.creds.get((name.lower(), typ))
            if not entry:
                return False
            blob, blen = entry
            buf = self.mem_alloc(blen + ptr * 2, tag="api.advapi32.cred")
            self.mem_write(buf, blob)
            self.mem_write(buf + blen, (buf + blen + ptr).to_bytes(ptr, "little"))
            self.mem_write(buf + blen + ptr, name.encode("utf-16le") + b"\x00\x00")
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return True

        reg("CredReadW", CredRead, 4)
        reg("CredReadA", CredRead, 4)

        def CredWrite(self, emu, argv, ctx=None):
            cred, flags = argv
            if not cred:
                return False
            username = int.from_bytes(self.mem_read(cred + ptr, ptr), "little")
            target = int.from_bytes(self.mem_read(cred + ptr * 2, ptr), "little")
            blob_size = int.from_bytes(self.mem_read(cred + ptr * 6, ptr), "little")
            blob = int.from_bytes(self.mem_read(cred + ptr * 7, ptr), "little")
            typ = int.from_bytes(self.mem_read(cred + ptr * 8, 4), "little")
            name = self.read_wide_string(target) if target else ""
            data = self.mem_read(blob, blob_size) if blob and blob_size else b""
            self.creds[(name.lower(), typ)] = (data, blob_size)
            return True

        reg("CredWriteW", CredWrite, 2)
        reg("CredWriteA", CredWrite, 2)

        def CredDelete(self, emu, argv, ctx=None):
            target, typ, flags = argv
            if not target:
                return False
            ctx, cw = self.prepare_ctx(ctx)
            name = self.read_mem_string(target, cw)
            self.creds.pop((name.lower(), typ), None)
            return True

        reg("CredDeleteW", CredDelete, 3)
        reg("CredDeleteA", CredDelete, 3)

        def CredFree(self, emu, argv, ctx=None):
            buf = argv[0]
            if buf:
                try:
                    self.mem_free(buf)
                except Exception:
                    pass

        reg("CredFree", CredFree, 1)

        def CredEnumerate(self, emu, argv, ctx=None):
            filter_, flags, count_out, list_out = argv
            if count_out:
                self.mem_write(count_out, b"\x00\x00\x00\x00")
            if list_out:
                self.mem_write(list_out, b"\x00" * ptr)
            return False

        reg("CredEnumerateW", CredEnumerate, 4)
        reg("CredEnumerateA", CredEnumerate, 4)

        def CredUnprotect(self, emu, argv, ctx=None):
            return True

        reg("CredUnprotectW", CredUnprotect, 4)
        reg("CredUnprotectA", CredUnprotect, 4)

        def CredProtect(self, emu, argv, ctx=None):
            return False

        reg("CredProtectW", CredProtect, 6)
        reg("CredProtectA", CredProtect, 6)

        # ---- crypto (cryptbase SystemFunction*) ----
        def _systemfunction_hash(hash_fn):
            """SystemFunction00x(data_blob, out_blob): hash into the out blob."""

            def impl(self, emu, argv, ctx=None):
                data_in, out_in = argv
                if not data_in or not out_in:
                    return 1
                blob = self.mem_read(data_in, 4)
                size = int.from_bytes(blob[:4], "little") if len(blob) >= 4 else 0
                if not size:
                    return 1
                data = self.mem_read(int.from_bytes(self.mem_read(data_in + 4, ptr), "little"), size)
                digest = hash_fn(data)
                out_buf = int.from_bytes(self.mem_read(out_in + 4, ptr), "little")
                if not out_buf:
                    out_buf = self.mem_alloc(16, tag="api.advapi32.hash")
                    self.mem_write(out_in + 4, out_buf.to_bytes(ptr, "little"))
                self.mem_write(out_in, struct.pack("<I", 16))
                self.mem_write(out_buf, digest)
                return 0

            return impl

        import hashlib as _hashlib

        reg("SystemFunction001", _systemfunction_hash(lambda d: _hashlib.new("md4", d).digest()), 2)
        reg("SystemFunction002", _systemfunction_hash(lambda d: _hashlib.new("md4", d).digest()), 2)
        reg("SystemFunction003", _systemfunction_hash(lambda d: _hashlib.md5(d).digest()), 2)

        def SystemFunctionRC4(self, emu, argv, ctx=None):
            key, data = argv
            if not key or not data:
                return 1
            key_blob = self.mem_read(key, 4)
            key_size = int.from_bytes(key_blob[:4], "little") if len(key_blob) >= 4 else 0
            key_data = self.mem_read(int.from_bytes(self.mem_read(key + 4, ptr), "little"), key_size) if key_size else b""
            data_blob = self.mem_read(data, 4)
            data_size = int.from_bytes(data_blob[:4], "little") if len(data_blob) >= 4 else 0
            data_buf = int.from_bytes(self.mem_read(data + 4, ptr), "little")
            payload = self.mem_read(data_buf, data_size)
            cipher = ARC4.new(key_data)
            enc = cipher.encrypt(payload)
            self.mem_write(data_buf, enc)
            return 0

        reg("SystemFunction032", SystemFunctionRC4, 2)
        reg("SystemFunction033", SystemFunctionRC4, 2)

        # ---- misc ----
        def ImpersonateSelf(self, emu, argv, ctx=None):
            return True

        reg("ImpersonateSelf", ImpersonateSelf, 1)

        def AllocateLocallyUniqueId(self, emu, argv, ctx=None):
            out = argv[0]
            if not out:
                return False
            import uuid

            u = uuid.uuid4()
            self.mem_write(out, struct.pack("<QQ", u.time_low | (u.time_mid << 32), u.time_hi_version))
            return True

        reg("AllocateLocallyUniqueId", AllocateLocallyUniqueId, 1)

        def EncryptFile(self, emu, argv, ctx=None):
            path = argv[0]
            if not path:
                return False
            ctx, cw = self.prepare_ctx(ctx)
            p = self.read_mem_string(path, cw)
            return self.does_file_exist(p)

        reg("EncryptFileW", EncryptFile, 1)
        reg("EncryptFileA", EncryptFile, 1)

        def DecryptFile(self, emu, argv, ctx=None):
            return True

        reg("DecryptFileW", DecryptFile, 2)
        reg("DecryptFileA", DecryptFile, 2)

        def FileEncryptionStatus(self, emu, argv, ctx=None):
            path, out = argv
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00")
            return True

        reg("FileEncryptionStatusW", FileEncryptionStatus, 2)
        reg("FileEncryptionStatusA", FileEncryptionStatus, 2)

        def InitiateSystemShutdown(self, emu, argv, ctx=None):
            return True

        reg("InitiateSystemShutdownW", InitiateSystemShutdown, 5)
        reg("InitiateSystemShutdownA", InitiateSystemShutdown, 5)
        reg("InitiateSystemShutdownExW", InitiateSystemShutdown, 6)
        reg("InitiateSystemShutdownExA", InitiateSystemShutdown, 6)

        def AbortSystemShutdown(self, emu, argv, ctx=None):
            return True

        reg("AbortSystemShutdownW", AbortSystemShutdown, 1)
        reg("AbortSystemShutdownA", AbortSystemShutdown, 1)

        def LogonUser(self, emu, argv, ctx=None):
            username, domain, password, typ, provider, token_out = argv
            if not token_out:
                return False
            proc = emu.get_current_process()
            import speakeasy.windows.objman as _objman

            token = _objman.Token(emu)
            token.user = self.read_wide_string(username) if username else ""
            token.domain = self.read_wide_string(domain) if domain else ""
            token.privileges = ["SeChangeNotifyPrivilege"]
            hnd = emu.get_object_handle(token)
            self.mem_write(token_out, hnd.to_bytes(ptr, "little"))
            return True

        reg("LogonUserW", LogonUser, 6)
        reg("LogonUserA", LogonUser, 6)

        def GetFileSecurity(self, emu, argv, ctx=None):
            path, req, sd, size, needed = argv
            if needed:
                self.mem_write(needed, b"\x14\x00\x00\x00")
            if sd and size >= 20:
                self.mem_write(sd, b"\x01\x00\x04\x80" + b"\x00" * 16)
                return True
            return False

        reg("GetFileSecurityW", GetFileSecurity, 5)
        reg("GetFileSecurityA", GetFileSecurity, 5)

        def SetFileSecurity(self, emu, argv, ctx=None):
            return False

        reg("SetFileSecurityW", SetFileSecurity, 3)
        reg("SetFileSecurityA", SetFileSecurity, 3)

        def GetKernelObjectSecurity(self, emu, argv, ctx=None):
            handle, req, sd, size, needed = argv
            if needed:
                self.mem_write(needed, b"\x14\x00\x00\x00")
            return False

        reg("GetKernelObjectSecurity", GetKernelObjectSecurity, 5)

        def SetKernelObjectSecurity(self, emu, argv, ctx=None):
            return False

        reg("SetKernelObjectSecurity", SetKernelObjectSecurity, 3)

        def LookupPrivilegeDisplayName(self, emu, argv, ctx=None):
            system, name, display, size, lang = argv
            if not display or not size:
                return False
            n = self.read_wide_string(name) if name else ""
            self.write_wide_string(n, display)
            return True

        reg("LookupPrivilegeDisplayNameW", LookupPrivilegeDisplayName, 5)
        reg("LookupPrivilegeDisplayNameA", LookupPrivilegeDisplayName, 5)

        def LookupPrivilegeName(self, emu, argv, ctx=None):
            system, luid, name, size = argv
            if not name or not size:
                return False
            self.write_wide_string("SeChangeNotifyPrivilege", name)
            return True

        reg("LookupPrivilegeNameW", LookupPrivilegeName, 4)
        reg("LookupPrivilegeNameA", LookupPrivilegeName, 4)

        def GetSidSubAuthorityCount(self, emu, argv, ctx=None):
            sid = argv[0]
            if not sid:
                return 0
            return sid + 1

        reg("GetSidSubAuthorityCount", GetSidSubAuthorityCount, 1)

        def IsTokenRestricted(self, emu, argv, ctx=None):
            return False

        reg("IsTokenRestricted", IsTokenRestricted, 1)

        def OpenProcessToken(self, emu, argv, ctx=None):
            proc, access, out = argv
            if not out:
                return False
            token = objman.Token(emu)
            hnd = emu.get_object_handle(token)
            self.mem_write(out, hnd.to_bytes(ptr, "little"))
            return True

        reg("OpenProcessToken", OpenProcessToken, 3)

        def GetTokenInformation(self, emu, argv, ctx=None):
            token, info_class, info, size, needed = argv
            if needed:
                self.mem_write(needed, b"\x04\x00\x00\x00")
            if info and size >= 4:
                self.mem_write(info, b"\x00\x00\x00\x00")
            return True

        reg("GetTokenInformation", GetTokenInformation, 5)

        def SetTokenInformation(self, emu, argv, ctx=None):
            return False

        reg("SetTokenInformation", SetTokenInformation, 5)

        def GetTokenHandle(self, emu, argv, ctx=None):
            return 0

        reg("GetTokenHandle", GetTokenHandle, 0)

        def AreAllAccessesGranted(self, emu, argv, ctx=None):
            return True

        reg("AreAllAccessesGranted", AreAllAccessesGranted, 2)
        reg("AreAnyAccessesGranted", AreAllAccessesGranted, 2)

        def GetAce(self, emu, argv, ctx=None):
            acl, index, ace_out = argv
            if not ace_out:
                return False
            self.mem_write(ace_out, b"\x00" * ptr)
            return True

        reg("GetAce", GetAce, 3)

        def InitializeAcl(self, emu, argv, ctx=None):
            acl, size, revision = argv
            if not acl:
                return False
            self.mem_write(acl, struct.pack("<HBBI", revision, 0, size, 0))
            return True

        reg("InitializeAcl", InitializeAcl, 3)

        def IsValidAcl(self, emu, argv, ctx=None):
            return True

        reg("IsValidAcl", IsValidAcl, 1)

        def AddAccessAllowedAce(self, emu, argv, ctx=None):
            return True

        reg("AddAccessAllowedAce", AddAccessAllowedAce, 4)
        reg("AddAccessAllowedAceEx", AddAccessAllowedAce, 5)

        def AddAccessDeniedAce(self, emu, argv, ctx=None):
            return True

        reg("AddAccessDeniedAce", AddAccessDeniedAce, 4)
        reg("AddAccessDeniedAceEx", AddAccessDeniedAce, 5)

        def DeleteAce(self, emu, argv, ctx=None):
            return True

        reg("DeleteAce", DeleteAce, 2)

        def GetAclInformation(self, emu, argv, ctx=None):
            acl, info, size, cls = argv
            if info:
                self.mem_write(info, struct.pack("<HH", 0, 1) + b"\x00" * 4)
            return True

        reg("GetAclInformation", GetAclInformation, 4)

        def SetAclInformation(self, emu, argv, ctx=None):
            return True

        reg("SetAclInformation", SetAclInformation, 4)

        def MakeSelfRelativeSD(self, emu, argv, ctx=None):
            return False

        reg("MakeSelfRelativeSD", MakeSelfRelativeSD, 3)

        def MakeAbsoluteSD(self, emu, argv, ctx=None):
            return False

        reg("MakeAbsoluteSD", MakeAbsoluteSD, 8)
        reg("MakeAbsoluteSD2", MakeAbsoluteSD, 2)

        def GetSecurityDescriptorControl(self, emu, argv, ctx=None):
            sd, control, revision = argv
            if control:
                self.mem_write(control, b"\x00\x00")
            if revision:
                self.mem_write(revision, b"\x01\x00")
            return True

        reg("GetSecurityDescriptorControl", GetSecurityDescriptorControl, 3)

        def GetSecurityDescriptorDacl(self, emu, argv, ctx=None):
            sd, present, dacl, defaulted = argv
            if present:
                self.mem_write(present, b"\x00\x00\x00\x00")
            if dacl:
                self.mem_write(dacl, b"\x00" * ptr)
            if defaulted:
                self.mem_write(defaulted, b"\x00\x00\x00\x00")
            return True

        reg("GetSecurityDescriptorDacl", GetSecurityDescriptorDacl, 4)

        def GetSecurityDescriptorOwner(self, emu, argv, ctx=None):
            sd, owner, defaulted = argv
            if owner:
                self.mem_write(owner, b"\x00" * ptr)
            if defaulted:
                self.mem_write(defaulted, b"\x00\x00\x00\x00")
            return True

        reg("GetSecurityDescriptorOwner", GetSecurityDescriptorOwner, 3)

        def GetSecurityDescriptorGroup(self, emu, argv, ctx=None):
            return self.GetSecurityDescriptorOwner(emu, argv, ctx)

        reg("GetSecurityDescriptorGroup", GetSecurityDescriptorGroup, 3)

        def InitializeSecurityDescriptor(self, emu, argv, ctx=None):
            sd, revision = argv
            if not sd:
                return False
            self.mem_write(sd, b"\x01\x00\x00\x00" + b"\x00" * 16)
            return True

        reg("InitializeSecurityDescriptor", InitializeSecurityDescriptor, 2)

        def IsValidSecurityDescriptor(self, emu, argv, ctx=None):
            return True

        reg("IsValidSecurityDescriptor", IsValidSecurityDescriptor, 1)

        def SetSecurityDescriptorDacl(self, emu, argv, ctx=None):
            return True

        reg("SetSecurityDescriptorDacl", SetSecurityDescriptorDacl, 4)

        def SetSecurityDescriptorOwner(self, emu, argv, ctx=None):
            return True

        reg("SetSecurityDescriptorOwner", SetSecurityDescriptorOwner, 3)

        def SetSecurityDescriptorGroup(self, emu, argv, ctx=None):
            return True

        reg("SetSecurityDescriptorGroup", SetSecurityDescriptorGroup, 3)

        def GetSecurityInfo(self, emu, argv, ctx=None):
            handle, info, sec, owner, group, dacl, sacl, out = argv
            return False

        reg("GetSecurityInfo", GetSecurityInfo, 8)

        def SetSecurityInfo(self, emu, argv, ctx=None):
            return False

        reg("SetSecurityInfo", SetSecurityInfo, 7)

        def GetNamedSecurityInfo(self, emu, argv, ctx=None):
            name, obj, info, owner, group, dacl, sacl, out = argv
            return False

        reg("GetNamedSecurityInfoW", GetNamedSecurityInfo, 8)
        reg("GetNamedSecurityInfoA", GetNamedSecurityInfo, 8)

        def MapGenericMask(self, emu, argv, ctx=None):
            return

        reg("MapGenericMask", MapGenericMask, 2)

        def QueryServiceStatusEx(self, emu, argv, ctx=None):
            """
            BOOL QueryServiceStatusEx(
                SC_HANDLE      hService,
                SC_STATUS_TYPE InfoLevel,
                LPBYTE         lpBuffer,
                DWORD          cbBufSize,
                LPDWORD        pcbBytesNeeded
            );
            """
            handle, info_level, buf, size, needed = argv
            if info_level != 0:  # SC_STATUS_PROCESS_INFO
                if needed:
                    self.mem_write(needed, b"\x00\x00\x00\x00")
                return False
            if not buf or size < 44:
                if needed:
                    self.mem_write(needed, b"\x2c\x00\x00\x00")
                return False
            self.mem_write(
                buf,
                struct.pack(
                    "<IIIIIIIIIIQ",
                    0,  # dwServiceType
                    1,  # dwCurrentState (SERVICE_RUNNING)
                    0,  # dwControlsAccepted
                    0,  # dwWin32ExitCode
                    0,  # dwServiceSpecificExitCode
                    0,  # dwCheckPoint
                    0,  # dwWaitHint
                    0,  # dwProcessId
                    0,  # dwServiceFlags
                    0,  # dwServiceFlags2
                    0,  # dwServiceFlags3
                ),
            )
            if needed:
                self.mem_write(needed, b"\x2c\x00\x00\x00")
            return True

        reg("QueryServiceStatusEx", QueryServiceStatusEx, 5)

        def SetEntriesInAcl(self, emu, argv, ctx=None):
            count, entries, old, new = argv
            if new:
                self.mem_write(new, b"\x00" * ptr)
            return 87  # ERROR_INVALID_PARAMETER

        reg("SetEntriesInAclW", SetEntriesInAcl, 4)
        reg("SetEntriesInAclA", SetEntriesInAcl, 4)

    def get_handle(self):
        self.curr_handle += 4
        return self.curr_handle

    @apihook("RegOpenKey", argc=3, conv=_arch.CALL_CONV_STDCALL)
    def RegOpenKey(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegOpenKeyA(
          HKEY   hKey,
          LPCSTR lpSubKey,
          PHKEY  phkResult
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        hKey, lpSubKey, phkResult = argv
        rv = windefs.ERROR_SUCCESS
        hnd = 0

        hkey_name = regdefs.get_hkey_type(hKey)
        if hkey_name:
            argv[0] = hkey_name
            if not hnd and not lpSubKey:
                hnd = hKey
        else:
            key_obj = emu.regman.get_key_from_handle(hKey)
            if not key_obj:
                return windefs.ERROR_PATH_NOT_FOUND
            hkey_name = key_obj.path

        if lpSubKey:
            lpSubKey = self.read_mem_string(lpSubKey, cw)
            argv[1] = lpSubKey

            if hkey_name and lpSubKey:
                if not lpSubKey.startswith("\\"):
                    lpSubKey = "\\" + lpSubKey
                lpSubKey = hkey_name + lpSubKey

            hnd = self.reg_open_key(lpSubKey, create=False)
            if not hnd:
                rv = windefs.ERROR_PATH_NOT_FOUND

            self.record_registry_access_event(lpSubKey, REG_OPEN, handle=hnd)

        if phkResult and hnd:
            self.mem_write(phkResult, hnd.to_bytes(self.get_ptr_size(), "little"))

        return rv

    @apihook("RegOpenKeyEx", argc=5, conv=_arch.CALL_CONV_STDCALL)
    def RegOpenKeyEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegOpenKeyEx(
          HKEY   hKey,
          LPTSTR lpSubKey,
          DWORD  ulOptions,
          REGSAM samDesired,
          PHKEY  phkResult
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        hKey, lpSubKey, ulOptions, samDesired, phkResult = argv
        rv = windefs.ERROR_SUCCESS

        hnd = 0

        hkey_name = regdefs.get_hkey_type(hKey)
        if hkey_name:
            argv[0] = hkey_name
            if not hnd and not lpSubKey:
                hnd = hKey

        if lpSubKey:
            lpSubKey = self.read_mem_string(lpSubKey, cw)
            argv[1] = lpSubKey

            if hkey_name and lpSubKey:
                if not lpSubKey.startswith("\\"):
                    lpSubKey = "\\" + lpSubKey
                lpSubKey = hkey_name + lpSubKey

            hnd = self.reg_open_key(lpSubKey, create=False)
            if not hnd:
                rv = windefs.ERROR_PATH_NOT_FOUND

            self.record_registry_access_event(lpSubKey, REG_OPEN, handle=hnd)

        if phkResult and hnd:
            self.mem_write(phkResult, hnd.to_bytes(self.get_ptr_size(), "little"))

        return rv

    @apihook("RegQueryValueEx", argc=6, conv=_arch.CALL_CONV_STDCALL)
    def RegQueryValueEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegQueryValueEx(
          HKEY    hKey,
          LPTSTR  lpValueName,
          LPDWORD lpReserved,
          LPDWORD lpType,
          LPBYTE  lpData,
          LPDWORD lpcbData
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        hKey, lpValueName, lpReserved, lpType, lpData, lpcbData = argv
        rv = windefs.ERROR_SUCCESS

        if lpValueName:
            lpValueName = self.read_mem_string(lpValueName, cw)
            argv[1] = lpValueName

        type_name = regdefs.get_value_type(lpType)
        if type_name:
            argv[3] = type_name

        length = 0
        if lpcbData:
            length = self.mem_read(lpcbData, 4)
            length = int.from_bytes(length, "little")
            argv[5] = length

        key = self.reg_get_key(hKey)
        if key:
            val = key.get_value(lpValueName)
            if val:
                output = b""
                typ = val.get_type()
                data = val.get_data()
                if typ in ("REG_SZ", "REG_EXPAND_SZ", regdefs.REG_SZ, regdefs.REG_EXPAND_SZ):
                    enc = "utf-16le" if cw == 2 else "utf-8"
                    output = str(data).encode(enc)
                    output += b"\x00\x00" if cw == 2 else b"\x00"
                elif typ in ("REG_DWORD", regdefs.REG_DWORD):
                    output = (int(data) & 0xFFFFFFFF).to_bytes(4, "little")
                elif typ in ("REG_QWORD", regdefs.REG_QWORD):
                    output = int(data).to_bytes(8, "little")
                elif typ in ("REG_BINARY", regdefs.REG_BINARY):
                    output = data if isinstance(data, bytes) else bytes(data)
                elif data is not None:
                    output = bytes(data) if isinstance(data, bytes) else str(data).encode("utf-8")

                if not lpData and not lpcbData:
                    rv = windefs.ERROR_SUCCESS
                else:
                    if lpcbData:
                        self.mem_write(lpcbData, len(output).to_bytes(4, "little"))

                    if len(output) > length:
                        rv = windefs.ERROR_INSUFFICIENT_BUFFER
                    else:
                        if lpData:
                            self.mem_write(lpData, output)

            # Missing value: report ERROR_FILE_NOT_FOUND like Windows
            else:
                rv = windefs.ERROR_FILE_NOT_FOUND

            kp = key.get_path()
            self.record_registry_access_event(
                kp,
                REG_READ,
                value_name=lpValueName,
                data=output,
                size=length,
                buffer=lpData,
            )

        return rv

    @apihook("RegSetValueEx", argc=6, conv=_arch.CALL_CONV_STDCALL)
    def RegSetValueEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegSetValueEx(
          HKEY       hKey,
          LPCSTR     lpValueName,
          DWORD      Reserved,
          DWORD      dwType,
          const BYTE *lpData,
          DWORD      cbData
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        hKey, lpValueName, _reserved, dwType, lpData, cbData = argv

        key = self.reg_get_key(hKey)
        if not key:
            return windefs.ERROR_INVALID_HANDLE

        value_name = ""
        if lpValueName:
            value_name = self.read_mem_string(lpValueName, cw)
            argv[1] = value_name

        value_data = ""
        if lpData and cbData:
            raw = self.mem_read(lpData, cbData)
            if dwType in (regdefs.REG_SZ, regdefs.REG_EXPAND_SZ):
                value_data = raw.decode("utf-16le" if cw == 2 else "utf-8", errors="ignore").rstrip("\x00")
            elif dwType == regdefs.REG_MULTI_SZ:
                value_data = raw.decode("utf-16le" if cw == 2 else "utf-8", errors="ignore").rstrip("\x00")
            elif dwType == regdefs.REG_DWORD:
                value_data = int.from_bytes(raw[:4].ljust(4, b"\x00"), "little")
            elif dwType == regdefs.REG_QWORD:
                value_data = int.from_bytes(raw[:8].ljust(8, b"\x00"), "little")
            else:
                value_data = raw

        value = key.get_value(value_name)
        if value:
            value.type = dwType
            value.data = value.normalize_value(dwType, value_data)
        else:
            key.create_value(value_name, dwType, value_data)

        self.record_registry_access_event(
            key.get_path(),
            REG_WRITE,
            value_name=value_name,
            data=raw if lpData and cbData else b"",
            handle=hKey,
            size=cbData,
            buffer=lpData,
        )

        return windefs.ERROR_SUCCESS

    @apihook("RegCloseKey", argc=1, conv=_arch.CALL_CONV_STDCALL)
    def RegCloseKey(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegCloseKey(
          HKEY hKey
        );
        """

        (hKey,) = argv

        key = self.reg_get_key(hKey)
        if not key:
            return windefs.ERROR_INVALID_HANDLE

        # 预定义根键（>= 0x80000000）按 Windows 语义不真正关闭
        if hKey < 0x80000000:
            regman = getattr(emu, "regman", None)
            if regman is not None:
                regman.reg_handles.pop(hKey, None)
            # 注册表句柄由 regman 独立管理（RegKey 非 KernelObject，get_handle
            # 不登记到 om._handle_map），因此不应调用 om.close_handle，否则在
            # 句柄值与内核对象句柄冲突时会误删 objman 中的条目。

        return windefs.ERROR_SUCCESS

    @apihook("RegEnumKey", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def RegEnumKey(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegEnumKey(
          HKEY  hKey,
          DWORD dwIndex,
          LPTSTR lpName,
          DWORD cchName
        );
        """
        ctx = ctx or {}

        hKey, dwIndex, lpName, cchName = argv

        _argv = argv + [0, 0, 0, 0]
        rv = self.RegEnumKeyEx(emu, _argv, ctx)
        argv[:] = _argv[:4]

        return rv

    @apihook("RegEnumKeyEx", argc=8, conv=_arch.CALL_CONV_STDCALL)
    def RegEnumKeyEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegEnumKeyEx(
            HKEY      hKey,
            DWORD     dwIndex,
            LPSTR     lpName,
            LPDWORD   lpcchName,
            LPDWORD   lpReserved,
            LPSTR     lpClass,
            LPDWORD   lpcchClass,
            PFILETIME lpftLastWriteTime
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        hKey, dwIndex, lpName, cchName, res, pcls, cchcls, last_write = argv

        rv = windefs.ERROR_INVALID_HANDLE
        if hKey:
            key = self.reg_get_key(hKey)
            argv[0] = key.get_path()
            if not key:
                rv = windefs.ERROR_INVALID_HANDLE
            else:
                subkeys = self.reg_get_subkeys(key)
                if (dwIndex + 1) > len(subkeys):
                    rv = windefs.ERROR_NO_MORE_ITEMS
                else:
                    if lpName:
                        sk = subkeys[dwIndex]
                        name = sk.get_path()
                        if cw == 2:
                            name = name.encode("utf-16le")
                        else:
                            name = name.encode("utf-8")
                        self.mem_write(lpName, name)
                        rv = windefs.ERROR_SUCCESS
            self.record_registry_access_event(key.get_path(), REG_LIST)
        return rv

    @apihook("RegCreateKey", argc=3)
    def RegCreateKey(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegCreateKey(
            HKEY    hKey,
            LPCWSTR lpSubKey,
            PHKEY   phkResult
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        hkey, lpSubKey, phkResult = argv
        rv = windefs.ERROR_INVALID_HANDLE
        if hkey:
            key = self.reg_get_key(hkey)
            argv[0] = key.get_path()
            if not key:
                rv = windefs.ERROR_INVALID_HANDLE
            else:
                if lpSubKey:
                    lpSubKey = self.read_mem_string(lpSubKey, cw)
                    argv[1] = lpSubKey
                    sub_key_path = key.get_path() + "\\" + lpSubKey
                    self.emu.reg_create_key(sub_key_path)
                    self.record_registry_access_event(sub_key_path, REG_CREATE)
                else:
                    hkey = (hkey).to_bytes(self.get_ptr_size(), "little")
                    self.mem_write(phkResult, hkey)
                    rv = windefs.ERROR_SUCCESS
        return rv

    @apihook("RegCreateKeyEx", argc=9, conv=_arch.CALL_CONV_STDCALL)
    def RegCreateKeyEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegCreateKeyExA(
          HKEY                  hKey,
          LPCSTR                lpSubKey,
          DWORD                 Reserved,
          LPSTR                 lpClass,
          DWORD                 dwOptions,
          REGSAM                samDesired,
          const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          PHKEY                 phkResult,
          LPDWORD               lpdwDisposition
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        hKey, lpSubKey, _reserved, _lpClass, _dwOptions, _samDesired, _sa, phkResult, lpdwDisposition = argv

        key_path = ""
        hkey_name = regdefs.get_hkey_type(hKey)
        if hkey_name:
            argv[0] = hkey_name
            key_path = hkey_name
        else:
            key_obj = self.reg_get_key(hKey)
            if not key_obj:
                return windefs.ERROR_INVALID_HANDLE
            key_path = key_obj.get_path()

        if lpSubKey:
            sub_key = self.read_mem_string(lpSubKey, cw)
            argv[1] = sub_key
            if key_path and sub_key:
                if not sub_key.startswith("\\"):
                    sub_key = "\\" + sub_key
                key_path = key_path + sub_key

        existing = self.emu.reg_get_key(path=key_path)
        hnd = self.reg_open_key(key_path, create=True)
        if not hnd:
            return windefs.ERROR_PATH_NOT_FOUND

        if phkResult:
            self.mem_write(phkResult, hnd.to_bytes(self.get_ptr_size(), "little"))

        if lpdwDisposition:
            disp = 2 if existing else 1
            self.mem_write(lpdwDisposition, disp.to_bytes(4, "little"))

        self.record_registry_access_event(key_path, REG_CREATE, handle=hnd)
        return windefs.ERROR_SUCCESS

    @apihook("RegDeleteValue", argc=2, conv=_arch.CALL_CONV_STDCALL)
    def RegDeleteValue(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegDeleteValueA(
          HKEY   hKey,
          LPCSTR lpValueName
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        hKey, lpValueName = argv

        key = self.reg_get_key(hKey)
        if not key:
            return windefs.ERROR_INVALID_HANDLE

        value_name = ""
        if lpValueName:
            value_name = self.read_mem_string(lpValueName, cw)
            argv[1] = value_name

        value = key.get_value(value_name)
        if not value:
            return windefs.ERROR_FILE_NOT_FOUND

        key.values.remove(value)
        return windefs.ERROR_SUCCESS

    @apihook("RegQueryInfoKey", argc=12, conv=_arch.CALL_CONV_STDCALL)
    def RegQueryInfoKey(self, emu, argv, ctx: api.ApiContext = None):
        # TODO: stub
        """
        LSTATUS RegQueryInfoKeyA(
          HKEY      hKey,
          LPSTR     lpClass,
          LPDWORD   lpcchClass,
          LPDWORD   lpReserved,
          LPDWORD   lpcSubKeys,
          LPDWORD   lpcbMaxSubKeyLen,
          LPDWORD   lpcbMaxClassLen,
          LPDWORD   lpcValues,
          LPDWORD   lpcbMaxValueNameLen,
          LPDWORD   lpcbMaxValueLen,
          LPDWORD   lpcbSecurityDescriptor,
          PFILETIME lpftLastWriteTime
        );
        """

        (
            hKey,
            lpClass,
            lpcchClass,
            _,
            subkeys,
            max_subkey_len,
            max_class_len,
            values,
            max_value_name_len,
            max_value_len,
            sec_desc,
            last_write,
        ) = argv

        rv = windefs.ERROR_SUCCESS

        hkey_name = regdefs.get_hkey_type(hKey)
        if hkey_name:
            argv[0] = hkey_name

        key = self.reg_get_key(hKey)
        if not key:
            rv = windefs.ERROR_INVALID_HANDLE

        return rv

    @apihook("OpenProcessToken", argc=3, conv=_arch.CALL_CONV_STDCALL)
    def OpenProcessToken(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL OpenProcessToken(
          HANDLE  ProcessHandle,
          DWORD   DesiredAccess,
          PHANDLE pTokenHandle
        );
        """

        hProcess, DesiredAccess, pTokenHandle = argv
        rv = 0

        if hProcess == self.get_max_int():
            obj = emu.get_current_process()
        else:
            obj = self.get_object_from_handle(hProcess)

        if obj:
            token = obj.token
            hToken = token.get_handle()

            if pTokenHandle:
                hnd = (hToken).to_bytes(self.get_ptr_size(), "little")
                self.mem_write(pTokenHandle, hnd)
                rv = 1
                emu.set_last_error(windefs.ERROR_SUCCESS)
            else:
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook("OpenThreadToken", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def OpenThreadToken(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL OpenThreadToken(
            HANDLE  ThreadHandle,
            DWORD   DesiredAccess,
            BOOL    OpenAsSelf,
            PHANDLE TokenHandle
        );
        """

        ThreadHandle, DesiredAccess, OpenAsSelf, pTokenHandle = argv
        rv = 0

        if ThreadHandle == self.get_max_int():
            obj = emu.get_current_thread()
        else:
            obj = self.get_object_from_handle(ThreadHandle)

        if obj:
            token = obj.token
            hToken = token.get_handle()

            if pTokenHandle:
                hnd = (hToken).to_bytes(self.get_ptr_size(), "little")
                self.mem_write(pTokenHandle, hnd)
                rv = 1
                emu.set_last_error(windefs.ERROR_SUCCESS)
            else:
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook("DuplicateTokenEx", argc=6, conv=_arch.CALL_CONV_STDCALL)
    def DuplicateTokenEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL DuplicateTokenEx(
          HANDLE                       hExistingToken,
          DWORD                        dwDesiredAccess,
          LPSECURITY_ATTRIBUTES        lpTokenAttributes,
          SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
          TOKEN_TYPE                   TokenType,
          PHANDLE                      phNewToken
        );
        """

        (hExistingToken, access, token_attrs, imp_level, toktype, phNewToken) = argv
        rv = 0

        obj = self.get_object_from_handle(hExistingToken)

        if obj:
            new_token = emu.new_object(objman.Token)
            hnd_new_token = new_token.get_handle()

            if phNewToken:
                hnd = (hnd_new_token).to_bytes(self.get_ptr_size(), "little")
                self.mem_write(phNewToken, hnd)
                rv = 1
                emu.set_last_error(windefs.ERROR_SUCCESS)
            else:
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook("SetTokenInformation", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def SetTokenInformation(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SetTokenInformation(
          HANDLE                  TokenHandle,
          TOKEN_INFORMATION_CLASS TokenInformationClass,
          LPVOID                  TokenInformation,
          DWORD                   TokenInformationLength
        );
        """

        handle, info_class, info, info_len = argv

        rv = 1

        return rv

    @apihook("StartServiceCtrlDispatcher", argc=1)
    def StartServiceCtrlDispatcher(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL StartServiceCtrlDispatcher(
          const SERVICE_TABLE_ENTRY *lpServiceStartTable
        );
        """
        ctx, cw = self.prepare_ctx(ctx, default_cw=1)
        (lpServiceStartTable,) = argv


        ste = self.win.SERVICE_TABLE_ENTRY(emu.get_ptr_size())
        entry = self.mem_cast(ste, lpServiceStartTable)

        argv[0] = "lpServiceStartTable=["

        while entry.lpServiceName != windefs.NULL or entry.lpServiceProc != windefs.NULL:
            service_name = "Service"
            if entry.lpServiceName != windefs.NULL:
                service_name = self.read_mem_string(entry.lpServiceName, cw)
                argv[0] += f" {{ lpServiceName={service_name}"
            else:
                argv[0] += " { lpServiceName=NULL"

            if entry.lpServiceProc != windefs.NULL:
                service_main = entry.lpServiceProc
                argv[0] += f", lpServiceProc={hex(service_main)} }} "
                argc, svc_argv = emu.build_service_main_args(service_name, char_width=cw)
                self.queue_run("thread.service", service_main, [argc, svc_argv])
            else:
                argv[0] += ", lpServiceProc=NULL } "

            lpServiceStartTable += self.sizeof(ste)
            ste = self.win.SERVICE_TABLE_ENTRY(emu.get_ptr_size())
            entry = self.mem_cast(ste, lpServiceStartTable)

        argv[0] += "]"

        rv = True
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("RegisterServiceCtrlHandler", argc=2)
    def RegisterServiceCtrlHandler(self, emu, argv, ctx: api.ApiContext = None):
        """
        SERVICE_STATUS_HANDLE RegisterServiceCtrlHandlerA(
            LPCSTR             lpServiceName,
            LPHANDLER_FUNCTION lpHandlerProc
            );
        """

        lpServiceName, lpHandlerProc = argv

        # dummy SERVICE_STATUS_HANDLE
        self.service_status_handle += 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return self.service_status_handle

    @apihook("RegisterServiceCtrlHandlerEx", argc=3)
    def RegisterServiceCtrlHandlerEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        SERVICE_STATUS_HANDLE RegisterServiceCtrlHandlerExA(
            LPCSTR                lpServiceName,
            LPHANDLER_FUNCTION_EX lpHandlerProc,
            LPVOID                lpContext
        );
        """
        ctx = ctx or {}
        lpServiceName, lpHandlerProc, lpContext = argv

        return self.RegisterServiceCtrlHandler(self, emu, [lpServiceName, lpHandlerProc], ctx)

    @apihook("SetServiceStatus", argc=2)
    def SetServiceStatus(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SetServiceStatus(
            SERVICE_STATUS_HANDLE hServiceStatus,
            LPSERVICE_STATUS      lpServiceStatus
            );
        """

        hServiceStatus, lpServiceStatus = argv

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return 0x1

    @apihook("RevertToSelf", argc=0)
    def RevertToSelf(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL RevertToSelf();
        """
        return 1

    @apihook("ImpersonateLoggedOnUser", argc=1)
    def ImpersonateLoggedOnUser(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL ImpersonateLoggedOnUser(
        HANDLE hToken
        );
        """
        return 1

    @apihook("OpenSCManager", argc=3)
    def OpenSCManager(self, emu, argv, ctx: api.ApiContext = None):
        """
        SC_HANDLE OpenSCManager(
          LPCSTR lpMachineName,
          LPCSTR lpDatabaseName,
          DWORD  dwDesiredAccess
        );
        """
        lpMachineName, lpDatabaseName, dwDesiredAccess = argv

        hScm = self.mem_alloc(size=8)
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return hScm

    @apihook("CreateService", argc=13)
    def CreateService(self, emu, argv, ctx: api.ApiContext = None):
        """
        SC_HANDLE CreateServiceA(
          SC_HANDLE hSCManager,
          LPCSTR    lpServiceName,
          LPCSTR    lpDisplayName,
          DWORD     dwDesiredAccess,
          DWORD     dwServiceType,
          DWORD     dwStartType,
          DWORD     dwErrorControl,
          LPCSTR    lpBinaryPathName,
          LPCSTR    lpLoadOrderGroup,
          LPDWORD   lpdwTagId,
          LPCSTR    lpDependencies,
          LPCSTR    lpServiceStartName,
          LPCSTR    lpPassword
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        (
            hScm,
            svc_name,
            disp_name,
            access,
            svc_type,
            start_type,
            error_ctrl,
            bin_path,
            load_group,
            tag_id,
            deps,
            svc_start_name,
            password,
        ) = argv


        if svc_name:
            _sname = self.read_mem_string(svc_name, cw)
            argv[1] = _sname
        if disp_name:
            _dname = self.read_mem_string(disp_name, cw)
            argv[2] = _dname
        if bin_path:
            _bpname = self.read_mem_string(bin_path, cw)
            argv[7] = _bpname

        hSvc = self.mem_alloc(size=8)
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return hSvc

    @apihook("StartService", argc=3)
    def StartService(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL StartService(
          SC_HANDLE hService,
          DWORD     dwNumServiceArgs,
          LPCSTR    *lpServiceArgVectors
        );
        """
        hService, dwNumServiceArgs, lpServiceArgVectors = argv

        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("StartServiceA", argc=3)
    def StartServiceA(self, emu, argv, ctx: api.ApiContext = None):
        ctx = ctx or {}
        return self.StartService(emu, argv, ctx)

    @apihook("ControlService", argc=3)
    def ControlService(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL ControlService(
          [in]  SC_HANDLE        hService,
          [in]  DWORD            dwControl,
          [out] LPSERVICE_STATUS lpServiceStatus
        );
        """
        hService, dwControl, lpServiceStatus = argv

        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("QueryServiceStatus", argc=2)
    def QueryServiceStatus(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL QueryServiceStatus(
          SC_HANDLE        hService,
          LPSERVICE_STATUS lpServiceStatus
        );
        """
        hService, lpServiceStatus = argv

        if not hService:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        if lpServiceStatus:
            service_status = (
                (0x10).to_bytes(4, "little")
                + (0x4).to_bytes(4, "little")
                + (0x1).to_bytes(4, "little")
                + (0x0).to_bytes(4, "little")
                + (0x0).to_bytes(4, "little")
                + (0x0).to_bytes(4, "little")
                + (0x0).to_bytes(4, "little")
            )
            self.mem_write(lpServiceStatus, service_status)

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("QueryServiceConfig", argc=4)
    @apihook("QueryServiceConfigA", argc=4)
    @apihook("QueryServiceConfigW", argc=4)
    def QueryServiceConfig(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL QueryServiceConfigA(
          SC_HANDLE               hService,
          LPQUERY_SERVICE_CONFIGA lpServiceConfig,
          DWORD                   cbBufSize,
          LPDWORD                 pcbBytesNeeded
        );
        """
        hService, lpServiceConfig, cbBufSize, pcbBytesNeeded = argv

        if not hService:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        ptr_size = self.get_ptr_size()
        required = (4 * 4) + (5 * ptr_size)

        if pcbBytesNeeded:
            self.mem_write(pcbBytesNeeded, required.to_bytes(4, "little"))

        if not lpServiceConfig or cbBufSize < required:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0

        buf = bytearray()
        buf.extend((0x10).to_bytes(4, "little"))
        buf.extend((0x2).to_bytes(4, "little"))
        buf.extend((0x1).to_bytes(4, "little"))
        buf.extend((0).to_bytes(ptr_size, "little"))
        buf.extend((0).to_bytes(ptr_size, "little"))
        buf.extend((0).to_bytes(4, "little"))
        buf.extend((0).to_bytes(ptr_size, "little"))
        buf.extend((0).to_bytes(ptr_size, "little"))
        buf.extend((0).to_bytes(ptr_size, "little"))

        self.mem_write(lpServiceConfig, bytes(buf))
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("CloseServiceHandle", argc=1)
    def CloseServiceHandle(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CloseServiceHandle(
          SC_HANDLE hSCObject
        );
        """
        (CloseServiceHandle,) = argv

        self.mem_free(CloseServiceHandle)

        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("ChangeServiceConfig", argc=11)
    def ChangeServiceConfig(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL ChangeServiceConfigA(
          SC_HANDLE hService,
          DWORD     dwServiceType,
          DWORD     dwStartType,
          DWORD     dwErrorControl,
          LPCSTR    lpBinaryPathName,
          LPCSTR    lpLoadOrderGroup,
          LPDWORD   lpdwTagId,
          LPCSTR    lpDependencies,
          LPCSTR    lpServiceStartName,
          LPCSTR    lpPassword,
          LPCSTR    lpDisplayName
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        (
            _hService,
            _dwServiceType,
            _dwStartType,
            _dwErrorControl,
            lpBinaryPathName,
            lpLoadOrderGroup,
            _lpdwTagId,
            lpDependencies,
            lpServiceStartName,
            lpPassword,
            lpDisplayName,
        ) = argv


        if lpBinaryPathName:
            argv[4] = self.read_mem_string(lpBinaryPathName, cw)
        if lpLoadOrderGroup:
            argv[5] = self.read_mem_string(lpLoadOrderGroup, cw)
        if lpDependencies:
            argv[7] = self.read_mem_string(lpDependencies, cw)
        if lpServiceStartName:
            argv[8] = self.read_mem_string(lpServiceStartName, cw)
        if lpPassword:
            argv[9] = self.read_mem_string(lpPassword, cw)
        if lpDisplayName:
            argv[10] = self.read_mem_string(lpDisplayName, cw)

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("ChangeServiceConfig2", argc=3)
    def ChangeServiceConfig2(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL ChangeServiceConfig2(
          SC_HANDLE hService,
          DWORD     dwInfoLevel,
          LPVOID    lpInfo
        );
        """
        hService, dwInfoLevel, lpInfo = argv

        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("SystemFunction036", argc=2)
    def RtlGenRandom(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOLEAN RtlGenRandom(
            PVOID RandomBuffer,
            ULONG RandomBufferLength
        );
        """
        RandomBuffer, RandomBufferLength = argv

        rv = False
        if RandomBuffer and RandomBufferLength:
            buf = bytes([i for i in range(RandomBufferLength)])
            self.mem_write(RandomBuffer, buf)
            rv = True

        return rv

    @apihook("CryptAcquireContext", argc=5)
    def CryptAcquireContext(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CryptAcquireContext(
            HCRYPTPROV *phProv,
            LPCSTR     szContainer,
            LPCSTR     szProvider,
            DWORD      dwProvType,
            DWORD      dwFlags
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        phProv, szContainer, szProvider, dwProvType, dwFlags = argv
        cont_str, prov_str = "", ""
        rv = False

        if szContainer:
            cont_str = self.read_mem_string(szContainer, cw)
            argv[1] = cont_str
        if szProvider:
            prov_str = self.read_mem_string(szProvider, cw)
            argv[2] = prov_str

        cm = emu.get_crypt_manager()
        hnd = cm.crypt_open(cname=cont_str, pname=prov_str, ptype=dwProvType, flags=dwFlags)

        if hnd and phProv:
            self.mem_write(phProv, hnd.to_bytes(emu.get_ptr_size(), "little"))
            rv = True
            emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("CryptGenRandom", argc=3)
    def CryptGenRandom(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CryptGenRandom(
            HCRYPTPROV hProv,
            DWORD      dwLen,
            BYTE       *pbBuffer
        );
        """
        hProv, dwLen, pbBuffer = argv
        rv = False

        if pbBuffer:
            out = b"A" * dwLen
            self.mem_write(pbBuffer, out)
            rv = True

        return rv

    @apihook("AllocateAndInitializeSid", argc=11)
    def AllocateAndInitializeSid(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL AllocateAndInitializeSid(
            PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            BYTE                      nSubAuthorityCount,
            DWORD                     nSubAuthority0,
            DWORD                     nSubAuthority1,
            DWORD                     nSubAuthority2,
            DWORD                     nSubAuthority3,
            DWORD                     nSubAuthority4,
            DWORD                     nSubAuthority5,
            DWORD                     nSubAuthority6,
            DWORD                     nSubAuthority7,
            PSID                      *pSid
        );
        """
        auth, count, sa0, sa1, sa2, sa3, sa4, sa5, sa6, sa7, pSid = argv
        rv = False

        if pSid:
            sid = self.mem_alloc(0x100, tag="api.struct.SID")
            self.mem_write(pSid, sid.to_bytes(emu.get_ptr_size(), "little"))
            rv = True

        return rv

    @apihook("CheckTokenMembership", argc=3)
    def CheckTokenMembership(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CheckTokenMembership(
            HANDLE TokenHandle,
            PSID   SidToCheck,
            PBOOL  IsMember
        );
        """
        TokenHandle, SidToCheck, IsMember = argv
        rv = False

        if IsMember:
            self.mem_write(IsMember, (1).to_bytes(4, "little"))
            rv = True
        return rv

    @apihook("FreeSid", argc=1)
    def FreeSid(self, emu, argv, ctx: api.ApiContext = None):
        """
        PVOID FreeSid(
            PSID pSid
        );
        """
        (pSid,) = argv
        rv = pSid

        if pSid:
            self.mem_free(pSid)
            rv = 0
        return rv

    @apihook("CryptReleaseContext", argc=2)
    def CryptReleaseContext(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CryptReleaseContext(
            HCRYPTPROV hProv,
            DWORD      dwFlags
        );
        """
        hProv, dwFlags = argv
        rv = True

        cm = emu.get_crypt_manager()
        cm.crypt_close(hProv)

        return rv

    @apihook("GetCurrentHwProfile", argc=1)
    def GetCurrentHwProfile(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetCurrentHwProfileA(
          LPHW_PROFILE_INFOA lpHwProfileInfo
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        (lpHwProfileInfo,) = argv

        if not lpHwProfileInfo:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        guid = "{00000000-0000-0000-0000-000000000000}"
        profile_name = "Speakeasy HW Profile"

        if cw == 2:
            guid_bytes = (guid + "\x00").encode("utf-16le")
            name_bytes = (profile_name + "\x00").encode("utf-16le")
            guid_bytes = guid_bytes.ljust(39 * 2, b"\x00")[: 39 * 2]
            name_bytes = name_bytes.ljust(80 * 2, b"\x00")[: 80 * 2]
        else:
            guid_bytes = (guid + "\x00").encode("utf-8")
            name_bytes = (profile_name + "\x00").encode("utf-8")
            guid_bytes = guid_bytes.ljust(39, b"\x00")[:39]
            name_bytes = name_bytes.ljust(80, b"\x00")[:80]

        out = (0).to_bytes(4, "little") + guid_bytes + name_bytes
        self.mem_write(lpHwProfileInfo, out)
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("GetUserName", argc=2)
    def GetUserName(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetUserName(
            LPSTR   lpBuffer,
            LPDWORD pcbBuffer
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        lpBuffer, pcbBuffer = argv
        rv = False

        user_name = emu.config.user.name
        argv[0] = user_name

        if lpBuffer:
            if cw == 2:
                out = user_name.encode("utf-16le")
            elif cw == 1:
                out = user_name.encode("utf-8")
            self.mem_write(lpBuffer, out)
            rv = True
        if pcbBuffer:
            self.mem_write(pcbBuffer, (len(user_name)).to_bytes(4, "little"))

        return rv

    @apihook("LookupPrivilegeValue", argc=3)
    def LookupPrivilegeValue(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL LookupPrivilegeValue(
            LPCSTR lpSystemName,
            LPCSTR lpName,
            PLUID  lpLuid
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        sysname, name, luid = argv
        rv = False

        if sysname:
            sysname = self.read_mem_string(sysname, cw)
            argv[0] = sysname
        if name:
            name = self.read_mem_string(name, cw)
            argv[1] = name
            rv = True

        return rv

    @apihook("AdjustTokenPrivileges", argc=6)
    def AdjustTokenPrivileges(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL AdjustTokenPrivileges(
            HANDLE            TokenHandle,
            BOOL              DisableAllPrivileges,
            PTOKEN_PRIVILEGES NewState,
            DWORD             BufferLength,
            PTOKEN_PRIVILEGES PreviousState,
            PDWORD            ReturnLength
        );
        """
        rv = True

        return rv

    @apihook("GetTokenInformation", argc=5)
    def GetTokenInformation(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetTokenInformation(
            HANDLE                  TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            LPVOID                  TokenInformation,
            DWORD                   TokenInformationLength,
            PDWORD                  ReturnLength
        );
        """
        hnd, info_class, info, info_len, ret_len = argv
        rv = True

        if not info_len:
            rv = False
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)

        if info_class == 20 and info and emu.config.user.is_admin:
            self.mem_write(info, (1).to_bytes(4, "little"))
        if ret_len:
            self.mem_write(ret_len, (4).to_bytes(4, "little"))

        return rv

    @apihook("EqualSid", argc=2)
    def EqualSid(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL EqualSid(
            PSID pSid1,
            PSID pSid2
        );
        """
        sid1, sid2 = argv
        rv = False

        if sid1 and sid2:
            s1 = self.mem_read(sid1, 10)
            s2 = self.mem_read(sid2, 10)
            if s1 == s2:
                rv = True

        return rv

    @apihook("GetSidIdentifierAuthority", argc=1)
    def GetSidIdentifierAuthority(self, emu, argv, ctx: api.ApiContext = None):
        """
        PSID_IDENTIFIER_AUTHORITY GetSidIdentifierAuthority(
          [in] PSID pSid
        );
        """
        (sid,) = argv

        # IdentifierAuthority is at offset 0x02 in the SID structure
        return sid + 2

    @apihook("GetSidSubAuthorityCount", argc=1)
    def GetSidSubAuthorityCount(self, emu, argv, ctx: api.ApiContext = None):
        """
        PUCHAR GetSidSubAuthorityCount(
            PSID pSid
        );
        """
        (sid,) = argv
        rv = 0

        if sid:
            rv = sid + 1

        return rv

    @apihook("GetSidSubAuthority", argc=2)
    def GetSidSubAuthority(self, emu, argv, ctx: api.ApiContext = None):
        """
        PDWORD GetSidSubAuthority(
          [in] PSID  pSid,
          [in] DWORD nSubAuthority
        );
        """
        sid, nsub = argv

        # SubAuthorities begin at offset 0x8
        return sid + 8 + (nsub * 4)

    @apihook("LookupAccountName", argc=7)
    def LookupAccountName(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL LookupAccountNameA(
          [in, optional]  LPCSTR        lpSystemName,
          [in]            LPCSTR        lpAccountName,
          [out, optional] PSID          Sid,
          [in, out]       LPDWORD       cbSid,
          [out, optional] LPSTR         ReferencedDomainName,
          [in, out]       LPDWORD       cchReferencedDomainName,
          [out]           PSID_NAME_USE peUse
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        ptr_sysname, ptr_acctname, ptr_sid, ptr_cbsid, ptr_domname, ptr_cchdomname, ptr_peuse = argv
        rv = 0


        if ptr_sysname:
            sn = self.read_mem_string(ptr_sysname, cw)
            argv[0] = sn

        if not ptr_acctname:
            return rv

        acctname = self.read_mem_string(ptr_acctname, cw)
        argv[1] = acctname

        user = emu.config.user.name
        # Currently only supporting user SIDs specified in the config
        if user != acctname:
            return rv

        str_sid = emu.config.user.sid
        if not str_sid:
            return rv

        argv[2] = str_sid
        sid_struct = windefs.convert_sid_str_to_struct(emu.get_ptr_size(), str_sid)
        side_struct_size = sid_struct.sizeof()

        cbsid = self.mem_read(ptr_cbsid, 4)
        cbsid = int.from_bytes(cbsid, "little")
        argv[3] = cbsid
        if not cbsid:
            self.mem_write(ptr_cbsid, side_struct_size.to_bytes(4, "little"))
            return rv

        if cbsid < side_struct_size:
            return rv

        domain = emu.config.domain
        cchdomname = self.mem_read(ptr_cchdomname, 4)
        cbcchdomname = int.from_bytes(cchdomname, "little")
        argv[5] = cbcchdomname
        if not cbcchdomname:
            buf_size = len(domain) + 1
            self.mem_write(ptr_cchdomname, buf_size.to_bytes(4, "little"))
            return rv

        rv = 1

        self.mem_write(ptr_sid, self.get_bytes(sid_struct))

        self.write_mem_string(domain, ptr_domname, cw)
        argv[4] = domain

        # Currently only supporting user SIDs (SidTypeUser = 1)
        self.mem_write(ptr_peuse, (1).to_bytes(4, "little"))
        argv[6] = 1

        return rv

    @apihook("LookupAccountSid", argc=7)
    def LookupAccountSid(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL LookupAccountSid(
            LPCSTR        lpSystemName,
            PSID          Sid,
            LPSTR         Name,
            LPDWORD       cchName,
            LPSTR         ReferencedDomainName,
            LPDWORD       cchReferencedDomainName,
            PSID_NAME_USE peUse
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        sysname, sid, name, cchname, domname, cchdomname, peuse = argv
        rv = False


        if not cchname or not cchdomname:
            return rv

        name_size = self.mem_read(cchname, 4)
        name_size = int.from_bytes(name_size, "little")

        dom_size = self.mem_read(cchdomname, 4)
        dom_size = int.from_bytes(dom_size, "little")

        self.write_mem_string("myuser", name, cw)
        self.write_mem_string("mydomain", domname, cw)
        rv = True

        if sysname:
            sn = self.read_mem_string(sysname, cw)
            argv[0] = sn

        return rv

    @apihook("CreateProcessAsUser", argc=11, conv=_arch.CALL_CONV_STDCALL)
    def CreateProcessAsUser(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CreateProcessAsUser(
          HANDLE                hToken,
          LPCSTR                lpApplicationName,
          LPSTR                 lpCommandLine,
          LPSECURITY_ATTRIBUTES lpProcessAttributes,
          LPSECURITY_ATTRIBUTES lpThreadAttributes,
          BOOL                  bInheritHandles,
          DWORD                 dwCreationFlags,
          LPVOID                lpEnvironment,
          LPCSTR                lpCurrentDirectory,
          LPSTARTUPINFOA        lpStartupInfo,
          LPPROCESS_INFORMATION lpProcessInformation
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        token, app, cmd, pa, ta, inherit, flags, env, cd, si, ppi = argv

        cmdstr = ""
        appstr = ""
        if app:
            appstr = self.read_mem_string(app, cw)
            argv[1] = appstr
        if cmd:
            cmdstr = self.read_mem_string(cmd, cw)
            if not appstr:
                appstr = cmdstr.split(" ")[0]
            argv[2] = cmdstr

        proc = emu.create_process(path=appstr, cmdline=cmdstr)
        proc_hnd = self.get_object_handle(proc)

        thread = proc.threads[0]
        thread_hnd = self.get_object_handle(thread)

        _pi = self.k32types.PROCESS_INFORMATION(emu.get_ptr_size())
        data = self.mem_cast(_pi, ppi)
        _pi.hProcess = proc_hnd
        _pi.hThread = thread_hnd
        _pi.dwProcessId = proc.pid
        _pi.dwThreadId = thread.tid

        self.mem_write(ppi, self.get_bytes(data))

        rv = 1

        self.record_process_event(proc, PROC_CREATE)
        return rv

    @apihook("CryptCreateHash", argc=5)
    def CryptCreateHash(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CryptCreateHash(
          HCRYPTPROV hProv,
          ALG_ID     Algid,
          HCRYPTKEY  hKey,
          DWORD      dwFlags,
          HCRYPTHASH *phHash
        );
        """

        hash_algs = {
            0x00008004: ("CALG_SHA1", hashlib.sha1),
            0x0000800C: ("CALG_SHA_256", hashlib.sha256),
            0x0000800D: ("CALG_SHA_384", hashlib.sha384),
            0x0000800E: ("CALG_SHA_512", hashlib.sha512),
            0x00008003: ("CALG_MD5", hashlib.md5),
        }

        hProv, Algid, hKey, dwFlags, phHash = argv
        argv[1] = hash_algs.get(Algid, Algid)[0]

        if hKey != 0:
            return 0

        if Algid not in hash_algs:
            emu.set_last_error(adv32.NTE_BAD_ALGID)
            return 0

        hnd = self.get_handle()
        self.hash_objects.update({hnd: hash_algs[Algid][1]()})
        self.mem_write(phHash, hnd.to_bytes(self.get_ptr_size(), "little"))
        return 1

    @apihook("CryptHashData", argc=4)
    def CryptHashData(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CryptHashData(
          HCRYPTHASH hHash,
          const BYTE *pbData,
          DWORD      dwDataLen,
          DWORD      dwFlags
        );
        """

        hHash, pbData, dwDataLen, dwFlags = argv
        hnd = self.hash_objects.get(hHash, None)
        if hnd is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        if dwDataLen <= 0:
            return 0

        data = self.mem_read(pbData, dwDataLen)
        hnd.update(data)
        return 1

    @apihook("CryptGetHashParam", argc=5)
    def CryptGetHashParam(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CryptGetHashParam(
          HCRYPTHASH hHash,
          DWORD      dwParam,
          BYTE       *pbData,
          DWORD      *pdwDataLen,
          DWORD      dwFlags
        );
        """
        hHash, dwParam, pbData, pdwDataLen, dwFlags = argv

        param_enums = {1: "HP_ALGID", 2: "HP_HASHVAL", 4: "HP_HASHSIZE", 5: "HP_HMAC_INFO"}

        if dwParam in param_enums.keys():
            argv[1] = param_enums[dwParam]

        return 1

    @apihook("CryptDestroyHash", argc=1)
    def CryptDestroyHash(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CryptDestroyHash(
          HCRYPTHASH hHash
        );
        """
        return 1

    @apihook("CryptDeriveKey", argc=5)
    def CryptDeriveKey(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CryptDeriveKey(
          HCRYPTPROV hProv,
          ALG_ID     Algid,
          HCRYPTHASH hBaseData,
          DWORD      dwFlags,
          HCRYPTKEY  *phKey
        );
        """

        hProv, Algid, hBaseData, dwFlags, phKey = argv

        # Only RC4 supported right now
        if Algid != 0x6801:
            return 0

        hnd = self.hash_objects.get(hBaseData, None)

        if hnd is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        # CryptDeriveKey zeroes out the last 11 bytes of the hash,
        # so we gotta do the same before it is written to the
        # phKey structure
        fixed_digest = hnd.digest()[:5] + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        ptrsz = emu.get_ptr_size()

        hKey = self.win.HCRYPTKEY(ptrsz)
        hKey.Algid = Algid
        hKey.keylen = hnd.digest_size
        hKey.keyp = self.mem_alloc(hKey.keylen)

        hKeyp = self.mem_alloc(hKey.sizeof())

        self.mem_write(hKey.keyp, fixed_digest)

        self.mem_write(hKeyp, hKey.get_bytes())
        self.mem_write(phKey, hKeyp.to_bytes(ptrsz, "little"))

        return 1

    @apihook("CryptDecrypt", argc=6)
    def CryptDecrypt(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CryptDecrypt(
          HCRYPTKEY  hKey,
          HCRYPTHASH hHash,
          BOOL       Final,
          DWORD      dwFlags,
          BYTE       *pbData,
          DWORD      *pdwDataLen
        );
        """

        hKey, hHash, Final, dwFlags, pbData, pdwDataLen = argv

        # Hashing not supported
        if hHash:
            return 0

        ptrsz = emu.get_ptr_size()

        hKey = self.mem_cast(self.win.HCRYPTKEY(ptrsz), hKey)

        # Only RC4 supported right now
        if hKey.Algid != 0x6801:
            return 0

        encdatalen_b = self.mem_read(pdwDataLen, 4)
        encdatalen = int.from_bytes(encdatalen_b, "little")

        encdata = self.mem_read(pbData, encdatalen)

        key = self.mem_read(hKey.keyp, hKey.keylen)

        if self.rc4 is None:
            self.rc4 = ARC4.new(key)

        dec = self.rc4.decrypt(encdata)
        declen = len(dec)

        self.mem_write(pbData, dec)
        self.mem_write(pdwDataLen, int.to_bytes(declen, 4, "little"))

        if Final:
            self.rc4 = None

        return 1

    @apihook("RegGetValue", argc=7, conv=_arch.CALL_CONV_STDCALL)
    def RegGetValue(self, emu, argv, ctx: api.ApiContext = None):
        """
        LSTATUS RegGetValueW(
            HKEY    hkey,
            LPCWSTR lpSubKey,
            LPCWSTR lpValue,
            DWORD   dwFlags,
            LPDWORD pdwType,
            PVOID   pvData,
            LPDWORD pcbData
            );
        """
        ctx, cw = self.prepare_ctx(ctx)

        hKey, lpSubKey, lpValue, dwFlags, lpType, lpData, lpcbData = argv
        rv = windefs.ERROR_SUCCESS

        if lpSubKey:
            lpSubKey = self.read_mem_string(lpSubKey, cw)
            argv[1] = lpSubKey

        if lpValue:
            lpValue = self.read_mem_string(lpValue, cw)
            argv[2] = lpValue

        type_name = regdefs.get_value_type(lpType)
        if type_name:
            argv[4] = type_name

        length = 0
        if lpcbData:
            length = self.mem_read(lpcbData, 4)
            length = int.from_bytes(length, "little")

        key = self.reg_get_key(hKey)
        if key:
            val = key.get_value(lpValue)
            if val:
                output = b""

                if lpcbData:
                    self.mem_write(lpcbData, len(output).to_bytes(4, "little"))

                if len(output) > length:
                    rv = windefs.ERROR_INSUFFICIENT_BUFFER
                else:
                    self.mem_write(lpData, output)

            # For now, return an empty buffer
            else:
                output = b"\x00" * length
                self.mem_write(lpData, output)
                rv = windefs.ERROR_SUCCESS

            kp = key.get_path()
            self.record_registry_access_event(
                kp,
                REG_READ,
                value_name=lpValue,
                data=output,
                size=length,
                buffer=lpData,
            )

        return rv

    @apihook("EnumServicesStatus", argc=8, conv=_arch.CALL_CONV_STDCALL)
    def EnumServicesStatus(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL EnumServicesStatusA(
          SC_HANDLE              hSCManager,
          DWORD                  dwServiceType,
          DWORD                  dwServiceState,
          LPENUM_SERVICE_STATUSA lpServices,
          DWORD                  cbBufSize,
          LPDWORD                pcbBytesNeeded,
          LPDWORD                lpServicesReturned,
          LPDWORD                lpResumeHandle
        );
        """
        (
            hSCManager,
            dwServiceType,
            dwServiceState,
            lpServices,
            cbBufSize,
            pcbBytesNeeded,
            lpServicesReturned,
            lpResumeHandle,
        ) = argv

        service_type_str = adv32.get_define_int(dwServiceType, "SERVICE_")
        if service_type_str:
            argv[1] = service_type_str

        service_state_str = adv32.get_define_int(dwServiceState, "SERVICE_")
        if service_state_str:
            argv[2] = service_state_str

        # TODO: Populate service status output
        return 1

    @apihook("OpenService", argc=3, conv=_arch.CALL_CONV_STDCALL)
    def OpenService(self, emu, argv, ctx: api.ApiContext = None):
        """
        SC_HANDLE OpenServiceA(
          SC_HANDLE hSCManager,
          LPCSTR    lpServiceName,
          DWORD     dwDesiredAccess
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        hSCManager, lpServiceName, dwDesiredAccess = argv
        svcname = self.read_mem_string(lpServiceName, cw)
        argv[1] = svcname
        return self.get_handle()

    @apihook("DeleteService", argc=1, conv=_arch.CALL_CONV_STDCALL)
    def DeleteService(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL DeleteService(
          SC_HANDLE hService
        );
        """
        return 1
