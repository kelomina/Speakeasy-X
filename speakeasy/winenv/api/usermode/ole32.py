# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import logging
import struct
import uuid

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.com as com
import speakeasy.winenv.defs.windows.windows as windefs

from .. import api

logger = logging.getLogger(__name__)


class Ole32(api.ApiHandler):
    name = "ole32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)
        self.netman = emu.get_network_manager()
        self.names = {}

        self._register_ole32_batch()

    def _register_ole32_batch(self):
        """Register real handlers for stream/GUID/COM helpers."""
        sd = _arch.CALL_CONV_STDCALL
        ptr = self.get_ptr_size()

        def reg(name, func, argc):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, sd, None)

        def CoInitializeEx(self, emu, argv, ctx=None):
            return 0  # S_OK

        reg("CoInitializeEx", CoInitializeEx, 2)

        def CoUninitialize(self, emu, argv, ctx=None):
            return

        reg("CoUninitialize", CoUninitialize, 0)

        def CoCreateInstanceEx(self, emu, argv, ctx=None):
            clsid, outer, context, server, count, results = argv
            return 0x80040154  # REGDB_E_CLASSNOTREG

        reg("CoCreateInstanceEx", CoCreateInstanceEx, 6)

        def CoGetClassObject(self, emu, argv, ctx=None):
            clsid, context, reserved, riid, out = argv
            if out:
                self.mem_write(out, b"\x00" * ptr)
            return 0x80040154  # REGDB_E_CLASSNOTREG

        reg("CoGetClassObject", CoGetClassObject, 5)

        def StringFromGUID(self, emu, argv, ctx=None):
            rguid, out = argv
            return self.StringFromIID(emu, argv, ctx)

        reg("StringFromGUID", StringFromGUID, 2)

        def CoFileTimeNow(self, emu, argv, ctx=None):
            out = argv[0]
            if not out:
                return 0x80070057
            import datetime as _dt

            ts = 116444736000000000 + int(_dt.datetime.now(_dt.timezone.utc).timestamp()) * 10000000
            self.mem_write(out, struct.pack("<Q", ts))
            return 0

        reg("CoFileTimeNow", CoFileTimeNow, 1)

        def CoDosDateTimeToFileTime(self, emu, argv, ctx=None):
            dosdate, dostime, out = argv
            if not out:
                return False
            self.mem_write(out, struct.pack("<Q", 116444736000000000))
            return True

        reg("CoDosDateTimeToFileTime", CoDosDateTimeToFileTime, 3)

        def CoFileTimeToDosDateTime(self, emu, argv, ctx=None):
            ft, dosdate, dostime = argv
            if not ft:
                return False
            if dosdate:
                self.mem_write(dosdate, struct.pack("<H", 0x2100))
            if dostime:
                self.mem_write(dostime, struct.pack("<H", 0))
            return True

        reg("CoFileTimeToDosDateTime", CoFileTimeToDosDateTime, 3)

        def CoRegisterClassObject(self, emu, argv, ctx=None):
            clsid, unk, context, flags, out = argv
            if out:
                self.mem_write(out, struct.pack("<I", 0x1234))
            return 0

        reg("CoRegisterClassObject", CoRegisterClassObject, 5)

        def CoRevokeClassObject(self, emu, argv, ctx=None):
            return 0

        reg("CoRevokeClassObject", CoRevokeClassObject, 1)

        def CoLockObjectExternal(self, emu, argv, ctx=None):
            return 0

        reg("CoLockObjectExternal", CoLockObjectExternal, 3)

        def CoGetObjectContext(self, emu, argv, ctx=None):
            riid, out = argv
            if out:
                self.mem_write(out, b"\x00" * ptr)
            return 0x80004002  # E_NOINTERFACE

        reg("CoGetObjectContext", CoGetObjectContext, 2)

        def CoCreateFreeThreadedMarshaler(self, emu, argv, ctx=None):
            outer, out = argv
            if out:
                self.mem_write(out, b"\x00" * ptr)
            return 0x80004002

        reg("CoCreateFreeThreadedMarshaler", CoCreateFreeThreadedMarshaler, 2)

        def CoDisconnectObject(self, emu, argv, ctx=None):
            return 0

        reg("CoDisconnectObject", CoDisconnectObject, 2)

        def CoFreeUnusedLibraries(self, emu, argv, ctx=None):
            return

        reg("CoFreeUnusedLibraries", CoFreeUnusedLibraries, 0)
        reg("CoFreeUnusedLibrariesEx", CoFreeUnusedLibraries, 2)

        def CoFreeLibrary(self, emu, argv, ctx=None):
            return

        reg("CoFreeLibrary", CoFreeLibrary, 1)

        def CoLoadLibrary(self, emu, argv, ctx=None):
            return 0x7000

        reg("CoLoadLibrary", CoLoadLibrary, 2)

        # ---- streams / structured storage ----
        self.streams = {}

        def CreateStreamOnHGlobal(self, emu, argv, ctx=None):
            hglobal, delete, out = argv
            if not out:
                return 0x80070057
            buf = self.mem_alloc(0x1000, tag="api.ole32.stream")
            self.streams[buf] = 0
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return 0

        reg("CreateStreamOnHGlobal", CreateStreamOnHGlobal, 3)

        def GetHGlobalFromStream(self, emu, argv, ctx=None):
            stream, out = argv
            if not out:
                return 0x80070057
            self.mem_write(out, stream.to_bytes(ptr, "little"))
            return 0

        reg("GetHGlobalFromStream", GetHGlobalFromStream, 2)

        def ReadClassStm(self, emu, argv, ctx=None):
            stream, clsid = argv
            if not clsid:
                return 0x80070057
            self.mem_write(clsid, b"\x00" * 16)
            return 0

        reg("ReadClassStm", ReadClassStm, 2)

        def WriteClassStm(self, emu, argv, ctx=None):
            stream, clsid = argv
            return 0

        reg("WriteClassStm", WriteClassStm, 2)

        def ReadClassStg(self, emu, argv, ctx=None):
            storage, clsid = argv
            if not clsid:
                return 0x80070057
            self.mem_write(clsid, b"\x00" * 16)
            return 0

        reg("ReadClassStg", ReadClassStg, 2)

        def WriteClassStg(self, emu, argv, ctx=None):
            storage, clsid = argv
            return 0

        reg("WriteClassStg", WriteClassStg, 2)

        def StgCreateDocfile(self, emu, argv, ctx=None):
            name, mode, reserved, out = argv
            if not out:
                return 0x80070057
            buf = self.mem_alloc(0x1000, tag="api.ole32.storage")
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return 0

        reg("StgCreateDocfile", StgCreateDocfile, 4)
        reg("StgCreateStorageEx", StgCreateDocfile, 8)
        reg("StgCreateDocfileOnILockBytes", StgCreateDocfile, 5)

        def StgOpenStorage(self, emu, argv, ctx=None):
            name, mode, snb, reserved, out = argv
            if not out:
                return 0x80070057
            if not name:
                return 0x80030001  # STG_E_INVALIDNAME
            buf = self.mem_alloc(0x1000, tag="api.ole32.storage")
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return 0

        reg("StgOpenStorage", StgOpenStorage, 5)
        reg("StgOpenStorageEx", StgOpenStorage, 8)
        reg("StgOpenStorageOnILockBytes", StgOpenStorage, 6)
        reg("StgOpenStorageOnHandle", StgOpenStorage, 6)

        def StgIsStorageFile(self, emu, argv, ctx=None):
            name = argv[0]
            if not name:
                return 0x80030001
            return 0x80030000  # STG_E_INVALIDFLAG

        reg("StgIsStorageFile", StgIsStorageFile, 1)
        reg("StgIsStorageILockBytes", StgIsStorageFile, 1)

        def StgSetTimes(self, emu, argv, ctx=None):
            return 0

        reg("StgSetTimes", StgSetTimes, 4)

        def OleRun(self, emu, argv, ctx=None):
            return 0

        reg("OleRun", OleRun, 1)

        def OleInitialize(self, emu, argv, ctx=None):
            return 0

        reg("OleInitialize", OleInitialize, 1)

        def OleUninitialize(self, emu, argv, ctx=None):
            return

        reg("OleUninitialize", OleUninitialize, 0)

        def OleFlushClipboard(self, emu, argv, ctx=None):
            return 0

        reg("OleFlushClipboard", OleFlushClipboard, 0)

        def OleIsCurrentClipboard(self, emu, argv, ctx=None):
            return 0

        reg("OleIsCurrentClipboard", OleIsCurrentClipboard, 1)

        def DoDragDrop(self, emu, argv, ctx=None):
            return 0x80040100  # DRAGDROP_S_CANCEL

        reg("DoDragDrop", DoDragDrop, 5)

        def ReleaseStgMedium(self, emu, argv, ctx=None):
            return

        reg("ReleaseStgMedium", ReleaseStgMedium, 1)

        def CoGetTreatAsClass(self, emu, argv, ctx=None):
            clsid, out = argv
            if out:
                self.mem_write(out, self.mem_read(clsid, 16))
            return 0

        reg("CoGetTreatAsClass", CoGetTreatAsClass, 2)

        def CoTreatAsClass(self, emu, argv, ctx=None):
            return 0

        reg("CoTreatAsClass", CoTreatAsClass, 2)

        def CoAddRefServerProcess(self, emu, argv, ctx=None):
            return 1

        reg("CoAddRefServerProcess", CoAddRefServerProcess, 0)

        def CoReleaseServerProcess(self, emu, argv, ctx=None):
            return 1

        reg("CoReleaseServerProcess", CoReleaseServerProcess, 0)

        def CoRegisterMessageFilter(self, emu, argv, ctx=None):
            new, old = argv
            if old:
                self.mem_write(old, b"\x00" * ptr)
            return 0

        reg("CoRegisterMessageFilter", CoRegisterMessageFilter, 2)

        def CoIsOle1Class(self, emu, argv, ctx=None):
            return False

        reg("CoIsOle1Class", CoIsOle1Class, 1)

        def DllGetClassObject(self, emu, argv, ctx=None):
            return 0x80004002  # E_NOINTERFACE

        reg("DllGetClassObject", DllGetClassObject, 3)

        def DllRegisterServer(self, emu, argv, ctx=None):
            return 0

        reg("DllRegisterServer", DllRegisterServer, 0)

    def _guid_to_uuid(self, guid_ptr):
        if not guid_ptr:
            return None
        data = self.mem_read(guid_ptr, 16)
        d1, d2, d3 = struct.unpack("<IHH", data[:8])
        d4 = data[8:16]
        return uuid.UUID(f"{d1:08x}-{d2:04x}-{d3:04x}-{d4.hex()}")

    def _write_uuid(self, guid_ptr, guid):
        if not guid_ptr:
            return
        data = struct.pack("<IHH", guid.time_low, guid.time_mid, guid.time_hi_version) + guid.bytes[8:16]
        self.mem_write(guid_ptr, data)

    @apihook("CoCreateGuid", argc=1)
    def CoCreateGuid(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoCreateGuid(
            GUID *pguid
        );
        """
        pguid = argv[0]
        if not pguid:
            return 0x80070057  # E_INVALIDARG
        self._write_uuid(pguid, uuid.uuid4())
        return 0

    @apihook("StringFromGUID2", argc=3)
    def StringFromGUID2(self, emu, argv, ctx: api.ApiContext = None):
        """
        int StringFromGUID2(
            REFGUID rguid,
            LPOLESTR lpsz,
            int      cchMax
        );
        """
        rguid, out, cch = argv
        guid = self._guid_to_uuid(rguid)
        if not guid or not out:
            return 0
        s = "{%s}" % str(guid).upper()
        if len(s) + 1 > cch:
            return 0
        self.write_wide_string(s, out)
        return len(s)

    @apihook("StringFromIID", argc=2)
    def StringFromIID(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT StringFromIID(
            REFIID rguid,
            LPOLESTR *lplpsz
        );
        """
        rguid, out = argv
        guid = self._guid_to_uuid(rguid)
        if not guid or not out:
            return 0x80070057
        s = "{%s}" % str(guid).upper()
        ws = s.encode("utf-16le") + b"\x00\x00"
        buf = self.mem_alloc(len(ws), tag="api.ole32.guidstr")
        self.mem_write(buf, ws)
        self.mem_write(out, buf.to_bytes(self.get_ptr_size(), "little"))
        return 0

    @apihook("StringFromCLSID", argc=2)
    def StringFromCLSID(self, emu, argv, ctx: api.ApiContext = None):
        return self.StringFromIID(emu, argv, ctx)

    @apihook("CLSIDFromString", argc=2)
    def CLSIDFromString(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CLSIDFromString(
            LPCOLESTR lpsz,
            LPCLSID   pclsid
        );
        """
        s, out = argv
        if not s or not out:
            return 0x80070057
        txt = self.read_wide_string(s).strip("{}").strip()
        try:
            guid = uuid.UUID(txt)
        except Exception:
            return 0x80040111  # CLASS_E_CLASSNOTAVAILABLE
        self._write_uuid(out, guid)
        return 0

    @apihook("IIDFromString", argc=2)
    def IIDFromString(self, emu, argv, ctx: api.ApiContext = None):
        return self.CLSIDFromString(emu, argv, ctx)

    @apihook("IsEqualGUID", argc=2)
    def IsEqualGUID(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL IsEqualGUID(
            REFGUID rguid1,
            REFGUID rguid2
        );
        """
        a, b = argv
        if not a or not b:
            return False
        return self.mem_read(a, 16) == self.mem_read(b, 16)

    @apihook("CoTaskMemAlloc", argc=1)
    def CoTaskMemAlloc(self, emu, argv, ctx: api.ApiContext = None):
        """void *CoTaskMemAlloc(SIZE_T cb);"""
        size = argv[0]
        if not size:
            return 0
        return self.mem_alloc(size, tag="api.ole32.taskmem")

    @apihook("CoTaskMemFree", argc=1)
    def CoTaskMemFree(self, emu, argv, ctx: api.ApiContext = None):
        """void CoTaskMemFree(LPVOID pv);"""
        pv = argv[0]
        if pv:
            try:
                self.mem_free(pv)
            except Exception:
                pass

    @apihook("CoTaskMemRealloc", argc=2)
    def CoTaskMemRealloc(self, emu, argv, ctx: api.ApiContext = None):
        """LPVOID CoTaskMemRealloc(LPVOID pv, SIZE_T cb);"""
        pv, size = argv
        if not pv:
            return self.CoTaskMemAlloc(emu, [size], ctx)
        new = self.mem_alloc(size, tag="api.ole32.taskmem")
        try:
            self.mem_write(new, self.mem_read(pv, min(size, 0x1000)))
            self.mem_free(pv)
        except Exception:
            pass
        return new

    @apihook("CoBuildVersion", argc=0)
    def CoBuildVersion(self, emu, argv, ctx: api.ApiContext = None):
        """DWORD CoBuildVersion();"""
        return 0x00000000  # rComDllMajor << 16 | rComDllMinor

    @apihook("CoGetMalloc", argc=2)
    def CoGetMalloc(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoGetMalloc(
            DWORD    dwMemContext,
            LPMALLOC *ppMalloc
        );
        """
        ctx, out = argv
        if not out:
            return 0x80070057
        # No IMalloc implementation; report E_NOINTERFACE
        return 0x80004002

    @apihook("ProgIDFromCLSID", argc=2)
    def ProgIDFromCLSID(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT ProgIDFromCLSID(
            REFCLSID clsid,
            LPOLESTR *lplpszProgID
        );
        """
        clsid, out = argv
        guid = self._guid_to_uuid(clsid)
        if not guid or not out:
            return 0x80070057
        reg_path = f"HKEY_CLASSES_ROOT\\CLSID\\{{{guid}}}\\ProgID"
        key = self.reg_open_key(reg_path)
        if not key:
            return 0x80040111
        prog_id = key.get_value("")
        if not prog_id:
            return 0x80040111
        text = prog_id.get_data()
        ws = str(text).encode("utf-16le") + b"\x00\x00"
        buf = self.mem_alloc(len(ws), tag="api.ole32.progid")
        self.mem_write(buf, ws)
        self.mem_write(out, buf.to_bytes(self.get_ptr_size(), "little"))
        return 0

    @apihook("CLSIDFromProgID", argc=2)
    def CLSIDFromProgID(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CLSIDFromProgID(
            LPCOLESTR lpszProgID,
            LPCLSID   lpclsid
        );
        """
        progid, out = argv
        if not progid or not out:
            return 0x80070057
        txt = self.read_wide_string(progid)
        reg_path = f"HKEY_CLASSES_ROOT\\{txt}\\CLSID"
        key = self.reg_open_key(reg_path)
        if not key:
            return 0x80040111
        val = key.get_value("")
        if not val:
            return 0x80040111
        guid_str = val.get_data()
        try:
            guid = uuid.UUID(str(guid_str).strip("{}"))
        except Exception:
            return 0x80040111
        self._write_uuid(out, guid)
        return 0

    @apihook("CoIsOle1Class", argc=1)
    def CoIsOle1Class(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL CoIsOle1Class(REFCLSID rclsid);"""
        return False

    @apihook("CoInitializeSecurity", argc=8)
    def CoInitializeSecurity(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoInitializeSecurity(
            PSECURITY_DESCRIPTOR pVoid,
            LONG                 cAuthSvc,
            SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
            void                *pReserved1,
            DWORD                dwAuthnLevel,
            DWORD                dwImpLevel,
            void                *pAuthList,
            DWORD                dwCapabilities
        );
        """
        return 0

    @apihook("CoSetProxyBlanket", argc=9)
    def CoSetProxyBlanket(self, emu, argv, ctx: api.ApiContext = None):
        return 0

    @apihook("CoQueryProxyBlanket", argc=8)
    def CoQueryProxyBlanket(self, emu, argv, ctx: api.ApiContext = None):
        return 0x80004002  # E_NOINTERFACE

    @apihook("CoImpersonateClient", argc=0)
    def CoImpersonateClient(self, emu, argv, ctx: api.ApiContext = None):
        return 0

    @apihook("CoRevertToSelf", argc=0)
    def CoRevertToSelf(self, emu, argv, ctx: api.ApiContext = None):
        return 0

    @apihook("CoWaitForMultipleHandles", argc=5)
    def CoWaitForMultipleHandles(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoWaitForMultipleHandles(
            DWORD   dwFlags,
            DWORD   dwTimeout,
            ULONG   cHandles,
            LPHANDLE pHandles,
            LPDWORD lpdwindex
        );
        """
        flags, timeout, handles, phandles, index = argv
        if index:
            self.mem_write(index, b"\x00\x00\x00\x00")
        return 0x00000102  # RPC_S_CALLPENDING

    @apihook("CoDisableCallCancellation", argc=0)
    def CoDisableCallCancellation(self, emu, argv, ctx: api.ApiContext = None):
        return 0

    @apihook("CoEnableCallCancellation", argc=0)
    def CoEnableCallCancellation(self, emu, argv, ctx: api.ApiContext = None):
        return 0

    @apihook("OleInitialize", argc=1)
    def OleInitialize(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT OleInitialize(
            IN LPVOID pvReserved
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook("CoInitialize", argc=1)
    def CoInitialize(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoInitialize(
          LPVOID pvReserved
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook("CoInitializeEx", argc=2)
    def CoInitializeEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoInitializeEx(
          LPVOID pvReserved,
          DWORD  dwCoInit
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook("CoUninitialize", argc=0)
    def CoUninitialize(self, emu, argv, ctx: api.ApiContext = None):
        """
        void CoUninitialize();
        """

    @apihook("CoInitializeSecurity", argc=9)
    def CoInitializeSecurity(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoInitializeSecurity(
          PSECURITY_DESCRIPTOR        pSecDesc,
          LONG                        cAuthSvc,
          SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
          void                        *pReserved1,
          DWORD                       dwAuthnLevel,
          DWORD                       dwImpLevel,
          void                        *pAuthList,
          DWORD                       dwCapabilities,
          void                        *pReserved3
        );
        """

        rv = windefs.S_OK

        authn_level = com.get_define_int(argv[4])
        if authn_level:
            argv[4] = authn_level

        imp_level = com.get_define_int(argv[5])
        if imp_level:
            argv[5] = imp_level

        return rv

    @apihook("CoCreateInstance", argc=5)
    def CoCreateInstance(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoCreateInstance(
          REFCLSID  rclsid,
          LPUNKNOWN pUnkOuter,
          DWORD     dwClsContext,
          REFIID    riid,
          LPVOID    *ppv
        );
        """
        rclsid, pUnkOuter, dwClsContext, riid, ppv = argv
        rv = windefs.S_OK

        clsid_bytes = self.mem_read(rclsid, self.sizeof(windefs.GUID()))
        clsid_str = com.convert_guid_bytes_to_str(clsid_bytes)
        clsid_name = com.get_clsid(clsid_str)
        if clsid_name:
            argv[0] = clsid_name
            riid_bytes = self.mem_read(riid, self.sizeof(windefs.GUID()))
            riid_str = com.convert_guid_bytes_to_str(riid_bytes)
            iid_name = com.get_iid(riid_str)
            if iid_name:
                argv[3] = iid_name
                if ppv:
                    ci = emu.com.get_interface(emu, emu.get_ptr_size(), iid_name.replace("IID_", ""))
                    pv = self.mem_alloc(emu.get_ptr_size(), tag=f"emu.COM.pv_{iid_name}")
                    self.mem_write(pv, ci.address.to_bytes(emu.get_ptr_size(), "little"))
                    self.mem_write(ppv, pv.to_bytes(emu.get_ptr_size(), "little"))
            else:
                logger.info("Unsupported COM IID %s", riid)
        else:
            logger.info("Unsupported COM CLSID %s", clsid_str)

        return rv

    @apihook("CoSetProxyBlanket", argc=8)
    def CoSetProxyBlanket(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoSetProxyBlanket(
            IUnknown                 *pProxy,
            DWORD                    dwAuthnSvc,
            DWORD                    dwAuthzSvc,
            OLECHAR                  *pServerPrincName,
            DWORD                    dwAuthnLevel,
            DWORD                    dwImpLevel,
            RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
            DWORD                    dwCapabilities
        );
        """
        return 1

    @apihook("StringFromCLSID", argc=2)
    def StringFromCLSID(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT StringFromCLSID(
        REFCLSID rclsid,
        LPOLESTR *lplpsz
        );
        """

        rclsid, lplpsz = argv
        rv = windefs.S_OK

        guid = self.mem_read(rclsid, self.sizeof(windefs.GUID()))
        u = com.convert_guid_bytes_to_str(guid)
        argv[1] = u
        u = (u + "\x00").encode("utf-16le")

        ptr = self.mem_alloc(len(u), tag="api.StringFromCLSID")

        if lplpsz:
            self.mem_write(lplpsz, ptr.to_bytes(emu.get_ptr_size(), "little"))

        return rv

    @apihook("CoCreateGuid", argc=1)
    def CoCreateGuid(self, emu, argv, ctx: api.ApiContext = None):
        pguid = argv[0]
        guid_bytes = b"\xde\xad\xc0\xde\xbe\xef\xca\xfe\xba\xbe\x01\x23\x45\x67\x89\xab"
        if pguid:
            try:
                self.emu.mem_write(pguid, guid_bytes)
            except Exception:
                self.emu.mem_map(pguid & ~0xFFF, 0x1000)
                self.emu.mem_write(pguid, guid_bytes)
        return 0
