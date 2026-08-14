# Copyright (C) 2026 Speakeasy-X

import struct

import speakeasy.winenv.arch as _arch

from .. import api


class Shcore(api.ApiHandler):
    """
    Implements exported functions from shcore.dll.
    """

    name = "shcore"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)

    @apihook("SHAnsiToUnicode", argc=3)
    def SHAnsiToUnicode(self, emu, argv, ctx: api.ApiContext = None):
        """
        int SHAnsiToUnicode(
            LPCSTR  pszSrc,
            LPWSTR  pwszDst,
            int     cchBuf
        );
        """
        src, dst, size = argv
        if not src:
            return 0
        s = self.read_string(src)
        if not dst or size <= 0:
            return 0
        self.write_wide_string(s[: max(size - 1, 0)], dst)
        return min(len(s), max(size - 1, 0))

    @apihook("SHUnicodeToAnsi", argc=3)
    def SHUnicodeToAnsi(self, emu, argv, ctx: api.ApiContext = None):
        """
        int SHUnicodeToAnsi(
            LPCWSTR pwszSrc,
            LPSTR   pszDst,
            int     cchBuf
        );
        """
        src, dst, size = argv
        if not src:
            return 0
        s = self.read_wide_string(src)
        if not dst or size <= 0:
            return 0
        self.write_string(s[: max(size - 1, 0)], dst)
        return min(len(s), max(size - 1, 0))

    @apihook("GetDpiForMonitor", argc=3)
    def GetDpiForMonitor(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT GetDpiForMonitor(
            HMONITOR hmonitor,
            MONITOR_DPI_TYPE dpiType,
            UINT *dpiX,
            UINT *dpiY
        );
        """
        hmonitor, dpi_type, dpi_x, dpi_y = argv
        if dpi_x:
            self.mem_write(dpi_x, b"\x60\x00\x00\x00")  # 96
        if dpi_y:
            self.mem_write(dpi_y, b"\x60\x00\x00\x00")  # 96
        return 0

    @apihook("GetProcessDpiAwareness", argc=2)
    def GetProcessDpiAwareness(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT GetProcessDpiAwareness(
            HANDLE hprocess,
            PROCESS_DPI_AWARENESS *value
        );
        """
        hprocess, out = argv
        if not out:
            return 0x80070057  # E_INVALIDARG
        self.mem_write(out, b"\x02\x00\x00\x00")  # PROCESS_PER_MONITOR_DPI_AWARE
        return 0

    @apihook("GetScaleFactorForDevice", argc=1)
    def GetScaleFactorForDevice(self, emu, argv, ctx: api.ApiContext = None):
        """DEVICE_SCALE_FACTOR GetScaleFactorForDevice(DEVICE_TYPE deviceType);"""
        return 100  # DEVICE_SCALE_FACTOR_INVALID

    @apihook("GetScaleFactorForMonitor", argc=2)
    def GetScaleFactorForMonitor(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT GetScaleFactorForMonitor(
            HMONITOR hMon,
            DEVICE_SCALE_FACTOR *pValue
        );
        """
        hmon, out = argv
        if not out:
            return 0x80070057
        self.mem_write(out, b"\x64\x00\x00\x00")  # 100
        return 0

    @apihook("GetDpiForShellUIComponent", argc=1)
    def GetDpiForShellUIComponent(self, emu, argv, ctx: api.ApiContext = None):
        """UINT GetDpiForShellUIComponent(SHELL_UI_COMPONENT component);"""
        return 96

    @apihook("GetProcessReference", argc=1)
    def GetProcessReference(self, emu, argv, ctx: api.ApiContext = None):
        """ULONG_PTR GetProcessReference(HANDLE hProcess);"""
        return 0

    @apihook("GetFeatureEnabledState", argc=2)
    def GetFeatureEnabledState(self, emu, argv, ctx: api.ApiContext = None):
        """FEATURE_ENABLED_STATE GetFeatureEnabledState(FEATURE_ENABLED_STATE featureId, UINT64 changeStamp);"""
        return 0  # FEATURE_ENABLED_STATE_DEFAULT

    @apihook("IsOS", argc=1)
    def IsOS(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL IsOS(OS_DEPRECATED_FUNCTION dwOS);"""
        return True

    @apihook("DllGetClassObject", argc=3)
    def DllGetClassObject(self, emu, argv, ctx: api.ApiContext = None):
        return 0x80004002  # E_NOINTERFACE

    @apihook("DllCanUnloadNow", argc=0)
    def DllCanUnloadNow(self, emu, argv, ctx: api.ApiContext = None):
        return 0  # S_OK

    @apihook("CommandLineToArgvW", argc=2)
    def CommandLineToArgvW(self, emu, argv, ctx: api.ApiContext = None):
        """LPWSTR *CommandLineToArgvW(LPCWSTR lpCmdLine, int *pNumArgs);"""
        import shlex

        cmdline, num_out = argv
        if not cmdline or not num_out:
            return 0
        cmd = self.read_wide_string(cmdline)
        parts = shlex.split(cmd)
        argc = len(parts)
        self.mem_write(num_out, argc.to_bytes(4, "little"))
        ptr = self.get_ptr_size()
        arr = self.mem_alloc((argc + 1) * ptr, tag="api.shcore.argv")
        offset = arr + (argc + 1) * ptr
        for i, part in enumerate(parts):
            ws = part.encode("utf-16le") + b"\x00\x00"
            self.mem_write(offset, ws)
            self.mem_write(arr + i * ptr, offset.to_bytes(ptr, "little"))
            offset += len(ws)
        self.mem_write(arr + argc * ptr, b"\x00" * ptr)
        return arr
