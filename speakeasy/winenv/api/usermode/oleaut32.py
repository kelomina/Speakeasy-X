# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import datetime
import struct

import speakeasy.winenv.arch as _arch

from .. import api


class OleAut32(api.ApiHandler):
    name = "oleaut32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)
        super().__get_hook_attrs__(self)

        self._register_oleaut32_batch()

    def _register_oleaut32_batch(self):
        """Register real handlers for VARIANT arithmetic/conversions and time."""
        sd = _arch.CALL_CONV_STDCALL
        ptr = self.get_ptr_size()

        def reg(name, func, argc):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, sd, None)

        VT_EMPTY, VT_NULL, VT_I2, VT_I4, VT_R4, VT_R8, VT_CY, VT_DATE, VT_BSTR, VT_ERROR = (
            0, 1, 2, 3, 4, 5, 6, 7, 8, 10,
        )
        VT_BOOL = 11
        VT_DECIMAL = 14
        VT_UI1 = 17
        VT_I1 = 16
        VT_UI2 = 18
        VT_UI4 = 19
        VT_I8 = 20
        VT_UI8 = 21

        def _var_read(pvarg):
            """Read a VARIANT as (vt, value)."""
            if not pvarg:
                return (VT_EMPTY, 0)
            data = self.mem_read(pvarg, 0x18)
            vt = int.from_bytes(data[:2], "little")
            if vt == VT_I2:
                return (vt, struct.unpack("<h", data[8:10])[0])
            if vt == VT_I4:
                return (vt, struct.unpack("<i", data[8:12])[0])
            if vt == VT_UI1:
                return (vt, data[8])
            if vt == VT_I1:
                return (vt, struct.unpack("<b", data[8:9])[0])
            if vt == VT_UI2:
                return (vt, struct.unpack("<H", data[8:10])[0])
            if vt == VT_UI4:
                return (vt, struct.unpack("<I", data[8:12])[0])
            if vt == VT_I8:
                return (vt, struct.unpack("<q", data[8:16])[0])
            if vt == VT_UI8:
                return (vt, struct.unpack("<Q", data[8:16])[0])
            if vt == VT_R4:
                return (vt, struct.unpack("<f", data[8:12])[0])
            if vt == VT_R8:
                return (vt, struct.unpack("<d", data[8:16])[0])
            if vt == VT_CY:
                return (vt, struct.unpack("<q", data[8:16])[0])
            if vt == VT_DATE:
                return (vt, struct.unpack("<d", data[8:16])[0])
            if vt == VT_BOOL:
                return (vt, struct.unpack("<h", data[8:10])[0])
            if vt == VT_BSTR:
                return (vt, int.from_bytes(data[8 : 8 + ptr], "little"))
            return (vt, 0)

        def _var_write(pvarg, vt, value, extra=None):
            if not pvarg:
                return
            data = bytearray(0x18)
            data[0:2] = vt.to_bytes(2, "little")
            if vt == VT_I2:
                data[8:10] = struct.pack("<h", int(value))
            elif vt == VT_I4:
                data[8:12] = struct.pack("<i", int(value))
            elif vt == VT_UI1:
                data[8] = int(value) & 0xFF
            elif vt == VT_UI2:
                data[8:10] = struct.pack("<H", int(value))
            elif vt == VT_UI4:
                data[8:12] = struct.pack("<I", int(value))
            elif vt == VT_I8:
                data[8:16] = struct.pack("<q", int(value))
            elif vt == VT_UI8:
                data[8:16] = struct.pack("<Q", int(value))
            elif vt == VT_R4:
                data[8:12] = struct.pack("<f", float(value))
            elif vt == VT_R8 or vt == VT_DATE:
                data[8:16] = struct.pack("<d", float(value))
            elif vt == VT_CY:
                data[8:16] = struct.pack("<q", int(value))
            elif vt == VT_BOOL:
                data[8:10] = struct.pack("<h", 0xFFFF if value else 0)
            elif vt == VT_BSTR and extra is not None:
                data[8 : 8 + ptr] = extra.to_bytes(ptr, "little")
            self.mem_write(pvarg, bytes(data))

        def _var_to_number(vt, value):
            if vt in (VT_I2, VT_I4, VT_I8, VT_UI1, VT_I1, VT_UI2, VT_UI4, VT_UI8, VT_BOOL):
                return int(value)
            if vt in (VT_R4, VT_R8, VT_DATE):
                return float(value)
            if vt == VT_CY:
                return int(value) / 10000.0
            return None

        def _var_to_i8(vt, value):
            n = _var_to_number(vt, value)
            if n is None:
                return None
            return int(n)

        def VarFromStr(self, emu, argv, ctx=None):
            s, lcid, flags, out = argv
            if not out:
                return 0x80004003
            txt = self.read_wide_string(s) if s else ""
            txt = txt.strip()
            try:
                n = float(txt)
            except Exception:
                return 0x8002000A  # DISP_E_TYPEMISMATCH
            _var_write(out, VT_R8, n)
            return 0

        reg("VarR8FromStr", VarFromStr, 4)
        reg("VarR4FromStr", VarFromStr, 4)
        reg("VarI8FromStr", VarFromStr, 4)
        reg("VarI4FromStr", VarFromStr, 4)
        reg("VarI2FromStr", VarFromStr, 4)
        reg("VarI1FromStr", VarFromStr, 4)
        reg("VarUI1FromStr", VarFromStr, 4)
        reg("VarUI2FromStr", VarFromStr, 4)
        reg("VarUI4FromStr", VarFromStr, 4)
        reg("VarBoolFromStr", VarFromStr, 4)
        reg("VarCyFromStr", VarFromStr, 4)
        reg("VarDecFromStr", VarFromStr, 4)
        reg("VarDateFromStr", VarFromStr, 4)

        def _variant_time_to_epoch(vt):
            """OLE date (days since 1899-12-30) -> unix timestamp."""
            days = int(vt)
            frac = vt - days
            base = datetime.datetime(1899, 12, 30)
            return base + datetime.timedelta(days=days, seconds=frac * 86400)

        def VariantTimeToSystemTime(self, emu, argv, ctx=None):
            vtime, systime = argv
            if not systime:
                return False
            try:
                dt = _variant_time_to_epoch(vtime)
            except Exception:
                return False
            self.mem_write(
                systime,
                struct.pack("<8H", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond // 1000, dt.weekday()),
            )
            return True

        reg("VariantTimeToSystemTime", VariantTimeToSystemTime, 2)

        def SystemTimeToVariantTime(self, emu, argv, ctx=None):
            systime, vtime = argv
            if not systime or not vtime:
                return False
            year, month, day, hour, minute, second, ms, wday = struct.unpack("<8H", self.mem_read(systime, 16))
            try:
                dt = datetime.datetime(year, month, day, hour, minute, second, ms * 1000)
            except Exception:
                return False
            base = datetime.datetime(1899, 12, 30)
            delta = dt - base
            val = delta.days + delta.seconds / 86400.0
            self.mem_write(vtime, struct.pack("<d", val))
            return True

        reg("SystemTimeToVariantTime", SystemTimeToVariantTime, 2)

        def VarDateFromI4(self, emu, argv, ctx=None):
            value, lcid, out = argv
            if not out:
                return 0x80004003
            _var_write(out, VT_DATE, float(value))
            return 0

        reg("VarDateFromI4", VarDateFromI4, 3)
        reg("VarDateFromI8", VarDateFromI4, 3)
        reg("VarDateFromR8", VarDateFromI4, 3)
        reg("VarDateFromR4", VarDateFromI4, 3)

        def VarBstrFromDate(self, emu, argv, ctx=None):
            value, lcid, out = argv
            if not out:
                return 0x80004003
            try:
                dt = _variant_time_to_epoch(value)
                s = dt.strftime("%m/%d/%Y %H:%M:%S")
            except Exception:
                s = "0"
            ws = s.encode("utf-16le")
            bstr_data = self.mem_alloc(len(ws) + 6, tag="api.oleaut32.bstr")
            self.mem_write(bstr_data, struct.pack("<I", len(ws)) + ws + b"\x00\x00")
            self.mem_write(out, (bstr_data + 4).to_bytes(ptr, "little"))
            return 0

        reg("VarBstrFromDate", VarBstrFromDate, 3)

        def _var_binary_op(op):
            def impl(self, emu, argv, ctx=None):
                left, right, out = argv
                if not out:
                    return 0x80004003
                lvt, lval = _var_read(left)
                rvt, rval = _var_read(right)
                ln = _var_to_number(lvt, lval)
                rn = _var_to_number(rvt, rval)
                if ln is None or rn is None:
                    return 0x8002000A
                try:
                    result = op(ln, rn)
                except Exception:
                    return 0x8002000B  # DISP_E_OVERFLOW
                _var_write(out, VT_R8, result)
                return 0

            return impl

        reg("VarAdd", _var_binary_op(lambda a, b: a + b), 3)
        reg("VarSub", _var_binary_op(lambda a, b: a - b), 3)
        reg("VarMul", _var_binary_op(lambda a, b: a * b), 3)
        reg("VarIAdd", _var_binary_op(lambda a, b: a + b), 3)
        reg("VarISub", _var_binary_op(lambda a, b: a - b), 3)
        reg("VarIMul", _var_binary_op(lambda a, b: a * b), 3)

        def VarDiv(self, emu, argv, ctx=None):
            left, right, out = argv
            if not out:
                return 0x80004003
            lvt, lval = _var_read(left)
            rvt, rval = _var_read(right)
            ln = _var_to_number(lvt, lval)
            rn = _var_to_number(rvt, rval)
            if ln is None or rn is None or rn == 0:
                return 0x8002000A
            _var_write(out, VT_R8, ln / rn)
            return 0

        reg("VarDiv", VarDiv, 3)
        reg("VarIDiv", VarDiv, 3)

        def VarMod(self, emu, argv, ctx=None):
            left, right, out = argv
            if not out:
                return 0x80004003
            lvt, lval = _var_read(left)
            rvt, rval = _var_read(right)
            ln = _var_to_i8(lvt, lval)
            rn = _var_to_i8(rvt, rval)
            if ln is None or rn is None or rn == 0:
                return 0x8002000A
            _var_write(out, VT_I8, ln % rn)
            return 0

        reg("VarMod", VarMod, 3)
        reg("VarIMod", VarMod, 3)

        def VarAnd(self, emu, argv, ctx=None):
            left, right, out = argv
            if not out:
                return 0x80004003
            lvt, lval = _var_read(left)
            rvt, rval = _var_read(right)
            ln = _var_to_i8(lvt, lval)
            rn = _var_to_i8(rvt, rval)
            if ln is None or rn is None:
                return 0x8002000A
            _var_write(out, VT_I8, ln & rn)
            return 0

        reg("VarAnd", VarAnd, 3)
        reg("VarOr", VarAnd, 3)
        reg("VarXor", VarAnd, 3)
        reg("VarIAnd", VarAnd, 3)
        reg("VarIOr", VarAnd, 3)
        reg("VarIXor", VarAnd, 3)

        def VarNeg(self, emu, argv, ctx=None):
            left, out = argv
            if not out:
                return 0x80004003
            lvt, lval = _var_read(left)
            ln = _var_to_number(lvt, lval)
            if ln is None:
                return 0x8002000A
            _var_write(out, VT_R8, -ln)
            return 0

        reg("VarNeg", VarNeg, 2)
        reg("VarNot", VarNeg, 2)
        reg("VarINeg", VarNeg, 2)

        def VarAbs(self, emu, argv, ctx=None):
            left, out = argv
            if not out:
                return 0x80004003
            lvt, lval = _var_read(left)
            ln = _var_to_number(lvt, lval)
            if ln is None:
                return 0x8002000A
            _var_write(out, VT_R8, abs(ln))
            return 0

        reg("VarAbs", VarAbs, 2)
        reg("VarIAbs", VarAbs, 2)

        def VarInt(self, emu, argv, ctx=None):
            left, out = argv
            if not out:
                return 0x80004003
            lvt, lval = _var_read(left)
            ln = _var_to_number(lvt, lval)
            if ln is None:
                return 0x8002000A
            _var_write(out, VT_I8, int(ln))
            return 0

        reg("VarInt", VarInt, 2)
        reg("VarFix", VarInt, 2)
        reg("VarIInt", VarInt, 2)

        def VarRound(self, emu, argv, ctx=None):
            left, digits, out = argv
            if not out:
                return 0x80004003
            lvt, lval = _var_read(left)
            ln = _var_to_number(lvt, lval)
            if ln is None:
                return 0x8002000A
            _var_write(out, VT_R8, round(ln, digits))
            return 0

        reg("VarRound", VarRound, 3)
        reg("VarIRound", VarRound, 3)

        def VarCmp(self, emu, argv, ctx=None):
            left, right, lcid, flags = argv
            lvt, lval = _var_read(left)
            rvt, rval = _var_read(right)
            ln = _var_to_number(lvt, lval)
            rn = _var_to_number(rvt, rval)
            if ln is None or rn is None:
                return 0x8002000A
            if ln == rn:
                return 0
            return 1 if ln > rn else -1

        reg("VarCmp", VarCmp, 4)
        reg("VarBstrCmp", VarCmp, 4)
        reg("VarR8Cmp", VarCmp, 4)
        reg("VarI4Cmp", VarCmp, 4)
        reg("VarDateCmp", VarCmp, 4)
        reg("VarCyCmp", VarCmp, 4)
        reg("VarDecCmp", VarCmp, 4)

        # ---- error info store ----
        if not hasattr(self, "error_info"):
            self.error_info = None

        def CreateErrorInfo(self, emu, argv, ctx=None):
            out = argv[0]
            if not out:
                return 0x80004003
            self.mem_write(out, struct.pack("<Q", 0x7000))
            return 0

        reg("CreateErrorInfo", CreateErrorInfo, 1)

        def SetErrorInfo(self, emu, argv, ctx=None):
            reserved, info = argv
            self.error_info = info
            return 0

        reg("SetErrorInfo", SetErrorInfo, 2)

        def GetErrorInfo(self, emu, argv, ctx=None):
            reserved, out = argv
            if not out:
                return 0x80004003
            self.mem_write(out, b"\x00" * ptr)
            return 1  # S_FALSE (no error info)

        reg("GetErrorInfo", GetErrorInfo, 2)

        def SysAllocStringByteLen(self, emu, argv, ctx=None):
            s, size = argv
            if not size:
                return 0
            data = self.mem_read(s, size) if s else b"\x00" * size
            bstr_data = self.mem_alloc(size + 6, tag="api.oleaut32.bstr")
            self.mem_write(bstr_data, struct.pack("<I", size) + data + b"\x00\x00")
            return bstr_data + 4

        reg("SysAllocStringByteLen", SysAllocStringByteLen, 2)

        def OaBuildVersion(self, emu, argv, ctx=None):
            return 0x00020000  # rBuildMajor << 16 | rBuildMinor

        reg("OaBuildVersion", OaBuildVersion, 0)

        def VarWeekdayName(self, emu, argv, ctx=None):
            day, abbreviate, first, out = argv
            if not out:
                return 0x80004003
            names = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
            s = names[int(day) % 7]
            if abbreviate:
                s = s[:3]
            ws = s.encode("utf-16le")
            bstr_data = self.mem_alloc(len(ws) + 6, tag="api.oleaut32.bstr")
            self.mem_write(bstr_data, struct.pack("<I", len(ws)) + ws + b"\x00\x00")
            self.mem_write(out, (bstr_data + 4).to_bytes(ptr, "little"))
            return 0

        reg("VarWeekdayName", VarWeekdayName, 4)

        def VarMonthName(self, emu, argv, ctx=None):
            month, abbreviate, out = argv
            if not out:
                return 0x80004003
            names = ["January", "February", "March", "April", "May", "June",
                     "July", "August", "September", "October", "November", "December"]
            s = names[int(month) % 12]
            if abbreviate:
                s = s[:3]
            ws = s.encode("utf-16le")
            bstr_data = self.mem_alloc(len(ws) + 6, tag="api.oleaut32.bstr")
            self.mem_write(bstr_data, struct.pack("<I", len(ws)) + ws + b"\x00\x00")
            self.mem_write(out, (bstr_data + 4).to_bytes(ptr, "little"))
            return 0

        reg("VarMonthName", VarMonthName, 3)

        def VarFormatDateTime(self, emu, argv, ctx=None):
            vtime, flags, out = argv
            if not out:
                return 0x80004003
            lvt, lval = _var_read(vtime)
            n = _var_to_number(lvt, lval)
            if n is None:
                return 0x8002000A
            try:
                s = _variant_time_to_epoch(n).strftime("%m/%d/%Y %H:%M:%S")
            except Exception:
                s = ""
            ws = s.encode("utf-16le")
            bstr_data = self.mem_alloc(len(ws) + 6, tag="api.oleaut32.bstr")
            self.mem_write(bstr_data, struct.pack("<I", len(ws)) + ws + b"\x00\x00")
            self.mem_write(out, (bstr_data + 4).to_bytes(ptr, "little"))
            return 0

        reg("VarFormatDateTime", VarFormatDateTime, 3)

        def VarFormatNumber(self, emu, argv, ctx=None):
            vnum, digits, include, paren, group, out = argv
            if not out:
                return 0x80004003
            lvt, lval = _var_read(vnum)
            n = _var_to_number(lvt, lval)
            if n is None:
                return 0x8002000A
            s = f"{float(n):,}" if group else str(float(n))
            ws = s.encode("utf-16le")
            bstr_data = self.mem_alloc(len(ws) + 6, tag="api.oleaut32.bstr")
            self.mem_write(bstr_data, struct.pack("<I", len(ws)) + ws + b"\x00\x00")
            self.mem_write(out, (bstr_data + 4).to_bytes(ptr, "little"))
            return 0

        reg("VarFormatNumber", VarFormatNumber, 6)
        reg("VarFormatPercent", VarFormatNumber, 6)
        reg("VarFormatCurrency", VarFormatNumber, 6)

    @apihook("SysAllocString", argc=1, ordinal=2)
    def SysAllocString(self, emu, argv, ctx: api.ApiContext = None):
        """
        BSTR SysAllocString(
            const OLECHAR *psz
        );
        """
        (psz,) = argv
        alloc_str = self.read_mem_string(psz, 2)
        if alloc_str:
            argv[0] = alloc_str
            alloc_str += "\x00"
            ws = alloc_str.encode("utf-16le")
            ws_len = len(ws)

            # https://docs.microsoft.com/en-us/previous-versions/windows/desktop/automat/bstr
            bstr_len = 4 + ws_len
            bstr = self.mem_alloc(bstr_len)
            bstr_bytes = struct.pack("<I", ws_len - 2) + ws

            self.mem_write(bstr, bstr_bytes)

            return bstr + 4

        return 0

    @apihook("SysAllocStringLen", argc=2, ordinal=4)
    def SysAllocStringLen(self, emu, argv, ctx: api.ApiContext = None):
        """
        BSTR SysAllocStringLen(
          [in] const OLECHAR *strIn,
          [in] UINT          ui
        );
        """
        strin, ui = argv

        ws_len = (ui + 1) * 2
        bstr = self.mem_alloc(4 + ws_len)

        if not strin:
            bstr_bytes = struct.pack("<I", ui * 2)
        else:
            alloc_str = self.read_mem_string(strin, 2)
            if alloc_str:
                argv[0] = alloc_str
                alloc_str = alloc_str[:ui]
                alloc_str += "\x00"
                ws = alloc_str.encode("utf-16le")
                bstr_bytes = struct.pack("<I", ui * 2) + ws
            else:
                return 0

        self.mem_write(bstr, bstr_bytes)

        return bstr + 4

    @apihook("SysFreeString", argc=1, ordinal=6)
    def SysFreeString(self, emu, argv, ctx: api.ApiContext = None):
        """
        void SysFreeString(
            BSTR bstrString
        );
        """
        argv[0] = self.read_wide_string(argv[0])
        return

    @apihook("VariantInit", argc=1, ordinal=8)
    def VariantInit(self, emu, argv, ctx: api.ApiContext = None):
        """
        void VariantInit(
            VARIANTARG *pvarg
        );
        """
        (pvarg,) = argv
        if pvarg:
            size = 0x18 if emu.get_ptr_size() == 8 else 0x10
            self.mem_write(pvarg, b"\x00" * size)
        return

    @apihook("SysReAllocString", argc=2)
    def SysReAllocString(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SysReAllocString(
            BSTR       *pbstr,
            const OLECHAR *psz
        );
        """
        pbstr, psz = argv
        if not pbstr:
            return False
        if not psz:
            self.mem_write(pbstr, b"\x00" * self.get_ptr_size())
            return True
        new_bstr = self.SysAllocString(emu, [psz], ctx)
        if not new_bstr:
            return False
        self.mem_write(pbstr, new_bstr.to_bytes(self.get_ptr_size(), "little"))
        return True

    @apihook("SysReAllocStringLen", argc=3)
    def SysReAllocStringLen(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SysReAllocStringLen(
            BSTR       *pbstr,
            const OLECHAR *psz,
            UINT       cch
        );
        """
        pbstr, psz, cch = argv
        if not pbstr:
            return False
        new_bstr = self.SysAllocStringLen(emu, [psz, cch], ctx)
        if not new_bstr:
            return False
        self.mem_write(pbstr, new_bstr.to_bytes(self.get_ptr_size(), "little"))
        return True

    @apihook("SysStringLen", argc=1)
    def SysStringLen(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT SysStringLen(
            BSTR bstr
        );
        """
        bstr = argv[0]
        if not bstr:
            return 0
        length = int.from_bytes(self.mem_read(bstr - 4, 4), "little")
        return length // 2

    @apihook("SysStringByteLen", argc=1)
    def SysStringByteLen(self, emu, argv, ctx: api.ApiContext = None):
        """UINT SysStringByteLen(BSTR bstr);"""
        bstr = argv[0]
        if not bstr:
            return 0
        return int.from_bytes(self.mem_read(bstr - 4, 4), "little")

    @apihook("VariantClear", argc=1)
    def VariantClear(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT VariantClear(
            VARIANTARG *pvarg
        );
        """
        pvarg = argv[0]
        if not pvarg:
            return 0x80004003  # E_POINTER
        size = 0x18 if emu.get_ptr_size() == 8 else 0x10
        self.mem_write(pvarg, b"\x00" * size)
        return 0

    @apihook("VariantCopy", argc=2)
    def VariantCopy(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT VariantCopy(
            VARIANTARG *pvargDest,
            const VARIANTARG *pvargSrc
        );
        """
        dest, src = argv
        if not dest or not src:
            return 0x80004003
        size = 0x18 if emu.get_ptr_size() == 8 else 0x10
        self.mem_write(dest, self.mem_read(src, size))
        return 0

    @apihook("VariantCopyInd", argc=2)
    def VariantCopyInd(self, emu, argv, ctx: api.ApiContext = None):
        return self.VariantCopy(emu, argv, ctx)

    @apihook("VariantChangeType", argc=4)
    def VariantChangeType(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT VariantChangeType(
            VARIANTARG *pvargDest,
            const VARIANTARG *pvargSrc,
            USHORT     wFlags,
            VARTYPE    vt
        );
        """
        dest, src, flags, vt = argv
        if not dest or not src:
            return 0x80004003
        size = 0x18 if emu.get_ptr_size() == 8 else 0x10
        data = self.mem_read(src, size)
        vt_src = int.from_bytes(data[:2], "little")
        if vt == 0x0008 or vt_src == 0x0008:  # VT_BSTR
            data = bytearray(data)
            data[0:2] = vt.to_bytes(2, "little")
            self.mem_write(dest, bytes(data))
            return 0
        self.mem_write(dest, data)
        return 0

    @apihook("VariantChangeTypeEx", argc=5)
    def VariantChangeTypeEx(self, emu, argv, ctx: api.ApiContext = None):
        dest, src, lcid, flags, vt = argv
        return self.VariantChangeType(emu, [dest, src, flags, vt], ctx)

    @apihook("SafeArrayDestroy", argc=1)
    def SafeArrayDestroy(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT SafeArrayDestroy(SAFEARRAY *psa);"""
        psa = argv[0]
        if not psa:
            return 0
        try:
            self.mem_free(psa)
        except Exception:
            pass
        return 0

    @apihook("SafeArrayDestroyData", argc=1)
    def SafeArrayDestroyData(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT SafeArrayDestroyData(SAFEARRAY *psa);"""
        return 0

    @apihook("SafeArrayGetLBound", argc=3)
    def SafeArrayGetLBound(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT SafeArrayGetLBound(SAFEARRAY *psa, UINT nDim, LONG *plLbound);"""
        psa, dim, out = argv
        if out:
            self.mem_write(out, b"\x00\x00\x00\x00")
        return 0

    @apihook("SafeArrayGetUBound", argc=3)
    def SafeArrayGetUBound(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT SafeArrayGetUBound(SAFEARRAY *psa, UINT nDim, LONG *plUbound);"""
        psa, dim, out = argv
        if out:
            self.mem_write(out, struct.pack("<i", -1))
        return 0

    @apihook("SafeArrayGetElemsize", argc=1)
    def SafeArrayGetElemsize(self, emu, argv, ctx: api.ApiContext = None):
        """UINT SafeArrayGetElemsize(SAFEARRAY *psa);"""
        return 4

    @apihook("SafeArrayGetDim", argc=1)
    def SafeArrayGetDim(self, emu, argv, ctx: api.ApiContext = None):
        """UINT SafeArrayGetDim(SAFEARRAY *psa);"""
        return 1

    @apihook("SafeArrayAccessData", argc=2)
    def SafeArrayAccessData(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT SafeArrayAccessData(SAFEARRAY *psa, void **ppvData);"""
        psa, out = argv
        if out and psa:
            data_addr = psa + 0x18
            self.mem_write(out, data_addr.to_bytes(self.get_ptr_size(), "little"))
        return 0

    @apihook("SafeArrayUnaccessData", argc=1)
    def SafeArrayUnaccessData(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT SafeArrayUnaccessData(SAFEARRAY *psa);"""
        return 0

    @apihook("SafeArrayCreate", argc=3)
    def SafeArrayCreate(self, emu, argv, ctx: api.ApiContext = None):
        """SAFEARRAY *SafeArrayCreate(VARTYPE vt, UINT cDims, SAFEARRAYBOUND *rgsabound);"""
        vt, dims, bounds = argv
        total = 1
        if bounds:
            for i in range(dims):
                c = int.from_bytes(self.mem_read(bounds + i * 8, 4), "little")
                total *= max(c, 1)
        psa = self.mem_alloc(0x18 + total * 4, tag="api.oleaut32.safearray")
        self.mem_write(psa, struct.pack("<HH", 0, dims))
        return psa

    @apihook("SafeArrayGetElement", argc=3)
    def SafeArrayGetElement(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT SafeArrayGetElement(SAFEARRAY *psa, LONG *rgIndices, void *pv);"""
        return 0

    @apihook("SafeArrayPutElement", argc=3)
    def SafeArrayPutElement(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT SafeArrayPutElement(SAFEARRAY *psa, LONG *rgIndices, void *pv);"""
        return 0

    @apihook("SafeArrayCreateVector", argc=3)
    def SafeArrayCreateVector(self, emu, argv, ctx: api.ApiContext = None):
        """SAFEARRAY *SafeArrayCreateVector(VARTYPE vt, LONG lLbound, ULONG cElements);"""
        vt, lbound, count = argv
        psa = self.mem_alloc(0x18 + max(count, 1) * 4, tag="api.oleaut32.safearray")
        self.mem_write(psa, struct.pack("<HH", 0, 1))
        return psa

    @apihook("SafeArrayCreateVectorEx", argc=4)
    def SafeArrayCreateVectorEx(self, emu, argv, ctx: api.ApiContext = None):
        return self.SafeArrayCreateVector(emu, argv[:3], ctx)

    @apihook("SafeArrayDestroyVector", argc=1)
    def SafeArrayDestroyVector(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT SafeArrayDestroyVector(SAFEARRAY *psa);"""
        return self.SafeArrayDestroy(emu, argv, ctx)

    @apihook("VarBstrFromI4", argc=3)
    def VarBstrFromI4(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT VarBstrFromI4(LONG lIn, LCID lcid, BSTR *pbstrOut);"""
        value, lcid, out = argv
        if not out:
            return 0x80004003
        bstr = self.SysAllocString(emu, [self.mem_alloc(8)], ctx)
        bstr_data = self.mem_alloc(len(str(value)) * 2 + 4, tag="api.oleaut32.bstr")
        ws = str(value).encode("utf-16le")
        self.mem_write(bstr_data, struct.pack("<I", len(ws)) + ws + b"\x00\x00")
        self.mem_write(out, (bstr_data + 4).to_bytes(self.get_ptr_size(), "little"))
        return 0

    @apihook("VarI4FromStr", argc=4)
    def VarI4FromStr(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT VarI4FromStr(OLECHAR *strIn, LCID lcid, ULONG dwFlags, LONG *plOut);"""
        s, lcid, flags, out = argv
        if not out:
            return 0x80004003
        txt = self.read_wide_string(s) if s else ""
        try:
            val = int(txt.strip())
        except Exception:
            return 0x8002000A  # DISP_E_TYPEMISMATCH
        self.mem_write(out, struct.pack("<i", val))
        return 0

    @apihook("VarI8FromStr", argc=4)
    def VarI8FromStr(self, emu, argv, ctx: api.ApiContext = None):
        s, lcid, flags, out = argv
        if not out:
            return 0x80004003
        txt = self.read_wide_string(s) if s else ""
        try:
            val = int(txt.strip())
        except Exception:
            return 0x8002000A
        self.mem_write(out, struct.pack("<q", val))
        return 0

    @apihook("VarR8FromStr", argc=4)
    def VarR8FromStr(self, emu, argv, ctx: api.ApiContext = None):
        s, lcid, flags, out = argv
        if not out:
            return 0x80004003
        txt = self.read_wide_string(s) if s else ""
        try:
            val = float(txt.strip())
        except Exception:
            return 0x8002000A
        self.mem_write(out, struct.pack("<d", val))
        return 0

    @apihook("VarBstrFromR8", argc=3)
    def VarBstrFromR8(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT VarBstrFromR8(DOUBLE dblIn, LCID lcid, BSTR *pbstrOut);"""
        value, lcid, out = argv
        if not out:
            return 0x80004003
        ws = repr(float(value)).encode("utf-16le")
        bstr_data = self.mem_alloc(len(ws) + 6, tag="api.oleaut32.bstr")
        self.mem_write(bstr_data, struct.pack("<I", len(ws)) + ws + b"\x00\x00")
        self.mem_write(out, (bstr_data + 4).to_bytes(self.get_ptr_size(), "little"))
        return 0

    @apihook("VarBstrFromBool", argc=3)
    def VarBstrFromBool(self, emu, argv, ctx: api.ApiContext = None):
        value, lcid, out = argv
        if not out:
            return 0x80004003
        ws = ("True" if value else "False").encode("utf-16le")
        bstr_data = self.mem_alloc(len(ws) + 6, tag="api.oleaut32.bstr")
        self.mem_write(bstr_data, struct.pack("<I", len(ws)) + ws + b"\x00\x00")
        self.mem_write(out, (bstr_data + 4).to_bytes(self.get_ptr_size(), "little"))
        return 0

    @apihook("VarBoolFromStr", argc=4)
    def VarBoolFromStr(self, emu, argv, ctx: api.ApiContext = None):
        s, lcid, flags, out = argv
        if not out:
            return 0x80004003
        txt = (self.read_wide_string(s) if s else "").strip().lower()
        val = 1 if txt in ("true", "-1", "1", "yes") else 0
        self.mem_write(out, struct.pack("<h", val))
        return 0

    @apihook("DispCallFunc", argc=8)
    def DispCallFunc(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT DispCallFunc(
            void *pvInstance,
            ULONG_PTR oVft,
            CALLCONV cc,
            VARTYPE vtReturn,
            UINT cActuals,
            VARIANT *prgvt,
            VARIANT *prgpvarg,
            VARIANT *pvargResult
        );
        """
        pvInstance, oVft, cc, vtReturn, cActuals, prgvt, prgpvarg, pvargResult = argv
        return 0
