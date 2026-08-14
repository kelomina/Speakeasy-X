# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import struct

import speakeasy.winenv.arch as _arch

from .. import api


class GDI32(api.ApiHandler):
    """
    Implements exported functions from gdi32.dll
    """

    name = "gdi32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.handle = 0
        self.count = 0
        super().__get_hook_attrs__(self)

        self._register_gdi32_batch()

    def _register_gdi32_batch(self):
        """Register real handlers for common gdi32 drawing/object helpers."""
        sd = _arch.CALL_CONV_STDCALL

        def reg(name, func, argc):
            # Override legacy stub handlers: the batch provides the real
            # implementation for these names.
            self.funcs[name] = (name, func, argc, sd, None)

        self.stock_objects = {
            0: 0x1000,   # WHITE_BRUSH
            1: 0x1004,   # LTGRAY_BRUSH
            2: 0x1008,   # GRAY_BRUSH
            3: 0x100C,   # DKGRAY_BRUSH
            4: 0x1010,   # BLACK_BRUSH
            5: 0x1014,   # NULL_BRUSH
            6: 0x1018,   # WHITE_PEN
            7: 0x101C,   # BLACK_PEN
            8: 0x1020,   # NULL_PEN
            9: 0x1024,   # OEM_FIXED_FONT
            10: 0x1028,  # ANSI_FIXED_FONT
            11: 0x102C,  # ANSI_VAR_FONT
            12: 0x1030,  # SYSTEM_FONT
            13: 0x1034,  # DEVICE_DEFAULT_FONT
            14: 0x1038,  # DEFAULT_PALETTE
            15: 0x103C,  # SYSTEM_FIXED_FONT
            16: 0x1040,  # DEFAULT_GUI_FONT
        }

        def MulDiv_impl(self, emu, argv, ctx=None):
            a, b, c = argv
            if c == 0:
                return -1
            return (a * b) // c

        reg("MulDiv", MulDiv_impl, 3)

        def GetStockObject_impl(self, emu, argv, ctx=None):
            obj = argv[0]
            return self.stock_objects.get(obj, 0)

        reg("GetStockObject", GetStockObject_impl, 1)

        def CreateCompatibleDC_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateCompatibleDC", CreateCompatibleDC_impl, 1)

        def CreateCompatibleBitmap_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateCompatibleBitmap", CreateCompatibleBitmap_impl, 3)

        def CreateSolidBrush_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateSolidBrush", CreateSolidBrush_impl, 1)

        def CreatePen_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreatePen", CreatePen_impl, 3)

        def CreateFontIndirect_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateFontIndirectW", CreateFontIndirect_impl, 1)
        reg("CreateFontIndirectA", CreateFontIndirect_impl, 1)

        def CreateDIBitmap_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateDIBitmap", CreateDIBitmap_impl, 6)

        def CreateDIBSection_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateDIBSection", CreateDIBSection_impl, 7)

        def CreatePatternBrush_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreatePatternBrush", CreatePatternBrush_impl, 1)

        def CreateHatchBrush_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateHatchBrush", CreateHatchBrush_impl, 2)

        def DeleteObject_impl(self, emu, argv, ctx=None):
            return True

        reg("DeleteObject", DeleteObject_impl, 1)

        def DeleteDC_impl(self, emu, argv, ctx=None):
            return True

        reg("DeleteDC", DeleteDC_impl, 1)

        def SelectObject_impl(self, emu, argv, ctx=None):
            return argv[1]

        reg("SelectObject", SelectObject_impl, 2)

        def GetObject_impl(self, emu, argv, ctx=None):
            obj, count, out = argv
            if not out:
                return 0
            self.mem_write(out, b"\x00" * min(count, 0x40))
            return min(count, 0x40)

        reg("GetObjectW", GetObject_impl, 3)
        reg("GetObjectA", GetObject_impl, 3)

        def GetDeviceCaps_impl(self, emu, argv, ctx=None):
            hdc, index = argv
            values = {
                0x00: 10,    # HORZRES
                0x01: 10,    # VERTRES
                0x02: 96,    # LOGPIXELSX
                0x03: 96,    # LOGPIXELSY
                0x0B: 1,     # NUMCOLORS
                0x0C: 0x18,  # BITSPIXEL
                0x0D: 1,     # PLANES
                0x0E: 32,    # NUMBRUSHES
                0x10: 32,    # NUMPENS
                0x12: 1,     # NUMFONTS
                0x16: 2,     # TECHNOLOGY
                0x18: 100,   # SCALINGFACTORX
                0x19: 100,   # SCALINGFACTORY
                0x1A: 0,     # HORZRES
                0x20: 8,     # RASTERCAPS
                0x2A: 0,     # SHADEBLENDCAPS
            }
            return values.get(index, 0)

        reg("GetDeviceCaps", GetDeviceCaps_impl, 2)

        def SetBkMode_impl(self, emu, argv, ctx=None):
            hdc, mode = argv
            return mode

        reg("SetBkMode", SetBkMode_impl, 2)

        def GetBkMode_impl(self, emu, argv, ctx=None):
            return 1  # OPAQUE

        reg("GetBkMode", GetBkMode_impl, 1)

        def SetBkColor_impl(self, emu, argv, ctx=None):
            hdc, color = argv
            return color

        reg("SetBkColor", SetBkColor_impl, 2)

        def SetTextColor_impl(self, emu, argv, ctx=None):
            hdc, color = argv
            return color

        reg("SetTextColor", SetTextColor_impl, 2)

        def GetTextColor_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetTextColor", GetTextColor_impl, 1)

        def SetMapMode_impl(self, emu, argv, ctx=None):
            hdc, mode = argv
            return mode

        reg("SetMapMode", SetMapMode_impl, 2)

        def GetMapMode_impl(self, emu, argv, ctx=None):
            return 1  # MM_TEXT

        reg("GetMapMode", GetMapMode_impl, 1)

        def SetROP2_impl(self, emu, argv, ctx=None):
            hdc, rop = argv
            return rop

        reg("SetROP2", SetROP2_impl, 2)

        def GetROP2_impl(self, emu, argv, ctx=None):
            return 13  # R2_COPYPEN

        reg("GetROP2", GetROP2_impl, 1)

        def SetPolyFillMode_impl(self, emu, argv, ctx=None):
            hdc, mode = argv
            return mode

        reg("SetPolyFillMode", SetPolyFillMode_impl, 2)

        def GetPolyFillMode_impl(self, emu, argv, ctx=None):
            return 1  # ALTERNATE

        reg("GetPolyFillMode", GetPolyFillMode_impl, 1)

        def SetStretchBltMode_impl(self, emu, argv, ctx=None):
            hdc, mode = argv
            return mode

        reg("SetStretchBltMode", SetStretchBltMode_impl, 2)

        def GetStretchBltMode_impl(self, emu, argv, ctx=None):
            return 3  # COLORONCOLOR

        reg("GetStretchBltMode", GetStretchBltMode_impl, 1)

        def SetGraphicsMode_impl(self, emu, argv, ctx=None):
            hdc, mode = argv
            return mode

        reg("SetGraphicsMode", SetGraphicsMode_impl, 2)

        def GetGraphicsMode_impl(self, emu, argv, ctx=None):
            return 1  # GM_COMPATIBLE

        reg("GetGraphicsMode", GetGraphicsMode_impl, 1)

        def BitBlt_impl(self, emu, argv, ctx=None):
            return True

        reg("BitBlt", BitBlt_impl, 11)

        def StretchBlt_impl(self, emu, argv, ctx=None):
            return True

        reg("StretchBlt", StretchBlt_impl, 12)

        def PatBlt_impl(self, emu, argv, ctx=None):
            return True

        reg("PatBlt", PatBlt_impl, 6)

        def TextOut_impl(self, emu, argv, ctx=None):
            hdc, x, y, s, count = argv
            if s:
                self.read_mem_string(s, 2 if ctx and (ctx or {}).get("func_name", "").endswith("W") else 1)
            return True

        reg("TextOutW", TextOut_impl, 5)
        reg("TextOutA", TextOut_impl, 5)

        def ExtTextOut_impl(self, emu, argv, ctx=None):
            return True

        reg("ExtTextOutW", ExtTextOut_impl, 9)
        reg("ExtTextOutA", ExtTextOut_impl, 9)

        def GetTextExtentPoint32_impl(self, emu, argv, ctx=None):
            hdc, s, count, out = argv
            if not out:
                return False
            self.mem_write(out, struct.pack("<ii", max(count, 1) * 7, 16))
            return True

        reg("GetTextExtentPoint32W", GetTextExtentPoint32_impl, 4)
        reg("GetTextExtentPoint32A", GetTextExtentPoint32_impl, 4)
        reg("GetTextExtentPointW", GetTextExtentPoint32_impl, 4)
        reg("GetTextExtentPointA", GetTextExtentPoint32_impl, 4)

        def SetViewportOrgEx_impl(self, emu, argv, ctx=None):
            hdc, x, y, old = argv
            if old:
                self.mem_write(old, b"\x00\x00\x00\x00" * 2)
            return True

        reg("SetViewportOrgEx", SetViewportOrgEx_impl, 4)

        def GetViewportOrgEx_impl(self, emu, argv, ctx=None):
            hdc, out = argv
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00" * 2)
            return True

        reg("GetViewportOrgEx", GetViewportOrgEx_impl, 2)

        def SetWindowOrgEx_impl(self, emu, argv, ctx=None):
            return True

        reg("SetWindowOrgEx", SetWindowOrgEx_impl, 4)

        def GetWindowOrgEx_impl(self, emu, argv, ctx=None):
            hdc, out = argv
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00" * 2)
            return True

        reg("GetWindowOrgEx", GetWindowOrgEx_impl, 2)

        def GetClipBox_impl(self, emu, argv, ctx=None):
            hdc, out = argv
            if out:
                self.mem_write(out, struct.pack("<iiii", 0, 0, 1024, 768))
            return 4  # SIMPLEREGION

        reg("GetClipBox", GetClipBox_impl, 2)

        def SaveDC_impl(self, emu, argv, ctx=None):
            return 1

        reg("SaveDC", SaveDC_impl, 1)

        def RestoreDC_impl(self, emu, argv, ctx=None):
            return True

        reg("RestoreDC", RestoreDC_impl, 2)

        def GetDCOrgEx_impl(self, emu, argv, ctx=None):
            hdc, out = argv
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00" * 2)
            return True

        reg("GetDCOrgEx", GetDCOrgEx_impl, 2)

        def Rectangle_impl(self, emu, argv, ctx=None):
            return True

        reg("Rectangle", Rectangle_impl, 5)

        def Ellipse_impl(self, emu, argv, ctx=None):
            return True

        reg("Ellipse", Ellipse_impl, 5)

        def FillRect_impl(self, emu, argv, ctx=None):
            return True

        reg("FillRect", FillRect_impl, 3)

        def FrameRect_impl(self, emu, argv, ctx=None):
            return True

        reg("FrameRect", FrameRect_impl, 3)

        def InvertRect_impl(self, emu, argv, ctx=None):
            return True

        reg("InvertRect", InvertRect_impl, 2)

        def DrawText_impl(self, emu, argv, ctx=None):
            hdc, s, count, rect, flags = argv
            if s:
                self.read_mem_string(s, 2)
            if rect:
                self.mem_write(rect + 12, b"\x10\x00\x00\x00")
            return 1

        reg("DrawTextW", DrawText_impl, 5)
        reg("DrawTextA", DrawText_impl, 5)

        def GetPixel_impl(self, emu, argv, ctx=None):
            return 0xFFFFFFFF  # CLR_INVALID

        reg("GetPixel", GetPixel_impl, 3)

        def SetPixel_impl(self, emu, argv, ctx=None):
            hdc, x, y, color = argv
            return color

        reg("SetPixel", SetPixel_impl, 4)

        def GetCurrentObject_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetCurrentObject", GetCurrentObject_impl, 2)

        def GetNearestColor_impl(self, emu, argv, ctx=None):
            hdc, color = argv
            return color

        reg("GetNearestColor", GetNearestColor_impl, 2)

        def SetDIBitsToDevice_impl(self, emu, argv, ctx=None):
            return True

        reg("SetDIBitsToDevice", SetDIBitsToDevice_impl, 13)

        def StretchDIBits_impl(self, emu, argv, ctx=None):
            return 0

        reg("StretchDIBits", StretchDIBits_impl, 13)

        def GetDIBits_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetDIBits", GetDIBits_impl, 7)

        def SetDIBits_impl(self, emu, argv, ctx=None):
            return 0

        reg("SetDIBits", SetDIBits_impl, 7)

        def GetTextMetrics_impl(self, emu, argv, ctx=None):
            hdc, out = argv
            if not out:
                return False
            self.mem_write(out, struct.pack("<iiihhhhhhH", 16, 16, 0, 1, 0, 0, 0, 0, 0, 0, 0x31))
            return True

        reg("GetTextMetricsW", GetTextMetrics_impl, 2)
        reg("GetTextMetricsA", GetTextMetrics_impl, 2)

        def SetTextAlign_impl(self, emu, argv, ctx=None):
            hdc, align = argv
            return align

        reg("SetTextAlign", SetTextAlign_impl, 2)

        def GetTextAlign_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetTextAlign", GetTextAlign_impl, 1)

        def SetTextJustification_impl(self, emu, argv, ctx=None):
            return True

        reg("SetTextJustification", SetTextJustification_impl, 3)

        def SetBkColor_impl(self, emu, argv, ctx=None):
            hdc, color = argv
            return color

        reg("SetBkColor", SetBkColor_impl, 2)

        def CreatePenIndirect_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreatePenIndirect", CreatePenIndirect_impl, 1)

        def CreateBrushIndirect_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateBrushIndirect", CreateBrushIndirect_impl, 1)

        def CreateDCA_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateDCA", CreateDCA_impl, 4)
        reg("CreateDCW", CreateDCA_impl, 4)
        reg("CreateDC", CreateDCA_impl, 4)

        def CreateICW_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateICW", CreateICW_impl, 4)
        reg("CreateICA", CreateICW_impl, 4)

        def EnumFontFamiliesEx_impl(self, emu, argv, ctx=None):
            return 0

        reg("EnumFontFamiliesExW", EnumFontFamiliesEx_impl, 5)
        reg("EnumFontFamiliesExA", EnumFontFamiliesEx_impl, 5)

        def EnumFonts_impl(self, emu, argv, ctx=None):
            return 0

        reg("EnumFontsW", EnumFonts_impl, 4)
        reg("EnumFontsA", EnumFonts_impl, 4)

        def GetCharWidth_impl(self, emu, argv, ctx=None):
            hdc, first, last, out = argv
            if not out:
                return False
            count = last - first + 1
            self.mem_write(out, b"\x07\x00" * count)
            return True

        reg("GetCharWidthW", GetCharWidth_impl, 4)
        reg("GetCharWidthA", GetCharWidth_impl, 4)

        def GetGlyphOutline_impl(self, emu, argv, ctx=None):
            return 0xFFFFFFFF  # GDI_ERROR

        reg("GetGlyphOutlineW", GetGlyphOutline_impl, 7)
        reg("GetGlyphOutlineA", GetGlyphOutline_impl, 7)

        def GetFontData_impl(self, emu, argv, ctx=None):
            return 0xFFFFFFFF  # GDI_ERROR

        reg("GetFontData", GetFontData_impl, 5)

        def GetOutlineTextMetrics_impl(self, emu, argv, ctx=None):
            hdc, count, out = argv
            if not out:
                return 0x60
            self.mem_write(out, b"\x00" * min(count, 0x60))
            return min(count, 0x60)

        reg("GetOutlineTextMetricsW", GetOutlineTextMetrics_impl, 3)
        reg("GetOutlineTextMetricsA", GetOutlineTextMetrics_impl, 3)

        def GetRgnBox_impl(self, emu, argv, ctx=None):
            rgn, out = argv
            if out:
                self.mem_write(out, struct.pack("<iiii", 0, 0, 0, 0))
            return 2  # NULLREGION

        reg("GetRgnBox", GetRgnBox_impl, 2)

        def CreateRectRgn_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreateRectRgn", CreateRectRgn_impl, 4)
        reg("CreateRectRgnIndirect", CreateRectRgn_impl, 1)
        reg("CreateRoundRectRgn", CreateRectRgn_impl, 6)

        def CombineRgn_impl(self, emu, argv, ctx=None):
            return 1  # SIMPLEREGION

        reg("CombineRgn", CombineRgn_impl, 4)

        def SetRectRgn_impl(self, emu, argv, ctx=None):
            return True

        reg("SetRectRgn", SetRectRgn_impl, 5)

        def OffsetRgn_impl(self, emu, argv, ctx=None):
            return 1  # SIMPLEREGION

        reg("OffsetRgn", OffsetRgn_impl, 3)

        def PtInRegion_impl(self, emu, argv, ctx=None):
            return False

        reg("PtInRegion", PtInRegion_impl, 3)

        def Polygon_impl(self, emu, argv, ctx=None):
            return True

        reg("Polygon", Polygon_impl, 4)

        def Polyline_impl(self, emu, argv, ctx=None):
            return True

        reg("Polyline", Polyline_impl, 3)

        def Arc_impl(self, emu, argv, ctx=None):
            return True

        reg("Arc", Arc_impl, 9)

        def Chord_impl(self, emu, argv, ctx=None):
            return True

        reg("Chord", Chord_impl, 9)

        def Pie_impl(self, emu, argv, ctx=None):
            return True

        reg("Pie", Pie_impl, 9)

        def RoundRect_impl(self, emu, argv, ctx=None):
            return True

        reg("RoundRect", RoundRect_impl, 7)

        def SetViewportExtEx_impl(self, emu, argv, ctx=None):
            hdc, x, y, old = argv
            if old:
                self.mem_write(old, struct.pack("<ii", x, y))
            return True

        reg("SetViewportExtEx", SetViewportExtEx_impl, 4)

        def GetViewportExtEx_impl(self, emu, argv, ctx=None):
            hdc, out = argv
            if out:
                self.mem_write(out, struct.pack("<ii", 1024, 768))
            return True

        reg("GetViewportExtEx", GetViewportExtEx_impl, 2)

        def SetWindowExtEx_impl(self, emu, argv, ctx=None):
            return True

        reg("SetWindowExtEx", SetWindowExtEx_impl, 4)

        def GetWindowExtEx_impl(self, emu, argv, ctx=None):
            hdc, out = argv
            if out:
                self.mem_write(out, struct.pack("<ii", 1024, 768))
            return True

        reg("GetWindowExtEx", GetWindowExtEx_impl, 2)

        def SetWorldTransform_impl(self, emu, argv, ctx=None):
            return True

        reg("SetWorldTransform", SetWorldTransform_impl, 2)

        def GetWorldTransform_impl(self, emu, argv, ctx=None):
            hdc, out = argv
            if out:
                self.mem_write(out, struct.pack("<ffffffff", 1, 0, 0, 1, 0, 0, 0, 1))
            return True

        reg("GetWorldTransform", GetWorldTransform_impl, 2)

        def ModifyWorldTransform_impl(self, emu, argv, ctx=None):
            return True

        reg("ModifyWorldTransform", ModifyWorldTransform_impl, 3)

        def SetMiterLimit_impl(self, emu, argv, ctx=None):
            hdc, limit, old = argv
            if old:
                self.mem_write(old, struct.pack("<f", 10.0))
            return True

        reg("SetMiterLimit", SetMiterLimit_impl, 3)

        def GetMiterLimit_impl(self, emu, argv, ctx=None):
            hdc, out = argv
            if out:
                self.mem_write(out, struct.pack("<f", 10.0))
            return True

        reg("GetMiterLimit", GetMiterLimit_impl, 2)

        def SetBrushOrgEx_impl(self, emu, argv, ctx=None):
            return True

        reg("SetBrushOrgEx", SetBrushOrgEx_impl, 4)

        def GetBrushOrgEx_impl(self, emu, argv, ctx=None):
            hdc, out = argv
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00" * 2)
            return True

        reg("GetBrushOrgEx", GetBrushOrgEx_impl, 2)

        def SetPixelFormat_impl(self, emu, argv, ctx=None):
            return True

        reg("SetPixelFormat", SetPixelFormat_impl, 3)

        def ChoosePixelFormat_impl(self, emu, argv, ctx=None):
            return 1

        reg("ChoosePixelFormat", ChoosePixelFormat_impl, 2)

        def DescribePixelFormat_impl(self, emu, argv, ctx=None):
            hdc, fmt, size, out = argv
            if not out:
                return 0
            self.mem_write(out, b"\x00" * min(size, 0x28))
            return 1

        reg("DescribePixelFormat", DescribePixelFormat_impl, 4)

        def SwapBuffers_impl(self, emu, argv, ctx=None):
            return True

        reg("SwapBuffers", SwapBuffers_impl, 1)

        def wglCreateContext_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("wglCreateContext", wglCreateContext_impl, 1)

        def wglDeleteContext_impl(self, emu, argv, ctx=None):
            return True

        reg("wglDeleteContext", wglDeleteContext_impl, 1)

        def wglMakeCurrent_impl(self, emu, argv, ctx=None):
            return True

        reg("wglMakeCurrent", wglMakeCurrent_impl, 2)

        def wglGetCurrentContext_impl(self, emu, argv, ctx=None):
            return 0

        reg("wglGetCurrentContext", wglGetCurrentContext_impl, 0)

        def wglGetProcAddress_impl(self, emu, argv, ctx=None):
            return 0

        reg("wglGetProcAddress", wglGetProcAddress_impl, 1)

        def wglSwapBuffers_impl(self, emu, argv, ctx=None):
            return True

        reg("wglSwapBuffers", wglSwapBuffers_impl, 1)

        def wglShareLists_impl(self, emu, argv, ctx=None):
            return True

        reg("wglShareLists", wglShareLists_impl, 2)

        def wglUseFontBitmaps_impl(self, emu, argv, ctx=None):
            return True

        reg("wglUseFontBitmapsW", wglUseFontBitmaps_impl, 5)
        reg("wglUseFontBitmapsA", wglUseFontBitmaps_impl, 5)

        def GdiFlush_impl(self, emu, argv, ctx=None):
            return True

        reg("GdiFlush", GdiFlush_impl, 0)

        def GdiGetBatchLimit_impl(self, emu, argv, ctx=None):
            return 0

        reg("GdiGetBatchLimit", GdiGetBatchLimit_impl, 0)

        def GdiSetBatchLimit_impl(self, emu, argv, ctx=None):
            return 0

        reg("GdiSetBatchLimit", GdiSetBatchLimit_impl, 1)

        def GetBkColor_impl(self, emu, argv, ctx=None):
            return 0xFFFFFF

        reg("GetBkColor", GetBkColor_impl, 1)

    def get_handle(self):
        self.handle += 4
        hnd = self.handle
        return hnd

    @apihook("CreateBitmap", argc=5)
    def CreateBitmap(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP CreateBitmap(
            int        nWidth,
            int        nHeight,
            UINT       nPlanes,
            UINT       nBitCount,
            const VOID *lpBits
        );
        """
        return self.get_handle()

    @apihook("MoveToEx", argc=1)
    def MoveToEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL MoveToEx(
          HDC     hdc,
          int     x,
          int     y,
          LPPOINT lppt
        );
        """
        return 1

    @apihook("LineTo", argc=1)
    def LineTo(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL LineTo(
          HDC hdc,
          int x,
          int y
        )
        """
        return 1

    @apihook("GetStockObject", argc=1)
    def GetStockObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        HGDIOBJ GetStockObject(
            int i
        );
        """
        return 0

    @apihook("GetMapMode", argc=1)
    def GetMapMode(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetMapMode(
            HDC hdc
        );
        """
        return 1

    @apihook("GetDeviceCaps", argc=2)
    def GetDeviceCaps(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetDeviceCaps(
            HDC hdc,
            int index
        );
        """
        return 16

    @apihook("GdiSetBatchLimit", argc=1)
    def GdiSetBatchLimit(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GdiSetBatchLimit(
          DWORD dw
        );
        """
        return 0

    @apihook("MaskBlt", argc=12)
    def MaskBlt(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL MaskBlt(
          HDC     hdcDest,
          int     xDest,
          int     yDest,
          int     width,
          int     height,
          HDC     hdcSrc,
          int     xSrc,
          int     ySrc,
          HBITMAP hbmMask,
          int     xMask,
          int     yMask,
          DWORD   rop
        );
        """
        return 1

    @apihook("BitBlt", argc=9)
    def BitBlt(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL BitBlt(
        HDC   hdc,
        int   x,
        int   y,
        int   cx,
        int   cy,
        HDC   hdcSrc,
        int   x1,
        int   y1,
        DWORD rop
        """
        return 1

    @apihook("DeleteDC", argc=1)
    def DeleteDC(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL DeleteDC(
        HDC hdc
        );
        """
        return 1

    @apihook("SelectObject", argc=2)
    def SelectObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        HGDIOBJ SelectObject(
          HDC     hdc,
          HGDIOBJ h
        );
        """
        return 0

    @apihook("DeleteObject", argc=1)
    def DeleteObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL DeleteObject(
        HGDIOBJ ho
        );
        """
        return 1

    @apihook("CreateCompatibleBitmap", argc=3)
    def CreateCompatibleBitmap(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP CreateCompatibleBitmap(
        HDC hdc,
        int cx,
        int cy
        );
        """
        return 0

    @apihook("CreateCompatibleDC", argc=1)
    def CreateCompatibleDC(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDC CreateCompatibleDC(
        HDC hdc
        );
        """
        return 0

    @apihook("GetDIBits", argc=7)
    def GetDIBits(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetDIBits(
        HDC          hdc,
        HBITMAP      hbm,
        UINT         start,
        UINT         cLines,
        LPVOID       lpvBits,
        LPBITMAPINFO lpbmi,
        UINT         usage
        );
        """
        return 0

    @apihook("CreateDIBSection", argc=6)
    def CreateDIBSection(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP CreateDIBSection(
          [in]  HDC              hdc,
          [in]  const BITMAPINFO *pbmi,
          [in]  UINT             usage,
          [out] VOID             **ppvBits,
          [in]  HANDLE           hSection,
          [in]  DWORD            offset
        );
        """
        return 0

    @apihook("CreateDCA", argc=4)
    def CreateDCA(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDC CreateDCA(
        LPCSTR         pwszDriver,
        LPCSTR         pwszDevice,
        LPCSTR         pszPort,
        const DEVMODEA *pdm
        );
        """
        return 0

    @apihook("GetTextCharacterExtra", argc=1)
    def GetTextCharacterExtra(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetTextCharacterExtra(
          HDC hdc
        );
        """
        return 0x8000000

    @apihook("StretchBlt", argc=11)
    def StretchBlt(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL StretchBlt(
          HDC   hdcDest,
          int   xDest,
          int   yDest,
          int   wDest,
          int   hDest,
          HDC   hdcSrc,
          int   xSrc,
          int   ySrc,
          int   wSrc,
          int   hSrc,
          DWORD rop
        );
        """
        return 0

    @apihook("CreateFontIndirectA", argc=1)
    def CreateFontIndirectA(self, emu, argv, ctx: api.ApiContext = None):
        """
        HFONT CreateFontIndirectA(
            const LOGFONTA *lplf
        );
        """
        # Return a fake HFONT handle.
        # Any non-zero value is treated as success.
        return 0x6000

    @apihook("GetObjectA", argc=3)
    def GetObjectA(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetObjectA(
            HANDLE h,
            int    c,
            LPVOID pv
        );
        """
        h, c, pv = argv

        # If caller provided a buffer, fill it with zeros.
        if pv and c:
            try:
                data = b"\x00" * c
                try:
                    emu.mem_write(pv, data)
                except Exception:
                    base_addr = pv & ~0xFFF
                    emu.mem_map(base_addr, 0x1000)
                    emu.mem_write(pv, data)
            except Exception:
                pass

        # Return number of bytes "written"
        return c

    @apihook("WidenPath", argc=1)
    def WidenPath(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL WidenPath(
            HDC hdc
        );
        """
        # We don't emulate actual path widening; just report success.
        return 1
