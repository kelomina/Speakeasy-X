# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import struct
from typing import Any

import speakeasy.windows.sessman as sessman
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.user32 as windefs
import speakeasy.winenv.defs.windows.windef as windef

from .. import api

IDCANCEL = 2

IDI_APPLICATION = 32512
IDI_ASTERISK = 32516
IDI_ERROR = 32513
IDI_EXCLAMATION = 32515
IDI_HAND = 32513
IDI_INFORMATION = 32516
IDI_QUESTION = 32514
IDI_SHIELD = 32518
IDI_WARNING = 32515
IDI_WINLOGO = 32517

UOI_FLAGS = 1


class User32(api.ApiHandler):
    """
    Implements exported functions from user32.dll
    """

    name = "user32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)

        self.funcs: dict[str, Any] = {}
        self.data: dict[str, Any] = {}
        self.window_hooks: dict[int, tuple] = {}
        self.handle: int = 0
        self.win: Any | None = None
        self.handles: list[int] = []
        self.wndprocs: dict[int, int] = {}
        self.timer_count: int = 0
        self.sessman = sessman.SessionManager(config=None)
        self.synthetic_async_keys = [0x41, 0x42, 0x43]
        self.synthetic_async_key_index = 0
        self.synthetic_hook_keys = [0x41, 0x42, 0x43]
        self.synthetic_hook_key_index = 0

        super().__get_hook_attrs__(self)

        self._register_user32_batch()

    def get_handle(self):
        self.handle += 4
        hnd = self.handle
        self.handles.append(hnd)
        return hnd

    def _register_user32_batch(self):
        """Register real handlers for common user32 string/window helpers."""
        ptr = self.get_ptr_size()
        sd = _arch.CALL_CONV_STDCALL
        self.window_text: dict[int, str] = {}

        def reg(name, func, argc):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, sd, None)

        def lstrlen_impl(self, emu, argv, ctx=None):
            s = argv[0]
            if not s:
                return 0
            ctx, cw = self.prepare_ctx(ctx)
            return len(self.read_mem_string(s, cw))

        reg("lstrlenA", lstrlen_impl, 1)
        reg("lstrlenW", lstrlen_impl, 1)

        def lstrcmp_impl(self, emu, argv, ctx=None):
            a, b = argv
            if not a or not b:
                return 0
            ctx, cw = self.prepare_ctx(ctx)
            sa = self.read_mem_string(a, cw)
            sb = self.read_mem_string(b, cw)
            if sa == sb:
                return 0
            return -1 if sa < sb else 1

        reg("lstrcmpA", lstrcmp_impl, 2)
        reg("lstrcmpW", lstrcmp_impl, 2)
        reg("lstrcmpiA", lstrcmp_impl, 2)
        reg("lstrcmpiW", lstrcmp_impl, 2)

        def lstrcpy_impl(self, emu, argv, ctx=None):
            dst, src = argv
            if not dst or not src:
                return 0
            ctx, cw = self.prepare_ctx(ctx)
            s = self.read_mem_string(src, cw)
            self.write_mem_string(s, dst, cw)
            return dst

        reg("lstrcpyA", lstrcpy_impl, 2)
        reg("lstrcpyW", lstrcpy_impl, 2)

        def lstrcat_impl(self, emu, argv, ctx=None):
            dst, src = argv
            if not dst or not src:
                return 0
            ctx, cw = self.prepare_ctx(ctx)
            d = self.read_mem_string(dst, cw)
            s = self.read_mem_string(src, cw)
            self.write_mem_string(d + s, dst, cw)
            return dst

        reg("lstrcatA", lstrcat_impl, 2)
        reg("lstrcatW", lstrcat_impl, 2)

        def char_case_impl(upper, wide):
            def impl(self, emu, argv, ctx=None):
                s = argv[0]
                if not s:
                    return 0
                if wide:
                    txt = self.read_wide_string(s)
                    self.write_wide_string(txt.upper() if upper else txt.lower(), s)
                else:
                    txt = self.read_string(s)
                    self.write_string(txt.upper() if upper else txt.lower(), s)
                return s

            return impl

        reg("CharUpperA", char_case_impl(True, False), 1)
        reg("CharUpperW", char_case_impl(True, True), 1)
        reg("CharLowerA", char_case_impl(False, False), 1)
        reg("CharLowerW", char_case_impl(False, True), 1)

        def CharUpperBuff_impl(self, emu, argv, ctx=None):
            s, count = argv
            if not s:
                return 0
            data = self.mem_read(s, count)
            self.mem_write(s, data.upper())
            return count

        reg("CharUpperBuffW", CharUpperBuff_impl, 2)
        reg("CharLowerBuffW", CharUpperBuff_impl, 2)

        def GetMessagePos_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetMessagePos", GetMessagePos_impl, 0)

        def GetMessageTime_impl(self, emu, argv, ctx=None):
            return self.timer_count

        reg("GetMessageTime", GetMessageTime_impl, 0)

        def GetKeyState_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetKeyState", GetKeyState_impl, 1)

        def IsWindow_impl(self, emu, argv, ctx=None):
            hwnd = argv[0]
            if not hwnd:
                return False
            return hwnd in self.wndprocs

        reg("IsWindow", IsWindow_impl, 1)

        def GetWindowTextLength_impl(self, emu, argv, ctx=None):
            hwnd = argv[0]
            text = self.window_text.get(hwnd, "")
            return len(text)

        reg("GetWindowTextLengthW", GetWindowTextLength_impl, 1)
        reg("GetWindowTextLengthA", GetWindowTextLength_impl, 1)

        def SetWindowText_impl(self, emu, argv, ctx=None):
            hwnd, text = argv
            if not text:
                return False
            ctx, cw = self.prepare_ctx(ctx)
            self.window_text[hwnd] = self.read_mem_string(text, cw)
            return True

        reg("SetWindowTextW", SetWindowText_impl, 2)
        reg("SetWindowTextA", SetWindowText_impl, 2)

        def EnableWindow_impl(self, emu, argv, ctx=None):
            return True

        reg("EnableWindow", EnableWindow_impl, 2)

        def IsWindowVisible_impl(self, emu, argv, ctx=None):
            return True

        reg("IsWindowVisible", IsWindowVisible_impl, 1)

        def IsIconic_impl(self, emu, argv, ctx=None):
            return False

        reg("IsIconic", IsIconic_impl, 1)

        def GetFocus_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetFocus", GetFocus_impl, 0)

        def SetFocus_impl(self, emu, argv, ctx=None):
            return argv[0]

        reg("SetFocus", SetFocus_impl, 1)

        def SetForegroundWindow_impl(self, emu, argv, ctx=None):
            return True

        reg("SetForegroundWindow", SetForegroundWindow_impl, 1)

        def GetActiveWindow_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetActiveWindow", GetActiveWindow_impl, 0)

        def SetActiveWindow_impl(self, emu, argv, ctx=None):
            return argv[0]

        reg("SetActiveWindow", SetActiveWindow_impl, 1)

        def MoveWindow_impl(self, emu, argv, ctx=None):
            return True

        reg("MoveWindow", MoveWindow_impl, 6)

        def GetWindowRect_impl(self, emu, argv, ctx=None):
            hwnd, rect = argv
            if rect:
                self.mem_write(rect, b"\x00" * 16)
            return True

        reg("GetWindowRect", GetWindowRect_impl, 2)

        def ScreenToClient_impl(self, emu, argv, ctx=None):
            hwnd, point = argv
            if point:
                self.mem_write(point, b"\x00\x00\x00\x00" * 2)
            return True

        reg("ScreenToClient", ScreenToClient_impl, 2)
        reg("ClientToScreen", ScreenToClient_impl, 2)

        def GetDlgCtrlID_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetDlgCtrlID", GetDlgCtrlID_impl, 1)

        def GetDlgItem_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetDlgItem", GetDlgItem_impl, 2)

        def GetWindowLongPtr_impl(self, emu, argv, ctx=None):
            hwnd, index = argv
            return 0

        reg("GetWindowLongPtrW", GetWindowLongPtr_impl, 2)
        reg("GetWindowLongPtrA", GetWindowLongPtr_impl, 2)

        def SetWindowLongPtr_impl(self, emu, argv, ctx=None):
            hwnd, index, value = argv
            if index in (0xFFFFFFFC, 0xFFFFFFF8):  # GWLP_WNDPROC / GWLP_HINSTANCE-ish
                self.wndprocs[hwnd] = value
            return 0

        reg("SetWindowLongPtrW", SetWindowLongPtr_impl, 3)
        reg("SetWindowLongPtrA", SetWindowLongPtr_impl, 3)

        def MessageBeep_impl(self, emu, argv, ctx=None):
            return True

        reg("MessageBeep", MessageBeep_impl, 1)

        def GetWindowPlacement_impl(self, emu, argv, ctx=None):
            hwnd, wndpl = argv
            if wndpl:
                self.mem_write(wndpl, b"\x00" * 40)
            return True

        reg("GetWindowPlacement", GetWindowPlacement_impl, 2)

        def SetWindowPlacement_impl(self, emu, argv, ctx=None):
            return True

        reg("SetWindowPlacement", SetWindowPlacement_impl, 2)

        def GetWindow_impl(self, emu, argv, ctx=None):
            hwnd, cmd = argv
            return 0

        reg("GetWindow", GetWindow_impl, 2)

        def GetWindowThreadProcessId_impl(self, emu, argv, ctx=None):
            hwnd, pid_out = argv
            proc = emu.get_current_process()
            if pid_out:
                self.mem_write(pid_out, (proc.id if proc else 0).to_bytes(4, "little"))
            return proc.id if proc else 0

        reg("GetWindowThreadProcessId", GetWindowThreadProcessId_impl, 2)

        # ---- window class / prop / timer / clipboard / text stores ----
        self.window_classes: dict[int, str] = {}
        self.window_props: dict[int, dict[int, int]] = {}
        self.timers: dict[int, int] = {}
        self.clipboard: dict[int, bytes] = {}
        self.clipboard_formats: dict[str, int] = {}
        self.next_clipboard_format = 0xC000
        self.cursor: int = 0
        self.cursor_pos: tuple = (100, 100)
        self.window_rects: dict[int, tuple] = {}

        def GetClassName_impl(self, emu, argv, ctx=None):
            hwnd, buf, size = argv
            if not buf:
                return 0
            name = self.window_classes.get(hwnd, "")
            if len(name) + 1 > size:
                return 0
            ctx, cw = self.prepare_ctx(ctx)
            self.write_mem_string(name, buf, cw)
            return len(name)

        reg("GetClassNameW", GetClassName_impl, 3)
        reg("GetClassNameA", GetClassName_impl, 3)

        def GetProp_impl(self, emu, argv, ctx=None):
            hwnd, atom = argv
            props = self.window_props.get(hwnd, {})
            return props.get(atom, 0)

        reg("GetPropW", GetProp_impl, 2)
        reg("GetPropA", GetProp_impl, 2)

        def SetProp_impl(self, emu, argv, ctx=None):
            hwnd, atom, value = argv
            self.window_props.setdefault(hwnd, {})[atom] = value
            return True

        reg("SetPropW", SetProp_impl, 3)
        reg("SetPropA", SetProp_impl, 3)

        def RemoveProp_impl(self, emu, argv, ctx=None):
            hwnd, atom = argv
            props = self.window_props.get(hwnd, {})
            return props.pop(atom, 0)

        reg("RemovePropW", RemoveProp_impl, 2)
        reg("RemovePropA", RemoveProp_impl, 2)

        def SetTimer_impl(self, emu, argv, ctx=None):
            hwnd, id_, elapse, proc = argv
            tid = id_ if id_ else 1
            self.timers[(hwnd, tid)] = elapse
            return tid

        reg("SetTimer", SetTimer_impl, 4)

        def KillTimer_impl(self, emu, argv, ctx=None):
            hwnd, id_ = argv
            self.timers.pop((hwnd, id_), None)
            return True

        reg("KillTimer", KillTimer_impl, 2)

        def GetQueueStatus_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetQueueStatus", GetQueueStatus_impl, 1)

        def WaitMessage_impl(self, emu, argv, ctx=None):
            return False

        reg("WaitMessage", WaitMessage_impl, 0)

        def OpenClipboard_impl(self, emu, argv, ctx=None):
            return True

        reg("OpenClipboard", OpenClipboard_impl, 1)

        def CloseClipboard_impl(self, emu, argv, ctx=None):
            return True

        reg("CloseClipboard", CloseClipboard_impl, 0)

        def EmptyClipboard_impl(self, emu, argv, ctx=None):
            self.clipboard.clear()
            return True

        reg("EmptyClipboard", EmptyClipboard_impl, 0)

        def SetClipboardData_impl(self, emu, argv, ctx=None):
            fmt, data = argv
            if not data:
                return 0
            size = 0
            if fmt == 13:  # CF_UNICODETEXT
                raw = self.read_wide_string(data)
                self.clipboard[fmt] = raw.encode("utf-16le") + b"\x00\x00"
                size = len(raw) * 2 + 2
            elif fmt == 1:  # CF_TEXT
                raw = self.read_string(data)
                self.clipboard[fmt] = raw.encode("latin-1") + b"\x00"
                size = len(raw) + 1
            else:
                self.clipboard[fmt] = b""
            return data

        reg("SetClipboardData", SetClipboardData_impl, 2)

        def GetClipboardData_impl(self, emu, argv, ctx=None):
            fmt = argv[0]
            raw = self.clipboard.get(fmt)
            if raw is None:
                return 0
            buf = self.mem_alloc(len(raw), tag="api.user32.clipboard")
            self.mem_write(buf, raw)
            return buf

        reg("GetClipboardData", GetClipboardData_impl, 1)

        def IsClipboardFormatAvailable_impl(self, emu, argv, ctx=None):
            fmt = argv[0]
            return fmt in self.clipboard

        reg("IsClipboardFormatAvailable", IsClipboardFormatAvailable_impl, 1)

        def RegisterClipboardFormat_impl(self, emu, argv, ctx=None):
            name = argv[0]
            if not name:
                return 0
            s = self.read_wide_string(name)
            fmt = self.clipboard_formats.get(s)
            if fmt is None:
                fmt = self.next_clipboard_format
                self.next_clipboard_format += 1
                self.clipboard_formats[s] = fmt
            return fmt

        reg("RegisterClipboardFormatW", RegisterClipboardFormat_impl, 1)
        reg("RegisterClipboardFormatA", RegisterClipboardFormat_impl, 1)

        def CountClipboardFormats_impl(self, emu, argv, ctx=None):
            return len(self.clipboard)

        reg("CountClipboardFormats", CountClipboardFormats_impl, 0)

        def EnumClipboardFormats_impl(self, emu, argv, ctx=None):
            fmt = argv[0]
            formats = sorted(self.clipboard.keys())
            if fmt == 0:
                return formats[0] if formats else 0
            for f in formats:
                if f > fmt:
                    return f
            return 0

        reg("EnumClipboardFormats", EnumClipboardFormats_impl, 1)

        def GetPriorityClipboardFormat_impl(self, emu, argv, ctx=None):
            formats, count = argv
            if not formats:
                return 0
            for i in range(min(count, 8)):
                fmt = int.from_bytes(self.mem_read(formats + i * 4, 4), "little")
                if fmt in self.clipboard:
                    return fmt
            return 0

        reg("GetPriorityClipboardFormat", GetPriorityClipboardFormat_impl, 2)

        def SetCursor_impl(self, emu, argv, ctx=None):
            old = self.cursor
            self.cursor = argv[0]
            return old

        reg("SetCursor", SetCursor_impl, 1)

        def SetCursorPos_impl(self, emu, argv, ctx=None):
            x, y = argv
            self.cursor_pos = (x, y)
            return True

        reg("SetCursorPos", SetCursorPos_impl, 2)

        def GetCursorPos_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if not out:
                return False
            x, y = self.cursor_pos
            self.mem_write(out, struct.pack("<ii", x, y))
            return True

        reg("GetCursorPos", GetCursorPos_impl, 1)

        def ShowCursor_impl(self, emu, argv, ctx=None):
            return 0

        reg("ShowCursor", ShowCursor_impl, 1)

        def SetCapture_impl(self, emu, argv, ctx=None):
            return argv[0]

        reg("SetCapture", SetCapture_impl, 1)

        def ReleaseCapture_impl(self, emu, argv, ctx=None):
            return True

        reg("ReleaseCapture", ReleaseCapture_impl, 0)

        def GetCapture_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetCapture", GetCapture_impl, 0)

        def InvalidateRect_impl(self, emu, argv, ctx=None):
            return True

        reg("InvalidateRect", InvalidateRect_impl, 3)

        def ValidateRect_impl(self, emu, argv, ctx=None):
            return True

        reg("ValidateRect", ValidateRect_impl, 2)

        def GetUpdateRect_impl(self, emu, argv, ctx=None):
            hwnd, rect, erase = argv
            if rect:
                self.mem_write(rect, b"\x00" * 16)
            return False

        reg("GetUpdateRect", GetUpdateRect_impl, 3)

        def BeginPaint_impl(self, emu, argv, ctx=None):
            hwnd, ps = argv
            if ps:
                self.mem_write(ps, b"\x00" * 64)
            return self.get_handle()

        reg("BeginPaint", BeginPaint_impl, 2)

        def EndPaint_impl(self, emu, argv, ctx=None):
            return True

        reg("EndPaint", EndPaint_impl, 2)

        def GetDCEx_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("GetDCEx", GetDCEx_impl, 3)

        def GetWindowDC_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("GetWindowDC", GetWindowDC_impl, 1)

        def SetWindowPos_impl(self, emu, argv, ctx=None):
            return True

        reg("SetWindowPos", SetWindowPos_impl, 7)

        def IsChild_impl(self, emu, argv, ctx=None):
            return False

        reg("IsChild", IsChild_impl, 2)

        def GetDlgItemText_impl(self, emu, argv, ctx=None):
            dlg, id_, buf, size = argv
            if not buf:
                return 0
            ctx, cw = self.prepare_ctx(ctx)
            text = self.window_text.get(dlg, "")
            if len(text) + 1 > size:
                return 0
            self.write_mem_string(text, buf, cw)
            return len(text)

        reg("GetDlgItemTextW", GetDlgItemText_impl, 4)
        reg("GetDlgItemTextA", GetDlgItemText_impl, 4)

        def SetDlgItemText_impl(self, emu, argv, ctx=None):
            dlg, id_, text = argv
            if not text:
                return False
            ctx, cw = self.prepare_ctx(ctx)
            self.window_text[dlg] = self.read_mem_string(text, cw)
            return True

        reg("SetDlgItemTextW", SetDlgItemText_impl, 3)
        reg("SetDlgItemTextA", SetDlgItemText_impl, 3)

        def GetDlgItemInt_impl(self, emu, argv, ctx=None):
            dlg, id_, trans, signed = argv
            return 0

        reg("GetDlgItemInt", GetDlgItemInt_impl, 4)

        def GetKeyNameText_impl(self, emu, argv, ctx=None):
            lparam, buf, size = argv
            if not buf:
                return 0
            self.write_string("", buf)
            return 0

        reg("GetKeyNameTextW", GetKeyNameText_impl, 3)
        reg("GetKeyNameTextA", GetKeyNameText_impl, 3)

        def MapVirtualKey_impl(self, emu, argv, ctx=None):
            code, maptype = argv
            return code & 0xFF

        reg("MapVirtualKeyW", MapVirtualKey_impl, 2)
        reg("MapVirtualKeyA", MapVirtualKey_impl, 2)
        reg("MapVirtualKeyExW", MapVirtualKey_impl, 3)
        reg("MapVirtualKeyExA", MapVirtualKey_impl, 3)

        def VkKeyScan_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFF
            if 0x61 <= c <= 0x7A:
                c -= 0x20
            return c

        reg("VkKeyScanW", VkKeyScan_impl, 1)
        reg("VkKeyScanA", VkKeyScan_impl, 1)

        def GetKeyboardState_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if not out:
                return False
            self.mem_write(out, b"\x00" * 256)
            return True

        reg("GetKeyboardState", GetKeyboardState_impl, 1)

        def SetKeyboardState_impl(self, emu, argv, ctx=None):
            return True

        reg("SetKeyboardState", SetKeyboardState_impl, 1)

        def ToAscii_impl(self, emu, argv, ctx=None):
            vk, scan, state, out, flags = argv
            if not out:
                return 0
            self.mem_write(out, b"\x00\x00")
            return 0

        reg("ToAscii", ToAscii_impl, 5)
        reg("ToUnicode", ToAscii_impl, 6)

        def GetKeyboardLayoutName_impl(self, emu, argv, ctx=None):
            buf = argv[0]
            if not buf:
                return False
            self.write_wide_string("00000409", buf)
            return True

        reg("GetKeyboardLayoutNameW", GetKeyboardLayoutName_impl, 1)
        reg("GetKeyboardLayoutNameA", GetKeyboardLayoutName_impl, 1)

        def LoadKeyboardLayout_impl(self, emu, argv, ctx=None):
            return 0x4090409

        reg("LoadKeyboardLayoutW", LoadKeyboardLayout_impl, 2)
        reg("LoadKeyboardLayoutA", LoadKeyboardLayout_impl, 2)

        def GetKeyboardLayout_impl(self, emu, argv, ctx=None):
            return 0x4090409

        reg("GetKeyboardLayout", GetKeyboardLayout_impl, 1)

        def ActivateKeyboardLayout_impl(self, emu, argv, ctx=None):
            return argv[0]

        reg("ActivateKeyboardLayout", ActivateKeyboardLayout_impl, 2)

        def GetDoubleClickTime_impl(self, emu, argv, ctx=None):
            return 500

        reg("GetDoubleClickTime", GetDoubleClickTime_impl, 0)

        def SetDoubleClickTime_impl(self, emu, argv, ctx=None):
            return True

        reg("SetDoubleClickTime", SetDoubleClickTime_impl, 1)

        def WindowFromPoint_impl(self, emu, argv, ctx=None):
            return 0

        reg("WindowFromPoint", WindowFromPoint_impl, 1)

        def ChildWindowFromPoint_impl(self, emu, argv, ctx=None):
            hwnd, pt = argv
            return 0

        reg("ChildWindowFromPoint", ChildWindowFromPoint_impl, 2)

        def GetMessageExtraInfo_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetMessageExtraInfo", GetMessageExtraInfo_impl, 0)

        def SetMessageExtraInfo_impl(self, emu, argv, ctx=None):
            return argv[0]

        reg("SetMessageExtraInfo", SetMessageExtraInfo_impl, 1)

        def GetSystemMenu_impl(self, emu, argv, ctx=None):
            hwnd, revert = argv
            return 0

        reg("GetSystemMenu", GetSystemMenu_impl, 2)

        def CreatePopupMenu_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("CreatePopupMenu", CreatePopupMenu_impl, 0)

        def DestroyMenu_impl(self, emu, argv, ctx=None):
            return True

        reg("DestroyMenu", DestroyMenu_impl, 1)

        def AppendMenu_impl(self, emu, argv, ctx=None):
            menu, flags, id_, text = argv
            return True

        reg("AppendMenuW", AppendMenu_impl, 4)
        reg("AppendMenuA", AppendMenu_impl, 4)

        def GetMenuItemCount_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetMenuItemCount", GetMenuItemCount_impl, 1)

        def TrackPopupMenu_impl(self, emu, argv, ctx=None):
            return False

        reg("TrackPopupMenu", TrackPopupMenu_impl, 7)

        def DrawIcon_impl(self, emu, argv, ctx=None):
            return True

        reg("DrawIcon", DrawIcon_impl, 4)

        def DrawIconEx_impl(self, emu, argv, ctx=None):
            return True

        reg("DrawIconEx", DrawIconEx_impl, 9)

        def LoadImage_impl(self, emu, argv, ctx=None):
            inst, name, typ, cx, cy, flags = argv
            return self.get_handle()

        reg("LoadImageW", LoadImage_impl, 6)
        reg("LoadImageA", LoadImage_impl, 6)

        def LoadIcon_impl(self, emu, argv, ctx=None):
            return self.get_handle()

        reg("LoadIconW", LoadIcon_impl, 2)
        reg("LoadIconA", LoadIcon_impl, 2)

        def GetIconInfo_impl(self, emu, argv, ctx=None):
            icon, out = argv
            if not out:
                return False
            self.mem_write(out, b"\x00" * 40)
            return False

        reg("GetIconInfo", GetIconInfo_impl, 2)

        def DestroyIcon_impl(self, emu, argv, ctx=None):
            return True

        reg("DestroyIcon", DestroyIcon_impl, 1)

        def IsDialogMessage_impl(self, emu, argv, ctx=None):
            return False

        reg("IsDialogMessageW", IsDialogMessage_impl, 2)
        reg("IsDialogMessageA", IsDialogMessage_impl, 2)

        def GetDlgCtrlID_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetDlgCtrlID", GetDlgCtrlID_impl, 1)

        def SetWindowRgn_impl(self, emu, argv, ctx=None):
            return 0

        reg("SetWindowRgn", SetWindowRgn_impl, 3)

        def GetWindowRgn_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetWindowRgn", GetWindowRgn_impl, 2)

        def RedrawWindow_impl(self, emu, argv, ctx=None):
            return True

        reg("RedrawWindow", RedrawWindow_impl, 4)

        def UpdateLayeredWindow_impl(self, emu, argv, ctx=None):
            return True

        reg("UpdateLayeredWindow", UpdateLayeredWindow_impl, 9)

        def GetLayeredWindowAttributes_impl(self, emu, argv, ctx=None):
            return False

        reg("GetLayeredWindowAttributes", GetLayeredWindowAttributes_impl, 4)

        def SetLayeredWindowAttributes_impl(self, emu, argv, ctx=None):
            return True

        reg("SetLayeredWindowAttributes", SetLayeredWindowAttributes_impl, 4)

        def ScrollWindow_impl(self, emu, argv, ctx=None):
            return True

        reg("ScrollWindow", ScrollWindow_impl, 5)

        def ScrollWindowEx_impl(self, emu, argv, ctx=None):
            return 0

        reg("ScrollWindowEx", ScrollWindowEx_impl, 8)

        def GetScrollInfo_impl(self, emu, argv, ctx=None):
            hwnd, bar, info = argv
            if info:
                self.mem_write(info, b"\x00" * 28)
            return False

        reg("GetScrollInfo", GetScrollInfo_impl, 3)

        def SetScrollInfo_impl(self, emu, argv, ctx=None):
            return 0

        reg("SetScrollInfo", SetScrollInfo_impl, 4)

        def GetScrollPos_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetScrollPos", GetScrollPos_impl, 2)

        def SetScrollPos_impl(self, emu, argv, ctx=None):
            return 0

        reg("SetScrollPos", SetScrollPos_impl, 4)

        def EnableScrollBar_impl(self, emu, argv, ctx=None):
            return True

        reg("EnableScrollBar", EnableScrollBar_impl, 3)

        def GetWindowInfo_impl(self, emu, argv, ctx=None):
            hwnd, info = argv
            if info:
                self.mem_write(info, b"\x00" * 60)
            return True

        reg("GetWindowInfo", GetWindowInfo_impl, 2)

        def GetTitleBarInfo_impl(self, emu, argv, ctx=None):
            hwnd, info = argv
            if info:
                self.mem_write(info, b"\x00" * 44)
            return True

        reg("GetTitleBarInfo", GetTitleBarInfo_impl, 2)

        def GetMenuBarInfo_impl(self, emu, argv, ctx=None):
            return False

        reg("GetMenuBarInfo", GetMenuBarInfo_impl, 4)

        def FlashWindow_impl(self, emu, argv, ctx=None):
            return False

        reg("FlashWindow", FlashWindow_impl, 2)

        def FlashWindowEx_impl(self, emu, argv, ctx=None):
            return True

        reg("FlashWindowEx", FlashWindowEx_impl, 1)

        def SetForegroundWindow_impl(self, emu, argv, ctx=None):
            return True

        reg("SetForegroundWindow", SetForegroundWindow_impl, 1)

        def GetForegroundWindow_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetForegroundWindow", GetForegroundWindow_impl, 0)

        def GetWindowLongPtr_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetWindowLongPtrW", GetWindowLongPtr_impl, 2)
        reg("GetWindowLongPtrA", GetWindowLongPtr_impl, 2)

        def GetUserObjectInformation_impl(self, emu, argv, ctx=None):
            obj, index, info, size, needed = argv
            if needed:
                self.mem_write(needed, b"\x00\x00\x00\x00")
            return False

        reg("GetUserObjectInformationW", GetUserObjectInformation_impl, 5)
        reg("GetUserObjectInformationA", GetUserObjectInformation_impl, 5)

        def GetProcessWindowStation_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetProcessWindowStation", GetProcessWindowStation_impl, 0)

        def GetThreadDesktop_impl(self, emu, argv, ctx=None):
            return 0

        reg("GetThreadDesktop", GetThreadDesktop_impl, 1)

        def OpenInputDesktop_impl(self, emu, argv, ctx=None):
            return 0

        reg("OpenInputDesktop", OpenInputDesktop_impl, 3)

        def GetWindowTextLength_impl(self, emu, argv, ctx=None):
            hwnd = argv[0]
            return len(self.window_text.get(hwnd, ""))

        reg("GetWindowTextLengthW", GetWindowTextLength_impl, 1)
        reg("GetWindowTextLengthA", GetWindowTextLength_impl, 1)

    def get_synthetic_async_key_state(self, vkey):
        if self.synthetic_async_key_index >= len(self.synthetic_async_keys):
            return 0

        if vkey != self.synthetic_async_keys[self.synthetic_async_key_index]:
            return 0

        self.synthetic_async_key_index += 1
        return 0x8001

    def get_synthetic_keyboard_hook(self):
        for _, hook in self.window_hooks.items():
            if len(hook) == 3 and hook[0] == windefs.WH_KEYBOARD_LL:
                return hook
        return None

    def emit_synthetic_keyboard_hook_event(self, emu, caller_argv):
        hook = self.get_synthetic_keyboard_hook()
        if not hook:
            return None

        if self.synthetic_hook_key_index >= len(self.synthetic_hook_keys):
            return None

        hook_index = self.synthetic_hook_key_index
        vkey = self.synthetic_hook_keys[hook_index]
        self.synthetic_hook_key_index += 1

        wparam = windefs.WM_KEYDOWN if (hook_index % 2 == 0) else windefs.WM_SYSKEYDOWN

        kbd = windefs.KBDLLHOOKSTRUCT(emu.get_ptr_size())
        kbd.vkCode = vkey
        kbd.scanCode = 0
        kbd.flags = 0
        kbd.time = 0
        kbd.dwExtraInfo = 0

        kbd_ptr = self.mem_alloc(kbd.sizeof(), tag="api.user32.kbdllhook")
        self.mem_write(kbd_ptr, kbd.get_bytes())

        _, lpfn, _ = hook
        self.setup_callback(lpfn, (0, wparam, kbd_ptr), caller_argv=caller_argv)
        return wparam, vkey

    def find_string_resource_by_id(self, pe, uID):
        pe_metadata = pe.get_pe_metadata()
        if not pe_metadata:
            return None
        return pe_metadata.string_table.get(uID)

    @apihook("GetDesktopWindow", argc=0)
    def GetDesktopWindow(self, emu, argv, ctx: api.ApiContext = None):
        """HWND GetDesktopWindow();"""

        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("ShowWindow", argc=2)
    def ShowWindow(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL ShowWindow(
          HWND hWnd,
          int  nCmdShow
        );"""

        rv = 1

        return rv

    @apihook("CreateWindowStation", argc=4)
    def CreateWindowStation(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWINSTA CreateWindowStation(
            LPCSTR                lpwinsta,
            DWORD                 dwFlags,
            ACCESS_MASK           dwDesiredAccess,
            LPSECURITY_ATTRIBUTES lpsa
        );
        """
        winsta, flags, access, sa = argv

        return self.get_handle()

    @apihook("SetProcessWindowStation", argc=1)
    def SetProcessWindowStation(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SetProcessWindowStation(
            HWINSTA hWinSta
        );
        """
        (winsta,) = argv

        rv = False
        if winsta:
            rv = True

        return rv

    @apihook("GetDC", argc=1)
    def GetDC(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDC GetDC(
          HWND hWnd
        );
        """

        rv = self.sessman.get_device_context()

        return rv

    @apihook("RegisterClassEx", argc=1)
    def RegisterClassEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        ATOM RegisterClassEx(
            const WNDCLASSEXA *Arg1
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        (Arg1,) = argv
        wclass = windefs.WNDCLASSEX(emu.get_ptr_size())
        wclass = self.mem_cast(wclass, Arg1)

        cn = None
        if wclass.lpszClassName:
            cn = self.read_mem_string(wclass.lpszClassName, cw)

        atom = self.sessman.create_window_class(wclass, cn)

        return atom

    @apihook("UnregisterClass", argc=2)
    def UnregisterClass(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL UnregisterClass(
            LPCSTR    lpClassName,
            HINSTANCE hInstance
        );
        """

        return 1

    @apihook("SetCursorPos", argc=2)
    def SetCursorPos(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SetCursorPos(
        int X,
        int Y
        );
        """
        return 1

    @apihook("CloseDesktop", argc=1)
    def CloseDesktop(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CloseDesktop(
        HDESK hDesktop
        );
        """
        return 1

    @apihook("CloseWindowStation", argc=1)
    def CloseWindowStation(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CloseWindowStation(
        HWINSTA hWinSta
        );
        """
        return 1

    @apihook("GetThreadDesktop", argc=1)
    def GetThreadDesktop(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDESK GetThreadDesktop(
        DWORD dwThreadId
        );
        """
        return 1

    @apihook("OpenWindowStation", argc=3)
    def OpenWindowStation(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWINSTA OpenWindowStation(
        LPCSTR      lpszWinSta,
        BOOL        fInherit,
        ACCESS_MASK dwDesiredAccess
        );
        """
        return 1

    @apihook("ChangeWindowMessageFilter", argc=2)
    def ChangeWindowMessageFilter(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL ChangeWindowMessageFilter(
            UINT  message,
            DWORD dwFlag
        );
        """
        msg, flag = argv
        emu.enable_code_hook()
        return True

    @apihook("UpdateWindow", argc=1)
    def UpdateWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL UpdateWindow(
            HWND hWnd
        );
        """
        (hnd,) = argv
        window = self.sessman.get_window(hnd)
        if not window:
            return False

        wc = self.sessman.get_window_class(window.class_name)
        if wc.wclass.lpfnWndProc:
            cb_args = (hnd, windefs.WM_PAINT, 0, 0)
            self.setup_callback(wc.wclass.lpfnWndProc, cb_args, caller_argv=argv)

        return True

    @apihook("PostQuitMessage", argc=1)
    def PostQuitMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        void PostQuitMessage(
            int nExitCode
        );
        """
        return

    @apihook("DestroyWindow", argc=1)
    def DestroyWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL DestroyWindow(
            HWND hWnd
        );
        """
        return True

    @apihook("DefWindowProc", argc=4)
    def DefWindowProc(self, emu, argv, ctx: api.ApiContext = None):
        """
        LRESULT LRESULT DefWindowProc(
            HWND   hWnd,
            UINT   Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        return 0

    @apihook("CreateWindowEx", argc=12)
    def CreateWindowEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND CreateWindowExA(
            DWORD     dwExStyle,
            LPCSTR    lpClassName,
            LPCSTR    lpWindowName,
            DWORD     dwStyle,
            int       X,
            int       Y,
            int       nWidth,
            int       nHeight,
            HWND      hWndParent,
            HMENU     hMenu,
            HINSTANCE hInstance,
            LPVOID    lpParam
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        _, cn, wn, _, x, y, width, height, parent, menu, inst, param = argv
        if cn:
            cn = self.read_mem_string(cn, cw)
            argv[1] = cn
        else:
            cn = None
        if wn:
            wn = self.read_mem_string(wn, cw)
            argv[2] = wn
        else:
            wn = None
        hnd = self.sessman.create_window(wn, cn)
        return hnd

    @apihook("SetLayeredWindowAttributes", argc=4)
    def SetLayeredWindowAttributes(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SetLayeredWindowAttributes(
          [in] HWND     hwnd,
          [in] COLORREF crKey,
          [in] BYTE     bAlpha,
          [in] DWORD    dwFlags
        );
        """
        hwnd, crKey, bAlpha, dwFlags = argv
        return 1

    @apihook("MessageBox", argc=4)
    def MessageBox(self, emu, argv, ctx: api.ApiContext = None):
        """int MessageBox(
          HWND    hWnd,
          LPCTSTR lpText,
          LPCTSTR lpCaption,
          UINT    uType
        );"""
        ctx, cw = self.prepare_ctx(ctx)
        hWnd, lpText, lpCaption, uType = argv


        if lpText:
            text = self.read_mem_string(lpText, cw)
            argv[1] = text
        if lpCaption:
            cap = self.read_mem_string(lpCaption, cw)
            argv[2] = cap
        rv = IDCANCEL

        return rv

    @apihook("MessageBoxEx", argc=5)
    def MessageBoxEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        int MessageBoxExA(
            HWND   hWnd,
            LPCSTR lpText,
            LPCSTR lpCaption,
            UINT   uType,
            WORD   wLanguageId
        );
        """
        ctx = ctx or {}
        av = argv[:-1]
        rv = self.MessageBox(emu, av, ctx)
        argv[:4] = av
        return rv

    @apihook("LoadString", argc=4)
    def LoadString(self, emu, argv, ctx: api.ApiContext = None):
        """
        int LoadStringW(
          HINSTANCE hInstance,
          UINT      uID,
          LPWSTR    lpBuffer,
          int       cchBufferMax
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        hInstance, uID, lpBuffer, ccBufferMax = argv
        size = 0

        if hInstance == 0:
            pe = emu.modules[0] if emu.modules else None
        else:
            pe = emu.get_mod_from_addr(hInstance)
            if pe and hInstance != pe.base:
                return 0

        if not pe:
            return 0

        s = self.find_string_resource_by_id(pe, uID)
        if s is None:
            # self.logger.info("unable to find resource string id %04X" % uID)
            return 0

        if cw == 2:
            encoded = s.encode("utf-16le")
        elif cw == 1:
            encoded = s.encode("utf-8")

        size = int(len(encoded) / cw)

        if size == 0:
            # self.logger.debug("resource id %04X not found" % uID)
            return 0

        if ccBufferMax == 0:
            # Returning a pointer to the resource string is not supported without raw access
            return 0

        if len(encoded) > ccBufferMax:
            encoded = encoded[: ccBufferMax * cw]

        emu.mem_write(lpBuffer, encoded)
        if cw == 1:
            argv[2] = s
        else:
            argv[2] = s

        return len(encoded)

    @apihook("GetCursorPos", argc=1)
    def GetCursorPos(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetCursorPos(
          LPPOINT lpPoint
        );
        """

        (lpPoint,) = argv

        rv = 0
        return rv

    @apihook("GetAsyncKeyState", argc=1)
    def GetAsyncKeyState(self, emu, argv, ctx: api.ApiContext = None):
        """
        SHORT GetAsyncKeyState(
          [in] int vKey
        );
        """

        (vkey,) = argv
        return self.get_synthetic_async_key_state(vkey)

    @apihook("GetKeyboardType", argc=1)
    def GetKeyboardType(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetKeyboardType(
          int nTypeFlag
        );
        """
        (_type,) = argv
        if _type == 0:
            return 4
        elif _type == 1:
            return 0
        elif _type == 2:
            return 12
        return 0

    @apihook("GetSystemMetrics", argc=1)
    def GetSystemMetrics(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetSystemMetrics(
          int nIndex
        );
        """

        (nIndex,) = argv

        rv = 1
        return rv

    @apihook("LoadBitmap", argc=2)
    def LoadBitmap(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP LoadBitmap(
            HINSTANCE hInstance,
            LPCSTR    lpBitmapName
        );
        """
        hInstance, lpBitmapName = argv
        rv = self.get_handle()
        return rv

    @apihook("GetClientRect", argc=2)
    def GetClientRect(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetClientRect(
          [in]  HWND   hWnd,
          [out] LPRECT lpRect
        );
        """
        return 0

    @apihook("RegisterWindowMessage", argc=1)
    def RegisterWindowMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT RegisterWindowMessageA(
          LPCSTR lpString
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        (lpString,) = argv
        rv = 0xC000


        s = self.read_mem_string(lpString, cw)
        argv[0] = s

        return rv

    @apihook("wsprintf", argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def wsprintf(self, emu, argv, ctx: api.ApiContext = None):
        """
        int WINAPIV wsprintf(
          LPSTR  ,
          LPCSTR ,
          ...
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        buf, fmt = emu.get_func_argv(_arch.CALL_CONV_CDECL, 2)
        fmt_str = self.read_mem_string(fmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        if not fmt_cnt:
            self.write_mem_string(fmt_str, buf, cw)
            return len(fmt_str)

        _args = emu.get_func_argv(_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _args)

        self.write_mem_string(fin, buf, cw)

        argv.append(fin)
        argv.append(fmt_str)
        return len(fin)

    @apihook("PeekMessage", argc=5)
    def PeekMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL PeekMessageA(
            LPMSG lpMsg,
            HWND  hWnd,
            UINT  wMsgFilterMin,
            UINT  wMsgFilterMax,
            UINT  wRemoveMsg
        );
        """
        return False

    @apihook("PostMessage", argc=4)
    def PostMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL PostMessage(
            HWND   hWnd,
            UINT   Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        return True

    @apihook("SendMessage", argc=4)
    def SendMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        LRESULT SendMessage(
            HWND   hWnd,
            UINT   Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hWnd, Msg, wParam, lParam = argv
        if hWnd in self.wndprocs:
            emu.set_pc(self.wndprocs[hWnd])

        return False

    @apihook("CallNextHookEx", argc=4)
    def CallNextHookEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        LRESULT CallNextHookEx(
            HHOOK  hhk,
            int    nCode,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hhk, nCode, wParam, lParam = argv
        return 0

    @apihook("SetWindowsHookEx", argc=4)
    def SetWindowsHookEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        HHOOK SetWindowsHookEx(
            int       idHook,
            HOOKPROC  lpfn,
            HINSTANCE hmod,
            DWORD     dwThreadId
        );
        """
        idHook, lpfn, hmod, dwThreadId = argv

        hname = windefs.get_windowhook_flags(idHook)
        if hname:
            hname = hname[0]
            argv[0] = hname

        hnd = self.get_handle()
        self.window_hooks.update({hnd: (idHook, lpfn, hmod)})
        return hnd

    @apihook("UnhookWindowsHookEx", argc=1)
    def UnhookWindowsHookEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL UnhookWindowsHookEx(
            HHOOK hhk
        );
        """
        (hhk,) = argv

        rv = False
        if self.window_hooks.get(hhk):
            self.window_hooks.pop(hhk)
            rv = True
        return rv

    @apihook("MsgWaitForMultipleObjects", argc=5)
    def MsgWaitForMultipleObjects(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD MsgWaitForMultipleObjects(
            DWORD        nCount,
            const HANDLE *pHandles,
            BOOL         fWaitAll,
            DWORD        dwMilliseconds,
            DWORD        dwWakeMask
        );
        """
        return 0

    @apihook("GetMessage", argc=4)
    def GetMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetMessage(
            LPMSG lpMsg,
            HWND  hWnd,
            UINT  wMsgFilterMin,
            UINT  wMsgFilterMax
        );
        """
        lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax = argv

        t = emu.get_current_thread()
        msg = None

        try:
            msg = t.message_queue.pop(0)
        except IndexError:
            if self.timer_count > 0:
                msg = windefs.MSG(emu.get_ptr_size())
                msg.hwnd = hWnd
                msg.message = windefs.WM_TIMER
            else:
                synthetic = self.emit_synthetic_keyboard_hook_event(emu, argv)
                if synthetic is None:
                    return False
                if lpMsg:
                    wparam, vkey = synthetic
                    msg = windefs.MSG(emu.get_ptr_size())
                    msg.hwnd = hWnd
                    msg.message = wparam
                    msg.wParam = vkey
                    msg.lParam = 0
                else:
                    return True

        if lpMsg:
            self.mem_write(lpMsg, msg.get_bytes())

        return True

    @apihook("TranslateMessage", argc=1)
    def TranslateMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL TranslateMessage(
            const MSG *lpMsg
        );
        """
        return True

    @apihook("DispatchMessage", argc=1)
    def DispatchMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        LRESULT DispatchMessage(
            const MSG *lpMsg
        );
        """
        (lpMsg,) = argv

        msg = windefs.MSG(emu.get_ptr_size())
        msg = self.mem_cast(msg, lpMsg)

        return 0

    @apihook("GetForegroundWindow", argc=0)
    def GetForegroundWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetForegroundWindow();
        """
        return self.get_handle()

    @apihook("LoadCursor", argc=2)
    def LoadCursor(self, emu, argv, ctx: api.ApiContext = None):
        """
        HCURSOR LoadCursor(
        HINSTANCE hInstance,
        LPCSTR    lpCursorName
        );
        """
        return self.get_handle()

    @apihook("FindWindow", argc=2)
    def FindWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND FindWindow(
            LPCSTR lpClassName,
            LPCSTR lpWindowName
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        lpClassName, lpWindowName = argv
        if lpClassName:
            cn = self.read_mem_string(lpClassName, cw)
            argv[0] = cn
        if lpWindowName:
            wn = self.read_mem_string(lpWindowName, cw)
            argv[1] = wn
        return 0

    @apihook("GetWindowText", argc=3)
    def GetWindowText(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetWindowText(
            HWND  hWnd,
            LPSTR lpString,
            int   nMaxCount
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        hnd, pstr, maxc = argv

        win_text = self.window_text.get(hnd, "")
        win_text = win_text[: max(maxc, 0)]
        if pstr:
            if cw == 2:
                wt = (win_text).encode("utf-16le")
            else:
                wt = (win_text).encode("utf-8")
            self.mem_write(pstr, wt)

        return len(win_text)

    @apihook("PaintDesktop", argc=1)
    def PaintDesktop(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL PaintDesktop(
        HDC hdc
        );
        """
        return 0

    @apihook("wvsprintf", argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def wvsprintf(self, emu, argv, ctx: api.ApiContext = None):
        ctx, cw = self.prepare_ctx(ctx)
        buf, fmt, va_list = emu.get_func_argv(_arch.CALL_CONV_CDECL, 3)[:3]
        fmt_str = self.read_mem_string(fmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(va_list, fmt_cnt)
        fin = self.do_str_format(fmt_str, vargs)
        self.write_string(fin, buf)
        argv.clear()
        argv.append(fin)
        argv.append(fmt_str)
        return len(fin)

    @apihook("ReleaseDC", argc=2)
    def ReleaseDC(self, emu, argv, ctx: api.ApiContext = None):
        """
        int ReleaseDC(
          HWND hWnd,
          HDC  hDC
        );
        """
        return 0

    @apihook("CharNext", argc=1)
    def CharNext(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPSTR CharNext(
            LPCSTR lpsz
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        (s,) = argv
        rv = 0
        if s:
            rv = s + cw
        return rv

    @apihook("CharPrev", argc=2)
    def CharPrev(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPSTR CharPrev(
            LPCSTR lpszStart,
            LPCSTR lpszCurrent
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        """
        Got this from wine.          
        https://github.com/wine-mirror/wine/blob/a8c1d5c108fc57e4d78e9db126f395c89083a83d/dlls/kernelbase/string.c
        """
        s, c = argv
        while s < c:
            n = s + cw
            if n >= c:
                break
            s = n

        return s

    @apihook("EnumWindows", argc=2)
    def EnumWindows(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL EnumWindows(
            WNDENUMPROC lpEnumFunc,
            LPARAM      lParam
        );
        """
        lpEnumFunc, lParam = argv
        rv = 1

        return rv

    @apihook("GetSysColor", argc=1)
    def GetSysColor(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GetSysColor(
            int nIndex
        );
        """
        (nIndex,) = argv
        rv = 1

        return rv

    @apihook("GetParent", argc=1)
    def GetParent(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetParent(
            HWND hWnd
        );
        """
        return self.get_handle()

    @apihook("GetSysColorBrush", argc=1)
    def GetSysColorBrush(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBRUSH GetSysColorBrush(
            int nIndex
        );
        """
        (nIndex,) = argv
        rv = 1

        return rv

    @apihook("GetWindowLong", argc=2)
    def GetWindowLong(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG GetWindowLongA(
            HWND hWnd,
            int  nIndex
        );
        """
        (
            hWnd,
            nIndex,
        ) = argv
        rv = 2

        return rv

    @apihook("SetWindowLong", argc=3)
    def SetWindowLong(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG SetWindowLongA(
          HWND hWnd,
          int  nIndex,
          LONG dwNewLong
        );
        """
        hWnd, nIndex, dwNewLong = argv
        if (self.get_ptr_size() == 4 and nIndex == 0xFFFFFFFC) or (
            self.get_ptr_size() == 8 and nIndex == 0xFFFFFFFFFFFFFFFC
        ):
            self.wndprocs[hWnd] = dwNewLong

        return 1

    @apihook("DialogBoxParam", argc=5)
    def DialogBoxParam(self, emu, argv, ctx: api.ApiContext = None):
        """
        INT_PTR DialogBoxParam(
            HINSTANCE hInstance,
            LPCSTR    lpTemplateName,
            HWND      hWndParent,
            DLGPROC   lpDialogFunc,
            LPARAM    dwInitParam
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam = argv
        rv = self.get_handle()
        if lpTemplateName:
            tname = self.read_mem_string(lpTemplateName, cw)
            argv[1] = tname

        return rv

    @apihook("CreateDialogIndirectParam", argc=5)
    def CreateDialogIndirectParam(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND CreateDialogIndirectParam(
        HINSTANCE       hInstance,
        LPCDLGTEMPLATEA lpTemplate,
        HWND            hWndParent,
        DLGPROC         lpDialogFunc,
        LPARAM          dwInitParam
        );
        """

        (
            hnd,
            template,
            hnd_parent,
            func,
            param,
        ) = argv

        cb_args = (hnd_parent, windefs.WM_INITDIALOG, param, 0)
        self.setup_callback(func, cb_args, caller_argv=argv)
        return self.get_handle()

    @apihook("GetMenuInfo", argc=2)
    def GetMenuInfo(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetMenuInfo(
            HMENU,
            LPMENUINFO
        );
        """
        return 1

    @apihook("GetProcessWindowStation", argc=0)
    def GetProcessWindowStation(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWINSTA GetProcessWindowStation();
        """
        sta = self.sessman.get_current_station()
        return sta.get_handle()

    @apihook("LoadAccelerators", argc=2)
    def LoadAccelerators(self, emu, argv, ctx: api.ApiContext = None):
        """
        HACCEL LoadAccelerators(
        HINSTANCE hInstance,
        LPCSTR    lpTableName
        );
        """
        return self.get_handle()

    @apihook("IsWindowVisible", argc=1)
    def IsWindowVisible(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL IsWindowVisible(
        HWND hWnd
        );
        """
        return True

    @apihook("BeginPaint", argc=2)
    def BeginPaint(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDC BeginPaint(
        HWND          hWnd,
        LPPAINTSTRUCT lpPaint
        );
        """
        return self.get_handle()

    @apihook("LookupIconIdFromDirectory", argc=2)
    def LookupIconIdFromDirectory(self, emu, argv, ctx: api.ApiContext = None):
        """
        int LookupIconIdFromDirectory(
        PBYTE presbits,
        BOOL  fIcon
        );
        """
        return 1

    @apihook("GetActiveWindow", argc=0)
    def GetActiveWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetActiveWindow();
        """
        return self.get_handle()

    @apihook("GetLastActivePopup", argc=1)
    def GetLastActivePopup(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetLastActivePopup(
        HWND hWnd
        );
        """
        (hWnd,) = argv
        return self.get_handle()

    @apihook("GetUserObjectInformation", argc=5)
    def GetUserObjectInformation(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetUserObjectInformation(
            HANDLE  hObj,
            int     nIndex,
            PVOID   pvInfo,
            DWORD   nLength,
            LPDWORD lpnLengthNeeded
        );
        """
        obj, index, info, length, needed = argv

        if index == UOI_FLAGS:
            uoi = windefs.USEROBJECTFLAGS(emu.get_ptr_size())
            uoi.fInherit = 1
            uoi.dwFlags = 1

            if info:
                self.mem_write(info, uoi.get_bytes())

        return True

    @apihook("LoadIcon", argc=2)
    def LoadIcon(self, emu, argv, ctx: api.ApiContext = None):
        """
        HICON LoadIcon(
            HINSTANCE hInstance,
            LPCSTR    lpIconName
        );
        """
        (
            inst,
            name,
        ) = argv

        if name not in (
            IDI_APPLICATION,
            IDI_ASTERISK,
            IDI_ERROR,
            IDI_EXCLAMATION,
            IDI_HAND,
            IDI_INFORMATION,
            IDI_QUESTION,
            IDI_SHIELD,
            IDI_WARNING,
            IDI_WINLOGO,
        ):
            return 0
        return 1

    @apihook("GetRawInputDeviceList", argc=3)
    def GetRawInputDeviceList(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT GetRawInputDeviceList(
          PRAWINPUTDEVICELIST pRawInputDeviceList,
          PUINT               puiNumDevices,
          UINT                cbSize
        );
        """
        pRawInputDeviceList, puiNumDevices, cbSize = argv
        num_devices = 4
        self.mem_write(puiNumDevices, num_devices.to_bytes(4, "little"))
        return num_devices

    @apihook("GetNextDlgTabItem", argc=3)
    def GetNextDlgTabItem(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetNextDlgTabItem(
          HWND hDlg,
          HWND hCtl,
          BOOL bPrevious
        );
        """
        return 0

    @apihook("GetCaretPos", argc=1)
    def GetCaretPos(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetCaretPos(
          LPPOINT lpPoint
        );
        """
        lpPoint = argv[0]
        point = windef.POINT(emu.get_ptr_size())
        point.x = 0
        point.y = 0
        self.mem_write(lpPoint, self.get_bytes(point))
        return 1

    @apihook("GetMonitorInfo", argc=2)
    def GetMonitorInfo(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetMonitorInfo(
          HMONITOR      hMonitor,
          LPMONITORINFO lpmi
        );
        """
        hMonitor, lpmi = argv
        mi = windef.MONITORINFO(emu.get_ptr_size())
        mi = self.mem_cast(mi, lpmi)
        # just a stub for now
        self.mem_write(lpmi, self.get_bytes(mi))
        return 1

    @apihook("EndPaint", argc=2)
    def EndPaint(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL EndPaint(
          HWND              hWnd,
          const PAINTSTRUCT *lpPaint
        );
        """
        return 1

    @apihook("GetDlgCtrlID", argc=1)
    def GetDlgCtrlID(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetDlgCtrlID(
          HWND hWnd
        );
        """
        return 1

    @apihook("GetUpdateRect", argc=3)
    def GetUpdateRect(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetUpdateRect(
          HWND   hWnd,
          LPRECT lpRect,
          BOOL   bErase
        );
        """
        return 0

    @apihook("GetAltTabInfo", argc=5)
    def GetAltTabInfo(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetAltTabInfoA(
          HWND        hwnd,
          int         iItem,
          PALTTABINFO pati,
          LPSTR       pszItemText,
          UINT        cchItemText
        );
        """
        return 0

    @apihook("GetUpdateRgn", argc=3)
    def GetUpdateRgn(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetUpdateRgn(
          HWND hWnd,
          HRGN hRgn,
          BOOL bErase
        );
        """
        return 0

    @apihook("FlashWindow", argc=2)
    def FlashWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL FlashWindow(
          HWND hWnd,
          BOOL bInvert
        );
        """
        return 1

    @apihook("IsClipboardFormatAvailable", argc=1)
    def IsClipboardFormatAvailable(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL IsClipboardFormatAvailable(
          UINT format
        );
        """
        return 0

    @apihook("IsWindow", argc=1)
    def IsWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL IsWindow(
            HWND hWnd
        );
        """
        (hnd,) = argv

        return True

    @apihook("EnableWindow", argc=2)
    def EnableWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL EnableWindow(
        HWND hWnd,
        BOOL bEnable
        );
        """
        hnd, bEnable = argv

        return False

    @apihook("CharLowerBuff", argc=2)
    def CharLowerBuff(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD CharLowerBuffA(
            LPSTR lpsz,
            DWORD cchLength
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        _str, cchLength = argv
        val = self.read_mem_string(_str, cw, max_chars=cchLength)
        argv[0] = val
        argv[1] = cchLength
        self.write_mem_string(val.lower(), _str, cw)
        return cchLength

    @apihook("CharUpperBuff", argc=2)
    def CharUpperBuff(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD CharUpperBuffA(
            LPSTR lpsz,
            DWORD cchLength
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        _str, cchLength = argv
        val = self.read_mem_string(_str, cw, max_chars=cchLength)
        argv[0] = val
        argv[1] = cchLength
        self.write_mem_string(val.upper(), _str, cw)
        return cchLength

    @apihook("CharLower", argc=1)
    def CharLower(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPSTR CharLowerA(
            LPSTR lpsz
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        (_str,) = argv
        bits = _str.bit_length()
        if bits <= 16:
            if cw == 1:
                val = chr(_str).lower().encode("ascii")
            else:
                val = chr(_str).lower().encode("utf-16le")
            return int.from_bytes(val, byteorder="little")
        else:
            val = self.read_mem_string(_str, cw)
            self.write_mem_string(val.lower(), _str, cw)
            return _str

    @apihook("CharUpper", argc=1)
    def CharUpper(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPSTR CharUpperA(
            LPSTR lpsz
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        (_str,) = argv
        bits = _str.bit_length()
        if bits <= 16:
            if cw == 1:
                val = chr(_str).upper().encode("ascii")
            else:
                val = chr(_str).upper().encode("utf-16le")
            return int.from_bytes(val, byteorder="little")
        else:
            val = self.read_mem_string(_str, cw)
            self.write_mem_string(val.upper(), _str, cw)
            return _str

    @apihook("SetTimer", argc=4)
    def SetTimer(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT_PTR SetTimer(
          HWND      hWnd,
          UINT_PTR  nIDEvent,
          UINT      uElapse,
          TIMERPROC lpTimerFunc
        );
        """
        self.timer_count += 1

        return self.get_handle()

    @apihook("KillTimer", argc=2)
    def KillTimer(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL KillTimer(
          HWND     hWnd,
          UINT_PTR uIDEvent
        );
        """
        self.timer_count -= 1

        return True

    @apihook("OpenDesktop", argc=4)
    def OpenDesktop(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDESK OpenDesktopA(
            LPCSTR      lpszDesktop,
            DWORD       dwFlags,
            BOOL        fInherit,
            ACCESS_MASK dwDesiredAccess
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        lpszDesktop, dwFlags, fInherit, dwDesiredAccess = argv
        desktop = self.read_mem_string(lpszDesktop, cw)
        argv[0] = desktop
        return self.get_handle()

    @apihook("SetThreadDesktop", argc=1)
    def SetThreadDesktop(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SetThreadDesktop(
            HDESK hDesktop
        );
        """
        return 0

    @apihook("GetKeyboardLayoutList", argc=2)
    def GetKeyboardLayoutList(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetKeyboardLayoutList(
          int nBuff,
          HKL *lpList
        );
        """
        nBuff, lpList = argv
        if not nBuff:
            # number of items
            return 1
        locale = 0x409  # English - United States
        self.mem_write(lpList, locale.to_bytes(2, "little"))
        self.mem_write(lpList + 4, locale.to_bytes(2, "little"))

        return 1

    @apihook("GetKBCodePage", argc=0)
    def GetKBCodePage(self, emu, argv, ctx: api.ApiContext = None):
        """
        INT GetKBCodePage();
        """
        # >>> ctypes.windll.user32.GetKBCodePage()
        # 437
        # https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
        return 437  # OEM United States

    @apihook("GetClipboardViewer", argc=0)
    def GetClipboardViewer(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetClipboardViewer();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetClipboardOwner", argc=0)
    def GetClipboardOwner(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetClipboardOwner();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetMenuCheckMarkDimensions", argc=0)
    def GetMenuCheckMarkDimensions(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG GetMenuCheckMarkDimensions();
        """
        # >>> ctypes.windll.user32.GetMenuCheckMarkDimensions()
        # 983055
        return 983055

    @apihook("GetOpenClipboardWindow", argc=0)
    def GetOpenClipboardWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetOpenClipboardWindow();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetFocus", argc=0)
    def GetFocus(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetFocus();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetCursor", argc=0)
    def GetCursor(self, emu, argv, ctx: api.ApiContext = None):
        """
        HCURSOR GetCursor();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetClipboardSequenceNumber", argc=0)
    def GetClipboardSequenceNumber(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GetClipboardSequenceNumber();
        """
        # >>> ctypes.windll.user32.GetClipboardSequenceNumber()
        # 295
        return 295

    @apihook("GetCaretBlinkTime", argc=0)
    def GetCaretBlinkTime(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT GetCaretBlinkTime();
        """
        # >>> ctypes.windll.user32.GetCaretBlinkTime()
        # 530
        return 530

    @apihook("GetDoubleClickTime", argc=0)
    def GetDoubleClickTime(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT GetDoubleClickTime();
        """
        # >>> ctypes.windll.user32.GetDoubleClickTime()
        # 500
        return 500

    @apihook("RegisterClipboardFormatA", argc=1)
    def RegisterClipboardFormatA(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT RegisterClipboardFormatA(
            LPCSTR lpszFormat
        );
        """
        # Return a fake clipboard format ID.
        # Clipboard format IDs start at 0xC000 for custom formats.
        return 0xC000

    @apihook("SystemParametersInfoA", argc=4)
    def SystemParametersInfoA(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SystemParametersInfoA(
            UINT  uiAction,
            UINT  uiParam,
            PVOID pvParam,
            UINT  fWinIni
        );
        """
        uiAction, uiParam, pvParam, fWinIni = argv

        # Many callers expect pvParam to be filled with something.
        # We return success without writing anything unless needed.
        return 1

    @apihook("GetKeyboardLayout", argc=1)
    def GetKeyboardLayout(self, emu, argv, ctx: api.ApiContext = None):
        """
        HKL GetKeyboardLayout(
            DWORD idThread
        );
        """
        # Return a fake HKL (keyboard layout handle).
        # Real HKLs are typically like 0x04090409 (LANG + device id).
        return 0x04090409

    @apihook("EnumDisplayMonitors", argc=4)
    def EnumDisplayMonitors(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL EnumDisplayMonitors(
            HDC             hdc,
            LPCRECT         lprcClip,
            MONITORENUMPROC lpfnEnum,
            LPARAM          dwData
        );
        """
        hdc, lprcClip, lpfnEnum, dwData = argv

        # Most callers expect TRUE to indicate success.
        # We do not invoke the callback — Speakeasy doesn't emulate monitor enumeration.
        return 1

    @apihook("OemToCharA", argc=2)
    def OemToCharA(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL OemToCharA(
            LPCSTR lpszSrc,
            LPSTR  lpszDst
        );
        """
        src, dst = argv

        # If destination buffer exists, copy source bytes into it.
        if src and dst:
            try:
                data = emu.mem_read(src, 256)
                try:
                    emu.mem_write(dst, data)
                except Exception:
                    base_addr = dst & ~0xFFF
                    emu.mem_map(base_addr, 0x1000)
                    emu.mem_write(dst, data)
            except Exception:
                pass

        # Return TRUE
        return 1

    @apihook("CharPrevW", argc=2)
    def CharPrevW(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPWSTR CharPrevW(
            LPCWSTR lpszStart,
            LPCWSTR lpszCurrent
        );
        """
        start, current = argv

        # If current > start, return current - 2 (one WCHAR back)
        try:
            if current and start and current > start:
                return current - 2
        except Exception:
            pass

        # Otherwise return start
        return start
