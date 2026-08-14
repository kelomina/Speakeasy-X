# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
import shlex
from typing import Any

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.shell32 as shell32_defs
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.profiler_events import PROC_CREATE

from .. import api


class Shell32(api.ApiHandler):
    """
    Implements exported functions from shell32.dll
    """

    name = "shell32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)

        self.funcs: dict[str, Any] = {}
        self.data: dict[str, Any] = {}
        self.window_hooks: dict[int, tuple] = {}
        self.handle: int = 0
        self.win: Any | None = None
        self.curr_handle: int = 0x2800

        super().__get_hook_attrs__(self)

        self._register_shell32_batch()

    def _register_shell32_batch(self):
        """Register real handlers for common shell32 helpers."""
        ptr = self.get_ptr_size()
        sd = _arch.CALL_CONV_STDCALL

        def reg(name, func, argc):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, sd, None)

        def _known_folder_path(csidl):
            user = getattr(self.emu.config, "user", None) if getattr(self.emu, "config", None) else None
            name = ""
            if user:
                name = getattr(user, "name", "") or ""
            paths = {
                0x00: "C:\\Windows\\Desktop",
                0x1A: f"C:\\Users\\{name}\\AppData\\Roaming",
                0x1C: f"C:\\Users\\{name}\\AppData\\Local",
                0x24: "C:\\Windows",
                0x25: "C:\\Windows\\system32",
                0x26: "C:\\Program Files",
                0x27: "C:\\Program Files (x86)",
                0x28: f"C:\\Users\\{name}",
                0x2E: f"C:\\Users\\{name}\\AppData\\Local\\Temp",
                0x2F: f"C:\\Users\\{name}\\AppData\\Local\\Temp",
            }
            return paths.get(csidl, "C:\\")

        def SHGetFolderPath(self, emu, argv, ctx=None):
            """
            HRESULT SHGetFolderPathW(
                HWND   hwndOwner,
                int    nFolder,
                HANDLE hToken,
                DWORD  dwFlags,
                LPWSTR pszPath
            );
            """
            ctx, cw = self.prepare_ctx(ctx)
            hwnd, folder, token, flags, out = argv
            if not out:
                return 0x80070057
            path = _known_folder_path(folder)
            self.write_mem_string(path, out, cw)
            self.record_file_access_event(path, "directory_open")
            return 0

        reg("SHGetFolderPathW", SHGetFolderPath, 5)
        reg("SHGetFolderPathA", SHGetFolderPath, 5)

        def SHGetSpecialFolderPath(self, emu, argv, ctx=None):
            ctx, cw = self.prepare_ctx(ctx)
            hwnd, out, csidl, create = argv
            if not out:
                return False
            path = _known_folder_path(csidl)
            self.write_mem_string(path, out, cw)
            return True

        reg("SHGetSpecialFolderPathW", SHGetSpecialFolderPath, 4)
        reg("SHGetSpecialFolderPathA", SHGetSpecialFolderPath, 4)

        def SHGetKnownFolderPath(self, emu, argv, ctx=None):
            """
            HRESULT SHGetKnownFolderPath(
                REFKNOWNFOLDERID rfid,
                DWORD            dwFlags,
                HANDLE           hToken,
                PWSTR           *ppszPath
            );
            """
            rfid, flags, token, out = argv
            if not out:
                return 0x80070057
            path = "C:\\Windows\\system32"
            ws = path.encode("utf-16le") + b"\x00\x00"
            buf = self.mem_alloc(len(ws), tag="api.shell32.path")
            self.mem_write(buf, ws)
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return 0

        reg("SHGetKnownFolderPath", SHGetKnownFolderPath, 4)

        def SHGetPathFromIDList(self, emu, argv, ctx=None):
            pidl, path = argv
            if not path:
                return False
            ctx, cw = self.prepare_ctx(ctx)
            self.write_mem_string("C:\\", path, cw)
            return True

        reg("SHGetPathFromIDListW", SHGetPathFromIDList, 2)
        reg("SHGetPathFromIDListA", SHGetPathFromIDList, 2)

        def PathFileExists(self, emu, argv, ctx=None):
            path = argv[0]
            if not path:
                return False
            ctx, cw = self.prepare_ctx(ctx)
            p = self.read_mem_string(path, cw)
            return self.does_file_exist(p)

        reg("PathFileExistsW", PathFileExists, 1)
        reg("PathFileExistsA", PathFileExists, 1)

        def PathIsDirectory(self, emu, argv, ctx=None):
            path = argv[0]
            if not path:
                return False
            ctx, cw = self.prepare_ctx(ctx)
            p = self.read_mem_string(path, cw)
            return self.does_file_exist(p)

        reg("PathIsDirectoryW", PathIsDirectory, 1)
        reg("PathIsDirectoryA", PathIsDirectory, 1)

        def CommandLineToArgvW(self, emu, argv, ctx=None):
            """
            LPWSTR *CommandLineToArgvW(
                LPCWSTR lpCmdLine,
                int    *pNumArgs
            );
            """
            cmdline, num_out = argv
            if not cmdline or not num_out:
                return 0
            cmd = self.read_wide_string(cmdline)
            parts = shlex.split(cmd)
            argc = len(parts)
            self.mem_write(num_out, argc.to_bytes(4, "little"))
            arr = self.mem_alloc((argc + 1) * ptr, tag="api.shell32.argv")
            offset = arr + (argc + 1) * ptr
            for i, part in enumerate(parts):
                ws = part.encode("utf-16le") + b"\x00\x00"
                self.mem_write(offset, ws)
                self.mem_write(arr + i * ptr, offset.to_bytes(ptr, "little"))
                offset += len(ws)
            self.mem_write(arr + argc * ptr, b"\x00" * ptr)
            return arr

        reg("CommandLineToArgvW", CommandLineToArgvW, 2)

        def ShellExecuteW(self, emu, argv, ctx=None):
            hwnd, verb, file, params, directory, show = argv
            if file:
                ctx, cw = self.prepare_ctx(ctx)
                f = self.read_mem_string(file, cw)
                argv[2] = f
                self.record_file_access_event(f, "file_open")
            return 0x21  # success handle (arbitrary > 32)

        reg("ShellExecuteW", ShellExecuteW, 6)

        def ShellExecuteA(self, emu, argv, ctx=None):
            return ShellExecuteW(self, emu, argv, ctx)

        reg("ShellExecuteA", ShellExecuteA, 6)

        def SHFileOperation(self, emu, argv, ctx=None):
            op = argv[0]
            return 0  # DE_SUCCESS

        reg("SHFileOperationW", SHFileOperation, 1)
        reg("SHFileOperationA", SHFileOperation, 1)

        def IsUserAnAdmin(self, emu, argv, ctx=None):
            return True

        reg("IsUserAnAdmin", IsUserAnAdmin, 0)

        def GetCurrentProcessExplicitAppUserModelID(self, emu, argv, ctx=None):
            out = argv[0]
            if not out:
                return 0x80070057
            ws = b"\x00\x00"
            buf = self.mem_alloc(2, tag="api.shell32.appid")
            self.mem_write(buf, ws)
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return 0

        reg("GetCurrentProcessExplicitAppUserModelID", GetCurrentProcessExplicitAppUserModelID, 1)

        def SHCreateDirectory(self, emu, argv, ctx=None):
            ctx, cw = self.prepare_ctx(ctx)
            hwnd, path, psa = argv
            if path:
                p = self.read_mem_string(path, cw)
                self.record_file_access_event(p, "directory_create")
            return 0

        reg("SHCreateDirectoryExW", SHCreateDirectory, 3)
        reg("SHCreateDirectoryExA", SHCreateDirectory, 3)

        # ---- Str* / Path* string helpers (shell32 re-exports shlwapi) ----
        def str_impl(wide, fn):
            def impl(self, emu, argv, ctx=None):
                if fn == "len":
                    s = argv[0]
                    return len(self.read_wide_string(s)) if wide else len(self.read_string(s)) if s else 0
                if fn == "cpy":
                    dst, src = argv
                    if not dst or not src:
                        return 0
                    s = self.read_wide_string(src) if wide else self.read_string(src)
                    if wide:
                        self.write_wide_string(s, dst)
                    else:
                        self.write_string(s, dst)
                    return dst
                if fn == "cat":
                    dst, src = argv
                    if not dst or not src:
                        return 0
                    d = self.read_wide_string(dst) if wide else self.read_string(dst)
                    s = self.read_wide_string(src) if wide else self.read_string(src)
                    if wide:
                        self.write_wide_string(d + s, dst)
                    else:
                        self.write_string(d + s, dst)
                    return dst
                if fn == "cmp":
                    a, b = argv
                    if not a or not b:
                        return 0
                    sa = self.read_wide_string(a) if wide else self.read_string(a)
                    sb = self.read_wide_string(b) if wide else self.read_string(b)
                    if sa == sb:
                        return 0
                    return -1 if sa < sb else 1
                if fn == "cmpi":
                    a, b = argv
                    if not a or not b:
                        return 0
                    sa = (self.read_wide_string(a) if wide else self.read_string(a)).lower()
                    sb = (self.read_wide_string(b) if wide else self.read_string(b)).lower()
                    if sa == sb:
                        return 0
                    return -1 if sa < sb else 1
                if fn == "cmpn":
                    a, b, n = argv
                    if not a or not b:
                        return 0
                    sa = (self.read_wide_string(a) if wide else self.read_string(a))[:n]
                    sb = (self.read_wide_string(b) if wide else self.read_string(b))[:n]
                    if sa == sb:
                        return 0
                    return -1 if sa < sb else 1
                if fn == "cmpni":
                    a, b, n = argv
                    if not a or not b:
                        return 0
                    sa = (self.read_wide_string(a) if wide else self.read_string(a))[:n].lower()
                    sb = (self.read_wide_string(b) if wide else self.read_string(b))[:n].lower()
                    if sa == sb:
                        return 0
                    return -1 if sa < sb else 1
                if fn == "chr":
                    s, c = argv
                    if not s:
                        return 0
                    data = self.read_wide_string(s) if wide else self.read_string(s)
                    for i, ch in enumerate(data):
                        if ch == chr(c & 0xFFFF):
                            return s + i * (2 if wide else 1)
                    return 0
                if fn == "chri":
                    s, c = argv
                    if not s:
                        return 0
                    data = (self.read_wide_string(s) if wide else self.read_string(s)).lower()
                    for i, ch in enumerate(data):
                        if ch == chr(c & 0xFFFF).lower():
                            return s + i * (2 if wide else 1)
                    return 0
                if fn == "rchr":
                    s, c = argv
                    if not s:
                        return 0
                    data = self.read_wide_string(s) if wide else self.read_string(s)
                    for i in range(len(data) - 1, -1, -1):
                        if data[i] == chr(c & 0xFFFF):
                            return s + i * (2 if wide else 1)
                    return 0
                if fn == "str":
                    s, sub = argv
                    if not s or not sub:
                        return 0
                    data = self.read_wide_string(s) if wide else self.read_string(s)
                    needle = self.read_wide_string(sub) if wide else self.read_string(sub)
                    idx = data.find(needle)
                    return s + idx * (2 if wide else 1) if idx >= 0 else 0
                if fn == "stri":
                    s, sub = argv
                    if not s or not sub:
                        return 0
                    data = (self.read_wide_string(s) if wide else self.read_string(s)).lower()
                    needle = (self.read_wide_string(sub) if wide else self.read_string(sub)).lower()
                    idx = data.find(needle)
                    return s + idx * (2 if wide else 1) if idx >= 0 else 0
                if fn == "spn":
                    s, accept = argv
                    if not s or not accept:
                        return 0
                    data = self.read_wide_string(s) if wide else self.read_string(s)
                    acc = set(self.read_wide_string(accept) if wide else self.read_string(accept))
                    n = 0
                    for ch in data:
                        if ch not in acc:
                            break
                        n += 1
                    return n
                if fn == "cspn":
                    s, reject = argv
                    if not s or not reject:
                        return 0
                    data = self.read_wide_string(s) if wide else self.read_string(s)
                    rej = set(self.read_wide_string(reject) if wide else self.read_string(reject))
                    n = 0
                    for ch in data:
                        if ch in rej:
                            break
                        n += 1
                    return n
                if fn == "toi":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    try:
                        return int(txt.strip(), 0) & 0xFFFFFFFF
                    except Exception:
                        return 0
                if fn == "toi64":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    try:
                        return int(txt.strip(), 0)
                    except Exception:
                        return 0
                if fn == "trim":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    new = txt.strip(" ")
                    if wide:
                        self.write_wide_string(new, s)
                    else:
                        self.write_string(new, s)
                    return s
                if fn == "addslash":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    if txt and not txt.endswith("\\"):
                        txt += "\\"
                        if wide:
                            self.write_wide_string(txt, s)
                        else:
                            self.write_string(txt, s)
                    return s
                if fn == "rmslash":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    if txt.endswith("\\") and txt != "\\":
                        txt = txt[:-1]
                        if wide:
                            self.write_wide_string(txt, s)
                        else:
                            self.write_string(txt, s)
                    return s
                if fn == "fnext":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    import os as _os

                    base = _os.path.basename(txt)
                    out = argv[1]
                    if wide:
                        self.write_wide_string(base, out)
                    else:
                        self.write_string(base, out)
                    return out
                if fn == "fname":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    import os as _os

                    base = _os.path.basename(txt)
                    return s + (len(txt) - len(base)) * (2 if wide else 1)
                if fn == "fext":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    import os as _os

                    base = _os.path.basename(txt)
                    _, ext = _os.path.splitext(base)
                    return s + (len(txt) - len(ext)) * (2 if wide else 1) if ext else 0
                if fn == "fnext_off":
                    return 0
                if fn == "rext":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    import os as _os

                    base, ext = _os.path.splitext(txt)
                    new = base + ("" if fn == "rext" else "")
                    if wide:
                        self.write_wide_string(new, s)
                    else:
                        self.write_string(new, s)
                    return s
                if fn == "rmspec":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    import os as _os

                    new = _os.path.dirname(txt)
                    if wide:
                        self.write_wide_string(new, s)
                    else:
                        self.write_string(new, s)
                    return s
                if fn == "strippath":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    import os as _os

                    new = _os.path.basename(txt)
                    if wide:
                        self.write_wide_string(new, s)
                    else:
                        self.write_string(new, s)
                    return s
                if fn == "relative":
                    s = argv[0]
                    if not s:
                        return False
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    return not (txt.startswith("\\") or txt[1:3] == ":\\" if len(txt) > 2 else False)
                if fn == "root":
                    s = argv[0]
                    if not s:
                        return False
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    return txt in ("\\", "/") or (len(txt) >= 3 and txt[1:3] == ":\\")
                if fn == "isunc":
                    s = argv[0]
                    if not s:
                        return False
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    return txt.startswith("\\\\")
                if fn == "combine":
                    dst, a, b = argv
                    if not dst:
                        return 0
                    sa = self.read_wide_string(a) if wide else self.read_string(a)
                    sb = self.read_wide_string(b) if wide else self.read_string(b)
                    new = sa.rstrip("\\") + "\\" + sb.lstrip("\\")
                    if wide:
                        self.write_wide_string(new, dst)
                    else:
                        self.write_string(new, dst)
                    return dst
                if fn == "append":
                    dst, src = argv
                    if not dst or not src:
                        return 0
                    d = self.read_wide_string(dst) if wide else self.read_string(dst)
                    s = self.read_wide_string(src) if wide else self.read_string(src)
                    new = d.rstrip("\\") + "\\" + s.lstrip("\\")
                    if wide:
                        self.write_wide_string(new, dst)
                    else:
                        self.write_string(new, dst)
                    return dst
                if fn == "canon":
                    dst, src = argv
                    if not dst or not src:
                        return 0
                    s = self.read_wide_string(src) if wide else self.read_string(src)
                    import os as _os

                    new = _os.path.normpath(s)
                    if wide:
                        self.write_wide_string(new, dst)
                    else:
                        self.write_string(new, dst)
                    return dst
                if fn == "commonprefix":
                    a, b = argv
                    if not a or not b:
                        return 0
                    sa = self.read_wide_string(a) if wide else self.read_string(a)
                    sb = self.read_wide_string(b) if wide else self.read_string(b)
                    n = 0
                    for x, y in zip(sa, sb):
                        if x != y:
                            break
                        n += 1
                    return n
                if fn == "isurl":
                    s = argv[0]
                    if not s:
                        return False
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    return "://" in txt
                if fn == "unquote":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    if len(txt) >= 2 and txt[0] == '"' and txt[-1] == '"':
                        txt = txt[1:-1]
                        if wide:
                            self.write_wide_string(txt, s)
                        else:
                            self.write_string(txt, s)
                    return s
                if fn == "quote":
                    s = argv[0]
                    if not s:
                        return 0
                    txt = self.read_wide_string(s) if wide else self.read_string(s)
                    if not (txt.startswith('"') and txt.endswith('"')):
                        txt = f'"{txt}"'
                        if wide:
                            self.write_wide_string(txt, s)
                        else:
                            self.write_string(txt, s)
                    return s
                return 0

            return impl

        str_funcs = {
            "StrLenW": ("len", True), "StrLenA": ("len", False),
            "StrCpyW": ("cpy", True), "StrCpyA": ("cpy", False),
            "StrCatW": ("cat", True), "StrCatA": ("cat", False),
            "StrCmpW": ("cmp", True), "StrCmpA": ("cmp", False),
            "StrCmpIW": ("cmpi", True), "StrCmpIA": ("cmpi", False),
            "StrCmpNW": ("cmpn", True), "StrCmpNA": ("cmpn", False),
            "StrCmpNIW": ("cmpni", True), "StrCmpNIA": ("cmpni", False),
            "StrChrW": ("chr", True), "StrChrA": ("chr", False),
            "StrChrIW": ("chri", True), "StrChrIA": ("chri", False),
            "StrRChrW": ("rchr", True), "StrRChrA": ("rchr", False),
            "StrRChrIW": ("rchr", True), "StrRChrIA": ("rchr", False),
            "StrStrW": ("str", True), "StrStrA": ("str", False),
            "StrStrIW": ("stri", True), "StrStrIA": ("stri", False),
            "StrSpnW": ("spn", True), "StrSpnA": ("spn", False),
            "StrCSpnW": ("cspn", True), "StrCSpnA": ("cspn", False),
            "StrToIntW": ("toi", True), "StrToIntA": ("toi", False),
            "StrToInt64W": ("toi64", True), "StrToInt64A": ("toi64", False),
            "StrTrimW": ("trim", True), "StrTrimA": ("trim", False),
            "PathAddBackslashW": ("addslash", True), "PathAddBackslashA": ("addslash", False),
            "PathRemoveBackslashW": ("rmslash", True), "PathRemoveBackslashA": ("rmslash", False),
            "PathFindExtensionW": ("fext", True), "PathFindExtensionA": ("fext", False),
            "PathFindFileNameW": ("fname", True), "PathFindFileNameA": ("fname", False),
            "PathRemoveExtensionW": ("rext", True), "PathRemoveExtensionA": ("rext", False),
            "PathRemoveFileSpecW": ("rmspec", True), "PathRemoveFileSpecA": ("rmspec", False),
            "PathStripPathW": ("strippath", True), "PathStripPathA": ("strippath", False),
            "PathIsRelativeW": ("relative", True), "PathIsRelativeA": ("relative", False),
            "PathIsRootW": ("root", True), "PathIsRootA": ("root", False),
            "PathIsUNCW": ("isunc", True), "PathIsUNCA": ("isunc", False),
            "PathCombineW": ("combine", True), "PathCombineA": ("combine", False),
            "PathAppendW": ("append", True), "PathAppendA": ("append", False),
            "PathCanonicalizeW": ("canon", True), "PathCanonicalizeA": ("canon", False),
            "PathCommonPrefixW": ("commonprefix", True), "PathCommonPrefixA": ("commonprefix", False),
            "PathIsURLW": ("isurl", True), "PathIsURLA": ("isurl", False),
            "PathUnquoteSpacesW": ("unquote", True), "PathUnquoteSpacesA": ("unquote", False),
            "PathQuoteSpacesW": ("quote", True), "PathQuoteSpacesA": ("quote", False),
        }
        argc_map = {
            "len": 1, "cpy": 2, "cat": 2, "cmp": 2, "cmpi": 2, "cmpn": 3, "cmpni": 3,
            "chr": 2, "chri": 2, "rchr": 2, "str": 2, "stri": 2, "spn": 2, "cspn": 2,
            "toi": 1, "toi64": 1, "trim": 1, "addslash": 1, "rmslash": 1,
            "fext": 1, "fname": 1, "rext": 1, "rmspec": 1, "strippath": 1,
            "relative": 1, "root": 1, "isunc": 1, "combine": 3, "append": 2,
            "canon": 2, "commonprefix": 2, "isurl": 1, "unquote": 1, "quote": 1,
        }
        for name, (fn, wide) in str_funcs.items():
            reg(name, str_impl(wide, fn), argc_map[fn])

        def SHGetFileInfo_impl(self, emu, argv, ctx=None):
            path, attrs, out, size, flags = argv
            if not out:
                return 0
            self.mem_write(out, b"\x00" * min(size, 0x100))
            return 0

        reg("SHGetFileInfoW", SHGetFileInfo_impl, 5)
        reg("SHGetFileInfoA", SHGetFileInfo_impl, 5)

        def ShellExecuteEx_impl(self, emu, argv, ctx=None):
            info = argv[0]
            if info:
                self.mem_write(info + self.get_ptr_size(), b"\x28\x00\x00\x00")
            return True

        reg("ShellExecuteExW", ShellExecuteEx_impl, 1)
        reg("ShellExecuteExA", ShellExecuteEx_impl, 1)

        def DragQueryFile_impl(self, emu, argv, ctx=None):
            hdrop, index, buf, size = argv
            if not buf:
                return 0
            if wide := False:
                pass
            self.write_string("", buf)
            return 0

        reg("DragQueryFileW", DragQueryFile_impl, 4)
        reg("DragQueryFileA", DragQueryFile_impl, 4)

        def SHGetSpecialFolderLocation_impl(self, emu, argv, ctx=None):
            hwnd, csidl, pidl_out = argv
            if not pidl_out:
                return 0x80070057
            self.mem_write(pidl_out, b"\x00" * ptr)
            return 0x80070003  # E_PATHNOTFOUND

        reg("SHGetSpecialFolderLocation", SHGetSpecialFolderLocation_impl, 3)

        def SHGetFolderLocation_impl(self, emu, argv, ctx=None):
            hwnd, csidl, token, reserved, pidl_out = argv
            if not pidl_out:
                return 0x80070057
            self.mem_write(pidl_out, b"\x00" * ptr)
            return 0x80070003

        reg("SHGetFolderLocation", SHGetFolderLocation_impl, 5)

        def ILFree_impl(self, emu, argv, ctx=None):
            pidl = argv[0]
            if pidl:
                try:
                    self.mem_free(pidl)
                except Exception:
                    pass

        reg("ILFree", ILFree_impl, 1)

        def SHParseDisplayName_impl(self, emu, argv, ctx=None):
            name, binder, pidl_out, attrs, out_attrs = argv
            if pidl_out:
                self.mem_write(pidl_out, b"\x00" * ptr)
            return 0x80070003

        reg("SHParseDisplayName", SHParseDisplayName_impl, 5)

        def SHCreateItemFromParsingName_impl(self, emu, argv, ctx=None):
            name, binder, riid, out = argv
            if out:
                self.mem_write(out, b"\x00" * ptr)
            return 0x80004002  # E_NOINTERFACE

        reg("SHCreateItemFromParsingName", SHCreateItemFromParsingName_impl, 4)

        def AssocQueryString_impl(self, emu, argv, ctx=None):
            flags, assoc, ext, verb, out, size = argv
            if not out:
                return 0x8007007A  # ERROR_INSUFFICIENT_BUFFER
            self.write_wide_string("", out)
            return 0

        reg("AssocQueryStringW", AssocQueryString_impl, 6)
        reg("AssocQueryStringA", AssocQueryString_impl, 6)

        def SHOpenFolderAndSelectItems_impl(self, emu, argv, ctx=None):
            return 0

        reg("SHOpenFolderAndSelectItems", SHOpenFolderAndSelectItems_impl, 4)

        def SHBrowseForFolder_impl(self, emu, argv, ctx=None):
            info = argv[0]
            return 0

        reg("SHBrowseForFolderW", SHBrowseForFolder_impl, 1)
        reg("SHBrowseForFolderA", SHBrowseForFolder_impl, 1)

        def SHGetDesktopFolder_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, b"\x00" * ptr)
            return 0x80004002

        reg("SHGetDesktopFolder", SHGetDesktopFolder_impl, 1)

    def get_handle(self):
        self.curr_handle += 4
        return self.curr_handle

    @apihook("SHCreateDirectoryEx", argc=3)
    def SHCreateDirectoryEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        int SHCreateDirectoryExA(
            HWND                      hwnd,
            LPCSTR                    pszPath,
            const SECURITY_ATTRIBUTES *psa
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        hwnd, pszPath, psa = argv

        dn = ""
        if pszPath:
            dn = self.read_mem_string(pszPath, cw)
            argv[1] = dn

            self.record_file_access_event(dn, "directory_create")

        return 0

    @apihook("ShellExecute", argc=6)
    def ShellExecute(self, emu, argv, ctx: api.ApiContext = None):
        """
        HINSTANCE ShellExecuteA(
            HWND   hwnd,
            LPCSTR lpOperation,
            LPCSTR lpFile,
            LPCSTR lpParameters,
            LPCSTR lpDirectory,
            INT    nShowCmd
        );
        """
        ctx, cw = self.prepare_ctx(ctx)

        hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd = argv


        fn = ""
        param = ""
        dn = ""
        if lpOperation:
            op = self.read_mem_string(lpOperation, cw)
            argv[1] = op
        if lpFile:
            fn = self.read_mem_string(lpFile, cw)
            argv[2] = fn
        if lpParameters:
            param = self.read_mem_string(lpParameters, cw)
            argv[3] = param
        if lpDirectory:
            dn = self.read_mem_string(lpDirectory, cw)
            argv[4] = dn

        if dn and fn:
            fn = f"{dn}\\{fn}"

        proc = emu.create_process(path=fn, cmdline=param)
        self.record_process_event(proc, PROC_CREATE)

        return 33

    @apihook("ShellExecuteEx", argc=1)
    def ShellExecuteEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL ShellExecuteExA(
            [in, out] SHELLEXECUTEINFOA *pExecInfo
        );
        """
        ctx = ctx or {}
        (lpShellExecuteInfo,) = argv

        sei = shell32_defs.SHELLEXECUTEINFOA(emu.get_ptr_size())
        sei_struct = self.mem_cast(sei, lpShellExecuteInfo)

        self.ShellExecute(
            emu, [0, sei_struct.lpVerb, sei_struct.lpFile, sei_struct.lpParameters, sei_struct.lpDirectory, 0], ctx
        )

        return True

    @apihook("SHChangeNotify", argc=4)
    def SHChangeNotify(self, emu, argv, ctx: api.ApiContext = None):
        """
        void SHChangeNotify(
            LONG wEventId,
            UINT uFlags,
            LPCVOID dwItem1,
            LPCVOID dwItem2
        );
        """
        return

    @apihook("IsUserAnAdmin", argc=0, ordinal=680)
    def IsUserAnAdmin(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL IsUserAnAdmin();
        """
        return emu.config.user.is_admin

    @apihook("SHGetMalloc", argc=1)
    def SHGetMalloc(self, emu, argv, ctx: api.ApiContext = None):
        """
        SHSTDAPI SHGetMalloc(
            IMalloc **ppMalloc
        );
        """
        (ppMalloc,) = argv

        if ppMalloc:
            ci = emu.com.get_interface(emu, emu.get_ptr_size(), "IMalloc")
            self.mem_write(ppMalloc, ci.address.to_bytes(emu.get_ptr_size(), "little"))
        rv = windefs.S_OK
        return rv

    @apihook("CommandLineToArgv", argc=2)
    def CommandLineToArgv(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPWSTR * CommandLineToArgv(
            LPCWSTR lpCmdLine,
            int     *pNumArgs
        );
        """
        ctx, cw = self.prepare_ctx(ctx)
        cmdline, argc = argv

        cl = self.read_mem_string(cmdline, cw)

        ptrsize = emu.get_ptr_size()

        split = shlex.split(cl)
        nargs = len(split)

        # Get the total size we need
        size = (len(split) + 1) * ptrsize
        size += (len(cl) * cw) + (len(split) * cw)

        # Allocate the array
        buf = self.mem_alloc(size, tag="api.CommandLineToArgv")
        ptrs = buf
        strs = buf + ((len(split) + 1) * ptrsize)
        for i, p in enumerate(split):
            self.mem_write(ptrs + (i * ptrsize), strs.to_bytes(emu.get_ptr_size(), "little"))

            p += "\x00"
            if cw == 2:
                s = p.encode("utf-16le")
            else:
                s = p.encode("utf-8")
            self.mem_write(strs, s)

            strs += len(s)

        if argc:
            self.mem_write(argc, nargs.to_bytes(4, "little"))

        return buf

    @apihook("ExtractIcon", argc=3)
    def ExtractIcon(self, emu, argv, ctx: api.ApiContext = None):
        """
        HICON ExtractIconA(
          HINSTANCE hInst,
          LPCSTR    pszExeFileName,
          UINT      nIconIndex
        );
        """

        return self.get_handle()

    @apihook("SHGetFolderPath", argc=5)
    def SHGetFolderPath(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND   hwnd,
        int    csidl,
        HANDLE hToken,
        DWORD  dwFlags,
        LPWSTR pszPath
        """
        ctx = ctx or {}
        hwnd, csidl, hToken, dwFlags, pszPath = argv
        if csidl in shell32_defs.CSIDL:
            argv[1] = shell32_defs.CSIDL[csidl]
        if csidl == 0x1A:
            # CSIDL_APPDATA
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Roaming"
        elif csidl == 0x28:
            # csidl_profile
            path = f"C:\\Users\\{emu.config.user.name}"
        elif csidl == 0 or csidl == 0x10:
            # CSIDL_DESKTOP or CSIDL_DESKTOPDIRECTORY
            path = f"C:\\Users\\{emu.config.user.name}\\Desktop"
        elif csidl == 2:
            # CSIDL_PROGRAMS
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"  # noqa
        elif csidl == 6 or csidl == 0x1F:
            # CSIDL_FAVORITES or CSIDL_COMMON_FAVORITES
            path = f"C:\\Users\\{emu.config.user.name}\\Favorites"
        elif csidl == 7:
            # CSIDL_STARTUP
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"  # noqa
        elif csidl == 8:
            # CSIDL_RECENT
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Recent".format(emu.config.user.name)  # noqa
        elif csidl == 9:
            # csidl_sendto
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\SendTo".format(emu.config.user.name)  # noqa
        elif csidl == 0xB:
            # CSIDL_STARTMENU
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu".format(emu.config.user.name)  # noqa
        elif csidl == 0x13:
            # CSIDL_NETHOOD
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts".format(emu.config.user.name)  # noqa
        elif csidl == 0x15:
            # CSIDL_TEMPLATES
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Templates".format(emu.config.user.name)  # noqa
        elif csidl == 0x1B:
            # CSIDL_PRINTHOOD
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts".format(emu.config.user.name)  # noqa
        elif csidl == 0x1C:
            # CSIDL_LOCAL_APPDATA
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Local"
        elif csidl == 0x20:
            # CSIDL_INTERNET_CACHE
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet File"  # noqa
        elif csidl == 0x21:
            # CSIDL_COOKIES
            path = "C:\\Users\\{}\\AppData\\AppData\\Roaming\\Microsoft\\Windows\\Cookies".format(emu.config.user.name)  # noqa
        elif csidl == 0x22:
            # CSIDL_HISTORY
            path = "C:\\Users\\{}\\AppData\\Local\\Microsoft\\Windows\\History".format(emu.config.user.name)  # noqa
        elif csidl == 0x27:
            # CSIDL_MYPICTURES
            path = f"C:\\Users\\{emu.config.user.name}\\Pictures"
        elif csidl == 0x2F or csidl == 0x30:
            user = emu.config.user.name
            path = (
                f"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"
            )
        elif csidl == 0x1D:
            # CSIDL_ALTSTARTUP
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"  # noqa
        elif csidl == 0x1E:
            path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        elif csidl == 0x2A or csidl == 0x26:
            path = "C:\\Program Files"
        elif csidl == 0x2B or csidl == 0x2C:
            path = "C:\\Program Files\\Common Files"
        elif csidl == 0x24:
            path = "C:\\Windows"
        elif csidl == 0x25:
            path = "C:\\Windows\\System32"
        elif csidl == 0x14:
            path = "C:\\Windows\\Fonts"
        elif csidl == 0x23:
            path = "C:\\ProgramData"
        else:
            # Temp
            path = "C:\\Windows\\Temp"

        emu.write_mem_string(path, pszPath, self.get_char_width(ctx))
        return 0
