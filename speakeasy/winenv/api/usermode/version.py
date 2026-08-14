# Copyright (C) 2026 Speakeasy-X

import io
import os
import struct

import pefile

from .. import api


def _align4(value):
    return (value + 3) & ~3


class Version(api.ApiHandler):
    """
    Implements exported functions from VERSION.dll by parsing the
    VS_VERSION_INFO resource of the queried file (resolved through the
    emulated file manager).
    """

    name = "version"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)

    def _get_file_data(self, path):
        """Return raw bytes for an emulated file path (or a loaded module)."""
        if not path:
            return None
        try:
            fobj = self.file_open(path)
            if fobj is not None:
                data = getattr(fobj, "data", None)
                if isinstance(data, io.BytesIO):
                    return data.getvalue()
                if isinstance(data, bytes):
                    return data
        except Exception:
            pass
        # Fall back to a loaded module whose base name matches the path
        base = os.path.basename(path).lower()
        modules = getattr(self.emu, "modules", []) or []
        for mod in modules:
            mod_name = (getattr(mod, "name", "") or "").lower()
            if mod_name and base.startswith(mod_name):
                try:
                    return self.emu.mem_read(mod.base, mod.image_size)
                except Exception:
                    return None
        return None

    def _get_version_block(self, path):
        """Return the raw RT_VERSION resource bytes for a file, or None."""
        data = self._get_file_data(path)
        if not data:
            return None
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        except Exception:
            return None
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return None
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if res_type.name is not None:
                continue
            if res_type.struct.Id != 16:  # RT_VERSION
                continue
            if not hasattr(res_type, "directory"):
                continue
            for res_id in res_type.directory.entries:
                if not hasattr(res_id, "directory"):
                    continue
                for lang in res_id.directory.entries:
                    if hasattr(lang, "data"):
                        rva = lang.data.struct.OffsetToData
                        size = lang.data.struct.Size
                        try:
                            return pe.get_data(rva, size)
                        except Exception:
                            return None
        return None

    @staticmethod
    def _synthesize_block(mod_name):
        """
        Build a minimal VS_VERSION_INFO block for a known system DLL whose
        virtual module has no version resource.
        """
        base = os.path.basename(mod_name).lower().replace(".dll", "")
        key = "VS_VERSION_INFO"
        key_bytes = key.encode("utf-16le") + b"\x00\x00"
        key_padded = key_bytes + b"\x00" * (-len(key_bytes) % 4)
        # VS_FIXEDFILEINFO (all 4-byte fields)
        ffi = struct.pack(
            "<IIIIIIIIIIIII",
            0xFEEF04BD,  # dwSignature
            0x00010000,  # dwStrucVersion
            0x00010000,  # dwFileVersionMS (1.0)
            0x00000000,  # dwFileVersionLS
            0x00010000,  # dwProductVersionMS
            0x00000000,  # dwProductVersionLS
            0x3F,        # dwFileFlagsMask
            0,           # dwFileFlags
            0x00040004,  # dwFileOS (VOS_NT_WINDOWS32)
            0x00000002,  # dwFileType (VFT_DLL)
            0,           # dwFileSubtype
            0,           # dwFileDateMS
            0,           # dwFileDateLS
        )
        string_info = {
            "CompanyName": "Microsoft Corporation",
            "FileDescription": f"{base}",
            "FileVersion": "10.0.19045.0",
            "InternalName": f"{base}",
            "OriginalFilename": f"{base}.dll",
            "ProductName": f"Microsoft\xae Windows\xae Operating System",
            "ProductVersion": "10.0.19045.0",
        }
        lang_block = bytearray()
        for name, value in string_info.items():
            name_b = name.encode("utf-16le") + b"\x00\x00"
            name_pad = name_b + b"\x00" * (-len(name_b) % 4)
            value_b = value.encode("utf-16le") + b"\x00\x00"
            value_pad = value_b + b"\x00" * (-len(value_b) % 4)
            entry_len = 6 + len(name_pad) + len(value_pad)
            lang_block += struct.pack("<HHH", entry_len, len(value_b), 1)
            lang_block += name_pad + value_pad
        lang_key = "040904b0".encode("utf-16le") + b"\x00\x00"
        lang_pad = lang_key + b"\x00" * (-len(lang_key) % 4)
        lang_len = 6 + len(lang_pad) + len(lang_block)
        lang_hdr = struct.pack("<HHH", lang_len, 0, 1) + lang_pad + lang_block
        sf_key = "StringFileInfo".encode("utf-16le") + b"\x00\x00"
        sf_pad = sf_key + b"\x00" * (-len(sf_key) % 4)
        sf_len = 6 + len(sf_pad) + len(lang_hdr)
        sf_hdr = struct.pack("<HHH", sf_len, 0, 1) + sf_pad + lang_hdr
        total = 6 + len(key_padded) + len(ffi) + len(sf_hdr)
        root = struct.pack("<HHH", total, len(ffi), 0) + key_padded + ffi + sf_hdr
        return bytes(root)

    def _resolve_block(self, path):
        """Version block for a file, synthesizing one for known system DLLs."""
        block = self._get_version_block(path)
        if block is not None:
            return block
        base = os.path.basename(path or "").lower().replace(".dll", "")
        if not base:
            return None
        for mod in getattr(self.emu, "modules", []) or []:
            mod_name = (getattr(mod, "name", "") or "").lower()
            if mod_name == base or mod_name.startswith(base):
                return self._synthesize_block(base)
        return None

    def _query_block(self, block_data, block_addr, sub_block):
        """
        Resolve a VerQueryValue sub-block key against a VS_VERSION_INFO block.
        Returns (absolute_addr, length) or (None, None).
        """
        if not block_data:
            return None, None

        def u16(data, off):
            return int.from_bytes(data[off : off + 2], "little")

        def walk(data, off):
            """Yield (offset, length, value_len, key) for a version block."""
            while off + 6 <= len(data):
                wlen = u16(data, off)
                if wlen == 0:
                    break
                vlen = u16(data, off + 2)
                key_off = off + 6
                end = key_off
                while end + 1 < len(data) and not (data[end] == 0 and data[end + 1] == 0):
                    end += 2
                key = data[key_off:end].decode("utf-16le", "ignore")
                value_off = _align4(end + 2)
                yield off, wlen, vlen, key, value_off
                off += _align4(wlen)

        blocks = list(walk(block_data, 0))
        if not blocks:
            return None, None
        root = blocks[0]
        if sub_block == "\\":
            value_off = root[4]
            return block_addr + value_off, root[2]
        sub = sub_block.strip("\\").split("\\")
        if sub[0].lower() == "stringfileinfo" and len(sub) == 3:
            lang, key_name = sub[1], sub[2]
            for off, wlen, vlen, key, value_off in blocks[1:]:
                if key.lower() != "stringfileinfo":
                    continue
                children = list(walk(block_data, off + _align4(6 + len("StringFileInfo") * 2 + 2)))
                for coff, cwlen, cvlen, ckey, cvalue_off in children:
                    if ckey.lower() != lang.lower():
                        continue
                    for soff, swlen, svlen, skey, svalue_off in walk(block_data, coff + _align4(6 + len(ckey) * 2 + 2)):
                        if skey.lower() == key_name.lower():
                            return block_addr + svalue_off, svlen
            return None, None
        if sub[0].lower() == "varfileinfo" and len(sub) == 2 and sub[1].lower() == "translation":
            for off, wlen, vlen, key, value_off in blocks[1:]:
                if key.lower() == "varfileinfo":
                    return block_addr + value_off, vlen
            return None, None
        return None, None

    @apihook("GetFileVersionInfoSizeW", argc=2)
    def GetFileVersionInfoSizeW(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GetFileVersionInfoSizeW(
            LPCWSTR lptstrFilename,
            LPDWORD lpdwHandle
        );
        """
        path, handle = argv
        if handle:
            self.mem_write(handle, b"\x00\x00\x00\x00")
        if not path:
            return 0
        p = self.read_wide_string(path)
        block = self._resolve_block(p)
        if not block:
            return 0
        return len(block)

    @apihook("GetFileVersionInfoSizeA", argc=2)
    def GetFileVersionInfoSizeA(self, emu, argv, ctx: api.ApiContext = None):
        path, handle = argv
        if handle:
            self.mem_write(handle, b"\x00\x00\x00\x00")
        if not path:
            return 0
        p = self.read_string(path)
        block = self._resolve_block(p)
        if not block:
            return 0
        return len(block)

    @apihook("GetFileVersionInfoW", argc=4)
    def GetFileVersionInfoW(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetFileVersionInfoW(
            LPCWSTR lptstrFilename,
            DWORD   dwHandle,
            DWORD   dwLen,
            LPVOID  lpData
        );
        """
        path, handle, length, data = argv
        if not path:
            return False
        p = self.read_wide_string(path)
        block = self._resolve_block(p)
        if not block or not data:
            return False
        self.mem_write(data, block[: min(length, len(block))])
        return True

    @apihook("GetFileVersionInfoA", argc=4)
    def GetFileVersionInfoA(self, emu, argv, ctx: api.ApiContext = None):
        path, handle, length, data = argv
        if not path:
            return False
        p = self.read_string(path)
        block = self._resolve_block(p)
        if not block or not data:
            return False
        self.mem_write(data, block[: min(length, len(block))])
        return True

    @apihook("GetFileVersionInfoExW", argc=5)
    def GetFileVersionInfoExW(self, emu, argv, ctx: api.ApiContext = None):
        flags, path, handle, length, data = argv
        return self.GetFileVersionInfoW(emu, [path, handle, length, data], ctx)

    @apihook("GetFileVersionInfoExA", argc=5)
    def GetFileVersionInfoExA(self, emu, argv, ctx: api.ApiContext = None):
        flags, path, handle, length, data = argv
        return self.GetFileVersionInfoA(emu, [path, handle, length, data], ctx)

    @apihook("GetFileVersionInfoByHandle", argc=3)
    def GetFileVersionInfoByHandle(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetFileVersionInfoByHandle(HANDLE hHandle, DWORD dwLen, LPVOID lpData);"""
        handle, length, data = argv
        return False

    @apihook("VerQueryValueW", argc=4)
    def VerQueryValueW(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL VerQueryValueW(
            const VOID  *pBlock,
            LPCWSTR      lpSubBlock,
            LPVOID      *lplpBuffer,
            PUINT        puLen
        );
        """
        block, sub, buffer_out, len_out = argv
        if not block or not sub or not buffer_out or not len_out:
            return False
        sub_key = self.read_wide_string(sub)
        try:
            blen = int.from_bytes(self.mem_read(block, 2), "little")
        except Exception:
            return False
        data = self.mem_read(block, min(max(blen, 0x100), 0x4000))
        addr, length = self._query_block(data, block, sub_key)
        if addr is None:
            return False
        self.mem_write(buffer_out, addr.to_bytes(self.get_ptr_size(), "little"))
        self.mem_write(len_out, length.to_bytes(4, "little"))
        return True

    @apihook("VerQueryValueA", argc=4)
    def VerQueryValueA(self, emu, argv, ctx: api.ApiContext = None):
        block, sub, buffer_out, len_out = argv
        if not block or not sub or not buffer_out or not len_out:
            return False
        sub_key = self.read_string(sub)
        try:
            blen = int.from_bytes(self.mem_read(block, 2), "little")
        except Exception:
            return False
        data = self.mem_read(block, min(max(blen, 0x100), 0x4000))
        addr, length = self._query_block(data, block, sub_key)
        if addr is None:
            return False
        self.mem_write(buffer_out, addr.to_bytes(self.get_ptr_size(), "little"))
        self.mem_write(len_out, length.to_bytes(4, "little"))
        return True

    _LANG_NAMES = {
        0x0409: "English (United States)",
        0x0411: "Japanese (Japan)",
        0x0404: "Chinese (Taiwan)",
        0x0804: "Chinese (People's Republic of China)",
        0x0C0C: "French (France)",
        0x0407: "German (Germany)",
        0x0410: "Italian (Italy)",
        0x0419: "Russian (Russia)",
        0x040A: "Spanish (Spain)",
        0x0416: "Portuguese (Brazil)",
        0x041D: "Swedish (Sweden)",
        0x0413: "Dutch (Netherlands)",
        0x0415: "Polish (Poland)",
        0x0422: "Ukrainian (Ukraine)",
        0x0408: "Greek (Greece)",
        0x040E: "Hungarian (Hungary)",
        0x0405: "Czech (Czech Republic)",
        0x041B: "Slovak (Slovakia)",
        0x0402: "Bulgarian (Bulgaria)",
        0x0418: "Romanian (Romania)",
        0x040C: "French (France)",
        0x0813: "Dutch (Belgium)",
        0x0809: "English (United Kingdom)",
        0x0C09: "English (Australia)",
        0x1009: "English (Canada)",
        0x0401: "Arabic (Saudi Arabia)",
        0x040D: "Hebrew (Israel)",
        0x041F: "Turkish (Turkey)",
        0x0421: "Indonesian (Indonesia)",
        0x042D: "Basque (Basque)",
        0x0414: "Norwegian (Bokmal, Norway)",
        0x0406: "Danish (Denmark)",
        0x040B: "Finnish (Finland)",
        0x0412: "Korean (Korea)",
        0x0000: "Language Neutral",
    }

    def _ver_language_name(self, lcid, out, size, wide):
        name = self._LANG_NAMES.get(lcid & 0xFFFF)
        if not name:
            name = "Unknown Language"
        if wide:
            self.write_wide_string(name[: max(size - 1, 0)], out)
        else:
            self.write_string(name[: max(size - 1, 0)], out)
        return min(len(name), max(size - 1, 0))

    @apihook("VerLanguageNameW", argc=3)
    def VerLanguageNameW(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD VerLanguageNameW(
            DWORD  wLang,
            LPWSTR szLang,
            DWORD  cchSize
        );
        """
        lang, out, size = argv
        if not out:
            return 0
        return self._ver_language_name(lang, out, size, True)

    @apihook("VerLanguageNameA", argc=3)
    def VerLanguageNameA(self, emu, argv, ctx: api.ApiContext = None):
        lang, out, size = argv
        if not out:
            return 0
        return self._ver_language_name(lang, out, size, False)

    @apihook("VerFindFileW", argc=8)
    def VerFindFileW(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD VerFindFileW(
            DWORD   uFlags,
            LPCWSTR szFileName,
            LPCWSTR szWinDir,
            LPCWSTR szAppDir,
            LPWSTR  szCurDir,
            UINT   *lpuCurDirLen,
            LPWSTR  szDestDir,
            UINT   *lpuDestDirLen
        );
        """
        flags, filename, windir, appdir, curdir, curlen, destdir, destlen = argv
        if curdir and appdir:
            app = self.read_wide_string(appdir)
            self.write_wide_string(app, curdir)
            if curlen:
                self.mem_write(curlen, (len(app) + 1).to_bytes(4, "little"))
        if destdir and appdir:
            app = self.read_wide_string(appdir)
            self.write_wide_string(app, destdir)
            if destlen:
                self.mem_write(destlen, (len(app) + 1).to_bytes(4, "little"))
        return 0x4000  # VFF_NOTFOUND

    @apihook("VerFindFileA", argc=8)
    def VerFindFileA(self, emu, argv, ctx: api.ApiContext = None):
        flags, filename, windir, appdir, curdir, curlen, destdir, destlen = argv
        if curdir and appdir:
            app = self.read_string(appdir)
            self.write_string(app, curdir)
            if curlen:
                self.mem_write(curlen, (len(app) + 1).to_bytes(4, "little"))
        if destdir and appdir:
            app = self.read_string(appdir)
            self.write_string(app, destdir)
            if destlen:
                self.mem_write(destlen, (len(app) + 1).to_bytes(4, "little"))
        return 0x4000  # VFF_NOTFOUND

    @apihook("VerInstallFileW", argc=8)
    def VerInstallFileW(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD VerInstallFileW(
            DWORD   uFlags,
            LPCWSTR szSrcFileName,
            LPCWSTR szDestFileName,
            LPCWSTR szSrcDir,
            LPCWSTR szDestDir,
            LPCWSTR szCurDir,
            LPWSTR  szTmpFile,
            PUINT   lpuTmpFileLen
        );
        """
        flags, src_file, dest_file, src_dir, dest_dir, cur_dir, tmp_file, tmp_len = argv
        if tmp_file:
            self.write_wide_string(src_file, tmp_file)
        if tmp_len:
            self.mem_write(tmp_len, (len(self.read_wide_string(src_file)) + 1).to_bytes(4, "little"))
        return 0

    @apihook("VerInstallFileA", argc=8)
    def VerInstallFileA(self, emu, argv, ctx: api.ApiContext = None):
        flags, src_file, dest_file, src_dir, dest_dir, cur_dir, tmp_file, tmp_len = argv
        if tmp_file:
            self.write_string(src_file, tmp_file)
        if tmp_len:
            self.mem_write(tmp_len, (len(self.read_string(src_file)) + 1).to_bytes(4, "little"))
        return 0
