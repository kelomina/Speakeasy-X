# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import fnmatch
import hashlib
import io
import logging
import ntpath
import os
import shlex
from typing import Any

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.errors import FileSystemEmuError

logger = logging.getLogger(__name__)


def normalize_response_path(path):
    def _get_speakeasy_root():
        return os.path.join(os.path.dirname(__file__), os.pardir)

    root_var = "$ROOT$"
    if root_var in path:
        root = _get_speakeasy_root()
        return path.replace(root_var, root)
    return path


class MapView:
    """
    Represents a shared memory view
    """

    def __init__(self, base, offset, size, protect, process=None):
        self.base = base
        self.offset = offset
        self.size = size
        self.protect = protect
        self.process = process


class FileMap:
    """
    Represents a memory mapped file
    """

    curr_handle = 0x280

    def __init__(self, name, size, prot, backed_file=None):
        self.name = name
        self.backed_file = backed_file
        self.views = {}
        self.size = size
        self.prot = prot

    def get_handle(self):
        hmap = FileMap.curr_handle
        FileMap.curr_handle += 4
        return hmap

    def add_view(self, base, offset, size, protect):
        view = MapView(base, offset, size, protect)
        self.views.update({base: view})


class File:
    """
    Base class for an emulated file
    """

    curr_handle = 0x80

    def __init__(self, path, config=None, data=b""):
        self.path: str = path
        self.data: io.BytesIO | bytes | None = None
        self.bytes_written: int = 0
        self._size: int = 0
        if data:
            self.data = io.BytesIO(data)
            self._size = len(data)
        self.curr_offset: int = 0
        self.is_dir: bool = False
        self.config: Any = config if config is not None else {}

    def duplicate(self):
        if not self.data and self.config:
            self.data = self.handle_file_data()
            self._sync_size()

        if isinstance(self.data, io.BytesIO):
            data = self.data.getvalue()
        elif isinstance(self.data, bytes):
            data = self.data
        else:
            data = b""

        new = File(self.path, config=self.config, data=data)
        new.is_dir = self.is_dir
        return new

    def get_handle(self):
        hfile = File.curr_handle
        File.curr_handle += 4
        return hfile

    def get_hash(self):
        h = hashlib.sha256()
        data = self.get_data(reset_pointer=True)
        h.update(data)
        return h.hexdigest()

    def _sync_size(self):
        """Refresh self._size from the current self.data buffer."""
        if isinstance(self.data, io.BytesIO):
            self._size = len(self.data.getvalue())
        elif isinstance(self.data, bytes):
            self._size = len(self.data)
        else:
            self._size = 0

    def get_size(self):
        if not self.data and self.config:
            self.data = self.handle_file_data()
            self._sync_size()
        return self._size

    def get_data(self, size=-1, reset_pointer=False):
        if not self.data and self.config:
            self.data = self.handle_file_data()
            self._sync_size()

        if not self.data:
            return b""

        off = self.data.tell()
        if off == self._size:
            if reset_pointer:
                # Reset the file pointer
                self.data.seek(0)
            else:
                return b""

        return self.data.read(size)

    def seek(self, offset, whence):
        if whence not in [io.SEEK_CUR, io.SEEK_SET, io.SEEK_END]:
            return
        if self.data:
            self.data.seek(offset, whence)

    def tell(self):
        if self.data:
            return self.data.tell()
        return None

    def add_data(self, data):

        if not self.data:
            self.data = io.BytesIO()
        off = self.data.tell()
        self.data.seek(0, io.SEEK_END)
        self.data.write(data)
        self.data.seek(off, io.SEEK_SET)
        self.bytes_written += len(data)
        self._size += len(data)

    def remove_data(self):
        self.data = io.BytesIO(b"")
        self._size = 0

    def is_directory(self):
        return self.is_dir

    def handle_file_data(self):
        """
        Based on the emulation config, determine what data
        to return from the read request
        """
        if not self.config:
            return io.BytesIO(b"")

        path = getattr(self.config, "path", None)
        if path:
            path = normalize_response_path(path)
            with open(path, "rb") as f:
                return io.BytesIO(f.read())
        bf = getattr(self.config, "byte_fill", None)
        if bf:
            byte = bf.byte
            if byte.startswith("0x"):
                byte = 0xFF & int(byte, 0)
            else:
                byte = 0xFF & int(byte, 16)
            size = bf.size
            b = (byte).to_bytes(1, "little")
            return b * size
        return io.BytesIO(b"")


class Pipe(File):
    """
    Emulated named pipe objects
    """

    curr_handle = 0x400

    def __init__(self, name, mode, num_instances, out_size, in_size, config=None):
        super().__init__(path=name, config=config)
        self.name = name
        self.mode = mode
        self.num_instances = num_instances
        self.out_size = out_size
        self.in_size = in_size

    def get_handle(self):
        hpipe = Pipe.curr_handle
        Pipe.curr_handle += 4
        return hpipe


class FileManager:
    """
    Manages file system activity during emulation
    """

    def __init__(self, config, emu):
        super().__init__()
        self.file_handles: dict[int, File] = {}
        self.pipe_handles: dict[int, Pipe] = {}
        self.file_maps: dict[int, FileMap] = {}

        # top level config
        self.config: Any = config

        # "files" key of config
        self.file_config: Any = self.config.filesystem
        self.emu: Any = emu

        cmdline = self.config.command_line or ""

        self.emulated_binname = shlex.split(cmdline)[0] if cmdline else ""

        # First file in this list seems to always be the module itself
        self.files: list[File] = []

        # V2-6-2: O(1) path lookup index (key = lowercase path as stored)
        self._path_index: dict[str, File] = {}

        # V2-6-3: pre-built indices for get_emu_file lookups
        self._full_path_exact: dict[str, Any] = {}
        self._full_path_patterns: list[Any] = []
        self._by_ext: dict[str, Any] = {}
        self._default_handler: Any = None
        self._modules_indexed: bool = False
        self._user_modules_by_path: dict[str, Any] = {}
        self._system_modules_by_path: dict[str, Any] = {}
        self._build_file_config_indices()

        full_path_entries = [f for f in self.file_config.files if f.mode == "full_path"]
        if full_path_entries:
            logger.info("Emulated filesystem: %d full_path entries", len(full_path_entries))
            for f in full_path_entries:
                logger.debug("  emu_path=%s  host_path=%s", f.emu_path, getattr(f, "path", None))

    def file_create_mapping(self, hfile, name, size, prot):
        if hfile not in (windefs.INVALID_HANDLE_VALUE, 0):
            f = self.get_file_from_handle(hfile)
            fm = FileMap(name, size, prot, f)
            hnd = fm.get_handle()
            self.file_maps.update({hnd: fm})
            return hnd
        else:
            fm = FileMap(name, size, prot, None)
            hnd = fm.get_handle()
            self.file_maps.update({hnd: fm})
            return hnd

    def walk_files(self):
        for f in self.file_config.files:
            path = getattr(f, "emu_path", None)
            if not path:
                continue
            yield path

    def find_matching_entries(self, search):
        """
        Given a search pattern like ``C:\\*`` or ``C:\\Windows\\*.exe``,
        yield ``(name, is_dir)`` tuples for immediate children that match,
        synthesizing directory entries from configured file paths.
        """
        search_dir = ntpath.dirname(search)
        pattern = ntpath.basename(search)
        if not pattern:
            return

        search_dir_lower = search_dir.lower().rstrip("\\")
        seen = set()

        for emu_path in self.walk_files():
            emu_lower = emu_path.lower()
            if not emu_lower.startswith(search_dir_lower + "\\"):
                continue
            remainder = emu_lower[len(search_dir_lower) + 1 :]
            parts = remainder.split("\\")
            child = parts[0]
            is_dir = len(parts) > 1
            if child in seen:
                continue
            if fnmatch.fnmatch(child, pattern.lower()):
                seen.add(child)
                yield (child, is_dir)

    def get_dropped_files(self):
        return [f for f in self.files if f.bytes_written == f.get_size()]

    def get_mapping_from_handle(self, handle):
        return self.file_maps.get(handle)

    def get_mapping_from_addr(self, addr):
        for h, fmap in self.file_maps.items():
            for base, view in fmap.views.items():
                if base == addr:
                    return fmap

    def get_file_from_handle(self, handle):
        return self.file_handles.get(handle)

    def get_pipe_from_handle(self, handle):
        return self.pipe_handles.get(handle)

    def get_file_from_path(self, path):
        # The emulated sample is requesting itself. The module path
        # for it is(?) always the first entry in self.files
        if self.emulated_binname in path:
            return self.files[0]

        # Resolve relative paths against the current directory
        if not ntpath.isabs(path):
            cwd = self.config.current_dir
            path = ntpath.normpath(ntpath.join(cwd, path))

        return self._path_index.get(path.lower())

    def get_all_files(self):
        return self.files

    def handle_file_data(self, fconf):
        path = getattr(fconf, "path", None)
        if path:
            path = normalize_response_path(path)
            with open(path, "rb") as f:
                return f.read()
        bf = getattr(fconf, "byte_fill", None)
        if bf:
            byte = bf.byte if hasattr(bf, "byte") else bf.get("byte")
            if byte.startswith("0x"):
                byte = 0xFF & int(byte, 0)
            else:
                byte = 0xFF & int(byte, 16)
            size = bf.size if hasattr(bf, "size") else bf.get("size")
            b = (byte).to_bytes(1, "little")
            return b * size

    def add_existing_file(self, path, data):
        """
        Register an existing file already included in the emulation space
        (with data)
        """
        f = File(path, data=data)
        self.files.append(f)
        if f.path:
            self._path_index[f.path.lower()] = f
        return f

    def create_file(self, path):
        f = self.get_file_from_path(path)
        if f:
            self.files.remove(f)
            if f.path:
                self._path_index.pop(f.path.lower(), None)
        f = File(path)
        self.files.append(f)
        if f.path:
            self._path_index[f.path.lower()] = f
        return f

    def delete_file(self, path):
        f = self.get_file_from_path(path)
        if f:
            self.files.remove(f)
            if f.path:
                self._path_index.pop(f.path.lower(), None)
            return True
        return False

    def _build_file_config_indices(self):
        """Pre-build indices for get_emu_file lookups (V2-6-3)."""
        for f in self.file_config.files:
            mode = getattr(f, "mode", None)
            if mode == "full_path":
                emu_path = getattr(f, "emu_path", None)
                if not emu_path:
                    continue
                emu_lower = emu_path.lower()
                # Split exact paths (no wildcard chars) for O(1) lookup,
                # keep wildcard patterns for fnmatch fallback.
                if any(c in emu_lower for c in "*?["):
                    self._full_path_patterns.append(f)
                else:
                    self._full_path_exact.setdefault(emu_lower, f)
            elif mode == "by_ext":
                ext = getattr(f, "ext", None)
                if ext:
                    self._by_ext.setdefault(ext, f)
            elif mode == "default":
                if self._default_handler is None:
                    self._default_handler = f

    def _ensure_modules_indexed(self):
        """Lazily build module path indices (modules may be populated after init)."""
        if self._modules_indexed:
            return
        all_modules = getattr(self.config, "modules", None)
        if all_modules is not None:
            for m in getattr(all_modules, "user_modules", None) or []:
                mp = getattr(m, "path", None)
                if mp:
                    self._user_modules_by_path.setdefault(mp, m)
            for m in getattr(all_modules, "system_modules", None) or []:
                mp = getattr(m, "path", None)
                if mp:
                    self._system_modules_by_path.setdefault(mp, m)
        self._modules_indexed = True

    def get_emu_file(self, path):
        # Resolve relative paths against the current directory
        if not ntpath.isabs(path):
            cwd = self.config.current_dir
            path = ntpath.normpath(ntpath.join(cwd, path))

        path_lower = path.lower()

        # Does this file exist in our emulation environment
        # See if we have a handler for this exact file (O(1) exact match)
        f = self._full_path_exact.get(path_lower)
        if f is not None:
            return f
        # Fall back to wildcard pattern match
        for f in self._full_path_patterns:
            if fnmatch.fnmatch(path_lower, f.emu_path.lower()):
                return f

        all_modules = self.config.modules

        if self.emu.arch == _arch.ARCH_X86:
            decoy_dir = all_modules.module_directory_x86 or ""
        else:
            decoy_dir = all_modules.module_directory_x64 or ""

        ext = os.path.splitext(path)[1]

        # Check if we can load the contents of a decoy DLL (indexed by path)
        self._ensure_modules_indexed()
        m = self._user_modules_by_path.get(path)
        if m is not None:
            newconf = dict()
            newconf["path"] = os.path.join(decoy_dir, m.name + ext)
            return newconf

        m = self._system_modules_by_path.get(path)
        if m is not None:
            newconf = dict()
            newconf["path"] = os.path.join(decoy_dir, m.name + ext)
            return newconf

        # If no full path handler exists, do we have an extension handler?
        path_ext = ntpath.splitext(path)[-1:][0].strip(".")
        if path_ext:
            f = self._by_ext.get(path_ext.lower())
            if f is not None:
                return f

        # Finally, do we have a catch-all default handler?
        return self._default_handler

    def pipe_open(self, path, mode, num_instances, out_size, in_size):
        hnd = None
        fconf = self.get_emu_file(path)
        if not fconf:
            fconf = {}
        p = Pipe(path, mode, num_instances, out_size, in_size, config=fconf)
        hnd = p.get_handle()
        self.pipe_handles.update({hnd: p})
        return hnd

    def does_file_exist(self, path):
        if self.get_file_from_path(path):
            return True

        if self.get_emu_file(path):
            return True
        return False

    def get_object_from_handle(self, handle):
        obj = self.file_maps.get(handle)
        if obj:
            return obj
        obj = self.pipe_handles.get(handle)
        if obj:
            return obj
        obj = self.file_handles.get(handle)
        if obj:
            return obj

    def file_open(self, path, create=False, truncate=False, is_dir=False):
        hnd = None

        if create:
            f = self.create_file(path)
            hnd = f.get_handle()
            self.file_handles.update({hnd: f})
        else:
            f = self.get_file_from_path(path)

            if f:
                # Deep-copy this file so we can have separate file
                # offset pointers
                dup = f.duplicate()
                hnd = dup.get_handle()
                self.file_handles.update({hnd: dup})
                return hnd

            fconf = self.get_emu_file(path)
            if not fconf:
                logger.debug("file_open: no handler for path %r", path)
                return hnd

            real_path = getattr(fconf, "path", None) or ""
            real_path = normalize_response_path(real_path)
            if not truncate:
                if real_path and not os.path.exists(real_path):
                    raise FileSystemEmuError(f"File path not found: {real_path}")
                f = File(path, config=fconf)
                self.files.append(f)
                if f.path:
                    self._path_index[f.path.lower()] = f
            else:
                if real_path and not os.path.exists(real_path):
                    raise FileSystemEmuError(f"File path not found: {real_path}")
                f = File(path, config=fconf)
                self.files.append(f)
                if f.path:
                    self._path_index[f.path.lower()] = f
            hnd = f.get_handle()
            self.file_handles.update({hnd: f})

        return hnd
