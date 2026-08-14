# Copyright (C) 2026 Speakeasy-X

import struct
import uuid

import speakeasy.winenv.arch as _arch

from .. import api


class Rpcrt4(api.ApiHandler):
    """
    Implements exported functions from rpcrt4.dll.
    """

    name = "rpcrt4"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)

        self._register_rpcrt4_batch()

    def _register_rpcrt4_batch(self):
        """Register real handlers for UUID/RPC-string helpers."""
        sd = _arch.CALL_CONV_STDCALL
        ptr = self.get_ptr_size()

        def reg(name, func, argc):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, sd, None)

        def _guid_read(addr):
            if not addr:
                return None
            data = self.mem_read(addr, 16)
            d1, d2, d3 = struct.unpack("<IHH", data[:8])
            return uuid.UUID(f"{d1:08x}-{d2:04x}-{d3:04x}-{data[8:16].hex()}")

        def _guid_write(addr, guid):
            if not addr:
                return
            data = struct.pack("<IHH", guid.time_low, guid.time_mid, guid.time_hi_version) + guid.bytes[8:16]
            self.mem_write(addr, data)

        def UuidCreate(self, emu, argv, ctx=None):
            """RPC_STATUS UuidCreate(UUID *Uuid);"""
            out = argv[0]
            if not out:
                return 87  # RPC_S_INVALID_ARG
            _guid_write(out, uuid.uuid4())
            return 0

        reg("UuidCreate", UuidCreate, 1)

        def UuidCreateSequential(self, emu, argv, ctx=None):
            out = argv[0]
            if not out:
                return 87
            u = uuid.uuid4()
            # sequential variant: version 1 with random node
            u = uuid.UUID(fields=(u.time_low, u.time_mid, 0x1000 | (u.time_hi_version & 0x0FFF), 0x80, 0x80, u.node))
            _guid_write(out, u)
            return 0

        reg("UuidCreateSequential", UuidCreateSequential, 1)

        def UuidFromString(self, emu, argv, ctx=None):
            """RPC_STATUS UuidFromStringW(RPC_WSTR StringUuid, UUID *Uuid);"""
            s, out = argv
            if not s or not out:
                return 87
            txt = self.read_wide_string(s).strip("{}").strip()
            try:
                guid = uuid.UUID(txt)
            except Exception:
                return 1338  # RPC_S_INVALID_STRING_UUID
            _guid_write(out, guid)
            return 0

        reg("UuidFromStringW", UuidFromString, 2)
        reg("UuidFromStringA", UuidFromString, 2)

        def UuidToString(self, emu, argv, ctx=None):
            """RPC_STATUS UuidToStringW(UUID *Uuid, RPC_WSTR *StringUuid);"""
            guid, out = argv
            if not guid or not out:
                return 87
            u = _guid_read(guid)
            if u is None:
                return 1338
            s = str(u).upper()
            wide = (ctx or {}).get("func_name", "").endswith("W")
            data = s.encode("utf-16le") + b"\x00\x00" if wide else s.encode("ascii") + b"\x00"
            buf = self.mem_alloc(len(data), tag="api.rpcrt4.uuidstr")
            self.mem_write(buf, data)
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return 0

        reg("UuidToStringW", UuidToString, 2)
        reg("UuidToStringA", UuidToString, 2)

        def RpcStringFree(self, emu, argv, ctx=None):
            """RPC_STATUS RpcStringFreeW(RPC_WSTR *String);"""
            s = argv[0]
            if not s:
                return 87
            addr = int.from_bytes(self.mem_read(s, ptr), "little")
            if addr:
                try:
                    self.mem_free(addr)
                except Exception:
                    pass
            self.mem_write(s, b"\x00" * ptr)
            return 0

        reg("RpcStringFreeW", RpcStringFree, 1)
        reg("RpcStringFreeA", RpcStringFree, 1)

        def RpcStringBindingCompose(self, emu, argv, ctx=None):
            """RPC_STATUS RpcStringBindingComposeW(
                RPC_CSTR ObjUuid, RPC_CSTR Protseq, RPC_CSTR NetworkAddr,
                RPC_CSTR Endpoint, RPC_CSTR Options, RPC_WSTR *StringBinding);
            """
            obj, protseq, addr, endpoint, options, out = argv
            if not out:
                return 87
            parts = []
            if protseq:
                parts.append(self.read_wide_string(protseq))
            if addr:
                parts.append(self.read_wide_string(addr))
            if endpoint:
                parts.append(self.read_wide_string(endpoint))
            if options:
                parts.append("opt=" + self.read_wide_string(options))
            binding = ""
            if protseq:
                binding = ",".join(parts)
            if obj:
                binding += (":" if binding else "") + self.read_wide_string(obj)
            ws = binding.encode("utf-16le") + b"\x00\x00"
            buf = self.mem_alloc(len(ws), tag="api.rpcrt4.binding")
            self.mem_write(buf, ws)
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return 0

        reg("RpcStringBindingComposeW", RpcStringBindingCompose, 6)
        reg("RpcStringBindingComposeA", RpcStringBindingCompose, 6)

        def RpcStringBindingParse(self, emu, argv, ctx=None):
            binding, obj, protseq, addr, endpoint, options = argv
            if not binding:
                return 87
            if obj:
                self.mem_write(obj, b"\x00" * ptr)
            if protseq:
                self.mem_write(protseq, b"\x00" * ptr)
            if addr:
                self.mem_write(addr, b"\x00" * ptr)
            if endpoint:
                self.mem_write(endpoint, b"\x00" * ptr)
            if options:
                self.mem_write(options, b"\x00" * ptr)
            return 0

        reg("RpcStringBindingParseW", RpcStringBindingParse, 6)
        reg("RpcStringBindingParseA", RpcStringBindingParse, 6)

        def RpcBindingFree(self, emu, argv, ctx=None):
            binding = argv[0]
            if binding:
                self.mem_write(binding, b"\x00" * ptr)
            return 0

        reg("RpcBindingFree", RpcBindingFree, 1)

        def RpcBindingFromStringBinding(self, emu, argv, ctx=None):
            binding, out = argv
            if not out:
                return 87
            self.mem_write(out, struct.pack("<Q", 0xB000))
            return 0

        reg("RpcBindingFromStringBindingW", RpcBindingFromStringBinding, 2)
        reg("RpcBindingFromStringBindingA", RpcBindingFromStringBinding, 2)

        def RpcBindingToStringBinding(self, emu, argv, ctx=None):
            binding, out = argv
            if not out:
                return 87
            ws = b"ncacn_np\x00\x00"
            buf = self.mem_alloc(len(ws), tag="api.rpcrt4.binding")
            self.mem_write(buf, ws)
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            return 0

        reg("RpcBindingToStringBindingW", RpcBindingToStringBinding, 2)
        reg("RpcBindingToStringBindingA", RpcBindingToStringBinding, 2)

        def RpcNetworkIsProtseqValid(self, emu, argv, ctx=None):
            return 0

        reg("RpcNetworkIsProtseqValidW", RpcNetworkIsProtseqValid, 1)
        reg("RpcNetworkIsProtseqValidA", RpcNetworkIsProtseqValid, 1)

        def RpcProtseqVectorFree(self, emu, argv, ctx=None):
            vec = argv[0]
            if vec:
                self.mem_write(vec, b"\x00" * ptr)
            return 0

        reg("RpcProtseqVectorFreeW", RpcProtseqVectorFree, 1)
        reg("RpcProtseqVectorFreeA", RpcProtseqVectorFree, 1)
