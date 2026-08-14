# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import datetime
import math
import struct
from typing import Any

import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.windows.windows as windef

from .. import api

EINVAL = 22
ERANGE = 34
_TRUNCATE = 0xFFFFFFFF

TIME_BASE = 1576292568
RAND_BASE = 0
TICK_BASE = 86400000  # 1 day in millisecs

# Signal types
SIGINT = 2  # interrupt
SIGILL = 4  # illegal instruction - invalid function image
SIGFPE = 8  # floating point exception
SIGSEGV = 11  # segment violation
SIGTERM = 15  # Software termination signal from kill
SIGBREAK = 21  # Ctrl-Break sequence
SIGABRT = 22  # abnormal termination triggered by abort call

# Signal action codes
SIG_DFL = 0  # default signal action
SIG_IGN = 1  # ignore signal
SIG_GET = 2  # return current value
SIG_SGE = 3  # signal gets error
SIG_ACK = 4  # acknowledge
SIG_ERR = -1  # signal error value


class Msvcrt(api.ApiHandler):
    """
    Implements functions from various versions of the C runtime on Windows
    """

    name = "msvcrt"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)

        self.stdin = 0
        self.stdout = 1
        self.stderr = 2

        self.rand_int = RAND_BASE

        self.funcs: dict[str, Any] = {}
        self.data: dict[str, Any] = {}
        self.wintypes = windef

        self.tick_counter: int = TICK_BASE
        self.errno_t: int | None = None
        self.file_streams: dict[int, Any] = {}

        super().__get_hook_attrs__(self)

        self._register_crt_batch()
        self._register_crt_io_batch()

    def _register_crt_batch(self):
        """
        Register real handlers for CRT pure functions (math, ctype, string,
        conversions, time and formatting) that share common semantics, using
        the same conventions as the rest of this module. Names that already
        have a real handler are left untouched; the generated stubs only
        remain for functions without a real implementation. UCRT legacy
        aliases (`_o_X`) and locale variants (`_X_l`) reuse the base handlers.
        """
        cd = e_arch.CALL_CONV_CDECL
        fl = e_arch.CALL_CONV_FLOAT
        ptr = self.get_ptr_size()

        def reg(name, func, argc, conv):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, conv, None)

        def reg_dbl(name, fn, argc):
            if argc == 1:
                def impl(self, emu, argv, ctx=None):
                    return self.double_to_hex(fn(self.hex_to_double(argv[0])))
            elif argc == 2:
                def impl(self, emu, argv, ctx=None):
                    return self.double_to_hex(fn(self.hex_to_double(argv[0]), self.hex_to_double(argv[1])))
            else:
                def impl(self, emu, argv, ctx=None):
                    return self.double_to_hex(fn(*(self.hex_to_double(a) for a in argv[:argc])))
            reg(name, impl, argc, fl)

        def reg_flt(name, fn, argc):
            if argc == 1:
                def impl(self, emu, argv, ctx=None):
                    v = struct.unpack("<f", struct.pack("<I", argv[0] & 0xFFFFFFFF))[0]
                    return struct.unpack("<I", struct.pack("<f", fn(v)))[0]
            else:
                def impl(self, emu, argv, ctx=None):
                    vals = [struct.unpack("<f", struct.pack("<I", a & 0xFFFFFFFF))[0] for a in argv[:argc]]
                    return struct.unpack("<I", struct.pack("<f", fn(*vals)))[0]
            reg(name, impl, argc, fl)

        def reg_dbl_mixed(name, fn, argc):
            """double-returning function whose args are not doubles:
            the result is written to XMM0 explicitly (return reg for floats)."""

            def impl(self, emu, argv, ctx=None):
                rv = fn(*argv)
                emu.reg_write(e_arch.X86_REG_XMM0, self.double_to_hex(rv))
                return 0

            reg(name, impl, argc, cd)

        # ---- math (double) ----
        math_unary = {
            "acos": math.acos, "acosh": math.acosh, "asin": math.asin,
            "asinh": math.asinh, "atan": math.atan, "atanh": math.atanh,
            "cbrt": lambda x: math.copysign(abs(x) ** (1.0 / 3.0), x),
            "ceil": lambda x: float(math.ceil(x)),
            "cos": math.cos, "cosh": math.cosh,
            "erf": math.erf, "erfc": math.erfc, "exp": math.exp,
            "exp2": lambda x: 2.0 ** x, "expm1": math.expm1,
            "fabs": math.fabs, "floor": lambda x: float(math.floor(x)),
            "lgamma": math.lgamma,
            "log": math.log, "log10": math.log10, "log1p": math.log1p,
            "log2": math.log2, "sin": math.sin, "sinh": math.sinh,
            "sqrt": math.sqrt, "tan": math.tan, "tanh": math.tanh,
            "tgamma": math.gamma, "trunc": lambda x: float(math.trunc(x)),
            "nearbyint": lambda x: float(round(x)), "rint": lambda x: float(round(x)),
            "round": lambda x: float(round(x)),
            "logb": lambda x: math.floor(math.log2(abs(x))) if x else float("-inf"),
        }
        math_binary = {
            "atan2": math.atan2, "copysign": math.copysign,
            "fdim": lambda a, b: max(a - b, 0.0), "fmax": max, "fmin": min,
            "fmod": math.fmod, "hypot": math.hypot, "nextafter": math.nextafter,
            "pow": math.pow, "remainder": math.remainder,
            "ldexp": lambda x, n: math.ldexp(x, int(n)),
            "scalbn": lambda x, n: math.ldexp(x, int(n)),
            "scalbln": lambda x, n: math.ldexp(x, int(n)),
        }
        for name, fn in math_unary.items():
            reg_dbl(name, fn, 1)
            reg_flt(name + "f", fn, 1)
            reg_dbl(name + "l", fn, 1)
        for name, fn in math_binary.items():
            reg_dbl(name, fn, 2)
            reg_flt(name + "f", fn, 2)
            reg_dbl(name + "l", fn, 2)
        reg_dbl("fma", lambda a, b, c: a * b + c, 3)
        reg_flt("fmaf", lambda a, b, c: a * b + c, 3)
        reg_dbl("fmal", lambda a, b, c: a * b + c, 3)

        def modf_impl(self, emu, argv, ctx=None):
            x = self.hex_to_double(argv[0])
            ip, fp = math.modf(x)
            if argv[1]:
                self.mem_write(argv[1], self.double_to_hex(ip).to_bytes(8, "little"))
            return self.double_to_hex(fp)

        reg("modf", modf_impl, 2, fl)

        def modff_impl(self, emu, argv, ctx=None):
            x = struct.unpack("<f", struct.pack("<I", argv[0] & 0xFFFFFFFF))[0]
            ip, fp = math.modf(x)
            if argv[1]:
                self.mem_write(argv[1], struct.pack("<I", struct.unpack("<I", struct.pack("<f", ip))[0]))
            return struct.unpack("<I", struct.pack("<f", fp))[0]

        reg("modff", modff_impl, 2, fl)

        def frexp_impl(self, emu, argv, ctx=None):
            x = self.hex_to_double(argv[0])
            m, e = math.frexp(x)
            if argv[1]:
                self.mem_write(argv[1], struct.pack("<i", e))
            return self.double_to_hex(m)

        reg("frexp", frexp_impl, 2, fl)

        def remquo_impl(self, emu, argv, ctx=None):
            x = self.hex_to_double(argv[0])
            y = self.hex_to_double(argv[1])
            q = int(round(x / y)) if y else 0
            if argv[2]:
                self.mem_write(argv[2], struct.pack("<i", q))
            return self.double_to_hex(x - q * y)

        reg("remquo", remquo_impl, 3, fl)

        # ---- ctype ----
        def _isascii_c(c):
            return 0 <= c < 0x80

        def _isalnum(c):
            return _isascii_c(c) and chr(c).isalnum()

        def _isalpha(c):
            return _isascii_c(c) and chr(c).isalpha()

        def _isblank(c):
            return c in (0x20, 0x09)

        def _iscntrl(c):
            return 0 <= c < 0x20 or c == 0x7F

        def _isdigit(c):
            return 0x30 <= c <= 0x39

        def _isgraph(c):
            return 0x21 <= c <= 0x7E

        def _islower(c):
            return 0x61 <= c <= 0x7A

        def _isprint(c):
            return 0x20 <= c <= 0x7E

        def _ispunct(c):
            return _isgraph(c) and not (_isalnum(c))

        def _isspace(c):
            return c in (0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D)

        def _isupper(c):
            return 0x41 <= c <= 0x5A

        def _isxdigit(c):
            return _isdigit(c) or 0x41 <= c <= 0x46 or 0x61 <= c <= 0x66

        def _isleadbyte(c):
            return 0x81 <= c <= 0x9F or 0xE0 <= c <= 0xFC

        ctype_ansi = {
            "isalnum": _isalnum, "isalpha": _isalpha, "isblank": _isblank,
            "iscntrl": _iscntrl, "isdigit": _isdigit, "isgraph": _isgraph,
            "islower": _islower, "isprint": _isprint, "ispunct": _ispunct,
            "isspace": _isspace, "isupper": _isupper, "isxdigit": _isxdigit,
            "isleadbyte": _isleadbyte,
        }

        def ctype_impl(fn):
            def impl(self, emu, argv, ctx=None):
                return 1 if fn(argv[0] & 0xFFFFFFFF) else 0

            return impl

        for name, fn in ctype_ansi.items():
            reg(name, ctype_impl(fn), 1, cd)
            reg(f"_{name}_l", ctype_impl(fn), 2, cd)

        def isw_impl(fn):
            def impl(self, emu, argv, ctx=None):
                c = argv[0] & 0xFFFF
                if c < 0x100:
                    return 1 if fn(c) else 0
                try:
                    return 1 if fn(c) or (c and getattr(chr(c), fn.__name__.replace("_isw", "is"))()) else 0
                except Exception:
                    return 0

            return impl

        for name, fn in {
            "iswalnum": lambda c: _isalnum(c),
            "iswalpha": lambda c: _isalpha(c),
            "iswblank": lambda c: _isblank(c),
            "iswcntrl": lambda c: _iscntrl(c) or 0x80 <= c <= 0x9F,
            "iswdigit": lambda c: _isdigit(c),
            "iswgraph": lambda c: _isgraph(c),
            "iswlower": lambda c: _islower(c),
            "iswprint": lambda c: _isprint(c),
            "iswpunct": lambda c: _ispunct(c),
            "iswspace": lambda c: _isspace(c),
            "iswupper": lambda c: _isupper(c),
            "iswxdigit": lambda c: _isxdigit(c),
        }.items():
            reg(name, isw_impl(fn), 1, cd)
            reg(f"_{name}_l", isw_impl(fn), 2, cd)

        def iswascii_impl(self, emu, argv, ctx=None):
            return 1 if _isascii_c(argv[0] & 0xFFFF) else 0

        reg("iswascii", iswascii_impl, 1, cd)
        reg("_iswascii_l", iswascii_impl, 2, cd)

        def towlower_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFFFF
            if _isupper(c):
                return c + 0x20
            if c > 0x7F:
                try:
                    return ord(chr(c).lower())
                except Exception:
                    return c
            return c

        def towupper_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFFFF
            if _islower(c):
                return c - 0x20
            if c > 0x7F:
                try:
                    return ord(chr(c).upper())
                except Exception:
                    return c
            return c

        reg("towlower", towlower_impl, 1, cd)
        reg("towupper", towupper_impl, 1, cd)
        reg("_towlower_l", towlower_impl, 2, cd)
        reg("_towupper_l", towupper_impl, 2, cd)

        def _tolower_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFF
            return c + 0x20 if _isupper(c) else c

        def _toupper_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFF
            return c - 0x20 if _islower(c) else c

        reg("_tolower", _tolower_impl, 1, cd)
        reg("_toupper", _toupper_impl, 1, cd)
        reg("_tolower_l", _tolower_impl, 2, cd)
        reg("_toupper_l", _toupper_impl, 2, cd)

        def __isascii_impl(self, emu, argv, ctx=None):
            return 1 if _isascii_c(argv[0] & 0xFF) else 0

        reg("__isascii", __isascii_impl, 1, cd)

        def __iscsym_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFF
            return 1 if _isalnum(c) or c == 0x5F else 0

        reg("__iscsym", __iscsym_impl, 1, cd)

        def __iscsymf_impl(self, emu, argv, ctx=None):
            c = argv[0] & 0xFF
            return 1 if _isalpha(c) or c == 0x5F else 0

        reg("__iscsymf", __iscsymf_impl, 1, cd)

        def __toascii_impl(self, emu, argv, ctx=None):
            return argv[0] & 0x7F

        reg("__toascii", __toascii_impl, 1, cd)

        # _isctype / is_wctype with ctype masks
        def ctype_mask(c):
            mask = 0
            if _isupper(c):
                mask |= 0x0001
            if _islower(c):
                mask |= 0x0002
            if _isdigit(c):
                mask |= 0x0004
            if _isspace(c):
                mask |= 0x0008
            if _ispunct(c):
                mask |= 0x0010
            if _iscntrl(c):
                mask |= 0x0020
            if _isblank(c):
                mask |= 0x0040
            if _isxdigit(c):
                mask |= 0x0080
            if _isleadbyte(c):
                mask |= 0x8000
            return mask

        def isctype_impl(self, emu, argv, ctx=None):
            c, mask = argv
            return 1 if (ctype_mask(c & 0xFFFFFFFF) & mask) else 0

        reg("_isctype", isctype_impl, 2, cd)
        reg("is_wctype", isctype_impl, 2, cd)
        reg("_isctype_l", isctype_impl, 3, cd)
        reg("_iswctype_l", isctype_impl, 3, cd)

        # ---- string / memory ----
        def memchr_impl(self, emu, argv, ctx=None):
            dest, c, count = argv
            if not dest:
                return 0
            data = self.mem_read(dest, count)
            idx = data.find(bytes([c & 0xFF]))
            return dest + idx if idx >= 0 else 0

        reg("memchr", memchr_impl, 3, cd)

        def memcpy_s_impl(self, emu, argv, ctx=None):
            dest, destsz, src, count = argv
            if count > destsz:
                return 22  # EINVAL
            self.mem_write(dest, self.mem_read(src, count))
            return 0

        reg("memcpy_s", memcpy_s_impl, 4, cd)
        reg("memmove_s", memcpy_s_impl, 4, cd)

        def memccpy_impl(self, emu, argv, ctx=None):
            dest, src, c, count = argv
            if not dest or not src:
                return 0
            data = self.mem_read(src, count)
            idx = data.find(bytes([c & 0xFF]))
            if idx < 0:
                self.mem_write(dest, data)
                return 0
            self.mem_write(dest, data[: idx + 1])
            return dest + idx + 1

        reg("_memccpy", memccpy_impl, 4, cd)

        def memicmp_impl(self, emu, argv, ctx=None):
            s1, s2, count = argv
            a = self.mem_read(s1, count).lower()
            b = self.mem_read(s2, count).lower()
            if a == b:
                return 0
            return -1 if a < b else 1

        reg("_memicmp", memicmp_impl, 3, cd)

        def strnlen_impl(self, emu, argv, ctx=None):
            s, maxlen = argv
            if not s:
                return 0
            try:
                data = self.mem_read(s, maxlen)
            except Exception:
                return 0
            idx = data.find(b"\x00")
            return idx if idx >= 0 else maxlen

        reg("strnlen", strnlen_impl, 2, cd)

        def wcsnlen_impl(self, emu, argv, ctx=None):
            s, maxlen = argv
            if not s:
                return 0
            try:
                data = self.mem_read(s, maxlen * 2)
            except Exception:
                return 0
            n = 0
            for i in range(0, len(data), 2):
                if data[i : i + 2] == b"\x00\x00":
                    return n
                n += 1
            return maxlen

        reg("wcsnlen", wcsnlen_impl, 2, cd)

        def strspn_impl(self, emu, argv, ctx=None):
            s, accept = argv
            if not s or not accept:
                return 0
            data = self.read_string(s).encode("latin-1")
            acc = set(self.read_string(accept).encode("latin-1"))
            n = 0
            for b in data:
                if b not in acc:
                    break
                n += 1
            return n

        reg("strspn", strspn_impl, 2, cd)
        reg("_strspn_l", strspn_impl, 3, cd)

        def strcspn_impl(self, emu, argv, ctx=None):
            s, reject = argv
            if not s or not reject:
                return 0
            data = self.read_string(s).encode("latin-1")
            rej = set(self.read_string(reject).encode("latin-1"))
            n = 0
            for b in data:
                if b in rej:
                    break
                n += 1
            return n

        reg("strcspn", strcspn_impl, 2, cd)
        reg("_strcspn_l", strcspn_impl, 3, cd)

        def strpbrk_impl(self, emu, argv, ctx=None):
            s, accept = argv
            if not s or not accept:
                return 0
            data = self.read_string(s).encode("latin-1")
            acc = set(self.read_string(accept).encode("latin-1"))
            for i, b in enumerate(data):
                if b in acc:
                    return s + i
            return 0

        reg("strpbrk", strpbrk_impl, 2, cd)
        reg("_strpbrk_l", strpbrk_impl, 3, cd)

        def wcspbrk_impl(self, emu, argv, ctx=None):
            s, accept = argv
            if not s or not accept:
                return 0
            data = self.read_wide_string(s)
            acc = set(self.read_wide_string(accept))
            for i, ch in enumerate(data):
                if ch in acc:
                    return s + i * 2
            return 0

        reg("wcspbrk", wcspbrk_impl, 2, cd)
        reg("_wcspbrk_l", wcspbrk_impl, 3, cd)

        def strtok_impl(self, emu, argv, ctx=None):
            s, delim = argv
            if not delim:
                return 0
            dset = set(self.read_string(delim).encode("latin-1"))
            if s:
                self._strtok_save = [s, dset]
            elif self._strtok_save:
                s, dset = self._strtok_save
                if s is None:
                    return 0
            else:
                return 0
            start = s
            while True:
                b = self.mem_read(start, 1)
                if not b or b[0] not in dset:
                    break
                start += 1
            if not self.mem_read(start, 1) or self.mem_read(start, 1)[0] == 0:
                self._strtok_save = [None, dset]
                return 0
            end = start
            while True:
                b = self.mem_read(end, 1)
                if not b or b[0] == 0:
                    self._strtok_save = [None, dset]
                    return start
                if b[0] in dset:
                    self.mem_write(end, b"\x00")
                    self._strtok_save = [end + 1, dset]
                    return start
                end += 1

        self._strtok_save = None
        reg("strtok", strtok_impl, 2, cd)

        def strtok_s_impl(self, emu, argv, ctx=None):
            s, delim, context = argv
            if not delim or not context:
                return 0
            dset = set(self.read_string(delim).encode("latin-1"))
            cur = s if s else int.from_bytes(self.mem_read(context, ptr), "little")
            if not cur:
                return 0
            while True:
                b = self.mem_read(cur, 1)
                if not b or b[0] not in dset:
                    break
                cur += 1
            if not self.mem_read(cur, 1) or self.mem_read(cur, 1)[0] == 0:
                self.mem_write(context, b"\x00" * ptr)
                return 0
            end = cur
            while True:
                b = self.mem_read(end, 1)
                if not b or b[0] == 0:
                    self.mem_write(context, b"\x00" * ptr)
                    return cur
                if b[0] in dset:
                    self.mem_write(end, b"\x00")
                    self.mem_write(context, (end + 1).to_bytes(ptr, "little"))
                    return cur
                end += 1

        reg("strtok_s", strtok_s_impl, 3, cd)

        def wcstok_impl(self, emu, argv, ctx=None):
            s, delim = argv
            if not delim:
                return 0
            dset = set(self.read_wide_string(delim))
            if s:
                self._wcstok_save = [s, dset]
            elif self._wcstok_save:
                s, dset = self._wcstok_save
                if s is None:
                    return 0
            else:
                return 0
            while True:
                b = self.mem_read(s, 2)
                if len(b) < 2 or b not in dset:
                    break
                s += 2
            if not self.mem_read(s, 2) or self.mem_read(s, 2) == b"\x00\x00":
                self._wcstok_save = [None, dset]
                return 0
            end = s
            while True:
                b = self.mem_read(end, 2)
                if len(b) < 2 or b == b"\x00\x00":
                    self._wcstok_save = [None, dset]
                    return s
                if b in dset:
                    self.mem_write(end, b"\x00\x00")
                    self._wcstok_save = [end + 2, dset]
                    return s
                end += 2

        self._wcstok_save = None
        reg("wcstok", wcstok_impl, 2, cd)

        def wcstok_s_impl(self, emu, argv, ctx=None):
            s, delim, context = argv
            if not delim or not context:
                return 0
            dset = set(self.read_wide_string(delim))
            cur = s if s else int.from_bytes(self.mem_read(context, ptr), "little")
            if not cur:
                return 0
            while True:
                b = self.mem_read(cur, 2)
                if len(b) < 2 or b not in dset:
                    break
                cur += 2
            if not self.mem_read(cur, 2) or self.mem_read(cur, 2) == b"\x00\x00":
                self.mem_write(context, b"\x00" * ptr)
                return 0
            end = cur
            while True:
                b = self.mem_read(end, 2)
                if len(b) < 2 or b == b"\x00\x00":
                    self.mem_write(context, b"\x00" * ptr)
                    return cur
                if b in dset:
                    self.mem_write(end, b"\x00\x00")
                    self.mem_write(context, (end + 2).to_bytes(ptr, "little"))
                    return cur
                end += 2

        reg("wcstok_s", wcstok_s_impl, 3, cd)

        def case_impl(wide, upper):
            def impl(self, emu, argv, ctx=None):
                s = argv[0]
                if not s:
                    return 0
                if wide:
                    data = self.read_wide_string(s)
                else:
                    data = self.read_string(s)
                if upper:
                    conv = data.upper()
                else:
                    conv = data.lower()
                if wide:
                    self.write_wide_string(conv, s)
                else:
                    self.write_string(conv, s)
                return s

            return impl

        for name, wide, upper in [
            ("_strlwr_s", False, False), ("_strupr", False, True), ("_strupr_s", False, True),
            ("wcslwr", True, False), ("wcslwr_s", True, False),
            ("wcsupr", True, True), ("wcsupr_s", True, True),
        ]:
            argc = 2 if name.endswith("_s") else 1
            reg(name, case_impl(wide, upper), argc, cd)
            if name.endswith("_s"):
                reg(f"_{name}_l", case_impl(wide, upper), argc + 1, cd)
            elif not name.startswith("_"):
                reg(f"_{name}_l", case_impl(wide, upper), argc + 1, cd)

        def strrev_impl(self, emu, argv, ctx=None):
            s = argv[0]
            if not s:
                return 0
            data = self.read_string(s)
            self.write_string(data[::-1], s)
            return s

        reg("_strrev", strrev_impl, 1, cd)

        def strset_impl(self, emu, argv, ctx=None):
            s, c = argv
            if not s:
                return 0
            data = self.read_string(s)
            self.write_string(chr(c & 0xFF) * len(data), s)
            return s

        reg("_strset", strset_impl, 2, cd)
        reg("_strset_s", strset_impl, 3, cd)

        def strnset_impl(self, emu, argv, ctx=None):
            s, c, n = argv
            if not s:
                return 0
            data = self.read_string(s)
            n = min(n, len(data))
            self.write_string(chr(c & 0xFF) * n + data[n:], s)
            return s

        reg("_strnset", strnset_impl, 3, cd)
        reg("_strnset_s", strnset_impl, 4, cd)

        def wcsset_impl(self, emu, argv, ctx=None):
            s, c = argv
            if not s:
                return 0
            data = self.read_wide_string(s)
            self.write_wide_string(chr(c & 0xFFFF) * len(data), s)
            return s

        reg("wcsset", wcsset_impl, 2, cd)
        reg("_wcsset", wcsset_impl, 2, cd)
        reg("wcsset_s", wcsset_impl, 3, cd)
        reg("_wcsset_s", wcsset_impl, 3, cd)

        def wcsnset_impl(self, emu, argv, ctx=None):
            s, c, n = argv
            if not s:
                return 0
            data = self.read_wide_string(s)
            n = min(n, len(data))
            self.write_wide_string(chr(c & 0xFFFF) * n + data[n:], s)
            return s

        reg("wcsnset", wcsnset_impl, 3, cd)
        reg("_wcsnset", wcsnset_impl, 3, cd)
        reg("wcsnset_s", wcsnset_impl, 4, cd)
        reg("_wcsnset_s", wcsnset_impl, 4, cd)

        def safe_cat_impl(wide, dstfirst):
            def impl(self, emu, argv, ctx=None):
                dst = argv[0]
                src = argv[1]
                if not dst or not src:
                    return 22  # EINVAL
                if wide:
                    d = self.read_wide_string(dst)
                    s = self.read_wide_string(src)
                else:
                    d = self.read_string(dst)
                    s = self.read_string(src)
                if dstfirst:
                    d = s + d
                else:
                    d = d + s
                if wide:
                    self.write_wide_string(d, dst)
                else:
                    self.write_string(d, dst)
                return 0

            return impl

        reg("strcat_s", safe_cat_impl(False, False), 3, cd)
        reg("wcscat_s", safe_cat_impl(True, False), 3, cd)
        reg("_mbscat_s", safe_cat_impl(False, False), 3, cd)
        reg("_mbscat_s_l", safe_cat_impl(False, False), 4, cd)

        def safe_copy_impl(wide, trunc):
            def impl(self, emu, argv, ctx=None):
                dst = argv[0]
                src = argv[1]
                if not dst or not src:
                    return 22  # EINVAL
                if wide:
                    s = self.read_wide_string(src)
                else:
                    s = self.read_string(src)
                size = argv[2] if len(argv) > 2 else len(s) + 1
                if trunc:
                    if len(s) >= size:
                        s = s[: max(size - 1, 0)]
                elif len(s) + 1 > size:
                    return 34  # ERANGE
                if wide:
                    self.write_wide_string(s, dst)
                else:
                    self.write_string(s, dst)
                return 0

            return impl

        reg("strcpy_s", safe_copy_impl(False, False), 3, cd)
        reg("wcscpy_s", safe_copy_impl(True, False), 3, cd)
        reg("strncpy_s", safe_copy_impl(False, True), 4, cd)
        reg("wcsncpy_s", safe_copy_impl(True, True), 4, cd)
        reg("_mbscpy_s", safe_copy_impl(False, False), 3, cd)
        reg("_mbscpy_s_l", safe_copy_impl(False, False), 4, cd)
        reg("_mbsncpy_s", safe_copy_impl(False, True), 4, cd)
        reg("_mbsncpy_s_l", safe_copy_impl(False, True), 5, cd)

        def strncat_impl(self, emu, argv, ctx=None):
            dst, src, n = argv
            if not dst or not src:
                return 0
            d = self.read_string(dst)
            s = self.read_string(src)
            self.write_string(d + s[:n], dst)
            return dst

        reg("strncat", strncat_impl, 3, cd)

        def wcsncat_impl(self, emu, argv, ctx=None):
            dst, src, n = argv
            if not dst or not src:
                return 0
            d = self.read_wide_string(dst)
            s = self.read_wide_string(src)
            self.write_wide_string(d + s[:n], dst)
            return dst

        reg("wcsncat", wcsncat_impl, 3, cd)
        reg("wcsncat_s", wcsncat_impl, 4, cd)
        reg("_wcsncat_s", wcsncat_impl, 4, cd)

        def strncat_s_impl(self, emu, argv, ctx=None):
            dst, size, src, n = argv
            if not dst or not src:
                return 22
            d = self.read_string(dst)
            s = self.read_string(src)
            new = d + s[:n]
            if len(new) >= size:
                return 34  # ERANGE
            self.write_string(new, dst)
            return 0

        reg("strncat_s", strncat_s_impl, 4, cd)

        def strdup_impl(wide):
            def impl(self, emu, argv, ctx=None):
                s = argv[0]
                if not s:
                    return 0
                if wide:
                    text = self.read_wide_string(s)
                    data = text.encode("utf-16le") + b"\x00\x00"
                else:
                    text = self.read_string(s)
                    data = text.encode("latin-1") + b"\x00"
                buf = self.mem_alloc(len(data), tag="api.msvcrt.strdup")
                self.mem_write(buf, data)
                return buf

            return impl

        reg("_strdup", strdup_impl(False), 1, cd)
        reg("_wcsdup", strdup_impl(True), 1, cd)

        def wmemcpy_s_impl(self, emu, argv, ctx=None):
            dest, destsz, src, count = argv
            if count > destsz:
                return 22
            self.mem_write(dest, self.mem_read(src, count * 2))
            return 0

        reg("wmemcpy_s", wmemcpy_s_impl, 4, cd)
        reg("wmemmove_s", wmemcpy_s_impl, 4, cd)

        def mbstowcs_impl(self, emu, argv, ctx=None):
            dst, src, n = argv
            if not src:
                return 0
            s = self.read_string(src)
            if not dst:
                return len(s)
            self.write_wide_string(s[:n], dst)
            return min(len(s), n)

        reg("mbstowcs", mbstowcs_impl, 3, cd)

        def mbstowcs_s_impl(self, emu, argv, ctx=None):
            conv, dst, dstsz, src, maxcount = argv
            if not src:
                if conv:
                    self.mem_write(conv, b"\x00\x00\x00\x00")
                return 0
            s = self.read_string(src)
            if not dst:
                if conv:
                    self.mem_write(conv, (len(s) + 1).to_bytes(4, "little"))
                return 0
            if len(s) >= dstsz:
                return 34  # ERANGE
            self.write_wide_string(s[: dstsz - 1], dst)
            if conv:
                self.mem_write(conv, (len(s) + 1).to_bytes(4, "little"))
            return 0

        reg("mbstowcs_s", mbstowcs_s_impl, 6, cd)

        def wcstombs_s_impl(self, emu, argv, ctx=None):
            conv, dst, dstsz, src, maxcount = argv
            if not src:
                if conv:
                    self.mem_write(conv, b"\x00\x00\x00\x00")
                return 0
            s = self.read_wide_string(src)
            if not dst:
                if conv:
                    self.mem_write(conv, (len(s) + 1).to_bytes(4, "little"))
                return 0
            if len(s) >= dstsz:
                return 34
            self.write_string(s[: dstsz - 1], dst)
            if conv:
                self.mem_write(conv, (len(s) + 1).to_bytes(4, "little"))
            return 0

        reg("wcstombs_s", wcstombs_s_impl, 6, cd)
        reg("_wcstombs_s_l", wcstombs_s_impl, 7, cd)

        # ---- conversions ----
        def _parse_int(txt, base, signed):
            i = 0
            neg = False
            n = len(txt)
            while i < n and txt[i] in " \t\n\v\f\r":
                i += 1
            if i < n and txt[i] in "+-":
                neg = txt[i] == "-"
                i += 1
            if base == 0:
                if i < n and txt[i] == "0":
                    if i + 1 < n and txt[i + 1] in "xX":
                        base = 16
                        i += 2
                    elif i + 1 < n and txt[i + 1] in "bB":
                        base = 2
                        i += 2
                    else:
                        base = 8
                        i += 1
                else:
                    base = 10
            digits = "0123456789abcdefghijklmnopqrstuvwxyz"
            val = 0
            consumed = 0
            while i < n:
                ch = txt[i].lower()
                if ch not in digits[:base]:
                    break
                val = val * base + digits.index(ch)
                i += 1
                consumed += 1
            if consumed == 0 and base == 8:
                consumed = 0
            if neg:
                val = -val
            return val, i

        def strto_impl(size, signed):
            def impl(self, emu, argv, ctx=None):
                s, endptr, base = argv
                txt = self.read_string(s)
                val, consumed = _parse_int(txt, base, signed)
                if endptr:
                    self.mem_write(endptr, (s + consumed).to_bytes(ptr, "little"))
                if size == 32:
                    bits = (1 << 32)
                    lo = val & 0xFFFFFFFF
                    if signed and val < 0:
                        val = lo - (1 << 32) if lo >= (1 << 31) else lo
                    else:
                        val = lo
                if size == 32 and signed:
                    if val >= (1 << 31):
                        val -= 1 << 32
                    elif val < -(1 << 31):
                        val += 1 << 32
                elif size == 32 and not signed:
                    val &= 0xFFFFFFFF
                return val

            return impl

        for name, size, signed in [
            ("strtol", 32, True), ("strtoul", 32, False),
            ("strtoll", 64, True), ("strtoull", 64, False),
            ("strtoimax", 64, True), ("strtoumax", 64, False),
            ("_strtoi64", 64, True), ("_strtoui64", 64, False),
        ]:
            reg(name, strto_impl(size, signed), 3, cd)
            reg(f"_{name}_l", strto_impl(size, signed), 4, cd)

        def wcsto_impl(size, signed):
            def impl(self, emu, argv, ctx=None):
                s, endptr, base = argv
                txt = self.read_wide_string(s)
                val, consumed = _parse_int(txt, base, signed)
                if endptr:
                    self.mem_write(endptr, (s + consumed * 2).to_bytes(ptr, "little"))
                if size == 32:
                    if signed:
                        if val >= (1 << 31):
                            val -= 1 << 32
                        elif val < -(1 << 31):
                            val += 1 << 32
                    else:
                        val &= 0xFFFFFFFF
                return val

            return impl

        for name, size, signed in [
            ("wcstol", 32, True), ("wcstoul", 32, False),
            ("wcstoll", 64, True), ("wcstoull", 64, False),
            ("wcstoimax", 64, True), ("wcstoumax", 64, False),
            ("wcstoi64", 64, True), ("wcstoui64", 64, False),
        ]:
            reg(name, wcsto_impl(size, signed), 3, cd)
            reg(f"_{name}_l", wcsto_impl(size, signed), 4, cd)

        def ato_impl(wide, bits, signed):
            def impl(self, emu, argv, ctx=None):
                s = argv[0]
                if not s:
                    return 0
                if wide:
                    txt = self.read_wide_string(s)
                else:
                    txt = self.read_string(s)
                val, _ = _parse_int(txt, 10, signed)
                if bits == 32:
                    val &= 0xFFFFFFFF
                    if signed and val >= (1 << 31):
                        val -= 1 << 32
                return val

            return impl

        reg("atol", ato_impl(False, 32, True), 1, cd)
        reg("atoll", ato_impl(False, 64, True), 1, cd)
        reg("_atoi64", ato_impl(False, 64, True), 1, cd)
        reg("_wtoi", ato_impl(True, 32, True), 1, cd)
        reg("_wtoi64", ato_impl(True, 64, True), 1, cd)
        reg("_wtol", ato_impl(True, 32, True), 1, cd)
        reg("_wtoll", ato_impl(True, 64, True), 1, cd)

        def atof_impl(self, emu, argv, ctx=None):
            s = argv[0]
            if not s:
                return 0.0
            try:
                return float(self.read_string(s))
            except Exception:
                return 0.0

        reg_dbl_mixed("atof", atof_impl, 1)
        reg_dbl_mixed("_atof_l", atof_impl, 2)

        def strtod_impl(self, emu, argv, ctx=None):
            s, endptr = argv
            txt = self.read_string(s)
            i = 0
            while i < len(txt) and txt[i] in " \t\n\v\f\r":
                i += 1
            try:
                val = float(txt[i:])
            except Exception:
                val = 0.0
            if endptr:
                self.mem_write(endptr, (s + len(txt)).to_bytes(ptr, "little"))
            return val

        reg_dbl_mixed("strtod", strtod_impl, 2)
        reg_dbl_mixed("strtold", strtod_impl, 2)
        reg_dbl_mixed("_strtod_l", strtod_impl, 3)
        reg_dbl_mixed("_strtold_l", strtod_impl, 3)
        reg_dbl_mixed("wcstod", strtod_impl, 2)
        reg_dbl_mixed("wcstold", strtod_impl, 2)
        reg_dbl_mixed("_wcstod_l", strtod_impl, 3)
        reg_dbl_mixed("_wcstold_l", strtod_impl, 3)

        def strtof_impl(self, emu, argv, ctx=None):
            s, endptr = argv
            txt = self.read_string(s)
            i = 0
            while i < len(txt) and txt[i] in " \t\n\v\f\r":
                i += 1
            try:
                val = float(txt[i:])
            except Exception:
                val = 0.0
            if endptr:
                self.mem_write(endptr, (s + len(txt)).to_bytes(ptr, "little"))
            return val

        reg_dbl_mixed("strtof", strtof_impl, 2)
        reg_dbl_mixed("_strtof_l", strtof_impl, 3)
        reg_dbl_mixed("wcstof", strtof_impl, 2)
        reg_dbl_mixed("_wcstof_l", strtof_impl, 3)

        def wtof_impl(self, emu, argv, ctx=None):
            s = argv[0]
            if not s:
                return 0.0
            try:
                return float(self.read_wide_string(s))
            except Exception:
                return 0.0

        reg_dbl_mixed("_wtof", wtof_impl, 1)
        reg_dbl_mixed("_wtof_l", wtof_impl, 2)

        def radix_to_str(value, radix, upper):
            digits = "0123456789abcdefghijklmnopqrstuvwxyz"
            if upper:
                digits = digits.upper()
            neg = value < 0
            val = abs(value)
            if val == 0:
                out = "0"
            else:
                out = ""
                while val:
                    out = digits[val % radix] + out
                    val //= radix
            return ("-" if neg else "") + out

        def i64toa_impl(wide, value_bits):
            def impl(self, emu, argv, ctx=None):
                value, buf, radix = argv
                s = radix_to_str(value, radix, False)
                if wide:
                    self.write_wide_string(s, buf)
                else:
                    self.write_string(s, buf)
                return buf

            return impl

        for name in ["_i64toa", "_i64tow", "_ui64toa", "_ui64tow", "_ultoa", "_ultow"]:
            wide = name.endswith("w")
            reg(name, i64toa_impl(wide, 64), 3, cd)

        def itoa_s_impl(wide):
            def impl(self, emu, argv, ctx=None):
                value, buf, size, radix = argv
                s = radix_to_str(value, radix, False)
                if len(s) >= size:
                    return 34  # ERANGE
                if wide:
                    self.write_wide_string(s, buf)
                else:
                    self.write_string(s, buf)
                return 0

            return impl

        for name in ["_itoa_s", "_itow_s", "_ltoa_s", "_ltow_s", "_i64toa_s", "_i64tow_s",
                      "_ui64toa_s", "_ui64tow_s", "_ultoa_s", "_ultow_s"]:
            reg(name, itoa_s_impl(name.endswith("w")), 4, cd)

        def rotl_impl(bits):
            def impl(self, emu, argv, ctx=None):
                value, count = argv
                count &= bits - 1
                mask = (1 << bits) - 1
                return ((value << count) | (value >> (bits - count))) & mask

            return impl

        def rotr_impl(bits):
            def impl(self, emu, argv, ctx=None):
                value, count = argv
                count &= bits - 1
                mask = (1 << bits) - 1
                return ((value >> count) | (value << (bits - count))) & mask

            return impl

        reg("_rotl", rotl_impl(32), 2, cd)
        reg("_rotr", rotr_impl(32), 2, cd)
        reg("_rotl64", rotl_impl(64), 2, cd)
        reg("_rotr64", rotr_impl(64), 2, cd)

        def labs_impl(self, emu, argv, ctx=None):
            return abs(argv[0])

        reg("labs", labs_impl, 1, cd)
        reg("llabs", labs_impl, 1, cd)
        reg("imaxabs", labs_impl, 1, cd)

        # ---- time ----
        def _epoch():
            return int(datetime.datetime.now(datetime.timezone.utc).timestamp())

        def time32_impl(self, emu, argv, ctx=None):
            out = argv[0]
            t = _epoch() & 0xFFFFFFFF
            if out:
                self.mem_write(out, struct.pack("<i", t))
            return t

        reg("_time32", time32_impl, 1, cd)

        def time64_impl(self, emu, argv, ctx=None):
            out = argv[0]
            t = _epoch()
            if out:
                self.mem_write(out, struct.pack("<q", t))
            return t

        reg("_time64", time64_impl, 1, cd)

        def tm_struct(ts, utc):
            dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc) if utc else datetime.datetime.fromtimestamp(ts)
            return struct.pack(
                "<9i",
                dt.second, dt.minute, dt.hour, dt.day, dt.month - 1, dt.year - 1900,
                dt.weekday(), dt.timetuple().tm_yday - 1, 0,
            )

        self._tm_static = None

        def gmtime_impl(self, emu, argv, ctx=None):
            t = argv[0]
            if not t:
                return 0
            ts = struct.unpack("<q", self.mem_read(t, 8))[0]
            if self._tm_static is None:
                self._tm_static = self.mem_alloc(36, tag="api.msvcrt.tm")
            self.mem_write(self._tm_static, tm_struct(ts, True))
            return self._tm_static

        reg("gmtime", gmtime_impl, 1, cd)
        reg("_gmtime32", gmtime_impl, 1, cd)
        reg("_gmtime64", gmtime_impl, 1, cd)

        def localtime_impl(self, emu, argv, ctx=None):
            t = argv[0]
            if not t:
                return 0
            ts = struct.unpack("<q", self.mem_read(t, 8))[0]
            if self._tm_static is None:
                self._tm_static = self.mem_alloc(36, tag="api.msvcrt.tm")
            self.mem_write(self._tm_static, tm_struct(ts, False))
            return self._tm_static

        reg("localtime", localtime_impl, 1, cd)
        reg("_localtime32", localtime_impl, 1, cd)
        reg("_localtime64", localtime_impl, 1, cd)

        def tm_safe_impl(utc):
            def impl(self, emu, argv, ctx=None):
                buf, size, t = argv
                if not t or not buf or size < 36:
                    return 34  # ERANGE
                ts = struct.unpack("<q", self.mem_read(t, 8))[0]
                self.mem_write(buf, tm_struct(ts, utc))
                return 0

            return impl

        reg("gmtime_s", tm_safe_impl(True), 3, cd)
        reg("_gmtime32_s", tm_safe_impl(True), 3, cd)
        reg("_gmtime64_s", tm_safe_impl(True), 3, cd)
        reg("localtime_s", tm_safe_impl(False), 3, cd)
        reg("_localtime32_s", tm_safe_impl(False), 3, cd)
        reg("_localtime64_s", tm_safe_impl(False), 3, cd)

        def mktime_impl(self, emu, argv, ctx=None):
            tm = argv[0]
            if not tm:
                return -1
            sec, minute, hour, day, mon, year, wday, yday, isdst = struct.unpack("<9i", self.mem_read(tm, 36))
            try:
                dt = datetime.datetime(year + 1900, mon + 1, day, hour, minute, sec)
            except Exception:
                return -1
            return int(dt.timestamp())

        reg("mktime", mktime_impl, 1, cd)
        reg("_mktime32", mktime_impl, 1, cd)
        reg("_mktime64", mktime_impl, 1, cd)

        def mkgmtime_impl(self, emu, argv, ctx=None):
            tm = argv[0]
            if not tm:
                return -1
            sec, minute, hour, day, mon, year, wday, yday, isdst = struct.unpack("<9i", self.mem_read(tm, 36))
            try:
                dt = datetime.datetime(year + 1900, mon + 1, day, hour, minute, sec, tzinfo=datetime.timezone.utc)
            except Exception:
                return -1
            return int(dt.timestamp())

        reg("_mkgmtime32", mkgmtime_impl, 1, cd)
        reg("_mkgmtime64", mkgmtime_impl, 1, cd)

        def asctime_impl(self, emu, argv, ctx=None):
            tm = argv[0]
            if not tm:
                return 0
            sec, minute, hour, day, mon, year, wday, yday, isdst = struct.unpack("<9i", self.mem_read(tm, 36))
            days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
            months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
            s = f"{days[wday]} {months[mon]} {day:02d} {hour:02d}:{minute:02d}:{sec:02d} {year + 1900}\n"
            if self._tm_static is None:
                self._tm_static = self.mem_alloc(64, tag="api.msvcrt.tm")
            self.write_string(s, self._tm_static)
            return self._tm_static

        reg("asctime", asctime_impl, 1, cd)

        def asctime_s_impl(self, emu, argv, ctx=None):
            buf, size, tm = argv
            if not tm or not buf:
                return 22
            sec, minute, hour, day, mon, year, wday, yday, isdst = struct.unpack("<9i", self.mem_read(tm, 36))
            days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
            months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
            s = f"{days[wday]} {months[mon]} {day:02d} {hour:02d}:{minute:02d}:{sec:02d} {year + 1900}\n"
            if len(s) >= size:
                return 34
            self.write_string(s, buf)
            return 0

        reg("asctime_s", asctime_s_impl, 3, cd)
        reg("_asctime_s", asctime_s_impl, 3, cd)

        def ctime_impl(self, emu, argv, ctx=None):
            t = argv[0]
            if not t:
                return 0
            ts = struct.unpack("<q", self.mem_read(t, 8))[0]
            if self._tm_static is None:
                self._tm_static = self.mem_alloc(64, tag="api.msvcrt.tm")
            s = datetime.datetime.fromtimestamp(ts).strftime("%a %b %d %H:%M:%S %Y") + "\n"
            self.write_string(s, self._tm_static)
            return self._tm_static

        reg("ctime", ctime_impl, 1, cd)

        def ctime_s_impl(self, emu, argv, ctx=None):
            buf, size, t = argv
            if not t or not buf:
                return 22
            ts = struct.unpack("<q", self.mem_read(t, 8))[0]
            s = datetime.datetime.fromtimestamp(ts).strftime("%a %b %d %H:%M:%S %Y") + "\n"
            if len(s) >= size:
                return 34
            self.write_string(s, buf)
            return 0

        reg("_ctime32_s", ctime_s_impl, 3, cd)
        reg("_ctime64_s", ctime_s_impl, 3, cd)

        def difftime_impl(self, emu, argv, ctx=None):
            return float(argv[0] - argv[1])

        reg_dbl_mixed("difftime", difftime_impl, 2)

        # ---- formatting ----
        def vscprintf_impl(wide):
            def impl(self, emu, argv, ctx=None):
                fmt, va = argv
                if not fmt:
                    return 0
                if wide:
                    fmt_str = self.read_wide_string(fmt)
                else:
                    fmt_str = self.read_string(fmt)
                count = self.get_va_arg_count(fmt_str)
                args = self.va_args(va, count)
                fin = self.do_str_format(fmt_str, args)
                return len(fin)

            return impl

        reg("_vscprintf", vscprintf_impl(False), 2, cd)
        reg("_vscwprintf", vscprintf_impl(True), 2, cd)

        def scprintf_impl(wide):
            def impl(self, emu, argv, ctx=None):
                fmt = emu.get_func_argv(cd, 1)[0]
                if not fmt:
                    return 0
                if wide:
                    fmt_str = self.read_wide_string(fmt)
                else:
                    fmt_str = self.read_string(fmt)
                count = self.get_va_arg_count(fmt_str)
                args = emu.get_func_argv(cd, 2 + count)[2:]
                fin = self.do_str_format(fmt_str, args)
                return len(fin)

            return impl

        reg("_scprintf", scprintf_impl(False), e_arch.VAR_ARGS, cd)
        reg("_scwprintf", scprintf_impl(True), e_arch.VAR_ARGS, cd)

        def sprintf_s_impl(wide):
            def impl(self, emu, argv, ctx=None):
                fixed = emu.get_func_argv(cd, 3)
                buf, size, fmt = fixed[0], fixed[1], fixed[2]
                if not buf:
                    return 0
                if wide:
                    fmt_str = self.read_wide_string(fmt)
                    write = self.write_wide_string
                else:
                    fmt_str = self.read_string(fmt)
                    write = self.write_string
                count = self.get_va_arg_count(fmt_str)
                args = emu.get_func_argv(cd, 3 + count)[3:]
                fin = self.do_str_format(fmt_str, args)
                if len(fin) >= size:
                    return -1
                write(fin, buf)
                return len(fin)

            return impl

        reg("sprintf_s", sprintf_s_impl(False), e_arch.VAR_ARGS, cd)
        reg("swprintf_s", sprintf_s_impl(True), e_arch.VAR_ARGS, cd)
        reg("_sprintf_s_l", sprintf_s_impl(False), e_arch.VAR_ARGS, cd)
        reg("_swprintf_s_l", sprintf_s_impl(True), e_arch.VAR_ARGS, cd)

        def swprintf_impl(wide):
            def impl(self, emu, argv, ctx=None):
                fixed = emu.get_func_argv(cd, 2)
                buf, fmt = fixed[0], fixed[1]
                if wide:
                    fmt_str = self.read_wide_string(fmt)
                    write = self.write_wide_string
                else:
                    fmt_str = self.read_string(fmt)
                    write = self.write_string
                count = self.get_va_arg_count(fmt_str)
                args = emu.get_func_argv(cd, 2 + count)[2:]
                fin = self.do_str_format(fmt_str, args)
                write(fin, buf)
                return len(fin)

            return impl

        reg("swprintf", swprintf_impl(True), e_arch.VAR_ARGS, cd)
        reg("_swprintf", swprintf_impl(True), e_arch.VAR_ARGS, cd)

        def vsprintf_impl(wide, count_off):
            def impl(self, emu, argv, ctx=None):
                buf = argv[0]
                if wide:
                    fmt = argv[1]
                    fmt_str = self.read_wide_string(fmt)
                    write = self.write_wide_string
                else:
                    fmt = argv[1]
                    fmt_str = self.read_string(fmt)
                    write = self.write_string
                va = argv[2]
                fmt_cnt = self.get_va_arg_count(fmt_str)
                args = self.va_args(va, fmt_cnt)
                fin = self.do_str_format(fmt_str, args)
                if count_off:
                    size = argv[1] if count_off == 1 else argv[2]
                    if len(fin) >= size:
                        return -1
                write(fin, buf)
                return len(fin)

            return impl

        reg("vsprintf", vsprintf_impl(False, 0), 3, cd)
        reg("vsprintf_s", vsprintf_impl(False, 1), 4, cd)
        reg("_vsprintf_l", vsprintf_impl(False, 0), 4, cd)
        reg("vswprintf", vsprintf_impl(True, 0), 3, cd)
        reg("vswprintf_s", vsprintf_impl(True, 1), 4, cd)
        reg("_vswprintf", vsprintf_impl(True, 0), 3, cd)
        reg("_vswprintf_l", vsprintf_impl(True, 0), 4, cd)

        def vsnprintf_impl(wide):
            def impl(self, emu, argv, ctx=None):
                buf, size = argv[0], argv[1]
                if wide:
                    fmt = argv[2]
                    fmt_str = self.read_wide_string(fmt)
                    write = self.write_wide_string
                else:
                    fmt = argv[2]
                    fmt_str = self.read_string(fmt)
                    write = self.write_string
                va = argv[3]
                fmt_cnt = self.get_va_arg_count(fmt_str)
                args = self.va_args(va, fmt_cnt)
                fin = self.do_str_format(fmt_str, args)
                if len(fin) >= size:
                    write(fin[: max(size - 1, 0)], buf)
                    return -1
                write(fin, buf)
                return len(fin)

            return impl

        reg("vsnprintf", vsnprintf_impl(False), 4, cd)
        reg("_vsnprintf_s", vsnprintf_impl(False), 5, cd)
        reg("_vsnwprintf_s", vsnprintf_impl(True), 5, cd)

        def snprintf_s_impl(wide):
            def impl(self, emu, argv, ctx=None):
                fixed = emu.get_func_argv(cd, 4)
                buf, size = fixed[0], fixed[1]
                if wide:
                    fmt_str = self.read_wide_string(fixed[3])
                    write = self.write_wide_string
                else:
                    fmt_str = self.read_string(fixed[3])
                    write = self.write_string
                base = 4
                fmt_cnt = self.get_va_arg_count(fmt_str)
                args = emu.get_func_argv(cd, base + fmt_cnt)[base:]
                fin = self.do_str_format(fmt_str, args)
                if len(fin) >= size:
                    write(fin[: max(size - 1, 0)], buf)
                    return -1
                write(fin, buf)
                return len(fin)

            return impl

        reg("_snprintf_s", snprintf_s_impl(False), e_arch.VAR_ARGS, cd)
        reg("_snwprintf_s", snprintf_s_impl(True), e_arch.VAR_ARGS, cd)
        reg("_snprintf_c", snprintf_s_impl(False), e_arch.VAR_ARGS, cd)
        reg("_snprintf_c_l", snprintf_s_impl(False), e_arch.VAR_ARGS, cd)

        # ---- sscanf family (basic %d/%u/%x/%o/%s/%c parsing) ----
        def sscanf_impl(wide, fixed_args):
            def impl(self, emu, argv, ctx=None):
                fixed = emu.get_func_argv(cd, fixed_args)
                src = fixed[0]
                fmt = fixed[fixed_args - 1]
                if not src or not fmt:
                    return 0
                if wide:
                    data = self.read_wide_string(src)
                    fmt_str = self.read_wide_string(fmt)
                else:
                    data = self.read_string(src)
                    fmt_str = self.read_string(fmt)
                nconv = fmt_str.count("%") - fmt_str.count("%%")
                out_args = emu.get_func_argv(cd, fixed_args + nconv)[fixed_args:]
                parsed, pos, assigned = 0, 0, 0
                i = 0
                while i < len(fmt_str) and pos <= len(data):
                    c = fmt_str[i]
                    if c == "%":
                        i += 1
                        if i >= len(fmt_str):
                            break
                        conv = fmt_str[i]
                        if conv == "%":
                            pos += 1
                            i += 1
                            continue
                        if conv == "d" or conv == "i":
                            while pos < len(data) and data[pos] in " \t\n\v\f\r":
                                pos += 1
                            start = pos
                            if pos < len(data) and data[pos] in "+-":
                                pos += 1
                            while pos < len(data) and data[pos].isdigit():
                                pos += 1
                            if pos > start:
                                val = int(data[start:pos])
                                if parsed < len(out_args) and out_args[parsed]:
                                    self.mem_write(out_args[parsed], struct.pack("<i", val))
                                parsed += 1
                                assigned += 1
                        elif conv == "u":
                            while pos < len(data) and data[pos] in " \t\n\v\f\r":
                                pos += 1
                            start = pos
                            while pos < len(data) and data[pos].isdigit():
                                pos += 1
                            if pos > start:
                                val = int(data[start:pos])
                                if parsed < len(out_args) and out_args[parsed]:
                                    self.mem_write(out_args[parsed], struct.pack("<I", val))
                                parsed += 1
                                assigned += 1
                        elif conv == "x":
                            while pos < len(data) and data[pos] in " \t\n\v\f\r":
                                pos += 1
                            start = pos
                            while pos < len(data) and (data[pos].isdigit() or data[pos].lower() in "abcdef"):
                                pos += 1
                            if pos > start:
                                val = int(data[start:pos], 16)
                                if parsed < len(out_args) and out_args[parsed]:
                                    self.mem_write(out_args[parsed], struct.pack("<I", val))
                                parsed += 1
                                assigned += 1
                        elif conv == "o":
                            while pos < len(data) and data[pos] in " \t\n\v\f\r":
                                pos += 1
                            start = pos
                            while pos < len(data) and data[pos] in "01234567":
                                pos += 1
                            if pos > start:
                                val = int(data[start:pos], 8)
                                if parsed < len(out_args) and out_args[parsed]:
                                    self.mem_write(out_args[parsed], struct.pack("<I", val))
                                parsed += 1
                                assigned += 1
                        elif conv == "c":
                            if pos < len(data) and parsed < len(out_args) and out_args[parsed]:
                                self.mem_write(out_args[parsed], data[pos].encode("utf-16le") if wide else data[pos].encode("latin-1"))
                                parsed += 1
                                assigned += 1
                                pos += 1
                        elif conv == "s":
                            while pos < len(data) and data[pos] in " \t\n\v\f\r":
                                pos += 1
                            start = pos
                            while pos < len(data) and data[pos] not in " \t\n\v\f\r":
                                pos += 1
                            if pos > start and parsed < len(out_args) and out_args[parsed]:
                                tok = data[start:pos]
                                if wide:
                                    self.write_wide_string(tok, out_args[parsed])
                                else:
                                    self.write_string(tok, out_args[parsed])
                                parsed += 1
                                assigned += 1
                        elif conv == "f" or conv == "g" or conv == "e":
                            while pos < len(data) and data[pos] in " \t\n\v\f\r":
                                pos += 1
                            start = pos
                            while pos < len(data) and (data[pos].isdigit() or data[pos] in ".eE+-"):
                                pos += 1
                            if pos > start:
                                try:
                                    val = float(data[start:pos])
                                except Exception:
                                    val = 0.0
                                if parsed < len(out_args) and out_args[parsed]:
                                    self.mem_write(out_args[parsed], self.double_to_hex(val).to_bytes(8, "little"))
                                parsed += 1
                                assigned += 1
                        i += 1
                    elif c in " \t\n\v\f\r":
                        while pos < len(data) and data[pos] in " \t\n\v\f\r":
                            pos += 1
                        i += 1
                    else:
                        if pos < len(data) and data[pos] == c:
                            pos += 1
                        else:
                            break
                        i += 1
                return assigned

            return impl

        reg("sscanf_s", sscanf_impl(False, 2), e_arch.VAR_ARGS, cd)
        reg("swscanf_s", sscanf_impl(True, 2), e_arch.VAR_ARGS, cd)
        reg("_snscanf_s", sscanf_impl(False, 3), e_arch.VAR_ARGS, cd)
        reg("_snwscanf_s", sscanf_impl(True, 3), e_arch.VAR_ARGS, cd)
        reg("_sscanf_s_l", sscanf_impl(False, 3), e_arch.VAR_ARGS, cd)
        reg("_swscanf_s_l", sscanf_impl(True, 3), e_arch.VAR_ARGS, cd)

        # ---- misc ----
        def isatty_impl(self, emu, argv, ctx=None):
            return 1 if argv[0] in (0, 1, 2) else 0

        reg("_isatty", isatty_impl, 1, cd)

        def getcwd_impl(self, emu, argv, ctx=None):
            buf, size = argv
            if not buf:
                return 0
            try:
                cd = emu.get_cd()
            except Exception:
                cd = "C:\\"
            if len(cd) >= size:
                return 0
            self.write_string(cd, buf)
            return buf

        reg("_getcwd", getcwd_impl, 2, cd)

        def access_impl(self, emu, argv, ctx=None):
            path, mode = argv
            p = self.read_string(path) if path else ""
            if not p:
                return -1
            if self.does_file_exist(p):
                return 0
            return -1

        reg("_access", access_impl, 2, cd)
        reg("_waccess", access_impl, 2, cd)

        def unlink_impl(self, emu, argv, ctx=None):
            path = argv[0]
            if not path:
                return -1
            p = self.read_string(path)
            if self.does_file_exist(p):
                emu.file_delete(p)
                return 0
            return -1

        reg("_unlink", unlink_impl, 1, cd)
        reg("_wunlink", unlink_impl, 1, cd)

        def remove_impl(self, emu, argv, ctx=None):
            return unlink_impl(self, emu, argv, None)

        reg("remove", remove_impl, 1, cd)

        def get_errno_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, struct.pack("<i", self.errno_t or 0))
            return 0

        reg("_get_errno", get_errno_impl, 1, cd)

        def set_errno_impl(self, emu, argv, ctx=None):
            self.errno_t = argv[0]
            return 0

        reg("_set_errno", set_errno_impl, 1, cd)

        def get_doserrno_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00")
            return 0

        reg("_get_doserrno", get_doserrno_impl, 1, cd)

        def set_doserrno_impl(self, emu, argv, ctx=None):
            return 0

        reg("_set_doserrno", set_doserrno_impl, 1, cd)

        def sleep_impl(self, emu, argv, ctx=None):
            return 0

        reg("_sleep", sleep_impl, 1, cd)

        def tzset_impl(self, emu, argv, ctx=None):
            return 0

        reg("_tzset", tzset_impl, 0, cd)

        def get_timezone_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, struct.pack("<l", -28800))
            return 0

        reg("_get_timezone", get_timezone_impl, 1, cd)

        def get_daylight_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, b"\x01\x00\x00\x00")
            return 0

        reg("_get_daylight", get_daylight_impl, 1, cd)

        def get_dstbias_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, struct.pack("<l", 0))
            return 0

        reg("_get_dstbias", get_dstbias_impl, 1, cd)

        def get_fmode_impl(self, emu, argv, ctx=None):
            out = argv[0]
            if out:
                self.mem_write(out, b"\x00\x00\x00\x00")
            return 0

        reg("_get_fmode", get_fmode_impl, 1, cd)

        def raise_impl(self, emu, argv, ctx=None):
            return 0

        reg("raise", raise_impl, 1, cd)

        def abort_impl(self, emu, argv, ctx=None):
            logger = self.emu.get_profiler()  # noqa: F841 - mirror exit() behavior
            emu.exit_process()
            return 0

        reg("abort", abort_impl, 0, cd)
        reg("quick_exit", abort_impl, 1, cd)

        def purecall_impl(self, emu, argv, ctx=None):
            emu.exit_process()
            return 0

        reg("_purecall", purecall_impl, 0, cd)

        # UCRT legacy aliases: _o_X reuses the same handler (same signature)
        for name in list(self.funcs.keys()):
            if name.startswith("_o_") or name.startswith("ordinal_"):
                continue
            alias = f"_o_{name}"
            if alias not in self.funcs:
                _h, _f, _a, _c, _o = self.funcs[name]
                self.funcs[alias] = (alias, _f, _a, _c, _o)

    def _register_crt_io_batch(self):
        """
        Register real handlers for CRT environment, file I/O, stdio, time and
        allocation helper functions.
        """
        cd = e_arch.CALL_CONV_CDECL
        ptr = self.get_ptr_size()

        def reg(name, func, argc, conv=None):
            if name not in self.funcs:
                self.funcs[name] = (name, func, argc, conv or cd, None)

        def _fd_map():
            if not hasattr(self, "_fd_handles"):
                self._fd_handles = {}
                self._next_fd = 3
            return self._fd_handles

        def _alloc_fd(handle):
            _fd_map()
            fd = self._next_fd
            self._next_fd += 1
            _fd_map()[fd] = handle
            return fd

        # ---- environment ----
        self._env_ptrs = {}

        def _env_str_addr(value):
            addr = self._env_ptrs.get(value)
            if addr is None:
                data = value.encode("utf-8") + b"\x00"
                addr = self.mem_alloc(len(data), tag="api.msvcrt.env")
                self.mem_write(addr, data)
                self._env_ptrs[value] = addr
            return addr

        def getenv_impl(self, emu, argv, ctx=None):
            name = argv[0]
            if not name:
                return 0
            n = self.read_string(name)
            try:
                env = self.emu.get_env() or {}
                value = env.get(n.lower(), "") or ""
            except Exception:
                value = ""
            if not value:
                return 0
            return _env_str_addr(value)

        reg("getenv", getenv_impl, 1)
        reg("_wgetenv", getenv_impl, 1)

        def getenv_s_impl(self, emu, argv, ctx=None):
            size_out, buf, size, name = argv
            if not name:
                return 22
            n = self.read_string(name)
            try:
                env = self.emu.get_env() or {}
                value = env.get(n.lower(), "") or ""
            except Exception:
                value = ""
            if not value:
                if size_out:
                    self.mem_write(size_out, b"\x00\x00\x00\x00")
                return 0
            if len(value) + 1 > size:
                return 34  # ERANGE
            self.write_string(value, buf)
            if size_out:
                self.mem_write(size_out, (len(value) + 1).to_bytes(4, "little"))
            return 0

        reg("getenv_s", getenv_s_impl, 4)
        reg("_getenv_s", getenv_s_impl, 4)
        reg("_wgetenv_s", getenv_s_impl, 4)

        def putenv_impl(self, emu, argv, ctx=None):
            s = argv[0]
            if not s:
                return -1
            txt = self.read_string(s)
            if "=" in txt:
                name, _, value = txt.partition("=")
                try:
                    self.emu.set_env(name, value)
                except Exception:
                    pass
            return 0

        reg("_putenv", putenv_impl, 1)
        reg("_wputenv", putenv_impl, 1)

        def putenv_s_impl(self, emu, argv, ctx=None):
            s = argv[0]
            if not s:
                return 22
            txt = self.read_string(s)
            if "=" in txt:
                name, _, value = txt.partition("=")
                try:
                    self.emu.set_env(name, value)
                except Exception:
                    pass
            return 0

        reg("_putenv_s", putenv_s_impl, 1)
        reg("_wputenv_s", putenv_s_impl, 1)

        def dupenv_s_impl(self, emu, argv, ctx=None):
            out, count, name = argv
            if not out:
                return 22
            self.mem_write(out, b"\x00" * ptr)
            if not name:
                if count:
                    self.mem_write(count, b"\x00\x00\x00\x00")
                return 0
            n = self.read_string(name)
            try:
                env = self.emu.get_env() or {}
                value = env.get(n.lower(), "") or ""
            except Exception:
                value = ""
            if not value:
                if count:
                    self.mem_write(count, b"\x00\x00\x00\x00")
                return 0
            data = value.encode("utf-8") + b"\x00"
            buf = self.mem_alloc(len(data), tag="api.msvcrt.env")
            self.mem_write(buf, data)
            self.mem_write(out, buf.to_bytes(ptr, "little"))
            if count:
                self.mem_write(count, (len(value) + 1).to_bytes(4, "little"))
            return 0

        reg("_dupenv_s", dupenv_s_impl, 3)
        reg("_wdupenv_s", dupenv_s_impl, 3)

        # ---- fd-based file I/O ----
        def _open_impl(self, emu, argv, ctx=None):
            path, flags, mode = argv
            if not path:
                return -1
            p = self.read_string(path)
            create = bool(flags & 0x0100)
            truncate = bool(flags & 0x0200)
            hnd = self.file_open(p, create=False)
            if not hnd and create:
                hnd = self.file_open(p, create=True, truncate=truncate)
            if not hnd:
                self.errno_t = 2  # ENOENT
                return -1
            return _alloc_fd(hnd)

        reg("_open", _open_impl, 3)
        reg("_wopen", _open_impl, 3)
        reg("_sopen", _open_impl, 4)
        reg("_wsopen", _open_impl, 4)
        reg("_sopen_s", _open_impl, 6)
        reg("_wsopen_s", _open_impl, 6)
        reg("_creat", _open_impl, 2)
        reg("_wcreat", _open_impl, 2)

        def _close_impl(self, emu, argv, ctx=None):
            fd = argv[0]
            hnd = _fd_map().pop(fd, None)
            if hnd is None:
                return -1
            fman = getattr(self.emu, "fileman", None)
            if fman is not None:
                fman.file_handles.pop(hnd, None)
            return 0

        reg("_close", _close_impl, 1)

        def _read_impl(self, emu, argv, ctx=None):
            fd, buf, count = argv
            hnd = _fd_map().get(fd)
            if hnd is None:
                self.errno_t = 9  # EBADF
                return -1
            f = self.file_get(hnd)
            if f is None:
                return -1
            data = f.get_data(count)
            if buf and data:
                self.mem_write(buf, data)
            return len(data)

        reg("_read", _read_impl, 3)

        def _write_impl(self, emu, argv, ctx=None):
            fd, buf, count = argv
            hnd = _fd_map().get(fd)
            if hnd is None:
                self.errno_t = 9
                return -1
            f = self.file_get(hnd)
            if f is None:
                return -1
            data = self.mem_read(buf, count)
            if getattr(f, "data", None) is not None:
                f.data.write(data)
                f._sync_size()
            else:
                f.data = data
                f._sync_size()
            return count

        reg("_write", _write_impl, 3)

        def _lseek_impl(self, emu, argv, ctx=None):
            fd, offset, whence = argv
            hnd = _fd_map().get(fd)
            if hnd is None:
                return -1
            f = self.file_get(hnd)
            if f is None:
                return -1
            f.seek(offset, whence)
            return f.tell() or 0

        reg("_lseek", _lseek_impl, 3)
        reg("_lseeki64", _lseek_impl, 3)

        def _tell_impl(self, emu, argv, ctx=None):
            fd = argv[0]
            hnd = _fd_map().get(fd)
            if hnd is None:
                return -1
            f = self.file_get(hnd)
            if f is None:
                return -1
            return f.tell() or 0

        reg("_tell", _tell_impl, 1)
        reg("_telli64", _tell_impl, 1)

        def _eof_impl(self, emu, argv, ctx=None):
            fd = argv[0]
            hnd = _fd_map().get(fd)
            if hnd is None:
                return -1
            f = self.file_get(hnd)
            if f is None:
                return -1
            pos = f.tell() or 0
            size = f.get_size()
            return 1 if pos >= size else 0

        reg("_eof", _eof_impl, 1)

        def _commit_impl(self, emu, argv, ctx=None):
            return 0

        reg("_commit", _commit_impl, 1)

        def _chsize_impl(self, emu, argv, ctx=None):
            fd, size = argv
            hnd = _fd_map().get(fd)
            if hnd is None:
                return -1
            f = self.file_get(hnd)
            if f is None:
                return -1
            return 0

        reg("_chsize", _chsize_impl, 2)
        reg("_chsize_s", _chsize_impl, 3)

        def _fileno_impl(self, emu, argv, ctx=None):
            stream = argv[0]
            for fd, hnd in _fd_map().items():
                if hnd == stream:
                    return fd
            return -1

        reg("_fileno", _fileno_impl, 1)

        def _dup_impl(self, emu, argv, ctx=None):
            fd = argv[0]
            hnd = _fd_map().get(fd)
            if hnd is None:
                return -1
            return _alloc_fd(hnd)

        reg("_dup", _dup_impl, 1)

        def _dup2_impl(self, emu, argv, ctx=None):
            oldfd, newfd = argv
            hnd = _fd_map().get(oldfd)
            if hnd is None:
                return -1
            _fd_map()[newfd] = hnd
            return 0

        reg("_dup2", _dup2_impl, 2)

        def _get_osfhandle_impl(self, emu, argv, ctx=None):
            fd = argv[0]
            hnd = _fd_map().get(fd)
            return hnd if hnd is not None else -1

        reg("_get_osfhandle", _get_osfhandle_impl, 1)

        def _open_osfhandle_impl(self, emu, argv, ctx=None):
            handle, flags = argv
            return _alloc_fd(handle)

        reg("_open_osfhandle", _open_osfhandle_impl, 2)

        def _setmode_impl(self, emu, argv, ctx=None):
            fd, mode = argv
            if fd < 0 or mode not in (0x8000, 0x4000):
                return -1
            return mode

        reg("_setmode", _setmode_impl, 2)

        # ---- directories ----
        def _chdir_impl(self, emu, argv, ctx=None):
            path = argv[0]
            if not path:
                return -1
            p = self.read_string(path)
            try:
                self.emu.set_cd(p)
            except Exception:
                return -1
            return 0

        reg("_chdir", _chdir_impl, 1)
        reg("_wchdir", _chdir_impl, 1)

        def _mkdir_impl(self, emu, argv, ctx=None):
            path = argv[0]
            if not path:
                return -1
            self.record_file_access_event(self.read_string(path), "directory_create")
            return 0

        reg("_mkdir", _mkdir_impl, 1)
        reg("_wmkdir", _mkdir_impl, 1)

        def _rmdir_impl(self, emu, argv, ctx=None):
            path = argv[0]
            if not path:
                return -1
            p = self.read_string(path)
            if self.does_file_exist(p):
                try:
                    self.emu.file_delete(p)
                except Exception:
                    pass
                return 0
            return -1

        reg("_rmdir", _rmdir_impl, 1)
        reg("_wrmdir", _rmdir_impl, 1)

        def _getdrive_impl(self, emu, argv, ctx=None):
            return 3  # C:

        reg("_getdrive", _getdrive_impl, 0)

        def _getdrives_impl(self, emu, argv, ctx=None):
            return 0x0C  # A: + C:

        reg("_getdrives", _getdrives_impl, 0)

        def _chdrive_impl(self, emu, argv, ctx=None):
            drive = argv[0]
            return 0 if 1 <= drive <= 26 else -1

        reg("_chdrive", _chdrive_impl, 1)

        def _getcwd_local(self, emu, argv, ctx=None):
            buf, size = argv
            if not buf:
                return 0
            try:
                cd = emu.get_cd()
            except Exception:
                cd = "C:\\"
            if len(cd) >= size:
                return 0
            self.write_string(cd, buf)
            return buf

        def _getdcwd_impl(self, emu, argv, ctx=None):
            drive, buf, size = argv
            return _getcwd_local(self, emu, [buf, size], None)

        reg("_getdcwd", _getdcwd_impl, 3)
        reg("_wgetdcwd", _getdcwd_impl, 3)
        reg("_wgetcwd", _getcwd_local, 2)

        def _fullpath_impl(self, emu, argv, ctx=None):
            buf, path, size = argv
            if not path:
                return 0
            p = self.read_string(path)
            if not buf:
                data = p.encode("utf-8") + b"\x00"
                out = self.mem_alloc(len(data), tag="api.msvcrt.path")
                self.mem_write(out, data)
                return out
            if len(p) + 1 > size:
                return 0
            self.write_string(p, buf)
            return buf

        reg("_fullpath", _fullpath_impl, 3)
        reg("_wfullpath", _fullpath_impl, 3)

        def _splitpath_impl(self, emu, argv, ctx=None):
            path, drive, dir_, fname, ext = argv
            if not path:
                return
            p = self.read_string(path)
            import ntpath as _nt

            d, fn = _nt.split(p)
            drv, _tail = _nt.splitdrive(p)
            name, extn = _nt.splitext(fn)
            # dir is the path between the drive and the file name (with trailing backslash)
            dir_val = p[len(drv) : len(p) - len(fn)]
            for out, val in ((drive, drv), (dir_, dir_val), (fname, name), (ext, extn)):
                if out:
                    self.write_string(val, out)

        reg("_splitpath", _splitpath_impl, 5)
        reg("_wsplitpath", _splitpath_impl, 5)
        reg("_splitpath_s", _splitpath_impl, 9)
        reg("_wsplitpath_s", _splitpath_impl, 9)

        def _makepath_impl(self, emu, argv, ctx=None):
            path, drive, dir_, fname, ext = argv
            if not path:
                return
            d = self.read_string(drive) if drive else ""
            dn = self.read_string(dir_) if dir_ else ""
            fn = self.read_string(fname) if fname else ""
            ex = self.read_string(ext) if ext else ""
            out = d + dn + fn + ex
            self.write_string(out, path)

        def _makepath_s_impl(self, emu, argv, ctx=None):
            path, size, drive, dir_, fname, ext = argv
            if not path:
                return
            d = self.read_string(drive) if drive else ""
            dn = self.read_string(dir_) if dir_ else ""
            fn = self.read_string(fname) if fname else ""
            ex = self.read_string(ext) if ext else ""
            out = d + dn + fn + ex
            if len(out) + 1 > size:
                return 34  # ERANGE
            self.write_string(out, path)
            return 0

        reg("_makepath", _makepath_impl, 5)
        reg("_wmakepath", _makepath_impl, 5)
        reg("_makepath_s", _makepath_s_impl, 6)
        reg("_wmakepath_s", _makepath_s_impl, 6)

        # ---- findfirst/findnext ----
        self._find_states = {}
        self._find_next_handle = 0x100

        def _find_matches(pattern):
            fman = getattr(self.emu, "fileman", None)
            if fman is None:
                return []
            files = []
            for f in getattr(fman, "files", []) or []:
                p = getattr(f, "path", "") or ""
                files.append(p)
            for p in getattr(fman, "_path_index", {}) or {}:
                files.append(p)
            import fnmatch as _fn

            return sorted({p for p in files if _fn.fnmatch(p, pattern)})

        def _findfirst_impl(self, emu, argv, ctx=None):
            path, finddata = argv
            if not path or not finddata:
                return -1
            pattern = self.read_string(path)
            matches = _find_matches(pattern)
            hnd = self._find_next_handle
            self._find_next_handle += 1
            self._find_states[hnd] = [matches, 0]
            if not matches:
                self.errno_t = 2  # ENOENT
                return -1
            name = matches[0]
            size = 0
            fman = getattr(self.emu, "fileman", None)
            if fman is not None:
                for f in getattr(fman, "files", []) or []:
                    if getattr(f, "path", "") == name:
                        size = f.get_size()
                        break
            self.mem_write(finddata + 0x20, size.to_bytes(8, "little"))
            self.write_string(name, finddata + 0x30)
            return hnd

        reg("_findfirst64", _findfirst_impl, 2)
        reg("_findfirst64i32", _findfirst_impl, 2)
        reg("_findfirst32", _findfirst_impl, 2)
        reg("_findfirst32i64", _findfirst_impl, 2)
        reg("_findfirst", _findfirst_impl, 2)
        reg("_findfirsti64", _findfirst_impl, 2)
        reg("_wfindfirst64", _findfirst_impl, 2)
        reg("_wfindfirst64i32", _findfirst_impl, 2)
        reg("_wfindfirst32", _findfirst_impl, 2)
        reg("_wfindfirst32i64", _findfirst_impl, 2)
        reg("_wfindfirst", _findfirst_impl, 2)
        reg("_wfindfirsti64", _findfirst_impl, 2)

        def _findnext_impl(self, emu, argv, ctx=None):
            hnd, finddata = argv
            state = self._find_states.get(hnd)
            if not state or not finddata:
                return -1
            matches, idx = state
            idx += 1
            if idx >= len(matches):
                return -1
            state[1] = idx
            name = matches[idx]
            size = 0
            fman = getattr(self.emu, "fileman", None)
            if fman is not None:
                for f in getattr(fman, "files", []) or []:
                    if getattr(f, "path", "") == name:
                        size = f.get_size()
                        break
            self.mem_write(finddata + 0x20, size.to_bytes(8, "little"))
            self.write_string(name, finddata + 0x30)
            return 0

        reg("_findnext64", _findnext_impl, 2)
        reg("_findnext64i32", _findnext_impl, 2)
        reg("_findnext32", _findnext_impl, 2)
        reg("_findnext32i64", _findnext_impl, 2)
        reg("_findnext", _findnext_impl, 2)
        reg("_findnexti64", _findnext_impl, 2)
        reg("_wfindnext64", _findnext_impl, 2)
        reg("_wfindnext64i32", _findnext_impl, 2)
        reg("_wfindnext32", _findnext_impl, 2)
        reg("_wfindnext32i64", _findnext_impl, 2)
        reg("_wfindnext", _findnext_impl, 2)
        reg("_wfindnexti64", _findnext_impl, 2)

        def _findclose_impl(self, emu, argv, ctx=None):
            hnd = argv[0]
            self._find_states.pop(hnd, None)
            return 0

        reg("_findclose", _findclose_impl, 1)
        reg("_wfindclose", _findclose_impl, 1)

        # ---- stat ----
        def _stat_impl(self, emu, argv, ctx=None):
            path, buf = argv
            if not path or not buf:
                return -1
            p = self.read_string(path)
            size = 0
            fman = getattr(self.emu, "fileman", None)
            if fman is not None:
                for f in getattr(fman, "files", []) or []:
                    if getattr(f, "path", "") == p:
                        size = f.get_size()
                        break
            if self.get_ptr_size() == 8:
                self.mem_write(
                    buf,
                    struct.pack("<IHHIIHHI", 2, 0, 0x81B6, 1, 0, 0, 2, 0)
                    + struct.pack("<Q", size)
                    + struct.pack("<qqq", 0, 0, 0),
                )
            else:
                self.mem_write(
                    buf,
                    struct.pack("<IHHIIIII", 2, 0, 0x81B6, 1, 0, 0, 2, size)
                    + struct.pack("<iii", 0, 0, 0),
                )
            return 0

        reg("_stat64", _stat_impl, 2)
        reg("_stat64i32", _stat_impl, 2)
        reg("_stat32", _stat_impl, 2)
        reg("_stat32i64", _stat_impl, 2)
        reg("_stat", _stat_impl, 2)
        reg("_stati64", _stat_impl, 2)
        reg("_wstat64", _stat_impl, 2)
        reg("_wstat64i32", _stat_impl, 2)
        reg("_wstat32", _stat_impl, 2)
        reg("_wstat32i64", _stat_impl, 2)
        reg("_wstat", _stat_impl, 2)
        reg("_wstati64", _stat_impl, 2)

        def _fstat_impl(self, emu, argv, ctx=None):
            fd, buf = argv
            hnd = _fd_map().get(fd)
            if hnd is None:
                return -1
            f = self.file_get(hnd)
            size = f.get_size() if f else 0
            return _stat_buf(buf, size)

        def _stat_buf(buf, size):
            if self.get_ptr_size() == 8:
                self.mem_write(
                    buf,
                    struct.pack("<IHHIIHHI", 2, 0, 0x81B6, 1, 0, 0, 2, 0)
                    + struct.pack("<Q", size)
                    + struct.pack("<qqq", 0, 0, 0),
                )
            else:
                self.mem_write(
                    buf,
                    struct.pack("<IHHIIIII", 2, 0, 0x81B6, 1, 0, 0, 2, size)
                    + struct.pack("<iii", 0, 0, 0),
                )
            return 0

        reg("_fstat64", _fstat_impl, 2)
        reg("_fstat64i32", _fstat_impl, 2)
        reg("_fstat32", _fstat_impl, 2)
        reg("_fstat32i64", _fstat_impl, 2)
        reg("_fstat", _fstat_impl, 2)

        # ---- stdio helpers ----
        def _stream_file(stream):
            fman = getattr(self.emu, "fileman", None)
            if fman is None:
                return None
            return fman.get_object_from_handle(stream)

        def fgets_impl(self, emu, argv, ctx=None):
            buf, count, stream = argv
            if not buf or count <= 0:
                return 0
            f = _stream_file(stream)
            if f is None:
                return 0
            data = f.get_data(count - 1)
            if not data:
                return 0
            newline = data.find(b"\n")
            if newline >= 0:
                data = data[: newline + 1]
            self.mem_write(buf, data + b"\x00")
            return buf

        reg("fgets", fgets_impl, 3)
        reg("_fgets_nolock", fgets_impl, 3)

        def fgetws_impl(self, emu, argv, ctx=None):
            buf, count, stream = argv
            if not buf or count <= 0:
                return 0
            f = _stream_file(stream)
            if f is None:
                return 0
            data = f.get_data((count - 1) * 2)
            if not data:
                return 0
            newline = data.find(b"\x0a\x00")
            if newline >= 0:
                data = data[: newline + 2]
            self.mem_write(buf, data + b"\x00\x00")
            return buf

        reg("fgetws", fgetws_impl, 3)

        def fputs_impl(self, emu, argv, ctx=None):
            s, stream = argv
            if not s:
                return -1
            txt = self.read_string(s)
            return len(txt)

        reg("fputs", fputs_impl, 2)

        def fputws_impl(self, emu, argv, ctx=None):
            s, stream = argv
            if not s:
                return -1
            txt = self.read_wide_string(s)
            return len(txt)

        reg("fputws", fputws_impl, 2)

        def _fgetc_impl(self, emu, argv, ctx=None):
            stream = argv[0]
            f = _stream_file(stream)
            if f is None:
                return -1  # EOF
            data = f.get_data(1)
            return data[0] if data else -1

        reg("fgetc", _fgetc_impl, 1)
        reg("getc", _fgetc_impl, 1)
        reg("_fgetc_nolock", _fgetc_impl, 1)
        reg("_getc_nolock", _fgetc_impl, 1)

        def _fputc_impl(self, emu, argv, ctx=None):
            c, stream = argv
            return c & 0xFF

        reg("fputc", _fputc_impl, 2)
        reg("putc", _fputc_impl, 2)
        reg("_fputc_nolock", _fputc_impl, 2)
        reg("_putc_nolock", _fputc_impl, 2)

        def getchar_impl(self, emu, argv, ctx=None):
            return -1  # EOF (no stdin)

        reg("getchar", getchar_impl, 0)
        reg("getwchar", getchar_impl, 0)
        reg("_getchar_nolock", getchar_impl, 0)
        reg("_getwchar_nolock", getchar_impl, 0)

        def putchar_impl(self, emu, argv, ctx=None):
            return argv[0] & 0xFF

        reg("putchar", putchar_impl, 1)
        reg("putwchar", putchar_impl, 1)
        reg("_putchar_nolock", putchar_impl, 1)
        reg("_putwchar_nolock", putchar_impl, 1)

        def _getch_impl(self, emu, argv, ctx=None):
            return 0x1B  # ESC

        reg("_getch", _getch_impl, 0)
        reg("_getche", _getch_impl, 0)
        reg("_getwch", _getch_impl, 0)
        reg("_getwche", _getch_impl, 0)
        reg("_getch_nolock", _getch_impl, 0)
        reg("_getche_nolock", _getch_impl, 0)
        reg("_getwch_nolock", _getch_impl, 0)
        reg("_getwche_nolock", _getch_impl, 0)

        def _putch_impl(self, emu, argv, ctx=None):
            return argv[0] & 0xFF

        reg("_putch", _putch_impl, 1)
        reg("_putwch", _putch_impl, 1)
        reg("_putch_nolock", _putch_impl, 1)
        reg("_putwch_nolock", _putch_impl, 1)

        def _ungetch_impl(self, emu, argv, ctx=None):
            return argv[0] & 0xFF

        reg("_ungetch", _ungetch_impl, 1)
        reg("_ungetwch", _ungetch_impl, 1)
        reg("_ungetch_nolock", _ungetch_impl, 1)
        reg("_ungetwch_nolock", _ungetch_impl, 1)

        def _kbhit_impl(self, emu, argv, ctx=None):
            return 0

        reg("_kbhit", _kbhit_impl, 0)

        def feof_impl(self, emu, argv, ctx=None):
            return 0

        reg("feof", feof_impl, 1)
        reg("ferror", feof_impl, 1)

        def clearerr_impl(self, emu, argv, ctx=None):
            return 0

        reg("clearerr", clearerr_impl, 1)
        reg("clearerr_s", clearerr_impl, 2)

        def rewind_impl(self, emu, argv, ctx=None):
            stream = argv[0]
            f = _stream_file(stream)
            if f is not None:
                f.seek(0, 0)
            return 0

        reg("rewind", rewind_impl, 1)

        def _flushall_impl(self, emu, argv, ctx=None):
            return 0

        reg("_flushall", _flushall_impl, 0)

        def _fcloseall_impl(self, emu, argv, ctx=None):
            return 0

        reg("_fcloseall", _fcloseall_impl, 0)

        def fgetpos_impl(self, emu, argv, ctx=None):
            stream, pos = argv
            f = _stream_file(stream)
            if f is None or not pos:
                return -1
            self.mem_write(pos, (f.tell() or 0).to_bytes(8, "little"))
            return 0

        reg("fgetpos", fgetpos_impl, 2)
        reg("fgetpos64", fgetpos_impl, 2)

        def fsetpos_impl(self, emu, argv, ctx=None):
            stream, pos = argv
            f = _stream_file(stream)
            if f is None or not pos:
                return -1
            off = int.from_bytes(self.mem_read(pos, 8), "little")
            f.seek(off, 0)
            return 0

        reg("fsetpos", fsetpos_impl, 2)
        reg("fsetpos64", fsetpos_impl, 2)

        def _fseeki64_impl(self, emu, argv, ctx=None):
            stream, offset, whence = argv
            f = _stream_file(stream)
            if f is None:
                return -1
            f.seek(offset, whence)
            return 0

        reg("_fseeki64", _fseeki64_impl, 3)
        reg("_fseeki64_nolock", _fseeki64_impl, 3)

        def _ftelli64_impl(self, emu, argv, ctx=None):
            stream = argv[0]
            f = _stream_file(stream)
            if f is None:
                return -1
            return f.tell() or 0

        reg("_ftelli64", _ftelli64_impl, 1)
        reg("_ftelli64_nolock", _ftelli64_impl, 1)

        def _getws_impl(self, emu, argv, ctx=None):
            buf = argv[0]
            if not buf:
                return 0
            self.write_wide_string("", buf)
            return buf

        reg("_getws", _getws_impl, 1)
        reg("_getws_s", _getws_impl, 3)

        def _cputs_impl(self, emu, argv, ctx=None):
            s = argv[0]
            if not s:
                return 0
            self.read_string(s)
            return 0

        reg("_cputs", _cputs_impl, 1)
        reg("_cputws", _cputs_impl, 1)

        def _getw_impl(self, emu, argv, ctx=None):
            return -1  # EOF

        reg("_getw", _getw_impl, 1)

        def _putw_impl(self, emu, argv, ctx=None):
            return argv[0]

        reg("_putw", _putw_impl, 2)

        def _strdate_s_impl(self, emu, argv, ctx=None):
            buf, size = argv
            if not buf or size < 9:
                return 34
            now = datetime.datetime.now()
            self.write_string(now.strftime("%m/%d/%y"), buf)
            return 0

        reg("_strdate_s", _strdate_s_impl, 2)
        reg("_wstrdate_s", _strdate_s_impl, 2)

        def _strtime_s_impl(self, emu, argv, ctx=None):
            buf, size = argv
            if not buf or size < 9:
                return 34
            now = datetime.datetime.now()
            self.write_string(now.strftime("%H:%M:%S"), buf)
            return 0

        reg("_strtime_s", _strtime_s_impl, 2)
        reg("_wstrtime_s", _strtime_s_impl, 2)

        def _wstrdate_impl(self, emu, argv, ctx=None):
            buf = argv[0]
            if not buf:
                return 0
            now = datetime.datetime.now()
            self.write_string(now.strftime("%m/%d/%y"), buf)
            return buf

        reg("_wstrdate", _wstrdate_impl, 1)

        def _wstrtime_impl(self, emu, argv, ctx=None):
            buf = argv[0]
            if not buf:
                return 0
            now = datetime.datetime.now()
            self.write_string(now.strftime("%H:%M:%S"), buf)
            return buf

        reg("_wstrtime", _wstrtime_impl, 1)

        # ---- temp names ----
        self._temp_counter = 0

        def _temp_name_impl(self, emu, argv, ctx=None):
            self._temp_counter += 1
            return f"tmp{self._temp_counter:04x}"

        def tmpnam_impl(self, emu, argv, ctx=None):
            buf = argv[0]
            name = _temp_name_impl(self, emu, [], None)
            if not buf:
                buf = self.mem_alloc(0x100, tag="api.msvcrt.tmp")
            self.write_string(name, buf)
            return buf

        reg("tmpnam", tmpnam_impl, 1)
        reg("_wtmpnam", tmpnam_impl, 1)

        def tmpnam_s_impl(self, emu, argv, ctx=None):
            buf, size = argv
            name = _temp_name_impl(self, emu, [], None)
            if len(name) + 1 > size:
                return 34
            self.write_string(name, buf)
            return 0

        reg("tmpnam_s", tmpnam_s_impl, 2)
        reg("_wtmpnam_s", tmpnam_s_impl, 2)
        reg("_tmpnam_s", tmpnam_s_impl, 2)
        reg("_wtmpnam_s", tmpnam_s_impl, 2)

        def _mktemp_impl(self, emu, argv, ctx=None):
            s = argv[0]
            if not s:
                return 0
            self._temp_counter += 1
            self.write_string(f"tmp{self._temp_counter:04x}", s)
            return s

        reg("_mktemp", _mktemp_impl, 1)
        reg("_wmktemp", _mktemp_impl, 1)

        def _mktemp_s_impl(self, emu, argv, ctx=None):
            s, size = argv
            if not s:
                return 22
            self._temp_counter += 1
            name = f"tmp{self._temp_counter:04x}"
            if len(name) + 1 > size:
                return 34
            self.write_string(name, s)
            return 0

        reg("_mktemp_s", _mktemp_s_impl, 2)
        reg("_wmktemp_s", _mktemp_s_impl, 2)

        def _tempnam_impl(self, emu, argv, ctx=None):
            name = _temp_name_impl(self, emu, [], None)
            data = name.encode("utf-8") + b"\x00"
            buf = self.mem_alloc(len(data), tag="api.msvcrt.tmp")
            self.mem_write(buf, data)
            return buf

        reg("_tempnam", _tempnam_impl, 2)
        reg("_wtempnam", _tempnam_impl, 2)
        reg("_tempnam_dbg", _tempnam_impl, 2)
        reg("_wtempnam_dbg", _tempnam_impl, 2)

        def tmpfile_impl(self, emu, argv, ctx=None):
            hnd = self.file_open("C:\\temp.tmp", create=True, truncate=True)
            return hnd if hnd else 0

        reg("tmpfile", tmpfile_impl, 0)

        def tmpfile_s_impl(self, emu, argv, ctx=None):
            out = argv[0]
            hnd = tmpfile_impl(self, emu, [], None)
            if out:
                self.mem_write(out, hnd.to_bytes(ptr, "little"))
            return 0

        reg("tmpfile_s", tmpfile_s_impl, 2)

        def _rmtmp_impl(self, emu, argv, ctx=None):
            return 0

        reg("_rmtmp", _rmtmp_impl, 0)

        # ---- misc helpers ----
        def _msize_impl(self, emu, argv, ctx=None):
            return 0x1000

        reg("_msize", _msize_impl, 1)
        reg("_msize_dbg", _msize_impl, 1)

        def _expand_impl(self, emu, argv, ctx=None):
            mem, size = argv
            return mem if mem else 0

        reg("_expand", _expand_impl, 2)

        def _recalloc_impl(self, emu, argv, ctx=None):
            count, size = argv
            chunk = self.heap_alloc(count * size, heap="HeapAlloc")
            self.mem_write(chunk, b"\x00" * (count * size))
            return chunk

        reg("_recalloc", _recalloc_impl, 2)

        def _malloc_base_impl(self, emu, argv, ctx=None):
            size = argv[0]
            if not size:
                return 0
            return self.heap_alloc(size, heap="HeapAlloc")

        reg("_malloc_base", _malloc_base_impl, 1)

        def _free_base_impl(self, emu, argv, ctx=None):
            mem = argv[0]
            if mem:
                try:
                    self.mem_free(mem)
                except Exception:
                    pass
            return

        reg("_free_base", _free_base_impl, 1)

        def _realloc_base_impl(self, emu, argv, ctx=None):
            mem, size = argv
            if not mem:
                return self.heap_alloc(size, heap="HeapAlloc")
            if not size:
                try:
                    self.mem_free(mem)
                except Exception:
                    pass
                return 0
            new = self.heap_alloc(size, heap="HeapAlloc")
            try:
                self.mem_write(new, self.mem_read(mem, min(size, 0x1000)))
                self.mem_free(mem)
            except Exception:
                pass
            return new

        reg("_realloc_base", _realloc_base_impl, 2)

        def _calloc_base_impl(self, emu, argv, ctx=None):
            count, size = argv
            chunk = self.heap_alloc(count * size, heap="HeapAlloc")
            self.mem_write(chunk, b"\x00" * (count * size))
            return chunk

        reg("_calloc_base", _calloc_base_impl, 2)

        def _aligned_malloc_impl(self, emu, argv, ctx=None):
            size, align = argv
            chunk = self.heap_alloc(size + align, heap="HeapAlloc")
            aligned = (chunk + align - 1) & ~(align - 1)
            return aligned

        reg("_aligned_malloc", _aligned_malloc_impl, 2)
        reg("_aligned_offset_malloc", _aligned_malloc_impl, 3)

        def _aligned_free_impl(self, emu, argv, ctx=None):
            mem = argv[0]
            if mem:
                try:
                    self.mem_free(mem & ~0xFFF)
                except Exception:
                    pass

        reg("_aligned_free", _aligned_free_impl, 1)

        def _aligned_realloc_impl(self, emu, argv, ctx=None):
            mem, size, align = argv
            return _aligned_malloc_impl(self, emu, [size, align], None)

        reg("_aligned_realloc", _aligned_realloc_impl, 3)
        reg("_aligned_offset_realloc", _aligned_realloc_impl, 4)

        def _aligned_recalloc_impl(self, emu, argv, ctx=None):
            mem, count, size, align = argv
            return _aligned_malloc_impl(self, emu, [count * size, align], None)

        reg("_aligned_recalloc", _aligned_recalloc_impl, 4)
        reg("_aligned_offset_recalloc", _aligned_recalloc_impl, 5)

        def _heapchk_impl(self, emu, argv, ctx=None):
            return 1  # _HEAPOK

        reg("_heapchk", _heapchk_impl, 0)

        def _heapmin_impl(self, emu, argv, ctx=None):
            return 0

        reg("_heapmin", _heapmin_impl, 0)

        def _get_heap_handle_impl(self, emu, argv, ctx=None):
            return 0x12340000

        reg("_get_heap_handle", _get_heap_handle_impl, 0)

        def _setmaxstdio_impl(self, emu, argv, ctx=None):
            n = argv[0]
            return n if 0 < n <= 0x8000 else -1

        reg("_setmaxstdio", _setmaxstdio_impl, 1)

        def _swab_impl(self, emu, argv, ctx=None):
            src, dst, n = argv
            if not src or not dst or n <= 0:
                return
            data = self.mem_read(src, n)
            self.mem_write(dst, data[1::2] + data[::2] if len(data) % 2 == 0 else data[: n - 1][1::2] + data[: n - 1][::2])

        reg("_swab", _swab_impl, 3)

        def _umask_impl(self, emu, argv, ctx=None):
            return 0

        reg("_umask", _umask_impl, 1)
        reg("_umask_s", _umask_impl, 2)

        def strerror_impl(self, emu, argv, ctx=None):
            if self._strerror_buf is None:
                self._strerror_buf = self.mem_alloc(0x100, tag="api.msvcrt.strerror")
            self.write_string("Unknown error", self._strerror_buf)
            return self._strerror_buf

        self._strerror_buf = None
        reg("strerror", strerror_impl, 1)

        def strerror_s_impl(self, emu, argv, ctx=None):
            buf, size, err = argv
            if not buf:
                return 22
            s = "Unknown error"
            if len(s) + 1 > size:
                return 34
            self.write_string(s, buf)
            return 0

        reg("strerror_s", strerror_s_impl, 3)
        reg("_strerror_s", strerror_s_impl, 3)
        reg("_wcserror_s", strerror_s_impl, 3)

        def _strerror_impl(self, emu, argv, ctx=None):
            return strerror_impl(self, emu, [0], None)

        reg("_strerror", _strerror_impl, 1)
        reg("_wcserror", _strerror_impl, 1)

        def perror_impl(self, emu, argv, ctx=None):
            return 0

        reg("perror", perror_impl, 1)
        reg("_wperror", perror_impl, 1)

        def _set_abort_behavior_impl(self, emu, argv, ctx=None):
            return 0

        reg("_set_abort_behavior", _set_abort_behavior_impl, 2)

        def _set_printf_count_output_impl(self, emu, argv, ctx=None):
            return 0

        reg("_set_printf_count_output", _set_printf_count_output_impl, 1)

        def _set_output_format_impl(self, emu, argv, ctx=None):
            return 0

        reg("_set_output_format", _set_output_format_impl, 1)

        def _query_app_type_impl(self, emu, argv, ctx=None):
            return 0

        reg("_query_app_type", _query_app_type_impl, 0)

        def _fpclass_impl(self, emu, argv, ctx=None):
            x = self.hex_to_double(argv[0])
            if x != x:
                return 2  # _FPCLASS_QNAN
            if x == float("inf"):
                return 10  # _FPCLASS_PINF
            if x == float("-inf"):
                return 3  # _FPCLASS_NINF
            if x == 0:
                return 7  # _FPCLASS_PZ
            if x > 0:
                return 9  # _FPCLASS_PN
            return 4  # _FPCLASS_NN

        reg("_fpclass", _fpclass_impl, 1, e_arch.CALL_CONV_FLOAT)

        def _fpclassf_impl(self, emu, argv, ctx=None):
            return 9  # _FPCLASS_PN

        reg("_fpclassf", _fpclassf_impl, 1)

        def _hypot_impl(self, emu, argv, ctx=None):
            a = self.hex_to_double(argv[0])
            b = self.hex_to_double(argv[1])
            return self.double_to_hex(math.hypot(a, b))

        reg("_hypot", _hypot_impl, 2, e_arch.CALL_CONV_FLOAT)
        reg("_hypotf", _hypot_impl, 2, e_arch.CALL_CONV_FLOAT)

    def hex_to_double(self, x):
        x = x.to_bytes(8, "little")
        x = struct.unpack("d", x)[0]
        return x

    def double_to_hex(self, x):
        return struct.unpack("<Q", struct.pack("<d", x))[0]

    @impdata("_acmdln")
    def _acmdln(self, ptr=0):
        """Command line global CRT variable"""

        cmdln = ptr
        _argv = self.emu.get_argv()
        _argv = " ".join(_argv).encode("utf-8")

        ptr_size = self.emu.get_ptr_size()

        if not ptr:
            cmdln = self.mem_alloc(len(_argv) + ptr_size, base=None, tag="api.msvcrt._acmdln")
            p_cmdln = cmdln + ptr_size
            self.emu.mem_write(cmdln, p_cmdln.to_bytes(ptr_size, "little"))
            self.emu.mem_write(p_cmdln, _argv)
        return cmdln

    @apihook("__p__acmdln", argc=0)
    def __p__acmdln(self, emu, argv, ctx: api.ApiContext = None):
        """Command line global CRT variable"""

        cmdln = self._acmdln()

        return cmdln

    @apihook("_onexit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _onexit(self, emu, argv, ctx: api.ApiContext = None):
        """
        _onexit_t _onexit(
            _onexit_t function
        )
        """

        (func,) = argv
        return func

    @apihook("mbstowcs_s", argc=5, conv=e_arch.CALL_CONV_CDECL)
    def mbstowcs_s(self, emu, argv, ctx: api.ApiContext = None):
        """
        errno_t mbstowcs_s(
            size_t *pReturnValue,
            wchar_t *wcstr,
            size_t sizeInWords,
            const char *mbstr,
            size_t count
        )
        """

        pReturnValue, wcstr, sizeInWords, mbstr, count = argv

        rv = 0
        if pReturnValue:
            self.mem_write(pReturnValue, struct.pack("<I", 0))

        # Sanity checks
        if sizeInWords > 0 and not wcstr:
            rv = EINVAL
        elif not mbstr:
            rv = EINVAL
        elif sizeInWords == 0 and wcstr:
            rv = EINVAL
        else:
            # Convert the string
            mbs = self.read_mem_string(mbstr, 1)
            argv[3] = mbs
            mbs += "\x00"
            ws = mbs.encode("utf-16le")

            if (len(ws) / 2 > sizeInWords and count != _TRUNCATE) and (count >= sizeInWords):
                # Buffer too small
                rv = ERANGE
            else:
                if count == _TRUNCATE:
                    self.mem_write(wcstr, ws[: (sizeInWords - 1) * 2])
                    if pReturnValue:
                        self.mem_write(pReturnValue, struct.pack("<I", sizeInWords))
                else:
                    self.mem_write(wcstr, ws[: count * 2])
                    if pReturnValue:
                        self.mem_write(pReturnValue, struct.pack("<I", count + 1))

        return rv

    @apihook("_wcsnicmp", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _wcsnicmp(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _wcsnicmp(
            const wchar_t *string1,
            const wchar_t *string2,
            size_t count
        )
        """

        string1, string2, count = argv
        rv = 1

        ws1 = self.read_wide_string(string1, max_chars=count)
        ws2 = self.read_wide_string(string2, max_chars=count)

        argv[0] = ws1
        argv[1] = ws2

        if ws1.lower() == ws2.lower():
            rv = 0

        return rv

    # Reference: https://wiki.osdev.org/Visual_C%2B%2B_Runtime
    @apihook("_initterm_e", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _initterm_e(self, emu, argv, ctx: api.ApiContext = None):
        """
        static int _initterm_e(_PIFV * pfbegin,
                                 _PIFV * pfend)
        """

        pfbegin, pfend = argv

        rv = 0

        return rv

    @apihook("_initterm", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _initterm(self, emu, argv, ctx: api.ApiContext = None):
        """static void _initterm (_PVFV * pfbegin, _PVFV * pfend)"""

        pfbegin, pfend = argv

        rv = 0

        return rv

    @apihook("__getmainargs", argc=5)
    def __getmainargs(self, emu, argv, ctx: api.ApiContext = None):
        """
        int __getmainargs(
            int * _Argc,
            char *** _Argv,
            char *** _Env,
            int _DoWildCard,
            _startupinfo * _StartInfo);
        """

        _Argc, _Argv, _Env, _DoWildCard, _StartInfo = argv
        rv = 0

        ptr_size = self.get_ptr_size()
        _argv = emu.get_argv()

        argc = len(_argv)

        if _Argc:
            self.mem_write(_Argc, argc.to_bytes(4, "little"))

        if _Argv:
            argv_list = [(a + "\x00").encode("utf-8") for a in _argv]
            array_size = ptr_size * (len(argv_list) + 1)
            total = sum([len(a) for a in argv_list]) + array_size

            arg_mem = self.mem_alloc(size=total, tag="api.argv")
            pptr = arg_mem
            sptr = arg_mem + array_size

            for a in argv_list:
                self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
                pptr += ptr_size
                self.mem_write(sptr, a)
                sptr += len(a)
            self.mem_write(pptr, b"\x00" * ptr_size)

            self.mem_write(_Argv, arg_mem.to_bytes(ptr_size, "little"))

        if _Env:
            env = emu.get_env()
            fmt_env = []
            total = ptr_size
            for k, v in env.items():
                envstr = f"{k}={v}\x00"
                envstr = envstr.encode("utf-8")
                total += len(envstr)
                fmt_env.append(envstr)
                total += ptr_size

            env_mem = self.mem_alloc(size=total, tag="api.envp")
            pptr = env_mem
            sptr = env_mem + ptr_size * (len(fmt_env) + 1)

            for v in fmt_env:
                self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
                pptr += ptr_size
                self.mem_write(sptr, v)
                sptr += len(v)
            self.mem_write(pptr, b"\x00" * ptr_size)

            self.mem_write(_Env, env_mem.to_bytes(ptr_size, "little"))

        return rv

    @apihook("__wgetmainargs", argc=5)
    def __wgetmainargs(self, emu, argv, ctx: api.ApiContext = None):
        """
        int __wgetmainargs (
           int *_Argc,
           wchar_t ***_Argv,
           wchar_t ***_Env,
           int _DoWildCard,
           _startupinfo * _StartInfo);
        """

        _Argc, _Argv, _Env, _DoWildCard, _StartInfo = argv
        rv = 0

        return rv

    @apihook("__p___wargv", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___wargv(self, emu, argv, ctx: api.ApiContext = None):
        """WCHAR *** __p___wargv ()"""

        ptr_size = self.get_ptr_size()
        _argv = emu.get_argv()

        argv = [(a + "\x00\x00\x00\x00").encode("utf-16le") for a in _argv]
        array_size = ptr_size * (len(argv) + 2)
        total = sum([len(a) for a in argv])
        total += array_size

        sptr = 0
        pptr = 0

        arg_mem = self.mem_alloc(size=total, tag="api.argv")
        pptr = arg_mem + ptr_size
        self.mem_write(arg_mem, pptr.to_bytes(ptr_size, "little"))
        sptr = pptr + array_size

        for a in argv:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
            pptr += ptr_size
            self.mem_write(sptr, a)
            sptr += len(a)
        self.mem_write(pptr, b"\x00" * ptr_size)
        rv = arg_mem

        # TODO: dispatch the VFV function array
        return rv

    @apihook("__p___argv", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___argv(self, emu, argv, ctx: api.ApiContext = None):
        """char *** __p___argv ()"""

        ptr_size = self.get_ptr_size()
        _argv = emu.get_argv()

        argv = [(a + "\x00\x00\x00\x00").encode("utf-8") for a in _argv]

        array_size = ptr_size * (len(argv) + 2)
        total = sum([len(a) for a in argv])
        total += array_size

        sptr = 0
        pptr = 0

        arg_mem = self.mem_alloc(size=total, tag="api.argv")
        pptr = arg_mem + ptr_size
        self.mem_write(arg_mem, pptr.to_bytes(ptr_size, "little"))
        sptr = pptr + array_size

        for a in argv:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
            pptr += ptr_size
            self.mem_write(sptr, a)
            sptr += len(a)
        self.mem_write(pptr, b"\x00" * ptr_size)

        rv = arg_mem
        return rv

    @apihook("__p___argc", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___argc(self, emu, argv, ctx: api.ApiContext = None):
        """int * __p___argc ()"""

        _argv = emu.get_argv()

        argc = self.mem_alloc(size=4, tag="api.argc")
        self.mem_write(argc, len(_argv).to_bytes(4, "little"))
        return argc

    @apihook("__p___initenv", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___initenv(self, emu, argv, ctx: api.ApiContext = None):
        """char *** __p___initenv ()"""
        ptr_size = self.get_ptr_size()
        ptr = self.mem_alloc(size=ptr_size, tag="api.initenv")
        return ptr

    @apihook("_get_initial_narrow_environment", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _get_initial_narrow_environment(self, emu, argv, ctx: api.ApiContext = None):
        """char** _get_initial_narrow_environment ()"""

        ptr_size = self.get_ptr_size()
        env = emu.get_env()
        total = ptr_size
        sptr = total
        pptr = 0
        fmt_env = []
        for k, v in env.items():
            envstr = f"{k}={v}\x00"
            envstr = envstr.encode("utf-8")
            total += len(envstr)
            fmt_env.append(envstr)
            total += ptr_size
            sptr += ptr_size

        envp = self.mem_alloc(size=total, tag="api.envp")
        pptr = envp
        sptr += envp

        for v in fmt_env:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
            pptr += ptr_size
            self.mem_write(sptr, v)
            sptr += len(v)

        return envp

    @apihook("_get_initial_wide_environment", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _get_initial_wide_environment(self, emu, argv, ctx: api.ApiContext = None):
        """WCHAR** _get_initial_wide_environment ()"""

        ptr_size = self.get_ptr_size()
        env = emu.get_env()
        total = ptr_size
        sptr = total
        pptr = 0
        fmt_env = []
        for k, v in env.items():
            envstr = f"{k}={v}\x00"
            envstr = envstr.encode("utf-16le")
            total += len(envstr)
            fmt_env.append(envstr)
            total += ptr_size
            sptr += ptr_size

        envp = self.mem_alloc(size=total, tag="api.envp")
        pptr = envp
        sptr += envp

        for v in fmt_env:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
            pptr += ptr_size
            self.mem_write(sptr, v)
            sptr += len(v)

        return envp

    @apihook("exit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def exit(self, emu, argv, ctx: api.ApiContext = None):
        """
        void exit(
           int const status
        );
        """

        self.exit_process()

    @apihook("_exit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _exit(self, emu, argv, ctx: api.ApiContext = None):
        """
        void _exit(
           int const status
        );
        """

        self.exit_process()

    @apihook("_XcptFilter", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _XcptFilter(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _XcptFilter(
            unsigned long xcptnum,
            struct _EXCEPTION_POINTERS *pxcptinfoptrs
        );
        """
        _xcptnum, _pxcptinfoptrs = argv

        return 0

    @apihook("_CxxThrowException", argc=2, conv=e_arch.CALL_CONV_STDCALL)
    def _CxxThrowException(self, emu, argv, ctx: api.ApiContext = None):
        """
        void _CxxThrowException(
            void *pExceptionObject,
            _ThrowInfo *pThrowInfo
        );
        """
        return

    @apihook("__acrt_iob_func", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __acrt_iob_func(self, emu, argv, ctx: api.ApiContext = None):
        """FILE * __acrt_iob_func (fd)"""

        (fd,) = argv

        return fd

    @apihook("pow", argc=2, conv=e_arch.CALL_CONV_FLOAT)
    def pow(self, emu, argv, ctx: api.ApiContext = None):
        """
        double pow(
           double x,
           double y
        );
        """
        x, y = argv

        x = self.hex_to_double(x)
        y = self.hex_to_double(y)

        z = pow(x, y)

        z = self.double_to_hex(z)

        return z

    @apihook("floor", argc=1, conv=e_arch.CALL_CONV_FLOAT)
    def floor(self, emu, argv, ctx: api.ApiContext = None):
        """
        double floor(
           double x
        );
        """
        (x,) = argv

        y = self.hex_to_double(x)
        z = math.floor(y)
        z = self.double_to_hex(z)

        return z

    @apihook("sin", argc=1, conv=e_arch.CALL_CONV_FLOAT)
    def sin(self, emu, argv, ctx: api.ApiContext = None):
        """
        double sin(
           double x
        );
        """
        (x,) = argv

        y = self.hex_to_double(x)
        z = math.sin(y)
        z = self.double_to_hex(z)

        return z

    @apihook("abs", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def abs(self, emu, argv, ctx: api.ApiContext = None):
        """
        int abs(
           int x
        );
        """
        (x,) = argv
        y = abs(x)
        return y

    @apihook("strstr", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strstr(self, emu, argv, ctx: api.ApiContext = None):
        """
        char *strstr(
           const char *str,
           const char *strSearch
        );
        """
        hay, needle = argv

        if hay:
            _hay = self.read_mem_string(hay, 1)
            argv[0] = _hay

        if needle:
            needle = self.read_mem_string(needle, 1)
            argv[1] = needle

        ret = _hay.find(needle)
        if ret != -1:
            ret = hay + ret
        else:
            ret = 0

        return ret

    @apihook("wcsstr", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcsstr(self, emu, argv, ctx: api.ApiContext = None):
        """
        wchar_t *wcsstr(
            const wchar_t *str,
            const wchar_t *strSearch
        );
        """
        hay, needle = argv

        if hay:
            _hay = self.read_mem_string(hay, 2)
            argv[0] = _hay

        if needle:
            needle = self.read_mem_string(needle, 2)
            argv[1] = needle

        ret = _hay.find(needle)
        if ret != -1:
            ret = hay + ret
        else:
            ret = 0

        return ret

    @apihook("strncat_s", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def strncat_s(self, emu, argv, ctx: api.ApiContext = None):
        """
        errno_t strncat_s(
           char *strDest,
           size_t numberOfElements,
           const char *strSource,
           size_t count
        );
        """
        strDest, num, src, count = argv
        rv = 0

        is_truncated = 0xFFFFFFFF & count
        if is_truncated == _TRUNCATE:
            is_truncated = True
        else:
            is_truncated = False

        argv[0] = self.read_mem_string(strDest, 1)
        argv[2] = self.read_mem_string(src, 1)

        slen1 = self.mem_string_len(strDest, 1)
        rem = num - slen1

        if is_truncated:
            if rem < count:
                self.mem_copy(strDest + slen1, src, count - 1)
            else:
                self.mem_copy(strDest + slen1, src, count)
        else:
            if rem < count:
                rv = EINVAL
            else:
                self.mem_copy(strDest + slen1, src, count)

        return rv

    @apihook("__stdio_common_vfprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vfprintf(self, emu, argv, ctx: api.ApiContext = None):

        arch = emu.get_arch()
        if arch == e_arch.ARCH_AMD64:
            opts, stream, fmt, _, va_list = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 5)[:5]
        else:
            opts, opts2, stream, fmt, _, va_list = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 6)[:6]

        rv = 0

        fmt_str = self.read_mem_string(fmt, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(va_list, fmt_cnt)
        fin = self.do_str_format(fmt_str, vargs)

        argv[:] = [opts, stream, fin]

        rv = len(fin)
        return rv

    @apihook("fprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def fprintf(self, emu, argv, ctx: api.ApiContext = None):
        """
        int fprintf(
            FILE *stream,
            const char *format,
            ...
            );
        """
        stream, fmt = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2)
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        if not fmt_cnt:
            argv.clear()
            argv.extend([stream, fmt_str])
            return len(fmt_str)

        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _argv)
        argv.clear()
        argv.extend([stream, fin])
        return len(fin)

    @apihook("printf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def printf(self, emu, argv, ctx: api.ApiContext = None):
        """
        int printf(
            const char *format,
            ...
            );
        """
        (fmt,) = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 1)
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        if not fmt_cnt:
            argv.clear()
            argv.extend([fmt_str])
            return len(fmt_str)

        fmt_argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 1 + fmt_cnt)[1:]
        fin = self.do_str_format(fmt_str, fmt_argv)
        argv.clear()
        argv.extend([fin])
        return len(fin)

    @apihook("memset", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memset(self, emu, argv, ctx: api.ApiContext = None):
        """
        void *memset ( void * ptr,
                       int value,
                       size_t num );
        """

        ptr, value, num = argv

        data = value.to_bytes(1, "little") * num
        self.mem_write(ptr, data)

        return ptr

    @apihook("time", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def time(self, emu, argv, ctx: api.ApiContext = None):
        """
        time_t time( time_t *destTime );
        """

        (destTime,) = argv

        out_time = TIME_BASE
        if destTime:
            self.mem_write(destTime, out_time.to_bytes(4, "little", signed=False))

        return out_time

    @apihook("_strtime", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _strtime(self, emu, argv, ctx: api.ApiContext = None):
        """
        char *_strtime(char *buffer);
        """
        (buffer,) = argv
        if not buffer:
            return 0
        self.mem_write(buffer, b"12:34:56\x00")
        return buffer

    @apihook("_strdate", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _strdate(self, emu, argv, ctx: api.ApiContext = None):
        """
        char *_strdate(char *buffer);
        """
        (buffer,) = argv
        if not buffer:
            return 0
        self.mem_write(buffer, b"12/29/19\x00")
        return buffer

    @apihook("clock", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def clock(self, emu, argv, ctx: api.ApiContext = None):
        """
        clock_t clock( void );
        """

        self.tick_counter += 200

        return self.tick_counter

    @apihook("srand", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def srand(self, emu, argv, ctx: api.ApiContext = None):
        """
        void srand (unsigned int seed);
        """

        (seed,) = argv

        return

    @apihook("sprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def sprintf(self, emu, argv, ctx: api.ApiContext = None):
        """
        int sprintf(
            char *buffer,
            const char *format [,
            argument] ...
            );
        """
        buf, fmt = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2)
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)
        if not fmt_cnt:
            self.write_string(fmt_str, buf)
            return len(fmt_str)

        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _argv)

        self.write_string(fin, buf)
        argv.clear()
        argv.append(fin)
        return len(fin)

    @apihook("_snprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def _snprintf(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _snprintf(
        char *buffer,
        size_t count,
        const char *format [,
        argument] ...
        );
        """
        buf, count, fmt = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3)
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)
        if not fmt_cnt:
            self.write_string(fmt_str, buf)
            return len(fmt_str)

        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
        fin = self.do_str_format(fmt_str, _argv)

        self.write_string(fin, buf)
        argv.clear()
        argv.append(fin)
        return len(fin)

    @apihook("atoi", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def atoi(self, emu, argv, ctx: api.ApiContext = None):
        """
        int atoi(
            const char *str
        );
        """

        (_str,) = argv

        i = self.read_string(_str)
        argv[0] = i

        txt = i.strip()
        neg = txt[:1] == "-"
        digits = txt[1:] if txt[:1] in "+-" else txt
        rv = 0
        for ch in digits:
            if not ch.isdigit():
                break
            rv = rv * 10 + int(ch)
        if neg:
            rv = -rv

        return rv

    @apihook("rand", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def rand(self, emu, argv, ctx: api.ApiContext = None):
        """
        int rand( void );
        """

        self.rand_int += 1

        return self.rand_int

    @apihook("__set_app_type", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __set_app_type(self, emu, argv, ctx: api.ApiContext = None):
        """
        void __set_app_type (
            int at
        )
        """
        return

    @apihook("_set_app_type", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_app_type(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("__p__fmode", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p__fmode(self, emu, argv, ctx: api.ApiContext = None):
        """
        int* __p__fmode();
        """
        _O_TEXT = 0x4000

        ptr = self.mem_alloc(4, tag="api.fmode")
        data = _O_TEXT.to_bytes(4, "little")
        self.mem_write(ptr, data)
        return ptr

    @apihook("__p__commode", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p__commode(self, emu, argv, ctx: api.ApiContext = None):
        """
        int* __p__commode();
        """
        _IOCOMMIT = 0x4000

        ptr = self.mem_alloc(4, tag="api.commode")
        data = _IOCOMMIT.to_bytes(4, "little")
        self.mem_write(ptr, data)
        return ptr

    @apihook("_controlfp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _controlfp(self, emu, argv, ctx: api.ApiContext = None):
        """
        unsigned int _controlfp(unsigned int new,
                                unsinged int mask)
        """
        return 0

    @apihook("strcpy", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strcpy(self, emu, argv, ctx: api.ApiContext = None):
        """
        char *strcpy(
           char *strDestination,
           const char *strSource
        );
        """
        dest, src = argv
        s = self.read_string(src)

        self.write_string(s, dest)
        argv[1] = s
        return dest

    @apihook("wcscpy", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcscpy(self, emu, argv, ctx: api.ApiContext = None):
        """
        wchar_t *wcscpy(
            wchar_t *strDestination,
            const wchar_t *strSource
        );
        """
        dest, src = argv
        ws = self.read_wide_string(src)
        self.write_wide_string(ws, dest)
        argv[1] = ws
        return dest

    @apihook("strncpy", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strncpy(self, emu, argv, ctx: api.ApiContext = None):
        """
        char * strncpy(
            char * destination,
            const char * source,
            size_t num
        );
        """
        dest, src, length = argv
        s = self.read_string(src, max_chars=length)
        if len(s) < length:
            s += "\x00" * (length - len(s))
        self.write_string(s, dest)
        argv[1] = s
        return dest

    @apihook("wcsncpy", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def wcsncpy(self, emu, argv, ctx: api.ApiContext = None):
        """
        wchar_t *wcsncpy(
           wchar_t *strDest,
           const wchar_t *strSource,
           size_t count
        );
        """
        dest, src, count = argv
        ws = self.read_wide_string(src, max_chars=count)
        if len(ws) < count:
            ws += "\x00" * (count - len(ws))
        self.write_wide_string(ws, dest)
        argv[1] = ws
        return dest

    @apihook("memcpy", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memcpy(self, emu, argv, ctx: api.ApiContext = None):
        """
        void *memcpy(
            void *dest,
            const void *src,
            size_t count
            );
        """
        dest, src, count = argv
        data = self.mem_read(src, count)
        self.mem_write(dest, data)
        return dest

    @apihook("memmove", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memmove(self, emu, argv, ctx: api.ApiContext = None):
        """
        void *memmove(
            void *dest,
            const void *src,
            size_t count
        );
        """
        dest, src, count = argv
        data = self.mem_read(src, count)
        self.mem_write(dest, data)
        return dest

    @apihook("memcmp", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memcmp(self, emu, argv, ctx: api.ApiContext = None):
        """
        int memcmp(
           const void *buffer1,
           const void *buffer2,
           size_t count
        );
        """
        diff = 0
        buff1, buff2, cnt = argv
        for i in range(cnt):
            b1 = self.mem_read(buff1, 1)
            b2 = self.mem_read(buff2, 1)
            if b1 > b2:
                diff = 1
                break
            elif b1 < b2:
                diff = -1
                break

        return diff

    @apihook("_except_handler4_common", argc=6, conv=e_arch.CALL_CONV_CDECL)
    def _except_handler4_common(self, emu, argv, ctx: api.ApiContext = None):
        """
        _CRTIMP  __C_specific_handler(
        _In_    struct _EXCEPTION_RECORD   *ExceptionRecord,
        _In_    void                       *EstablisherFrame,
        _Inout_ struct _CONTEXT            *ContextRecord,
        _Inout_ struct _DISPATCHER_CONTEXT *DispatcherContext
        );
        """
        # Inferred from the SEH teardowns described here:
        # https://bytepointer.com/resources/pietrek_crash_course_depths_of_win32_seh.htm
        # http://www.openrce.org/articles/full_view/21

        # Two additional arguments are pushed to the function to check security cookies
        cookie_ptr, cookie_func, record, frame, context, dispath_ctx = argv
        rv = 0

        cookie = self.mem_read(cookie_ptr, 4)
        cookie = int.from_bytes(cookie, "little")

        thread = emu.get_current_thread()

        # Break down the exception records into something more manageable
        curr_frame = frame
        seh = thread.seh

        _ctx = self.wintypes.CONTEXT(emu.get_ptr_size())
        _ctx = self.mem_cast(_ctx, context)

        seh.set_context(_ctx, address=context)
        seh.record = record

        seh.clear_frames()

        while curr_frame != 0:
            reg = self.wintypes.EXCEPTION_REGISTRATION(emu.get_ptr_size())
            reg = self.mem_cast(reg, curr_frame)

            scope_table = reg.ScopeTable ^ cookie

            st = self.wintypes.EH4_SCOPETABLE(emu.get_ptr_size())
            st = self.mem_cast(st, scope_table)

            rec = self.wintypes.EH4_SCOPETABLE_RECORD(emu.get_ptr_size())
            # The trylevel will tell us what scope record to get
            scope_record_offset = scope_table + st.sizeof()
            tl = reg.TryLevel
            if reg.TryLevel & 0x80000000:
                tl = -0x100000000 + reg.TryLevel

            if tl == -2:  # -2 is the outermost scope
                tl = 0

            scope_record_offset += rec.sizeof() * tl
            rec = self.mem_cast(rec, scope_record_offset)

            seh.add_frame(
                reg,
                st,
                [
                    rec,
                ],
            )

            curr_frame = reg.Next

        return rv

    @apihook("_seh_filter_exe", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _seh_filter_exe(self, emu, argv, ctx: api.ApiContext = None):
        """
        int __cdecl _seh_filter_exe(
           unsigned long _ExceptionNum,
           struct _EXCEPTION_POINTERS* _ExceptionPtr
        );
        """
        except_num, exc_ptr = argv
        rv = 1

        return rv

    @apihook("_except_handler3", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def _except_handler3(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _except_handler3(
        PEXCEPTION_RECORD exception_record,
        PEXCEPTION_REGISTRATION registration,
        PCONTEXT context,
        PEXCEPTION_REGISTRATION dispatcher
        );
        """
        rv = 1
        return rv

    @apihook("_seh_filter_dll", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _seh_filter_dll(self, emu, argv, ctx: api.ApiContext = None):
        """
        int __cdecl _seh_filter_dll(
           unsigned long _ExceptionNum,
           struct _EXCEPTION_POINTERS* _ExceptionPtr
        );
        """
        except_num, exc_ptr = argv
        rv = 1

        return rv

    @apihook("puts", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def puts(self, emu, argv, ctx: api.ApiContext = None):
        """
        int puts(
           const char *str
        );
        """
        (s,) = argv

        string = self.read_mem_string(s, 1)
        argv[0] = string
        rv = len(string)

        return rv

    @apihook("_initialize_onexit_table", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _initialize_onexit_table(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _initialize_onexit_table(
            _onexit_table_t* table
            );
        """
        rv = 0

        return rv

    @apihook("_register_onexit_function", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _register_onexit_function(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _register_onexit_function(
            _onexit_table_t* table,
            _onexit_t        function
            );
        """
        rv = 0

        return rv

    @apihook("malloc", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def malloc(self, emu, argv, ctx: api.ApiContext = None):
        """
        void *malloc(
        size_t size
        );
        """
        (size,) = argv

        chunk = self.heap_alloc(size, heap="HeapAlloc")
        return chunk

    @apihook("calloc", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def calloc(self, emu, argv, ctx: api.ApiContext = None):
        """
        void *calloc(
        size_t num,
        size_t size
        );
        """
        (
            num,
            size,
        ) = argv

        chunk = self.heap_alloc(num * size, heap="HeapAlloc")

        buf = b"\x00" * (num * size)
        self.mem_write(chunk, buf)

        return chunk

    @apihook("free", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def free(self, emu, argv, ctx: api.ApiContext = None):
        """
        void free(
        void *memblock
        );
        """
        (mem,) = argv
        self.mem_free(mem)

    @apihook("_beginthreadex", argc=6, conv=e_arch.CALL_CONV_CDECL)
    def _beginthreadex(self, emu, argv, ctx: api.ApiContext = None):
        """
        uintptr_t _beginthreadex(
            void *security,
            unsigned stack_size,
            unsigned ( __stdcall *start_address )( void * ),
            void *arglist,
            unsigned initflag,
            unsigned *thrdaddr
        );
        """
        security, stack_size, start_address, arglist, initflag, thrdaddr = argv

        handle, obj = self.create_thread(start_address, arglist, emu.get_current_process())

        if thrdaddr:
            self.mem_write(thrdaddr, obj.id.to_bytes(4, "little"))

        return handle

    @apihook("_beginthread", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _beginthread(self, emu, argv, ctx: api.ApiContext = None):
        """
        uintptr_t _beginthread
        void( __cdecl *start_address )( void * ),
        unsigned stack_size,
        void *arglist
        );
        """
        start_address, stack_size, arglist = argv

        handle, obj = self.create_thread(start_address, arglist, emu.get_current_process())
        return handle

    @apihook("system", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def system(self, emu, argv, ctx: api.ApiContext = None):
        """
        int system(
           const char *command
        );
        """
        (s,) = argv

        string = self.read_mem_string(s, 1)
        argv[0] = string
        rv = len(string)

        return rv

    @apihook("toupper", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def toupper(self, emu, argv, ctx: api.ApiContext = None):
        """
        int toupper(
           int c
        );
        """
        (c,) = argv
        argv[0] = c
        if 0x00 <= c <= 0x7F:
            c = ord(chr(c).upper())
        else:
            c = 0x00
        return c

    @apihook("strlen", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def strlen(self, emu, argv, ctx: api.ApiContext = None):
        """
        size_t strlen(
            const char *str
        );
        """
        (s,) = argv

        string = self.read_mem_string(s, 1)
        argv[0] = string
        rv = len(string)

        return rv

    @apihook("strcat", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strcat(self, emu, argv, ctx: api.ApiContext = None):
        """
        char *strcat(
            char *strDestination,
            const char *strSource
        );
        """
        _str1, _str2 = argv
        s1 = self.read_mem_string(_str1, 1)
        s2 = self.read_mem_string(_str2, 1)
        argv[0] = s1
        argv[1] = s2
        new = (s1 + s2).encode("utf-8")
        self.mem_write(_str1, new + b"\x00")
        return _str1

    @apihook("_strlwr", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _strlwr(self, emu, argv, ctx: api.ApiContext = None):
        """
        char *_strlwr(
            char *str
            );
        """
        (string_ptr,) = argv

        if not string_ptr:
            return 0

        string = self.read_string(string_ptr)
        argv[0] = string
        self.write_string(string.lower(), string_ptr)
        return string_ptr

    @apihook("strncat", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strncat(self, emu, argv, ctx: api.ApiContext = None):
        """
        char *strncat(
            char *destination,
            const char *source,
            size_t num
        );
        """
        dest, src, count = argv
        s1 = self.read_mem_string(dest, 1)
        s2 = self.read_string(src, max_chars=count)
        argv[0] = s1
        argv[1] = s2
        new = (s1 + s2).encode("utf-8")
        self.mem_write(dest, new + b"\x00")
        return dest

    @apihook("wcscat", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcscat(self, emu, argv, ctx: api.ApiContext = None):
        """
        wchar_t *wcscat(
           wchar_t *strDestination,
           const wchar_t *strSource
        );
        """
        _str1, _str2 = argv
        s1 = self.read_mem_string(_str1, 2)
        s2 = self.read_mem_string(_str2, 2)
        argv[0] = s1
        argv[1] = s2
        new = (s1 + s2).encode("utf-16le")
        self.mem_write(_str1, new + b"\x00\x00")
        return _str1

    @apihook("wcslen", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def wcslen(self, emu, argv, ctx: api.ApiContext = None):
        """
        size_t wcslen(
          const wchar_t* wcs
        );
        """
        (s,) = argv
        string = self.read_wide_string(s)
        argv[0] = string
        rv = len(string)

        return rv

    @apihook("_lock", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _lock(self, emu, argv, ctx: api.ApiContext = None):
        """
        void __cdecl _lock
            int locknum
        );
        """
        return

    @apihook("_unlock", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _unlock(self, emu, argv, ctx: api.ApiContext = None):
        """
        void __cdecl _unlock
            int locknum
        );
        """
        return

    @apihook("_ltoa", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _ltoa(self, emu, argv, ctx: api.ApiContext = None):
        """
        char *_ltoa(
            long value,
            char *str,
            int radix
        );
        """
        (
            val,
            out_str,
            radix,
        ) = argv

        v = str(val).encode("utf-8")
        self.mem_write(out_str, v)
        return

    @apihook("__dllonexit", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def __dllonexit(self, emu, argv, ctx: api.ApiContext = None):
        """
        onexit_t __dllonexit(
            _onexit_t func,
            _PVFV **  pbegin,
            _PVFV **  pend
        )
        """
        (
            func,
            pbegin,
            pend,
        ) = argv
        return func

    @apihook("strncmp", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strncmp(self, emu, argv, ctx: api.ApiContext = None):
        """
        int strncmp(
            const char *string1,
            const char *string2,
            size_t count
        );
        """
        s1, s2, c = argv
        rv = 1

        string1 = self.read_mem_string(s1, 1)
        string2 = self.read_mem_string(s2, 1)
        if string1 == string2:
            rv = 0
        argv[0] = string1
        argv[1] = string2

        return rv

    @apihook("strcmp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strcmp(self, emu, argv, ctx: api.ApiContext = None):
        """
        int strcmp(
            const char *string1,
            const char *string2,
        );
        """
        s1, s2 = argv
        rv = 1

        string1 = self.read_mem_string(s1, 1)
        string2 = self.read_mem_string(s2, 1)
        if string1 == string2:
            rv = 0
        argv[0] = string1
        argv[1] = string2

        return rv

    @apihook("strrchr", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strrchr(self, emu, argv, ctx: api.ApiContext = None):
        """
        char *strrchr(
            const char *str,
            int c
            );
        """
        cstr, c = argv
        cs = self.read_string(cstr)
        hay = cs.encode("utf-8")
        needle = c.to_bytes(1, "little")

        offset = hay.rfind(needle)
        if offset < 0:
            rv = 0
        else:
            rv = cstr + offset

        argv[0] = cs
        argv[1] = needle.decode("utf-8")

        return rv

    @apihook("_ftol", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _ftol(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _ftol(int);
        """
        (f,) = argv
        return int(f)

    @apihook("_adjust_fdiv", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _adjust_fdiv(self, emu, argv, ctx: api.ApiContext = None):
        """
        void _adjust_fdiv(void)
        """
        return

    @apihook("tolower", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def tolower(self, emu, argv, ctx: api.ApiContext = None):
        """
        int tolower ( int c );
        """
        (c,) = argv
        return c | 0x20

    @apihook("isdigit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def isdigit(self, emu, argv, ctx: api.ApiContext = None):
        """
        int isdigit(
            int c
            );
        """
        (c,) = argv
        return int(48 <= c <= 57)

    @apihook("sscanf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def sscanf(self, emu, argv, ctx: api.ApiContext = None):
        """
        int sscanf ( const char * s, const char * format, ...);
        """
        return

    @apihook("strchr", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strchr(self, emu, argv, ctx: api.ApiContext = None):
        """
        char *strchr(
            const char *str,
            int c
            );
        """
        cstr, c = argv
        cs = self.read_string(cstr)
        hay = cs.encode("utf-8")
        needle = c.to_bytes(1, "little")

        offset = hay.find(needle)
        if offset < 0:
            rv = 0
        else:
            rv = cstr + offset

        argv[0] = cs
        argv[1] = needle.decode("utf-8")

        return rv

    @apihook("_set_invalid_parameter_handler", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_invalid_parameter_handler(self, emu, argv, ctx: api.ApiContext = None):
        """
        _invalid_parameter_handler _set_invalid_parameter_handler(
        _invalid_parameter_handler pNew
        );
        """
        (pNew,) = argv

        return 0

    @apihook("__CxxFrameHandler", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def __CxxFrameHandler(self, emu, argv, ctx: api.ApiContext = None):
        """
        EXCEPTION_DISPOSITION __CxxFrameHandler(
            EHExceptionRecord  *pExcept,
            EHRegistrationNode *pRN,
            void               *pContext,
            DispatcherContext  *pDC
        )
        """
        (
            pExcept,
            pRN,
            pContext,
            pDC,
        ) = argv
        return 0

    @apihook("_vsnprintf", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def _vsnprintf(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _vsnprintf(
            char *buffer,
            size_t count,
            const char *format,
            va_list argptr
        );
        """
        buffer, count, _format, argptr = argv
        rv = 0

        fmt_str = self.read_mem_string(_format, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(argptr, fmt_cnt)

        fin = self.do_str_format(fmt_str, vargs)
        fin = fin[:count] + "\x00"

        rv = len(fin)
        self.mem_write(buffer, fin.encode("utf-8"))
        argv[0] = fin.replace("\x00", "")
        argv[1] = fmt_str

        return rv

    @apihook("__stdio_common_vsprintf", argc=7, conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vsprintf(self, emu, argv, ctx: api.ApiContext = None):
        """
        int __stdio_common_vsprintf(
            unsigned int64 Options,
            char *Buffer,
            unsigned int BufferCount,
            const char *format,
            locale_t Locale,
            va_list argptr
        );
        """
        options_lo, options_hi, buffer, count, _format, locale, argptr = argv
        rv = 0
        fmt_str = self.read_mem_string(_format, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(argptr, fmt_cnt)

        fin = self.do_str_format(fmt_str, vargs)
        fin = fin[:count] + "\x00"

        rv = len(fin)
        self.mem_write(buffer, fin.encode("utf-8"))
        argv[0] = fin.replace("\x00", "")
        argv[1] = fmt_str

        return rv

    @apihook("_strcmpi", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _strcmpi(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _strcmpi(
                const char *string1,
                const char *string2
                );
        """
        string1, string2 = argv
        rv = 1

        if not string1 or not string2:
            return rv

        cs1 = self.read_string(string1)
        cs2 = self.read_string(string2)

        argv[0] = cs1
        argv[1] = cs2

        if cs1.lower() == cs2.lower():
            rv = 0

        return rv

    @apihook("_wcsicmp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _wcsicmp(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _wcsicmp(
                const wchar_t *string1,
                const wchar_t *string2
                );
        """
        string1, string2 = argv
        rv = 1

        if not string1 or not string2:
            return rv

        cs1 = self.read_wide_string(string1)
        cs2 = self.read_wide_string(string2)

        argv[0] = cs1
        argv[1] = cs2

        if cs1.lower() == cs2.lower():
            rv = 0

        return rv

    @apihook("??3@YAXPAX@Z", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __3_YAXPAX_Z(self, emu, argv, ctx: api.ApiContext = None):
        (ptr,) = argv
        if ptr:
            self.mem_free(ptr)
        return

    @apihook("??2@YAPAXI@Z", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __2_YAPAXI_Z(self, emu, argv, ctx: api.ApiContext = None):
        (size,) = argv
        if size <= 0:
            size = self.get_ptr_size()
        return self.mem_alloc(size, tag="api.msvcrt.operator_new")

    @apihook("__current_exception_context", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __current_exception_context(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("__current_exception", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __current_exception(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_set_new_mode", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_new_mode(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_configthreadlocale", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _configthreadlocale(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_setusermatherr", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _setusermatherr(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("__setusermatherr", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __setusermatherr(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_cexit", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _cexit(self, emu, argv, ctx: api.ApiContext = None):
        # TODO: handle atexit flavor functions
        self.exit_process()

    @apihook("_c_exit", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _c_exit(self, emu, argv, ctx: api.ApiContext = None):
        self.exit_process()

    @apihook("_register_thread_local_exe_atexit_callback", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _register_thread_local_exe_atexit_callback(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_crt_atexit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _crt_atexit(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_controlfp_s", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _controlfp_s(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("terminate", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def terminate(self, emu, argv, ctx: api.ApiContext = None):
        self.exit_process()

    @apihook("_crt_atexit", argc=1, conv=e_arch.CALL_CONV_CDECL)  # type: ignore[no-redef]
    def _crt_atexit(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_initialize_narrow_environment", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _initialize_narrow_environment(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_configure_narrow_argv", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _configure_narrow_argv(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_set_fmode", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_fmode(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_itoa", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _itoa(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_itow", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _itow(self, emu, argv, ctx: api.ApiContext = None):
        return

    @apihook("_EH_prolog", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _EH_prolog(self, emu, argv, ctx: api.ApiContext = None):
        # push    -1
        emu.push_stack(0xFFFFFFFF)

        # push    eax
        emu.push_stack(emu.reg_read(e_arch.X86_REG_EAX))

        # mov     eax, DWORD PTR fs:[0]
        # push    eax
        emu.push_stack(emu.read_ptr(emu.fs_addr + 0))

        # mov     eax, DWORD PTR [esp+12]
        eax = emu.read_ptr(emu.reg_read(e_arch.X86_REG_ESP) + 12)

        # mov     DWORD PTR fs:[0], esp
        emu.write_ptr(emu.fs_addr + 0, emu.reg_read(e_arch.X86_REG_ESP))

        # mov     DWORD PTR [esp+12], ebp
        emu.write_ptr(emu.reg_read(e_arch.X86_REG_ESP) + 12, emu.reg_read(e_arch.X86_REG_EBP))

        # lea     ebp, DWORD PTR [esp+12]
        emu.reg_write(e_arch.X86_REG_EBP, emu.reg_read(e_arch.X86_REG_ESP) + 12)

        # push    eax
        # ret     0
        emu.push_stack(eax)
        return

    @apihook("wcstombs", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def wcstombs(self, emu, argv, ctx: api.ApiContext = None):
        """
        size_t wcstombs(
            char *mbstr,
            const wchar_t *wcstr,
            size_t count
        );
        """
        mbstr, wcstr, count = argv

        s = self.read_wide_string(wcstr, count)
        self.write_string(s, mbstr)
        return len(s.encode("ascii"))

    @apihook("_stricmp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _stricmp(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _stricmp(
                const char *string1,
                const char *string2
                );
        """
        string1, string2 = argv
        rv = 1

        if not string1 or not string2:
            return rv

        cs1 = self.read_string(string1)
        cs2 = self.read_string(string2)

        argv[0] = cs1
        argv[1] = cs2

        if cs1.lower() == cs2.lower():
            rv = 0

        return rv

    @apihook("_strnicmp", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _strnicmp(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _strnicmp(
            const char *string1,
            const char *string2,
            size_t count
        );
        """
        string1, string2, count = argv
        rv = 1

        if not string1 or not string2:
            return rv

        cs1 = self.read_string(string1)
        cs2 = self.read_string(string2)

        argv[0] = cs1
        argv[1] = cs2

        if cs1[:count].lower() == cs2[:count].lower():
            rv = 0

        return rv

    @apihook("_wcsicmp", argc=2, conv=e_arch.CALL_CONV_CDECL)  # type: ignore[no-redef]
    def _wcsicmp(self, emu, argv, ctx: api.ApiContext = None):
        """
        int wcsicmp(
            const wchar_t *string1,
            const wchar_t *string2
            );
        """
        string1, string2 = argv
        rv = 1

        ws1 = self.read_wide_string(string1)
        ws2 = self.read_wide_string(string2)

        argv[0] = ws1
        argv[1] = ws2

        if ws1.lower() == ws2.lower():
            rv = 0

        return rv

    @apihook("wcscmp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcscmp(self, emu, argv, ctx: api.ApiContext = None):
        """
        int wcscmp(
            const wchar_t *string1,
            const wchar_t *string2,
        );
        """
        s1, s2 = argv
        rv = 1

        string1 = self.read_wide_string(s1)
        string2 = self.read_wide_string(s2)
        if string1 == string2:
            rv = 0
        argv[0] = string1
        argv[1] = string2

        return rv

    @apihook("_snwprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def _snwprintf(self, emu, argv, ctx: api.ApiContext = None):
        """
        int _snwprintf(
            wchar_t *buffer,
            size_t count,
            const wchar_t *format [,
            argument] ...
            );
        """
        buf, cnt, fmt = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3)
        # the internal printf implementation requires uppercase S for wide string formatting,
        # otherwise the function replaces a latin1 string into an utf-16 string
        fmt_str = self.read_wide_string(fmt).replace(r"%s", r"%S")
        fmt_cnt = self.get_va_arg_count(fmt_str)

        if not fmt_cnt:
            self.write_wide_string(fmt_str, buf)
            return len(fmt_str)

        argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
        fin = self.do_str_format(fmt_str, argv)

        self.write_wide_string(fin, buf)

        argv = [buf, cnt, fmt] + argv
        argv[2] = fmt_str
        return len(fin)

    @apihook("_errno", argc=0)
    def _errno(self, emu, argv, ctx: api.ApiContext = None):
        """ """
        _VAL = 0x0C

        if not self.errno_t:
            self.errno_t = self.mem_alloc(4, tag="api.msvcrt._errno")
            self.mem_write(self.errno_t, _VAL.to_bytes(4, "little"))

        return self.errno_t

    @apihook("fopen", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def fopen(self, emu, argv, ctx: api.ApiContext = None):
        """
        FILE *fopen(
            const char *filename,
            const char *mode
            );
        """
        filename, mode = argv

        if not filename or not mode:
            return 0

        path = self.read_string(filename)
        mode_str = self.read_string(mode)

        argv[0] = path
        argv[1] = mode_str

        create = any(flag in mode_str for flag in ("w", "a", "+"))
        truncate = "w" in mode_str and "a" not in mode_str

        hfile = self.file_open(path, create=create, truncate=truncate)
        if hfile is None:
            return 0

        stream = self.mem_alloc(self.get_ptr_size(), tag="api.msvcrt.fopen")
        self.mem_write(stream, int(hfile).to_bytes(self.get_ptr_size(), "little"))
        self.file_streams[stream] = hfile
        return stream

    @apihook("_wfopen", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _wfopen(self, emu, argv, ctx: api.ApiContext = None):
        """
        FILE *_wfopen(
            const wchar_t *filename,
            const wchar_t *mode
            );
        """
        filename, mode = argv

        if not filename or not mode:
            return 0

        path = self.read_wide_string(filename)
        mode_str = self.read_wide_string(mode)

        argv[0] = path
        argv[1] = mode_str

        create = any(flag in mode_str for flag in ("w", "a", "+"))
        truncate = "w" in mode_str and "a" not in mode_str

        hfile = self.file_open(path, create=create, truncate=truncate)
        if hfile is None:
            return 0

        stream = self.mem_alloc(self.get_ptr_size(), tag="api.msvcrt._wfopen")
        self.mem_write(stream, int(hfile).to_bytes(self.get_ptr_size(), "little"))
        self.file_streams[stream] = hfile
        return stream

    @apihook("fclose", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def fclose(self, emu, argv, ctx: api.ApiContext = None):
        """
        int fclose(
            FILE *stream
            );
        """
        (stream,) = argv

        if not stream:
            return -1

        self.file_streams.pop(stream, None)
        self.mem_free(stream)
        return 0

    @apihook("fseek", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def fseek(self, emu, argv, ctx: api.ApiContext = None):
        """
        int fseek(
            FILE *stream,
            long offset,
            int origin
            );
        """
        stream, offset, origin = argv
        hfile = self.file_streams.get(stream)
        argv[0] = hfile or 0
        argv[1] = offset
        argv[2] = origin
        if hfile is None:
            return -1

        fobj = self.file_get(hfile)
        if not fobj:
            return -1

        fobj.seek(offset, origin)
        return 0

    @apihook("ftell", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def ftell(self, emu, argv, ctx: api.ApiContext = None):
        """
        long ftell(
            FILE *stream
            );
        """
        (stream,) = argv
        hfile = self.file_streams.get(stream)
        argv[0] = hfile or 0
        if hfile is None:
            return -1

        fobj = self.file_get(hfile)
        if not fobj:
            return -1

        pos = fobj.tell()
        if pos is None:
            return -1
        return pos

    @apihook("fread", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def fread(self, emu, argv, ctx: api.ApiContext = None):
        """
        size_t fread(
            void *ptr,
            size_t size,
            size_t count,
            FILE *stream
            );
        """
        ptr, size, count, stream = argv
        hfile = self.file_streams.get(stream)
        argv[3] = hfile or 0

        if not ptr or size == 0 or count == 0 or hfile is None:
            return 0

        fobj = self.file_get(hfile)
        if not fobj:
            return 0

        total = size * count
        data = fobj.get_data(size=total)
        if not data:
            return 0

        self.mem_write(ptr, data)
        return len(data) // size

    @apihook("fputc", argc=2)
    def fputc(self, emu, argv, ctx: api.ApiContext = None):
        """
        int fputc(
            int c,
            FILE *stream
        );
        """
        c, _ = argv
        return c

    @apihook("signal", argc=2)
    def signal(self, emu, argv, ctx: api.ApiContext = None):
        """
        void __cdecl *signal(
            int sig,
            int (*func)(int, int)
        );
        """
        sig, _ = argv

        if sig in [SIGINT, SIGILL, SIGFPE, SIGSEGV, SIGTERM, SIGBREAK, SIGABRT]:
            return SIG_IGN
        else:
            return SIG_ERR
