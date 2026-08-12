# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import bisect
import fnmatch
import logging
import re
import time
import traceback
from abc import ABC, abstractmethod
from typing import Any

import speakeasy.common as common
import speakeasy.version as version
import speakeasy.winenv.arch as e_arch
from speakeasy.config import SpeakeasyConfig
from speakeasy.engines import unicorn_eng
from speakeasy.errors import EmuException
from speakeasy.memmgr import MemoryManager
from speakeasy.profiler import Profiler
from speakeasy.report import ErrorInfo, Report

logger = logging.getLogger(__name__)

EMU_ENGINES = (("unicorn", unicorn_eng.EmuEngine),)

WILDCARD_FLAG = bool
API_LEVEL = tuple[dict[str, list[common.ApiHook]], WILDCARD_FLAG]
MODULE_LEVEL = tuple[dict[str, API_LEVEL], WILDCARD_FLAG]


# Generic emulator class for binary code
class BinaryEmulator(MemoryManager, ABC):
    """
    Base class for emulating binaries

    Subclasses must define the following attributes:
        arch: Architecture constant (e.g., ARCH_X86, ARCH_AMD64)
        modules: List of loaded modules
        input: Input metadata dictionary (or None)
    """

    arch: int
    modules: list[Any]
    input: dict[str, Any] | None

    @abstractmethod
    def _set_emu_hooks(self) -> None:
        """Set up emulator hooks. Subclasses must implement."""
        ...

    @abstractmethod
    def on_emu_complete(self) -> None:
        """Called when emulation completes. Subclasses must implement."""
        ...

    @abstractmethod
    def get_current_run(self) -> Any:
        """Get the current run context. Subclasses must implement."""
        ...

    def __init__(self, config):

        super().__init__()

        self.stack_base: int = 0
        self.page_size: int | None = None
        self.inst_count: int = 0
        self.curr_instr_size: int = 0
        self.disasm_eng: Any = None
        self.builtin_hooks_set: bool = False
        self.emu_eng: unicorn_eng.EmuEngine | None = None
        self.maps: list[Any] = []
        self.config = config
        self.hooks: dict[int, Any] = {}

        # V2-1-2: 模块按 base 排序的平行结构，支持 get_module_from_addr bisect O(log n) 查找。
        # 与 self.modules 同步：发现长度不一致时触发懒重建（add_module/load_module 走子类路径，无法在基类 hook）。
        self._sorted_mod_bases: list[int] = []
        self._sorted_mods: list[Any] = []
        # 单槽 LRU 缓存：指令级 tracing hook 重复查找同一地址时直接命中，避免 bisect 调用开销
        self._mod_addr_lru: tuple[int, Any] | None = None

        self.profiler: Profiler = Profiler()
        self.profiler.attach_emulator(self)

        self.runtime: float = 0

        self.emu_version = self.get_emu_version()

    def get_profiler(self) -> Profiler:
        """
        Get the current event profiler object (if any)
        """
        return self.profiler

    def get_report(self) -> Report | None:
        """
        Get the emulation report for all runs that were executed
        """
        if self.profiler:
            return self.profiler.get_report()
        return None

    def get_json_report(self) -> str | None:
        """
        Get the emulation report for all runs that were executed formatted as a JSON string
        """
        if self.profiler:
            return self.profiler.get_json_report()
        return None

    def get_pseudocode_text(self) -> str:
        if self.profiler:
            return self.profiler.get_pseudocode_text()
        return ""

    def get_pseudocode_visual(self, format_name: str = "svg") -> str:
        if self.profiler:
            return self.profiler.get_pseudocode_visual(format_name=format_name)
        return ""

    def enable_pseudocode(
        self,
        enabled: bool = True,
        include_comments: bool = True,
        string_encoding: str = "utf8",
        keep_filtered_jumps: bool = False,
        show_register_values: bool = False,
        enable_heuristics: bool = False,
    ) -> None:
        if self.profiler:
            self.profiler.enable_pseudocode(
                enabled,
                include_comments=include_comments,
                string_encoding=string_encoding,
                keep_filtered_jumps=keep_filtered_jumps,
                show_register_values=show_register_values,
                enable_heuristics=enable_heuristics,
            )

    def _parse_config(self, config: SpeakeasyConfig):
        """
        Parse the config to be used for emulation
        """
        self.config = config

        _eng = config.emu_engine
        for name, eng in EMU_ENGINES:
            if name.lower() == _eng.lower():
                self.emu_eng = eng()
        if not self.emu_eng:
            raise EmuException(f"Unsupported emulation engine: {_eng}")

        self.env = dict(config.env)

    def get_emu_version(self):
        """
        Get the version of the emulator
        """
        return version.__version__

    def get_osver_string(self):
        """
        Get the human readable OS version string
        """
        osver = self.config.os_ver
        if osver:
            os_name = osver.name or ""
            major = osver.major
            minor = osver.minor
            if major is not None and minor is not None:
                verstr = f"{os_name}.{major}_{minor}"
                return verstr
        return None

    def sizeof(self, obj):
        """
        Get the size (in the emulation space) of the supplied object
        """
        return obj.sizeof()

    def get_bytes(self, obj):
        """
        Get the bytes represented in the emulation space of the supplied object
        """
        return obj.get_bytes()

    def stop(self):
        """
        Stop emulation completely
        """
        assert self.emu_eng is not None
        self.emu_eng.stop()
        if self.profiler:
            self.profiler.stop_run_clock()

    def start(self, addr, size):
        """
        Begin emulation.

        V2-1-1: 把 winemu.start() 的 global_deadline + run_timeout wall-clock 超时模式
        上提到基类作为默认实现。Unicorn 的 emu_start(timeout=...) 在某些平台不可靠，
        改用 time.monotonic() 计算剩余预算作为 Python 级 deadline 兜底，跨平台防挂起。
        保留 GDB 旁路：子类设置 gdb_port 时 timeout 设为 0，让调试器自由暂停。
        """
        assert self.emu_eng is not None
        self.set_hooks()
        self._set_emu_hooks()
        if self.profiler:
            self.profiler.set_start_time()

        # GDB 旁路：子类若设置 gdb_port，则禁用 timeout 让调试器自由暂停
        gdb_port = getattr(self, 'gdb_port', None)
        configured_timeout = 0 if gdb_port is not None else self.config.timeout

        # 计算 wall-clock 预算：configured_timeout > 0 时为剩余毫秒，否则 0 表示不限
        if configured_timeout > 0:
            global_deadline = time.monotonic() + configured_timeout
            remaining = global_deadline - time.monotonic()
            if remaining <= 0:
                logger.error("* Timeout of %d sec(s) reached before start.", configured_timeout)
                self.on_emu_complete()
                return
            # max(0.1, remaining) 与 winemu.start() 一致，避免 0 触发 Unicorn 立即返回
            run_timeout = max(0.1, remaining)
        else:
            run_timeout = configured_timeout

        try:
            self.emu_eng.start(addr, timeout=run_timeout, count=self.config.max_instructions)
            if self.profiler and run_timeout > 0:
                if self.profiler.get_run_time() > run_timeout:
                    logger.error("* Timeout of %d sec(s) reached.", run_timeout)
        except Exception:
            if self.profiler:
                self.profiler.record_error_event(ErrorInfo(type="internal_error", traceback=traceback.format_exc()))
            self.on_emu_complete()

    def reg_write(self, reg, val):
        """
        Write a value to an emulated cpu register
        """
        assert self.emu_eng is not None
        if isinstance(reg, str):
            _reg = e_arch.REG_LOOKUP.get(reg.lower())
            if not _reg:
                raise EmuException(f"Invalid register access {reg}")
            reg = _reg

        self.emu_eng.reg_write(reg, val)

    def reg_read(self, reg):
        """
        Read a value from an emulated cpu register
        """
        assert self.emu_eng is not None
        if isinstance(reg, str):
            _reg = e_arch.REG_LOOKUP.get(reg.lower())
            if not _reg:
                raise EmuException(f"Invalid register access {reg}")
            reg = _reg

        return self.emu_eng.reg_read(reg)

    def set_hooks(self):
        """
        Set instruction level hooks
        """
        for ht in (
            common.HOOK_CODE,
            common.HOOK_MEM_READ,
            common.HOOK_MEM_WRITE,
            common.HOOK_MEM_INVALID,
            common.HOOK_INTERRUPT,
        ):
            for hook in self.hooks.get(ht, []):
                if not hook.added:
                    hook.add()

    def _cs_disasm(self, mem, addr, fast=True):
        """
        Disassemble bytes using capstone
        """
        assert self.disasm_eng is not None
        try:
            if fast:
                tu = [i for i in self.disasm_eng.disasm_lite(bytes(mem), addr)]
                address, size, mnem, oper = tu[0]
            else:
                return [i for i in self.disasm_eng.disasm(bytes(mem), addr)]
        except IndexError:
            raise EmuException(f"Failed to disasm at address: 0x{addr:x}")

        op = f"{mnem} {oper}"
        return (mnem, oper, op)

    def disasm(self, mem, addr, fast=True):
        """
        Disassemble bytes at a specified address
        """
        return self._cs_disasm(mem, addr, fast=fast)

    def get_register_state(self):
        """
        Get the current state of registers from the emulator
        """
        regs = {}
        if e_arch.ARCH_X86 == self.get_arch():
            for name, reg in (
                ("esp", e_arch.X86_REG_ESP),
                ("ebp", e_arch.X86_REG_EBP),
                ("eip", e_arch.X86_REG_EIP),
                ("esi", e_arch.X86_REG_ESI),
                ("edi", e_arch.X86_REG_EDI),
                ("eax", e_arch.X86_REG_EAX),
                ("ebx", e_arch.X86_REG_EBX),
                ("ecx", e_arch.X86_REG_ECX),
                ("edx", e_arch.X86_REG_EDX),
            ):
                val = self.reg_read(reg)
                regs[name] = "{0:#0{1}x}".format(val, 2 + (self.get_ptr_size() * 2))
        elif e_arch.ARCH_AMD64 == self.get_arch():
            for name, reg in (
                ("rsp", e_arch.AMD64_REG_RSP),
                ("rbp", e_arch.AMD64_REG_RBP),
                ("rip", e_arch.AMD64_REG_RIP),
                ("rsi", e_arch.AMD64_REG_RSI),
                ("rdi", e_arch.AMD64_REG_RDI),
                ("rax", e_arch.AMD64_REG_RAX),
                ("rbx", e_arch.AMD64_REG_RBX),
                ("rcx", e_arch.AMD64_REG_RCX),
                ("rdx", e_arch.AMD64_REG_RDX),
                ("r8", e_arch.AMD64_REG_R8),
                ("r9", e_arch.AMD64_REG_R9),
                ("r10", e_arch.AMD64_REG_R10),
                ("r11", e_arch.AMD64_REG_R11),
                ("r12", e_arch.AMD64_REG_R12),
                ("r13", e_arch.AMD64_REG_R13),
                ("r14", e_arch.AMD64_REG_R14),
                ("r15", e_arch.AMD64_REG_R15),
            ):
                val = self.reg_read(reg)
                regs[name] = "{0:#0{1}x}".format(val, 2 + (self.get_ptr_size() * 2))
        return regs

    def get_disasm(self, addr, size, fast=True):
        """
        Get the disassembly from an address
        """
        return self.disasm(self.mem_read(addr, size), addr, fast)

    def set_func_args(self, stack_addr, ret_addr, *args, home_space=True):
        """
        Set the arguments before an emulated function call. This is how we pass
        arguments to a function when calling it through the emulator.
        """
        curr_sp = stack_addr - self.ptr_size
        nargs = len(args)

        if self.get_arch() == e_arch.ARCH_X86:
            sp = e_arch.X86_REG_ESP
        elif self.get_arch() == e_arch.ARCH_AMD64:
            sp = e_arch.AMD64_REG_RSP
            i = 0
            for i, r in enumerate(
                (e_arch.AMD64_REG_RCX, e_arch.AMD64_REG_RDX, e_arch.AMD64_REG_R8, e_arch.AMD64_REG_R9)
            ):
                if nargs == 0:
                    break
                self.reg_write(r, args[i])
                nargs -= 1
            # Set the stack home space
            if home_space:
                curr_sp -= 0x20
            self.reg_write(sp, curr_sp)
        else:
            raise EmuException("Unsupported architecture")

        if nargs > 0:
            for arg in args[-nargs:][::-1]:
                a = arg.to_bytes(self.ptr_size, byteorder="little")

                self.mem_write(curr_sp, a)
                self.reg_write(sp, curr_sp)
                curr_sp -= self.ptr_size

        # Set the return address
        r = ret_addr.to_bytes(self.ptr_size, byteorder="little")
        self.mem_write(curr_sp, r)
        self.reg_write(sp, curr_sp)

    def get_func_argv(self, callconv, argc, offset=0):
        """
        Get the arguments for a function given the supplied calling convention

        V1-S-10: The `offset` parameter skips the first `offset` positional args
        (whether they reside in registers or on the stack) so variadic callees
        such as DbgPrint / sprintf that already consumed the leading fixed args
        via a prior get_func_argv call can fetch only the trailing variadic tail
        without re-scanning the entire argv list.
        """
        argv = []
        ptr_size = self.get_ptr_size()
        arch = self.get_arch()
        nargs = argc - offset
        endian = "little"
        reg_skip = offset  # registers (or leading stack slots) to skip before appending

        # Handle calling conventions using floats
        if arch in (e_arch.ARCH_X86, e_arch.ARCH_AMD64):
            if callconv == e_arch.CALL_CONV_FLOAT:
                for i, r in enumerate(
                    (e_arch.X86_REG_XMM0, e_arch.X86_REG_XMM1, e_arch.X86_REG_XMM2, e_arch.X86_REG_XMM3)
                ):
                    if nargs == 0:
                        break
                    if reg_skip > 0:
                        reg_skip -= 1
                        continue
                    val = self.reg_read(r)
                    argv.append(val)
                    nargs -= 1

        if arch == e_arch.ARCH_X86:
            sp = self.reg_read(e_arch.X86_REG_ESP)
            if callconv == e_arch.CALL_CONV_FASTCALL:
                # x86 FASTCALL: first 2 args in ECX/EDX, rest on stack.
                # Loop form (V1-S-10) preserves original semantics:
                #   nargs>=2 -> read both, nargs==1 -> read ECX only.
                for r in (e_arch.X86_REG_ECX, e_arch.X86_REG_EDX):
                    if nargs == 0:
                        break
                    if reg_skip > 0:
                        reg_skip -= 1
                        continue
                    argv.append(self.reg_read(r))
                    nargs -= 1
        elif arch == e_arch.ARCH_AMD64:
            sp = self.reg_read(e_arch.AMD64_REG_RSP)
            sp += 0x20

            for i, r in enumerate(
                (e_arch.AMD64_REG_RCX, e_arch.AMD64_REG_RDX, e_arch.AMD64_REG_R8, e_arch.AMD64_REG_R9)
            ):
                if nargs == 0:
                    break
                if reg_skip > 0:
                    reg_skip -= 1
                    continue
                val = self.reg_read(r)
                argv.append(val)
                nargs -= 1
        else:
            raise EmuException("Unsupported architecture")

        # Skip past the saved ret addr
        sp += ptr_size
        # V1-S-10: skip stack slots for any offset args not consumed by register reads
        if reg_skip > 0:
            sp += reg_skip * ptr_size
        for i in range(nargs):
            ptr = self.mem_read(sp, ptr_size)
            argv.append(int.from_bytes(ptr, endian))  # type: ignore[arg-type]  # endian is always "little"
            sp += ptr_size

        return argv

    def do_call_return(self, argc, ret_addr=None, ret_value=None, conv=None):
        """
        Set the emulation state after a call has completed
        """
        if self.get_arch() == e_arch.ARCH_X86:
            sp = e_arch.X86_REG_ESP
            pc = e_arch.X86_REG_EIP
            rr = e_arch.X86_REG_EAX
        elif self.get_arch() == e_arch.ARCH_AMD64:
            sp = e_arch.AMD64_REG_RSP
            pc = e_arch.AMD64_REG_RIP
            rr = e_arch.AMD64_REG_RAX
        else:
            raise EmuException("Unsupported architecture")

        if conv == e_arch.CALL_CONV_FLOAT:
            rr = e_arch.X86_REG_XMM0

        stk_ptr = self.reg_read(sp)

        if ret_addr:
            self.reg_write(sp, stk_ptr + self.ptr_size)
            self.reg_write(pc, ret_addr)
        if ret_value is not None:
            self.reg_write(rr, ret_value)

        # Cleanup the stack
        if conv == e_arch.CALL_CONV_CDECL:
            # If cdecl, the emu engine will clean the stack
            pass
        elif conv == e_arch.CALL_CONV_FASTCALL:
            if self.get_arch() == e_arch.ARCH_X86:
                if argc > 2:
                    self.clean_stack_args(argc - 2)
        else:
            self.clean_stack_args(argc)

    def get_ret_address(self):
        """
        Get the return address from the stack
        """

        endian = "little"

        sp = self.get_stack_ptr()
        ret = self.mem_read(sp, self.ptr_size)
        ret = int.from_bytes(ret, endian)  # type: ignore[arg-type]  # endian is always "little"
        return ret

    def set_ret_address(self, addr):
        """
        Set the return address on the stack
        """

        sp = self.get_stack_ptr()
        self.mem_write(sp, addr.to_bytes(self.get_ptr_size(), "little"))

    def push_stack(self, val):
        """
        Put a value on the stack and adjust the stack pointer
        """
        endian = "little"
        sp = self.get_stack_ptr()
        bval = val.to_bytes(self.ptr_size, endian)
        sp -= self.ptr_size
        self.mem_write(sp, bval)
        self.set_stack_ptr(sp)
        return val

    def pop_stack(self):
        """
        Get value from the stack and adjust the stack pointer
        """
        endian = "little"
        sp = self.get_stack_ptr()
        val = self.mem_read(sp, self.ptr_size)
        val = int.from_bytes(val, endian)  # type: ignore[arg-type]  # endian is always "little"
        sp += self.ptr_size
        self.set_stack_ptr(sp)
        return val

    def get_stack_ptr(self):
        """
        Get the current address of the stack pointer
        """
        if self.get_arch() == e_arch.ARCH_X86:
            sp = self.reg_read(e_arch.X86_REG_ESP)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            sp = self.reg_read(e_arch.AMD64_REG_RSP)
        return sp

    def set_stack_ptr(self, addr):
        """
        Set the current address of the stack pointer
        """
        if self.get_arch() == e_arch.ARCH_X86:
            self.reg_write(e_arch.X86_REG_ESP, addr)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            self.reg_write(e_arch.AMD64_REG_RSP, addr)

    def format_stack(self, num_ptrs):
        """
        Get the stack and format it for display
        """
        out: list[tuple] = []
        sp = self.get_stack_ptr()
        for i in range(num_ptrs):
            try:
                ptr = self.mem_read(sp, self.get_ptr_size())
            except Exception:
                return out
            ptr = int.from_bytes(ptr, "little")
            tag = self.get_address_tag(ptr)
            out.append((sp, ptr, tag))
            sp += self.get_ptr_size()
        return out

    def print_stack(self, num_ptrs):
        """
        This a debug function used to print the current stack state
        """
        ptrs = self.format_stack(num_ptrs)
        print("Stack:")
        print("***********************")
        for p in ptrs:
            sp, ptr, tag = p
            if tag:
                fmt = f"sp=0x{sp:x}:\t0x{ptr:x}\t->\t{tag}"
            else:
                fmt = f"sp=0x{sp:x}:\t0x{ptr:x}\t"

            print(fmt.expandtabs(5))
            sp += self.get_ptr_size()

    def get_stack_trace(self, num_ptrs=16):
        """
        Get the current stack state
        """
        trace = []
        sp = self.get_stack_ptr()
        for i in range(num_ptrs):
            try:
                ptr = self.mem_read(sp, self.get_ptr_size())
            except Exception:
                sp_off = "{0:#0{1}x}".format(i * self.get_ptr_size(), 2 * 2)
                trace.append(f"sp+{sp_off}: <unmapped @ 0x{sp:x}>")
                break
            ptr = int.from_bytes(ptr, "little")
            tag = self.get_address_tag(ptr)
            fmt = "{0:#0{1}x}".format(ptr, 2 + (self.get_ptr_size() * 2))
            sp_off = "{0:#0{1}x}".format(i * self.get_ptr_size(), 2 * 2)
            if not tag:
                entry = f"sp+{sp_off}: {fmt}"
            else:
                entry = f"sp+{sp_off}: {fmt} -> {tag}"
            trace.append(entry)
            sp += self.get_ptr_size()
        return trace

    def get_pc(self):
        """
        Get the value of the current program counter
        """
        if self.get_arch() == e_arch.ARCH_X86:
            pc = self.reg_read(e_arch.X86_REG_EIP)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            pc = self.reg_read(e_arch.AMD64_REG_RIP)
        else:
            raise EmuException("Unsupported architecture")
        return pc

    def set_pc(self, addr):
        """
        Set the value of the current program counter
        """
        if self.get_arch() == e_arch.ARCH_X86:
            self.reg_write(e_arch.X86_REG_EIP, addr)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            self.reg_write(e_arch.AMD64_REG_RIP, addr)
        else:
            raise EmuException("Unsupported architecture")

    def get_return_val(self):
        """
        Get the current value in the return register
        """
        if self.get_arch() == e_arch.ARCH_X86:
            val = self.reg_read(e_arch.X86_REG_EAX)
        elif self.get_arch() == e_arch.ARCH_AMD64:
            val = self.reg_read(e_arch.AMD64_REG_RAX)
        else:
            raise EmuException("Unsupported architecture")
        return val

    def reset_stack(self, base):
        """
        Reset stack to the supplied base address
        """
        arch = self.get_arch()
        ptr = base

        if arch == e_arch.ARCH_X86:
            self.reg_write(e_arch.X86_REG_ESP, base)
            self.reg_write(e_arch.X86_REG_EBP, base)
        elif arch == e_arch.ARCH_AMD64:
            # Save room for the "home space"
            ptr -= self.ptr_size * 5
            self.reg_write(e_arch.AMD64_REG_RSP, ptr)
            self.reg_write(e_arch.AMD64_REG_RBP, ptr)

        return base, ptr

    def alloc_stack(self, size):
        """
        Allocate memory to use for the program stack
        """
        # Allocate memory for our stack
        # Stack grows down
        chunk = self.get_valid_ranges(size, addr=0x1200000)
        addr, block_size = chunk
        self.mem_map(block_size, base=addr, tag="emu.stack")

        base = addr + block_size
        self.mem_reserve(size, base=base)

        base, ptr = self.reset_stack(base)

        return base, ptr

    def clean_stack_args(self, argc):
        """
        Adjust the stack for arguments that were supplied
        """
        ptr_size = self.get_ptr_size()
        arch = self.get_arch()

        if argc == 0:
            return

        if arch == e_arch.ARCH_X86:
            sp = self.reg_read(e_arch.X86_REG_ESP)
            sp += ptr_size * argc
            self.reg_write(e_arch.X86_REG_ESP, sp)

        elif arch == e_arch.ARCH_AMD64:
            return
        else:
            raise EmuException("Unsupported architecture")

    def get_arch(self):
        """
        Get the current emulated architecture
        """
        return self.arch

    def get_arch_name(self):
        """
        Get the name of current emulated architecture
        """
        if self.arch == e_arch.ARCH_AMD64:
            return "amd64"
        elif self.arch == e_arch.ARCH_X86:
            return "x86"
        return ""

    def eval_emu_var(self):
        """
        Used to expand variables supplied in the emulator config file. This
        might be useful for accessing files that are a relative path of the
        speakeasy package.
        For example:
            $ROOT$: This variable corresponds to the package root for speakeasy
        """

    def read_mem_string(self, address, width=1, max_chars=0):
        """
        Read a string from emulated memory
        """
        if width == 1:
            decode = "utf-8"
        elif width == 2:
            decode = "utf-16le"
        else:
            raise ValueError("Invalid string encoding")

        # 分块读取以避免逐字符调用 mem_read 造成的 O(n^2) 拼接开销
        terminator = b"\x00" * width
        chunk_size = 256
        buf = bytearray()  # extend 为 O(1) 均摊
        offset = 0
        done = False

        while not done:
            # 受 max_chars 限制时，本次最多可读取的字节数
            if max_chars:
                chars_remaining = max_chars - (len(buf) // width)
                if chars_remaining <= 0:
                    break
                read_size = min(chunk_size, chars_remaining * width)
            else:
                read_size = chunk_size

            # 一次读取整块内存
            chunk = self.mem_read(address + offset, read_size)
            if not chunk:
                break

            # 在块内查找终止符，需保证位于 width 边界上
            null_pos = -1
            search_start = 0
            while search_start < len(chunk):
                pos = chunk.find(terminator, search_start)
                if pos == -1:
                    break
                if pos % width == 0:
                    null_pos = pos
                    break
                search_start = pos + 1

            if null_pos != -1:
                buf.extend(chunk[:null_pos])
                done = True
            else:
                buf.extend(chunk)
                offset += len(chunk)
                # 读取不足一块说明已到达可读内存末尾
                if len(chunk) < read_size:
                    done = True

        try:
            dec = buf.decode(decode, "ignore").replace("\x00", "")
        except Exception:
            dec = bytes(buf).replace(b"\x00", b"")  # type: ignore[assignment]  # fallback returns bytes if decode fails
        return dec

    def mem_string_len(self, address, width=1):
        """
        Get the length of a string from emulated memory
        """
        # 分块读取以避免逐字符调用 mem_read
        terminator = b"\x00" * width
        chunk_size = 256
        slen = 0
        offset = 0

        while True:
            chunk = self.mem_read(address + offset, chunk_size)
            if not chunk:
                break

            # 在块内查找终止符，需保证位于 width 边界上
            null_pos = -1
            search_start = 0
            while search_start < len(chunk):
                pos = chunk.find(terminator, search_start)
                if pos == -1:
                    break
                if pos % width == 0:
                    null_pos = pos
                    break
                search_start = pos + 1

            if null_pos != -1:
                slen += null_pos // width
                break

            slen += len(chunk) // width
            offset += len(chunk)
            if len(chunk) < chunk_size:
                break

        return slen

    def get_ansi_strings(self, data, min_len=4):
        """
        Get all ansi strings from a supplied memory blob
        """
        astrs = []
        pat = b"[\x20-\x7f]{%d,}" % (min_len)
        res = re.compile(pat)
        hits = res.findall(data)
        offset = 0
        for s in hits:
            try:
                offset = data.find(s, offset)
                s = s.decode("utf-8")
                astrs.append((offset, s))
                offset += 1
            except UnicodeDecodeError:
                continue
        return astrs

    def get_unicode_strings(self, data, min_len=4):
        """
        Get all unicode strings from a supplied memory blob
        """
        wstrs = []
        pat = b"(?:[\x20-\x7f]\x00){%d,}" % (min_len)
        res = re.compile(pat)
        hits = res.findall(data)
        offset = 0
        for ws in hits:
            try:
                offset = data.find(ws, offset)
                ws = ws.decode("utf-16le")
                wstrs.append((offset, ws))
                offset += 1
            except UnicodeDecodeError:
                continue
        return wstrs

    def mem_copy(self, dst, src, n):
        """
        Copy bytes from one emulated address to another
        """
        sbytes = self.mem_read(src, n)
        self.mem_write(dst, sbytes)
        return n

    def write_mem_string(self, string, address, width=1):
        """
        Write string data to an emulated memory address. Appends terminating zero byte if not present.
        """

        if width == 1:
            encode = "utf-8"
        elif width == 2:
            encode = "utf-16le"
        else:
            raise ValueError("Invalid string encoding")

        if not string.endswith("\0"):
            string += "\0"

        enc_str = string.encode(encode)
        self.mem_write(address, enc_str)

    def read_ptr(self, address):
        val = self.mem_read(address, self.ptr_size)
        return int.from_bytes(val, "little")

    def write_ptr(self, address, val):
        self.mem_write(address, val.to_bytes(self.ptr_size, "little"))

    def get_ptr_size(self):
        """
        Get the pointer size of the current emulation state
        """
        return self.ptr_size

    def get_mem_strings(self):
        """
        Get ansi and unicode strings from emulated memory
        """
        tgt_tag_prefixes = ("emu.stack", "api")
        ansi_strings = []
        unicode_strings = []
        ret_ansi = []
        ret_unicode = []
        input_mem_tag = self.input.get("mem_tag") if self.input else None

        for mmap in self.get_mem_maps():
            tag = mmap.tag
            if tag and tag.startswith(tgt_tag_prefixes) and tag != input_mem_tag:
                data = self.mem_read(mmap.base, mmap.size - 1)
                ansi_strings += self.get_ansi_strings(data)
                unicode_strings += self.get_unicode_strings(data)

        [ret_ansi.append(a) for a in ansi_strings if a not in ret_ansi]  # type: ignore[func-returns-value]  # list comp for side effect
        [ret_unicode.append(a) for a in unicode_strings if a not in ret_unicode]  # type: ignore[func-returns-value]  # list comp for side effect

        return (ret_ansi, ret_unicode)

    def set_ptr_size(self, arch):
        """
        Set the current pointer size used in the emulator
        """
        if arch == e_arch.ARCH_AMD64:
            self.ptr_size = 8
        elif arch == e_arch.ARCH_X86:
            self.ptr_size = 4
        else:
            raise EmuException("Unsupported architecture")

    def _rebuild_sorted_mods(self):
        """
        V2-1-2: 重建模块按 base 升序的平行结构，保持与 self.modules 同步。
        子类的 add_module/load_module 走各自路径直接 append 到 self.modules，
        基类无法 hook，故采用与 winemu._rebuild_module_index 一致的懒重建策略：
        发现 _sorted_mods 长度与 self.modules 不一致时调用。
        """
        s_mods = sorted(self.modules, key=lambda m: m.base)
        self._sorted_mods = s_mods
        self._sorted_mod_bases = [m.base for m in s_mods]
        self._mod_addr_lru = None

    def get_module_from_addr(self, addr):
        """
        If the supplied address belongs to a module, return it.

        V2-1-2: 用 bisect.bisect_right 做 O(log n) 区间查找，替代原 O(n) 线性扫描。
        叠加单槽 LRU 缓存以缓解指令级 tracing hook 的重复查找。
        参考 memmgr._sorted_bases (P0-4) 与 winemu._mod_intervals (P0-5) 的 bisect 模式。
        """
        # 单槽 LRU：相同地址连续查询时直接命中（tracing hook 经常连续查同一 PC）
        lru = self._mod_addr_lru
        if lru is not None and lru[0] == addr:
            return lru[1]

        # 区间表若与 self.modules 不同步则重建，保证一致性
        if len(self._sorted_mods) != len(self.modules):
            self._rebuild_sorted_mods()

        bases = self._sorted_mod_bases
        if not bases:
            return None

        # bisect_right 找到 base <= addr 的最后一个候选区间，O(log n)
        idx = bisect.bisect_right(bases, addr) - 1
        if idx < 0:
            return None
        mod = self._sorted_mods[idx]
        base = mod.base
        end = base + mod.image_size
        # 保留原实现的上界包含语义（addr <= base + size）以兼容现有调用方
        if addr >= base and addr <= end:
            self._mod_addr_lru = (addr, mod)
            return mod
        return None

    def get_api_hooks(self, mod_name, func_name) -> list[common.ApiHook]:
        """
        If an API hook has been set, return it here
        """

        mod_name = mod_name.lower()
        func_name = func_name.lower()
        try:
            hook_struct, wildcard_module = self.hooks[common.HOOK_API]
        except KeyError:
            return []
        try:
            modules = [hook_struct[mod_name]]
        except KeyError:
            modules = []
        if wildcard_module:
            for module_name_saved, value in hook_struct.items():
                if fnmatch.fnmatch(mod_name, module_name_saved) and mod_name != module_name_saved:
                    modules.append(value)
        user_hooks = []
        for module in modules:
            hooks, wildcard_api = module
            try:
                user_hooks.extend(hooks[func_name])
            except KeyError:
                pass
            if wildcard_api:
                for func_name_saved, list_of_hooks in hooks.items():
                    if fnmatch.fnmatch(func_name, func_name_saved) and func_name != func_name_saved:
                        user_hooks.extend(list_of_hooks)
        return user_hooks

    def add_api_hook(self, cb, module="", api_name="", argc=0, call_conv=None, emu=None) -> common.ApiHook:
        """
        Add an API level hook (e.g. kernel32.CreateFile) here.

        When multiple hooks are registered for the same API, they execute in
        FIFO order (first registered, first called). All hooks in the chain are
        called, and the return value of the last hook is used. This ordering
        convention applies to all hook types in speakeasy.
        """
        module = module.lower()
        api_name = api_name.lower()

        wildcard_module, wildcard_api = False, False
        for wc in ["?", "*", "[", "]"]:
            if wc in module:
                wildcard_module = True
            if wc in api_name:
                wildcard_api = True

        if not emu:
            emu = self
        hook = common.ApiHook(emu, self.emu_eng, cb, module, api_name, argc, call_conv)
        _hooks: MODULE_LEVEL | None = self.hooks.get(common.HOOK_API)

        api_dictionary = ({api_name: [hook]}, wildcard_api)
        if not _hooks:
            # First addition
            obj = ({module: api_dictionary}, wildcard_module)
        else:
            module_dict, previous_wildcard_module = _hooks
            try:
                api_dict, previous_wildcard_api = module_dict[module]
            except KeyError:
                # The module asked is not present, so we just add the api dictionary
                module_dict[module] = api_dictionary
            else:
                # The module asked is present, so we can just add the hook
                api_dict.setdefault(api_name, []).append(hook)
                module_dict[module] = (api_dict, previous_wildcard_api | wildcard_api)
            obj = (module_dict, previous_wildcard_module | wildcard_module)
        self.hooks.update({common.HOOK_API: obj})
        return hook

    def add_code_hook(self, cb, begin=1, end=0, emu=None):
        """
        Add a hook that will fire for every CPU instruction
        """
        hl = self.hooks.get(common.HOOK_CODE, [])
        if not emu:
            emu = self
        hook = common.CodeHook(self, self.emu_eng, cb, begin, end)
        if not hl:
            self.hooks.update(
                {
                    common.HOOK_CODE: [
                        hook,
                    ]
                }
            )
        else:
            hl.append(hook)

        if self.emu_eng:
            hook.add()

        return hook

    def _fire_dyn_code_hooks(self, addr):
        profiler = self.get_profiler()
        mm = self.get_address_map(addr)
        if profiler:
            run = self.get_current_run()
            profiler.record_dyn_code_event(run, mm.tag, mm.base, mm.size)

        for h in self.hooks.get(common.HOOK_DYN_CODE, []):
            h.cb(mm)

    def _set_dyn_code_hook(self, addr, size):
        """
        Set the top level dispatch hook for dynamic code execution
        """
        max_hook_size = 0x10
        if size > max_hook_size:
            size = max_hook_size

        hook_ref = [None]

        def _dynamic_code_cb(emu, addr, size):
            self._fire_dyn_code_hooks(addr)
            if hook_ref[0]:
                hook_ref[0].disable()

        hook_ref[0] = self.add_code_hook(cb=_dynamic_code_cb, begin=addr, end=addr + size)

    def add_dyn_code_hook(self, cb, emu=None):
        """
        Add a hook that will fire when dynamically generated/copied code is executed
        """
        if not emu:
            emu = self
        hl = self.hooks.get(common.HOOK_DYN_CODE, [])

        hook = common.DynCodeHook(emu, self.emu_eng, cb)
        if not hl:
            self.hooks.update(
                {
                    common.HOOK_DYN_CODE: [
                        hook,
                    ]
                }
            )
        else:
            hl.append(hook)

        return hook

    def add_mem_read_hook(self, cb, begin=1, end=0, emu=None):
        """
        Add a hook that will fire for memory reads
        """
        if not emu:
            emu = self
        hook = common.ReadMemHook(emu, self.emu_eng, cb, begin, end)
        hl = self.hooks.get(common.HOOK_MEM_READ)
        if not hl:
            self.hooks.update(
                {
                    common.HOOK_MEM_READ: [
                        hook,
                    ]
                }
            )
        else:
            hl.append(hook)

        if self.emu_eng:
            hook.add()

        return hook

    def add_mem_write_hook(self, cb, begin=1, end=0, emu=None):
        """
        Add a hook that will fire for memory writes
        """
        if not emu:
            emu = self
        hook = common.WriteMemHook(emu, self.emu_eng, cb, begin, end)
        hl = self.hooks.get(common.HOOK_MEM_WRITE)
        if not hl:
            self.hooks.update(
                {
                    common.HOOK_MEM_WRITE: [
                        hook,
                    ]
                }
            )
        else:
            hl.append(hook)

        if self.emu_eng:
            hook.add()

        return hook

    def add_mem_map_hook(self, cb, begin=1, end=0, emu=None):
        """
        Add a hook that will fire for memory maps
        """
        if not emu:
            emu = self
        hook = common.MapMemHook(emu, self.emu_eng, cb, begin, end)
        hl = self.hooks.get(common.HOOK_MEM_MAP)
        if not hl:
            self.hooks.update(
                {
                    common.HOOK_MEM_MAP: [
                        hook,
                    ]
                }
            )
        else:
            hl.append(hook)

        if self.emu_eng:
            hook.add()

        return hook

    def _hook_mem_invalid_dispatch(self, emu, access, address, size, value):
        """
        This handler will dispatch other invalid memory hooks
        """
        hl = self.hooks.get(common.HOOK_MEM_INVALID, [])

        rv = True
        for mem_access_hook in hl[1:]:
            if mem_access_hook.enabled:
                rv = mem_access_hook.cb(emu, access, address, size, value)
                if rv is False:
                    break
        return rv

    def add_mem_invalid_hook(self, cb, emu=None):
        """
        Add a hook that will fire for invalid memory access
        """
        hook = common.InvalidMemHook(self, self.emu_eng, cb, native_hook=False)
        hl = self.hooks.get(common.HOOK_MEM_INVALID)
        if not emu:
            emu = self
        if not hl:
            dispatch_hook = common.InvalidMemHook(emu, self.emu_eng, self._hook_mem_invalid_dispatch, native_hook=True)
            if self.emu_eng:
                dispatch_hook.add()

            self.hooks.update({common.HOOK_MEM_INVALID: [dispatch_hook, hook]})
        else:
            hl.append(hook)

        if self.emu_eng:
            hook.add()

        return hook

    def add_interrupt_hook(self, cb, emu=None):
        """
        Add a hook that will fire for software interrupts
        """
        if not emu:
            emu = self
        hook = common.InterruptHook(emu, self.emu_eng, cb)
        hl = self.hooks.get(common.HOOK_INTERRUPT)
        if not hl:
            self.hooks.update(
                {
                    common.HOOK_INTERRUPT: [
                        hook,
                    ]
                }
            )
        else:
            hl.append(hook)

        if self.emu_eng:
            hook.add()

        return hook

    def add_instruction_hook(self, cb, begin=1, end=0, emu=None, insn=None):
        """
        Add a hook that will fire for IN, SYSCALL, or SYSENTER instructions
        """
        if not emu:
            emu = self
        hook = common.InstructionHook(emu, self.emu_eng, cb, insn=insn)
        hl = self.hooks.get(common.HOOK_INSN)
        if not hl:
            self.hooks.update(
                {
                    common.HOOK_INSN: [
                        hook,
                    ]
                }
            )
        else:
            hl.append(hook)

        if self.emu_eng:
            hook.add()

        return hook

    def add_invalid_instruction_hook(self, cb, emu=None):
        if not emu:
            emu = self

        hook = common.InvalidInstructionHook(emu, self.emu_eng, cb)
        hl = self.hooks.get(common.HOOK_INSN_INVALID)

        if not hl:
            self.hooks.update(
                {
                    common.HOOK_INSN_INVALID: [
                        hook,
                    ]
                }
            )
        else:
            hl.append(hook)

        if self.emu_eng:
            hook.add()

        return hook
