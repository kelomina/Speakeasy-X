# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

# Unicorn specific wrappers and abstraction implemented here

import ctypes as ct
import platform

import unicorn as uc
import unicorn.x86_const as u
from unicorn.unicorn_py3.arch.types import uc_hook_h
from unicorn.unicorn_py3.unicorn import (
    HOOK_CODE_CFUNC as UC_HOOK_CODE_CB,
)
from unicorn.unicorn_py3.unicorn import (
    HOOK_MEM_ACCESS_CFUNC as UC_HOOK_MEM_ACCESS_CB,
)
from unicorn.unicorn_py3.unicorn import (
    HOOK_MEM_INVALID_CFUNC as UC_HOOK_MEM_INVALID_CB,
)
from unicorn.unicorn_py3.unicorn import uclib as _uc

import speakeasy.common as common
import speakeasy.winenv.arch as arch
from speakeasy.errors import EmuEngineError

uc_engine = ct.c_void_p
UC_HOOK_INSN_IN_CB = ct.CFUNCTYPE(ct.c_uint32, uc_engine, ct.c_uint32, ct.c_int, ct.c_void_p)
UC_HOOK_INSN_SYSCALL_CB = ct.CFUNCTYPE(None, uc_engine, ct.c_void_p)
hook_id = uc_hook_h()


def is_platform_intel():
    mach = platform.machine()
    if mach in ("x86_64", "i386", "x86"):
        return True
    return False


class ToggleableHook:
    """
    Hook than can be toggled on/off at arbitrary times.
    """

    # V2-3-2: __slots__ 减少实例内存占用与属性访问开销
    __slots__ = ("cb", "enabled")

    def __init__(self, cb):
        self.cb = cb
        self.enabled = False

    def enable(self):
        if self.enabled:
            return
        self.enabled = True

    def disable(self):
        self.enabled = False


class EmuEngine:
    """Wrapper class for underlying cpu emulation engines"""

    def __init__(self):
        self.name = "unicorn"
        self.emu = None
        self.mmap = None
        self._callbacks = {}
        # P0-1: code hook 单分发器——所有 UC_HOOK_CODE 回调合并为单个原生
        # hook，由 _dispatch_code_hooks 依次调用，避免每条指令多次 C→Python 回调
        self._code_hooks: list = []
        self._code_dispatch_id = None
        self._code_dispatch_cb = None
        # V2-3-2: per-hook 句柄表 + 禁用索引集合，使 hook_enable/hook_disable
        # 可单独控制每个 code hook（句柄置于 0x40000000+ 段以避免与原生句柄碰撞）
        self._code_hook_handles: dict = {}
        self._code_hook_disabled: set = set()
        self._code_hook_seq = 0

        self.regs = {
            arch.X86_REG_EAX: u.UC_X86_REG_EAX,
            arch.X86_REG_EBX: u.UC_X86_REG_EBX,
            arch.X86_REG_ESP: u.UC_X86_REG_ESP,
            arch.X86_REG_EIP: u.UC_X86_REG_EIP,
            arch.X86_REG_EBP: u.UC_X86_REG_EBP,
            arch.X86_REG_ECX: u.UC_X86_REG_ECX,
            arch.X86_REG_EDX: u.UC_X86_REG_EDX,
            arch.X86_REG_EDI: u.UC_X86_REG_EDI,
            arch.X86_REG_ESI: u.UC_X86_REG_ESI,
            arch.X86_REG_EFLAGS: u.UC_X86_REG_EFLAGS,
            arch.AMD64_REG_RIP: u.UC_X86_REG_RIP,
            arch.AMD64_REG_RAX: u.UC_X86_REG_RAX,
            arch.AMD64_REG_RBX: u.UC_X86_REG_RBX,
            arch.AMD64_REG_RSP: u.UC_X86_REG_RSP,
            arch.AMD64_REG_RCX: u.UC_X86_REG_RCX,
            arch.AMD64_REG_RDX: u.UC_X86_REG_RDX,
            arch.AMD64_REG_RSI: u.UC_X86_REG_RSI,
            arch.AMD64_REG_RDI: u.UC_X86_REG_RDI,
            arch.AMD64_REG_RBP: u.UC_X86_REG_RBP,
            arch.AMD64_REG_R8: u.UC_X86_REG_R8,
            arch.AMD64_REG_R9: u.UC_X86_REG_R9,
            arch.AMD64_REG_R10: u.UC_X86_REG_R10,
            arch.AMD64_REG_R11: u.UC_X86_REG_R11,
            arch.AMD64_REG_R12: u.UC_X86_REG_R12,
            arch.AMD64_REG_R13: u.UC_X86_REG_R13,
            arch.AMD64_REG_R14: u.UC_X86_REG_R14,
            arch.AMD64_REG_R15: u.UC_X86_REG_R15,
            arch.X86_REG_IDTR: u.UC_X86_REG_IDTR,
            arch.X86_REG_XMM0: u.UC_X86_REG_XMM0,
            arch.X86_REG_XMM1: u.UC_X86_REG_XMM1,
            arch.X86_REG_XMM2: u.UC_X86_REG_XMM2,
            arch.X86_REG_XMM3: u.UC_X86_REG_XMM3,
            arch.X86_REG_GDTR: u.UC_X86_REG_GDTR,
            arch.X86_REG_CS: u.UC_X86_REG_CS,
            arch.X86_REG_ES: u.UC_X86_REG_ES,
            arch.X86_REG_SS: u.UC_X86_REG_SS,
            arch.X86_REG_DS: u.UC_X86_REG_DS,
            arch.X86_REG_FS: u.UC_X86_REG_FS,
            arch.X86_REG_GS: u.UC_X86_REG_GS,
            arch.X86_REG_MSR: u.UC_X86_REG_MSR,
        }

        self.mem_access = {
            uc.UC_MEM_FETCH_UNMAPPED: common.INVALID_MEM_EXEC,  # noqa
            uc.UC_MEM_READ_UNMAPPED: common.INVALID_MEM_READ,
            uc.UC_MEM_FETCH_PROT: common.INVAL_PERM_MEM_EXEC,
            uc.UC_MEM_WRITE_PROT: common.INVAL_PERM_MEM_WRITE,
            uc.UC_MEM_READ_PROT: common.INVAL_PERM_MEM_READ,
            uc.UC_MEM_WRITE_UNMAPPED: common.INVALID_MEM_WRITE,
        }

        self.perms = {
            common.PERM_MEM_NONE: uc.UC_PROT_NONE,
            common.PERM_MEM_EXEC: uc.UC_PROT_EXEC,
            common.PERM_MEM_READ: uc.UC_PROT_READ,
            common.PERM_MEM_WRITE: uc.UC_PROT_WRITE,
            common.PERM_MEM_RW: uc.UC_PROT_READ | uc.UC_PROT_WRITE,
            common.PERM_MEM_RX: uc.UC_PROT_READ | uc.UC_PROT_EXEC,
            common.PERM_MEM_RWX: uc.UC_PROT_ALL,
        }

        self.hook_types = {
            common.HOOK_CODE: uc.UC_HOOK_CODE,
            common.HOOK_MEM_ACCESS: uc.UC_HOOK_MEM_VALID,
            common.HOOK_MEM_INVALID: uc.UC_HOOK_MEM_INVALID,
            common.HOOK_MEM_PERM_EXEC: uc.UC_HOOK_MEM_FETCH_PROT,
            common.HOOK_MEM_PERM_WRITE: uc.UC_HOOK_MEM_WRITE_PROT,
            common.HOOK_MEM_READ: uc.UC_HOOK_MEM_READ,
            common.HOOK_MEM_WRITE: uc.UC_HOOK_MEM_WRITE,
            common.HOOK_INTERRUPT: uc.UC_HOOK_INTR,
            common.HOOK_INSN: uc.UC_HOOK_INSN,
            common.HOOK_INSN_INVALID: uc.UC_HOOK_INSN_INVALID,
        }

    def _sec_to_usec(self, sec):
        """
        Unicorn expects timeouts to be supplied in microsecond granularity
        """
        return int(sec * 1000000)

    def init_engine(self, eng_arch, mode):
        """Initialize cpu engine"""
        if eng_arch == arch.ARCH_X86 or eng_arch == arch.ARCH_AMD64:
            _arch = uc.UC_ARCH_X86
        else:
            raise Exception("Invalid architecture")

        if mode == arch.BITS_32:
            _mode = uc.UC_MODE_32
        elif mode == arch.BITS_64:
            _mode = uc.UC_MODE_64
        else:
            raise Exception("Invalid bitness")

        self.emu = uc.Uc(_arch, _mode)

    def mem_map(self, base, size, perms=common.PERM_MEM_RWX):
        """Allocate memory in the cpu engine"""
        perm = self.perms.get(perms, uc.UC_PROT_ALL)
        return self.emu.mem_map(base, size, perm)  # type: ignore[union-attr]

    def mem_unmap(self, addr, size):
        """Free memory in the cpu engine"""
        return self.emu.mem_unmap(addr, size)  # type: ignore[union-attr]

    def mem_regions(self):
        """Get current memory allocations from the engine"""
        return self.emu.mem_regions()  # type: ignore[union-attr]

    def mem_write(self, addr, data):
        """Write data into the address space of the engine"""
        return self.emu.mem_write(addr, data)  # type: ignore[union-attr]

    def mem_read(self, addr, size):
        """Read data from the address space of the engine"""
        return self.emu.mem_read(addr, size)  # type: ignore[union-attr]

    def mem_protect(self, addr, size, perms):
        """Change the memory protections for pages in the emu engine"""
        perm = self.perms.get(perms, uc.UC_PROT_ALL)
        return self.emu.mem_protect(addr, size, perm)  # type: ignore[union-attr]

    def reg_write(self, reg, val):
        """Modify register values"""
        ereg = self.regs.get(reg)
        if not ereg:
            raise EmuEngineError(f"Unknown register: {reg}")
        return self.emu.reg_write(ereg, val)  # type: ignore[union-attr]

    def reg_read(self, reg):
        """Read register values"""
        ereg = self.regs.get(reg)
        if not ereg:
            raise EmuEngineError(f"Unknown register: {reg}")
        return self.emu.reg_read(ereg)  # type: ignore[union-attr]

    def reg_read_batch(self, regs):
        """V2-3-1: 批量读取寄存器，单次 C 边界跨越（替代多次 reg_read）。

        args:
            regs: 可迭代的架构层寄存器常量列表
        return:
            与输入顺序一致的寄存器值 list
        """
        eregs = []
        for r in regs:
            ereg = self.regs.get(r)
            if not ereg:
                raise EmuEngineError(f"Unknown register: {r}")
            eregs.append(ereg)
        return list(self.emu.reg_read_batch(eregs))  # type: ignore[union-attr]

    def reg_write_batch(self, reg_dict):
        """V2-3-1: 批量写入寄存器，单次 C 边界跨越。

        args:
            reg_dict: {arch_reg_const: value} 映射
        """
        data = []
        for reg, val in reg_dict.items():
            ereg = self.regs.get(reg)
            if not ereg:
                raise EmuEngineError(f"Unknown register: {reg}")
            data.append((ereg, val))
        return self.emu.reg_write_batch(data)  # type: ignore[union-attr]

    def context_save(self):
        """V2-3-5: 保存当前 CPU 上下文（基于 uc_context_save）。

        用于 SEH/fiber 切换等需要寄存器快照的场景，避免逐字段 reg_read。
        """
        return self.emu.context_save()  # type: ignore[union-attr]

    def context_restore(self, ctx):
        """V2-3-5: 恢复之前保存的 CPU 上下文（基于 uc_context_restore）。"""
        self.emu.context_restore(ctx)  # type: ignore[union-attr]

    def context_update(self, ctx, reg, val):
        """V2-3-5: 在已保存的上下文中更新单个寄存器值（无需恢复后再写）。"""
        ereg = self.regs.get(reg)
        if not ereg:
            raise EmuEngineError(f"Unknown register: {reg}")
        ctx.reg_write(ereg, val)

    def stop(self):
        """Stop the emulation engine"""
        return self.emu.emu_stop()  # type: ignore[union-attr]

    def start(self, addr, timeout=0, count=0):
        """Start the emulation engine"""
        if count == -1:
            count = 0

        # Unicorn expects the timeout to be in microseconds, convert it here
        timeout = self._sec_to_usec(timeout)
        return self.emu.emu_start(addr, 0xFFFFFFFF, timeout=timeout, count=count)  # type: ignore[union-attr]

    def hook_add(self, addr=None, cb=None, htype=None, begin=1, end=0, arg1=0):
        """
        Add a callback function for a specific event type or address
        """
        hook_type = self.hook_types.get(htype)
        if not hook_type:
            raise EmuEngineError("Invalid hook type")

        # P0-1: UC_HOOK_CODE 走单分发器，避免每条指令触发多次 C→Python 回调
        if hook_type == uc.UC_HOOK_CODE:
            return self.add_code_hook(cb, begin=begin, end=end)

        handle = self.emu._uch  # type: ignore[union-attr]

        # The unicorn bindings have a default python wrapper. We want to use
        # our own wrapper and don't need the extra overhead. Add callbacks directly
        # to the unicorn library here.
        if hook_type == uc.UC_HOOK_INSN:
            if arg1 == u.UC_X86_INS_IN:  # IN instruction
                cb = ct.cast(UC_HOOK_INSN_IN_CB(cb), UC_HOOK_INSN_IN_CB)
            elif arg1 in (u.UC_X86_INS_SYSCALL, u.UC_X86_INS_SYSENTER):  # SYSCALL/SYSENTER
                cb = ct.cast(UC_HOOK_INSN_SYSCALL_CB(cb), UC_HOOK_INSN_SYSCALL_CB)
        elif hook_type in (uc.UC_HOOK_MEM_READ, uc.UC_HOOK_MEM_WRITE):
            cb = ct.cast(UC_HOOK_MEM_ACCESS_CB(cb), UC_HOOK_MEM_ACCESS_CB)
        elif hook_type == uc.UC_HOOK_MEM_INVALID:
            cb = ct.cast(UC_HOOK_MEM_INVALID_CB(cb), UC_HOOK_MEM_INVALID_CB)
        else:
            return self.emu.hook_add(htype=hook_type, callback=cb, begin=begin, end=end)  # type: ignore[union-attr]
        ptr = ct.cast(cb, ct.c_void_p)
        # uc_hook_add requires an additional paramter for the hook type UC_HOOK_INSN
        if hook_type == uc.UC_HOOK_INSN:
            insn = ct.c_int(arg1)
            rv = _uc.uc_hook_add(handle, ct.byref(hook_id), hook_type, ptr.value, None, begin, end, insn)
        else:
            rv = _uc.uc_hook_add(handle, ct.byref(hook_id), hook_type, ptr.value, None, begin, end)
        if rv != uc.UC_ERR_OK:
            raise uc.UcError(rv)

        th = ToggleableHook(cb)
        self._callbacks.update({hook_id.value: th})

        return hook_id.value

    def add_code_hook(self, callback, begin=1, end=0):
        """
        P0-1: 将 code hook 回调加入列表，仅向 Unicorn 注册一个原生
        UC_HOOK_CODE 分发器，由分发器依次调用所有回调，避免每条指令
        触发多次 C→Python 回调。回调签名保持 (eng, addr, size, ctx)。
        V2-3-2: 返回 per-hook 独立句柄，使 hook_enable/hook_disable
        可单独控制每个 code hook（底层仍共享单个原生分发器）。
        """
        self._code_hooks.append((callback, begin, end))
        index = len(self._code_hooks) - 1
        self._code_hook_seq += 1
        # 句柄置于 0x40000000+ 段以避免与 unicorn 原生 hook 句柄碰撞
        handle = 0x40000000 + self._code_hook_seq
        self._code_hook_handles[handle] = index
        if self._code_dispatch_id is None:
            self._code_dispatch_cb = UC_HOOK_CODE_CB(self._dispatch_code_hooks)
            ptr = ct.cast(self._code_dispatch_cb, ct.c_void_p)
            rv = _uc.uc_hook_add(
                self.emu._uch,  # type: ignore[union-attr]
                ct.byref(hook_id),
                uc.UC_HOOK_CODE,
                ptr.value,
                None,
                1,
                0,
            )
            if rv != uc.UC_ERR_OK:
                raise uc.UcError(rv)
            self._code_dispatch_id = hook_id.value
            self._callbacks[self._code_dispatch_id] = ToggleableHook(self._code_dispatch_cb)
        return handle

    def _dispatch_code_hooks(self, eng, addr, size, ctx=None):
        """P0-1/V2-3-2: 单分发器——按注册顺序依次调用所有 code hook。

        V2-3-2: 跳过被 hook_disable 禁用的 hook（按 index 查询），避免
        无谓的 Python 回调跨 C 边界；同时保留 begin/end 范围过滤。
        """
        disabled = self._code_hook_disabled
        if not disabled:
            # 快速路径：无禁用 hook，避免 enumerate 索引开销
            for cb, begin, end in self._code_hooks:
                # begin > end（如默认 begin=1, end=0）表示作用于全部地址
                if begin <= end and (addr < begin or addr > end):
                    continue
                cb(eng, addr, size, ctx)
        else:
            for index, (cb, begin, end) in enumerate(self._code_hooks):
                if index in disabled:
                    continue
                if begin <= end and (addr < begin or addr > end):
                    continue
                cb(eng, addr, size, ctx)

    def hook_enable(self, hook_handle):
        """
        Enable a previously disabled hook
        """
        # V2-3-2: code hook 使用 per-hook 句柄，单独启用
        idx = self._code_hook_handles.get(hook_handle)
        if idx is not None:
            self._code_hook_disabled.discard(idx)
            return
        hook = self._callbacks.get(hook_handle)
        if hook:
            return hook.enable()

    def hook_disable(self, hook_handle):
        """
        Disable a previously enabled hook
        """
        # V2-3-2: code hook 使用 per-hook 句柄，单独禁用
        idx = self._code_hook_handles.get(hook_handle)
        if idx is not None:
            self._code_hook_disabled.add(idx)
            return
        hook = self._callbacks.get(hook_handle)
        if hook:
            return hook.disable()

    def hook_remove(self, hid):
        return self.emu.hook_del(hid)  # type: ignore[union-attr]

    def close(self):
        if self.emu is None:
            return
        for hid in list(self._callbacks):
            try:
                self.emu.hook_del(hid)
            except Exception:
                pass
        self._callbacks.clear()
        # P0-1/V2-3-2: 重置 code hook 单分发器状态与 per-hook 句柄表
        self._code_hooks = []
        self._code_dispatch_id = None
        self._code_dispatch_cb = None
        self._code_hook_handles = {}
        self._code_hook_disabled = set()
