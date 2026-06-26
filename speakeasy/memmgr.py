# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import bisect
from typing import TYPE_CHECKING, Any

import speakeasy.common as common

if TYPE_CHECKING:
    from speakeasy.engines.unicorn_eng import EmuEngine


class MemMap:
    """
    Class that defines a memory mapping (e.g. heap/pool alloc, binary image, etc.)
    """

    def __init__(self, base, size, tag, prot, flags, block_base, block_size, shared=False, process=None):
        self.base = base
        self.size = size

        base_addr_tag = f".0x{base:x}"
        if tag and base_addr_tag not in tag:
            tag += base_addr_tag

        if tag:
            tag = list(tag)
            bad_chars = "\\?[]:]"
            [tag.__setitem__(j, "_") for j in [i for i, e in enumerate(tag) if e in bad_chars]]
            tag = "".join(tag)

        self.tag = tag
        self.prot = prot
        self.flags = flags
        self.shared = shared
        self.free = False
        self.process = process
        self.block_base = block_base
        self.block_size = block_size

    def __hash__(self):
        return hash(self.base)

    def __eq__(self, other):
        if other is not None:
            return self.base == other.base

    def __ne__(self, other):
        return not (self == other)


class MemoryManager:
    """
    Primitive memory manager used to block OS sized allocation units into something more practical

    Subclasses must define the following attributes:
        hooks: Dictionary of hooks
        keep_memory_on_free: Whether to keep memory on free
    """

    hooks: dict[int, Any]
    keep_memory_on_free: bool

    def get_current_process(self) -> Any:
        return None

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.maps = []
        self.emu_eng: EmuEngine | None = None
        self.mem_reserves = []
        self.block_base = 0
        self.block_size = 0
        self.block_offset = 0
        self.page_size = 0x1000
        # P0-4: 维护按 base 排序的平行结构，支持 get_address_map 等二分查找 O(log n)
        self._sorted_bases: list[int] = []          # self.maps 的 base 升序列表（与 _sorted_maps 平行）
        self._sorted_maps: list[MemMap] = []         # self.maps 按 base 升序的副本
        self._sorted_reserve_bases: list[int] = []   # self.mem_reserves 的 base 升序列表
        self._sorted_reserve_maps: list[MemMap] = []  # self.mem_reserves 按 base 升序的副本
        # P0-9: 空闲区间有序表，支持 get_valid_ranges 二分查找，替代页展开
        self._free_ranges: list[list[int]] = []      # 每项 [base, size]，按 base 升序

    # ---- P0-4: 排序结构维护 ----
    def _rebuild_sorted_bases(self):
        # 重建 maps 和 mem_reserves 按 base 升序的平行结构（删除后调用以保证一致性）
        s_maps = sorted(self.maps, key=lambda m: m.base)
        self._sorted_maps = s_maps
        self._sorted_bases = [m.base for m in s_maps]
        s_res = sorted(self.mem_reserves, key=lambda m: m.base)
        self._sorted_reserve_maps = s_res
        self._sorted_reserve_bases = [m.base for m in s_res]

    def _sorted_insert(self, mm, bases, maps):
        # 增量插入 MemMap 到按 base 升序的平行结构，O(log n) + O(n) 平移
        idx = bisect.bisect_right(bases, mm.base)
        bases.insert(idx, mm.base)
        maps.insert(idx, mm)

    def _sorted_remove(self, mm, bases, maps):
        # 增量删除 MemMap，O(log n) + O(n) 平移
        idx = bisect.bisect_left(bases, mm.base)
        if idx < len(bases) and bases[idx] == mm.base and maps[idx] is mm:
            bases.pop(idx)
            maps.pop(idx)

    # ---- P0-9: 空闲区间表维护 ----
    # 注意：因 winemu 等处可能直接调用 emu_eng.mem_map（绕过本类），
    # get_valid_ranges 每次会基于 emu_eng.mem_regions()+mem_reserves 重建 _free_ranges 以保证正确性；
    # 以下增量方法在 map/unmap 时同步更新 _free_ranges，保持调用间隙的一致性。
    def _rebuild_free_ranges(self):
        # 从 emu_eng 已映射区间与 mem_reserves 计算空闲区间补集（按区间而非页展开，O(n log n)）
        self._free_ranges = []
        if self.emu_eng is None:
            return
        upper = 0xFFFFFFFFFFFFE000  # 空闲空间上界（覆盖 64 位高地址映射）
        occupied = []
        try:
            for region in self.emu_eng.mem_regions():
                # unicorn 返回 (begin, end, perms)，end 为包含，转 [begin, end+1)
                occupied.append((region[0], region[1] + 1))
        except Exception:
            return
        for res in self.mem_reserves:
            occupied.append((res.base, res.base + res.size))
        if not occupied:
            self._free_ranges = [[0, upper]]
            return
        occupied.sort()
        # 合并重叠/相邻的占用区间
        merged = []
        cur_start, cur_end = occupied[0]
        for start, end in occupied[1:]:
            if start <= cur_end:
                if end > cur_end:
                    cur_end = end
            else:
                merged.append((cur_start, cur_end))
                cur_start, cur_end = start, end
        merged.append((cur_start, cur_end))
        # 计算补集（空闲区间），从 0 开始（地址 0 可用于 fakeout 映射）
        free = []
        cursor = 0
        for start, end in merged:
            if start > cursor:
                free.append([cursor, start - cursor])
            if end > cursor:
                cursor = end
        if cursor < upper:
            free.append([cursor, upper - cursor])
        self._free_ranges = free

    def _consume_free_range(self, base, size):
        # 从空闲区间表中移除/分割 [base, base+size)
        free = self._free_ranges
        if not free:
            return
        bases = [fr[0] for fr in free]
        idx = bisect.bisect_right(bases, base)
        if idx == 0:
            return
        i = idx - 1
        fb, fs = free[i]
        end = fb + fs
        alloc_end = base + size
        if base < fb or alloc_end > end:
            return  # 跨区间或越界，跳过（下次 get_valid_ranges 会重建）
        del free[i]
        if base > fb:
            free.insert(i, [fb, base - fb])
        if alloc_end < end:
            free.insert(i + (1 if base > fb else 0), [alloc_end, end - alloc_end])

    def _restore_free_range(self, base, size):
        # 将 [base, base+size) 加回空闲区间表并合并相邻区间
        free = self._free_ranges
        if not free:
            return
        end = base + size
        bases = [fr[0] for fr in free]
        idx = bisect.bisect_left(bases, base)
        merged_end = end
        # 合并后继相邻区间
        if idx < len(free) and free[idx][0] == end:
            merged_end = free[idx][0] + free[idx][1]
            del free[idx]
        # 合并前驱相邻区间
        if idx > 0 and free[idx - 1][0] + free[idx - 1][1] == base:
            free[idx - 1][1] = merged_end - free[idx - 1][0]
            return
        free.insert(idx, [base, merged_end - base])

    def _hook_mem_map_dispatch(self, mm):
        hl = self.hooks.get(common.HOOK_MEM_MAP, [])
        for mem_map_hook in hl:
            if mem_map_hook.enabled:
                # the mapped memory region's base address falls within the hook's bounds
                if mem_map_hook.begin <= mm.base:
                    if not mem_map_hook.end or mem_map_hook.end > mm.base:
                        mem_map_hook.cb(self, mm.base, mm.size, mm.tag, mm.prot, mm.flags)

    def mem_map(self, size, base=None, perms=common.PERM_MEM_RWX, tag=None, flags=0, shared=False, process=None):
        """
        Map a block of memory with specified permissions and a tag
        """
        if not process and tag and not tag.startswith("emu"):
            process = self.get_current_process()

        if base is None:
            if size < self.page_size and size % self.page_size:
                addr = self.block_base + self.block_offset
                pad_size = 0x10 - (size % 0x10)
                size += pad_size
                if not self.block_base or ((addr + size) > self.block_base + self.page_size):
                    block = self.get_valid_ranges(self.page_size)
                    self.block_base, self.block_size = block

                    self.emu_eng.mem_map(self.block_base, self.block_size)  # type: ignore[union-attr]
                    self._consume_free_range(self.block_base, self.block_size)
                    self.block_offset = 0
                    addr = self.block_base + self.block_offset

                self.block_offset += size
                base = addr

                mm = MemMap(base, size, tag, perms, flags, self.block_base, self.block_size, shared, process)

                self.maps.append(mm)
                self._sorted_insert(mm, self._sorted_bases, self._sorted_maps)
                self._hook_mem_map_dispatch(mm)
                return base

        block = self.get_valid_ranges(size, addr=base)
        base, size = block

        block_size = self.block_size
        if size > self.block_size:
            block_size = size
        mm = MemMap(base, size, tag, perms, flags, base, block_size, shared, process)
        self.emu_eng.mem_map(base, size, perms=perms)  # type: ignore[union-attr]
        self._consume_free_range(base, size)
        self.maps.append(mm)
        self._sorted_insert(mm, self._sorted_bases, self._sorted_maps)
        self._hook_mem_map_dispatch(mm)
        return base

    def mem_free(self, base):
        """
        Free a block of memory, if all blocks in a block are set to free, unmap the entire block
        """
        mm = self.get_address_map(base)
        if mm:
            mm.free = True

            # If we want to freeze memory, just return
            if self.config.keep_memory_on_free:  # type: ignore[attr-defined]  # config is defined on subclasses
                return

            ml = [m for m in self.get_mem_maps() if m.block_base == mm.block_base]
            # if all blocks are free in the current block, free it from the emu engine
            if all([m.free for m in ml]):
                self.block_base = 0
                self.mem_unmap(mm.block_base, mm.block_size)
                [self.maps.remove(mm) for mm in ml]  # type: ignore[func-returns-value]  # list comp used for side effect
                # 批量删除后重建排序结构以保持不变量
                self._rebuild_sorted_bases()

    def mem_remap(self, frm, to):
        """
        Remap a block of emulated memory, and return the new address,
        or -1 on error
        Protections remain the same
        """
        map = self.get_address_map(frm)

        if not map:
            return -1

        prot = map.prot
        size = map.size

        # Exclude old memory region in tag name
        tag = map.tag[: map.tag.rfind(".")]

        contents = self.mem_read(map.base, size)

        # Will unmap as well
        self.mem_free(map.base)

        newmem = self.mem_map(size, base=to, perms=prot, tag=tag)

        if newmem != to:
            return -1

        self.mem_write(newmem, contents)

        return newmem

    def mem_unmap(self, base, size):
        """
        Free a block of emulated memory
        """
        self.emu_eng.mem_unmap(base, size)  # type: ignore[union-attr]
        self._restore_free_range(base, size)

    def mem_write(self, addr, data):
        """
        Write bytes into the emulated address space
        """
        self.emu_eng.mem_write(addr, data)  # type: ignore[union-attr]

    def mem_read(self, addr, size):
        """
        Read bytes from the emulated address space
        """
        return bytes(self.emu_eng.mem_read(addr, size))  # type: ignore[union-attr]

    def mem_protect(self, addr, size, perms):
        """
        Change memory protections
        """
        self.emu_eng.mem_protect(addr, size, perms)  # type: ignore[union-attr]

    def _mem_unmap_region(self, base, size):
        """
        Remove an entire memory region that may not have blocks allocated within it
        """
        self.emu_eng.mem_unmap(base, size)  # type: ignore[union-attr]
        self._restore_free_range(base, size)

    def get_address_map(self, address):
        """
        Get the "MemMap" object associated with a specific address
        """
        # P0-4: 用 bisect 在按 base 升序的平行结构中二分查找，O(log n)
        bases = self._sorted_bases
        if not bases:
            return None
        idx = bisect.bisect_right(bases, address)
        if idx == 0:
            return None
        m = self._sorted_maps[idx - 1]
        if m.base <= address <= (m.base + m.size) - 1:
            return m
        return None

    def get_reserve_map(self, address):
        """
        Get the "MemMap" object that was only reserved for a specific address
        """
        # P0-4: 对 mem_reserves 的排序结构二分查找，O(log n)
        bases = self._sorted_reserve_bases
        if not bases:
            return None
        idx = bisect.bisect_right(bases, address)
        if idx == 0:
            return None
        m = self._sorted_reserve_maps[idx - 1]
        if m.base <= address <= (m.base + m.size) - 1:
            return m
        return None

    def is_address_valid(self, address):
        """
        Was this address previously reserved or mapped?
        """
        if self.get_address_map(address):
            return True
        if self.get_reserve_map(address):
            return True
        return False

    def get_address_tag(self, address):
        """
        Get the tag for a supplied memory address
        """
        # P0-4: 复用 get_address_map 的二分查找
        m = self.get_address_map(address)
        if m is not None:
            return m.tag
        return None

    def mem_reserve(self, size, base=None, perms=None, tag=None, flags=0, shared=False):
        """
        Reserve (but do not map) a block of memory
        """
        if base is None:
            block = self.get_valid_ranges(size)
            base, size = block

        mm = MemMap(base, size, tag, perms, flags, base, self.block_size, shared)

        self.mem_reserves.append(mm)
        self._sorted_insert(mm, self._sorted_reserve_bases, self._sorted_reserve_maps)
        # 预留区同样占用空闲地址空间
        self._consume_free_range(base, size)
        return base

    def purge_memory(self):
        """
        Unmap all current blocks of mapped memory
        """
        for region in self.get_mem_regions():
            base, end, perms = region
            size = (end - base) + 1
            self._mem_unmap_region(base, size)

    def get_mem_maps(self):
        """
        Get the listing of current memory maps
        """
        return self.maps

    def mem_map_reserve(self, mapped_base):
        """
        Map a previously reserved block of memory
        """
        for r in self.mem_reserves:
            if mapped_base == r.base:
                self.mem_reserves.remove(r)
                self._sorted_remove(r, self._sorted_reserve_bases, self._sorted_reserve_maps)
                return self.mem_map(r.size, base=r.base, perms=r.prot, tag=r.tag)
        return None

    def get_mem_regions(self):
        """
        Get the current regions of mapped memory
        """
        return self.emu_eng.mem_regions()  # type: ignore[union-attr]

    def get_valid_ranges(self, size, addr=None):
        """
        Retrieve a valid address range that can satisfy the requested size.
        Optionally, a base address can be specified to test if it can be used
        """
        page_size = self.page_size

        # mem_map needs to be page aligned
        total = size

        # alloced address needs to also be on a page boundary
        if addr is None:
            addr = page_size
        base = addr - (addr % page_size)

        if total < page_size:
            total = page_size
        elif total % page_size:
            total += page_size - (total % page_size)

        # P0-9: 基于空闲区间表二分查找，替代页展开。
        # 每次按 emu_eng.mem_regions()+mem_reserves 重建 _free_ranges，
        # 保证与引擎实际状态同步（含 winemu 等处直接 emu_eng.mem_map 的情况）。
        self._rebuild_free_ranges()
        free = self._free_ranges
        if not free:
            raise Exception("Failed to allocate emulator memory")

        free_bases = [fr[0] for fr in free]
        idx = bisect.bisect_right(free_bases, base)

        # 1) base 落入某空闲区间且该区间足够容纳 total，直接使用 base
        if idx > 0:
            fb, fs = free[idx - 1]
            if fb <= base and fb + fs >= base + total:
                return (base, total)

        # 2) 否则从 base 之后第一个空闲区间起，找首个能容纳 total 的区间
        i = idx
        while i < len(free):
            fb, fs = free[i]
            if fs >= total:
                return (fb, total)
            i += 1

        raise Exception("Failed to allocate emulator memory")
