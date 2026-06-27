# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
"""P0-15 句柄清理功能验证测试。

直接以未绑定方式调用 Ntoskrnl.ZwClose / Kernel32.CloseHandle / AdvApi32.RegCloseKey，
配合轻量 mock emu 验证句柄清理逻辑、引用计数递减与预定义根键保护。
"""

import types

import pytest

import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.winenv.api.kernelmode.ntoskrnl import Ntoskrnl
from speakeasy.winenv.api.usermode.advapi32 import AdvApi32
from speakeasy.winenv.api.usermode.kernel32 import Kernel32

# 预定义注册表根键（句柄值 >= 0x80000000）
HKEY_CLASSES_ROOT = 0x80000000
HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_USERS = 0x80000003


class FakeOm:
    """模拟 objman.ObjectManager 的句柄表与引用计数行为。"""

    def __init__(self):
        self._handle_map = {}
        self.closed_handles = []
        self.decref_objs = []

    def close_handle(self, handle):
        self.closed_handles.append(handle)
        return self._handle_map.pop(handle, None)

    def dec_ref(self, obj):
        self.decref_objs.append(obj)
        return 0


class FakeFileMan:
    def __init__(self):
        self.file_handles = {}
        self.pipe_handles = {}
        self.file_maps = {}


class FakeRegMan:
    def __init__(self):
        self.reg_handles = {}


def make_emu():
    emu = types.SimpleNamespace()
    emu.om = FakeOm()
    emu.regman = FakeRegMan()
    emu._fileman = FakeFileMan()
    emu.get_file_manager = lambda: emu._fileman
    emu.last_error = None

    def set_last_error(code):
        emu.last_error = code

    emu.set_last_error = set_last_error
    emu.dec_ref = lambda obj: emu.om.dec_ref(obj)

    def reg_get_key(handle=0, path=""):
        return emu.regman.reg_handles.get(handle)

    emu.reg_get_key = reg_get_key
    return emu


def _advapi_self(emu):
    """AdvApi32.RegCloseKey 通过 self.reg_get_key 访问注册表。"""
    self_obj = types.SimpleNamespace()
    self_obj.emu = emu
    self_obj.reg_get_key = lambda handle: emu.reg_get_key(handle)
    return self_obj


# ----------------------------- ZwClose --------------------------------------


def test_zwclose_closes_known_handle_and_decrefs():
    emu = make_emu()
    obj = object()
    handle = 0x100
    emu.om._handle_map[handle] = obj

    rv = Ntoskrnl.ZwClose(None, emu, [handle], None)

    assert rv == ddk.STATUS_SUCCESS
    assert handle in emu.om.closed_handles
    assert obj in emu.om.decref_objs
    assert handle not in emu.om._handle_map


def test_zwclose_unknown_handle_returns_success_no_decref():
    emu = make_emu()
    rv = Ntoskrnl.ZwClose(None, emu, [0xDEAD], None)
    assert rv == ddk.STATUS_SUCCESS
    assert 0xDEAD in emu.om.closed_handles
    assert emu.om.decref_objs == []


# ----------------------------- CloseHandle ----------------------------------


def test_closehandle_rejects_registry_handle():
    emu = make_emu()
    hKey = 0x200
    emu.regman.reg_handles[hKey] = object()

    rv = Kernel32.CloseHandle(None, emu, [hKey], None)

    assert rv == 0
    assert emu.last_error == windefs.ERROR_INVALID_HANDLE
    # 注册表句柄仍存在，未被 CloseHandle 清理
    assert hKey in emu.regman.reg_handles
    assert emu.om.closed_handles == []


def test_closehandle_closes_file_handle():
    emu = make_emu()
    hObject = 0x300
    emu._fileman.file_handles[hObject] = object()

    rv = Kernel32.CloseHandle(None, emu, [hObject], None)

    assert rv == 1
    assert emu.last_error == windefs.ERROR_SUCCESS
    assert hObject not in emu._fileman.file_handles
    assert hObject in emu.om.closed_handles


def test_closehandle_closes_pipe_handle():
    emu = make_emu()
    hObject = 0x310
    emu._fileman.pipe_handles[hObject] = object()

    rv = Kernel32.CloseHandle(None, emu, [hObject], None)

    assert rv == 1
    assert emu.last_error == windefs.ERROR_SUCCESS
    assert hObject not in emu._fileman.pipe_handles
    assert hObject in emu.om.closed_handles


def test_closehandle_closes_file_map():
    emu = make_emu()
    hObject = 0x320
    emu._fileman.file_maps[hObject] = object()

    rv = Kernel32.CloseHandle(None, emu, [hObject], None)

    assert rv == 1
    assert emu.last_error == windefs.ERROR_SUCCESS
    assert hObject not in emu._fileman.file_maps
    assert hObject in emu.om.closed_handles


def test_closehandle_closes_om_only_handle_and_decrefs():
    emu = make_emu()
    hObject = 0x330
    obj = object()
    emu.om._handle_map[hObject] = obj

    rv = Kernel32.CloseHandle(None, emu, [hObject], None)

    assert rv == 1
    assert emu.last_error == windefs.ERROR_SUCCESS
    assert obj in emu.om.decref_objs
    assert hObject not in emu.om._handle_map


def test_closehandle_unknown_handle_returns_zero():
    emu = make_emu()
    rv = Kernel32.CloseHandle(None, emu, [0xBEEF], None)
    assert rv == 0
    assert emu.last_error == windefs.ERROR_INVALID_HANDLE


# ----------------------------- RegCloseKey ----------------------------------


def test_regclosekey_unknown_handle_returns_invalid_handle():
    emu = make_emu()
    self_obj = _advapi_self(emu)

    rv = AdvApi32.RegCloseKey(self_obj, emu, [0x9999], None)

    assert rv == windefs.ERROR_INVALID_HANDLE
    assert emu.om.closed_handles == []


@pytest.mark.parametrize("predefined", [
    HKEY_CLASSES_ROOT,
    HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE,
    HKEY_USERS,
])
def test_regclosekey_predefined_root_not_closed(predefined):
    emu = make_emu()
    emu.regman.reg_handles[predefined] = object()
    self_obj = _advapi_self(emu)

    rv = AdvApi32.RegCloseKey(self_obj, emu, [predefined], None)

    assert rv == windefs.ERROR_SUCCESS
    # 预定义根键仍存在
    assert predefined in emu.regman.reg_handles
    # 不应触发 objman 清理
    assert emu.om.closed_handles == []


def test_regclosekey_normal_key_cleaned():
    emu = make_emu()
    hKey = 0x180
    emu.regman.reg_handles[hKey] = object()
    self_obj = _advapi_self(emu)

    rv = AdvApi32.RegCloseKey(self_obj, emu, [hKey], None)

    assert rv == windefs.ERROR_SUCCESS
    assert hKey not in emu.regman.reg_handles
    # 注册表句柄由 regman 独立管理（RegKey 非 KernelObject），不在 objman 中
    # 登记，因此 RegCloseKey 不应触碰 objman。
    assert emu.om.closed_handles == []


# ------------------- 集成：句柄清理后无残留/无副作用 -------------------------


def test_handle_lifecycle_no_leak_after_close():
    """模拟 创建文件句柄 -> CloseHandle -> 句柄表无残留，可重新分配。"""
    emu = make_emu()
    fman = emu.get_file_manager()

    # 创建两个文件句柄
    h1, h2 = 0x400, 0x404
    fman.file_handles[h1] = object()
    fman.file_handles[h2] = object()

    # 关闭 h1
    assert Kernel32.CloseHandle(None, emu, [h1], None) == 1
    assert h1 not in fman.file_handles
    assert h2 in fman.file_handles  # h2 未受影响

    # 关闭 h2
    assert Kernel32.CloseHandle(None, emu, [h2], None) == 1
    assert fman.file_handles == {}

    # 重复关闭已关闭句柄 -> 返回 0（无效句柄），无副作用
    assert Kernel32.CloseHandle(None, emu, [h1], None) == 0
    assert emu.last_error == windefs.ERROR_INVALID_HANDLE


def test_registry_lifecycle_predefined_persistent():
    """预定义根键可被多次 RegCloseKey 仍保持存在。"""
    emu = make_emu()
    emu.regman.reg_handles[HKEY_LOCAL_MACHINE] = object()
    self_obj = _advapi_self(emu)

    for _ in range(3):
        rv = AdvApi32.RegCloseKey(self_obj, emu, [HKEY_LOCAL_MACHINE], None)
        assert rv == windefs.ERROR_SUCCESS
    assert HKEY_LOCAL_MACHINE in emu.regman.reg_handles


# ------------------- P0-15 回归：多句柄 use-after-free --------------------


class FakeOmWithHandles:
    """模拟 objman.ObjectManager：close_handle 同步从 obj.handles 移除，
    用于验证“仅当最后一把句柄关闭时才 dec_ref”的修复逻辑。"""

    def __init__(self):
        self._handle_map = {}
        self.closed_handles = []
        self.decref_objs = []

    def close_handle(self, handle):
        self.closed_handles.append(handle)
        obj = self._handle_map.pop(handle, None)
        if obj is not None:
            handles = getattr(obj, "handles", None)
            if handles is not None:
                while handle in handles:
                    handles.remove(handle)
        return obj

    def dec_ref(self, obj):
        self.decref_objs.append(obj)
        return 0


def _emu_with_handle_om():
    """构造 emu，om 使用会维护 handles 列表的 FakeOmWithHandles。"""
    emu = make_emu()
    emu.om = FakeOmWithHandles()
    emu.dec_ref = lambda obj: emu.om.dec_ref(obj)
    return emu


def test_zwclose_multi_handle_no_use_after_free():
    """同一对象持有多把句柄时，关闭其一不应 dec_ref/移除对象，余下句柄仍可用。"""
    emu = _emu_with_handle_om()
    obj = types.SimpleNamespace(handles=[])
    h1, h2 = 0x500, 0x504
    emu.om._handle_map[h1] = obj
    emu.om._handle_map[h2] = obj
    obj.handles = [h1, h2]

    # 关闭 h1：h2 仍存在，不应 dec_ref
    rv = Ntoskrnl.ZwClose(None, emu, [h1], None)
    assert rv == ddk.STATUS_SUCCESS
    assert emu.om.decref_objs == []
    assert h2 in emu.om._handle_map
    assert obj.handles == [h2]

    # 关闭 h2（最后一把）：此时才 dec_ref
    rv = Ntoskrnl.ZwClose(None, emu, [h2], None)
    assert rv == ddk.STATUS_SUCCESS
    assert obj in emu.om.decref_objs
    assert obj.handles == []


def test_closehandle_multi_handle_no_use_after_free():
    """CloseHandle 关闭多句柄对象的一把时不应提前 dec_ref，避免其余句柄悬空。"""
    emu = _emu_with_handle_om()
    obj = types.SimpleNamespace(handles=[])
    h1, h2 = 0x600, 0x604
    emu.om._handle_map[h1] = obj
    emu.om._handle_map[h2] = obj
    obj.handles = [h1, h2]

    rv = Kernel32.CloseHandle(None, emu, [h1], None)
    assert rv == 1
    assert emu.last_error == windefs.ERROR_SUCCESS
    assert emu.om.decref_objs == []  # h2 仍存在，不应 dec_ref
    assert h2 in emu.om._handle_map

    rv = Kernel32.CloseHandle(None, emu, [h2], None)
    assert rv == 1
    assert obj in emu.om.decref_objs


def test_closehandle_om_object_double_close_safe():
    """objman 对象双重关闭：第二次返回 0（无效句柄），不重复 dec_ref。"""
    emu = _emu_with_handle_om()
    obj = types.SimpleNamespace(handles=[])
    h = 0x700
    emu.om._handle_map[h] = obj
    obj.handles = [h]

    assert Kernel32.CloseHandle(None, emu, [h], None) == 1
    assert obj in emu.om.decref_objs

    # 重置 decref_objs 以验证第二次关闭不再 dec_ref
    emu.om.decref_objs.clear()
    rv = Kernel32.CloseHandle(None, emu, [h], None)
    assert rv == 0
    assert emu.last_error == windefs.ERROR_INVALID_HANDLE
    assert emu.om.decref_objs == []


# --------- P0-15 回归：RegCloseKey 不得误删 objman 同值句柄 ---------


def test_regclosekey_does_not_touch_objman_on_collision():
    """注册表句柄值与 objman 句柄冲突时，RegCloseKey 不得清理 objman 条目。"""
    emu = make_emu()
    hKey = 0x190
    emu.regman.reg_handles[hKey] = object()
    # 故意在 om 中放入同值句柄，验证 RegCloseKey 不会误删
    sentinel = object()
    emu.om._handle_map[hKey] = sentinel
    self_obj = _advapi_self(emu)

    rv = AdvApi32.RegCloseKey(self_obj, emu, [hKey], None)

    assert rv == windefs.ERROR_SUCCESS
    assert hKey not in emu.regman.reg_handles
    # om 中的同值句柄必须保持不变
    assert emu.om.closed_handles == []
    assert emu.om._handle_map.get(hKey) is sentinel
