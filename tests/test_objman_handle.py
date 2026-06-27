"""
P0 句柄管理回归测试。

验证内容：
  - P0-6: ObjectManager.get_object_from_handle 走 handle->object 反向字典
  - P0-6: add_object / get_handle / close_handle 一致维护反向字典
  - P0-6: remove_object 同步清理反向字典
  - P0-15: close_handle 后再查找应返回 None（与 CloseHandle/RegCloseKey/ZwClose
            的清理路径一致）
"""

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.objman import Event, Mutant


@pytest.fixture
def emu_with_om(config, load_test_bin):
    """加载一个 DLL 让 Win32Emulator.setup() 完成，从而 emu.om 就绪。"""
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        # 加载完成后 om 必然非空
        assert se.emu.om is not None
        yield se.emu
    finally:
        se.shutdown()


def test_get_handle_registers_in_reverse_map(emu_with_om):
    """get_handle 后应能通过 get_object_from_handle 反向 O(1) 命中。"""
    emu = emu_with_om
    om = emu.om

    evt = om.new_object(Event)
    h = om.get_handle(evt)

    # 反向字典直接命中
    assert om._handle_map.get(h) is evt
    # 通过公共 API 也能拿到
    assert om.get_object_from_handle(h) is evt
    # 句柄已登记到对象的 handles 列表
    assert h in evt.handles


def test_close_handle_clears_reverse_map_and_handles_list(emu_with_om):
    """P0-15 关键路径：close_handle 后反向字典 + 对象 handles 列表都要清理。"""
    emu = emu_with_om
    om = emu.om

    evt = om.new_object(Event)
    h = om.get_handle(evt)
    assert om.get_object_from_handle(h) is evt

    closed_obj = om.close_handle(h)
    assert closed_obj is evt

    # 反向字典已 pop
    assert h not in om._handle_map
    # 对象的 handles 列表也已移除
    assert h not in evt.handles
    # 再次查找返回 None（不抛异常）
    assert om.get_object_from_handle(h) is None
    # 重复 close 应安全返回 None
    assert om.close_handle(h) is None


def test_close_one_handle_does_not_affect_others(emu_with_om):
    """关闭一个句柄不应影响其它对象/句柄。"""
    emu = emu_with_om
    om = emu.om

    evt1 = om.new_object(Event)
    evt2 = om.new_object(Event)
    h1 = om.get_handle(evt1)
    h2 = om.get_handle(evt2)

    assert om.close_handle(h1) is evt1

    assert om.get_object_from_handle(h1) is None
    assert om.get_object_from_handle(h2) is evt2
    assert h2 in evt2.handles


def test_multiple_handles_per_object(emu_with_om):
    """同一对象可持有多把句柄，关闭单把不应影响其他句柄指向同一对象。"""
    emu = emu_with_om
    om = emu.om

    mtx = om.new_object(Mutant)
    h1 = om.get_handle(mtx)
    h2 = om.get_handle(mtx)

    assert om.get_object_from_handle(h1) is mtx
    assert om.get_object_from_handle(h2) is mtx
    assert set(mtx.handles) == {h1, h2}

    om.close_handle(h1)
    assert om.get_object_from_handle(h1) is None
    assert om.get_object_from_handle(h2) is mtx
    assert mtx.handles == [h2]


def test_remove_object_clears_all_its_handles(emu_with_om):
    """remove_object 应同步从反向字典移除该对象的全部句柄。"""
    emu = emu_with_om
    om = emu.om

    evt = om.new_object(Event)
    h1 = om.get_handle(evt)
    h2 = om.get_handle(evt)

    om.remove_object(evt)

    assert om.get_object_from_handle(h1) is None
    assert om.get_object_from_handle(h2) is None
    assert h1 not in om._handle_map
    assert h2 not in om._handle_map


def test_close_handle_then_dec_ref_path_simulates_p0_15(emu_with_om):
    """
    模拟 P0-15 中 CloseHandle / ZwClose 的清理路径：
    om.close_handle(handle) -> emu.dec_ref(obj)。

    引用计数归零时应触发 remove_object，使对象从 objects 字典消失。
    """
    emu = emu_with_om
    om = emu.om

    evt = om.new_object(Event)  # new_object 内部 add_object 已 +1 ref_cnt
    h = om.get_handle(evt)

    # 关闭句柄并递减引用计数，模拟 CloseHandle/RegCloseKey/ZwClose 的清理路径
    closed = om.close_handle(h)
    assert closed is evt
    remaining = emu.dec_ref(evt)

    # 引用计数归零，对象应被移除
    assert remaining == 0
    assert om.get_object_from_addr(evt.address) is None
    assert om.get_object_from_handle(h) is None
