# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

__all__ = ["volmgr"]  # noqa

from . import *  # noqa


def _get_kmods():
    # 遍历 __all__ 显式列表，避免扫描 globals() 全部条目
    import sys

    kmods = []
    pkg = __name__
    for name in __all__:
        mod = sys.modules.get(f"{pkg}.{name}")
        if mod is not None and hasattr(mod, "DriverModule"):
            kmods.append(mod)
    return kmods
