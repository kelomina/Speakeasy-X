"""模拟文件系统的主机文件挂载支持。"""

from __future__ import annotations

from pathlib import Path, PureWindowsPath


def parse_volume_spec(spec: str) -> tuple[Path, PureWindowsPath]:
    """解析 ``host_path:guest_path`` 卷规格。

    处理两侧的 Windows 驱动器字母冒号（例如
    ``C:\\samples:C:\\guest``）。真正的分隔符是第一个 ``:``，
    它不是驱动器字母前缀的第二个字符。
    """
    if not spec:
        raise ValueError("Empty volume specification")

    # 查找分隔符冒号。跳过主机侧的前导驱动器字母 (X:)，
    # 然后查找下一个冒号。
    start = 0
    if len(spec) >= 2 and spec[1] == ":":
        # 主机路径以驱动器字母开头——跳过它。
        start = 2

    idx = spec.find(":", start)
    if idx == -1:
        raise ValueError(f"无效的卷规格（缺少 ':' 分隔符）：{spec!r}")

    host_str = spec[:idx]
    guest_str = spec[idx + 1 :]

    if not host_str:
        raise ValueError(f"卷规格中主机路径为空：{spec!r}")
    if not guest_str:
        raise ValueError(f"卷规格中客户机路径为空：{spec!r}")

    return Path(host_str), PureWindowsPath(guest_str)


def expand_volume_to_entries(host_path: Path, guest_path: PureWindowsPath) -> list[dict]:
    """将卷映射扩展为 ``FileEntryFullPath`` 兼容的字典。

    如果 *host_path* 是文件，则返回一个条目。如果是目录，
    则其下的每个文件（递归地）都会成为一个条目，
    相对路径附加到 *guest_path*。
    """
    host_path = host_path.resolve()

    if not host_path.exists():
        raise FileNotFoundError(f"卷主机路径不存在：{host_path}")

    entries: list[dict] = []

    if host_path.is_file():
        entries.append(
            {
                "mode": "full_path",
                "emu_path": str(guest_path),
                "path": str(host_path),
            }
        )
    elif host_path.is_dir():
        for child in sorted(host_path.rglob("*")):
            if not child.is_file():
                continue
            rel = child.relative_to(host_path)
            emu_path = guest_path / PureWindowsPath(*rel.parts)
            entries.append(
                {
                    "mode": "full_path",
                    "emu_path": str(emu_path),
                    "path": str(child),
                }
            )

    return entries


def apply_volumes(config: dict, volume_specs: list[str]) -> dict:
    """解析 *volume_specs* 并将生成的文件条目前置到 *config*。

    条目被前置，以便它们在 ``get_emu_file()`` 中
    优先匹配解决。
    """
    if not volume_specs:
        return config

    new_entries: list[dict] = []
    for spec in volume_specs:
        host_path, guest_path = parse_volume_spec(spec)
        new_entries.extend(expand_volume_to_entries(host_path, guest_path))

    fs = config.setdefault("filesystem", {})
    existing = fs.get("files", [])
    fs["files"] = new_entries + existing

    return config
