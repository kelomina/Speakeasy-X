import base64
import os
import zlib
from unittest.mock import patch

import pytest

from speakeasy.artifacts import LARGE_ARTIFACT_THRESHOLD, ArtifactStore
from speakeasy.report import DataArtifact, Report


def decode_artifact(entry: DataArtifact) -> bytes:
    return zlib.decompress(base64.b64decode(entry.data))


def test_artifact_store_deduplicates_payloads():
    store = ArtifactStore()

    first_ref = store.put_bytes(b"artifact-bytes")
    second_ref = store.put_bytes(b"artifact-bytes")

    assert first_ref == second_ref
    report_data = store.to_report_data()
    assert list(report_data) == [first_ref]
    assert decode_artifact(report_data[first_ref]) == b"artifact-bytes"


def test_report_data_roundtrip_json():
    report = Report(
        emulation_total_runtime=1.0,
        timestamp=123,
        entry_points=[],
        data={
            "deadbeef": DataArtifact(
                compression="zlib",
                encoding="base64",
                size=4,
                data=base64.b64encode(zlib.compress(b"data")).decode(),
            )
        },
    )

    restored = Report.model_validate_json(report.model_dump_json())

    assert decode_artifact(restored.data["deadbeef"]) == b"data"


# ---------------------------------------------------------------------------
# P0-11/P0-17 回归测试：append_bytes 增量缓冲、大产物落盘、cleanup 生命周期
# ---------------------------------------------------------------------------


def test_append_bytes_removes_old_artifact_from_report():
    """append_bytes 产生新 digest 时，旧 artifact 不应残留在报告中。"""
    store = ArtifactStore()
    ref1 = store.put_bytes(b"foo")
    ref2 = store.append_bytes(ref1, b"bar")

    assert ref1 != ref2
    report_data = store.to_report_data()

    # 旧 ref1 不应出现在报告中（已过时，无事件引用）
    assert ref1 not in report_data, "旧 artifact 残留在报告中"
    assert ref2 in report_data
    assert decode_artifact(report_data[ref2]) == b"foobar"


def test_append_bytes_multiple_calls_keep_only_latest():
    """多次 append_bytes 后，只有最新 digest 的 artifact 保留。"""
    store = ArtifactStore()
    ref = store.put_bytes(b"a")
    refs = [ref]
    for chunk in [b"b", b"c", b"d"]:
        ref = store.append_bytes(ref, chunk)
        refs.append(ref)

    report_data = store.to_report_data()

    # 只有最后一个 ref 应该保留
    assert len(report_data) == 1, f"报告中有多余 artifact: {list(report_data)}"
    assert refs[-1] in report_data
    assert decode_artifact(report_data[refs[-1]]) == b"abcd"
    # 中间 ref 不应残留
    for stale in refs[:-1]:
        assert stale not in report_data


def test_append_bytes_preserves_data_integrity_with_limit():
    """append_bytes 的 limit 截断行为应与原 merge_binary_data 一致。"""
    store = ArtifactStore()
    ref = store.put_bytes(b"hello")
    ref = store.append_bytes(ref, b" world", limit=8)

    report_data = store.to_report_data()
    assert decode_artifact(report_data[ref]) == b"hello wo"


def test_append_bytes_dedup_when_digest_unchanged():
    """append_bytes 后 digest 未变时，应正确更新缓冲区。"""
    store = ArtifactStore()
    ref1 = store.put_bytes(b"")
    # 追加空数据，digest 不变
    ref2 = store.append_bytes(ref1, b"")
    assert ref1 == ref2

    # 追加实际数据
    ref3 = store.append_bytes(ref2, b"data")
    report_data = store.to_report_data()
    assert decode_artifact(report_data[ref3]) == b"data"


def test_store_spilled_cleanup_temp_file_on_write_error():
    """_store_spilled 写入失败时应清理临时文件，不泄漏。"""
    store = ArtifactStore()
    large_data = b"x" * (LARGE_ARTIFACT_THRESHOLD + 1)

    with patch("speakeasy.artifacts.os.fdopen") as mock_fdopen:
        mock_fdopen.side_effect = OSError("disk full")
        with pytest.raises(OSError):
            store.put_bytes(large_data)

    # 临时文件不应残留（mkstemp 创建的文件应被清理）
    # 由于 put_bytes 失败，不应有临时文件被记录
    assert store._temp_files == [], "写入失败的临时文件未被清理"


def test_store_spilled_does_not_close_fd_twice():
    """_store_spilled 在 with 块关闭 fd 后不应再次 os.close 导致 OSError 掩盖原始异常。"""
    store = ArtifactStore()
    large_data = b"x" * (LARGE_ARTIFACT_THRESHOLD + 1)

    # 模拟 fh.write 抛出异常，验证 except 块不会因 os.close 已关闭的 fd 而抛 OSError
    original_fdopen = os.fdopen

    def failing_fdopen(fd, *args, **kwargs):
        fh = original_fdopen(fd, *args, **kwargs)
        original_write = fh.write

        def write_with_error(data):
            original_write(data)
            raise OSError("write error after write")

        fh.write = write_with_error
        return fh

    with patch("speakeasy.artifacts.os.fdopen", side_effect=failing_fdopen):
        with pytest.raises(OSError) as exc_info:
            store.put_bytes(large_data)

    # 应该看到原始的 "write error after write"，而不是 "Bad file descriptor"
    assert "write error after write" in str(exc_info.value), (
        f"原始异常被掩盖: {exc_info.value}"
    )


def test_cleanup_removes_all_temp_files():
    """cleanup() 应删除所有落盘的临时文件。"""
    store = ArtifactStore()
    large_data = b"x" * (LARGE_ARTIFACT_THRESHOLD + 1)
    store.put_bytes(large_data)

    temp_files = list(store._temp_files)
    assert len(temp_files) == 1
    assert os.path.exists(temp_files[0])

    store.cleanup()

    for path in temp_files:
        assert not os.path.exists(path), f"临时文件未被清理: {path}"
    assert store._temp_files == []


def test_cleanup_is_safe_when_temp_file_already_deleted():
    """cleanup() 在临时文件已被删除时应静默跳过。"""
    store = ArtifactStore()
    large_data = b"x" * (LARGE_ARTIFACT_THRESHOLD + 1)
    store.put_bytes(large_data)

    temp_files = list(store._temp_files)
    os.unlink(temp_files[0])  # 手动删除

    # 不应抛异常
    store.cleanup()
    assert store._temp_files == []


def test_get_bytes_reads_spilled_file():
    """get_bytes 应能正确读取落盘的大产物。"""
    store = ArtifactStore()
    large_data = b"y" * (LARGE_ARTIFACT_THRESHOLD + 1)
    ref = store.put_bytes(large_data)

    assert store.get_bytes(ref) == large_data

    store.cleanup()


def test_to_report_data_includes_spilled_artifact():
    """to_report_data 应包含落盘的大产物引用。"""
    store = ArtifactStore()
    large_data = b"z" * (LARGE_ARTIFACT_THRESHOLD + 1)
    ref = store.put_bytes(large_data)

    report_data = store.to_report_data()
    assert ref in report_data
    artifact = report_data[ref]
    assert artifact.encoding == "file"
    assert artifact.compression == "none"
    assert artifact.size == len(large_data)

    store.cleanup()


def test_append_bytes_with_spilled_artifact():
    """append_bytes 对落盘的大产物也能正确增量追加。"""
    store = ArtifactStore()
    # 先存一个大产物
    large_data = b"a" * (LARGE_ARTIFACT_THRESHOLD + 1)
    ref1 = store.put_bytes(large_data)

    # 追加数据
    ref2 = store.append_bytes(ref1, b"suffix")

    # 旧 ref1 的临时文件应被清理（或至少不出现在报告中）
    report_data = store.to_report_data()
    assert ref2 in report_data
    assert ref1 not in report_data, "旧的大产物 artifact 残留"

    data = store.get_bytes(ref2)
    assert data == large_data + b"suffix"

    store.cleanup()
