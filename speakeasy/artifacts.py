import hashlib
import os
import tempfile
import zlib
from base64 import b64decode, b64encode

from speakeasy.report import DataArtifact

MAX_EMBEDDED_FILE_SIZE = 10 * 1024 * 1024

# 超过该阈值（1MB）的产物落盘到临时文件，避免内存膨胀
LARGE_ARTIFACT_THRESHOLD = 1 * 1024 * 1024


class ArtifactStore:
    def __init__(self):
        # 已压缩的产物，键为 sha256
        self._artifacts: dict[str, DataArtifact] = {}
        # 增量合并用的原始缓冲区，键为 sha256；延迟压缩到 to_report_data
        self._raw: dict[str, bytearray] = {}
        # 大产物落盘的临时文件路径列表，用于 cleanup
        self._temp_files: list[str] = []

    def _store_compressed(self, digest: str, data: bytes) -> None:
        """压缩并以 base64 形式存储产物。"""
        if digest in self._artifacts:
            return
        compressed = zlib.compress(data)
        self._artifacts[digest] = DataArtifact(
            compression="zlib",
            encoding="base64",
            size=len(data),
            data=b64encode(compressed).decode("ascii"),
        )

    def _store_spilled(self, digest: str, data: bytes) -> None:
        """将大产物写入临时文件，报告中仅存文件引用。"""
        if digest in self._artifacts:
            return
        fd, path = tempfile.mkstemp(prefix="speakeasy_art_", suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        except Exception:
            os.close(fd)
            raise
        self._temp_files.append(path)
        self._artifacts[digest] = DataArtifact(
            compression="none",
            encoding="file",
            size=len(data),
            data=path,
        )

    def put_bytes(self, data: bytes) -> str:
        """存储二进制产物，返回 sha256 引用。大产物自动落盘。"""
        digest = hashlib.sha256(data).hexdigest()
        if digest not in self._artifacts:
            if len(data) > LARGE_ARTIFACT_THRESHOLD:
                self._store_spilled(digest, data)
            else:
                self._store_compressed(digest, data)
        return digest

    def append_bytes(self, ref: str, data: bytes, limit: int | None = None) -> str:
        """增量追加到已有产物的原始缓冲区，延迟压缩。

        首次追加时解压一次以建立原始缓冲区，后续追加 O(1) 均摊。
        最终压缩在 to_report_data 中统一完成。
        """
        if ref in self._raw:
            raw = self._raw[ref]
        else:
            raw = bytearray(self.get_bytes(ref))
        raw.extend(data)
        if limit and len(raw) > limit:
            del raw[limit:]
        new_digest = hashlib.sha256(bytes(raw)).hexdigest()
        if new_digest != ref:
            self._raw[new_digest] = raw
            self._raw.pop(ref, None)
        else:
            self._raw[ref] = raw
        return new_digest

    def get_bytes(self, artifact_ref: str) -> bytes:
        """根据引用获取原始字节。优先读原始缓冲区，其次解压产物。"""
        if artifact_ref in self._raw:
            return bytes(self._raw[artifact_ref])
        artifact = self._artifacts[artifact_ref]
        if artifact.encoding == "file":
            with open(artifact.data, "rb") as fh:
                return fh.read()
        if artifact.compression != "zlib":
            raise ValueError(f"Unsupported compression: {artifact.compression}")
        if artifact.encoding != "base64":
            raise ValueError(f"Unsupported encoding: {artifact.encoding}")
        return zlib.decompress(b64decode(artifact.data))

    def to_report_data(self) -> dict[str, DataArtifact]:
        """生成报告数据。将未压缩的原始缓冲区统一压缩后返回。"""
        for digest, raw in self._raw.items():
            if digest not in self._artifacts:
                data = bytes(raw)
                if len(data) > LARGE_ARTIFACT_THRESHOLD:
                    self._store_spilled(digest, data)
                else:
                    self._store_compressed(digest, data)
        self._raw.clear()
        return dict(self._artifacts)

    def cleanup(self) -> None:
        """清理落盘的临时文件。"""
        for path in self._temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass
        self._temp_files.clear()
