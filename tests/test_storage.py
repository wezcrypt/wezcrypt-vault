from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest

from conftest import write_file
from storage.local import LocalDirectoryBackend
from utils.errors import NetworkInterruptedError, UploadVerificationError, ValidationError

NAME = "ab" * 32 + ".wezenc"


class _FailingWriter(io.RawIOBase):
    def __init__(self, inner, budget: list[int]):
        self.inner, self.budget = inner, budget

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:
        if self.budget[0] <= 0:
            raise ConnectionResetError("simulated network drop")
        self.budget[0] -= len(b)
        return self.inner.write(b)

    def close(self) -> None:
        self.inner.close()
        super().close()


class FlakyBackend(LocalDirectoryBackend):
    """Drops the connection after ``budget`` bytes have been written."""

    def __init__(self, root: Path, budget: int):
        super().__init__(root)
        self.budget = [budget]

    def _open_write(self, path: str, append: bool):
        return _FailingWriter(super()._open_write(path, append), self.budget)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_upload_download_round_trip(tmp_path, remote_dir):
    src = write_file(tmp_path / "c.bin", 3_000_000)
    be = LocalDirectoryBackend(remote_dir)
    r = be.upload(src, NAME, sha(src))
    assert r.size == src.stat().st_size and not r.already_present
    assert not (remote_dir / (NAME + ".part")).exists()
    dst = tmp_path / "dl.part"
    be.download(NAME, dst)
    assert dst.read_bytes() == src.read_bytes()


def test_object_names_must_be_file_ids(tmp_path, remote_dir):
    be = LocalDirectoryBackend(remote_dir)
    src = write_file(tmp_path / "c.bin", 10)
    for bad in ("secret.docx", "../../etc/passwd.wezenc", "AB" * 32 + ".wezenc"):
        with pytest.raises(ValidationError):
            be.upload(src, bad, sha(src))


def test_network_interruption_keeps_part_and_resumes(tmp_path, remote_dir):
    src = write_file(tmp_path / "c.bin", 2_000_000)
    flaky = FlakyBackend(remote_dir, budget=700_000)
    with pytest.raises(NetworkInterruptedError):
        flaky.upload(src, NAME, sha(src))
    part = remote_dir / (NAME + ".part")
    assert part.exists() and 0 < part.stat().st_size < src.stat().st_size
    assert not (remote_dir / NAME).exists(), "incomplete ciphertext must never become the final object"
    partial = part.stat().st_size
    r = LocalDirectoryBackend(remote_dir).upload(src, NAME, sha(src))
    assert r.resumed_from == partial
    assert (remote_dir / NAME).read_bytes() == src.read_bytes()


def test_resume_refuses_tampered_partial(tmp_path, remote_dir):
    src = write_file(tmp_path / "c.bin", 1_000_000)
    part = remote_dir / (NAME + ".part")
    data = bytearray(src.read_bytes()[:400_000])
    data[100] ^= 0xFF
    part.write_bytes(bytes(data))
    r = LocalDirectoryBackend(remote_dir).upload(src, NAME, sha(src))
    assert r.resumed_from == 0, "unverifiable partial upload must be discarded"
    assert (remote_dir / NAME).read_bytes() == src.read_bytes()


def test_resume_refuses_oversized_partial(tmp_path, remote_dir):
    src = write_file(tmp_path / "c.bin", 1000)
    (remote_dir / (NAME + ".part")).write_bytes(b"x" * 5000)
    r = LocalDirectoryBackend(remote_dir).upload(src, NAME, sha(src))
    assert r.resumed_from == 0


def test_refuses_to_overwrite_different_object(tmp_path, remote_dir):
    src = write_file(tmp_path / "c.bin", 1000)
    (remote_dir / NAME).write_bytes(b"other content")
    with pytest.raises(UploadVerificationError):
        LocalDirectoryBackend(remote_dir).upload(src, NAME, sha(src))


def test_identical_existing_object_is_idempotent(tmp_path, remote_dir):
    src = write_file(tmp_path / "c.bin", 1000)
    be = LocalDirectoryBackend(remote_dir)
    be.upload(src, NAME, sha(src))
    assert be.upload(src, NAME, sha(src)).already_present


def test_upload_hash_mismatch_detected(tmp_path, remote_dir):
    src = write_file(tmp_path / "c.bin", 1000)
    with pytest.raises(UploadVerificationError):
        LocalDirectoryBackend(remote_dir).upload(src, NAME, "0" * 64)
    assert not (remote_dir / NAME).exists()


def test_download_resume(tmp_path, remote_dir):
    src = write_file(tmp_path / "c.bin", 1_500_000)
    (remote_dir / NAME).write_bytes(src.read_bytes())
    dst = tmp_path / "dl.part"
    dst.write_bytes(src.read_bytes()[:600_000])
    LocalDirectoryBackend(remote_dir).download(NAME, dst)
    assert dst.read_bytes() == src.read_bytes()
