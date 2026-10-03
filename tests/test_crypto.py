from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

import pytest

import crypto.container as container_mod
from conftest import SMALL_CHUNK, write_file
from crypto.aes import TAG_LEN
from crypto.chunks import MAX_CHUNKS, chunk_nonce, total_chunks_for
from crypto.container import HEADER_LEN, decrypt_container, encrypt_file, read_header
from crypto.key_manager import generate_master_key
from crypto.nonce_manager import NonceManager
from utils.errors import (
    AuthenticationFailedError,
    ContainerFormatError,
    NonceReuseError,
    UnsupportedVersionError,
    WrongKeyError,
)

REJECT = (AuthenticationFailedError, ContainerFormatError)


def encrypt_to(tmp: Path, src: Path, key: bytes, nonces: NonceManager, chunk: int = SMALL_CHUNK, **kw) -> Path:
    fid = os.urandom(32)
    res = nonces.reserve(fid)
    dst = tmp / f"{fid.hex()}.wezenc"
    with dst.open("wb") as fh:
        encrypt_file(src, fh, key=key, file_id=fid, reservation=res, chunk_size=chunk, **kw)
    return dst


def out_dir(tmp: Path) -> Path:
    d = tmp / "out"
    d.mkdir(exist_ok=True)
    return d


def assert_no_output(tmp: Path) -> None:
    assert list(out_dir(tmp).iterdir()) == [], "no plaintext or .part may remain after a failure"


@pytest.mark.parametrize("size", [0, 1, SMALL_CHUNK - 1, SMALL_CHUNK, SMALL_CHUNK + 1, SMALL_CHUNK * 7 + 123])
def test_round_trip(tmp_path, key, nonces, size):
    src = write_file(tmp_path / "plain.bin", size)
    c = encrypt_to(tmp_path, src, key, nonces)
    r = decrypt_container(c, out_dir(tmp_path), key=key)
    assert r.output_path.read_bytes() == src.read_bytes()
    assert r.original_name == "plain.bin"
    assert r.output_path.parent == out_dir(tmp_path).resolve()
    assert c.stat().st_size == HEADER_LEN + read_header(c).metadata_ct_len + size + TAG_LEN * total_chunks_for(size, SMALL_CHUNK)


def test_zero_byte_file(tmp_path, key, nonces):
    src = write_file(tmp_path / "empty", 0)
    c = encrypt_to(tmp_path, src, key, nonces)
    assert read_header(c).total_chunks == 1
    assert decrypt_container(c, out_dir(tmp_path), key=key).output_path.read_bytes() == b""


def test_one_byte_file(tmp_path, key, nonces):
    src = tmp_path / "one"
    src.write_bytes(b"\x42")
    c = encrypt_to(tmp_path, src, key, nonces)
    assert decrypt_container(c, out_dir(tmp_path), key=key).output_path.read_bytes() == b"\x42"


def test_multi_chunk_file(tmp_path, key, nonces):
    src = write_file(tmp_path / "multi.dat", SMALL_CHUNK * 25 + 17)
    c = encrypt_to(tmp_path, src, key, nonces)
    assert read_header(c).total_chunks == 26
    assert decrypt_container(c, out_dir(tmp_path), key=key).output_path.read_bytes() == src.read_bytes()


def test_large_file_default_chunks(tmp_path, key, nonces):
    size = 64 * 1024 * 1024 + 5  # 9 chunks at the 8 MiB default
    src = write_file(tmp_path / "big.iso", size)
    c = encrypt_to(tmp_path, src, key, nonces, chunk=8 * 1024 * 1024)
    assert read_header(c).total_chunks == 9
    r = decrypt_container(c, out_dir(tmp_path), key=key)
    h1 = hashlib.sha256(src.read_bytes()).hexdigest()
    assert r.sha256 == h1 and r.size == size
    assert hashlib.sha256(r.output_path.read_bytes()).hexdigest() == h1


def test_plaintext_not_in_container(tmp_path, key, nonces):
    src = tmp_path / "secret-report.txt"
    src.write_bytes(b"TOP SECRET PLAINTEXT CONTENT " * 100)
    raw = encrypt_to(tmp_path, src, key, nonces).read_bytes()
    assert b"TOP SECRET" not in raw
    assert b"secret-report" not in raw and b".txt" not in raw
    assert key not in raw


def test_unicode_filename(tmp_path, key, nonces):
    src = tmp_path / "отчёт_数据_🔒.pdf"
    src.write_bytes(b"unicode")
    r = decrypt_container(encrypt_to(tmp_path, src, key, nonces), out_dir(tmp_path), key=key)
    assert r.original_name == "отчёт_数据_🔒.pdf"
    assert r.output_path.name == "отчёт_数据_🔒.pdf"


def test_very_long_filename(tmp_path, key, nonces):
    src = tmp_path / ("ä" * 120 + ".bin")  # 240 bytes UTF-8 + ext
    src.write_bytes(b"x")
    r = decrypt_container(encrypt_to(tmp_path, src, key, nonces), out_dir(tmp_path), key=key)
    assert len(r.output_path.name.encode()) <= 200 and r.output_path.name.endswith(".bin")


def test_wrong_master_key(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", 1000), key, nonces)
    with pytest.raises(WrongKeyError):
        decrypt_container(c, out_dir(tmp_path), key=generate_master_key())
    assert_no_output(tmp_path)


def test_forged_fingerprint_still_fails_authentication(tmp_path, key, nonces):
    other = generate_master_key()
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", 1000), key, nonces)
    data = bytearray(c.read_bytes())
    from crypto.key_manager import key_fingerprint
    data[60:76] = key_fingerprint(other)
    c.write_bytes(bytes(data))
    with pytest.raises(AuthenticationFailedError):
        decrypt_container(c, out_dir(tmp_path), key=other)
    assert_no_output(tmp_path)


def _tamper(path: Path, offset: int) -> None:
    data = bytearray(path.read_bytes())
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))


def test_modified_ciphertext(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", SMALL_CHUNK * 3), key, nonces)
    base = HEADER_LEN + read_header(c).metadata_ct_len
    _tamper(c, base + SMALL_CHUNK + 100)  # inside chunk 1
    with pytest.raises(AuthenticationFailedError):
        decrypt_container(c, out_dir(tmp_path), key=key)
    assert_no_output(tmp_path)


def test_modified_gcm_tag(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", SMALL_CHUNK * 2), key, nonces)
    _tamper(c, c.stat().st_size - 1)  # last byte = last chunk's tag
    with pytest.raises(AuthenticationFailedError):
        decrypt_container(c, out_dir(tmp_path), key=key)
    assert_no_output(tmp_path)


def test_modified_metadata(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", 100), key, nonces)
    _tamper(c, HEADER_LEN + 5)
    with pytest.raises(AuthenticationFailedError):
        decrypt_container(c, out_dir(tmp_path), key=key)


@pytest.mark.parametrize("offset", [12, 30, 44, 50])  # file id bytes, nonce prefix bytes
def test_modified_header_file_id_and_nonce(tmp_path, key, nonces, offset):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", 100), key, nonces)
    _tamper(c, offset)
    with pytest.raises(AuthenticationFailedError):
        decrypt_container(c, out_dir(tmp_path), key=key)


def test_modified_version_rejected(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", 100), key, nonces)
    data = bytearray(c.read_bytes())
    data[8:10] = struct.pack(">H", 2)
    c.write_bytes(bytes(data))
    with pytest.raises(UnsupportedVersionError):
        decrypt_container(c, out_dir(tmp_path), key=key)


def test_unexpected_algorithm_rejected(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", 100), key, nonces)
    data = bytearray(c.read_bytes())
    data[10] = 7
    c.write_bytes(bytes(data))
    with pytest.raises(ContainerFormatError):
        decrypt_container(c, out_dir(tmp_path), key=key)


def test_corrupt_container_magic(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", 100), key, nonces)
    data = bytearray(c.read_bytes())
    data[0:8] = b"NOTWEZCR"
    c.write_bytes(bytes(data))
    with pytest.raises(ContainerFormatError):
        decrypt_container(c, out_dir(tmp_path), key=key)


def test_random_garbage_container(tmp_path, key):
    c = tmp_path / "junk.wezenc"
    c.write_bytes(os.urandom(5000))
    with pytest.raises(ContainerFormatError):
        decrypt_container(c, out_dir(tmp_path), key=key)


def test_huge_declared_lengths_rejected(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", 100), key, nonces)
    for off, value in ((52, 0xFFFFFFFF), (56, 0), (76, 0xFFFFFFFF), (56, 0xFFFFFFFF)):
        data = bytearray(c.read_bytes())
        data[off:off + 4] = struct.pack(">I", value)
        bad = tmp_path / f"bad{off}{value}.wezenc"
        bad.write_bytes(bytes(data))
        with pytest.raises(REJECT):
            decrypt_container(bad, out_dir(tmp_path), key=key)
    assert_no_output(tmp_path)


@pytest.mark.parametrize("cut", [1, 10, TAG_LEN, SMALL_CHUNK + TAG_LEN])
def test_truncated_container(tmp_path, key, nonces, cut):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", SMALL_CHUNK * 3 + 50), key, nonces)
    data = c.read_bytes()
    c.write_bytes(data[:-cut])
    with pytest.raises(REJECT):
        decrypt_container(c, out_dir(tmp_path), key=key)
    assert_no_output(tmp_path)


def test_truncated_header(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", 10), key, nonces)
    c.write_bytes(c.read_bytes()[:40])
    with pytest.raises(ContainerFormatError):
        decrypt_container(c, out_dir(tmp_path), key=key)


def test_trailing_data_rejected(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", 100), key, nonces)
    c.write_bytes(c.read_bytes() + b"\x00")
    with pytest.raises(ContainerFormatError):
        decrypt_container(c, out_dir(tmp_path), key=key)


def _chunks(c: Path) -> tuple[bytes, list[bytes]]:
    data = c.read_bytes()
    base = HEADER_LEN + read_header(c).metadata_ct_len
    step = SMALL_CHUNK + TAG_LEN
    body = data[base:]
    return data[:base], [body[i:i + step] for i in range(0, len(body), step)]


def test_reordered_chunks(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", SMALL_CHUNK * 4), key, nonces)
    head, ch = _chunks(c)
    ch[1], ch[2] = ch[2], ch[1]
    c.write_bytes(head + b"".join(ch))
    with pytest.raises(AuthenticationFailedError):
        decrypt_container(c, out_dir(tmp_path), key=key)
    assert_no_output(tmp_path)


def test_duplicated_chunk(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", SMALL_CHUNK * 4), key, nonces)
    head, ch = _chunks(c)
    ch[2] = ch[1]
    c.write_bytes(head + b"".join(ch))
    with pytest.raises(AuthenticationFailedError):
        decrypt_container(c, out_dir(tmp_path), key=key)


def test_inserted_duplicate_chunk(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", SMALL_CHUNK * 4), key, nonces)
    head, ch = _chunks(c)
    ch.insert(1, ch[1])
    c.write_bytes(head + b"".join(ch))
    with pytest.raises(REJECT):
        decrypt_container(c, out_dir(tmp_path), key=key)


def test_missing_chunk(tmp_path, key, nonces):
    c = encrypt_to(tmp_path, write_file(tmp_path / "a", SMALL_CHUNK * 4), key, nonces)
    head, ch = _chunks(c)
    del ch[2]
    c.write_bytes(head + b"".join(ch))
    with pytest.raises(REJECT):
        decrypt_container(c, out_dir(tmp_path), key=key)
    assert_no_output(tmp_path)


def test_chunk_swapped_between_files(tmp_path, key, nonces):
    src = write_file(tmp_path / "a", SMALL_CHUNK * 2)
    c1 = encrypt_to(tmp_path, src, key, nonces)
    c2 = encrypt_to(tmp_path, src, key, nonces)
    h1, ch1 = _chunks(c1)
    _, ch2 = _chunks(c2)
    c1.write_bytes(h1 + ch2[0] + ch1[1])
    with pytest.raises(AuthenticationFailedError):
        decrypt_container(c1, out_dir(tmp_path), key=key)


def test_chunk_counter_overflow_stops_encryption(tmp_path, key, nonces):
    src = write_file(tmp_path / "a", SMALL_CHUNK * 4)
    with pytest.raises(NonceReuseError):
        encrypt_to(tmp_path, src, key, nonces, max_chunks=3)
    with pytest.raises(NonceReuseError):
        chunk_nonce(b"\x00" * 8, MAX_CHUNKS)
    with pytest.raises(NonceReuseError):
        chunk_nonce(b"\x00" * 8, -1)
    with pytest.raises(NonceReuseError):
        total_chunks_for(SMALL_CHUNK * (MAX_CHUNKS + 1), SMALL_CHUNK)


def test_reservation_cannot_be_reused(tmp_path, key, nonces):
    src = write_file(tmp_path / "a", 100)
    fid = os.urandom(32)
    res = nonces.reserve(fid)
    with (tmp_path / "1").open("wb") as fh:
        encrypt_file(src, fh, key=key, file_id=fid, reservation=res, chunk_size=SMALL_CHUNK)
    with pytest.raises(NonceReuseError), (tmp_path / "2").open("wb") as fh:
        encrypt_file(src, fh, key=key, file_id=fid, reservation=res, chunk_size=SMALL_CHUNK)


def test_reservation_for_other_file_rejected(tmp_path, key, nonces):
    src = write_file(tmp_path / "a", 100)
    res = nonces.reserve(os.urandom(32))
    with pytest.raises(NonceReuseError), (tmp_path / "1").open("wb") as fh:
        encrypt_file(src, fh, key=key, file_id=os.urandom(32), reservation=res, chunk_size=SMALL_CHUNK)


def test_every_chunk_nonce_unique_across_files(tmp_path, key, nonces):
    seen = set()
    for _ in range(50):
        c = encrypt_to(tmp_path, write_file(tmp_path / "a", SMALL_CHUNK * 3), key, nonces)
        h = read_header(c)
        for i in range(h.total_chunks):
            n = chunk_nonce(h.nonce_prefix, i)
            assert n not in seen
            seen.add(n)


def test_malicious_filename_cannot_escape(tmp_path, key, nonces, monkeypatch):
    # Build a container whose authenticated metadata carries a hostile name.
    for hostile in ("../../Windows/System32/file.exe", "/etc/passwd", "C:\\evil\\x.dll", "CON", "a\x00b"):
        monkeypatch.setattr(container_mod, "sanitize_filename", lambda n, h=hostile: h)
        src = write_file(tmp_path / "a", 10)
        c = encrypt_to(tmp_path, src, key, nonces)
        monkeypatch.undo()
        r = decrypt_container(c, out_dir(tmp_path), key=key)
        assert r.output_path.parent == out_dir(tmp_path).resolve()
        assert "/" not in r.output_path.name and "\\" not in r.output_path.name
        assert r.output_path.name.upper() != "CON"
    assert not (tmp_path / "Windows").exists()
