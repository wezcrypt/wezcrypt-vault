from __future__ import annotations

import base64
import re

import pytest

from crypto.key_manager import (
    MasterKey,
    decode_recovery_key,
    encode_recovery_key,
    extract_key_from_backup_text,
    format_fingerprint,
    generate_master_key,
    key_fingerprint,
    recovery_file_text,
)
from utils.errors import InvalidRecoveryKeyError, KeyNotLoadedError


def test_key_is_256_bits_and_random():
    keys = {generate_master_key() for _ in range(1000)}
    assert len(keys) == 1000
    assert all(len(k) == 32 for k in keys)


def test_recovery_round_trip_exact_bytes():
    for _ in range(200):
        k = generate_master_key()
        s = encode_recovery_key(k)
        assert re.fullmatch(r"wezcrypt-v1-[A-Za-z0-9_-]{43}-[0-9a-f]{8}", s)
        assert decode_recovery_key(s) == k
        assert decode_recovery_key("  " + s[:20] + "\n" + s[20:] + " ") == k  # whitespace tolerant


def test_recovery_without_checksum_accepted():
    k = generate_master_key()
    s = encode_recovery_key(k).rsplit("-", 1)[0]
    assert decode_recovery_key(s) == k


@pytest.mark.parametrize("bad", [
    "", "wezcrypt-v1-", "wezcrypt-v2-" + "A" * 43, "hello",
    "wezcrypt-v1-" + "A" * 42, "wezcrypt-v1-" + "A" * 44, "wezcrypt-v1-" + "!" * 43,
    "x" * 500,
])
def test_invalid_recovery_keys(bad):
    with pytest.raises(InvalidRecoveryKeyError):
        decode_recovery_key(bad)


def test_checksum_detects_typo():
    s = encode_recovery_key(generate_master_key())
    body_char = s[15]
    typo = s[:15] + ("B" if body_char != "B" else "C") + s[16:]
    with pytest.raises(InvalidRecoveryKeyError):
        decode_recovery_key(typo)


def test_non_canonical_base64_rejected():
    k = bytes(32)
    body = base64.urlsafe_b64encode(k).decode().rstrip("=")
    noncanon = body[:-1] + "B"  # sets unused trailing bits
    with pytest.raises(InvalidRecoveryKeyError):
        decode_recovery_key("wezcrypt-v1-" + noncanon)


def test_fingerprint_format_and_not_key():
    k = generate_master_key()
    fp = key_fingerprint(k)
    assert len(fp) == 16 and fp != k[:16]
    assert re.fullmatch(r"[0-9A-F]{4}(-[0-9A-F]{4}){3}", format_fingerprint(fp))


def test_recovery_file_contents():
    k = generate_master_key()
    text = recovery_file_text(k)
    assert "Version: 1" in text and "Key ID: " + format_fingerprint(key_fingerprint(k)) in text
    assert extract_key_from_backup_text(text) == k
    assert "password" not in text.lower() and "host" not in text.lower()


def test_master_key_lock_wipes_state():
    mk = MasterKey()
    k = generate_master_key()
    mk.load(k)
    buf = mk._key
    assert mk.matches(k)
    mk.lock()
    assert not mk.is_loaded
    assert buf is not None and all(b == 0 for b in buf)
    with pytest.raises(KeyNotLoadedError):
        mk.material()


def test_master_key_never_silently_replaced():
    mk = MasterKey()
    mk.load(generate_master_key())
    with pytest.raises(InvalidRecoveryKeyError):
        mk.load(generate_master_key())
    mk.load(generate_master_key(), replace=True)


def test_wrong_length_rejected():
    with pytest.raises(InvalidRecoveryKeyError):
        MasterKey().load(b"\x00" * 16)
