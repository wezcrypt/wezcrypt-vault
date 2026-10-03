from __future__ import annotations

import hashlib
from pathlib import Path

import paramiko
import pytest

from conftest import write_file
from database.database import Database
from storage.sftp import HostKeyVerifier, SFTPBackend, fetch_host_key, host_key_fingerprint
from utils.errors import HostKeyChangedError, HostKeyUnknownError, RemoteDirectoryMissingError

NAME = "cd" * 32 + ".wezenc"


@pytest.fixture(scope="module")
def keys():
    return {
        "host": paramiko.ECDSAKey.generate(bits=256),
        "evil": paramiko.ECDSAKey.generate(bits=256),
        "client": paramiko.ECDSAKey.generate(bits=256),
    }


@pytest.fixture
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "v.db")


def test_unknown_host_key_requires_trust(db, keys):
    v = HostKeyVerifier(db)
    with pytest.raises(HostKeyUnknownError) as ei:
        v.verify("srv", 22, keys["host"])
    assert ei.value.fingerprint == host_key_fingerprint(keys["host"])
    db.trust_host_key("srv", 22, keys["host"].get_name(), ei.value.fingerprint)
    assert v.verify("srv", 22, keys["host"]) == ei.value.fingerprint


def test_ssh_fingerprint_mismatch_blocks(db, keys):
    v = HostKeyVerifier(db)
    db.trust_host_key("srv", 22, keys["host"].get_name(), host_key_fingerprint(keys["host"]))
    with pytest.raises(HostKeyChangedError) as ei:
        v.verify("srv", 22, keys["evil"])
    assert str(ei.value) == "Server host key changed. Connection blocked for security."


def test_trusted_key_cannot_be_silently_replaced(db, keys):
    db.trust_host_key("srv", 22, keys["host"].get_name(), host_key_fingerprint(keys["host"]))
    with pytest.raises(HostKeyChangedError):
        db.trust_host_key("srv", 22, keys["evil"].get_name(), host_key_fingerprint(keys["evil"]))


def test_fingerprint_is_per_port(db, keys):
    db.trust_host_key("srv", 22, keys["host"].get_name(), host_key_fingerprint(keys["host"]))
    with pytest.raises(HostKeyUnknownError):
        HostKeyVerifier(db).verify("srv", 2222, keys["host"])


def _server(tmp_path: Path, keys, host_key):
    from sftp_server import LocalSFTPServer

    root = tmp_path / "sftproot"
    root.mkdir(exist_ok=True)
    return LocalSFTPServer(root, "storage", keys["client"], host_key), root


def _backend(db, tmp_path, keys, port) -> SFTPBackend:
    kp = tmp_path / "id_ecdsa"
    if not kp.exists():
        keys["client"].write_private_key_file(str(kp))
    return SFTPBackend(db, host="127.0.0.1", port=port, username="storage",
                       remote_dir="/storage/encrypted/", private_key_path=str(kp), timeout=10)


def test_live_sftp_strict_host_key_flow(tmp_path, db, keys):
    srv, root = _server(tmp_path, keys, keys["host"])
    try:
        be = _backend(db, tmp_path, keys, srv.port)
        with pytest.raises(HostKeyUnknownError) as ei:
            be.connect()
        assert not srv.auth_attempted.is_set(), "no credentials before host key is trusted"
        assert fetch_host_key("127.0.0.1", srv.port)[1] == ei.value.fingerprint
        db.trust_host_key("127.0.0.1", srv.port, ei.value.key_type, ei.value.fingerprint)

        src = write_file(tmp_path / "c.wezenc", 1_234_567)
        digest = hashlib.sha256(src.read_bytes()).hexdigest()
        b = _backend(db, tmp_path, keys, srv.port)
        with pytest.raises(RemoteDirectoryMissingError):
            b.connect()  # never created implicitly
        b.step_transport()
        b.step_verify_host_key()
        b.step_authenticate()
        b.step_open_sftp()
        b.create_remote_dir()  # explicit, user-confirmed action
        b.close()
        with _backend(db, tmp_path, keys, srv.port) as b:
            r = b.upload(src, NAME, digest)
            assert r.size == src.stat().st_size
            dl = tmp_path / "dl.part"
            b.download(NAME, dl)
            assert dl.read_bytes() == src.read_bytes()
            b.delete(NAME)
        assert (root / "storage" / "encrypted").is_dir()
        assert list((root / "storage" / "encrypted").iterdir()) == []
    finally:
        srv.close()


def test_live_sftp_changed_host_key_blocked(tmp_path, db, keys):
    srv, _ = _server(tmp_path, keys, keys["evil"])
    try:
        db.trust_host_key("127.0.0.1", srv.port, keys["host"].get_name(), host_key_fingerprint(keys["host"]))
        with pytest.raises(HostKeyChangedError):
            _backend(db, tmp_path, keys, srv.port).connect()
        assert not srv.auth_attempted.is_set(), "credentials must never reach an impostor server"
    finally:
        srv.close()


def test_live_sftp_resume_after_interruption(tmp_path, db, keys):
    srv, root = _server(tmp_path, keys, keys["host"])
    try:
        db.trust_host_key("127.0.0.1", srv.port, keys["host"].get_name(), host_key_fingerprint(keys["host"]))
        src = write_file(tmp_path / "c.wezenc", 3_000_000)
        digest = hashlib.sha256(src.read_bytes()).hexdigest()
        remote_part = root / "storage" / "encrypted" / (NAME + ".part")
        remote_part.parent.mkdir(parents=True, exist_ok=True)
        remote_part.write_bytes(src.read_bytes()[:1_000_000])  # left by a dropped connection
        with _backend(db, tmp_path, keys, srv.port) as b:
            r = b.upload(src, NAME, digest)
        assert r.resumed_from == 1_000_000
        assert (root / "storage" / "encrypted" / NAME).read_bytes() == src.read_bytes()
    finally:
        srv.close()
