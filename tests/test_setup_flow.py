"""1.1.0 features: server profiles, connection test, end-to-end test, upgrade migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import paramiko
import pytest

from conftest import write_file
from crypto.key_manager import MasterKey, generate_master_key
from services.diagnostics import E2E_STAGES, FAIL, PASS, run_connection_test, run_end_to_end_test
from services.vault import VaultService
from utils.app_paths import AppPaths, migrate_legacy
from utils.config import AppConfig, load_config
from utils.errors import (
    BackupNotAcknowledgedError,
    ConnectionTestRequiredError,
    NoProfileError,
    ValidationError,
)
from utils.friendly import describe_error


@pytest.fixture(scope="module")
def keys():
    return {"host": paramiko.ECDSAKey.generate(bits=256), "evil": paramiko.ECDSAKey.generate(bits=256),
            "client": paramiko.ECDSAKey.generate(bits=256)}


@pytest.fixture
def svc(tmp_path: Path, key: bytes) -> VaultService:
    mk = MasterKey()
    mk.load(key)
    s = VaultService(tmp_path / "home", AppConfig(), mk)
    return s


@pytest.fixture
def sftp(tmp_path, keys):
    from sftp_server import LocalSFTPServer

    root = tmp_path / "sftproot"
    root.mkdir()
    srv = LocalSFTPServer(root, "storageuser", keys["client"], keys["host"], password="correct horse")
    kp = tmp_path / "id_ecdsa"
    keys["client"].write_private_key_file(str(kp))
    yield srv, root, kp
    srv.close()


def sftp_profile(svc, srv, kp, **over):
    values = {"name": "Personal VPS", "backend": "sftp", "host": "127.0.0.1", "port": srv.port,
              "username": "storageuser", "remote_path": "/storage/encrypted/", "auth_method": "key",
              "private_key_path": str(kp)}
    values.update(over)
    return svc.profiles.create(values)


# ---- profiles -------------------------------------------------------------------------

def test_profile_crud_and_active(svc):
    assert svc.needs_setup() and svc.profiles.active() is None
    with pytest.raises(NoProfileError):
        svc.make_backend()
    a = svc.profiles.create({"name": "Backup Server", "backend": "local", "local_path": "/tmp"})
    b = svc.profiles.create({"name": "Office Storage", "backend": "local", "local_path": "/tmp"})
    assert svc.profiles.active().id == a.id
    svc.profiles.set_active(b.id)
    assert svc.profiles.active().id == b.id
    with pytest.raises(ValidationError):
        svc.profiles.create({"name": "office storage", "backend": "local", "local_path": "/x"})
    svc.profiles.delete(b.id)
    assert svc.profiles.active().id == a.id
    with pytest.raises(ValidationError):
        svc.profiles.create({"name": "bad", "backend": "sftp", "host": "h", "port": 22,
                             "username": "u", "remote_path": "/../etc", "auth_method": "key",
                             "private_key_path": "k"})


def test_untested_profile_blocks_transfers(svc):
    p = svc.profiles.create({"name": "VPS", "backend": "local", "local_path": "/tmp"})
    with pytest.raises(ConnectionTestRequiredError):
        svc.make_backend(p)
    svc.db.mark_profile_tested(p.id)
    svc.make_backend(svc.profiles.get(p.id))
    svc.profiles.update(p.id, {"local_path": "/var/tmp"})  # connection-relevant change
    with pytest.raises(ConnectionTestRequiredError):
        svc.make_backend(svc.profiles.get(p.id))
    svc.db.mark_profile_tested(p.id)
    svc.profiles.update(p.id, {"name": "Renamed"})  # cosmetic change keeps test state
    assert svc.profiles.get(p.id).connection_tested_at is not None


def test_host_or_port_change_invalidates_trust(svc):
    p = svc.profiles.create({"name": "VPS", "backend": "sftp", "host": "vps.example.com", "port": 22,
                             "username": "storageuser", "remote_path": "/storage/encrypted/",
                             "auth_method": "password"})
    svc.db.trust_host_key("vps.example.com", 22, "ssh-ed25519", "SHA256:abc")
    svc.profiles.update(p.id, {"port": 2222})
    assert svc.db.get_host_key("vps.example.com", 22) is None
    assert svc.profiles.get(p.id).connection_tested_at is None


def test_shared_endpoint_trust_kept_while_used(svc):
    base = {"backend": "sftp", "host": "vps.example.com", "port": 22, "username": "u",
            "remote_path": "/a/", "auth_method": "password"}
    p1 = svc.profiles.create({**base, "name": "One"})
    svc.profiles.create({**base, "name": "Two"})
    svc.db.trust_host_key("vps.example.com", 22, "ssh-ed25519", "SHA256:abc")
    svc.profiles.update(p1.id, {"host": "other.example.com"})
    assert svc.db.get_host_key("vps.example.com", 22) is not None


def test_secrets_never_in_sqlite(svc, tmp_path):
    p = svc.profiles.create({"name": "VPS", "backend": "sftp", "host": "vps.example.com", "port": 22,
                             "username": "u", "remote_path": "/a/", "auth_method": "password"})
    res = svc.profiles.set_secret(p, "ssh-password", "S3cret-Passw0rd-Value")
    assert svc.profiles.get_secret("ssh-password", p.secret_ident) == "S3cret-Passw0rd-Value"
    # On Windows/macOS/Linux with a secure OS keyring available,
    # the secret may be persisted securely outside the application data directory.
    # On headless/test environments it may remain session-only.
    assert isinstance(res.persisted, bool)

    # The security requirement is that the secret never appears in SQLite,
    # config files, logs, or any other application-owned files.
    for f in svc.paths.root.rglob("*"):
        if f.is_file():
            assert b"S3cret-Passw0rd-Value" not in f.read_bytes()


def test_upload_requires_backup_acknowledgment(tmp_path, key, remote_dir):
    from storage.local import LocalDirectoryBackend

    mk = MasterKey()
    mk.load(key)
    s = VaultService(tmp_path / "h", AppConfig(), mk, backend_factory=lambda: LocalDirectoryBackend(remote_dir))
    out = s.encrypt(write_file(tmp_path / "a", 100))
    with pytest.raises(BackupNotAcknowledgedError):
        s.upload(out.result.file_id)
    s.acknowledge_backup()
    s.upload(out.result.file_id)


# ---- connection + end-to-end tests against a live SFTP server --------------------------

def test_connection_test_full_flow(svc, sftp):
    srv, root, kp = sftp
    p = sftp_profile(svc, srv, kp)
    r = run_connection_test(svc, p)
    assert r.stage("Host Reachable").status == PASS and r.stage("SSH Connected").status == PASS
    assert r.stage("Host Key").status == FAIL and r.host_key is not None
    assert not srv.auth_attempted.is_set(), "no credentials sent before the host key is trusted"
    assert r.stage("Authentication").status != PASS and not r.ok

    svc.db.trust_host_key("127.0.0.1", srv.port, *r.host_key)
    r = run_connection_test(svc, p)
    assert r.stage("Authentication").status == PASS
    assert r.remote_missing and not (root / "storage").exists(), "directory only created on confirmation"

    r = run_connection_test(svc, p, create_remote_dir=True)
    assert r.ok, [(s.name, s.status, s.message) for s in r.stages]
    assert (root / "storage" / "encrypted").is_dir()
    assert list((root / "storage" / "encrypted").iterdir()) == [], "probe deleted"
    assert svc.profiles.get(p.id).connection_tested_at is not None


def test_end_to_end_test_against_sftp(svc, sftp, keys):
    srv, root, kp = sftp
    p = sftp_profile(svc, srv, kp)
    svc.db.trust_host_key("127.0.0.1", srv.port, keys["host"].get_name(),
                          __import__("storage.sftp", fromlist=["x"]).host_key_fingerprint(keys["host"]))
    assert run_connection_test(svc, p, create_remote_dir=True).ok
    seen = []
    r = run_end_to_end_test(svc, svc.profiles.get(p.id), callback=lambda n, st, m: seen.append((n, st)))
    assert [s.status for s in r.stages] == [PASS] * len(E2E_STAGES), [(s.name, s.message) for s in r.stages]
    assert list((root / "storage" / "encrypted").iterdir()) == []
    assert not any(svc.paths.cache.iterdir())
    assert svc.db.list_files() == [], "test data never appears in My Files"


def test_password_auth_and_wrong_password(svc, sftp, keys):
    from storage.sftp import host_key_fingerprint

    srv, root, kp = sftp
    p = sftp_profile(svc, srv, kp, name="Pw", auth_method="password", private_key_path="")
    svc.db.trust_host_key("127.0.0.1", srv.port, keys["host"].get_name(), host_key_fingerprint(keys["host"]))
    svc.profiles.set_secret(p, "ssh-password", "wrong")
    r = run_connection_test(svc, p, create_remote_dir=True)
    assert r.stage("Authentication").status == FAIL and "Authentication failed" in r.stage("Authentication").message
    svc.profiles.set_secret(p, "ssh-password", "correct horse")
    assert run_connection_test(svc, p, create_remote_dir=True).ok


def test_changed_host_key_blocks_test(svc, sftp, keys):
    from storage.sftp import host_key_fingerprint

    srv, _, kp = sftp
    p = sftp_profile(svc, srv, kp)
    svc.db.trust_host_key("127.0.0.1", srv.port, keys["evil"].get_name(), host_key_fingerprint(keys["evil"]))
    r = run_connection_test(svc, p)
    assert r.host_key_changed and r.stage("Host Key").message.startswith("Server host key changed")
    assert not srv.auth_attempted.is_set()


def test_unreachable_server_is_friendly(svc):
    p = svc.profiles.create({"name": "Down", "backend": "sftp", "host": "127.0.0.1", "port": 1,
                             "username": "u", "remote_path": "/a/", "auth_method": "password"})
    r = run_connection_test(svc, p)
    assert r.stage("SSH Connected").status == FAIL
    assert "refused" in r.stage("SSH Connected").message or "reach" in r.stage("SSH Connected").message


def test_friendly_messages_have_no_tracebacks():
    import errno
    import socket

    for exc in (OSError(errno.ENOSPC, "x"), socket.gaierror(), TimeoutError(), ConnectionResetError(),
                sqlite3.OperationalError("locked"), paramiko.AuthenticationException(), ValueError("boom")):
        msg, cat = describe_error(exc)
        assert "Traceback" not in msg and msg and cat
    assert describe_error(OSError(errno.ENOSPC, "x"))[1] == "disk_full"


# ---- upgrade from 1.0 --------------------------------------------------------------------

def _make_v10_install(root: Path, key: bytes, remote_dir: Path) -> str:
    """Create a genuine 1.0-style flat layout using the 1.0 schema."""
    from database.migrations import MIGRATIONS

    root.mkdir(parents=True)
    conn = sqlite3.connect(root / "vault.db")
    conn.executescript("BEGIN;" + MIGRATIONS[0] + "PRAGMA user_version = 1; COMMIT;")
    fid = "ab" * 32
    conn.execute(
        "INSERT INTO files(file_id, original_filename, encrypted_filename, original_size, encrypted_size,"
        " encrypted_hash, created_at, uploaded_at, server_path, status, key_fingerprint, local_container_path)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (fid, "tax-2025.pdf", fid + ".wezenc", 10, 100, "0" * 64, "2026-01-01", "2026-01-01",
         "/storage/encrypted/" + fid + ".wezenc", "uploaded", "AB42-F731-0EF2-91CD", None),
    )
    conn.execute("INSERT INTO servers(host, port, key_type, host_key_fingerprint, trusted_at)"
                 " VALUES ('vps.example.com', 22, 'ssh-ed25519', 'SHA256:trusted', '2026-01-01')")
    conn.execute("INSERT INTO used_nonces VALUES ('deadbeef', '2026-01-01', ?)", (fid,))
    conn.commit()
    conn.close()
    (root / "config.toml").write_text(
        '[server]\nbackend = "sftp"\nhost = "vps.example.com"\nport = 22\nusername = "storageuser"\n'
        'remote_path = "/storage/encrypted/"\nprivate_key_path = "/home/u/.ssh/id_ed25519"\n'
        '[privacy]\nclipboard_clear_seconds = 45\n', encoding="utf-8")
    (root / "logs").mkdir()
    (root / "logs" / "wezcrypt.log").write_text("{}\n")
    return fid


@pytest.mark.parametrize("same_root", [True, False])
def test_upgrade_from_v10_preserves_state(tmp_path, key, remote_dir, same_root):
    old = tmp_path / ("new" if same_root else "old-appdata")
    fid = _make_v10_install(old, key, remote_dir)
    paths = AppPaths.from_root(tmp_path / "new")
    src = migrate_legacy(paths, extra_roots=[] if same_root else [old])
    assert src is not None
    cfg = load_config(paths.config_file)
    assert cfg.privacy.clipboard_clear_seconds == 45 and cfg.server.host == "vps.example.com"
    mk = MasterKey()
    mk.load(generate_master_key())
    svc = VaultService(paths, cfg, mk)
    rec = svc.db.get_file(fid)
    assert rec is not None and rec.original_filename == "tax-2025.pdf" and rec.status == "uploaded"
    assert svc.db.get_host_key("vps.example.com", 22) == ("ssh-ed25519", "SHA256:trusted")
    assert svc.nonces.count() == 1, "nonce reservations survive upgrades (no prefix reuse)"
    prof = svc.profiles.active()
    assert prof is not None and prof.host == "vps.example.com" and prof.auth_method == "key"
    assert prof.connection_tested_at is not None, "a 1.0 install that uploaded files stays usable"
    # a second start must not migrate again or overwrite anything
    assert migrate_legacy(paths, extra_roots=[] if same_root else [old]) is None
    assert len(VaultService(paths, cfg, mk).profiles.list()) == 1


def test_fresh_install_does_not_touch_existing_state(tmp_path):
    paths = AppPaths.from_root(tmp_path / "root")
    paths.db_path.write_bytes(b"")  # existing new-layout DB
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "vault.db").write_bytes(b"old")
    assert migrate_legacy(paths, extra_roots=[legacy]) is None
    assert paths.db_path.read_bytes() == b""
