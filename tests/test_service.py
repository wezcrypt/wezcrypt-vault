from __future__ import annotations

import os
import sqlite3
import ssl
from pathlib import Path

import pytest

from conftest import write_file
from crypto.key_manager import MasterKey, encode_recovery_key, generate_master_key
from services.vault import VaultService
from storage.https import HTTPSBackend, make_tls_context
from storage.local import LocalDirectoryBackend
from utils.config import AppConfig, load_config, save_config
from utils.errors import (
    AuthenticationFailedError,
    ConfigError,
    IntegrityError,
    KeyNotLoadedError,
    NetworkInterruptedError,
    WrongKeyError,
)
from utils.logging import recent_lines
from test_storage import FlakyBackend


def outdir(tmp: Path) -> Path:
    d = tmp / "restored"
    d.mkdir(exist_ok=True)
    return d


def test_end_to_end(service: VaultService, tmp_path, remote_dir):
    src = write_file(tmp_path / "Quarterly Report.xlsx", 50_000)
    stages = []
    outcome, up = service.encrypt_and_upload(src, progress=lambda s, d, t: stages.append(s))
    fid = outcome.result.file_id
    assert {"preparing", "hashing", "encrypting", "uploading", "complete"} <= set(stages)
    names = [p.name for p in remote_dir.iterdir()]
    assert names == [f"{fid}.wezenc"], "server sees only random object names"
    remote = (remote_dir / names[0]).read_bytes()
    assert src.read_bytes()[:64] not in remote and b"Quarterly" not in remote
    assert service.key.material() not in remote
    rec = service.db.get_file(fid)
    assert rec.status == "uploaded" and rec.local_container_path is None
    assert not list(service.temp_dir.iterdir()), "temp container auto-deleted"
    r = service.download_and_decrypt(fid, outdir(tmp_path))
    assert r.output_path.read_bytes() == src.read_bytes()
    assert r.output_path.name == "Quarterly Report.xlsx"


def test_locked_key_refuses(service: VaultService, tmp_path):
    service.key.lock()
    with pytest.raises(KeyNotLoadedError):
        service.encrypt(write_file(tmp_path / "a", 10))


def test_download_corruption_detected(service: VaultService, tmp_path, remote_dir):
    outcome, _ = service.encrypt_and_upload(write_file(tmp_path / "a.bin", 20_000))
    obj = remote_dir / f"{outcome.result.file_id}.wezenc"
    data = bytearray(obj.read_bytes())
    data[-100] ^= 1
    obj.write_bytes(bytes(data))
    with pytest.raises(IntegrityError):
        service.download_and_decrypt(outcome.result.file_id, outdir(tmp_path))
    assert list(outdir(tmp_path).iterdir()) == []
    # Without a registry hash, AES-GCM authentication still catches it.
    service.db.remove_file(outcome.result.file_id)
    with pytest.raises(AuthenticationFailedError):
        service.download_and_decrypt(outcome.result.file_id, outdir(tmp_path))
    assert list(outdir(tmp_path).iterdir()) == []


def test_download_with_wrong_key(service: VaultService, tmp_path):
    outcome, _ = service.encrypt_and_upload(write_file(tmp_path / "a.bin", 5000))
    service.key.load(generate_master_key(), replace=True)
    with pytest.raises(WrongKeyError):
        service.download_and_decrypt(outcome.result.file_id, outdir(tmp_path))


def test_interrupted_upload_recovery_and_resume(tmp_path, key, remote_dir):
    flaky = {"on": True}
    cfg = AppConfig()
    cfg.encryption.chunk_size = 4096
    mk = MasterKey()
    mk.load(key)

    def factory():
        return FlakyBackend(remote_dir, budget=300_000) if flaky["on"] else LocalDirectoryBackend(remote_dir)

    svc = VaultService(tmp_path / "home", cfg, mk, backend_factory=factory)
    svc.acknowledge_backup()
    src = write_file(tmp_path / "video.mp4", 1_000_000)
    with pytest.raises(NetworkInterruptedError):
        svc.encrypt_and_upload(src)
    # "Restart": a new service instance finds the abandoned operation.
    svc2 = VaultService(tmp_path / "home", cfg, mk, backend_factory=factory)
    items = svc2.pending_recovery()
    assert len(items) == 1 and items[0].resumable
    flaky["on"] = False
    r = svc2.resume_upload(items[0])
    assert r.resumed_from > 0
    assert svc2.pending_recovery() == []
    got = svc2.download_and_decrypt(items[0].operation.file_id, outdir(tmp_path))
    assert got.output_path.read_bytes() == src.read_bytes()


def test_failed_encryption_leaves_no_valid_ciphertext(service: VaultService, tmp_path):
    import threading
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(Exception):
        service.encrypt(write_file(tmp_path / "a", 100_000), cancel=cancel)
    assert list(service.temp_dir.iterdir()) == []
    assert service.db.list_files() == []


def test_no_secrets_in_sqlite_logs_or_config(service: VaultService, tmp_path):
    service.config.privacy.log_filenames = False
    service.encrypt_and_upload(write_file(tmp_path / "private-diary.txt", 3000))
    key = service.key.material()
    rk = encode_recovery_key(key).encode()
    for f in service.home.rglob("*"):
        if f.is_file():
            raw = f.read_bytes()
            assert key not in raw and rk not in raw and key.hex().encode() not in raw, f
    logs = "\n".join(recent_lines())
    assert "private-diary" not in logs and "wezcrypt-v1-" not in logs
    conn = sqlite3.connect(service.paths.db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"files", "servers", "used_nonces", "settings", "operations"} <= tables


def test_config_rejects_secrets(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("[server]\n" + "pass" + 'word = "not-a-real-secret"\n')
    with pytest.raises(ConfigError):
        load_config(p)
    p.write_text('[encryption]\nmaster_key = "x"\n')
    with pytest.raises(ConfigError):
        load_config(p)


def test_config_round_trip(tmp_path):
    cfg = AppConfig()
    cfg.server.host = 'example.com'
    cfg.privacy.clipboard_clear_seconds = 45
    p = save_config(cfg, tmp_path / "config.toml")
    assert load_config(p) == cfg


def test_example_config_loads():
    load_config(Path(__file__).resolve().parents[1] / "config.example.toml")


def test_tls_verification_always_on():
    ctx = make_tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    be = HTTPSBackend("https://storage.example.com/api")
    assert be.ctx.verify_mode == ssl.CERT_REQUIRED and be.ctx.check_hostname
    with pytest.raises(ConfigError):
        HTTPSBackend("http://storage.example.com")


def test_file_ids_are_random_and_anonymous(service: VaultService, tmp_path):
    ids = set()
    for i in range(5):
        o = service.encrypt(write_file(tmp_path / f"name{i}.txt", 10))
        ids.add(o.result.file_id)
        assert len(o.result.file_id) == 64
        assert all(c in "0123456789abcdef" for c in o.result.file_id)
    assert len(ids) == 5
