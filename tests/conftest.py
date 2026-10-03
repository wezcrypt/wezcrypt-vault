from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from crypto.key_manager import MasterKey, generate_master_key  # noqa: E402
from crypto.nonce_manager import NonceManager  # noqa: E402
from services.vault import VaultService  # noqa: E402
from storage.local import LocalDirectoryBackend  # noqa: E402
from utils.config import AppConfig  # noqa: E402
from utils.logging import configure_logging  # noqa: E402

SMALL_CHUNK = 4096


@pytest.fixture
def key() -> bytes:
    return generate_master_key()


@pytest.fixture
def nonces(tmp_path: Path) -> NonceManager:
    return NonceManager(tmp_path / "nonces.db")


@pytest.fixture
def remote_dir(tmp_path: Path) -> Path:
    d = tmp_path / "server"
    d.mkdir()
    return d


@pytest.fixture
def service(tmp_path: Path, key: bytes, remote_dir: Path) -> VaultService:
    home = tmp_path / "home"
    configure_logging(home / "logs")
    cfg = AppConfig()
    cfg.encryption.chunk_size = SMALL_CHUNK
    cfg.server.backend = "local"
    cfg.server.local_path = str(remote_dir)
    mk = MasterKey()
    mk.load(key)
    svc = VaultService(home, cfg, mk, backend_factory=lambda: LocalDirectoryBackend(remote_dir))
    svc.acknowledge_backup()
    return svc


def write_file(path: Path, size: int, seed: int = 1) -> Path:
    """Deterministic pseudo-random content without holding big buffers twice."""
    import hashlib

    with path.open("wb") as fh:
        counter = 0
        remaining = size
        while remaining > 0:
            block = hashlib.sha256(f"{seed}:{counter}".encode()).digest() * 2048  # 64 KiB
            fh.write(block[:remaining])
            remaining -= min(len(block), remaining)
            counter += 1
    return path
