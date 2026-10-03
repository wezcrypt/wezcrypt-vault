from __future__ import annotations

import multiprocessing as mp
import os
import sqlite3
import threading
from pathlib import Path

import pytest

from crypto.nonce_manager import NonceManager, generate_nonce, nonce_hash
from utils.errors import NonceReuseError


def test_one_million_nonces_unique():
    seen: set[bytes] = set()
    for _ in range(1_000_000):
        n = generate_nonce()
        assert len(n) == 12
        seen.add(n)
    assert len(seen) == 1_000_000, "duplicate 96-bit nonce generated"


def test_db_reservations_unique(nonces: NonceManager):
    prefixes = {nonces.reserve(os.urandom(32)).prefix for _ in range(20_000)}
    assert len(prefixes) == 20_000
    assert nonces.count() == 20_000


def test_known_nonce_collision_rejected(tmp_path: Path):
    known = bytes.fromhex("0011223344556677")
    fresh = bytes.fromhex("8899aabbccddeeff")
    seq = iter([known, known, fresh])
    nm = NonceManager(tmp_path / "n.db", random_source=lambda n: next(seq))
    first = nm.reserve(os.urandom(32))
    assert first.prefix == known
    second = nm.reserve(os.urandom(32))
    assert second.prefix == fresh, "collided prefix must be discarded and redrawn"
    assert nm.count() == 2


def test_manually_inserted_nonce_rejected(tmp_path: Path):
    known = b"\xaa" * 8
    nm = NonceManager(tmp_path / "n.db")
    conn = sqlite3.connect(tmp_path / "n.db")
    conn.execute("INSERT INTO used_nonces VALUES (?, ?, ?)", (nonce_hash(known), "2026-01-01", "x" * 64))
    conn.commit()
    conn.close()
    assert nm.is_used(known)
    nm2 = NonceManager(tmp_path / "n.db", random_source=lambda n: known)
    with pytest.raises(NonceReuseError):
        nm2.reserve(os.urandom(32))


def test_broken_random_source_stops(tmp_path: Path):
    nm = NonceManager(tmp_path / "n.db", random_source=lambda n: b"\x00" * n)
    nm.reserve(os.urandom(32))
    with pytest.raises(NonceReuseError):
        nm.reserve(os.urandom(32))
    bad = NonceManager(tmp_path / "m.db", random_source=lambda n: b"\x00" * 3)
    with pytest.raises(NonceReuseError):
        bad.reserve(os.urandom(32))


def test_reservations_persist_across_restart(tmp_path: Path):
    known = b"\x01" * 8
    NonceManager(tmp_path / "n.db", random_source=lambda n: known).reserve(os.urandom(32))
    restarted = NonceManager(tmp_path / "n.db", random_source=lambda n: known)
    with pytest.raises(NonceReuseError):
        restarted.reserve(os.urandom(32))


def test_db_stores_hash_not_raw_nonce(tmp_path: Path):
    nm = NonceManager(tmp_path / "n.db")
    res = nm.reserve(os.urandom(32))
    raw = (tmp_path / "n.db").read_bytes()
    assert res.prefix not in raw and res.prefix.hex().encode() not in raw


def test_threads_never_share_prefix(tmp_path: Path):
    nm = NonceManager(tmp_path / "n.db")
    out: list[bytes] = []
    lock = threading.Lock()

    def work():
        for _ in range(200):
            p = nm.reserve(os.urandom(32)).prefix
            with lock:
                out.append(p)

    ts = [threading.Thread(target=work) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(out) == len(set(out)) == 1600


def _proc_reserve(db: str, n: int, q) -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from crypto.nonce_manager import NonceManager as NM

    nm = NM(db)
    q.put([nm.reserve(os.urandom(32)).prefix.hex() for _ in range(n)])


def test_processes_never_share_prefix(tmp_path: Path):
    db = str(tmp_path / "shared.db")
    NonceManager(db)
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    procs = [ctx.Process(target=_proc_reserve, args=(db, 250, q)) for _ in range(4)]
    for p in procs:
        p.start()
    results = [q.get(timeout=120) for _ in procs]
    for p in procs:
        p.join(timeout=60)
    flat = [x for r in results for x in r]
    assert len(flat) == len(set(flat)) == 1000
    assert NonceManager(db).count() == 1000
