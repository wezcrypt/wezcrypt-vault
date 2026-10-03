"""Connection test and end-to-end encrypted round-trip test.

Neither test touches user data:
* The connection test writes a random 64-byte probe object with a random
  name, reads it back, and deletes it immediately.
* The end-to-end test encrypts a freshly generated random file with the real
  application encryption code (real nonce reservation, real container
  format), uploads only the encrypted container, downloads it, decrypts it
  locally, compares hashes byte for byte, then deletes the remote object and
  all local temporary data.

Every stage reports PASS only after the stage really succeeded.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import socket
import threading
from dataclasses import dataclass, field
from typing import Callable

from crypto.container import decrypt_container, encrypt_file
from crypto.hashing import hashes_equal, sha256_file
from database.database import Profile
from security.paths import create_private_file, ensure_private_dir
from security.validators import remote_object_name
from storage.sftp import SFTPBackend, map_sftp_error
from utils.errors import (
    HostKeyChangedError,
    HostKeyUnknownError,
    OperationCancelled,
    WezCryptError,
)
from utils.friendly import describe_error
from utils.logging import log_event

PASS, FAIL, SKIP, RUN = "PASS", "FAIL", "SKIPPED", "RUNNING"
CONNECTION_STAGES = ["Host Reachable", "SSH Connected", "Host Key", "Authentication",
                     "Remote Path", "Writable", "Readable"]
E2E_STAGES = ["Encryption", "Upload", "Download", "Decryption", "Integrity", "Cleanup"]

StageCallback = Callable[[str, str, str], None]  # stage, status, message


@dataclass
class StageResult:
    name: str
    status: str = SKIP
    message: str = ""


@dataclass
class TestReport:
    stages: list[StageResult]
    host_key: tuple[str, str] | None = None        # (type, fingerprint) awaiting trust
    host_key_changed: bool = False
    remote_missing: bool = False
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return all(s.status == PASS for s in self.stages)

    def stage(self, name: str) -> StageResult:
        return next(s for s in self.stages if s.name == name)


class _Runner:
    def __init__(self, names: list[str], cb: StageCallback | None, cancel: threading.Event | None) -> None:
        self.report = TestReport([StageResult(n) for n in names])
        self.cb = cb
        self.cancel = cancel

    def set(self, name: str, status: str, message: str = "") -> None:
        if self.cancel is not None and self.cancel.is_set() and status == RUN:
            raise OperationCancelled()
        st = self.report.stage(name)
        st.status, st.message = status, message
        if self.cb:
            self.cb(name, status, message)

    def fail(self, name: str, exc: BaseException) -> None:
        msg, _ = describe_error(exc)
        self.set(name, FAIL, msg)


# ---- connection test ------------------------------------------------------------------

def run_connection_test(service, profile: Profile, *, create_remote_dir: bool = False,
                        callback: StageCallback | None = None,
                        cancel: threading.Event | None = None) -> TestReport:
    if profile.backend == "sftp":
        report = _sftp_connection_test(service, profile, create_remote_dir, callback, cancel)
    else:
        report = _generic_connection_test(service, profile, callback, cancel)
    if report.ok:
        service.db.mark_profile_tested(profile.id)
    log_event("connection_test", status="ok" if report.ok else "failed", server=profile.label)
    return report


def _sftp_connection_test(service, profile: Profile, create_dir: bool, cb, cancel) -> TestReport:
    r = _Runner(CONNECTION_STAGES, cb, cancel)
    backend: SFTPBackend = service.backend_for(profile)  # type: ignore[assignment]
    try:
        r.set("Host Reachable", RUN)
        try:
            socket.getaddrinfo(profile.host, profile.port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            r.set("Host Reachable", FAIL, f"The server name '{profile.host}' could not be resolved.")
            raise _Stop from exc
        r.set("Host Reachable", PASS, f"{profile.host} resolved")

        r.set("SSH Connected", RUN)
        try:
            backend.step_transport()
        except WezCryptError as exc:
            r.fail("SSH Connected", exc)
            raise _Stop from exc
        r.set("SSH Connected", PASS, f"SSH handshake with {profile.host}:{profile.port}")

        r.set("Host Key", RUN)
        try:
            key_type, fp = backend.step_verify_host_key()
        except HostKeyUnknownError as exc:
            r.report.host_key = (exc.key_type, exc.fingerprint)
            r.set("Host Key", FAIL, f"Not trusted yet: {exc.key_type} {exc.fingerprint}")
            raise _Stop from exc
        except HostKeyChangedError as exc:
            r.report.host_key_changed = True
            r.set("Host Key", FAIL, HostKeyChangedError.MESSAGE)
            raise _Stop from exc
        r.set("Host Key", PASS, f"{key_type} {fp}")

        r.set("Authentication", RUN)
        try:
            backend.step_authenticate()
            backend.step_open_sftp()
        except WezCryptError as exc:
            r.fail("Authentication", exc)
            raise _Stop from exc
        r.set("Authentication", PASS, f"Logged in as {profile.username}")

        r.set("Remote Path", RUN)
        try:
            exists = backend.remote_dir_exists()
            if not exists and create_dir:
                backend.create_remote_dir()
                exists = backend.remote_dir_exists()
                if exists:
                    r.report.extra["created"] = backend.remote_dir
        except WezCryptError as exc:
            r.fail("Remote Path", exc)
            raise _Stop from exc
        if not exists:
            r.report.remote_missing = True
            r.set("Remote Path", FAIL, f"{backend.remote_dir} does not exist")
            raise _Stop
        r.set("Remote Path", PASS, backend.remote_dir + (" (created)" if "created" in r.report.extra else ""))

        probe = backend.remote_path(f".wezcrypt-connection-test-{secrets.token_hex(16)}.tmp")
        payload = os.urandom(64)
        r.set("Writable", RUN)
        try:
            with backend.sftp.open(probe, "wb") as fh:
                fh.write(payload)
        except OSError as exc:
            r.fail("Writable", map_sftp_error(exc, backend.remote_dir))
            raise _Stop from exc
        r.set("Writable", PASS, "Temporary probe written")
        r.set("Readable", RUN)
        try:
            with backend.sftp.open(probe, "rb") as fh:
                got = fh.read(1024)
            if got != payload:
                r.set("Readable", FAIL, "Probe data read back did not match")
            else:
                r.set("Readable", PASS, "Probe read back intact")
        except OSError as exc:
            r.fail("Readable", map_sftp_error(exc, backend.remote_dir))
        finally:
            try:
                backend.sftp.remove(probe)
            except OSError:
                r.report.extra["probe_cleanup"] = "failed"
                if r.report.stage("Readable").status == PASS:
                    r.set("Readable", FAIL, "Probe could not be deleted (no delete permission)")
    except _Stop:
        pass
    except OperationCancelled:
        raise
    except Exception as exc:  # unexpected: report, never PASS
        running = next((s.name for s in r.report.stages if s.status == RUN), CONNECTION_STAGES[0])
        r.fail(running, exc)
    finally:
        backend.close()
    return r.report


def _generic_connection_test(service, profile: Profile, cb, cancel) -> TestReport:
    """HTTPS / local folder: reach, write, read and delete a random probe container."""
    names = ["Host Reachable", "Remote Path", "Writable", "Readable"]
    r = _Runner(names, cb, cancel)
    backend = service.backend_for(profile)
    tmp = ensure_private_dir(service.paths.cache / f"probe-{secrets.token_hex(8)}")
    name = remote_object_name(secrets.token_hex(32))
    try:
        r.set("Host Reachable", RUN)
        try:
            backend.connect()
            backend.size(name)
        except WezCryptError as exc:
            r.fail("Host Reachable", exc)
            raise _Stop from exc
        r.set("Host Reachable", PASS, backend.description)
        r.set("Remote Path", PASS, backend.description)
        probe = tmp / "probe.bin"
        probe.write_bytes(os.urandom(64))
        digest = hashlib.sha256(probe.read_bytes()).hexdigest()
        r.set("Writable", RUN)
        try:
            backend.upload(probe, name, digest, verify_readback=False)
        except WezCryptError as exc:
            r.fail("Writable", exc)
            raise _Stop from exc
        r.set("Writable", PASS, "Temporary probe written")
        r.set("Readable", RUN)
        try:
            back = tmp / "back.part"
            backend.download(name, back)
            r.set("Readable", PASS if back.read_bytes() == probe.read_bytes() else FAIL,
                  "Probe read back" if back.read_bytes() == probe.read_bytes() else "Probe mismatch")
        except WezCryptError as exc:
            r.fail("Readable", exc)
        try:
            backend.delete(name)
        except WezCryptError:
            r.set("Readable", FAIL, "Probe could not be deleted")
    except _Stop:
        pass
    finally:
        backend.close()
        shutil.rmtree(tmp, ignore_errors=True)
    return r.report


class _Stop(Exception):
    pass


# ---- end-to-end encrypted round trip --------------------------------------------------

def run_end_to_end_test(service, profile: Profile, *, callback: StageCallback | None = None,
                        cancel: threading.Event | None = None) -> TestReport:
    r = _Runner(E2E_STAGES, callback, cancel)
    key = service.key.material()  # requires an unlocked master key
    work = ensure_private_dir(service.paths.cache / f"e2e-{secrets.token_hex(8)}")
    file_id = os.urandom(32)
    name = remote_object_name(file_id.hex())
    backend = service.make_backend(profile, require_tested=False)
    uploaded = False
    try:
        r.set("Encryption", RUN)
        plain = work / "wezcrypt-e2e-test.bin"
        plain.write_bytes(os.urandom(48 * 1024 + secrets.randbelow(16 * 1024)))
        plain_sha, _ = sha256_file(plain)
        container = work / f"{file_id.hex()}.wezenc"
        reservation = service.nonces.reserve(file_id)
        fd = create_private_file(container)
        with os.fdopen(fd, "wb") as fh:
            enc = encrypt_file(plain, fh, key=key, file_id=file_id, reservation=reservation,
                               chunk_size=16 * 1024)
        if plain.read_bytes() in container.read_bytes():
            r.set("Encryption", FAIL, "Plaintext found inside container")
            raise _Stop
        r.set("Encryption", PASS, f"{enc.total_chunks} chunks, AES-256-GCM")

        r.set("Upload", RUN)
        with backend:
            backend.upload(container, name, enc.encrypted_sha256)
            uploaded = True
            r.set("Upload", PASS, f"{enc.encrypted_size} encrypted bytes, verified")

            r.set("Download", RUN)
            dl = work / "download.part"
            backend.download(name, dl)
            dl_sha, _ = sha256_file(dl)
            if not hashes_equal(dl_sha, enc.encrypted_sha256):
                r.set("Download", FAIL, "Downloaded container hash mismatch")
                raise _Stop
            r.set("Download", PASS, "Encrypted SHA-256 verified")

            r.set("Decryption", RUN)
            out = ensure_private_dir(work / "out")
            res = decrypt_container(dl, out, key=key, expected_file_id=file_id.hex())
            r.set("Decryption", PASS, "Authenticated and decrypted locally")

            r.set("Integrity", RUN)
            same = hashes_equal(res.sha256, plain_sha) and res.output_path.read_bytes() == plain.read_bytes()
            r.set("Integrity", PASS if same else FAIL,
                  "Byte-for-byte identical" if same else "Decrypted data differs from original")
    except _Stop:
        pass
    except OperationCancelled:
        raise
    except Exception as exc:
        running = next((s.name for s in r.report.stages if s.status == RUN), "Encryption")
        r.fail(running, exc)
    finally:
        r.set("Cleanup", RUN)
        problems = []
        if uploaded:
            try:
                with service.make_backend(profile, require_tested=False) as b:
                    b.delete(name)
                    if b.size(name) is not None:
                        problems.append("remote test object still present")
            except Exception as exc:  # report precisely; never claim PASS
                problems.append(f"remote delete failed ({describe_error(exc)[0]})")
        shutil.rmtree(work, ignore_errors=True)
        if work.exists():
            problems.append("local temp data remains")
        r.set("Cleanup", FAIL if problems else PASS, "; ".join(problems) or "Remote and local test data deleted")
    log_event("e2e_test", status="ok" if r.report.ok else "failed", server=profile.label)
    return r.report


__all__ = ["run_connection_test", "run_end_to_end_test", "TestReport", "StageResult",
           "CONNECTION_STAGES", "E2E_STAGES", "PASS", "FAIL", "SKIP"]
