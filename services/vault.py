"""Application service layer (no Qt). Orchestrates crypto, storage and DB.

Upload workflow:
    validate file -> confirm key loaded -> generate File ID -> reserve nonce
    -> encrypt locally into <id>.wezenc.part -> fsync -> rename to .wezenc
    -> encrypted SHA-256 -> upload -> verify -> register -> (delete temp)

Download workflow:
    download -> verify encrypted SHA-256 (registry) -> validate container
    -> verify key fingerprint -> authenticate AES-GCM -> decrypt locally
    -> restore sanitized original filename
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from crypto.container import DecryptResult, EncryptResult, decrypt_container, encrypt_file, read_header
from crypto.hashing import hashes_equal, sha256_file
from crypto.key_manager import MasterKey, format_fingerprint
from crypto.nonce_manager import NonceManager
from database.database import Database, FileRecord, OperationRecord
from security.paths import create_private_file, ensure_private_dir, safe_unlink
from security.validators import remote_object_name, validate_file_id
from storage.base import StorageBackend, UploadResult
from storage.https import HTTPSBackend
from storage.local import LocalDirectoryBackend
from storage.sftp import SFTPBackend
from services.profiles import ProfileManager
from database.database import Profile
from utils.app_paths import AppPaths
from utils.config import AppConfig
from utils.errors import (
    BackupNotAcknowledgedError,
    ConfigError,
    ConnectionTestRequiredError,
    IntegrityError,
    NetworkInterruptedError,
    OperationCancelled,
    ValidationError,
    WezCryptError,
)
from utils.logging import log_event

StageProgress = Callable[[str, int, int], None]


@dataclass(frozen=True)
class EncryptOutcome:
    result: EncryptResult
    container_path: Path
    original_name: str


@dataclass(frozen=True)
class RecoveryItem:
    operation: OperationRecord
    resumable: bool
    description: str


class VaultService:
    BACKUP_ACK_KEY = "backup_acknowledged"
    SETUP_DONE_KEY = "setup_completed"

    def __init__(self, home: Path | AppPaths, config: AppConfig, master_key: MasterKey,
                 backend_factory: Callable[[], StorageBackend] | None = None) -> None:
        self.paths = home if isinstance(home, AppPaths) else AppPaths.from_root(Path(home))
        self.home = self.paths.root
        self.config = config
        self.key = master_key
        self.db = Database(self.paths.db_path)
        self.nonces = NonceManager(self.paths.db_path)
        self.temp_dir = ensure_private_dir(self.paths.temp)
        self.profiles = ProfileManager(self.db)
        self.profiles.migrate_from_config(config.server)
        self._backend_factory = backend_factory

    # ---- first-run state -------------------------------------------------------
    def backup_acknowledged(self) -> bool:
        return self.db.get_setting(self.BACKUP_ACK_KEY) == "1"

    def acknowledge_backup(self) -> None:
        self.db.set_setting(self.BACKUP_ACK_KEY, "1")
        log_event("backup_acknowledged", status="ok")

    def setup_completed(self) -> bool:
        return self.db.get_setting(self.SETUP_DONE_KEY) == "1"

    def mark_setup_completed(self) -> None:
        self.db.set_setting(self.SETUP_DONE_KEY, "1")

    def needs_setup(self) -> bool:
        return not self.setup_completed() or self.profiles.active() is None

    # ---- backend -------------------------------------------------------------
    def backend_for(self, profile: Profile) -> StorageBackend:
        timeout = self.config.server.connect_timeout
        if profile.backend == "sftp":
            return SFTPBackend(
                self.db, host=profile.host, port=profile.port, username=profile.username,
                remote_dir=profile.remote_path, auth_method=profile.auth_method,
                private_key_path=profile.private_key_path, secret_ident=profile.secret_ident,
                secrets=self.profiles.get_secret, timeout=timeout,
            )
        if profile.backend == "https":
            ident = profile.secret_ident
            return HTTPSBackend(profile.https_base_url, ca_bundle=profile.https_ca_bundle, timeout=timeout,
                                token_provider=lambda: self.profiles.get_secret("https-token", ident))
        if profile.backend == "local":
            return LocalDirectoryBackend(profile.local_path)
        raise ConfigError("Unknown storage backend.")

    def make_backend(self, profile: Profile | None = None, *, require_tested: bool = True) -> StorageBackend:
        if self._backend_factory is not None:
            return self._backend_factory()
        profile = profile or self.profiles.require_active()
        if require_tested and profile.connection_tested_at is None:
            raise ConnectionTestRequiredError(
                f"Server profile '{profile.name}' changed or was never tested. "
                "Run Test Connection in Settings before transferring files."
            )
        return self.backend_for(profile)

    def _profile_for_file(self, file_id: str) -> Profile | None:
        rec = self.db.get_file(file_id)
        if rec is not None and rec.profile_id is not None:
            prof = self.profiles.get(rec.profile_id)
            if prof is not None:
                return prof
        return None

    def server_label(self) -> str:
        prof = self.profiles.active()
        if prof is None:
            return "Not configured"
        return f"{prof.name} ({prof.label})"

    # ---- encrypt ----------------------------------------------------------------
    def encrypt(self, src: Path, *, progress: StageProgress | None = None,
                cancel: threading.Event | None = None) -> EncryptOutcome:
        src = Path(src)
        if not src.is_file():
            raise ValidationError("Selected path is not a regular file.")
        key = self.key.material()  # raises KeyNotLoadedError when locked
        info = self.key.info()
        if progress:
            progress("preparing", 0, 1)
        file_id = os.urandom(32)  # 256-bit random File ID: no name/user/host/time
        fid = file_id.hex()
        reservation = self.nonces.reserve(file_id)  # durable BEFORE encryption
        part = self.temp_dir / f"{fid}.wezenc.part"
        final = self.temp_dir / f"{fid}.wezenc"
        op = self.db.begin_operation(fid, "encrypt", str(part))
        fd = create_private_file(part)
        try:
            with os.fdopen(fd, "wb") as fh:
                result = encrypt_file(
                    src, fh, key=key, file_id=file_id, reservation=reservation,
                    chunk_size=self.config.encryption.chunk_size, progress=progress, cancel=cancel,
                )
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(part, final)
            self.db.add_file(
                file_id=fid, original_filename=src.name, encrypted_filename=final.name,
                original_size=result.plaintext_size, encrypted_size=result.encrypted_size,
                encrypted_hash=result.encrypted_sha256, key_fingerprint=info.display_fingerprint,
                status="encrypted", local_container_path=str(final),
            )
            self.db.finish_operation(op, "done")
        except BaseException as exc:
            safe_unlink(part)
            self.db.finish_operation(op, "failed", getattr(exc, "error_category", "unexpected"))
            log_event("encrypt", status="failed", file_id=fid,
                      error_category=getattr(exc, "error_category", "unexpected"))
            raise
        log_event("encrypt", status="ok", file_id=fid, encrypted_size=result.encrypted_size,
                  filename=src.name)
        return EncryptOutcome(result, final, src.name)

    # ---- upload -------------------------------------------------------------------
    def upload(self, file_id: str, *, progress: StageProgress | None = None,
               cancel: threading.Event | None = None) -> UploadResult:
        fid = validate_file_id(file_id)
        if not self.backup_acknowledged():
            raise BackupNotAcknowledgedError()
        rec = self.db.get_file(fid)
        if rec is None or not rec.local_container_path:
            raise ValidationError("No local encrypted container for this File ID.")
        container = Path(rec.local_container_path)
        if not container.is_file():
            raise ValidationError("Local encrypted container is missing.")
        # Re-verify the local container before sending it anywhere.
        if progress:
            progress("verifying", 0, rec.encrypted_size)
        digest, size = sha256_file(container, cancel=cancel)
        if size != rec.encrypted_size or not hashes_equal(digest, rec.encrypted_hash):
            raise IntegrityError("Local encrypted container changed since encryption; refusing to upload.")
        header = read_header(container)
        if header.file_id_hex != fid:
            raise IntegrityError("Container File ID mismatch.")

        op = self.db.begin_operation(fid, "upload", str(container))
        self.db.set_file_status(fid, "uploading")
        profile = None if self._backend_factory is not None else self.profiles.require_active()
        backend = self.make_backend(profile)
        try:
            with backend:
                result = backend.upload(
                    container, remote_object_name(fid), rec.encrypted_hash,
                    progress=(lambda d, t: progress("uploading", d, t)) if progress else None,
                    cancel=cancel, verify_readback=self.config.transfer.verify_upload_readback,
                )
            self.db.mark_uploaded(fid, result.remote_path, profile.id if profile else None)
            self.db.finish_operation(op, "done")
        except BaseException as exc:
            self.db.set_file_status(fid, "upload_failed")
            self.db.finish_operation(op, "failed", getattr(exc, "error_category", "unexpected"))
            log_event("upload", status="failed", file_id=fid, server=backend.description,
                      error_category=getattr(exc, "error_category", "unexpected"))
            raise
        if self.config.transfer.auto_delete_temp:
            safe_unlink(container)
            self.db.set_local_container(fid, None)
        log_event("upload", status="ok", file_id=fid, encrypted_size=result.size,
                  server=backend.description, detail=f"resumed_from={result.resumed_from}")
        if progress:
            progress("complete", 1, 1)
        return result

    def encrypt_and_upload(self, src: Path, *, progress: StageProgress | None = None,
                           cancel: threading.Event | None = None) -> tuple[EncryptOutcome, UploadResult]:
        outcome = self.encrypt(src, progress=progress, cancel=cancel)
        return outcome, self.upload(outcome.result.file_id, progress=progress, cancel=cancel)

    # ---- download / decrypt -----------------------------------------------------------
    def download_and_decrypt(self, file_id: str, out_dir: Path, *, progress: StageProgress | None = None,
                             cancel: threading.Event | None = None) -> DecryptResult:
        fid = validate_file_id(file_id)
        key = self.key.material()
        rec = self.db.get_file(fid)
        part = self.temp_dir / f"{fid}.download.part"
        op = self.db.begin_operation(fid, "download", str(part))
        backend = self.make_backend(self._profile_for_file(fid))
        try:
            with backend:
                backend.download(
                    remote_object_name(fid), part,
                    progress=(lambda d, t: progress("downloading", d, t)) if progress else None,
                    cancel=cancel,
                )
            if progress:
                progress("verifying", 0, 1)
            if rec is not None:
                digest, size = sha256_file(part, cancel=cancel)
                if size != rec.encrypted_size or not hashes_equal(digest, rec.encrypted_hash):
                    safe_unlink(part)  # never resume from corrupted data
                    raise IntegrityError("Downloaded container SHA-256 does not match the registered hash.")
            result = self._decrypt(part, out_dir, key, fid, progress, cancel)
            self.db.finish_operation(op, "done")
        except BaseException as exc:
            if not isinstance(exc, (NetworkInterruptedError, OperationCancelled)):
                safe_unlink(part)  # keep partial data only for resumable network failures
            self.db.finish_operation(op, "failed", getattr(exc, "error_category", "unexpected"))
            log_event("download", status="failed", file_id=fid, server=backend.description,
                      error_category=getattr(exc, "error_category", "unexpected"))
            raise
        safe_unlink(part)
        log_event("download", status="ok", file_id=fid, server=backend.description)
        return result

    def decrypt_local(self, container: Path, out_dir: Path, *, progress: StageProgress | None = None,
                      cancel: threading.Event | None = None) -> DecryptResult:
        key = self.key.material()
        return self._decrypt(Path(container), out_dir, key, None, progress, cancel)

    def _decrypt(self, container: Path, out_dir: Path, key: bytes, fid: str | None,
                 progress: StageProgress | None, cancel: threading.Event | None) -> DecryptResult:
        try:
            result = decrypt_container(container, out_dir, key=key, expected_file_id=fid,
                                       progress=progress, cancel=cancel)
        except WezCryptError as exc:
            log_event("decrypt", status="failed", file_id=fid, error_category=exc.error_category)
            raise
        # Remember this container's nonce prefix so it can never be reissued locally.
        header = read_header(container)
        self.nonces.record_external(header.nonce_prefix, header.file_id_hex)
        log_event("decrypt", status="ok", file_id=result.file_id, filename=result.original_name)
        if progress:
            progress("complete", 1, 1)
        return result

    # ---- management --------------------------------------------------------------------
    def list_files(self) -> list[FileRecord]:
        return self.db.list_files()

    def delete_remote(self, file_id: str) -> None:
        fid = validate_file_id(file_id)
        backend = self.make_backend(self._profile_for_file(fid))
        with backend:
            backend.delete(remote_object_name(fid))
        self.db.set_file_status(fid, "remote_deleted")
        log_event("delete_remote", status="ok", file_id=fid, server=backend.description)

    def remove_record(self, file_id: str) -> None:
        fid = validate_file_id(file_id)
        rec = self.db.get_file(fid)
        if rec and rec.local_container_path:
            safe_unlink(Path(rec.local_container_path))
        self.db.remove_file(fid)
        log_event("remove_record", status="ok", file_id=fid)

    def key_fingerprint_display(self) -> str:
        return format_fingerprint(self.key.info().fingerprint)

    # ---- crash recovery ----------------------------------------------------------------
    def pending_recovery(self) -> list[RecoveryItem]:
        items: list[RecoveryItem] = []
        seen: set[str] = set()
        for op in reversed(self.db.abandoned_operations()):
            key = f"{op.file_id}:{op.kind}"
            if key in seen:
                continue
            seen.add(key)
            rec = self.db.get_file(op.file_id)
            if rec is not None and rec.status == "uploaded":
                self.db.finish_operation(op.id, "superseded")
                continue
            if op.kind == "upload" and rec and rec.local_container_path and Path(rec.local_container_path).is_file():
                items.append(RecoveryItem(op, True, "Interrupted upload (encrypted container intact)"))
            elif op.temp_path and Path(op.temp_path).exists():
                items.append(RecoveryItem(op, False, f"Abandoned {op.kind} temporary file"))
            else:
                self.db.finish_operation(op.id, "abandoned")
        return items

    def discard_recovery(self, item: RecoveryItem) -> None:
        if item.operation.temp_path:
            p = Path(item.operation.temp_path)
            if p.parent.resolve() == self.temp_dir.resolve():
                safe_unlink(p)
        rec = self.db.get_file(item.operation.file_id)
        if rec is not None and rec.status != "uploaded":
            self.remove_record(item.operation.file_id)
        self.db.finish_operation(item.operation.id, "discarded")

    def resume_upload(self, item: RecoveryItem, *, progress: StageProgress | None = None,
                      cancel: threading.Event | None = None) -> UploadResult:
        result = self.upload(item.operation.file_id, progress=progress, cancel=cancel)
        self.db.finish_operation(item.operation.id, "resumed")
        return result
