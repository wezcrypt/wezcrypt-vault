"""Exception hierarchy for WezCrypt Vault.

Every exception carries an ``error_category`` that is safe to log. Messages
never contain key material, plaintext, passwords or tokens.
"""

from __future__ import annotations


class WezCryptError(Exception):
    """Base class for all application errors."""

    error_category = "general"


class ConfigError(WezCryptError):
    error_category = "config"


class MasterKeyError(WezCryptError):
    error_category = "master_key"


class KeyNotLoadedError(MasterKeyError):
    def __init__(self) -> None:
        super().__init__("Master key is locked. Unlock or import the master key first.")


class InvalidRecoveryKeyError(MasterKeyError):
    error_category = "invalid_recovery_key"


class NonceReuseError(WezCryptError):
    """Raised whenever nonce uniqueness cannot be guaranteed. Encryption stops."""

    error_category = "nonce_safety"


class ContainerFormatError(WezCryptError):
    error_category = "container_format"


class UnsupportedVersionError(ContainerFormatError):
    error_category = "container_version"


class AuthenticationFailedError(WezCryptError):
    error_category = "authentication_failed"
    MESSAGE = "Authentication failed. The file may be corrupted, modified, or the key is incorrect."

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.MESSAGE)


class WrongKeyError(WezCryptError):
    error_category = "wrong_key"
    MESSAGE = "This file appears to use a different master key."

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


class IntegrityError(WezCryptError):
    """Hash or size mismatch (encrypted container or restored plaintext)."""

    error_category = "integrity"


class SourceChangedError(WezCryptError):
    error_category = "source_changed"


class StorageError(WezCryptError):
    error_category = "storage"


class NetworkInterruptedError(StorageError):
    error_category = "network_interrupted"


class RemoteNotFoundError(StorageError):
    error_category = "remote_not_found"


class HostKeyUnknownError(StorageError):
    """First connection: the user must explicitly trust the presented key."""

    error_category = "host_key_unknown"

    def __init__(self, host: str, port: int, key_type: str, fingerprint: str) -> None:
        super().__init__(
            f"Unknown SSH host key for {host}:{port} ({key_type} {fingerprint}). "
            "Verify the fingerprint with your server administrator before trusting it."
        )
        self.host = host
        self.port = port
        self.key_type = key_type
        self.fingerprint = fingerprint


class HostKeyChangedError(StorageError):
    error_category = "host_key_changed"
    MESSAGE = "Server host key changed. Connection blocked for security."

    def __init__(self, expected: str = "", presented: str = "") -> None:
        super().__init__(self.MESSAGE)
        self.expected = expected
        self.presented = presented


class UploadVerificationError(StorageError):
    error_category = "upload_verification"


class ResumeVerificationError(StorageError):
    error_category = "resume_verification"


class PathSafetyError(WezCryptError):
    error_category = "path_safety"


class ValidationError(WezCryptError):
    error_category = "validation"


class OperationCancelled(WezCryptError):
    error_category = "cancelled"

    def __init__(self) -> None:
        super().__init__("Operation cancelled.")


# ---- 1.1.0: user-facing connection / environment errors ---------------------------


class ServerUnreachableError(StorageError):
    error_category = "server_unreachable"


class ConnectionTimeoutError(StorageError):
    error_category = "timeout"


class SSHNegotiationError(StorageError):
    error_category = "ssh_negotiation"


class SSHAuthenticationError(StorageError):
    error_category = "ssh_auth"


class SSHKeyFileError(StorageError):
    error_category = "ssh_key_file"


class PermissionDeniedError(StorageError):
    error_category = "permission_denied"


class RemoteDirectoryMissingError(StorageError):
    error_category = "remote_dir_missing"


class ConnectionTestRequiredError(StorageError):
    error_category = "connection_test_required"


class SecretUnavailableError(StorageError):
    error_category = "secret_unavailable"


class DiskFullError(WezCryptError):
    error_category = "disk_full"


class LocalDatabaseError(WezCryptError):
    error_category = "database"


class BackupNotAcknowledgedError(WezCryptError):
    error_category = "backup_not_acknowledged"

    def __init__(self) -> None:
        super().__init__(
            "Confirm that you have backed up your master key (Master Key page) before the first upload."
        )


class NoProfileError(WezCryptError):
    error_category = "no_profile"

    def __init__(self) -> None:
        super().__init__("No storage server is configured. Run the Setup Wizard or add a profile in Settings.")
