"""Central application metadata (no secrets)."""

from wezcrypt_vault.version import __version__

APP_NAME = "WezCrypt Vault"
APP_ID = "WezCryptVault"
APP_DESCRIPTION = "Secure Client-Side Encrypted File Storage"
DEVELOPER_NAME = "wezcrypt"
DEVELOPER_ROLES = ("Full-Stack Developer", "Systems Administrator", "Cybersecurity Researcher")
WEBSITE_URL = "https://wezcrypt.com"
GITHUB_URL = "https://github.com/wezcrypt"
REPOSITORY_URL = "https://github.com/wezcrypt/wezcrypt-vault"
COPYRIGHT = "Copyright © 2026 wezcrypt"
EXE_NAME = "WezCryptVault.exe"


def installer_name() -> str:
    return f"WezCryptVault-Setup-{__version__}.exe"


def app_information() -> str:
    """Plain-text summary for 'Copy App Information' (contains no secrets)."""
    import platform
    import sys

    return (
        f"{APP_NAME} {__version__}\n"
        f"{APP_DESCRIPTION}\n"
        f"Developer: {DEVELOPER_NAME}\n"
        f"Website: {WEBSITE_URL}\n"
        f"Repository: {REPOSITORY_URL}\n"
        "Encryption: AES-256-GCM, client-side, 256-bit unified master key\n"
        f"Platform: {platform.system()} {platform.release()} ({platform.machine()})\n"
        f"Runtime: Python {sys.version.split()[0]}{' (bundled)' if getattr(sys, 'frozen', False) else ''}\n"
    )


__all__ = [
    "APP_NAME", "APP_ID", "APP_DESCRIPTION", "DEVELOPER_NAME", "DEVELOPER_ROLES", "WEBSITE_URL",
    "GITHUB_URL", "REPOSITORY_URL", "COPYRIGHT", "EXE_NAME", "installer_name", "app_information",
    "__version__",
]
