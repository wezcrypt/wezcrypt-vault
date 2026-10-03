"""Single source of truth for the application version.

Used by the About page, window title, pyproject.toml (dynamic version),
PyInstaller Windows version resource, Inno Setup installer and release
artifact names.
"""

__version__ = "1.1.0"


def version_tuple() -> tuple[int, int, int, int]:
    """Four-part Windows file version, e.g. (1, 1, 0, 0)."""
    parts = [int(p) for p in __version__.split(".")]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])  # type: ignore[return-value]
