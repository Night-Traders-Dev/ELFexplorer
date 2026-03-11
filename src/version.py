from pathlib import Path


_VERSION_FALLBACK = "0.0.0+unknown"


def get_version() -> str:
    """Return the project version from the repository VERSION file."""
    version_file = Path(__file__).resolve().parents[1] / "VERSION"
    try:
        value = version_file.read_text(encoding="utf-8").strip()
    except OSError:
        return _VERSION_FALLBACK
    return value or _VERSION_FALLBACK
