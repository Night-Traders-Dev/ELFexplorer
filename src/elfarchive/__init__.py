"""GNU ar archive scanners for ELF member analysis."""

from elfarchive.scan import is_ar_archive, scan_ar_archive

__all__ = [
    "is_ar_archive",
    "scan_ar_archive",
]

