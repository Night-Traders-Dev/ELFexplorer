from pathlib import Path

from uf2 import is_uf2_file

from .elf_editor import ElfBinaryEditor, ElfEditError
from .uf2_editor import Uf2BinaryEditor


def open_binary_editor(path):
    candidate = Path(path).expanduser()
    if is_uf2_file(candidate):
        return Uf2BinaryEditor(candidate)
    return ElfBinaryEditor(candidate)


__all__ = ["ElfBinaryEditor", "ElfEditError", "Uf2BinaryEditor", "open_binary_editor"]
