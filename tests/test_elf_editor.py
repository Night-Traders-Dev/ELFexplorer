import tempfile
import unittest
from pathlib import Path

from edit import ElfBinaryEditor, ElfEditError


class ElfBinaryEditorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.sample_elf = cls.repo_root / "test-bin" / "x86_64" / "hello_c"

    def _editor_or_skip(self):
        if not self.sample_elf.is_file():
            self.skipTest(f"sample ELF fixture not found: {self.sample_elf}")
        return ElfBinaryEditor(self.sample_elf)

    def test_rejects_non_elf_magic(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "not-elf.bin"
            path.write_bytes(b"not-elf-data")
            with self.assertRaises(ElfEditError):
                ElfBinaryEditor(path)

    def test_status_and_header_are_available(self):
        editor = self._editor_or_skip()
        status = editor.status()
        header = editor.get_elf_header()

        self.assertIn(status["elf_class"], {32, 64})
        self.assertIn(status["endianness"], {"little", "big"})
        self.assertGreater(status["size"], 0)
        self.assertIn(status["disassembler"], {"objdump", "unavailable"})
        self.assertIn("e_machine", header)
        self.assertIn("e_phnum", header)
        self.assertIn("e_shnum", header)

    def test_hex_view_displays_elf_magic(self):
        editor = self._editor_or_skip()
        dump = editor.hex_view(offset=0, length=32, width=16)
        self.assertIn("7f 45 4c 46", dump)
        self.assertIn("00000000", dump)

    def test_set_elf_field_round_trip(self):
        editor = self._editor_or_skip()
        original = editor.get_elf_header()["e_flags"]
        updated = original ^ 0x1
        editor.set_elf_field("e_flags", updated)
        self.assertTrue(editor.is_dirty)

        with tempfile.TemporaryDirectory() as tmp_dir:
            out = Path(tmp_dir) / "edited-elf-header.elf"
            editor.save(out)
            reopened = ElfBinaryEditor(out)
            self.assertEqual(reopened.get_elf_header()["e_flags"], updated)

    def test_write_byte_round_trip(self):
        editor = self._editor_or_skip()
        offset = 0x10
        old_byte = editor.read_bytes(offset, 1)
        replacement = 0x90 if old_byte[0] != 0x90 else 0x91
        editor.write_byte(offset, replacement)
        self.assertEqual(editor.read_bytes(offset, 1), bytes([replacement]))

        with tempfile.TemporaryDirectory() as tmp_dir:
            out = Path(tmp_dir) / "edited-byte.elf"
            editor.save(out)
            reopened = ElfBinaryEditor(out)
            self.assertEqual(reopened.read_bytes(offset, 1), bytes([replacement]))

    def test_patch_hex_and_ascii_round_trip(self):
        editor = self._editor_or_skip()
        original = editor.read_bytes(0x20, 6)
        editor.patch_hex(0x20, "de ad be ef")
        editor.write_ascii(0x24, "EL")
        self.assertEqual(editor.read_bytes(0x20, 4), bytes.fromhex("de ad be ef"))
        self.assertEqual(editor.read_bytes(0x24, 2), b"EL")

        with tempfile.TemporaryDirectory() as tmp_dir:
            out = Path(tmp_dir) / "edited-hex-ascii.elf"
            editor.save(out)
            reopened = ElfBinaryEditor(out)
            self.assertEqual(reopened.read_bytes(0x20, 4), bytes.fromhex("de ad be ef"))
            self.assertEqual(reopened.read_bytes(0x24, 2), b"EL")
            # Confirm we can restore prior bytes in-memory and keep editor usable.
            reopened.write_bytes(0x20, original)
            self.assertEqual(reopened.read_bytes(0x20, 6), original)

    def test_set_program_header_field_round_trip(self):
        editor = self._editor_or_skip()
        header = editor.get_elf_header()
        if header["e_phnum"] <= 0:
            self.skipTest("ELF sample has no program headers.")

        original = editor.get_program_header(0)["p_flags"]
        updated = original ^ 0x1
        editor.set_program_header_field(0, "p_flags", updated)

        with tempfile.TemporaryDirectory() as tmp_dir:
            out = Path(tmp_dir) / "edited-phdr.elf"
            editor.save(out)
            reopened = ElfBinaryEditor(out)
            self.assertEqual(reopened.get_program_header(0)["p_flags"], updated)

    def test_set_section_header_field_round_trip(self):
        editor = self._editor_or_skip()
        header = editor.get_elf_header()
        if header["e_shnum"] <= 1:
            self.skipTest("ELF sample does not have enough section headers.")

        original = editor.get_section_header(1, resolve_name=False)["sh_flags"]
        updated = original ^ 0x1
        editor.set_section_header_field(1, "sh_flags", updated)

        with tempfile.TemporaryDirectory() as tmp_dir:
            out = Path(tmp_dir) / "edited-shdr.elf"
            editor.save(out)
            reopened = ElfBinaryEditor(out)
            self.assertEqual(reopened.get_section_header(1, resolve_name=False)["sh_flags"], updated)

    def test_revert_discards_pending_changes(self):
        editor = self._editor_or_skip()
        original = editor.get_elf_header()["e_flags"]
        editor.set_elf_field("e_flags", original ^ 0x1)
        self.assertTrue(editor.is_dirty)
        self.assertGreater(editor.change_count, 0)

        editor.revert()
        self.assertFalse(editor.is_dirty)
        self.assertEqual(editor.change_count, 0)
        self.assertEqual(editor.get_elf_header()["e_flags"], original)

    def test_disassemble_returns_text_when_available(self):
        editor = self._editor_or_skip()
        if editor.disassembler_backend() == "unavailable":
            self.skipTest("objdump not available in PATH")
        text = editor.disassemble(section=".text", max_lines=25)
        self.assertTrue(text.strip())

    def test_section_for_offset_maps_known_section(self):
        editor = self._editor_or_skip()
        sections = editor.list_section_headers(resolve_names=True)
        candidates = [
            (index, section)
            for index, section in enumerate(sections)
            if int(section.get("sh_size", 0)) > 0
            and int(section.get("sh_offset", 0)) < editor.file_size
        ]
        if not candidates:
            self.skipTest("ELF sample has no section with file-backed bytes.")

        index, section = candidates[0]
        offset = int(section["sh_offset"])
        mapped = editor.section_for_offset(offset)

        self.assertIsNotNone(mapped)
        self.assertEqual(mapped["index"], index)
        self.assertEqual(mapped["offset"], offset)
        self.assertEqual(mapped["size"], int(section["sh_size"]))

    def test_file_offset_to_vaddr_uses_section_mapping(self):
        editor = self._editor_or_skip()
        sections = editor.list_section_headers(resolve_names=True)
        candidates = [
            section
            for section in sections
            if int(section.get("sh_size", 0)) > 0
            and int(section.get("sh_addr", 0)) > 0
            and int(section.get("sh_offset", 0)) < editor.file_size
        ]
        if not candidates:
            self.skipTest("ELF sample has no section with mappable virtual address.")

        section = candidates[0]
        offset = int(section["sh_offset"])
        expected = int(section["sh_addr"])
        self.assertEqual(editor.file_offset_to_vaddr(offset), expected)

    def test_file_range_to_vaddr_range_maps_contiguous_region(self):
        editor = self._editor_or_skip()
        sections = editor.list_section_headers(resolve_names=True)
        candidates = [
            section
            for section in sections
            if int(section.get("sh_size", 0)) >= 4
            and int(section.get("sh_addr", 0)) > 0
            and int(section.get("sh_offset", 0)) < editor.file_size
        ]
        if not candidates:
            self.skipTest("ELF sample has no section suitable for range mapping.")

        section = candidates[0]
        offset = int(section["sh_offset"])
        length = min(16, int(section["sh_size"]))
        mapped = editor.file_range_to_vaddr_range(offset, length)

        self.assertIsNotNone(mapped)
        self.assertEqual(mapped[0], int(section["sh_addr"]))
        self.assertEqual(mapped[1], int(section["sh_addr"]) + length)


if __name__ == "__main__":
    unittest.main()
