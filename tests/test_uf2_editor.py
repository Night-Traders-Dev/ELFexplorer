import struct
import tempfile
import unittest
from pathlib import Path

from edit import ElfEditError, Uf2BinaryEditor, open_binary_editor
from uf2.scan import (
    UF2_BLOCK_SIZE,
    UF2_FLAG_FAMILY_ID_PRESENT,
    UF2_MAGIC_END,
    UF2_MAGIC_START0,
    UF2_MAGIC_START1,
)


def _make_uf2_bytes(payload, base_addr=0x10000000, family_id=0xE48BFF56):
    chunks = [payload[index : index + 256] for index in range(0, len(payload), 256)]
    if not chunks:
        chunks = [b""]
    total = len(chunks)
    blocks = []

    for block_no, chunk in enumerate(chunks):
        block = bytearray(UF2_BLOCK_SIZE)
        struct.pack_into(
            "<IIIIIIII",
            block,
            0,
            UF2_MAGIC_START0,
            UF2_MAGIC_START1,
            UF2_FLAG_FAMILY_ID_PRESENT,
            base_addr + (block_no * 256),
            len(chunk),
            block_no,
            total,
            family_id,
        )
        block[32 : 32 + len(chunk)] = chunk
        struct.pack_into("<I", block, 508, UF2_MAGIC_END)
        blocks.append(bytes(block))

    return b"".join(blocks)


class Uf2BinaryEditorTests(unittest.TestCase):
    def test_rejects_non_uf2_magic(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "not-uf2.bin"
            path.write_bytes(b"not-uf2")
            with self.assertRaises(ElfEditError):
                Uf2BinaryEditor(path)

    def test_status_and_overview_are_available(self):
        payload = b"hello uf2 payload\x00pico-sdk\x00"
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.uf2"
            path.write_bytes(_make_uf2_bytes(payload))
            editor = Uf2BinaryEditor(path)

        status = editor.status()
        overview = editor.get_uf2_overview()

        self.assertEqual(status["format"], "UF2")
        self.assertEqual(status["size"], len(payload))
        self.assertEqual(status["blocks"], 1)
        self.assertIn("0xE48BFF56 (RP2040)", status["family_ids"])
        self.assertEqual(overview["base_address"], 0x10000000)
        self.assertEqual(overview["end_address"], 0x10000000 + len(payload))

    def test_hex_view_and_mapping_include_target_address(self):
        payload = b"ABCDEF0123456789"
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.uf2"
            path.write_bytes(_make_uf2_bytes(payload))
            editor = Uf2BinaryEditor(path)

        dump = editor.hex_view(offset=0, length=16, width=8)
        self.assertIn("00000000 @0x10000000", dump)
        self.assertIn("41 42 43 44", dump)
        self.assertEqual(editor.file_offset_to_vaddr(3), 0x10000003)
        self.assertEqual(editor.file_range_to_vaddr_range(2, 4), (0x10000002, 0x10000006))

    def test_write_patch_and_save_round_trip(self):
        payload = b"0123456789abcdef"
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.uf2"
            path.write_bytes(_make_uf2_bytes(payload))
            editor = Uf2BinaryEditor(path)
            editor.write_byte(1, 0x41)
            editor.patch_hex(4, "de ad be ef")
            editor.write_ascii(8, "XY")

            out = Path(tmp_dir) / "edited.uf2"
            editor.save(out)
            reopened = Uf2BinaryEditor(out)

            self.assertEqual(reopened.read_bytes(0, 2), b"0A")
            self.assertEqual(reopened.read_bytes(4, 4), bytes.fromhex("de ad be ef"))
            self.assertEqual(reopened.read_bytes(8, 2), b"XY")

    def test_revert_discards_pending_changes(self):
        payload = b"abcdefgh"
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.uf2"
            path.write_bytes(_make_uf2_bytes(payload))
            editor = Uf2BinaryEditor(path)
            editor.write_byte(0, 0x5A)
            self.assertTrue(editor.is_dirty)
            self.assertGreater(editor.change_count, 0)

            editor.revert()

            self.assertFalse(editor.is_dirty)
            self.assertEqual(editor.change_count, 0)
            self.assertEqual(editor.read_bytes(0, len(payload)), payload)

    def test_export_payload_writes_reconstructed_binary(self):
        payload = b"\x11\x22\x33\x44"
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.uf2"
            path.write_bytes(_make_uf2_bytes(payload))
            editor = Uf2BinaryEditor(path)
            exported = editor.export_payload()
            self.assertEqual(Path(exported).read_bytes(), payload)

    def test_list_blocks_and_reported_offsets_are_stable(self):
        payload = bytes(range(32)) * 16
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.uf2"
            path.write_bytes(_make_uf2_bytes(payload))
            editor = Uf2BinaryEditor(path)

        blocks = editor.list_blocks()
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0]["payload_offset"], 0)
        self.assertEqual(blocks[1]["payload_offset"], 256)
        self.assertEqual(blocks[1]["target_addr"], 0x10000100)
        self.assertEqual(editor.get_block(1)["index"], 1)

    def test_open_binary_editor_returns_uf2_backend(self):
        payload = b"open binary editor"
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.uf2"
            path.write_bytes(_make_uf2_bytes(payload))
            editor = open_binary_editor(path)
            self.assertIsInstance(editor, Uf2BinaryEditor)

    def test_disassemble_returns_text_or_fallback_message(self):
        payload = b"\x00\xb5\x01\x20\x00\xbd" + (b"\x00" * 16)
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.uf2"
            path.write_bytes(_make_uf2_bytes(payload))
            editor = Uf2BinaryEditor(path)

        rendered = editor.disassemble(max_lines=10)
        self.assertTrue(isinstance(rendered, str) and rendered.strip())


if __name__ == "__main__":
    unittest.main()
