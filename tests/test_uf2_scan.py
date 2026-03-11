import struct
import tempfile
import unittest
from pathlib import Path

from scancli.scan import build_scan_report
from uf2.scan import (
    UF2_BLOCK_SIZE,
    UF2_FLAG_FAMILY_ID_PRESENT,
    UF2_MAGIC_END,
    UF2_MAGIC_START0,
    UF2_MAGIC_START1,
    is_uf2_file,
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


class UF2ScanTests(unittest.TestCase):
    def test_is_uf2_file_true_for_valid_magic(self):
        data = _make_uf2_bytes(b"hello")
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.uf2"
            path.write_bytes(data)
            self.assertTrue(is_uf2_file(path))

    def test_build_scan_report_handles_uf2_rp2040_firmware(self):
        payload = b"\x00".join(
            [
                b"/pico-sdk/",
                b"pico_platform",
                b"hardware_regs/include/hardware/regs",
                b"cmakelists.txt",
                b"gcc version 13.2.1",
                b"gnu c",
                b"_sbrk_r",
                b"multicore_launch_core1",
            ]
        )
        data = _make_uf2_bytes(payload)

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "firmware.uf2"
            path.write_bytes(data)
            report = build_scan_report(path)

        scan = report["scan_result"]
        artifact = scan["artifact_profile"]
        self.assertEqual(artifact["artifact_type"], "Bare-metal Firmware")
        self.assertEqual(scan["source_language"], "C")
        self.assertEqual(scan["compiler"], "GCC")
        self.assertEqual(scan["build_system"], "Pico SDK")
        self.assertIn("File Type: UF2", report["metadata_text"])
        self.assertIn("RP2040", report["metadata_text"])

    def test_build_scan_report_rejects_unknown_binary_format(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "unknown.txt"
            path.write_bytes(b"not-an-elf-or-uf2")
            with self.assertRaises(ValueError):
                build_scan_report(path)


if __name__ == "__main__":
    unittest.main()
