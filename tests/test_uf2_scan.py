import struct
import tempfile
import unittest
from pathlib import Path

from scancli.scan import build_scan_report
from uf2.scan import (
    UF2_BLOCK_SIZE,
    UF2_EXTENSION_TAG_DEVICE_DESCRIPTION,
    UF2_EXTENSION_TAG_DEVICE_TYPE,
    UF2_EXTENSION_TAG_FIRMWARE_VERSION,
    UF2_EXTENSION_TAG_PAGE_SIZE,
    UF2_FLAG_EXTENSION_TAGS_PRESENT,
    UF2_FLAG_FILE_CONTAINER,
    UF2_FLAG_FAMILY_ID_PRESENT,
    UF2_MAGIC_END,
    UF2_MAGIC_START0,
    UF2_MAGIC_START1,
    is_uf2_file,
)


def _encode_extension_tags(tags):
    blob = bytearray()
    for tag_type, value in tags:
        entry = bytearray(4)
        entry[0] = 4 + len(value)
        entry[1] = tag_type & 0xFF
        entry[2] = (tag_type >> 8) & 0xFF
        entry[3] = (tag_type >> 16) & 0xFF
        entry.extend(value)
        while len(entry) % 4:
            entry.append(0)
        blob.extend(entry)
    blob.extend(b"\x00\x00\x00\x00")
    return bytes(blob)


def _make_uf2_bytes(
    payload,
    base_addr=0x10000000,
    family_id=0xE48BFF56,
    extra_flags=0,
    extension_tags=None,
    file_name=None,
):
    chunks = [payload[index : index + 256] for index in range(0, len(payload), 256)]
    if not chunks:
        chunks = [b""]
    total = len(chunks)
    blocks = []

    for block_no, chunk in enumerate(chunks):
        block = bytearray(UF2_BLOCK_SIZE)
        flags = UF2_FLAG_FAMILY_ID_PRESENT | extra_flags
        struct.pack_into(
            "<IIIIIIII",
            block,
            0,
            UF2_MAGIC_START0,
            UF2_MAGIC_START1,
            flags,
            base_addr + (block_no * 256),
            len(chunk),
            block_no,
            total,
            family_id,
        )
        block[32 : 32 + len(chunk)] = chunk
        cursor = 32 + len(chunk)
        if file_name:
            encoded_name = file_name.encode("utf-8")
            block[cursor : cursor + len(encoded_name)] = encoded_name
            block[cursor + len(encoded_name)] = 0
        elif extension_tags:
            while cursor % 4:
                cursor += 1
            encoded_tags = _encode_extension_tags(extension_tags)
            block[cursor : cursor + len(encoded_tags)] = encoded_tags
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

    def test_build_scan_report_extracts_extension_tags_and_board_hints(self):
        payload = (
            b"UF2 Bootloader v1.0\n"
            b"Model: Raspberry Pi Pico W\n"
            b"Board-ID: RPI-RP2-pico-w\n"
            b"PICO_BOARD=pico_w\n"
            b"/pico-sdk/\n"
        )
        data = _make_uf2_bytes(
            payload,
            family_id=0xE48BFF56,
            extra_flags=UF2_FLAG_EXTENSION_TAGS_PRESENT,
            extension_tags=[
                (UF2_EXTENSION_TAG_FIRMWARE_VERSION, b"1.2.3"),
                (UF2_EXTENSION_TAG_DEVICE_DESCRIPTION, b"Raspberry Pi Pico W firmware"),
                (UF2_EXTENSION_TAG_PAGE_SIZE, (4096).to_bytes(4, "little")),
                (UF2_EXTENSION_TAG_DEVICE_TYPE, (0x12345678).to_bytes(4, "little")),
            ],
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "pico-w.uf2"
            path.write_bytes(data)
            report = build_scan_report(path)

        artifact = report["scan_result"]["artifact_profile"]
        fingerprint = report["scan_result"]["firmware_fingerprint"]
        self.assertEqual(artifact["board"], "Raspberry Pi Pico W")
        self.assertEqual(artifact["page_size"], 4096)
        self.assertEqual(artifact["device_type"], "0x12345678")
        self.assertIn("1.2.3", artifact["firmware_versions"])
        self.assertIn("Raspberry Pi Pico W", ", ".join(fingerprint["board_candidates"]))
        self.assertIn("Firmware Versions: 1.2.3", report["metadata_text"])
        self.assertIn("Detected Board: Raspberry Pi Pico W", report["metadata_text"])

    def test_build_scan_report_recognizes_rp2350_riscv_family(self):
        payload = b"/pico-sdk/\npico_platform\n"
        data = _make_uf2_bytes(payload, family_id=0xE48BFF5A)

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "rp2350-riscv.uf2"
            path.write_bytes(data)
            report = build_scan_report(path)

        artifact = report["scan_result"]["artifact_profile"]
        self.assertIn("RP2350 RISC-V image", artifact["target"])
        self.assertIn("RP2350_RISCV", report["metadata_text"])

    def test_build_scan_report_reports_file_container_blocks(self):
        data = _make_uf2_bytes(
            b"hello-world",
            family_id=0xE48BFF56,
            extra_flags=UF2_FLAG_FILE_CONTAINER,
            file_name="assets/config.txt",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "container.uf2"
            path.write_bytes(data)
            report = build_scan_report(path)

        self.assertIn("Container Files: assets/config.txt", report["metadata_text"])
        self.assertEqual(report["scan_result"]["artifact_profile"]["uf2_payload_mode"], "File container")

    def test_build_scan_report_rejects_unknown_binary_format(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "unknown.txt"
            path.write_bytes(b"not-an-elf-or-uf2")
            with self.assertRaises(ValueError):
                build_scan_report(path)


if __name__ == "__main__":
    unittest.main()
