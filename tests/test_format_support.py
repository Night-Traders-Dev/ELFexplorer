import tempfile
import unittest
from pathlib import Path

from scancli.scan import build_scan_report


def _ihex_record(address, record_type, data):
    payload = bytes([len(data), (address >> 8) & 0xFF, address & 0xFF, record_type]) + data
    checksum = (-sum(payload)) & 0xFF
    return ":" + (payload + bytes([checksum])).hex().upper()


def _make_ihex(data, start_address=0x0000):
    lines = []
    address = start_address
    for index in range(0, len(data), 16):
        chunk = data[index : index + 16]
        lines.append(_ihex_record(address, 0x00, chunk))
        address += len(chunk)
    lines.append(_ihex_record(0x0000, 0x01, b""))
    return "\n".join(lines) + "\n"


def _srec_record(record_type, address, data):
    addr_sizes = {"0": 2, "1": 2, "2": 3, "3": 4, "5": 2, "7": 4, "8": 3, "9": 2}
    addr_len = addr_sizes[record_type]
    addr_bytes = address.to_bytes(addr_len, "big")
    count = len(addr_bytes) + len(data) + 1
    payload = bytes([count]) + addr_bytes + data
    checksum = (~(sum(payload) & 0xFF)) & 0xFF
    return f"S{record_type}{(payload + bytes([checksum])).hex().upper()}"


def _make_srec(data, start_address=0x10000000):
    lines = [_srec_record("0", 0x0000, b"ELFexplorer")]
    address = start_address
    for index in range(0, len(data), 16):
        chunk = data[index : index + 16]
        lines.append(_srec_record("3", address, chunk))
        address += len(chunk)
    lines.append(_srec_record("7", start_address, b""))
    return "\n".join(lines) + "\n"


def _make_ar_with_member(member_name, member_payload):
    if len(member_name) > 15:
        raise ValueError("member_name too long for simple ar fixture")
    name_field = (member_name + "/").encode("ascii", errors="ignore").ljust(16, b" ")
    timestamp = b"0".rjust(12, b" ")
    owner = b"0".rjust(6, b" ")
    group = b"0".rjust(6, b" ")
    mode = b"100644".rjust(8, b" ")
    size = str(len(member_payload)).encode("ascii").rjust(10, b" ")
    header = name_field + timestamp + owner + group + mode + size + b"`\n"
    padding = b"\n" if len(member_payload) % 2 else b""
    return b"!<arch>\n" + header + member_payload + padding


class FormatSupportTests(unittest.TestCase):
    def test_scan_intel_hex_file(self):
        payload = b"\x00".join([b"/pico-sdk/", b"pico_platform", b"gcc version 13.2.1"])
        text = _make_ihex(payload)

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "firmware.hex"
            path.write_text(text, encoding="utf-8")
            report = build_scan_report(path)

        self.assertIn("Intel HEX", report["metadata_text"])
        self.assertEqual(report["scan_result"]["artifact_profile"]["artifact_type"], "Bare-metal Firmware")
        self.assertEqual(report["scan_result"]["source_language"], "C")

    def test_scan_srecord_file(self):
        payload = b"\x00".join([b"/pico-sdk/", b"_sbrk_r", b"cmakelists.txt"])
        text = _make_srec(payload)

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "firmware.srec"
            path.write_text(text, encoding="utf-8")
            report = build_scan_report(path)

        self.assertIn("Motorola S-Record", report["metadata_text"])
        self.assertEqual(report["scan_result"]["artifact_profile"]["artifact_type"], "Bare-metal Firmware")
        self.assertEqual(report["scan_result"]["source_language"], "C")

    def test_scan_raw_bin_file(self):
        payload = b"\x00".join([b"/pico-sdk/", b"_sbrk_r", b"gcc version 13.2.1", b"pico_platform"])

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "firmware.bin"
            path.write_bytes(payload)
            report = build_scan_report(path)

        self.assertIn("Raw Binary", report["metadata_text"])
        self.assertEqual(report["scan_result"]["artifact_profile"]["artifact_type"], "Bare-metal Firmware")

    def test_scan_gnu_ar_archive_with_elf_member(self):
        repo_root = Path(__file__).resolve().parents[1]
        elf_sample = repo_root / "test-bin" / "x86_64" / "hello_c"
        if not elf_sample.is_file():
            self.skipTest(f"ELF sample not found: {elf_sample}")

        archive_bytes = _make_ar_with_member("hello_c", elf_sample.read_bytes())
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "libhello.a"
            path.write_bytes(archive_bytes)
            report = build_scan_report(path)

        self.assertIn("GNU ar Archive", report["metadata_text"])
        self.assertIn(report["scan_result"]["source_language"], {"C", "C++"})
        self.assertNotEqual(report["scan_result"]["artifact_profile"]["artifact_type"], "Unknown")


if __name__ == "__main__":
    unittest.main()

