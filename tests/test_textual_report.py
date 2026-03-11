import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from edit import ElfBinaryEditor, ElfEditError
from ui.textual_report import default_report_export_path, open_report_editor


def _sample_report(file_path="/tmp/firmware.uf2", mode="important"):
    return {
        "file": file_path,
        "mode": mode,
        "version": "0.6.0",
        "scan_result": {
            "artifact_profile": {},
            "source_language": "C",
            "language_scores": {},
            "compiler": "GCC",
            "compiler_scores": {},
            "build_system": "Pico SDK",
            "build_scores": {},
        },
        "metadata_text": "",
    }


class TextualReportPathTests(unittest.TestCase):
    def test_default_report_export_path_markdown(self):
        report = _sample_report("/tmp/fw image.uf2", mode="general")
        now = datetime(2026, 3, 11, 14, 30, 0, tzinfo=timezone.utc)
        output = default_report_export_path(report, ".md", output_dir=Path("/tmp"), now_utc=now)
        self.assertEqual(output, Path("/tmp/fw_image-general-20260311T143000Z.md"))

    def test_default_report_export_path_pdf_adds_dot_extension(self):
        report = _sample_report("/tmp/hello_c", mode="detailed")
        now = datetime(2026, 3, 11, 14, 30, 0, tzinfo=timezone.utc)
        output = default_report_export_path(report, "pdf", output_dir=Path("/tmp"), now_utc=now)
        self.assertEqual(output, Path("/tmp/hello_c-detailed-20260311T143000Z.pdf"))

    def test_open_report_editor_for_valid_elf_fixture(self):
        repo_root = Path(__file__).resolve().parents[1]
        sample = repo_root / "test-bin" / "x86_64" / "hello_c"
        if not sample.is_file():
            self.skipTest(f"ELF fixture not found: {sample}")

        report = _sample_report(str(sample), mode="general")
        editor = open_report_editor(report)
        self.assertIsInstance(editor, ElfBinaryEditor)
        self.assertEqual(Path(editor.path), sample)

    def test_open_report_editor_rejects_non_elf_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample = Path(tmp_dir) / "not-elf.bin"
            sample.write_bytes(b"not-elf")
            report = _sample_report(str(sample), mode="general")
            with self.assertRaises(ElfEditError):
                open_report_editor(report)


if __name__ == "__main__":
    unittest.main()
