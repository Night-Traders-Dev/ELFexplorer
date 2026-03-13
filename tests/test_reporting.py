import json
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reporting.export import (
    export_collection_markdown,
    export_report_markdown,
    export_report_pdf,
)
from reporting.persistence import (
    list_saved_reports,
    load_collection,
    load_report,
    save_collection,
    save_report,
)
from reporting.tasks import run_task_file


def _fake_report(path="/tmp/hello_c"):
    return {
        "file": path,
        "mode": "general",
        "version": "0.5.0",
        "generated_at": "2026-03-11T00:00:00Z",
        "scan_result": {
            "source_language": "C",
            "compiler": "GCC",
            "build_system": "CMake",
            "language_scores": {"C": 30, "C++": 2},
            "compiler_scores": {"GCC": 20, "Clang": 4},
            "build_scores": {"CMake": 10, "Make": 2},
            "artifact_profile": {
                "artifact_type": "Linux User-space Executable",
                "confidence": 91,
                "confidence_raw": 93,
                "confidence_calibrated": 91,
                "scores": {
                    "Linux User-space Executable": 91,
                    "Bare-metal Firmware": 0,
                },
                "target": "Linux x86_64",
                "sdk": "Unknown",
                "rtos": "None detected",
                "runtime": "glibc",
                "linkage_model": "Dynamic user-space",
                "loader": "/lib64/ld-linux-x86-64.so.2",
                "indicators": ["PT_INTERP present", "DT_NEEDED includes libc.so.6"],
            },
            "firmware_fingerprint": {
                "is_firmware_candidate": False,
                "firmware_confidence": 0,
                "likely_mcu": "Unknown",
                "likely_vendor": "Unknown",
                "sdk_candidates": [],
                "sdk_versions": {},
                "rtos_candidates": [],
                "linker_hints": [],
                "vector_table_profile": {"looks_like_vector_table": False},
                "signals": [],
            },
        },
        "metadata_text": "File Type: ET_DYN\nMachine: EM_X86_64",
    }


class ReportingTests(unittest.TestCase):
    def test_save_and_load_report_round_trip(self):
        report = _fake_report()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_path = save_report(report, path=tmp_path / "scan.json")
            self.assertTrue(out_path.exists())
            loaded = load_report(out_path)
            self.assertEqual(loaded["file"], report["file"])
            self.assertEqual(loaded["scan_result"]["source_language"], "C")

    def test_save_and_load_collection_round_trip(self):
        reports = [_fake_report("/tmp/hello_c"), _fake_report("/tmp/hello_cpp")]
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_path = save_collection(reports, path=tmp_path / "collection.json")
            self.assertTrue(out_path.exists())
            loaded = load_collection(out_path)
            self.assertEqual(loaded["count"], 2)
            self.assertEqual(len(loaded["reports"]), 2)

    def test_list_saved_reports_returns_store_json_files(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "a.json").write_text("{}", encoding="utf-8")
            (tmp_path / "b.json").write_text("{}", encoding="utf-8")
            (tmp_path / "ignore.txt").write_text("x", encoding="utf-8")

            items = list_saved_reports(store_dir=tmp_path)
            names = [path.name for path in items]
            self.assertEqual(names, ["a.json", "b.json"])

    def test_export_report_markdown_contains_professional_sections(self):
        report = _fake_report()
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = export_report_markdown(report, Path(tmp_dir) / "report.md")
            self.assertTrue(out_path.exists())
            text = out_path.read_text(encoding="utf-8")
            self.assertIn("# ELFexplorer Scan Report", text)
            self.assertIn("## Detection Summary", text)
            self.assertIn("| Source Language | C |", text)
            self.assertIn("| Artifact Confidence Calibrated | 91 |", text)
            self.assertIn("## ELF Metadata", text)
            self.assertIn("## Tool Integrations", text)
            self.assertIn("| ghidra | Ghidra Script |", text)

    def test_export_collection_markdown_contains_index(self):
        collection = {
            "generated_at": "2026-03-11T00:00:00Z",
            "count": 2,
            "reports": [_fake_report("/tmp/hello_c"), _fake_report("/tmp/hello_cpp")],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = export_collection_markdown(collection, Path(tmp_dir) / "collection.md")
            self.assertTrue(out_path.exists())
            text = out_path.read_text(encoding="utf-8")
            self.assertIn("# ELFexplorer Scan Collection", text)
            self.assertIn("## Index", text)
            self.assertIn("/tmp/hello_cpp", text)

    def test_export_report_pdf_requires_reportlab_or_writes_pdf(self):
        report = _fake_report()
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "report.pdf"
            try:
                path = export_report_pdf(report, output)
            except RuntimeError as exc:
                self.assertIn("reportlab", str(exc))
            else:
                self.assertTrue(path.exists())
                self.assertGreater(path.stat().st_size, 0)

    def test_task_file_runs_scan_and_crawl_tasks(self):
        task_payload = {
            "tasks": [
                {"type": "scan", "path": "/tmp/hello_c", "mode": "important"},
                {"type": "crawl", "path": "/tmp/bin", "recursive": False, "max_files": 3},
                {"type": "scan", "path": "/tmp/hello_cpp"},
            ]
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            task_file = Path(tmp_dir) / "tasks.json"
            task_file.write_text(json.dumps(task_payload), encoding="utf-8")

            scan_calls = []
            crawl_calls = []

            def scan_binary(path, mode="general"):
                scan_calls.append((path, mode))
                return _fake_report(path)

            def crawl_directory(path, mode="general", recursive=True, max_files=None):
                crawl_calls.append((path, mode, recursive, max_files))
                return [_fake_report(f"{path}/one"), _fake_report(f"{path}/two")]

            reports = run_task_file(
                task_file,
                scan_binary_func=scan_binary,
                crawl_directory_func=crawl_directory,
                default_mode="general",
            )

            self.assertEqual(scan_calls, [("/tmp/hello_c", "important"), ("/tmp/hello_cpp", "general")])
            self.assertEqual(crawl_calls, [("/tmp/bin", "general", False, 3)])
            self.assertEqual(len(reports), 4)


if __name__ == "__main__":
    unittest.main()
