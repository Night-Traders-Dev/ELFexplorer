import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ui.web_dashboard import DashboardRuntime, build_dashboard_html


def _sample_report(path="/tmp/hello_c"):
    return {
        "file": path,
        "mode": "general",
        "version": "0.0.0",
        "metadata_text": "ELF metadata",
        "scan_result": {
            "source_language": "C",
            "compiler": "GCC",
            "build_system": "CMake",
            "language_scores": {"C": 10},
            "compiler_scores": {"GCC": 9},
            "build_scores": {"CMake": 8},
            "artifact_profile": {
                "artifact_type": "Linux User-space Executable",
                "confidence": 91,
                "scores": {"Linux User-space Executable": 91},
                "indicators": ["has PT_INTERP"],
            },
            "hardening_profile": {"signals": ["stripped=False"]},
            "firmware_fingerprint": {"signals": []},
            "plugin_evidence": {"diagnostics": []},
        },
    }


class WebDashboardTests(unittest.TestCase):
    def test_dashboard_runtime_state_includes_reports_and_saved_paths(self):
        runtime = DashboardRuntime(
            callbacks={"list_saved": lambda: [Path("/tmp/report-one.json"), Path("/tmp/report-two.json")]},
            initial_reports=[_sample_report()],
        )

        state = runtime.state()

        self.assertEqual(state["report_count"], 1)
        self.assertEqual(state["selected_index"], 0)
        self.assertEqual(state["summaries"][0]["language"], "C")
        self.assertEqual(state["saved_reports"][0], "/tmp/report-one.json")
        self.assertTrue(state["capabilities"]["list_saved"])

    def test_dashboard_runtime_scan_replaces_reports(self):
        runtime = DashboardRuntime(
            callbacks={"scan": lambda path, mode: _sample_report(path=path)},
            initial_reports=[],
        )

        state = runtime.scan("/tmp/new.elf", "important")

        self.assertEqual(state["report_count"], 1)
        self.assertEqual(state["reports"][0]["file"], "/tmp/new.elf")
        self.assertIn("Scanned /tmp/new.elf", state["message"])

    def test_dashboard_html_contains_bootstrap_and_controls(self):
        runtime = DashboardRuntime(initial_reports=[_sample_report()])
        html = build_dashboard_html(runtime.state())

        self.assertIn("ELFexplorer Web Dashboard", html)
        self.assertIn("id=\"initial-state\"", html)
        self.assertIn("Scan File", html)
        self.assertIn("Crawl Directory", html)
        self.assertIn("Load Saved JSON", html)


if __name__ == "__main__":
    unittest.main()
