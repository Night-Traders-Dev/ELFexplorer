import json
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from advanced.benchmark import render_benchmark_summary, run_benchmark_cases
from advanced.ci import evaluate_reports_ci, load_policy
from advanced.diffing import compare_reports, diff_to_markdown, render_diff_plain
from advanced.explain import explain_scores
from advanced.reinterop import export_re_payload, load_re_annotations, normalize_re_annotations
from advanced.signatures import (
    install_signature_pack,
    list_signature_packs,
    load_active_signature_pack,
)


def _fake_report(path, language="C", compiler="GCC", build="CMake", artifact_type="Linux User-space Executable"):
    return {
        "file": path,
        "mode": "general",
        "version": "0.7.0",
        "scan_result": {
            "source_language": language,
            "compiler": compiler,
            "build_system": build,
            "language_scores": {language: 10, "Unknown": 0},
            "compiler_scores": {compiler: 8, "Unknown": 0},
            "build_scores": {build: 7, "Unknown": 0},
            "artifact_profile": {
                "artifact_type": artifact_type,
                "confidence": 80,
                "scores": {artifact_type: 9, "Unknown": 0},
                "indicators": ["demo-indicator"],
            },
            "hardening_profile": {
                "likely_packed": False,
                "risk_level": "low",
            },
            "mixed_attribution": {
                "section_hints": [],
                "symbol_dominant_language": language,
                "symbol_dominant_score": 2,
            },
            "binary_map": {"sections": [], "symbols": []},
        },
    }


class AdvancedFeaturesTests(unittest.TestCase):
    def test_explain_scores_reports_margin(self):
        detail = explain_scores({"C": 10, "C++": 7, "Rust": 1}, "C")
        self.assertEqual(detail["predicted"], "C")
        self.assertEqual(detail["score_margin"], 3)
        self.assertFalse(detail["low_confidence"])

    def test_compare_reports_and_renderers(self):
        left = _fake_report("/tmp/a.elf", language="C", compiler="GCC")
        right = _fake_report("/tmp/b.elf", language="C++", compiler="Clang")
        diff = compare_reports(left, right)
        plain = render_diff_plain(diff)
        markdown = diff_to_markdown(diff)
        self.assertIn("Binary Diff Report", plain)
        self.assertIn("ELFexplorer Binary Diff Report", markdown)
        self.assertIn("language", diff["summary"])

    def test_ci_policy_flags_unknown_when_disallowed(self):
        report = _fake_report("/tmp/a.elf", language="Unknown")
        policy = load_policy()
        result = evaluate_reports_ci([report], policy)
        self.assertFalse(result["ok"])
        self.assertTrue(any("language is Unknown" in line for line in result["violations"]))

    def test_benchmark_runner_produces_accuracy(self):
        cases = [
            {"path": "/tmp/a.elf", "expected": {"language": "C"}},
            {"path": "/tmp/b.elf", "expected": {"language": "Rust"}},
        ]

        def _scan(path):
            if path.endswith("a.elf"):
                return _fake_report(path, language="C")
            return _fake_report(path, language="C")

        result = run_benchmark_cases(cases, _scan)
        summary = render_benchmark_summary(result)
        self.assertEqual(result["metrics"]["language"]["total"], 2)
        self.assertEqual(result["metrics"]["language"]["correct"], 1)
        self.assertIn("language: accuracy=", summary)

    def test_signature_install_and_load_active(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            pack_path = tmp_path / "pack.json"
            pack_path.write_text(
                json.dumps({"name": "test-pack", "languages": [{"target": "C", "score": 3, "any_of": ["hello"]}]}),
                encoding="utf-8",
            )
            installed, active = install_signature_pack(pack_path, signature_dir=tmp_path)
            self.assertTrue(installed.exists())
            self.assertTrue(active.exists())
            active_payload = load_active_signature_pack(signature_dir=tmp_path)
            self.assertEqual(active_payload.get("name"), "test-pack")
            self.assertGreaterEqual(len(list_signature_packs(signature_dir=tmp_path)), 2)

    def test_reinterop_export_and_import(self):
        report = _fake_report("/tmp/a.elf", language="Rust")
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir) / "re-export.json"
            exported = export_re_payload(report, out_path, export_format="ghidra")
            self.assertTrue(exported.exists())
            payload = load_re_annotations(exported)
            normalized = normalize_re_annotations(payload)
            self.assertEqual(normalized["source"], "unknown")


if __name__ == "__main__":
    unittest.main()
