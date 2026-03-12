import json
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from advanced.calibration import build_calibration_model, calibrate_confidence, save_calibration_model
from advanced.benchmark import render_benchmark_summary, run_benchmark_cases
from advanced.ci import evaluate_benchmark_ci, evaluate_reports_ci, load_policy
from advanced.diffing import compare_reports, diff_to_markdown, render_diff_plain
from advanced.explain import explain_scores
from advanced.plugins import validate_rule_pack_schema
from advanced.reinterop import (
    export_re_payload,
    load_re_annotations,
    merge_scan_and_re_annotations,
    normalize_re_annotations,
)
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
                "confidence_raw": 82,
                "confidence_calibrated": 80,
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
        self.assertIn("failing cases:", summary)

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
            self.assertEqual(normalized["source"], "ghidra")

    def test_reinterop_merge_policy(self):
        normalized = {
            "source": "ghidra",
            "functions": [{"name": "foo", "value": 4096}],
            "labels": [{"name": "bar", "value": 8192}],
            "comments": [{"address": 4096, "text": "entry"}],
        }
        scan_result = {"binary_map": {"symbols": [{"name": "foo", "value": 4096}]}}
        merged_union = merge_scan_and_re_annotations(scan_result, normalized, policy="union")
        merged_import = merge_scan_and_re_annotations(scan_result, normalized, policy="prefer-import")
        merged_scan = merge_scan_and_re_annotations(scan_result, normalized, policy="prefer-scan")
        self.assertEqual(merged_union["source"], "ghidra")
        self.assertGreaterEqual(merged_union["merged_symbol_count"], 2)
        self.assertEqual(merged_import["merged_symbol_count"], 2)
        self.assertEqual(merged_scan["merged_symbol_count"], 1)

    def test_signature_schema_validation_conflict_diagnostics(self):
        payload = {
            "name": "conflict-pack",
            "languages": [
                {"id": "r1", "target": "C", "score": 2, "any_of": ["alpha"], "sections": ["*"]},
                {"id": "r2", "target": "Rust", "score": 2, "any_of": ["alpha"], "sections": ["*"]},
            ],
        }
        validated, diagnostics = validate_rule_pack_schema(payload, source="unit")
        self.assertEqual(validated["name"], "conflict-pack")
        self.assertTrue(any("possible conflict" in line for line in diagnostics))

    def test_calibration_model_and_apply(self):
        benchmark_result = {
            "case_count": 5,
            "reliability_curve": {
                "00-10": {"total": 1, "correct": 0, "empirical_accuracy": 0.0},
                "50-60": {"total": 8, "correct": 6, "empirical_accuracy": 0.75},
            },
        }
        model = build_calibration_model(benchmark_result, min_samples=2)
        self.assertEqual(model["min_samples"], 2)
        self.assertEqual(model["source_case_count"], 5)
        self.assertEqual(calibrate_confidence(55, model), 75)
        # Low-sample bin should fall back to midpoint calibration.
        self.assertEqual(calibrate_confidence(5, model), 5)
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir) / "calibration.json"
            saved = save_calibration_model(model, out_path)
            self.assertTrue(saved.exists())

    def test_benchmark_ci_thresholds_and_reliability_gate(self):
        benchmark_result = {
            "metrics": {
                "language": {"accuracy": 0.9},
                "compiler": {"accuracy": 0.8},
                "build_system": {"accuracy": 0.71},
                "artifact_type": {"accuracy": 0.83},
            },
            "reliability_curve": {
                "80-90": {"total": 5, "correct": 5, "empirical_accuracy": 1.0},
                "40-50": {"total": 1, "correct": 0, "empirical_accuracy": 0.0},
            },
        }
        policy = load_policy()
        result = evaluate_benchmark_ci(benchmark_result, policy)
        self.assertTrue(result["ok"], result["violations"])


if __name__ == "__main__":
    unittest.main()
