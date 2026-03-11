import json
from collections import defaultdict
from pathlib import Path

from scancli.scan import is_supported_binary


FILENAME_LANGUAGE_MAP = {
    "asm": "ASM",
    "c": "C",
    "cpp": "C++",
    "go": "Go",
    "rust": "Rust",
    "dart": "Dart",
    "nim": "Nim",
    "zig": "Zig",
    "sage": "SageLang",
    "sagelang": "SageLang",
}


def _parse_expected_from_filename(path):
    stem = Path(path).stem.lower()
    if "_" not in stem:
        return {}
    suffix = stem.rsplit("_", 1)[-1]
    language = FILENAME_LANGUAGE_MAP.get(suffix)
    if not language:
        return {}
    return {"language": language}


def load_benchmark_manifest(path):
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict) and "cases" in payload and isinstance(payload["cases"], list):
        return payload["cases"]
    if isinstance(payload, list):
        return payload
    raise ValueError("Benchmark manifest must be either a list of cases or {\"cases\": [...]} payload.")


def discover_benchmark_cases(corpus_dir):
    root = Path(corpus_dir).expanduser()
    cases = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if not is_supported_binary(path):
            continue
        expected = _parse_expected_from_filename(path)
        if not expected:
            continue
        case = {"path": str(path), "expected": expected}
        cases.append(case)
    return cases


def _init_metric_state():
    return {
        "total": 0,
        "correct": 0,
        "confusion": defaultdict(lambda: defaultdict(int)),
        "labels": set(),
    }


def _update_metric_state(state, expected, predicted):
    state["total"] += 1
    state["labels"].add(expected)
    state["labels"].add(predicted)
    state["confusion"][expected][predicted] += 1
    if expected == predicted:
        state["correct"] += 1


def _finalize_metrics(state):
    labels = sorted(state["labels"])
    confusion = {
        expected: {predicted: int(state["confusion"][expected][predicted]) for predicted in labels}
        for expected in labels
    }

    per_label = {}
    for label in labels:
        tp = state["confusion"][label][label]
        fp = sum(state["confusion"][other][label] for other in labels if other != label)
        fn = sum(state["confusion"][label][other] for other in labels if other != label)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        per_label[label] = {
            "tp": int(tp),
            "fp": int(fp),
            "fn": int(fn),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    total = int(state["total"])
    correct = int(state["correct"])
    accuracy = (correct / total) if total else 0.0
    return {
        "total": total,
        "correct": correct,
        "accuracy": round(accuracy, 4),
        "labels": labels,
        "confusion_matrix": confusion,
        "per_label": per_label,
    }


def run_benchmark_cases(cases, scan_func):
    metrics = {
        "language": _init_metric_state(),
        "compiler": _init_metric_state(),
        "build_system": _init_metric_state(),
        "artifact_type": _init_metric_state(),
    }
    per_case = []

    for case in cases:
        path = case.get("path")
        expected = case.get("expected")
        if not expected:
            expected = {
                key: case[key]
                for key in ("language", "compiler", "build_system", "artifact_type")
                if key in case
            }
        if not path or not expected:
            continue
        report = scan_func(path)
        scan = report.get("scan_result", {})
        artifact = scan.get("artifact_profile", {})
        observed = {
            "language": scan.get("source_language", "Unknown"),
            "compiler": scan.get("compiler", "Unknown"),
            "build_system": scan.get("build_system", "Unknown"),
            "artifact_type": artifact.get("artifact_type", "Unknown"),
        }

        case_result = {"path": path, "expected": expected, "observed": observed, "matches": {}}
        for key in ("language", "compiler", "build_system", "artifact_type"):
            if key not in expected:
                continue
            exp_value = expected[key]
            obs_value = observed[key]
            _update_metric_state(metrics[key], exp_value, obs_value)
            case_result["matches"][key] = (exp_value == obs_value)
        per_case.append(case_result)

    finalized = {key: _finalize_metrics(value) for key, value in metrics.items()}
    return {"cases": per_case, "metrics": finalized, "case_count": len(per_case)}


def render_benchmark_summary(result):
    lines = ["Benchmark Summary:"]
    metrics = result.get("metrics", {})
    for key in ("language", "compiler", "build_system", "artifact_type"):
        entry = metrics.get(key, {})
        lines.append(
            f"  {key}: accuracy={entry.get('accuracy', 0.0):.4f} "
            f"({entry.get('correct', 0)}/{entry.get('total', 0)})"
        )
    return "\n".join(lines)
