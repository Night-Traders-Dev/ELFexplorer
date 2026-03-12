import json
from collections import defaultdict
from pathlib import Path

from scancli.scan import is_supported_binary


FILENAME_LANGUAGE_MAP = {
    "asm": "ASM",
    "c": "C",
    "cpp": "C++",
    "cc": "C++",
    "cxx": "C++",
    "cs": "C#",
    "csharp": "C#",
    "dotnet": "C#",
    "go": "Go",
    "rust": "Rust",
    "dart": "Dart",
    "nim": "Nim",
    "zig": "Zig",
    "sage": "SageLang",
    "sagelang": "SageLang",
}

FILENAME_COMPILER_MAP = {
    "gcc": "GCC",
    "clang": "Clang",
    "rustc": "Rustc",
    "go": "Go gc",
    "tinycc": "TinyCC",
    "tcc": "TinyCC",
    "nasm": "NASM",
    "fasm": "FASM",
    "masm": "MASM",
    "tasm": "TASM",
    "zig": "Zig",
}

FILENAME_BUILD_SYSTEM_MAP = {
    "cmake": "CMake",
    "meson": "Meson",
    "bazel": "Bazel",
    "cargo": "Cargo",
    "make": "Make",
    "ninja": "Ninja",
    "scons": "SCons",
    "xmake": "XMake",
    "buck2": "Buck2",
    "platformio": "PlatformIO",
    "idf": "ESP-IDF",
    "espidf": "ESP-IDF",
    "zephyr": "Zephyr West",
    "pico": "Pico SDK",
}

ARCH_ALIASES = {
    "x86_64": "x86_64",
    "x86": "x86",
    "arm32": "arm32",
    "arm": "arm32",
    "aarch64": "aarch64",
    "rv64": "rv64",
    "riscv64": "rv64",
    "rv32": "rv32",
    "riscv32": "rv32",
}


def _parse_expected_from_filename(path):
    item = Path(path)
    stem = item.stem.lower()
    expected = {}

    parts = [token for token in stem.split("_") if token]
    if len(parts) >= 2:
        lang_token = parts[-1]
        language = FILENAME_LANGUAGE_MAP.get(lang_token)
        if language:
            expected["language"] = language
        for token in parts:
            compiler = FILENAME_COMPILER_MAP.get(token)
            if compiler and "compiler" not in expected:
                expected["compiler"] = compiler
            build = FILENAME_BUILD_SYSTEM_MAP.get(token)
            if build and "build_system" not in expected:
                expected["build_system"] = build

    parent = item.parent.name.lower()
    arch = ARCH_ALIASES.get(parent)
    if arch:
        expected["architecture"] = arch
    return expected


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


def _init_arch_state():
    return defaultdict(lambda: {"total": 0, "correct": 0})


def _update_arch_state(state, arch, match):
    label = arch or "unknown"
    state[label]["total"] += 1
    if match:
        state[label]["correct"] += 1


def _finalize_arch_state(state):
    finalized = {}
    for arch, entry in sorted(state.items()):
        total = int(entry["total"])
        correct = int(entry["correct"])
        finalized[arch] = {
            "total": total,
            "correct": correct,
            "accuracy": round((correct / total) if total else 0.0, 4),
        }
    return finalized


def _confidence_bin(confidence, bins):
    value = max(0, min(99, int(confidence)))
    width = max(1, int(100 / bins))
    left = (value // width) * width
    right = min(100, left + width)
    return f"{left:02d}-{right:02d}"


def _finalize_reliability(state):
    out = {}
    for bucket, entry in sorted(state.items()):
        total = int(entry["total"])
        correct = int(entry["correct"])
        out[bucket] = {
            "total": total,
            "correct": correct,
            "empirical_accuracy": round((correct / total) if total else 0.0, 4),
        }
    return out


def run_benchmark_cases(cases, scan_func, reliability_bins=10):
    metrics = {
        "language": _init_metric_state(),
        "compiler": _init_metric_state(),
        "build_system": _init_metric_state(),
        "artifact_type": _init_metric_state(),
    }
    per_arch = {
        "language": _init_arch_state(),
        "compiler": _init_arch_state(),
        "build_system": _init_arch_state(),
        "artifact_type": _init_arch_state(),
    }
    reliability = defaultdict(lambda: {"total": 0, "correct": 0})
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
            "artifact_confidence": int(artifact.get("confidence", 0)),
        }

        case_result = {"path": path, "expected": expected, "observed": observed, "matches": {}}
        arch = expected.get("architecture")
        for key in ("language", "compiler", "build_system", "artifact_type"):
            if key not in expected:
                continue
            exp_value = expected[key]
            obs_value = observed[key]
            _update_metric_state(metrics[key], exp_value, obs_value)
            matched = exp_value == obs_value
            case_result["matches"][key] = matched
            _update_arch_state(per_arch[key], arch, matched)
            if key == "artifact_type":
                bucket = _confidence_bin(observed["artifact_confidence"], reliability_bins)
                reliability[bucket]["total"] += 1
                if matched:
                    reliability[bucket]["correct"] += 1
        per_case.append(case_result)

    finalized = {key: _finalize_metrics(value) for key, value in metrics.items()}
    per_arch_metrics = {key: _finalize_arch_state(value) for key, value in per_arch.items()}
    reliability_curve = _finalize_reliability(reliability)
    return {
        "cases": per_case,
        "metrics": finalized,
        "per_arch_metrics": per_arch_metrics,
        "reliability_curve": reliability_curve,
        "reliability_bins": reliability_bins,
        "case_count": len(per_case),
    }


def render_benchmark_summary(result):
    lines = ["Benchmark Summary:"]
    metrics = result.get("metrics", {})
    for key in ("language", "compiler", "build_system", "artifact_type"):
        entry = metrics.get(key, {})
        lines.append(
            f"  {key}: accuracy={entry.get('accuracy', 0.0):.4f} "
            f"({entry.get('correct', 0)}/{entry.get('total', 0)})"
        )
    reliability = result.get("reliability_curve", {})
    if reliability:
        lines.append("  reliability (artifact confidence bins):")
        for bucket, entry in reliability.items():
            lines.append(
                f"    {bucket}: empirical_accuracy={entry.get('empirical_accuracy', 0.0):.4f} "
                f"({entry.get('correct', 0)}/{entry.get('total', 0)})"
            )
    per_arch = result.get("per_arch_metrics", {})
    language_arch = per_arch.get("language", {})
    if language_arch:
        lines.append("  per-arch language accuracy:")
        for arch, entry in language_arch.items():
            lines.append(
                f"    {arch}: accuracy={entry.get('accuracy', 0.0):.4f} "
                f"({entry.get('correct', 0)}/{entry.get('total', 0)})"
            )

    mismatches = []
    for item in result.get("cases", []):
        matches = item.get("matches", {})
        if not all(matches.values()):
            mismatches.append(item)
    if mismatches:
        lines.append(f"  failing cases: {len(mismatches)}")
        for item in mismatches[:10]:
            path = item.get("path", "unknown")
            expected = item.get("expected", {})
            observed = item.get("observed", {})
            details = []
            for key in ("language", "compiler", "build_system", "artifact_type"):
                if key not in expected:
                    continue
                if expected.get(key) != observed.get(key):
                    details.append(f"{key}: {expected.get(key)} -> {observed.get(key)}")
            joined = "; ".join(details) if details else "mismatch"
            lines.append(f"    {path}: {joined}")
    return "\n".join(lines)
