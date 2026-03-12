import json
from pathlib import Path


DEFAULT_POLICY = {
    "min_artifact_confidence": 60,
    "use_calibrated_confidence": True,
    "allow_ambiguous": False,
    "allow_unknown": False,
    "forbidden_compilers": [],
    "forbidden_build_systems": [],
    "required_artifact_type": None,
    "required_language": None,
    "fail_on_hardening_flags": ["likely_packed"],
    "benchmark_thresholds": {
        "language_accuracy": 0.85,
        "compiler_accuracy": 0.75,
        "build_system_accuracy": 0.70,
        "artifact_type_accuracy": 0.80,
        "min_reliability_bin_samples": 3,
        "max_reliability_gap": 0.35,
    },
}


def load_policy(path=None):
    policy = dict(DEFAULT_POLICY)
    if not path:
        return policy
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict):
        policy.update(payload)
    return policy


def _is_ambiguous(value):
    return str(value).startswith("Ambiguous:")


def evaluate_reports_ci(reports, policy):
    violations = []
    for report in reports:
        file_path = report.get("file", "unknown")
        scan = report.get("scan_result", {})
        artifact = scan.get("artifact_profile", {})
        hardening = scan.get("hardening_profile", {})

        language = scan.get("source_language", "Unknown")
        compiler = scan.get("compiler", "Unknown")
        build_system = scan.get("build_system", "Unknown")
        artifact_type = artifact.get("artifact_type", "Unknown")
        confidence = int(artifact.get("confidence", 0))
        if policy.get("use_calibrated_confidence", True):
            confidence = int(artifact.get("confidence_calibrated", confidence))

        min_conf = int(policy.get("min_artifact_confidence", 0))
        if confidence < min_conf:
            violations.append(f"{file_path}: artifact confidence {confidence} < required {min_conf}")

        if not policy.get("allow_unknown", False):
            for field_name, value in (
                ("language", language),
                ("compiler", compiler),
                ("build_system", build_system),
                ("artifact_type", artifact_type),
            ):
                if str(value) == "Unknown":
                    violations.append(f"{file_path}: {field_name} is Unknown")

        if not policy.get("allow_ambiguous", False):
            for field_name, value in (
                ("language", language),
                ("compiler", compiler),
                ("build_system", build_system),
                ("artifact_type", artifact_type),
            ):
                if _is_ambiguous(value):
                    violations.append(f"{file_path}: {field_name} is ambiguous ({value})")

        required_artifact = policy.get("required_artifact_type")
        if required_artifact and artifact_type != required_artifact:
            violations.append(
                f"{file_path}: artifact type {artifact_type} != required {required_artifact}"
            )

        required_language = policy.get("required_language")
        if required_language and language != required_language:
            violations.append(f"{file_path}: language {language} != required {required_language}")

        forbidden_compilers = set(policy.get("forbidden_compilers", []))
        if compiler in forbidden_compilers:
            violations.append(f"{file_path}: compiler {compiler} is forbidden by CI policy")

        forbidden_builds = set(policy.get("forbidden_build_systems", []))
        if build_system in forbidden_builds:
            violations.append(f"{file_path}: build system {build_system} is forbidden by CI policy")

        for flag in policy.get("fail_on_hardening_flags", []):
            if hardening.get(flag):
                violations.append(f"{file_path}: hardening flag triggered ({flag})")

    return {
        "ok": not violations,
        "violations": violations,
        "policy": policy,
        "report_count": len(reports),
    }


def evaluate_benchmark_ci(benchmark_result, policy):
    thresholds = dict(DEFAULT_POLICY.get("benchmark_thresholds", {}))
    thresholds.update(policy.get("benchmark_thresholds", {}))
    metrics = benchmark_result.get("metrics", {})
    reliability = benchmark_result.get("reliability_curve", {})
    violations = []

    def _check_metric(metric_key, threshold_key):
        accuracy = float(metrics.get(metric_key, {}).get("accuracy", 0.0))
        threshold = float(thresholds.get(threshold_key, 0.0))
        if accuracy < threshold:
            violations.append(
                f"benchmark {metric_key} accuracy {accuracy:.4f} < threshold {threshold:.4f}"
            )

    _check_metric("language", "language_accuracy")
    _check_metric("compiler", "compiler_accuracy")
    _check_metric("build_system", "build_system_accuracy")
    _check_metric("artifact_type", "artifact_type_accuracy")

    min_samples = int(thresholds.get("min_reliability_bin_samples", 0))
    max_gap = float(thresholds.get("max_reliability_gap", 1.0))
    for bucket, entry in reliability.items():
        total = int(entry.get("total", 0))
        if total < min_samples:
            continue
        left = int(bucket.split("-", 1)[0])
        right = int(bucket.split("-", 1)[1])
        expected = ((left + right) / 2.0) / 100.0
        empirical = float(entry.get("empirical_accuracy", 0.0))
        gap = abs(empirical - expected)
        if gap > max_gap:
            violations.append(
                f"benchmark reliability gap too high for bin {bucket}: "
                f"empirical={empirical:.4f} expected~={expected:.4f} gap={gap:.4f}"
            )

    return {
        "ok": not violations,
        "violations": violations,
        "thresholds": thresholds,
    }
