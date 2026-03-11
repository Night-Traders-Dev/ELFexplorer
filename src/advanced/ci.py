import json
from pathlib import Path


DEFAULT_POLICY = {
    "min_artifact_confidence": 60,
    "allow_ambiguous": False,
    "allow_unknown": False,
    "forbidden_compilers": [],
    "forbidden_build_systems": [],
    "required_artifact_type": None,
    "required_language": None,
    "fail_on_hardening_flags": ["likely_packed"],
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

