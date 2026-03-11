import json
from pathlib import Path


def load_re_annotations(path):
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("RE annotation import payload must be a JSON object.")
    return payload


def normalize_re_annotations(payload):
    source = str(payload.get("source") or payload.get("tool") or "unknown").lower()
    normalized = {
        "source": source,
        "functions": [],
        "comments": [],
        "labels": [],
        "xrefs": [],
        "raw": payload,
    }

    for key in ("functions", "funcs"):
        if key in payload and isinstance(payload[key], list):
            normalized["functions"].extend(payload[key])
            break

    for key in ("comments", "notes"):
        if key in payload and isinstance(payload[key], list):
            normalized["comments"].extend(payload[key])
            break

    for key in ("labels", "symbols"):
        if key in payload and isinstance(payload[key], list):
            normalized["labels"].extend(payload[key])
            break

    if isinstance(payload.get("xrefs"), list):
        normalized["xrefs"] = payload["xrefs"]

    return normalized


def build_re_export_payload(report, export_format="generic"):
    scan = report.get("scan_result", {})
    artifact = scan.get("artifact_profile", {})
    payload = {
        "format": export_format,
        "generated_from": "ELFexplorer",
        "file": report.get("file"),
        "version": report.get("version"),
        "detections": {
            "language": scan.get("source_language", "Unknown"),
            "compiler": scan.get("compiler", "Unknown"),
            "build_system": scan.get("build_system", "Unknown"),
            "artifact_type": artifact.get("artifact_type", "Unknown"),
            "artifact_confidence": artifact.get("confidence", 0),
        },
        "artifact_indicators": artifact.get("indicators", []),
        "mixed_attribution": scan.get("mixed_attribution", {}),
        "binary_map": scan.get("binary_map", {}),
    }

    if export_format == "ghidra":
        payload["ghidra_tags"] = {
            "language_guess": scan.get("source_language", "Unknown"),
            "compiler_guess": scan.get("compiler", "Unknown"),
            "artifact_guess": artifact.get("artifact_type", "Unknown"),
        }
    elif export_format == "ida":
        payload["ida_comments"] = [
            f"ELFexplorer language={scan.get('source_language', 'Unknown')}",
            f"ELFexplorer compiler={scan.get('compiler', 'Unknown')}",
            f"ELFexplorer build={scan.get('build_system', 'Unknown')}",
            f"ELFexplorer artifact={artifact.get('artifact_type', 'Unknown')}",
        ]
    elif export_format == "rizin":
        payload["rizin_meta"] = {
            "analysis.language": scan.get("source_language", "Unknown"),
            "analysis.compiler": scan.get("compiler", "Unknown"),
            "analysis.build_system": scan.get("build_system", "Unknown"),
            "analysis.artifact": artifact.get("artifact_type", "Unknown"),
        }
    return payload


def export_re_payload(report, path, export_format="generic"):
    payload = build_re_export_payload(report, export_format=export_format)
    out_path = Path(path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return out_path

