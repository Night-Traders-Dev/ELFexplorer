import json
from pathlib import Path


def _freeze_entry(entry):
    if isinstance(entry, dict):
        items = tuple(sorted((str(k), str(v)) for k, v in entry.items()))
        return ("dict", items)
    if isinstance(entry, list):
        return ("list", tuple(str(item) for item in entry))
    return ("value", str(entry))


def _dedupe_entries(entries):
    seen = set()
    out = []
    for entry in entries:
        key = _freeze_entry(entry)
        if key in seen:
            continue
        seen.add(key)
        out.append(entry)
    return out


def load_re_annotations(path):
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("RE annotation import payload must be a JSON object.")
    return payload


def _normalize_generic(payload):
    normalized = {
        "source": str(payload.get("source") or payload.get("tool") or "unknown").lower(),
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


def _normalize_ghidra(payload):
    base = _normalize_generic(payload)
    gh = payload.get("ghidra", payload)
    base["source"] = "ghidra"
    if isinstance(gh.get("functions"), list):
        base["functions"] = gh["functions"]
    if isinstance(gh.get("comments"), list):
        base["comments"] = gh["comments"]
    if isinstance(gh.get("labels"), list):
        base["labels"] = gh["labels"]
    if isinstance(gh.get("xrefs"), list):
        base["xrefs"] = gh["xrefs"]
    return base


def _normalize_ida(payload):
    base = _normalize_generic(payload)
    ida = payload.get("ida", payload)
    base["source"] = "ida"
    if isinstance(ida.get("functions"), list):
        base["functions"] = ida["functions"]
    if isinstance(ida.get("comments"), list):
        base["comments"] = ida["comments"]
    if isinstance(ida.get("names"), list):
        base["labels"] = ida["names"]
    elif isinstance(ida.get("labels"), list):
        base["labels"] = ida["labels"]
    return base


def _normalize_rizin(payload):
    base = _normalize_generic(payload)
    rz = payload.get("rizin", payload)
    base["source"] = "rizin"
    if isinstance(rz.get("functions"), list):
        base["functions"] = rz["functions"]
    elif isinstance(rz.get("aflj"), list):
        base["functions"] = rz["aflj"]
    if isinstance(rz.get("comments"), list):
        base["comments"] = rz["comments"]
    if isinstance(rz.get("flags"), list):
        base["labels"] = rz["flags"]
    return base


def normalize_re_annotations(payload):
    source = str(payload.get("source") or payload.get("tool") or payload.get("format") or "unknown").lower()
    if source == "ghidra":
        return _normalize_ghidra(payload)
    if source == "ida":
        return _normalize_ida(payload)
    if source in {"rizin", "radare2", "rz"}:
        return _normalize_rizin(payload)
    normalized = _normalize_generic(payload)
    if "ghidra" in payload:
        return _normalize_ghidra(payload)
    if "ida" in payload:
        return _normalize_ida(payload)
    if "rizin" in payload:
        return _normalize_rizin(payload)
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
        payload["source"] = "ghidra"
        payload["ghidra"] = {
            "tags": {
                "language_guess": scan.get("source_language", "Unknown"),
                "compiler_guess": scan.get("compiler", "Unknown"),
                "artifact_guess": artifact.get("artifact_type", "Unknown"),
            },
            "functions": scan.get("binary_map", {}).get("symbols", [])[:300],
            "comments": [
                {"address": scan.get("binary_map", {}).get("entry_point", 0), "text": "ELFexplorer entrypoint"}
            ],
        }
    elif export_format == "ida":
        payload["source"] = "ida"
        payload["ida"] = {
            "comments": [
                f"ELFexplorer language={scan.get('source_language', 'Unknown')}",
                f"ELFexplorer compiler={scan.get('compiler', 'Unknown')}",
                f"ELFexplorer build={scan.get('build_system', 'Unknown')}",
                f"ELFexplorer artifact={artifact.get('artifact_type', 'Unknown')}",
            ],
            "names": scan.get("binary_map", {}).get("symbols", [])[:300],
        }
    elif export_format == "rizin":
        payload["source"] = "rizin"
        payload["rizin"] = {
            "meta": {
                "analysis.language": scan.get("source_language", "Unknown"),
                "analysis.compiler": scan.get("compiler", "Unknown"),
                "analysis.build_system": scan.get("build_system", "Unknown"),
                "analysis.artifact": artifact.get("artifact_type", "Unknown"),
            },
            "aflj": scan.get("binary_map", {}).get("symbols", [])[:300],
        }
    return payload


def export_re_payload(report, path, export_format="generic"):
    payload = build_re_export_payload(report, export_format=export_format)
    out_path = Path(path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return out_path


def merge_scan_and_re_annotations(scan_result, normalized_annotations, policy="union"):
    policy = str(policy or "union").strip().lower()
    if policy not in {"union", "prefer-import", "prefer-scan"}:
        raise ValueError("re merge policy must be one of: union, prefer-import, prefer-scan")

    scan_map = dict(scan_result.get("binary_map", {}))
    scan_symbols = list(scan_map.get("symbols", []))
    imported_functions = list(normalized_annotations.get("functions", []))
    imported_labels = list(normalized_annotations.get("labels", []))
    imported_comments = list(normalized_annotations.get("comments", []))

    if policy == "prefer-import":
        merged_symbols = _dedupe_entries(imported_functions + imported_labels)
    elif policy == "prefer-scan":
        merged_symbols = _dedupe_entries(scan_symbols)
    else:
        merged_symbols = _dedupe_entries(scan_symbols + imported_functions + imported_labels)

    return {
        "policy": policy,
        "source": normalized_annotations.get("source", "unknown"),
        "merged_symbol_count": len(merged_symbols),
        "imported_comment_count": len(imported_comments),
        "symbols": merged_symbols[:500],
        "comments": imported_comments[:500],
    }
