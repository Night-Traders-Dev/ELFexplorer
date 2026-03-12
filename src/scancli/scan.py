import io
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from elftools.elf.elffile import ELFFile

from advanced.calibration import calibrate_confidence
from advanced.explain import build_scan_explanations
from advanced.firmware import detect_firmware_fingerprint
from advanced.hardening import detect_binary_hardening
from advanced.mixed import detect_mixed_attribution
from advanced.plugins import PLUGIN_CATEGORIES, apply_score_rules
from advanced.reinterop import merge_scan_and_re_annotations, normalize_re_annotations
from baremetal import (
    is_intel_hex_file,
    is_raw_firmware_bin_file,
    is_srec_file,
    scan_intel_hex_file,
    scan_raw_binary_file,
    scan_srec_file,
)
from detect.elfdetect import (
    detect_artifact_profile,
    detect_build_system,
    detect_compiler,
    detect_source_language,
)
from elfarchive import is_ar_archive, scan_ar_archive
from info.elfinfo import print_detailed_info, print_general_info, print_important_info
from uf2 import is_uf2_file, scan_uf2_file
from version import get_version


def render_metadata(elf, output_mode):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        if output_mode == "general":
            print_general_info(elf)
        elif output_mode == "important":
            print_important_info(elf)
        elif output_mode == "detailed":
            print_detailed_info(elf)
        else:
            print("Unknown output mode selected.")
    return buffer.getvalue().rstrip()


def _select_scored_label(scores, min_score=1):
    if not scores:
        return "Unknown"
    max_score = max(scores.values())
    top = [label for label, value in scores.items() if value == max_score and value > 0]
    if max_score < min_score:
        return "Unknown"
    if len(top) == 1:
        return top[0]
    if top:
        return "Ambiguous: " + "/".join(top)
    return "Unknown"


def _artifact_confidence_from_scores(scores, label):
    ordered = sorted((scores or {}).values(), reverse=True)
    top_score = ordered[0] if ordered else 0
    second_score = ordered[1] if len(ordered) > 1 else 0
    margin = max(0, top_score - second_score)
    if label == "Unknown":
        return 20
    if str(label).startswith("Ambiguous:"):
        return max(35, min(80, 45 + top_score + margin))
    return max(45, min(99, 50 + top_score + (margin * 2)))


def _extract_binary_map(elf, max_sections=128, max_symbols=2048):
    sections = []
    for index, section in enumerate(elf.iter_sections()):
        if len(sections) >= max_sections:
            break
        try:
            sections.append(
                {
                    "index": index,
                    "name": section.name or "<unnamed>",
                    "type": str(section["sh_type"]),
                    "address": int(section["sh_addr"]),
                    "offset": int(section["sh_offset"]),
                    "size": int(section["sh_size"]),
                }
            )
        except Exception:
            continue

    symbols = []
    for sec_name in (".symtab", ".dynsym"):
        section = elf.get_section_by_name(sec_name)
        if not section:
            continue
        try:
            for symbol in section.iter_symbols():
                if len(symbols) >= max_symbols:
                    break
                name = symbol.name
                if not name:
                    continue
                entry = symbol.entry
                symbols.append(
                    {
                        "name": name,
                        "value": int(entry.get("st_value", 0)),
                        "size": int(entry.get("st_size", 0)),
                        "bind": str(entry.get("st_info", {}).get("bind", "")),
                        "type": str(entry.get("st_info", {}).get("type", "")),
                    }
                )
        except Exception:
            continue

    try:
        header = elf.header
        entry = int(header.get("e_entry", 0))
        machine = str(header.get("e_machine", "Unknown"))
        elf_type = str(header.get("e_type", "Unknown"))
    except Exception:
        entry = 0
        machine = "Unknown"
        elf_type = "Unknown"

    return {
        "entry_point": entry,
        "machine": machine,
        "elf_type": elf_type,
        "sections": sections,
        "symbols": symbols,
    }


def _apply_plugins_to_scores(elf, score_map_by_category, plugin_rules):
    if not plugin_rules:
        return {}
    evidence = {}
    for category in PLUGIN_CATEGORIES:
        rules = plugin_rules.get(category, [])
        if not rules:
            continue
        target_scores = score_map_by_category.get(category)
        if not target_scores:
            continue
        hits = apply_score_rules(elf, target_scores, rules)
        if hits:
            evidence[category] = hits
    pack_names = plugin_rules.get("_pack_names", [])
    if pack_names:
        evidence["pack_names"] = list(pack_names)
    diagnostics = plugin_rules.get("_diagnostics", [])
    if diagnostics:
        evidence["diagnostics"] = list(diagnostics)
    return evidence


def scan_heuristics(elf, options=None):
    options = options or {}
    plugin_rules = options.get("plugin_rules")
    imported_re_annotations = options.get("re_annotations")
    re_merge_policy = options.get("re_merge_policy", "union")
    calibration_model = options.get("calibration_model")
    artifact_profile = detect_artifact_profile(elf, emit_report=False)
    source_language, language_scores = detect_source_language(
        elf,
        artifact_profile=artifact_profile,
        emit_report=False,
        return_details=True,
    )
    compiler, compiler_scores = detect_compiler(
        elf,
        source_language=source_language,
        artifact_profile=artifact_profile,
        emit_report=False,
        return_details=True,
    )
    build_system, build_scores = detect_build_system(
        elf,
        artifact_profile=artifact_profile,
        emit_report=False,
        return_details=True,
    )
    score_map_by_category = {
        "languages": language_scores,
        "compilers": compiler_scores,
        "build_systems": build_scores,
        "artifacts": artifact_profile.get("scores", {}),
    }
    plugin_evidence = _apply_plugins_to_scores(elf, score_map_by_category, plugin_rules)
    if plugin_evidence:
        source_language = _select_scored_label(language_scores, min_score=1)
        compiler = _select_scored_label(compiler_scores, min_score=3)
        build_system = _select_scored_label(build_scores, min_score=3)
        artifact_type = _select_scored_label(artifact_profile.get("scores", {}), min_score=4)
        artifact_profile["artifact_type"] = artifact_type
        artifact_profile["confidence"] = _artifact_confidence_from_scores(
            artifact_profile.get("scores", {}), artifact_type
        )

    hardening_profile = detect_binary_hardening(elf)
    mixed_attribution = detect_mixed_attribution(elf)
    firmware_fingerprint = detect_firmware_fingerprint(elf, artifact_profile)
    binary_map = _extract_binary_map(elf)

    result = {
        "artifact_profile": artifact_profile,
        "source_language": source_language,
        "language_scores": language_scores,
        "compiler": compiler,
        "compiler_scores": compiler_scores,
        "build_system": build_system,
        "build_scores": build_scores,
        "hardening_profile": hardening_profile,
        "mixed_attribution": mixed_attribution,
        "firmware_fingerprint": firmware_fingerprint,
        "binary_map": binary_map,
    }
    if calibration_model and "confidence" in artifact_profile:
        raw_confidence = int(artifact_profile.get("confidence", 0))
        calibrated = calibrate_confidence(raw_confidence, calibration_model)
        artifact_profile["confidence_raw"] = raw_confidence
        artifact_profile["confidence_calibrated"] = calibrated
        artifact_profile["confidence"] = calibrated
        result["calibration_applied"] = True
    result["explanations"] = build_scan_explanations(result)
    if plugin_evidence:
        result["plugin_evidence"] = plugin_evidence
    if imported_re_annotations:
        normalized = normalize_re_annotations(imported_re_annotations)
        result["re_annotations_imported"] = normalized
        result["re_annotations_merged"] = merge_scan_and_re_annotations(
            result,
            normalized,
            policy=re_merge_policy,
        )
    return result


def report_timestamp():
    return datetime.now(timezone.utc).isoformat()


def build_scan_report(filepath, mode="general", options=None):
    options = options or {}
    input_path = Path(filepath).expanduser()
    if is_elf_file(input_path):
        resolved_path = str(input_path.resolve()) if input_path.exists() else str(input_path)

        with open(input_path, "rb") as handle:
            elf = ELFFile(handle)
            scan_result = scan_heuristics(elf, options=options)
            metadata_text = render_metadata(elf, mode)

        return {
            "file": resolved_path,
            "mode": mode,
            "version": get_version(),
            "generated_at": report_timestamp(),
            "scan_result": scan_result,
            "metadata_text": metadata_text,
        }

    if is_uf2_file(input_path):
        return scan_uf2_file(input_path, mode=mode)

    if is_ar_archive(input_path):
        return scan_ar_archive(input_path, mode=mode)

    if is_intel_hex_file(input_path):
        return scan_intel_hex_file(input_path, mode=mode)

    if is_srec_file(input_path):
        return scan_srec_file(input_path, mode=mode)

    if is_raw_firmware_bin_file(input_path):
        return scan_raw_binary_file(input_path, mode=mode)

    raise ValueError(
        "Unsupported file format. Expected ELF, UF2, GNU ar archive, Intel HEX, S-record, or raw firmware binary."
    )


def is_elf_file(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except Exception:
        return False


def is_supported_binary(path):
    return (
        is_elf_file(path)
        or is_uf2_file(path)
        or is_ar_archive(path)
        or is_intel_hex_file(path)
        or is_srec_file(path)
        or is_raw_firmware_bin_file(path)
    )
