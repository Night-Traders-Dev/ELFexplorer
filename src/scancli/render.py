import os

from advanced.toolbridge import list_tool_plugin_formats
from version import get_version

from .styles import (
    FG_CYAN,
    FG_GREEN,
    FG_MAGENTA,
    FG_YELLOW,
    STYLE_BOLD,
    STYLE_DIM,
    print_key_value,
    rule,
    styled,
)


def print_score_table(title, scores):
    print(title)
    for label, score in scores.items():
        print(f"  {label}: {score}")


def _print_explanation_block(explanations):
    if not explanations:
        print("No explainability data available.")
        return
    for key in ("language", "compiler", "build_system", "artifact"):
        data = explanations.get(key, {})
        print(f"{key}:")
        print(f"  predicted: {data.get('predicted', 'Unknown')}")
        print(f"  confidence note: {data.get('confidence_note', 'n/a')}")
        print(f"  score margin: {data.get('score_margin', 0)}")
        positives = data.get("top_positive", [])
        competitors = data.get("top_competitors", [])
        if positives:
            print("  top positive:")
            for item in positives[:5]:
                print(f"    - {item.get('label')}: {item.get('score')}")
        if competitors:
            print("  top competitors:")
            for item in competitors[:5]:
                print(f"    - {item.get('label')}: {item.get('score')}")


def print_plain_report(report, show_explain=False):
    scan_result = report["scan_result"]
    artifact_profile = scan_result["artifact_profile"]

    print(rule("Binary Scan Report", FG_CYAN))
    print_key_value("File", report.get("file", "Unknown"))
    print_key_value("Mode", report.get("mode", "general"))
    print_key_value("Version", report.get("version", get_version()), FG_MAGENTA)
    print_key_value("PID", str(os.getpid()), FG_MAGENTA)
    print()

    print(rule("Heuristic Scoring", FG_YELLOW))
    print_score_table("Artifact detection scores:", artifact_profile.get("scores", {}))
    print_score_table("Language detection scores:", scan_result.get("language_scores", {}))
    print_score_table("Compiler detection scores:", scan_result.get("compiler_scores", {}))
    print_score_table("Build system detection scores:", scan_result.get("build_scores", {}))
    print("Artifact profile details:")
    print(f"  Artifact Type: {artifact_profile.get('artifact_type', 'Unknown')}")
    print(f"  Confidence: {artifact_profile.get('confidence', 0)}")
    if "confidence_calibrated" in artifact_profile:
        print(f"  Confidence Calibrated: {artifact_profile.get('confidence_calibrated', 0)}")
    if "confidence_raw" in artifact_profile:
        print(f"  Confidence Raw: {artifact_profile.get('confidence_raw', 0)}")
    print(f"  Linkage Model: {artifact_profile.get('linkage_model', 'Unknown')}")
    print(f"  Target Hint: {artifact_profile.get('target', 'Unknown')}")
    print(f"  SDK Hint: {artifact_profile.get('sdk', 'Unknown')}")
    print(f"  RTOS Hint: {artifact_profile.get('rtos', 'None detected')}")
    print(f"  Runtime Hint: {artifact_profile.get('runtime', 'Unknown')}")
    print(f"  Loader: {artifact_profile.get('loader', 'None')}")
    print()

    print(rule("Detection Summary", FG_GREEN))
    lang_label = styled("Detected Source Language (heuristic):", STYLE_BOLD, FG_GREEN)
    comp_label = styled("Detected Compiler (heuristic):", STYLE_BOLD, FG_GREEN)
    build_label = styled("Detected Host Build System (heuristic):", STYLE_BOLD, FG_GREEN)
    artifact_label = styled("Detected Artifact Type (heuristic):", STYLE_BOLD, FG_GREEN)
    confidence_label = styled("Artifact Confidence:", STYLE_BOLD, FG_GREEN)
    target_label = styled("Likely Target (heuristic):", STYLE_BOLD, FG_GREEN)
    sdk_label = styled("Likely SDK/Framework (heuristic):", STYLE_BOLD, FG_GREEN)
    rtos_label = styled("Likely RTOS (heuristic):", STYLE_BOLD, FG_GREEN)
    linkage_label = styled("Likely Linkage Model:", STYLE_BOLD, FG_GREEN)
    runtime_label = styled("Likely Runtime C Library:", STYLE_BOLD, FG_GREEN)
    print(f"{lang_label} {scan_result.get('source_language', 'Unknown')}")
    print(f"{comp_label} {scan_result.get('compiler', 'Unknown')}")
    print(f"{build_label} {scan_result.get('build_system', 'Unknown')}\n")
    print(f"{artifact_label} {artifact_profile.get('artifact_type', 'Unknown')}")
    print(f"{confidence_label} {artifact_profile.get('confidence', 0)}")
    if "confidence_raw" in artifact_profile:
        print(f"{styled('Raw Artifact Confidence:', STYLE_BOLD, FG_GREEN)} {artifact_profile.get('confidence_raw', 0)}")
    if "confidence_calibrated" in artifact_profile:
        print(
            f"{styled('Calibrated Artifact Confidence:', STYLE_BOLD, FG_GREEN)} "
            f"{artifact_profile.get('confidence_calibrated', artifact_profile.get('confidence', 0))}"
        )
    print(f"{target_label} {artifact_profile.get('target', 'Unknown')}")
    print(f"{sdk_label} {artifact_profile.get('sdk', 'Unknown')}")
    print(f"{rtos_label} {artifact_profile.get('rtos', 'None detected')}")
    print(f"{linkage_label} {artifact_profile.get('linkage_model', 'Unknown')}")
    print(f"{runtime_label} {artifact_profile.get('runtime', 'Unknown')}\n")

    print(rule("Binary Metadata", FG_CYAN))
    print(report.get("metadata_text", "").rstrip())
    print()
    print(rule("Tool Integrations", FG_YELLOW))
    print("External-tool exports available from this report:")
    for key, meta in sorted(list_tool_plugin_formats().items()):
        print(
            f"  - {key}: {meta.get('label', key)} "
            f"({meta.get('extension', '')})"
        )
    if show_explain:
        print()
        print(rule("Explainability", FG_YELLOW))
        _print_explanation_block(scan_result.get("explanations", {}))

        print()
        print(rule("Hardening / Packing Signals", FG_YELLOW))
        hardening = scan_result.get("hardening_profile", {})
        if not hardening:
            print("No hardening profile available.")
        else:
            print(f"Risk Level: {hardening.get('risk_level', 'unknown')}")
            print(f"Stripped: {hardening.get('stripped', False)}")
            print(f"Likely Packed: {hardening.get('likely_packed', False)}")
            print(f"Likely Obfuscated: {hardening.get('likely_obfuscated', False)}")
            print(f".text Entropy: {hardening.get('text_entropy', 0.0)}")
            for item in hardening.get("signals", []):
                print(f"  - {item}")

        print()
        print(rule("Mixed Attribution", FG_YELLOW))
        mixed = scan_result.get("mixed_attribution", {})
        print(
            "Dominant symbol language: "
            f"{mixed.get('symbol_dominant_language', 'Unknown')} "
            f"(score={mixed.get('symbol_dominant_score', 0)})"
        )
        section_hints = mixed.get("section_hints", [])
        if section_hints:
            print("Section hints:")
            for hint in section_hints[:12]:
                print(
                    f"  - {hint.get('section')}: "
                    f"lang={hint.get('language_hint')}({hint.get('language_score')}) "
                    f"compiler={hint.get('compiler_hint')}({hint.get('compiler_score')})"
                )
        else:
            print("No section-level mixed-attribution hints.")

        print()
        print(rule("Firmware Fingerprint", FG_YELLOW))
        fw = scan_result.get("firmware_fingerprint", {})
        if fw:
            print(f"Firmware Candidate: {fw.get('is_firmware_candidate', False)}")
            print(f"Firmware Confidence: {fw.get('firmware_confidence', 0)}")
            print(f"Likely MCU: {fw.get('likely_mcu', 'Unknown')}")
            print(f"Likely Vendor: {fw.get('likely_vendor', 'Unknown')}")
            print(f"SDK Candidates: {', '.join(fw.get('sdk_candidates', [])) or 'None'}")
            sdk_versions = fw.get("sdk_versions", {})
            if sdk_versions:
                print("SDK Versions:")
                for sdk_name, versions in sorted(sdk_versions.items()):
                    print(f"  - {sdk_name}: {', '.join(versions)}")
            print(f"RTOS Candidates: {', '.join(fw.get('rtos_candidates', [])) or 'None'}")
            linker_hints = fw.get("linker_hints", [])
            if linker_hints:
                print("Linker Hints:")
                for hint in linker_hints:
                    print(f"  - {hint}")
            vector_profile = fw.get("vector_table_profile", {})
            if vector_profile:
                print(
                    "Vector Table Profile: "
                    f"present={vector_profile.get('looks_like_vector_table', False)} "
                    f"section={vector_profile.get('section', 'None')} "
                    f"initial_sp={vector_profile.get('initial_sp', 'None')} "
                    f"reset_handler={vector_profile.get('reset_handler', 'None')}"
                )
            for item in fw.get("signals", []):
                print(f"  - {item}")
        else:
            print("No firmware fingerprint data available.")

        plugin_evidence = scan_result.get("plugin_evidence")
        if plugin_evidence:
            print()
            print(rule("Plugin / Signature Evidence", FG_YELLOW))
            pack_names = plugin_evidence.get("pack_names", [])
            if pack_names:
                print(f"Active packs: {', '.join(pack_names)}")
            diagnostics = plugin_evidence.get("diagnostics", [])
            if diagnostics:
                print("Pack diagnostics:")
                for line in diagnostics:
                    print(f"  - {line}")
            for category in ("languages", "compilers", "build_systems", "artifacts"):
                hits = plugin_evidence.get(category, [])
                if not hits:
                    continue
                print(f"{category}:")
                for hit in hits:
                    print(
                        f"  - {hit.get('rule')}: target={hit.get('target')} "
                        f"delta={hit.get('score_delta', 0)} sections={hit.get('sections')} "
                        f"priority={hit.get('priority', 0)} op={hit.get('operation', 'add')}"
                    )
        merged_re = scan_result.get("re_annotations_merged")
        if merged_re:
            print()
            print(rule("Merged RE View", FG_YELLOW))
            print(f"source={merged_re.get('source', 'unknown')} policy={merged_re.get('policy', 'union')}")
            print(f"merged_symbol_count={merged_re.get('merged_symbol_count', 0)}")
            print(f"imported_comment_count={merged_re.get('imported_comment_count', 0)}")
    print()
    print(styled("Completed binary scan.", STYLE_DIM, FG_CYAN))


def run_textual_report(report, explicit_ui=False):
    try:
        from ui.textual_report import run_textual_report as run_textual_report_ui

        run_textual_report_ui(report)
        return True
    except Exception as exc:
        if explicit_ui:
            print("Textual UI unavailable, falling back to plain report.")
            print(f"Reason: {exc}")
        return False


def run_textual_workspace(callbacks, explicit_ui=False):
    try:
        from ui.textual_workspace import run_textual_workspace as run_textual_workspace_ui

        run_textual_workspace_ui(callbacks)
        return True
    except Exception as exc:
        if explicit_ui:
            print("Textual workspace unavailable.")
            print(f"Reason: {exc}")
        return False


def display_report(report, ui_mode="textual", explicit_ui=False, show_explain=False):
    if ui_mode == "textual" and run_textual_report(report, explicit_ui=explicit_ui):
        return
    print_plain_report(report, show_explain=show_explain)


def print_collection_summary(reports):
    if not reports:
        print("No reports to summarize.")
        return
    print(rule("Collection Summary", FG_YELLOW))
    print(f"Reports: {len(reports)}")
    for index, report in enumerate(reports, start=1):
        scan = report.get("scan_result", {})
        artifact = scan.get("artifact_profile", {})
        print(
            f"{index:>3}. {report.get('file', 'Unknown')} | "
            f"lang={scan.get('source_language', 'Unknown')} "
            f"compiler={scan.get('compiler', 'Unknown')} "
            f"build={scan.get('build_system', 'Unknown')} "
            f"artifact={artifact.get('artifact_type', 'Unknown')}"
        )
    print()
