import os

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


def print_plain_report(report):
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
    print(f"{target_label} {artifact_profile.get('target', 'Unknown')}")
    print(f"{sdk_label} {artifact_profile.get('sdk', 'Unknown')}")
    print(f"{rtos_label} {artifact_profile.get('rtos', 'None detected')}")
    print(f"{linkage_label} {artifact_profile.get('linkage_model', 'Unknown')}")
    print(f"{runtime_label} {artifact_profile.get('runtime', 'Unknown')}\n")

    print(rule("Binary Metadata", FG_CYAN))
    print(report.get("metadata_text", "").rstrip())
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


def display_report(report, ui_mode="textual", explicit_ui=False):
    if ui_mode == "textual" and run_textual_report(report, explicit_ui=explicit_ui):
        return
    print_plain_report(report)


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
