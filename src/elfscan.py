#!/usr/bin/env python3

"""
elfscan.py

A Python script to analyze ELF files with selectable output and UI modes.
"""

import argparse
import io
import os
import sys
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from elftools.elf.elffile import ELFFile

from detect.elfdetect import (
    detect_artifact_profile,
    detect_build_system,
    detect_compiler,
    detect_source_language,
)
from info.elfinfo import print_detailed_info, print_general_info, print_important_info
from reporting.export import (
    export_collection_markdown,
    export_collection_pdf,
    export_report_markdown,
    export_report_pdf,
)
from reporting.persistence import (
    list_saved_reports,
    load_collection,
    load_report,
    save_collection,
    save_report,
)
from reporting.tasks import run_task_file
from version import get_version

STYLE_RESET = "\033[0m"
STYLE_BOLD = "\033[1m"
STYLE_DIM = "\033[2m"
FG_CYAN = "\033[36m"
FG_GREEN = "\033[32m"
FG_YELLOW = "\033[33m"
FG_MAGENTA = "\033[35m"
FG_BLUE = "\033[34m"


def _color_enabled():
    if os.getenv("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _styled(text, *codes):
    if not _color_enabled():
        return text
    return "".join(codes) + text + STYLE_RESET


def _rule(title, color=FG_CYAN):
    label = _styled(f" {title} ", STYLE_BOLD, color)
    line = "-" * 20
    return f"{line}{label}{line}"


def _print_key_value(key, value, color=FG_BLUE):
    key_text = _styled(f"{key:<18}", STYLE_BOLD, color)
    print(f"{key_text} {value}")


def _render_metadata(elf, output_mode):
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


def _scan_heuristics(elf):
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
    return {
        "artifact_profile": artifact_profile,
        "source_language": source_language,
        "language_scores": language_scores,
        "compiler": compiler,
        "compiler_scores": compiler_scores,
        "build_system": build_system,
        "build_scores": build_scores,
    }


def _report_timestamp():
    return datetime.now(timezone.utc).isoformat()


def build_scan_report(filepath, mode="general"):
    input_path = Path(filepath).expanduser()
    resolved_path = str(input_path.resolve()) if input_path.exists() else str(input_path)

    with open(input_path, "rb") as handle:
        elf = ELFFile(handle)
        scan_result = _scan_heuristics(elf)
        metadata_text = _render_metadata(elf, mode)

    return {
        "file": resolved_path,
        "mode": mode,
        "version": get_version(),
        "generated_at": _report_timestamp(),
        "scan_result": scan_result,
        "metadata_text": metadata_text,
    }


def _print_score_table(title, scores):
    print(title)
    for label, score in scores.items():
        print(f"  {label}: {score}")


def print_plain_report(report):
    scan_result = report["scan_result"]
    artifact_profile = scan_result["artifact_profile"]

    print(_rule("ELF Scan Report", FG_CYAN))
    _print_key_value("File", report.get("file", "Unknown"))
    _print_key_value("Mode", report.get("mode", "general"))
    _print_key_value("Version", report.get("version", get_version()), FG_MAGENTA)
    _print_key_value("PID", str(os.getpid()), FG_MAGENTA)
    print()

    print(_rule("Heuristic Scoring", FG_YELLOW))
    _print_score_table("Artifact detection scores:", artifact_profile.get("scores", {}))
    _print_score_table("Language detection scores:", scan_result.get("language_scores", {}))
    _print_score_table("Compiler detection scores:", scan_result.get("compiler_scores", {}))
    _print_score_table("Build system detection scores:", scan_result.get("build_scores", {}))
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

    print(_rule("Detection Summary", FG_GREEN))
    lang_label = _styled("Detected Source Language (heuristic):", STYLE_BOLD, FG_GREEN)
    comp_label = _styled("Detected Compiler (heuristic):", STYLE_BOLD, FG_GREEN)
    build_label = _styled("Detected Host Build System (heuristic):", STYLE_BOLD, FG_GREEN)
    artifact_label = _styled("Detected Artifact Type (heuristic):", STYLE_BOLD, FG_GREEN)
    confidence_label = _styled("Artifact Confidence:", STYLE_BOLD, FG_GREEN)
    target_label = _styled("Likely Target (heuristic):", STYLE_BOLD, FG_GREEN)
    sdk_label = _styled("Likely SDK/Framework (heuristic):", STYLE_BOLD, FG_GREEN)
    rtos_label = _styled("Likely RTOS (heuristic):", STYLE_BOLD, FG_GREEN)
    linkage_label = _styled("Likely Linkage Model:", STYLE_BOLD, FG_GREEN)
    runtime_label = _styled("Likely Runtime C Library:", STYLE_BOLD, FG_GREEN)
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

    print(_rule("ELF Metadata", FG_CYAN))
    print(report.get("metadata_text", "").rstrip())
    print()
    print(_styled("Completed ELF scan.", STYLE_DIM, FG_CYAN))


def _run_textual_report(report, explicit_ui=False):
    try:
        from ui.textual_report import run_textual_report

        run_textual_report(report)
        return True
    except Exception as exc:
        if explicit_ui:
            print("Textual UI unavailable, falling back to plain report.")
            print(f"Reason: {exc}")
        return False


def _run_textual_workspace(callbacks, explicit_ui=False):
    try:
        from ui.textual_workspace import run_textual_workspace

        run_textual_workspace(callbacks)
        return True
    except Exception as exc:
        if explicit_ui:
            print("Textual workspace unavailable.")
            print(f"Reason: {exc}")
        return False


def _display_report(report, ui_mode="textual", explicit_ui=False):
    if ui_mode == "textual" and _run_textual_report(report, explicit_ui=explicit_ui):
        return
    print_plain_report(report)


def _is_elf_file(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except Exception:
        return False


def crawl_directory(directory, mode="general", recursive=True, max_files=None):
    root = Path(directory).expanduser()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Directory not found: {root}")

    paths = root.rglob("*") if recursive else root.glob("*")
    reports = []
    for path in paths:
        if not path.is_file():
            continue
        if not _is_elf_file(path):
            continue
        reports.append(build_scan_report(str(path), mode=mode))
        if max_files is not None and len(reports) >= max_files:
            break
    return reports


def _print_collection_summary(reports):
    if not reports:
        print("No reports to summarize.")
        return
    print(_rule("Collection Summary", FG_YELLOW))
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


def _save_and_export_single(report, args):
    saved_path = None
    if args.save_scan is not None:
        explicit_path = args.save_scan if args.save_scan else None
        saved_path = save_report(report, path=explicit_path, store_dir=args.store_dir)
        print(f"Saved scan JSON: {saved_path}")

    if args.export_md:
        md_path = export_report_markdown(report, args.export_md)
        print(f"Exported Markdown report: {md_path}")

    if args.export_pdf:
        pdf_path = export_report_pdf(report, args.export_pdf)
        print(f"Exported PDF report: {pdf_path}")

    return saved_path


def _save_and_export_collection(reports, args):
    collection_payload = {
        "generated_at": _report_timestamp(),
        "count": len(reports),
        "reports": reports,
    }

    if args.save_collection is not None:
        explicit_path = args.save_collection if args.save_collection else None
        saved = save_collection(reports, path=explicit_path, store_dir=args.store_dir)
        print(f"Saved collection JSON: {saved}")
    elif args.save_scan is not None and not args.save_scan:
        for report in reports:
            saved = save_report(report, path=None, store_dir=args.store_dir)
            print(f"Saved scan JSON: {saved}")
    elif args.save_scan:
        raise ValueError("Use --save-collection for multiple reports (or --save-scan with no path).")

    if args.export_collection_md:
        md_path = export_collection_markdown(collection_payload, args.export_collection_md)
        print(f"Exported Markdown collection: {md_path}")

    if args.export_collection_pdf:
        pdf_path = export_collection_pdf(collection_payload, args.export_collection_pdf)
        print(f"Exported PDF collection: {pdf_path}")


def _collect_reports_from_args(args):
    reports = []

    if args.load_scan:
        reports.append(load_report(args.load_scan))

    if args.load_collection:
        payload = load_collection(args.load_collection)
        reports.extend(payload.get("reports", []))

    if args.filepath:
        reports.append(build_scan_report(args.filepath, mode=args.mode))

    if args.crawl:
        reports.extend(
            crawl_directory(
                args.crawl,
                mode=args.mode,
                recursive=(not args.no_recursive),
                max_files=args.max_files,
            )
        )

    if args.task_file:
        task_reports = run_task_file(
            args.task_file,
            scan_binary_func=lambda path, mode=args.mode: build_scan_report(path, mode=mode),
            crawl_directory_func=lambda path, mode=args.mode, recursive=True, max_files=None: crawl_directory(
                path,
                mode=mode,
                recursive=recursive,
                max_files=max_files,
            ),
            default_mode=args.mode,
        )
        reports.extend(task_reports)

    return reports


def _workspace_callbacks(ui_mode, explicit_ui, store_dir):
    return {
        "scan": lambda path, mode="general": build_scan_report(path, mode=mode),
        "crawl": lambda path, mode="general", recursive=True, max_files=None: crawl_directory(
            path,
            mode=mode,
            recursive=recursive,
            max_files=max_files,
        ),
        "load_scan": load_report,
        "load_collection": load_collection,
        "save_scan": lambda report, path=None: save_report(report, path=path, store_dir=store_dir),
        "save_collection": lambda reports, path=None: save_collection(
            reports, path=path, store_dir=store_dir
        ),
        "list_saved": lambda: list_saved_reports(store_dir=store_dir),
        "export_report_md": export_report_markdown,
        "export_report_pdf": export_report_pdf,
        "export_collection_md": export_collection_markdown,
        "export_collection_pdf": export_collection_pdf,
        "show_report": lambda report: _display_report(
            report, ui_mode=ui_mode, explicit_ui=explicit_ui
        ),
    }


def _handle_no_input(args, explicit_ui):
    if args.ui == "textual":
        callbacks = _workspace_callbacks(args.ui, explicit_ui, args.store_dir)
        if _run_textual_workspace(callbacks, explicit_ui=explicit_ui):
            return 0

    print("No binary or workload specified.")
    print("Provide a binary path, --crawl, --task-file, --load-scan, or --load-collection.")
    print("Use --help for all options.")
    return 2


def main():
    explicit_ui = "--ui" in sys.argv[1:]

    parser = argparse.ArgumentParser(description="Analyze ELF files with heuristic profiling and UX modes.")
    parser.add_argument(
        "--version",
        action="version",
        version=f"ELFexplorer {get_version()}",
    )
    parser.add_argument("filepath", nargs="?", help="Path to a single ELF file to analyze.")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["general", "important", "detailed"],
        default="general",
        help="Metadata output mode: general (default), important, or detailed.",
    )
    parser.add_argument(
        "--ui",
        choices=["plain", "textual"],
        default="textual",
        help="UI mode: textual (default) or plain.",
    )
    parser.add_argument("--crawl", help="Recursively scan ELF files under a directory.")
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Disable recursive directory crawling (with --crawl).",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Maximum number of ELF files to process during crawl.",
    )
    parser.add_argument("--task-file", help="Run scan tasks from a JSON task file.")
    parser.add_argument("--load-scan", help="Load a previously saved scan JSON report.")
    parser.add_argument("--load-collection", help="Load a saved report collection JSON.")
    parser.add_argument(
        "--save-scan",
        nargs="?",
        const="",
        help="Save scan report JSON. Optional path; if omitted, save to default scan store.",
    )
    parser.add_argument(
        "--save-collection",
        nargs="?",
        const="",
        help="Save report collection JSON. Optional path; if omitted, save to default scan store.",
    )
    parser.add_argument(
        "--store-dir",
        default=None,
        help="Directory for default saved scan/collection JSON files.",
    )
    parser.add_argument("--export-md", help="Export single report as Markdown.")
    parser.add_argument("--export-pdf", help="Export single report as PDF (requires reportlab).")
    parser.add_argument("--export-collection-md", help="Export collection as Markdown.")
    parser.add_argument(
        "--export-collection-pdf",
        help="Export collection as PDF (requires reportlab).",
    )
    parser.add_argument(
        "--show-each",
        action="store_true",
        help="For multiple reports, render each report instead of only a collection summary.",
    )
    args = parser.parse_args()

    try:
        reports = _collect_reports_from_args(args)

        if not reports:
            return _handle_no_input(args, explicit_ui)

        if len(reports) == 1:
            report = reports[0]
            _display_report(report, ui_mode=args.ui, explicit_ui=explicit_ui)
            _save_and_export_single(report, args)
            return 0

        _print_collection_summary(reports)
        if args.show_each:
            for report in reports:
                _display_report(report, ui_mode="plain", explicit_ui=explicit_ui)
                print()
        _save_and_export_collection(reports, args)
        return 0
    except Exception as exc:
        msg = _styled("Error processing ELF file:", STYLE_BOLD, FG_MAGENTA)
        print(f"{msg} {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

