#!/usr/bin/env python3

"""
elfscan.py

A Python script to analyze an ELF file using pyelftools with selectable output modes.
Output modes:
  - general: Basic information overview.
  - important: Key header and segment information.
  - detailed: All available information including section details.

Usage:
  python3 elfscan.py [-m {general,important,detailed}] <path-to-elf-file>
"""

import argparse
import io
import os
import sys
from contextlib import redirect_stdout

from elftools.elf.elffile import ELFFile

from detect.elfdetect import (
    detect_artifact_profile,
    detect_build_system,
    detect_compiler,
    detect_source_language,
)
from info.elfinfo import print_detailed_info, print_general_info, print_important_info
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


def _scan_heuristics(elf, emit_report=True):
    artifact_profile = detect_artifact_profile(elf, emit_report=emit_report)
    source_language, language_scores = detect_source_language(
        elf,
        artifact_profile=artifact_profile,
        emit_report=emit_report,
        return_details=True,
    )
    compiler, compiler_scores = detect_compiler(
        elf,
        source_language=source_language,
        artifact_profile=artifact_profile,
        emit_report=emit_report,
        return_details=True,
    )
    build_system, build_scores = detect_build_system(
        elf,
        artifact_profile=artifact_profile,
        emit_report=emit_report,
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


def _print_score_table(title, scores):
    print(title)
    for label, score in scores.items():
        print(f"  {label}: {score}")


def _print_plain_report(filepath, output_mode, scan_result, metadata_text):
    artifact_profile = scan_result["artifact_profile"]
    source_language = scan_result["source_language"]
    compiler = scan_result["compiler"]
    build_system = scan_result["build_system"]

    print(_rule("ELF Scan Report", FG_CYAN))
    _print_key_value("File", filepath)
    _print_key_value("Mode", output_mode)
    _print_key_value("Version", get_version(), FG_MAGENTA)
    _print_key_value("PID", str(os.getpid()), FG_MAGENTA)
    print()

    print(_rule("Heuristic Scoring", FG_YELLOW))
    _print_score_table("Artifact detection scores:", artifact_profile.get("scores", {}))
    _print_score_table("Language detection scores:", scan_result["language_scores"])
    _print_score_table("Compiler detection scores:", scan_result["compiler_scores"])
    _print_score_table("Build system detection scores:", scan_result["build_scores"])
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
    print(f"{lang_label} {source_language}")
    print(f"{comp_label} {compiler}")
    print(f"{build_label} {build_system}\n")
    print(f"{artifact_label} {artifact_profile.get('artifact_type', 'Unknown')}")
    print(f"{confidence_label} {artifact_profile.get('confidence', 0)}")
    print(f"{target_label} {artifact_profile.get('target', 'Unknown')}")
    print(f"{sdk_label} {artifact_profile.get('sdk', 'Unknown')}")
    print(f"{rtos_label} {artifact_profile.get('rtos', 'None detected')}")
    print(f"{linkage_label} {artifact_profile.get('linkage_model', 'Unknown')}")
    print(f"{runtime_label} {artifact_profile.get('runtime', 'Unknown')}\n")

    print(_rule("ELF Metadata", FG_CYAN))
    print(metadata_text)
    print()
    print(_styled("Completed ELF scan.", STYLE_DIM, FG_CYAN))


def _run_textual_report(report):
    try:
        from ui.textual_report import run_textual_report
        run_textual_report(report)
        return True
    except Exception as exc:
        print("Textual UI unavailable, falling back to plain report.")
        print(f"Reason: {exc}")
        return False


def analyze_elf(filepath, output_mode, ui_mode="plain"):
    try:
        with open(filepath, "rb") as file:
            elf = ELFFile(file)
            scan_result = _scan_heuristics(elf, emit_report=False)
            metadata_text = _render_metadata(elf, output_mode)

            if ui_mode == "textual":
                report = {
                    "file": filepath,
                    "mode": output_mode,
                    "version": get_version(),
                    "scan_result": scan_result,
                    "metadata_text": metadata_text,
                }
                if _run_textual_report(report):
                    return

            _print_plain_report(filepath, output_mode, scan_result, metadata_text)
    except Exception as exc:
        msg = _styled("Error processing ELF file:", STYLE_BOLD, FG_MAGENTA)
        print(f"{msg} {exc}")


def main():
    parser = argparse.ArgumentParser(description="Analyze an ELF file with selectable output modes.")
    parser.add_argument(
        "--version",
        action="version",
        version=f"ELFexplorer {get_version()}",
    )
    parser.add_argument("filepath", help="Path to the ELF file to analyze.")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["general", "important", "detailed"],
        default="general",
        help="Output mode: general (default), important, or detailed.",
    )
    parser.add_argument(
        "--ui",
        choices=["plain", "textual"],
        default="plain",
        help="Report UI mode: plain (default) or textual.",
    )
    args = parser.parse_args()
    analyze_elf(args.filepath, args.mode, ui_mode=args.ui)


if __name__ == "__main__":
    main()
