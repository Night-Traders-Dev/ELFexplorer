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
import os
import sys

from elftools.elf.elffile import ELFFile

from detect.elfdetect import detect_build_system, detect_compiler, detect_source_language
from info.elfinfo import print_detailed_info, print_general_info, print_important_info

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


def analyze_elf(filepath, output_mode):
    try:
        with open(filepath, "rb") as file:
            elf = ELFFile(file)
            print(_rule("ELF Scan Report", FG_CYAN))
            _print_key_value("File", filepath)
            _print_key_value("Mode", output_mode)
            _print_key_value("PID", str(os.getpid()), FG_MAGENTA)
            print()

            print(_rule("Heuristic Scoring", FG_YELLOW))
            source_language = detect_source_language(elf)
            compiler = detect_compiler(elf)
            build_system = detect_build_system(elf)
            print()

            print(_rule("Detection Summary", FG_GREEN))
            lang_label = _styled("Detected Source Language (heuristic):", STYLE_BOLD, FG_GREEN)
            comp_label = _styled("Detected Compiler (heuristic):", STYLE_BOLD, FG_GREEN)
            build_label = _styled("Detected Host Build System (heuristic):", STYLE_BOLD, FG_GREEN)
            print(f"{lang_label} {source_language}")
            print(f"{comp_label} {compiler}\n")
            print(f"{build_label} {build_system}\n")

            print(_rule("ELF Metadata", FG_CYAN))
            if output_mode == "general":
                print_general_info(elf)
            elif output_mode == "important":
                print_important_info(elf)
            elif output_mode == "detailed":
                print_detailed_info(elf)
            else:
                print("Unknown output mode selected.")

            print()
            print(_styled("Completed ELF scan.", STYLE_DIM, FG_CYAN))
    except Exception as exc:
        msg = _styled("Error processing ELF file:", STYLE_BOLD, FG_MAGENTA)
        print(f"{msg} {exc}")


def main():
    parser = argparse.ArgumentParser(description="Analyze an ELF file with selectable output modes.")
    parser.add_argument("filepath", help="Path to the ELF file to analyze.")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["general", "important", "detailed"],
        default="general",
        help="Output mode: general (default), important, or detailed.",
    )
    args = parser.parse_args()
    analyze_elf(args.filepath, args.mode)


if __name__ == "__main__":
    main()
