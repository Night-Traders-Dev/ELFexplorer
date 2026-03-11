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

from elftools.elf.elffile import ELFFile

from detect.elfdetect import detect_compiler, detect_source_language
from info.elfinfo import print_detailed_info, print_general_info, print_important_info


def analyze_elf(filepath, output_mode):
    try:
        with open(filepath, "rb") as file:
            elf = ELFFile(file)
            source_language = detect_source_language(elf)
            compiler = detect_compiler(elf)
            print(f"Detected Source Language (heuristic): {source_language}\n")
            print(f"Detected Compiler (heuristic): {compiler}\n")
            if output_mode == "general":
                print_general_info(elf)
            elif output_mode == "important":
                print_important_info(elf)
            elif output_mode == "detailed":
                print_detailed_info(elf)
            else:
                print("Unknown output mode selected.")
    except Exception as exc:
        print(f"Error processing ELF file: {exc}")


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
