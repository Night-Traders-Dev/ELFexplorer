import argparse

from version import get_version


def build_parser():
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
    return parser

