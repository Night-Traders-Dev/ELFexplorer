import argparse

from advanced.toolbridge import list_tool_plugin_formats
from version import get_version


def build_parser():
    tool_plugin_formats = sorted(list_tool_plugin_formats())
    parser = argparse.ArgumentParser(
        description=(
            "Analyze ELF-related and firmware binaries "
            "(ELF, UF2, GNU ar, Intel HEX, S-record, raw BIN) with heuristic profiling and UX modes."
        )
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ELFexplorer {get_version()}",
    )
    parser.add_argument(
        "filepath",
        nargs="?",
        help="Path to a single supported binary (ELF/UF2/AR/HEX/SREC/BIN).",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["general", "important", "detailed"],
        default="general",
        help="Metadata output mode: general (default), important, or detailed.",
    )
    parser.add_argument(
        "--ui",
        choices=["plain", "textual", "web"],
        default="textual",
        help="UI mode: textual (default), plain, or web.",
    )
    parser.add_argument(
        "--web-host",
        default="127.0.0.1",
        help="Host/interface for the web dashboard server (used with --ui web).",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=8765,
        help="TCP port for the web dashboard server (used with --ui web).",
    )
    parser.add_argument(
        "--web-open-browser",
        action="store_true",
        help="Open the default browser automatically when starting the web dashboard.",
    )
    parser.add_argument("--crawl", help="Recursively scan supported binaries under a directory.")
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Disable recursive directory crawling (with --crawl).",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Maximum number of supported binaries to process during crawl.",
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
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Show explainability details (top evidence and competitors) in plain reports.",
    )
    parser.add_argument(
        "--signature-pack",
        action="append",
        default=[],
        help="Path to a JSON signature/rule pack to apply for this run. Can be repeated.",
    )
    parser.add_argument(
        "--signatures-dir",
        default=None,
        help="Directory for managed signature packs (default: ~/.elfexplorer/signatures).",
    )
    parser.add_argument(
        "--install-signature-pack",
        default=None,
        help="Install a local signature pack JSON into managed signatures and set as active.",
    )
    parser.add_argument(
        "--update-signatures",
        default=None,
        help="Fetch a signature pack JSON from URL and set as active.",
    )
    parser.add_argument(
        "--list-signature-packs",
        action="store_true",
        help="List managed signature pack JSON files.",
    )
    parser.add_argument(
        "--benchmark-manifest",
        default=None,
        help="Run benchmark from JSON manifest ({cases:[...]}) and exit.",
    )
    parser.add_argument(
        "--benchmark-corpus",
        default=None,
        help="Run benchmark by auto-discovering expected labels from corpus filenames and exit.",
    )
    parser.add_argument(
        "--benchmark-out",
        default=None,
        help="Optional path to save benchmark results JSON.",
    )
    parser.add_argument(
        "--benchmark-export-calibration",
        default=None,
        help="Optional path to save calibration model derived from benchmark reliability.",
    )
    parser.add_argument(
        "--diff",
        default=None,
        help="Compare the primary report against another binary path and print a diff report.",
    )
    parser.add_argument(
        "--export-diff-md",
        default=None,
        help="Optional path to export binary diff as Markdown (requires --diff).",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Enable CI policy evaluation. Non-compliant reports exit with non-zero code.",
    )
    parser.add_argument(
        "--policy-file",
        default=None,
        help="JSON CI policy file path (used with --ci).",
    )
    parser.add_argument(
        "--re-import",
        default=None,
        help="Import reverse-engineering annotations JSON and attach to scan result.",
    )
    parser.add_argument(
        "--re-export",
        default=None,
        help="Export RE annotations JSON after scan.",
    )
    parser.add_argument(
        "--re-export-format",
        choices=["generic", "ghidra", "ida", "rizin"],
        default="generic",
        help="Format for RE annotation export (used with --re-export).",
    )
    parser.add_argument(
        "--re-merge-policy",
        choices=["union", "prefer-import", "prefer-scan"],
        default="union",
        help="Merge policy when RE annotations are imported.",
    )
    parser.add_argument(
        "--list-tool-plugins",
        action="store_true",
        help="List supported external-tool plugin/script export formats.",
    )
    parser.add_argument(
        "--tool-plugin-format",
        choices=tool_plugin_formats,
        default="ghidra",
        help="External-tool plugin/script export format.",
    )
    parser.add_argument(
        "--tool-plugin-export",
        nargs="?",
        const="",
        help=(
            "Export current scan result as an external-tool plugin/script. "
            "Optional file or directory path; if omitted, save under ./reports/."
        ),
    )
    parser.add_argument(
        "--calibration-model",
        default=None,
        help="Path to confidence calibration model JSON to apply during scan.",
    )
    return parser
