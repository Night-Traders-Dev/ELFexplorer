#!/usr/bin/env python3

"""
elfscan.py

A Python script to analyze ELF files with selectable output and UI modes.
"""

import sys

from scancli.args import build_parser
from scancli.render import display_report, print_collection_summary, print_plain_report
from scancli.scan import build_scan_report
from scancli.styles import FG_MAGENTA, STYLE_BOLD, styled
from scancli.workflow import (
    collect_reports_from_args,
    crawl_directory,
    handle_no_input,
    save_and_export_collection,
    save_and_export_single,
)


def main():
    explicit_ui = "--ui" in sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args()

    try:
        reports = collect_reports_from_args(args)

        if not reports:
            return handle_no_input(args, explicit_ui)

        if len(reports) == 1:
            report = reports[0]
            display_report(report, ui_mode=args.ui, explicit_ui=explicit_ui)
            save_and_export_single(report, args)
            if args.save_collection is not None or args.export_collection_md or args.export_collection_pdf:
                save_and_export_collection(reports, args)
            return 0

        print_collection_summary(reports)
        if args.show_each:
            for report in reports:
                display_report(report, ui_mode="plain", explicit_ui=explicit_ui)
                print()
        save_and_export_collection(reports, args)
        return 0
    except Exception as exc:
        msg = styled("Error processing ELF file:", STYLE_BOLD, FG_MAGENTA)
        print(f"{msg} {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

