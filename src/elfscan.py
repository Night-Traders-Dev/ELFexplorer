#!/usr/bin/env python3

"""
elfscan.py

A Python script to analyze ELF files with selectable output and UI modes.
"""

import sys
from pathlib import Path

import json

from advanced.calibration import build_calibration_model, save_calibration_model
from advanced.benchmark import (
    discover_benchmark_cases,
    load_benchmark_manifest,
    render_benchmark_summary,
    run_benchmark_cases,
)
from advanced.ci import evaluate_benchmark_ci, evaluate_reports_ci, load_policy
from advanced.diffing import compare_reports, diff_to_markdown, render_diff_plain
from advanced.reinterop import export_re_payload
from advanced.signatures import (
    install_signature_pack,
    list_signature_packs,
    update_signature_pack,
)
from advanced.toolbridge import list_tool_plugin_formats
from scancli.args import build_parser
from scancli.render import display_report, print_collection_summary
from scancli.scan import build_scan_report
from scancli.styles import FG_MAGENTA, STYLE_BOLD, styled
from scancli.workflow import (
    build_scan_options,
    collect_reports_from_args,
    export_tool_plugins_for_reports,
    handle_no_input,
    save_and_export_collection,
    save_and_export_single,
)


def main():
    explicit_ui = "--ui" in sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.install_signature_pack:
            installed, active = install_signature_pack(
                args.install_signature_pack,
                signature_dir=args.signatures_dir,
            )
            print(f"Installed signature pack: {installed}")
            print(f"Activated signature pack: {active}")
            if not (
                args.filepath
                or args.crawl
                or args.task_file
                or args.load_scan
                or args.load_collection
                or args.benchmark_manifest
                or args.benchmark_corpus
            ):
                return 0

        if args.update_signatures:
            downloaded, active = update_signature_pack(
                args.update_signatures,
                signature_dir=args.signatures_dir,
            )
            print(f"Downloaded signature pack: {downloaded}")
            print(f"Activated signature pack: {active}")
            if not (
                args.filepath
                or args.crawl
                or args.task_file
                or args.load_scan
                or args.load_collection
                or args.benchmark_manifest
                or args.benchmark_corpus
            ):
                return 0

        if args.list_signature_packs:
            packs = list_signature_packs(args.signatures_dir)
            if not packs:
                print("No signature packs installed.")
            else:
                print("Installed signature packs:")
                for item in packs:
                    print(f"  - {item}")
            if not (
                args.filepath
                or args.crawl
                or args.task_file
                or args.load_scan
                or args.load_collection
                or args.benchmark_manifest
                or args.benchmark_corpus
            ):
                return 0

        if args.list_tool_plugins:
            formats = list_tool_plugin_formats()
            print("Supported tool plugin/script exports:")
            for key in sorted(formats):
                meta = formats[key]
                print(
                    f"  - {key}: {meta.get('label', key)} "
                    f"({meta.get('extension', '')}) - {meta.get('description', '')}"
                )
            if not (
                args.filepath
                or args.crawl
                or args.task_file
                or args.load_scan
                or args.load_collection
                or args.benchmark_manifest
                or args.benchmark_corpus
            ):
                return 0

        scan_options = build_scan_options(args)

        if args.benchmark_manifest or args.benchmark_corpus:
            cases = []
            if args.benchmark_manifest:
                cases.extend(load_benchmark_manifest(args.benchmark_manifest))
            if args.benchmark_corpus:
                cases.extend(discover_benchmark_cases(args.benchmark_corpus))

            def _scan_case(path):
                return build_scan_report(path, mode=args.mode, options=scan_options)

            result = run_benchmark_cases(cases, _scan_case)
            print(render_benchmark_summary(result))
            if args.benchmark_out:
                out_path = Path(args.benchmark_out).expanduser()
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
                print(f"Saved benchmark report: {out_path}")
            if args.benchmark_export_calibration:
                min_samples = 2
                if args.policy_file:
                    policy_for_calibration = load_policy(args.policy_file)
                    min_samples = int(
                        policy_for_calibration.get("benchmark_thresholds", {}).get(
                            "min_reliability_bin_samples",
                            min_samples,
                        )
                    )
                model = build_calibration_model(result, min_samples=min_samples)
                saved_model = save_calibration_model(model, args.benchmark_export_calibration)
                print(f"Saved calibration model: {saved_model}")
            if args.ci:
                ci_result = evaluate_benchmark_ci(result, load_policy(args.policy_file))
                if ci_result["ok"]:
                    print("Benchmark CI policy passed.")
                else:
                    print("Benchmark CI policy failed:")
                    for line in ci_result["violations"]:
                        print(f"  - {line}")
                    return 3
            return 0

        reports = collect_reports_from_args(args, scan_options=scan_options)
        if not reports:
            return handle_no_input(args, explicit_ui)

        if len(reports) == 1:
            report = reports[0]
            display_report(
                report,
                ui_mode=args.ui,
                explicit_ui=explicit_ui,
                show_explain=args.explain,
            )

            if args.diff:
                other_report = build_scan_report(args.diff, mode=args.mode, options=scan_options)
                diff = compare_reports(report, other_report)
                print()
                print(render_diff_plain(diff))
                if args.export_diff_md:
                    out_path = Path(args.export_diff_md).expanduser()
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(diff_to_markdown(diff), encoding="utf-8")
                    print(f"Exported Markdown diff: {out_path}")

            save_and_export_single(report, args)
            export_tool_plugins_for_reports(reports, args)

            if args.re_export:
                exported = export_re_payload(report, args.re_export, export_format=args.re_export_format)
                print(f"Exported RE annotations: {exported}")

            if args.save_collection is not None or args.export_collection_md or args.export_collection_pdf:
                save_and_export_collection(reports, args)

            if args.ci:
                ci_result = evaluate_reports_ci(reports, load_policy(args.policy_file))
                if ci_result["ok"]:
                    print("CI policy passed.")
                else:
                    print("CI policy failed:")
                    for line in ci_result["violations"]:
                        print(f"  - {line}")
                    return 3
            return 0

        print_collection_summary(reports)
        if args.show_each:
            for report in reports:
                display_report(
                    report,
                    ui_mode="plain",
                    explicit_ui=explicit_ui,
                    show_explain=args.explain,
                )
                print()
        save_and_export_collection(reports, args)
        export_tool_plugins_for_reports(reports, args)

        if args.ci:
            ci_result = evaluate_reports_ci(reports, load_policy(args.policy_file))
            if ci_result["ok"]:
                print("CI policy passed.")
            else:
                print("CI policy failed:")
                for line in ci_result["violations"]:
                    print(f"  - {line}")
                return 3
        return 0
    except Exception as exc:
        msg = styled("Error processing ELF file:", STYLE_BOLD, FG_MAGENTA)
        print(f"{msg} {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
