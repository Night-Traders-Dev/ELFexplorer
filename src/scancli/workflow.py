from pathlib import Path

from advanced.calibration import load_calibration_model
from advanced.plugins import load_rule_pack, merge_rule_packs
from advanced.reinterop import load_re_annotations
from advanced.signatures import load_active_signature_pack
from advanced.toolbridge import (
    default_tool_plugin_path,
    export_tool_plugin,
    list_tool_plugin_formats,
)
from advanced.tooling import (
    collect_external_tool_status,
    describe_external_tool,
    download_external_tool,
    install_external_tool,
)
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
from settings import load_tool_path, load_tool_paths

from .render import display_report, run_textual_workspace, run_web_dashboard
from .scan import build_scan_report, is_supported_binary, report_timestamp


def build_scan_options(args):
    packs = []
    if getattr(args, "signature_pack", None):
        for path in args.signature_pack:
            packs.append(load_rule_pack(path))

    active_pack = load_active_signature_pack(getattr(args, "signatures_dir", None))
    if active_pack:
        packs.append(active_pack)

    merged_pack = merge_rule_packs(packs) if packs else None

    re_annotations = None
    if getattr(args, "re_import", None):
        re_annotations = load_re_annotations(args.re_import)
    calibration_model = None
    if getattr(args, "calibration_model", None):
        calibration_model = load_calibration_model(args.calibration_model)

    return {
        "plugin_rules": merged_pack,
        "re_annotations": re_annotations,
        "re_merge_policy": getattr(args, "re_merge_policy", "union"),
        "calibration_model": calibration_model,
    }


def crawl_directory(directory, mode="general", recursive=True, max_files=None, options=None):
    root = Path(directory).expanduser()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Directory not found: {root}")

    paths = root.rglob("*") if recursive else root.glob("*")
    reports = []
    for path in paths:
        if not path.is_file():
            continue
        if not is_supported_binary(path):
            continue
        reports.append(build_scan_report(str(path), mode=mode, options=options))
        if max_files is not None and len(reports) >= max_files:
            break
    return reports


def save_and_export_single(report, args):
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


def save_and_export_collection(reports, args):
    collection_payload = {
        "generated_at": report_timestamp(),
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
    elif args.save_scan and len(reports) > 1:
        raise ValueError("Use --save-collection for multiple reports (or --save-scan with no path).")

    if args.export_collection_md:
        md_path = export_collection_markdown(collection_payload, args.export_collection_md)
        print(f"Exported Markdown collection: {md_path}")

    if args.export_collection_pdf:
        pdf_path = export_collection_pdf(collection_payload, args.export_collection_pdf)
        print(f"Exported PDF collection: {pdf_path}")


def export_tool_plugins_for_reports(reports, args):
    if getattr(args, "tool_plugin_export", None) is None:
        return []
    if not reports:
        return []

    tool_format = getattr(args, "tool_plugin_format", "ghidra")
    raw_target = args.tool_plugin_export
    explicit_target = None if raw_target in (None, "") else Path(raw_target).expanduser()

    if len(reports) == 1:
        report = reports[0]
        if explicit_target is None:
            target_path = default_tool_plugin_path(report, tool_format)
        elif explicit_target.exists() and explicit_target.is_dir():
            target_path = default_tool_plugin_path(report, tool_format, output_dir=explicit_target)
        else:
            target_path = explicit_target
        exported = export_tool_plugin(report, target_path, tool_format)
        print(f"Exported {tool_format} plugin/script: {exported}")
        return [exported]

    if explicit_target is None:
        output_dir = Path.cwd() / "reports"
    elif explicit_target.exists():
        if explicit_target.is_file():
            raise ValueError(
                "Tool-plugin export for multiple reports requires a directory path, not a file."
            )
        output_dir = explicit_target
    elif explicit_target.suffix:
        raise ValueError(
            "Tool-plugin export for multiple reports requires a directory path or omitted path."
        )
    else:
        output_dir = explicit_target

    exported_paths = []
    for report in reports:
        target_path = default_tool_plugin_path(report, tool_format, output_dir=output_dir)
        exported = export_tool_plugin(report, target_path, tool_format)
        print(f"Exported {tool_format} plugin/script: {exported}")
        exported_paths.append(exported)
    return exported_paths


def collect_reports_from_args(args, scan_options=None):
    reports = []
    if scan_options is None:
        scan_options = build_scan_options(args)

    if args.load_scan:
        reports.append(load_report(args.load_scan))

    if args.load_collection:
        payload = load_collection(args.load_collection)
        reports.extend(payload.get("reports", []))

    if args.filepath:
        reports.append(build_scan_report(args.filepath, mode=args.mode, options=scan_options))

    if args.crawl:
        reports.extend(
            crawl_directory(
                args.crawl,
                mode=args.mode,
                recursive=(not args.no_recursive),
                max_files=args.max_files,
                options=scan_options,
            )
        )

    if args.task_file:
        task_reports = run_task_file(
            args.task_file,
            scan_binary_func=lambda path, mode=args.mode: build_scan_report(
                path,
                mode=mode,
                options=scan_options,
            ),
            crawl_directory_func=lambda path, mode=args.mode, recursive=True, max_files=None: crawl_directory(
                path,
                mode=mode,
                recursive=recursive,
                max_files=max_files,
                options=scan_options,
            ),
            default_mode=args.mode,
        )
        reports.extend(task_reports)

    return reports


def workspace_callbacks(ui_mode, explicit_ui, store_dir, scan_options=None):
    scan_options = scan_options or {}
    return {
        "scan": lambda path, mode="general": build_scan_report(path, mode=mode, options=scan_options),
        "crawl": lambda path, mode="general", recursive=True, max_files=None: crawl_directory(
            path,
            mode=mode,
            recursive=recursive,
            max_files=max_files,
            options=scan_options,
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
        "list_tool_plugins": list_tool_plugin_formats,
        "default_tool_plugin_path": default_tool_plugin_path,
        "export_tool_plugin": export_tool_plugin,
        "tooling_snapshot": lambda: collect_external_tool_status(
            executable_overrides=load_tool_paths()
        ),
        "tooling_detail": lambda tool_key: describe_external_tool(
            tool_key,
            executable_override=load_tool_path(tool_key),
        ),
        "download_external_tool": download_external_tool,
        "install_external_tool": install_external_tool,
        "show_report": lambda report: display_report(report, ui_mode=ui_mode, explicit_ui=explicit_ui),
    }


def handle_no_input(args, explicit_ui):
    if args.ui == "textual":
        callbacks = workspace_callbacks(
            args.ui,
            explicit_ui,
            args.store_dir,
            scan_options=build_scan_options(args),
        )
        if run_textual_workspace(callbacks, explicit_ui=explicit_ui):
            return 0
    if args.ui == "web":
        callbacks = workspace_callbacks(
            args.ui,
            explicit_ui,
            args.store_dir,
            scan_options=build_scan_options(args),
        )
        if run_web_dashboard(
            [],
            callbacks=callbacks,
            explicit_ui=explicit_ui,
            host=args.web_host,
            port=args.web_port,
            open_browser=args.web_open_browser,
        ):
            return 0

    print("No binary or workload specified.")
    print("Provide a binary path, --crawl, --task-file, --load-scan, or --load-collection.")
    print("Use --help for all options.")
    return 2
