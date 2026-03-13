import shlex
from datetime import datetime, timezone

from advanced.diffing import compare_reports, render_diff_plain
from advanced.tooling import list_external_tools, render_external_tool_status_lines
from edit import ElfEditError, open_binary_editor
from settings import load_theme_preference, save_theme_preference
from version import get_version


def _now():
    return datetime.now(timezone.utc).isoformat()


def _parse_bool(text, default=True):
    normalized = str(text).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _parse_int_literal(text, label):
    try:
        return int(str(text), 0)
    except ValueError as exc:
        raise ValueError(f"{label} must be a numeric literal (examples: 10, 0x20).") from exc


def _fmt_value(value):
    if isinstance(value, int):
        if value >= 0:
            return f"{value} (0x{value:x})"
        return str(value)
    return str(value)


def _fmt_hex_or_unknown(value):
    if value is None:
        return "unknown"
    numeric = int(value)
    return f"0x{numeric:x}"


def _collection_payload(reports):
    return {
        "generated_at": _now(),
        "count": len(reports),
        "reports": reports,
    }


def _report_brief(report):
    scan = report.get("scan_result", {})
    artifact = scan.get("artifact_profile", {})
    return (
        f"file={report.get('file', 'Unknown')} "
        f"lang={scan.get('source_language', 'Unknown')} "
        f"compiler={scan.get('compiler', 'Unknown')} "
        f"build={scan.get('build_system', 'Unknown')} "
        f"artifact={artifact.get('artifact_type', 'Unknown')}"
    )


def _report_detail_lines(report):
    scan = report.get("scan_result", {})
    artifact = scan.get("artifact_profile", {})
    lines = [
        f"file: {report.get('file', 'Unknown')}",
        f"mode: {report.get('mode', 'general')}",
        f"version: {report.get('version', 'Unknown')}",
        f"generated_at: {report.get('generated_at', 'Unknown')}",
        f"source_language: {scan.get('source_language', 'Unknown')}",
        f"compiler: {scan.get('compiler', 'Unknown')}",
        f"build_system: {scan.get('build_system', 'Unknown')}",
        f"artifact_type: {artifact.get('artifact_type', 'Unknown')}",
        f"artifact_confidence: {artifact.get('confidence', 0)}",
        f"target_hint: {artifact.get('target', 'Unknown')}",
        f"sdk_hint: {artifact.get('sdk', 'Unknown')}",
        f"rtos_hint: {artifact.get('rtos', 'None detected')}",
        f"runtime_hint: {artifact.get('runtime', 'Unknown')}",
        f"linkage_model: {artifact.get('linkage_model', 'Unknown')}",
        f"loader: {artifact.get('loader', 'None')}",
    ]
    return lines


def run_textual_workspace(callbacks):
    from textual.app import App, ComposeResult
    from textual.containers import Vertical
    from textual.widgets import Footer, Header, Input, RichLog, Static

    class WorkspaceApp(App):
        CSS = """
        #help {
            height: auto;
            padding: 1 2;
            border: round $primary;
        }
        #log {
            height: 1fr;
            border: round $secondary;
        }
        #command {
            height: 3;
        }
        """

        BINDINGS = [
            ("ctrl+c", "quit", "Quit"),
            ("ctrl+l", "clear_log", "Clear Log"),
            ("ctrl+e", "open_editor_ui", "Editor UI"),
        ]

        def __init__(self):
            super().__init__()
            self.current_reports = []
            self.last_report = None
            self.editor = None
            self.tooling_snapshot = None

        def _apply_saved_theme(self):
            saved_theme = load_theme_preference()
            if saved_theme in self.available_themes and self.theme != saved_theme:
                self.theme = saved_theme

        def watch_theme(self, theme: str):
            try:
                save_theme_preference(theme)
            except OSError:
                pass

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Vertical():
                yield Static(
                    "Commands: help | scan <file> [mode] | crawl <dir> [mode] [recursive:true/false] [max_files]\n"
                    "load <scan.json> | load-collection <collection.json> | list-saved\n"
                    "save [path] | save-collection [path] | export-md <path> | export-pdf <path>\n"
                    "export-collection-md <path> | export-collection-pdf <path> | show\n"
                    "tool-list | tool-export <format> [path] | tool-status | tool-info <tool> | tool-download <tool> | tool-install <tool>\n"
                    "diff <other-file> [mode] | diff-ui <other-file> [mode]\n"
                    "edit-ui (or Ctrl+E) opens split-pane editor workbench\n"
                    "edit-open <path> | edit-status | edit-show-elf | edit-show-uf2 | edit-list-phdr | edit-list-shdr | edit-list-blocks | edit-show-block <idx> | edit-hex [offset] [length] [width]\n"
                    "edit-poke <offset> <byte> | edit-patch <offset> <hex-bytes...> | edit-write-ascii <offset> <text>\n"
                    "edit-disasm [section] [max_lines] | edit-disasm-range <start> <stop> [section] [max_lines]\n"
                    "edit-set-elf <field> <value> | edit-show-phdr <idx> | edit-set-phdr <idx> <field> <value>\n"
                    "edit-show-shdr <idx> | edit-set-shdr <idx> <field> <value> | edit-export-payload [path] | edit-diff | edit-revert | edit-save [path] | edit-close | quit",
                    id="help",
                )
                yield RichLog(id="log", wrap=True, markup=True)
                yield Input(placeholder="Enter command...", id="command")
            yield Footer()

        def get_system_commands(self, screen):
            from textual.app import SystemCommand

            yield from super().get_system_commands(screen)
            yield SystemCommand(
                "Tooling: Check External Tools",
                "Detect host package manager and installed reverse-engineering tools",
                self.action_tool_status,
            )
            for tool_key, meta in sorted(list_external_tools().items()):
                yield SystemCommand(
                    f"Tooling: Show Install Methods for {meta['label']}",
                    f"Show download URLs and install methods for {meta['label']}",
                    lambda tool_key=tool_key: self.action_show_tool_info(tool_key),
                )
                yield SystemCommand(
                    f"Tooling: Download {meta['label']}",
                    f"Download the current package for {meta['label']}",
                    lambda tool_key=tool_key: self.action_download_external_tool(tool_key),
                )
                yield SystemCommand(
                    f"Tooling: Install {meta['label']}",
                    f"Install {meta['label']} using the detected package manager when supported",
                    lambda tool_key=tool_key: self.action_install_external_tool(tool_key),
                )

        def action_clear_log(self):
            log = self.query_one("#log", RichLog)
            log.clear()

        def _log(self, text):
            log = self.query_one("#log", RichLog)
            log.write(text)

        def _launch_modal_task(
            self,
            *,
            title,
            intro,
            runner,
            on_complete=None,
            auto_close_on_success=False,
            close_label="Close",
        ):
            from ui.textual_tasks import BackgroundTaskScreenFactory

            self.push_screen(
                BackgroundTaskScreenFactory.build(
                    title=title,
                    intro=intro,
                    runner=runner,
                    on_complete=on_complete,
                    auto_close_on_success=auto_close_on_success,
                    close_label=close_label,
                )
            )

        def _log_tooling_snapshot(self):
            if self.tooling_snapshot is None:
                self._log("Tooling status is not loaded yet.")
                return
            self._log("[bold]External tool status:[/bold]")
            for line in render_external_tool_status_lines(self.tooling_snapshot):
                self._log(f"  {line}")

        def _launch_startup_splash(self):
            def runner(emit):
                emit({"kind": "log", "message": "Loading workspace settings", "progress": 10.0})
                emit({"kind": "log", "message": "Checking external integrations", "progress": 30.0})
                snapshot = callbacks["tooling_snapshot"]()
                emit({"kind": "log", "message": "Preparing workspace services", "progress": 85.0})
                return {"tooling_snapshot": snapshot, "message": "Workspace startup complete."}

            def on_complete(result, ok):
                if ok and result:
                    self.tooling_snapshot = result.get("tooling_snapshot")
                self._log("ELFexplorer Textual Workspace ready.")
                self._log("Type [bold]help[/bold] for command details.")
                if self.tooling_snapshot is not None:
                    environment = self.tooling_snapshot.get("environment", {})
                    self._log(
                        "Host: "
                        f"{environment.get('os_label', 'Unknown')} / "
                        f"{environment.get('primary_package_manager_label', 'None detected')}"
                    )

            self._launch_modal_task(
                title=f"ELFexplorer {get_version()}",
                intro="Loading workspace services and checking host integrations.",
                runner=runner,
                on_complete=on_complete,
                auto_close_on_success=True,
                close_label="Continue",
            )

        def on_mount(self):
            self._apply_saved_theme()
            self._launch_startup_splash()

        def _set_reports(self, reports):
            self.current_reports = list(reports)
            self.last_report = self.current_reports[-1] if self.current_reports else None

        def _show_reports_summary(self):
            if not self.current_reports:
                self._log("No reports loaded.")
                return

            self._log(f"[bold]Report Count:[/bold] {len(self.current_reports)}")
            for index, report in enumerate(self.current_reports, start=1):
                self._log(f"{index:>3}. {_report_brief(report)}")

        def _require_editor(self):
            if self.editor is None:
                self._log("[red]No active editor session.[/red] Use: edit-open <path>")
                return None
            return self.editor

        def _require_elf_editor(self):
            editor = self._require_editor()
            if not editor:
                return None
            if editor.status().get("format") != "ELF":
                self._log("[yellow]Current editor session is not an ELF image.[/yellow]")
                return None
            return editor

        def _require_uf2_editor(self):
            editor = self._require_editor()
            if not editor:
                return None
            if editor.status().get("format") != "UF2":
                self._log("[yellow]Current editor session is not a UF2 image.[/yellow]")
                return None
            return editor

        def _show_editor_status(self, editor):
            status = editor.status()
            self._log("[bold]Editor status:[/bold]")
            self._log(f"  path: {status['path']}")
            self._log(f"  format: {status.get('format', 'ELF')}")
            self._log(f"  size: {status['size']} bytes")
            if status.get("format") == "UF2":
                self._log(f"  container_size: {status['container_size']} bytes")
                self._log(f"  blocks: {status['blocks']}")
                self._log(
                    f"  address_range: {_fmt_hex_or_unknown(status.get('base_address'))} -> {_fmt_hex_or_unknown(status.get('end_address'))}"
                )
                families = ", ".join(status.get("family_ids", [])) or "Unknown"
                self._log(f"  family_ids: {families}")
            else:
                self._log(f"  class: ELF{status['elf_class']}")
                self._log(f"  endianness: {status['endianness']}")
                self._log(f"  program_headers: {status['program_headers']}")
                self._log(f"  section_headers: {status['section_headers']}")
            self._log(f"  dirty: {status['dirty']}")
            self._log(f"  change_count: {status['change_count']}")
            self._log(f"  disassembler: {status['disassembler']}")

        def action_open_editor_ui(self):
            editor = self._require_editor()
            if not editor:
                return
            from ui.textual_editor import EditorWorkbenchScreen

            self.push_screen(EditorWorkbenchScreen.build(editor))

        def action_tool_status(self):
            def runner(emit):
                emit({"kind": "log", "message": "Refreshing external-tool status", "progress": 15.0})
                snapshot = callbacks["tooling_snapshot"]()
                emit({"kind": "log", "message": "Status refresh complete", "progress": 100.0})
                return snapshot

            def on_complete(result, ok):
                if ok and result:
                    self.tooling_snapshot = result
                    self._log_tooling_snapshot()

            self._launch_modal_task(
                title="Checking External Tools",
                intro="Probing the host OS, package manager, and installed reverse-engineering tools.",
                runner=runner,
                on_complete=on_complete,
                auto_close_on_success=True,
                close_label="Continue",
            )

        def action_show_tool_info(self, tool_key):
            detail = callbacks["tooling_detail"](tool_key)
            status = detail["status"]
            self._log(f"[bold]{status['label']} install methods:[/bold]")
            self._log(f"  installed: {'yes' if status['installed'] else 'no'}")
            if status.get("path"):
                self._log(f"  path: {status['path']}")
            if status.get("version"):
                self._log(f"  version: {status['version']}")
            if detail.get("homepage"):
                self._log(f"  homepage: {detail['homepage']}")
            if detail.get("download_url"):
                self._log(f"  download: {detail['download_url']}")
            host_install = detail.get("host_install_command")
            if host_install:
                self._log(f"  host_install: {' '.join(host_install)}")
            else:
                self._log("  host_install: unavailable on this host")
            methods = detail.get("install_methods", [])
            if methods:
                self._log("  package_methods:")
                for method in methods:
                    self._log(f"    - {method['manager_label']}: {' '.join(method['command'])}")
            if detail.get("manual_install"):
                self._log(f"  manual: {detail['manual_install']}")

        def action_install_external_tool(self, tool_key):
            label = list_external_tools()[tool_key]["label"]

            def runner(emit):
                return callbacks["install_external_tool"](tool_key, event_cb=emit)

            def on_complete(result, ok):
                self.tooling_snapshot = callbacks["tooling_snapshot"]()
                if not result:
                    self._log(f"[yellow]{label} install ended without a result.[/yellow]")
                    return
                if result.get("ok"):
                    self._log(f"[green]{result['message']}[/green]")
                else:
                    self._log(f"[yellow]{result['message']}[/yellow]")
                command = result.get("command")
                if command:
                    self._log(f"  command: {' '.join(command)}")
                output = result.get("output")
                if output:
                    for line in output.splitlines():
                        self._log(f"  {line}")

            self._launch_modal_task(
                title=f"Installing {label}",
                intro="Running installer steps in the background with live progress and verbose logging.",
                runner=runner,
                on_complete=on_complete,
            )

        def action_download_external_tool(self, tool_key):
            label = list_external_tools()[tool_key]["label"]

            def runner(emit):
                return callbacks["download_external_tool"](tool_key, event_cb=emit)

            def on_complete(result, ok):
                self.tooling_snapshot = callbacks["tooling_snapshot"]()
                if not result:
                    self._log(f"[yellow]{label} download ended without a result.[/yellow]")
                    return
                if result.get("ok"):
                    self._log(f"[green]{result['message']}[/green]")
                else:
                    self._log(f"[yellow]{result['message']}[/yellow]")
                if result.get("download_url"):
                    self._log(f"  url: {result['download_url']}")
                if result.get("download_path"):
                    self._log(f"  path: {result['download_path']}")

            self._launch_modal_task(
                title=f"Downloading {label}",
                intro="Resolving the vendor package and downloading it in the background.",
                runner=runner,
                on_complete=on_complete,
            )

        async def on_input_submitted(self, event: Input.Submitted):
            raw = event.value.strip()
            event.input.value = ""
            if not raw:
                return

            self._log(f"> {raw}")
            try:
                parts = shlex.split(raw)
            except ValueError as exc:
                self._log(f"[red]Parse error:[/red] {exc}")
                return

            command = parts[0].lower()
            args = parts[1:]

            try:
                if command in {"q", "quit", "exit"}:
                    self.action_quit()
                    return

                if command == "help":
                    self._log("scan <file> [mode]")
                    self._log("crawl <dir> [mode] [recursive:true/false] [max_files]")
                    self._log("load <scan.json> | load-collection <collection.json>")
                    self._log("save [path] | save-collection [path]")
                    self._log("export-md <path> | export-pdf <path>")
                    self._log("export-collection-md <path> | export-collection-pdf <path>")
                    self._log("tool-list | tool-export <format> [path] | tool-status | tool-info <tool> | tool-download <tool> | tool-install <tool>")
                    self._log("diff <other-file> [mode] | diff-ui <other-file> [mode]")
                    self._log("edit-open <path> | edit-close | edit-status")
                    self._log("edit-ui (or Ctrl+E) -> open split-pane editor workbench")
                    self._log("edit-show-elf | edit-set-elf <field> <value>")
                    self._log("edit-show-uf2 | edit-list-blocks | edit-show-block <idx> | edit-export-payload [path]")
                    self._log("edit-list-phdr | edit-show-phdr <idx> | edit-set-phdr <idx> <field> <value>")
                    self._log("edit-list-shdr | edit-show-shdr <idx> | edit-set-shdr <idx> <field> <value>")
                    self._log("edit-poke <offset> <byte> | edit-patch <offset> <hex-bytes...>")
                    self._log("edit-write-ascii <offset> <text>")
                    self._log("edit-hex [offset] [length] [width] | edit-diff | edit-revert | edit-save [path]")
                    self._log("edit-disasm [section] [max_lines]")
                    self._log("edit-disasm-range <start> <stop> [section] [max_lines]")
                    self._log("list-saved | show | quit")
                    return

                if command == "scan":
                    if not args:
                        self._log("[red]Usage:[/red] scan <file> [mode]")
                        return
                    path = args[0]
                    mode = args[1] if len(args) >= 2 else "general"
                    report = callbacks["scan"](path, mode=mode)
                    self._set_reports([report])
                    self._log(f"[green]Scanned:[/green] {_report_brief(report)}")
                    return

                if command == "crawl":
                    if not args:
                        self._log("[red]Usage:[/red] crawl <dir> [mode] [recursive:true/false] [max_files]")
                        return
                    directory = args[0]
                    mode = args[1] if len(args) >= 2 else "general"
                    recursive = _parse_bool(args[2], default=True) if len(args) >= 3 else True
                    max_files = int(args[3]) if len(args) >= 4 else None
                    reports = callbacks["crawl"](
                        directory,
                        mode=mode,
                        recursive=recursive,
                        max_files=max_files,
                    )
                    self._set_reports(reports)
                    self._show_reports_summary()
                    return

                if command == "load":
                    if not args:
                        self._log("[red]Usage:[/red] load <scan.json>")
                        return
                    report = callbacks["load_scan"](args[0])
                    self._set_reports([report])
                    self._log(f"[green]Loaded report:[/green] {_report_brief(report)}")
                    return

                if command == "load-collection":
                    if not args:
                        self._log("[red]Usage:[/red] load-collection <collection.json>")
                        return
                    payload = callbacks["load_collection"](args[0])
                    reports = payload.get("reports", [])
                    self._set_reports(reports)
                    self._show_reports_summary()
                    return

                if command == "list-saved":
                    items = callbacks["list_saved"]()
                    if not items:
                        self._log("No saved scans found.")
                        return
                    for item in items:
                        self._log(str(item))
                    return

                if command == "save":
                    if not self.last_report:
                        self._log("[red]No current report to save.[/red]")
                        return
                    path = args[0] if args else None
                    saved = callbacks["save_scan"](self.last_report, path=path)
                    self._log(f"[green]Saved report:[/green] {saved}")
                    return

                if command == "save-collection":
                    if not self.current_reports:
                        self._log("[red]No current collection to save.[/red]")
                        return
                    path = args[0] if args else None
                    saved = callbacks["save_collection"](self.current_reports, path=path)
                    self._log(f"[green]Saved collection:[/green] {saved}")
                    return

                if command == "export-md":
                    if not self.last_report:
                        self._log("[red]No current report to export.[/red]")
                        return
                    if not args:
                        self._log("[red]Usage:[/red] export-md <path>")
                        return
                    exported = callbacks["export_report_md"](self.last_report, args[0])
                    self._log(f"[green]Exported Markdown:[/green] {exported}")
                    return

                if command == "export-pdf":
                    if not self.last_report:
                        self._log("[red]No current report to export.[/red]")
                        return
                    if not args:
                        self._log("[red]Usage:[/red] export-pdf <path>")
                        return
                    exported = callbacks["export_report_pdf"](self.last_report, args[0])
                    self._log(f"[green]Exported PDF:[/green] {exported}")
                    return

                if command == "export-collection-md":
                    if not self.current_reports:
                        self._log("[red]No current collection to export.[/red]")
                        return
                    if not args:
                        self._log("[red]Usage:[/red] export-collection-md <path>")
                        return
                    payload = _collection_payload(self.current_reports)
                    exported = callbacks["export_collection_md"](payload, args[0])
                    self._log(f"[green]Exported Markdown collection:[/green] {exported}")
                    return

                if command == "export-collection-pdf":
                    if not self.current_reports:
                        self._log("[red]No current collection to export.[/red]")
                        return
                    if not args:
                        self._log("[red]Usage:[/red] export-collection-pdf <path>")
                        return
                    payload = _collection_payload(self.current_reports)
                    exported = callbacks["export_collection_pdf"](payload, args[0])
                    self._log(f"[green]Exported PDF collection:[/green] {exported}")
                    return

                if command == "show":
                    if not self.last_report:
                        self._log("[red]No current report to show.[/red]")
                        return
                    self._log("[bold]Current report:[/bold]")
                    for line in _report_detail_lines(self.last_report):
                        self._log(f"  {line}")
                    return

                if command == "tool-list":
                    formats = callbacks["list_tool_plugins"]()
                    self._log("[bold]Available tool plugins/scripts:[/bold]")
                    for key in sorted(formats):
                        meta = formats[key]
                        self._log(
                            f"  {key}: {meta.get('label', key)} "
                            f"({meta.get('extension', '')}) - {meta.get('description', '')}"
                        )
                    return

                if command == "tool-status":
                    self.action_tool_status()
                    return

                if command == "tool-info":
                    if not args:
                        self._log("[red]Usage:[/red] tool-info <tool>")
                        return
                    self.action_show_tool_info(args[0])
                    return

                if command == "tool-install":
                    if not args:
                        self._log("[red]Usage:[/red] tool-install <tool>")
                        return
                    self.action_install_external_tool(args[0])
                    return

                if command == "tool-download":
                    if not args:
                        self._log("[red]Usage:[/red] tool-download <tool>")
                        return
                    self.action_download_external_tool(args[0])
                    return

                if command == "tool-export":
                    if not self.last_report:
                        self._log("[red]No current report to export.[/red]")
                        return
                    if not args:
                        self._log("[red]Usage:[/red] tool-export <format> [path]")
                        return
                    tool_format = args[0]
                    path = None
                    if len(args) >= 2:
                        path = args[1]
                    else:
                        path = callbacks["default_tool_plugin_path"](self.last_report, tool_format)
                    exported = callbacks["export_tool_plugin"](self.last_report, path, tool_format)
                    self._log(f"[green]Exported {tool_format} plugin/script:[/green] {exported}")
                    return

                if command in {"diff", "diff-ui"}:
                    if not self.last_report:
                        self._log("[red]No current baseline report.[/red] Run scan/load first.")
                        return
                    if not args:
                        self._log(f"[red]Usage:[/red] {command} <other-file> [mode]")
                        return
                    other_path = args[0]
                    mode = args[1] if len(args) >= 2 else self.last_report.get("mode", "general")
                    other_report = callbacks["scan"](other_path, mode=mode)
                    diff = compare_reports(self.last_report, other_report)
                    if command == "diff":
                        self._log("[bold]Binary diff:[/bold]")
                        for line in render_diff_plain(diff).splitlines():
                            self._log(f"  {line}")
                    else:
                        from ui.textual_diff import DiffViewerScreenFactory

                        self.push_screen(DiffViewerScreenFactory.build(self.last_report, other_report))
                    return

                if command == "edit-open":
                    if not args:
                        self._log("[red]Usage:[/red] edit-open <path>")
                        return
                    self.editor = open_binary_editor(args[0])
                    self._log(f"[green]Opened editor session:[/green] {self.editor.path}")
                    self._show_editor_status(self.editor)
                    return

                if command == "edit-ui":
                    self.action_open_editor_ui()
                    return

                if command == "edit-close":
                    if self.editor is None:
                        self._log("No editor session to close.")
                        return
                    session_path = self.editor.path
                    self.editor = None
                    self._log(f"[green]Closed editor session:[/green] {session_path}")
                    return

                if command == "edit-status":
                    editor = self._require_editor()
                    if not editor:
                        return
                    self._show_editor_status(editor)
                    return

                if command == "edit-show-elf":
                    editor = self._require_elf_editor()
                    if not editor:
                        return
                    header = editor.get_elf_header()
                    self._log("[bold]ELF header fields:[/bold]")
                    for key, value in header.items():
                        self._log(f"  {key}: {_fmt_value(value)}")
                    return

                if command == "edit-set-elf":
                    editor = self._require_elf_editor()
                    if not editor:
                        return
                    if len(args) < 2:
                        self._log("[red]Usage:[/red] edit-set-elf <field> <value>")
                        return
                    field = args[0]
                    value = _parse_int_literal(args[1], "value")
                    old, new = editor.set_elf_field(field, value)
                    self._log(
                        "[green]Updated ELF header:[/green] "
                        f"{field} {_fmt_value(old)} -> {_fmt_value(new)}"
                    )
                    return

                if command == "edit-show-uf2":
                    editor = self._require_uf2_editor()
                    if not editor:
                        return
                    overview = editor.get_uf2_overview()
                    self._log("[bold]UF2 overview:[/bold]")
                    self._log(f"  blocks: {overview['blocks']}")
                    self._log(f"  payload_size: {overview['payload_size']} bytes")
                    self._log(
                        f"  address_range: {_fmt_hex_or_unknown(overview['base_address'])} -> {_fmt_hex_or_unknown(overview['end_address'])}"
                    )
                    if overview["family_ids"]:
                        for family_id in overview["family_ids"]:
                            self._log(f"  family_id: 0x{int(family_id):08x}")
                    else:
                        self._log("  family_id: Unknown")
                    self._log(
                        f"  declared_counts: {', '.join(str(item) for item in overview['declared_counts']) or 'Unknown'}"
                    )
                    return

                if command == "edit-list-blocks":
                    editor = self._require_uf2_editor()
                    if not editor:
                        return
                    blocks = editor.list_blocks()
                    if not blocks:
                        self._log("No UF2 blocks found.")
                        return
                    self._log(f"[bold]UF2 blocks ({len(blocks)}):[/bold]")
                    for block in blocks:
                        family_text = (
                            f" family=0x{int(block['family_id']):08x}"
                            if block["family_id"] is not None
                            else ""
                        )
                        self._log(
                            f"  [{block['index']:>3}] block_no={block['block_no']} "
                            f"payload_off=0x{block['payload_offset']:x} "
                            f"target=0x{block['target_addr']:x} "
                            f"size=0x{block['payload_size']:x} "
                            f"raw_off=0x{block['raw_offset']:x}{family_text}"
                        )
                    return

                if command == "edit-show-block":
                    editor = self._require_uf2_editor()
                    if not editor:
                        return
                    if not args:
                        self._log("[red]Usage:[/red] edit-show-block <index>")
                        return
                    block = editor.get_block(_parse_int_literal(args[0], "index"))
                    self._log(f"[bold]UF2 block [{block['index']}]:[/bold]")
                    for key, value in block.items():
                        self._log(f"  {key}: {_fmt_value(value)}")
                    return

                if command == "edit-list-phdr":
                    editor = self._require_elf_editor()
                    if not editor:
                        return
                    headers = editor.list_program_headers()
                    if not headers:
                        self._log("No program headers found.")
                        return
                    self._log(f"[bold]Program headers ({len(headers)}):[/bold]")
                    for index, item in enumerate(headers):
                        self._log(
                            f"  [{index:>3}] type=0x{item['p_type']:x} "
                            f"flags=0x{item['p_flags']:x} "
                            f"off=0x{item['p_offset']:x} "
                            f"vaddr=0x{item['p_vaddr']:x} "
                            f"filesz=0x{item['p_filesz']:x} "
                            f"memsz=0x{item['p_memsz']:x}"
                        )
                    return

                if command == "edit-show-phdr":
                    editor = self._require_elf_editor()
                    if not editor:
                        return
                    if not args:
                        self._log("[red]Usage:[/red] edit-show-phdr <index>")
                        return
                    index = _parse_int_literal(args[0], "index")
                    item = editor.get_program_header(index)
                    self._log(f"[bold]Program header [{index}]:[/bold]")
                    for key, value in item.items():
                        self._log(f"  {key}: {_fmt_value(value)}")
                    return

                if command == "edit-set-phdr":
                    editor = self._require_elf_editor()
                    if not editor:
                        return
                    if len(args) < 3:
                        self._log("[red]Usage:[/red] edit-set-phdr <index> <field> <value>")
                        return
                    index = _parse_int_literal(args[0], "index")
                    field = args[1]
                    value = _parse_int_literal(args[2], "value")
                    old, new = editor.set_program_header_field(index, field, value)
                    self._log(
                        "[green]Updated program header:[/green] "
                        f"[{index}] {field} {_fmt_value(old)} -> {_fmt_value(new)}"
                    )
                    return

                if command == "edit-list-shdr":
                    editor = self._require_elf_editor()
                    if not editor:
                        return
                    sections = editor.list_section_headers(resolve_names=True)
                    if not sections:
                        self._log("No section headers found.")
                        return
                    self._log(f"[bold]Section headers ({len(sections)}):[/bold]")
                    for index, item in enumerate(sections):
                        self._log(
                            f"  [{index:>3}] {item.get('name', '<unnamed>')} "
                            f"type=0x{item['sh_type']:x} "
                            f"flags=0x{item['sh_flags']:x} "
                            f"off=0x{item['sh_offset']:x} "
                            f"size=0x{item['sh_size']:x}"
                        )
                    return

                if command == "edit-show-shdr":
                    editor = self._require_elf_editor()
                    if not editor:
                        return
                    if not args:
                        self._log("[red]Usage:[/red] edit-show-shdr <index>")
                        return
                    index = _parse_int_literal(args[0], "index")
                    item = editor.get_section_header(index, resolve_name=True)
                    self._log(f"[bold]Section header [{index}]:[/bold]")
                    for key, value in item.items():
                        self._log(f"  {key}: {_fmt_value(value)}")
                    return

                if command == "edit-set-shdr":
                    editor = self._require_elf_editor()
                    if not editor:
                        return
                    if len(args) < 3:
                        self._log("[red]Usage:[/red] edit-set-shdr <index> <field> <value>")
                        return
                    index = _parse_int_literal(args[0], "index")
                    field = args[1]
                    value = _parse_int_literal(args[2], "value")
                    old, new = editor.set_section_header_field(index, field, value)
                    self._log(
                        "[green]Updated section header:[/green] "
                        f"[{index}] {field} {_fmt_value(old)} -> {_fmt_value(new)}"
                    )
                    return

                if command == "edit-hex":
                    editor = self._require_editor()
                    if not editor:
                        return
                    offset = _parse_int_literal(args[0], "offset") if len(args) >= 1 else 0
                    length = _parse_int_literal(args[1], "length") if len(args) >= 2 else 256
                    width = _parse_int_literal(args[2], "width") if len(args) >= 3 else 16
                    dump = editor.hex_view(offset=offset, length=length, width=width)
                    if not dump:
                        self._log("Hex view is empty for the requested range.")
                        return
                    self._log(
                        f"[bold]Hex view:[/bold] offset=0x{offset:x} length={length} width={width}"
                    )
                    for line in dump.splitlines():
                        self._log(f"  {line}")
                    return

                if command == "edit-poke":
                    editor = self._require_editor()
                    if not editor:
                        return
                    if len(args) < 2:
                        self._log("[red]Usage:[/red] edit-poke <offset> <byte>")
                        return
                    offset = _parse_int_literal(args[0], "offset")
                    value = _parse_int_literal(args[1], "byte")
                    old, new = editor.write_byte(offset, value)
                    self._log(
                        "[green]Patched byte:[/green] "
                        f"offset=0x{offset:x} {_fmt_value(old)} -> {_fmt_value(new)}"
                    )
                    return

                if command == "edit-patch":
                    editor = self._require_editor()
                    if not editor:
                        return
                    if len(args) < 2:
                        self._log("[red]Usage:[/red] edit-patch <offset> <hex-bytes...>")
                        return
                    offset = _parse_int_literal(args[0], "offset")
                    hex_text = " ".join(args[1:])
                    old, new = editor.patch_hex(offset, hex_text)
                    self._log(
                        "[green]Patched bytes:[/green] "
                        f"offset=0x{offset:x} old={old.hex()} new={new.hex()}"
                    )
                    return

                if command == "edit-write-ascii":
                    editor = self._require_editor()
                    if not editor:
                        return
                    if len(args) < 2:
                        self._log("[red]Usage:[/red] edit-write-ascii <offset> <text>")
                        return
                    offset = _parse_int_literal(args[0], "offset")
                    text = " ".join(args[1:])
                    old, new = editor.write_ascii(offset, text)
                    self._log(
                        "[green]Wrote text bytes:[/green] "
                        f"offset=0x{offset:x} old={old.hex()} new={new.hex()}"
                    )
                    return

                if command == "edit-disasm":
                    editor = self._require_editor()
                    if not editor:
                        return
                    section = args[0] if len(args) >= 1 else ".text"
                    max_lines = _parse_int_literal(args[1], "max_lines") if len(args) >= 2 else 120
                    text = editor.disassemble(section=section, max_lines=max_lines)
                    self._log(f"[bold]Disassembly:[/bold] section={section} max_lines={max_lines}")
                    for line in text.splitlines():
                        self._log(f"  {line}")
                    return

                if command == "edit-disasm-range":
                    editor = self._require_editor()
                    if not editor:
                        return
                    if len(args) < 2:
                        self._log(
                            "[red]Usage:[/red] edit-disasm-range <start> <stop> [section] [max_lines]"
                        )
                        return
                    start_address = _parse_int_literal(args[0], "start")
                    stop_address = _parse_int_literal(args[1], "stop")
                    section = args[2] if len(args) >= 3 else ".text"
                    max_lines = _parse_int_literal(args[3], "max_lines") if len(args) >= 4 else 120
                    text = editor.disassemble(
                        section=section,
                        start_address=start_address,
                        stop_address=stop_address,
                        max_lines=max_lines,
                    )
                    self._log(
                        "[bold]Disassembly range:[/bold] "
                        f"start=0x{start_address:x} stop=0x{stop_address:x} "
                        f"section={section} max_lines={max_lines}"
                    )
                    for line in text.splitlines():
                        self._log(f"  {line}")
                    return

                if command == "edit-diff":
                    editor = self._require_editor()
                    if not editor:
                        return
                    changes = editor.get_changes()
                    if not changes:
                        self._log("No pending in-memory edits.")
                        return
                    self._log(f"[bold]Pending edits ({len(changes)}):[/bold]")
                    for index, change in enumerate(changes, start=1):
                        scope = change["scope"]
                        target = f"{scope}[{change['index']}]" if change["index"] is not None else scope
                        self._log(
                            f"  {index:>3}. {target}.{change['field']} "
                            f"{_fmt_value(change['old'])} -> {_fmt_value(change['new'])}"
                        )
                    return

                if command == "edit-revert":
                    editor = self._require_editor()
                    if not editor:
                        return
                    editor.revert()
                    self._log("[green]Reverted all in-memory edits to the original file.[/green]")
                    return

                if command == "edit-save":
                    editor = self._require_editor()
                    if not editor:
                        return
                    target = args[0] if args else None
                    saved = editor.save(path=target)
                    self._log(f"[green]Saved edited binary:[/green] {saved}")
                    return

                if command == "edit-export-payload":
                    editor = self._require_uf2_editor()
                    if not editor:
                        return
                    target = args[0] if args else None
                    saved = editor.export_payload(path=target)
                    self._log(f"[green]Exported UF2 payload:[/green] {saved}")
                    return

                self._log(f"[red]Unknown command:[/red] {command}")
            except (ValueError, ElfEditError) as exc:
                self._log(f"[red]Error:[/red] {exc}")
            except Exception as exc:
                self._log(f"[red]Error:[/red] {exc}")

    WorkspaceApp().run()
