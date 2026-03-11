import shlex
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


def _parse_bool(text, default=True):
    normalized = str(text).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return default


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
        ]

        def __init__(self):
            super().__init__()
            self.current_reports = []
            self.last_report = None

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Vertical():
                yield Static(
                    "Commands: help | scan <file> [mode] | crawl <dir> [mode] [recursive:true/false] [max_files]\n"
                    "load <scan.json> | load-collection <collection.json> | list-saved\n"
                    "save [path] | save-collection [path] | export-md <path> | export-pdf <path>\n"
                    "export-collection-md <path> | export-collection-pdf <path> | show | quit",
                    id="help",
                )
                yield RichLog(id="log", wrap=True, markup=True)
                yield Input(placeholder="Enter command...", id="command")
            yield Footer()

        def on_mount(self):
            self._log("ELFexplorer Textual Workspace ready.")
            self._log("Type [bold]help[/bold] for command details.")

        def action_clear_log(self):
            log = self.query_one("#log", RichLog)
            log.clear()

        def _log(self, text):
            log = self.query_one("#log", RichLog)
            log.write(text)

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

                self._log(f"[red]Unknown command:[/red] {command}")
            except Exception as exc:
                self._log(f"[red]Error:[/red] {exc}")

    WorkspaceApp().run()
