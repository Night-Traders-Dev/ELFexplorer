from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Tuple

from reporting.export import export_report_markdown, export_report_pdf
from scancli.scan import build_scan_report


def _summary_lines(report: Dict) -> str:
    scan = report["scan_result"]
    artifact = scan["artifact_profile"]
    lines = [
        f"File: {report['file']}",
        f"Mode: {report['mode']}",
        f"Version: {report['version']}",
        "",
        f"Source Language: {scan['source_language']}",
        f"Compiler: {scan['compiler']}",
        f"Build System: {scan['build_system']}",
        "",
        f"Artifact Type: {artifact.get('artifact_type', 'Unknown')}",
        f"Confidence: {artifact.get('confidence', 0)}",
        f"Target: {artifact.get('target', 'Unknown')}",
        f"SDK/Framework: {artifact.get('sdk', 'Unknown')}",
        f"RTOS: {artifact.get('rtos', 'None detected')}",
        f"Runtime: {artifact.get('runtime', 'Unknown')}",
        f"Linkage: {artifact.get('linkage_model', 'Unknown')}",
    ]
    return "\n".join(lines)


def _score_rows(scores: Dict[str, int]) -> Iterable[Tuple[str, str]]:
    ordered = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    for label, value in ordered:
        yield label, str(value)


def default_report_export_path(
    report: Dict,
    extension: str,
    output_dir: Path | None = None,
    now_utc: datetime | None = None,
) -> Path:
    if not extension.startswith("."):
        extension = f".{extension}"
    timestamp = (now_utc or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    source = Path(report.get("file", "scan"))
    stem = source.stem or "scan"
    mode = str(report.get("mode", "general")).lower()
    safe_stem = "".join(ch if (ch.isalnum() or ch in {"-", "_"}) else "_" for ch in stem)
    target_dir = output_dir or (Path.cwd() / "reports")
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir / f"{safe_stem}-{mode}-{timestamp}{extension}"


def run_textual_report(report: Dict):
    from textual.app import App, ComposeResult, SystemCommand
    from textual.containers import Container, VerticalScroll
    from textual.screen import Screen
    from textual.widgets import DataTable, Footer, Header, Static, TabbedContent, TabPane

    class ReportApp(App):
        CSS = """
        #summary {
            height: auto;
            padding: 1 2;
            border: round $primary;
        }
        DataTable {
            height: 1fr;
        }
        #metadata_scroll {
            height: 1fr;
            border: round $secondary;
        }
        #metadata {
            padding: 1 2;
        }
        #evidence_scroll {
            height: 1fr;
            border: round $accent;
        }
        #evidence {
            padding: 1 2;
        }
        """

        BINDINGS = [
            ("q", "quit", "Quit"),
            ("r", "rescan_current_mode", "Rescan"),
            ("1", "set_mode_general", "Mode: General"),
            ("2", "set_mode_important", "Mode: Important"),
            ("3", "set_mode_detailed", "Mode: Detailed"),
        ]

        def __init__(self, initial_report: Dict):
            super().__init__()
            self.report = dict(initial_report)

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Container():
                with TabbedContent():
                    with TabPane("Summary"):
                        yield Static("", id="summary")
                    with TabPane("Scores"):
                        yield DataTable(id="artifact_scores")
                        yield DataTable(id="language_scores")
                        yield DataTable(id="compiler_scores")
                        yield DataTable(id="build_scores")
                    with TabPane("Metadata"):
                        with VerticalScroll(id="metadata_scroll"):
                            yield Static("", id="metadata")
                    with TabPane("Evidence"):
                        with VerticalScroll(id="evidence_scroll"):
                            yield Static("", id="evidence")
            yield Footer()

        def get_system_commands(self, screen: Screen):
            yield from super().get_system_commands(screen)
            yield SystemCommand(
                "Report: Export Markdown",
                "Save current report as Markdown in ./reports/",
                self.action_export_markdown,
            )
            yield SystemCommand(
                "Report: Export PDF",
                "Save current report as PDF in ./reports/",
                self.action_export_pdf,
            )
            yield SystemCommand(
                "Report: Rescan Current Mode",
                "Rescan the current file with the same metadata mode",
                self.action_rescan_current_mode,
            )
            yield SystemCommand(
                "Report: Mode General + Rescan",
                "Switch mode to general and rescan current file",
                self.action_set_mode_general,
            )
            yield SystemCommand(
                "Report: Mode Important + Rescan",
                "Switch mode to important and rescan current file",
                self.action_set_mode_important,
            )
            yield SystemCommand(
                "Report: Mode Detailed + Rescan",
                "Switch mode to detailed and rescan current file",
                self.action_set_mode_detailed,
            )

        def _fill_table(self, table_id: str, title: str, scores: Dict[str, int]):
            table = self.query_one(f"#{table_id}", DataTable)
            table.cursor_type = "row"
            table.clear(columns=True)
            table.add_columns(title, "Score")
            for label, value in _score_rows(scores):
                table.add_row(label, value)

        def _refresh_view(self):
            summary = self.query_one("#summary", Static)
            metadata = self.query_one("#metadata", Static)
            evidence = self.query_one("#evidence", Static)

            summary.update(_summary_lines(self.report))
            metadata.update(self.report.get("metadata_text", ""))

            artifact = self.report["scan_result"]["artifact_profile"]
            indicators = artifact.get("indicators", [])
            evidence.update(
                "\n".join(f"- {line}" for line in indicators)
                if indicators
                else "No explicit artifact indicators collected."
            )

            scan = self.report["scan_result"]
            self._fill_table("artifact_scores", "Artifact", scan["artifact_profile"].get("scores", {}))
            self._fill_table("language_scores", "Language", scan["language_scores"])
            self._fill_table("compiler_scores", "Compiler", scan["compiler_scores"])
            self._fill_table("build_scores", "Build System", scan["build_scores"])

        def _rescan(self, mode: str | None = None):
            file_path = self.report.get("file")
            if not file_path:
                self.notify("No source file recorded in current report.", title="Rescan", severity="error")
                return

            selected_mode = mode or self.report.get("mode", "general")
            try:
                self.report = build_scan_report(file_path, mode=selected_mode)
                self._refresh_view()
                self.notify(
                    f"Rescanned {Path(file_path).name} using mode '{selected_mode}'.",
                    title="Rescan",
                    severity="information",
                )
            except Exception as exc:
                self.notify(f"Rescan failed: {exc}", title="Rescan", severity="error")

        def _export_markdown(self):
            try:
                target = default_report_export_path(self.report, ".md")
                exported = export_report_markdown(self.report, target)
                self.notify(f"Saved Markdown: {exported}", title="Export", severity="information")
            except Exception as exc:
                self.notify(f"Markdown export failed: {exc}", title="Export", severity="error")

        def _export_pdf(self):
            try:
                target = default_report_export_path(self.report, ".pdf")
                exported = export_report_pdf(self.report, target)
                self.notify(f"Saved PDF: {exported}", title="Export", severity="information")
            except Exception as exc:
                self.notify(f"PDF export failed: {exc}", title="Export", severity="error")

        def action_export_markdown(self):
            self._export_markdown()

        def action_export_pdf(self):
            self._export_pdf()

        def action_rescan_current_mode(self):
            self._rescan(mode=self.report.get("mode", "general"))

        def action_set_mode_general(self):
            self._rescan(mode="general")

        def action_set_mode_important(self):
            self._rescan(mode="important")

        def action_set_mode_detailed(self):
            self._rescan(mode="detailed")

        def on_mount(self) -> None:
            self._refresh_view()

    ReportApp(report).run()
