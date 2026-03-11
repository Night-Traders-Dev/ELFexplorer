from typing import Dict, Iterable, Tuple


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


def run_textual_report(report: Dict):
    from textual.app import App, ComposeResult
    from textual.containers import Container
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
        #metadata {
            height: 1fr;
            padding: 1 2;
            border: round $secondary;
            overflow: auto;
        }
        #evidence {
            height: 1fr;
            padding: 1 2;
            border: round $accent;
            overflow: auto;
        }
        """

        BINDINGS = [
            ("q", "quit", "Quit"),
        ]

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Container():
                with TabbedContent():
                    with TabPane("Summary"):
                        yield Static(_summary_lines(report), id="summary")
                    with TabPane("Scores"):
                        yield DataTable(id="artifact_scores")
                        yield DataTable(id="language_scores")
                        yield DataTable(id="compiler_scores")
                        yield DataTable(id="build_scores")
                    with TabPane("Metadata"):
                        yield Static(report.get("metadata_text", ""), id="metadata")
                    with TabPane("Evidence"):
                        artifact = report["scan_result"]["artifact_profile"]
                        indicators = artifact.get("indicators", [])
                        if indicators:
                            text = "\n".join(f"- {line}" for line in indicators)
                        else:
                            text = "No explicit artifact indicators collected."
                        yield Static(text, id="evidence")
            yield Footer()

        def _fill_table(self, table_id: str, title: str, scores: Dict[str, int]):
            table = self.query_one(f"#{table_id}", DataTable)
            table.cursor_type = "row"
            table.add_columns(title, "Score")
            for label, value in _score_rows(scores):
                table.add_row(label, value)

        def on_mount(self) -> None:
            scan = report["scan_result"]
            self._fill_table("artifact_scores", "Artifact", scan["artifact_profile"].get("scores", {}))
            self._fill_table("language_scores", "Language", scan["language_scores"])
            self._fill_table("compiler_scores", "Compiler", scan["compiler_scores"])
            self._fill_table("build_scores", "Build System", scan["build_scores"])

    ReportApp().run()

