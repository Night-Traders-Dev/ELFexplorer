from __future__ import annotations

from typing import Dict, Iterable

from advanced.diffing import compare_reports


def _rows_for_summary(diff: Dict) -> Iterable[tuple[str, str, str, str]]:
    summary = diff.get("summary", {})
    for field in ("language", "compiler", "build_system", "artifact_type", "artifact_confidence"):
        before, after = summary.get(field, ["Unknown", "Unknown"])
        status = "changed" if before != after else "same"
        yield (field, str(before), str(after), status)


def _rows_for_delta(diff: Dict, key: str, limit: int = 128) -> Iterable[tuple[str, str, str, str]]:
    for item in diff.get(key, [])[:limit]:
        yield (
            str(item.get("label", "")),
            str(item.get("before", 0)),
            str(item.get("after", 0)),
            f"{int(item.get('delta', 0)):+d}",
        )


class DiffViewerScreenFactory:
    @staticmethod
    def build(left_report: Dict, right_report: Dict):
        from textual.screen import Screen

        class DiffViewerScreen(Screen):
            BINDINGS = [
                ("escape", "app.pop_screen", "Back"),
                ("q", "app.pop_screen", "Back"),
            ]

            CSS = """
            #diff_header {
                height: auto;
                padding: 1 2;
                border: round $primary;
            }
            #indicator_scroll {
                height: 1fr;
                border: round $secondary;
            }
            #indicator_text {
                padding: 1 2;
            }
            DataTable {
                height: 1fr;
            }
            """

            def __init__(self):
                super().__init__()
                self.diff = compare_reports(left_report, right_report)

            def compose(self):
                from textual.containers import VerticalScroll
                from textual.widgets import DataTable, Static, TabbedContent, TabPane

                yield Static(
                    "Binary Diff\n"
                    f"left={self.diff.get('left_file', 'unknown')}\n"
                    f"right={self.diff.get('right_file', 'unknown')}",
                    id="diff_header",
                )
                with TabbedContent():
                    with TabPane("Summary"):
                        yield DataTable(id="summary_table")
                    with TabPane("Language Deltas"):
                        yield DataTable(id="language_table")
                    with TabPane("Compiler Deltas"):
                        yield DataTable(id="compiler_table")
                    with TabPane("Build Deltas"):
                        yield DataTable(id="build_table")
                    with TabPane("Artifact Deltas"):
                        yield DataTable(id="artifact_table")
                    with TabPane("Indicators"):
                        with VerticalScroll(id="indicator_scroll"):
                            yield Static("", id="indicator_text")

            def _fill_table(self, table_id: str, headers: tuple[str, ...], rows: Iterable[tuple[str, ...]]):
                from textual.widgets import DataTable

                table = self.query_one(f"#{table_id}", DataTable)
                table.clear(columns=True)
                table.cursor_type = "row"
                table.add_columns(*headers)
                count = 0
                for row in rows:
                    table.add_row(*row)
                    count += 1
                if count == 0:
                    table.add_row("(no changes)", "", "", "")

            def on_mount(self):
                from textual.widgets import Static

                self._fill_table(
                    "summary_table",
                    ("Field", "Left", "Right", "Status"),
                    _rows_for_summary(self.diff),
                )
                self._fill_table(
                    "language_table",
                    ("Label", "Before", "After", "Delta"),
                    _rows_for_delta(self.diff, "language_deltas"),
                )
                self._fill_table(
                    "compiler_table",
                    ("Label", "Before", "After", "Delta"),
                    _rows_for_delta(self.diff, "compiler_deltas"),
                )
                self._fill_table(
                    "build_table",
                    ("Label", "Before", "After", "Delta"),
                    _rows_for_delta(self.diff, "build_deltas"),
                )
                self._fill_table(
                    "artifact_table",
                    ("Label", "Before", "After", "Delta"),
                    _rows_for_delta(self.diff, "artifact_deltas"),
                )

                added = self.diff.get("indicator_added", [])
                removed = self.diff.get("indicator_removed", [])
                lines = ["Indicators Added:"]
                lines.extend([f"+ {line}" for line in added] or ["(none)"])
                lines.append("")
                lines.append("Indicators Removed:")
                lines.extend([f"- {line}" for line in removed] or ["(none)"])
                self.query_one("#indicator_text", Static).update("\n".join(lines))

        return DiffViewerScreen()
