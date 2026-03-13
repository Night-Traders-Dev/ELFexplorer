from __future__ import annotations

import queue
import threading
from pathlib import Path

from advanced.toolbridge import default_tool_plugin_path, export_tool_plugin
from advanced.tooling import (
    get_external_tool_workbench_model,
    launch_external_tool,
    list_external_tools,
    run_external_tool_command,
)


TOOL_EXPORT_FORMATS = {
    "binaryninja": "binaryninja",
    "ghidra": "ghidra",
    "ida": "ida-python",
    "radare2": "radare2",
    "cutter": "cutter",
    "rizin": "cutter",
    "imhex": "imhex",
}


class ToolWorkbenchScreenFactory:
    @staticmethod
    def build(*, initial_tool="radare2", target_path=None, report=None):
        from textual.app import ComposeResult
        from textual.containers import Horizontal, Vertical
        from textual.screen import Screen
        from textual.widgets import Button, DataTable, Footer, Header, Input, ProgressBar, RichLog, Static

        class _ToolWorkbenchScreen(Screen):
            CSS = """
            Screen {
                layout: vertical;
            }
            #tool_title {
                height: auto;
                border: round $primary;
                padding: 0 1;
            }
            #tool_main {
                height: 1fr;
            }
            #tool_sidebar, #tool_console {
                width: 1fr;
                border: round $secondary;
                padding: 0 1;
                margin-right: 1;
            }
            #tool_console {
                margin-right: 0;
            }
            .tool_pane_title {
                height: auto;
                color: $accent;
                text-style: bold;
                padding: 0 1;
            }
            #tool_status, #tool_help {
                height: auto;
                border: round $panel;
                padding: 1;
                margin-bottom: 1;
            }
            #tool_list, #tool_presets {
                height: 1fr;
                margin-bottom: 1;
            }
            #tool_target, #tool_args {
                margin-bottom: 1;
            }
            #tool_progress {
                margin-bottom: 1;
            }
            #tool_output {
                height: 1fr;
                border: round $panel;
                margin-bottom: 1;
            }
            #tool_actions, #tool_run_actions {
                height: auto;
                margin-bottom: 1;
            }
            #tool_actions Button, #tool_run_actions Button {
                margin-right: 1;
            }
            """

            BINDINGS = [
                ("escape", "close_workbench", "Back"),
                ("f5", "refresh_model", "Refresh"),
                ("f6", "run_selected_preset", "Run Preset"),
                ("f7", "launch_tool", "Launch"),
            ]

            def __init__(self):
                super().__init__()
                self.current_tool_key = initial_tool if initial_tool in list_external_tools() else "radare2"
                self.current_target_path = str(Path(target_path).expanduser()) if target_path else ""
                self.report = report
                self._tool_keys = sorted(list_external_tools())
                self._preset_rows = []
                self._events: "queue.Queue[dict]" = queue.Queue()
                self._busy = False
                self._current_result = None

            def compose(self) -> ComposeResult:
                yield Header(show_clock=True)
                yield Static("", id="tool_title")
                with Horizontal(id="tool_main"):
                    with Vertical(id="tool_sidebar"):
                        yield Static("Tool Catalog", classes="tool_pane_title")
                        yield Static("", id="tool_status")
                        tool_table = DataTable(id="tool_list")
                        tool_table.cursor_type = "row"
                        yield tool_table
                        yield Static("Presets", classes="tool_pane_title")
                        preset_table = DataTable(id="tool_presets")
                        preset_table.cursor_type = "row"
                        yield preset_table
                        with Horizontal(id="tool_actions"):
                            yield Button("Refresh", id="tool_btn_refresh", variant="primary")
                            yield Button("Launch App", id="tool_btn_launch", variant="success")
                            yield Button("Export Script", id="tool_btn_export", variant="warning")
                        yield Static(
                            "Use GUI-centric tools through Launch App. Use presets or raw args for CLI/headless tools.\n"
                            "Place `{file}` in the args field to inject the selected binary path explicitly.",
                            id="tool_help",
                        )
                    with Vertical(id="tool_console"):
                        yield Static("Command Console", classes="tool_pane_title")
                        yield Input(value=self.current_target_path, placeholder="Target binary path", id="tool_target")
                        yield Input(placeholder="Tool arguments or preset command", id="tool_args")
                        yield ProgressBar(total=100, show_eta=False, id="tool_progress")
                        yield RichLog(id="tool_output", wrap=True, markup=False, highlight=False, auto_scroll=True)
                        with Horizontal(id="tool_run_actions"):
                            yield Button("Apply Preset", id="tool_btn_apply_preset")
                            yield Button("Run Preset", id="tool_btn_run_preset", variant="primary")
                            yield Button("Run Args", id="tool_btn_run_args", variant="primary")
                            yield Button("Clear Output", id="tool_btn_clear")
                yield Footer()

            def on_mount(self) -> None:
                self.set_interval(0.1, self._drain_events)
                self._populate_tool_table()
                self._refresh_model()

            def _log(self, message: str) -> None:
                self.query_one("#tool_output", RichLog).write(message)

            def _selected_target_path(self) -> str | None:
                value = self.query_one("#tool_target", Input).value.strip()
                self.current_target_path = value
                return value or None

            def _populate_tool_table(self) -> None:
                table = self.query_one("#tool_list", DataTable)
                table.clear(columns=True)
                table.add_columns("Tool", "Installed", "Mode")
                for tool_key in self._tool_keys:
                    model = get_external_tool_workbench_model(tool_key, target_path=self.current_target_path or None)
                    status = model["status"]
                    mode = "CLI" if model["cli_friendly"] else "GUI"
                    table.add_row(status["label"], "yes" if status["installed"] else "no", mode)
                initial_index = self._tool_keys.index(self.current_tool_key)
                table.move_cursor(row=initial_index, column=0)

            def _populate_preset_table(self, presets) -> None:
                table = self.query_one("#tool_presets", DataTable)
                table.clear(columns=True)
                table.add_columns("Preset", "Description")
                self._preset_rows = list(presets)
                for item in self._preset_rows:
                    table.add_row(item["label"], item["description"])
                if self._preset_rows:
                    table.move_cursor(row=0, column=0)

            def _selected_preset(self):
                if not self._preset_rows:
                    return None
                table = self.query_one("#tool_presets", DataTable)
                row_index = int(table.cursor_row or 0)
                if row_index < 0 or row_index >= len(self._preset_rows):
                    return None
                return self._preset_rows[row_index]

            def _resolved_preset_text(self, preset) -> str:
                if not preset:
                    return ""
                args = list(preset.get("args", []))
                target_path = self._selected_target_path()
                if target_path:
                    args = [token.replace("{file}", target_path) for token in args]
                return " ".join(args)

            def _refresh_model(self) -> None:
                model = get_external_tool_workbench_model(
                    self.current_tool_key,
                    target_path=self._selected_target_path(),
                )
                status = model["status"]
                launch_text = " ".join(model.get("launch_args", [])) or "<none>"
                status_lines = [
                    f"Tool: {status['label']} ({self.current_tool_key})",
                    f"Installed: {'yes' if status['installed'] else 'no'}",
                    f"Executable: {status.get('path') or 'not found'}",
                    f"Version: {status.get('version') or 'unknown'}",
                    f"Mode: {'CLI/headless friendly' if model['cli_friendly'] else 'GUI-centric'}",
                    f"Default launch args: {launch_text}",
                    f"Homepage: {status.get('homepage') or 'n/a'}",
                ]
                self.query_one("#tool_status", Static).update("\n".join(status_lines))
                self.query_one("#tool_title", Static).update(
                    f"Tool Workbench  tool={status['label']}  target={self._selected_target_path() or 'none'}  busy={self._busy}"
                )
                self._populate_preset_table(model.get("presets", []))
                export_button = self.query_one("#tool_btn_export", Button)
                export_button.disabled = not bool(self.report and TOOL_EXPORT_FORMATS.get(self.current_tool_key))
                launch_button = self.query_one("#tool_btn_launch", Button)
                launch_button.disabled = not status.get("installed")
                if self._preset_rows and not self.query_one("#tool_args", Input).value.strip():
                    self.query_one("#tool_args", Input).value = self._resolved_preset_text(self._preset_rows[0])

            def _enqueue_event(self, event: dict) -> None:
                self._events.put(dict(event))

            def _drain_events(self) -> None:
                while True:
                    try:
                        event = self._events.get_nowait()
                    except queue.Empty:
                        break
                    self._handle_event(event)

            def _handle_event(self, event: dict) -> None:
                kind = event.get("kind", "log")
                message = str(event.get("message", "")).strip()
                progress = event.get("progress")
                if progress is not None:
                    self.query_one("#tool_progress", ProgressBar).update(progress=float(progress))
                if message:
                    self._log(message)
                if kind in {"done", "error"}:
                    self._busy = False
                    self._refresh_model()
                    if kind == "error":
                        self.notify(message or "Tool action failed.", title="Tool Workbench", severity="error")
                    elif message:
                        self.notify(message, title="Tool Workbench", severity="information")

            def _start_background(self, runner, intro: str) -> None:
                if self._busy:
                    self.notify("A tool task is already running.", title="Tool Workbench", severity="warning")
                    return
                self._busy = True
                self._current_result = None
                self.query_one("#tool_progress", ProgressBar).update(progress=0.0)
                self._log(intro)

                def worker():
                    try:
                        result = runner(self._enqueue_event)
                    except Exception as exc:
                        self._enqueue_event({"kind": "error", "message": str(exc), "progress": 100.0})
                    else:
                        done_message = "Task completed."
                        if isinstance(result, dict) and result.get("message"):
                            done_message = str(result["message"])
                        self._current_result = result
                        self._enqueue_event(
                            {
                                "kind": "done",
                                "message": done_message,
                                "progress": 100.0,
                                "result": result,
                            }
                        )

                threading.Thread(target=worker, daemon=True).start()
                self._refresh_model()

            def _run_args(self) -> None:
                args_value = self.query_one("#tool_args", Input).value.strip()
                if not args_value:
                    self.notify("Enter arguments or apply a preset first.", title="Tool Workbench", severity="warning")
                    return
                target_path = self._selected_target_path()

                def runner(emit):
                    return run_external_tool_command(
                        self.current_tool_key,
                        args=args_value,
                        target_path=target_path,
                        event_cb=emit,
                    )

                self._start_background(runner, f"Running args for {self.current_tool_key}: {args_value}")

            def _run_selected_preset(self) -> None:
                preset = self._selected_preset()
                if not preset:
                    self.notify("No preset selected.", title="Tool Workbench", severity="warning")
                    return
                target_path = self._selected_target_path()
                args = list(preset.get("args", []))

                def runner(emit):
                    return run_external_tool_command(
                        self.current_tool_key,
                        args=args,
                        target_path=target_path,
                        event_cb=emit,
                    )

                self._start_background(
                    runner,
                    f"Running preset '{preset['label']}' for {self.current_tool_key}",
                )

            def _launch_tool(self) -> None:
                target_path = self._selected_target_path()

                def runner(emit):
                    return launch_external_tool(
                        self.current_tool_key,
                        target_path=target_path,
                        event_cb=emit,
                    )

                self._start_background(runner, f"Launching {self.current_tool_key}")

            def _export_tool_script(self) -> None:
                if not self.report:
                    self.notify("No active scan report is available for export.", title="Tool Workbench", severity="warning")
                    return
                tool_format = TOOL_EXPORT_FORMATS.get(self.current_tool_key)
                if not tool_format:
                    self.notify("This tool has no export format mapping.", title="Tool Workbench", severity="warning")
                    return
                target = default_tool_plugin_path(self.report, tool_format)
                exported = export_tool_plugin(self.report, target, tool_format)
                self._log(f"Exported {tool_format} integration: {exported}")
                self.notify(f"Saved {tool_format} integration: {exported}", title="Tool Workbench", severity="information")

            def action_close_workbench(self) -> None:
                self.dismiss()

            def action_refresh_model(self) -> None:
                self._populate_tool_table()
                self._refresh_model()
                self.notify("Tool model refreshed.", title="Tool Workbench", severity="information")

            def action_run_selected_preset(self) -> None:
                self._run_selected_preset()

            def action_launch_tool(self) -> None:
                self._launch_tool()

            def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
                table_id = event.data_table.id
                row_index = int(event.coordinate.row)
                if table_id == "tool_list":
                    if 0 <= row_index < len(self._tool_keys):
                        self.current_tool_key = self._tool_keys[row_index]
                        self.query_one("#tool_args", Input).value = ""
                        self._refresh_model()
                elif table_id == "tool_presets":
                    preset = self._selected_preset()
                    if preset:
                        self.query_one("#tool_args", Input).value = self._resolved_preset_text(preset)

            def on_button_pressed(self, event: Button.Pressed) -> None:
                button_id = event.button.id
                if button_id == "tool_btn_refresh":
                    self.action_refresh_model()
                elif button_id == "tool_btn_launch":
                    self._launch_tool()
                elif button_id == "tool_btn_export":
                    self._export_tool_script()
                elif button_id == "tool_btn_apply_preset":
                    preset = self._selected_preset()
                    if preset:
                        self.query_one("#tool_args", Input).value = self._resolved_preset_text(preset)
                elif button_id == "tool_btn_run_preset":
                    self._run_selected_preset()
                elif button_id == "tool_btn_run_args":
                    self._run_args()
                elif button_id == "tool_btn_clear":
                    self.query_one("#tool_output", RichLog).clear()

        return _ToolWorkbenchScreen()
