from __future__ import annotations

import queue
import shlex
import threading
from pathlib import Path

from advanced.tooling import (
    build_bramble_command_args,
    get_external_tool_workbench_model,
    launch_external_tool,
    render_bramble_feature_lines,
    run_external_tool_command,
)


class BrambleScreenFactory:
    @staticmethod
    def build(*, target_path=None, report=None):
        from textual.app import ComposeResult
        from textual.containers import Horizontal, Vertical, VerticalScroll
        from textual.screen import Screen
        from textual.widgets import (
            Button,
            Checkbox,
            Footer,
            Header,
            Input,
            ProgressBar,
            RichLog,
            Static,
            TabbedContent,
            TabPane,
        )

        class _BrambleScreen(Screen):
            CSS = """
            Screen {
                layout: vertical;
            }
            #bramble_title {
                height: auto;
                border: round $primary;
                padding: 0 1;
            }
            #bramble_status {
                height: auto;
                border: round $secondary;
                padding: 1;
                margin-bottom: 1;
            }
            #bramble_controls {
                width: 46;
                min-width: 38;
                border: round $secondary;
                padding: 0 1;
                margin-right: 1;
            }
            #bramble_console {
                width: 1fr;
                border: round $secondary;
                padding: 0 1;
            }
            .bramble_pane_title {
                height: auto;
                color: $accent;
                text-style: bold;
                padding: 0 1;
            }
            .bramble_input {
                margin-bottom: 1;
            }
            .bramble_check {
                margin-bottom: 1;
            }
            #bramble_actions, #bramble_actions_2 {
                height: auto;
                margin-bottom: 1;
            }
            #bramble_actions Button, #bramble_actions_2 Button {
                margin-right: 1;
            }
            #bramble_preview {
                height: auto;
                border: round $panel;
                padding: 1;
                margin-bottom: 1;
            }
            #bramble_progress {
                margin-bottom: 1;
            }
            #bramble_output {
                height: 1fr;
                border: round $panel;
            }
            #bramble_reference_scroll, #bramble_examples_scroll {
                height: 1fr;
                border: round $secondary;
            }
            #bramble_reference, #bramble_examples {
                padding: 1 2;
            }
            TabbedContent {
                height: 1fr;
            }
            """

            BINDINGS = [
                ("escape", "close_screen", "Back"),
                ("f5", "refresh_status", "Refresh"),
                ("f6", "run_firmware", "Run"),
                ("f7", "run_gdb", "GDB"),
                ("f8", "launch_external", "Launch"),
            ]

            def __init__(self):
                super().__init__()
                self.report = report
                self.current_target_path = str(Path(target_path).expanduser()) if target_path else ""
                self._events: "queue.Queue[dict]" = queue.Queue()
                self._busy = False
                self._current_result = None

            def compose(self) -> ComposeResult:
                yield Header(show_clock=True)
                yield Static("", id="bramble_title")
                with TabbedContent():
                    with TabPane("Session"):
                        yield Static("", id="bramble_status")
                        with Horizontal():
                            with Vertical(id="bramble_controls"):
                                yield Static("Run Settings", classes="bramble_pane_title")
                                yield Input(
                                    value=self.current_target_path,
                                    placeholder="Target UF2 or ELF path",
                                    id="bramble_target",
                                    classes="bramble_input",
                                )
                                yield Input(placeholder="Clock MHz (example: 125)", id="bramble_clock", classes="bramble_input")
                                yield Input(value="3333", placeholder="GDB port", id="bramble_gdb_port", classes="bramble_input")
                                yield Input(placeholder="Flash image path", id="bramble_flash", classes="bramble_input")
                                yield Input(placeholder="Mount directory", id="bramble_mount", classes="bramble_input")
                                yield Input(placeholder="SD card image path", id="bramble_sdcard", classes="bramble_input")
                                yield Input(placeholder="SD card size MiB", id="bramble_sdcard_size", classes="bramble_input")
                                yield Input(placeholder="eMMC image path", id="bramble_emmc", classes="bramble_input")
                                yield Input(placeholder="eMMC size MiB", id="bramble_emmc_size", classes="bramble_input")
                                yield Input(placeholder="UART0 TCP port", id="bramble_uart0_port", classes="bramble_input")
                                yield Input(placeholder="UART0 connect host:port", id="bramble_uart0_connect", classes="bramble_input")
                                yield Input(placeholder="Wire UART0 socket path", id="bramble_wire_uart0", classes="bramble_input")
                                yield Input(placeholder="Wire GPIO socket path", id="bramble_wire_gpio", classes="bramble_input")
                                yield Checkbox("stdin -> UART0", id="bramble_stdin", classes="bramble_check")
                                yield Checkbox("Core 1 debug", id="bramble_debug1", classes="bramble_check")
                                yield Checkbox("Debug unmapped memory", id="bramble_debug_mem", classes="bramble_check")
                                yield Checkbox("Disable boot2", id="bramble_no_boot2", classes="bramble_check")
                                yield Checkbox("Enable JIT", id="bramble_jit", classes="bramble_check")
                                with Horizontal(id="bramble_actions"):
                                    yield Button("Run", id="bramble_btn_run", variant="primary")
                                    yield Button("Debug", id="bramble_btn_debug", variant="warning")
                                    yield Button("ASM", id="bramble_btn_asm", variant="warning")
                                    yield Button("Status", id="bramble_btn_status")
                                with Horizontal(id="bramble_actions_2"):
                                    yield Button("GDB", id="bramble_btn_gdb", variant="success")
                                    yield Button("Launch App", id="bramble_btn_launch")
                                    yield Button("Clear", id="bramble_btn_clear")
                            with Vertical(id="bramble_console"):
                                yield Static("Command Preview", classes="bramble_pane_title")
                                yield Static("", id="bramble_preview")
                                yield ProgressBar(total=100, show_eta=False, id="bramble_progress")
                                yield RichLog(id="bramble_output", wrap=True, markup=False, highlight=False, auto_scroll=True)
                    with TabPane("Reference"):
                        with VerticalScroll(id="bramble_reference_scroll"):
                            yield Static("", id="bramble_reference")
                    with TabPane("Examples"):
                        with VerticalScroll(id="bramble_examples_scroll"):
                            yield Static("", id="bramble_examples")
                yield Footer()

            def on_mount(self) -> None:
                self.set_interval(0.1, self._drain_events)
                self._refresh_status()
                self._refresh_preview()
                self._populate_reference()
                self._populate_examples()

            def _log(self, message: str) -> None:
                self.query_one("#bramble_output", RichLog).write(message)

            def _selected_target_path(self) -> str | None:
                value = self.query_one("#bramble_target", Input).value.strip()
                self.current_target_path = value
                return value or None

            def _checkbox(self, widget_id: str) -> bool:
                return bool(self.query_one(f"#{widget_id}", Checkbox).value)

            def _input_value(self, widget_id: str) -> str | None:
                value = self.query_one(f"#{widget_id}", Input).value.strip()
                return value or None

            def _build_args(self, mode: str = "run"):
                return build_bramble_command_args(
                    self._selected_target_path(),
                    debug=(mode == "debug"),
                    debug1=self._checkbox("bramble_debug1"),
                    asm_trace=(mode == "asm"),
                    status=(mode == "status"),
                    stdin_enabled=self._checkbox("bramble_stdin"),
                    gdb=(mode == "gdb"),
                    gdb_port=self._input_value("bramble_gdb_port"),
                    clock_mhz=self._input_value("bramble_clock"),
                    no_boot2=self._checkbox("bramble_no_boot2"),
                    debug_mem=self._checkbox("bramble_debug_mem"),
                    flash_path=self._input_value("bramble_flash"),
                    mount_path=self._input_value("bramble_mount"),
                    sdcard_path=self._input_value("bramble_sdcard"),
                    sdcard_size_mb=self._input_value("bramble_sdcard_size"),
                    emmc_path=self._input_value("bramble_emmc"),
                    emmc_size_mb=self._input_value("bramble_emmc_size"),
                    uart0_port=self._input_value("bramble_uart0_port"),
                    uart0_connect=self._input_value("bramble_uart0_connect"),
                    wire_uart0=self._input_value("bramble_wire_uart0"),
                    wire_gpio=self._input_value("bramble_wire_gpio"),
                    jit=self._checkbox("bramble_jit"),
                )

            def _refresh_status(self) -> None:
                model = get_external_tool_workbench_model("bramble", target_path=self._selected_target_path())
                status = model["status"]
                install_mode = (
                    "one-click source build"
                    if status.get("portable_install_supported")
                    else (status.get("install_manager_label") or "manual install")
                )
                lines = [
                    f"Tool: {status['label']} (bramble)",
                    f"Installed: {'yes' if status['installed'] else 'no'}",
                    f"Executable: {status.get('path') or 'not found'}",
                    f"Version: {status.get('version') or 'unknown'}",
                    f"Host install path: {install_mode}",
                    f"Homepage: {status.get('homepage') or 'n/a'}",
                    f"Target: {self._selected_target_path() or 'none'}",
                ]
                self.query_one("#bramble_status", Static).update("\n".join(lines))
                self.query_one("#bramble_title", Static).update(
                    f"Bramble Workbench  target={self._selected_target_path() or 'none'}  busy={self._busy}"
                )

            def _refresh_preview(self, mode: str = "run") -> None:
                try:
                    args = self._build_args(mode=mode)
                    preview = shlex.join(["bramble", *args])
                except Exception as exc:
                    preview = f"Configure a target firmware path to enable Bramble. ({exc})"
                self.query_one("#bramble_preview", Static).update(preview)

            def _populate_reference(self) -> None:
                self.query_one("#bramble_reference", Static).update("\n".join(render_bramble_feature_lines()))

            def _populate_examples(self) -> None:
                target = self._selected_target_path() or "firmware.uf2"
                examples = [
                    "Bramble workflows surfaced by ELFexplorer:",
                    "",
                    f"- Smoke test firmware: bramble {target}",
                    f"- Core 0 trace: bramble {target} -debug",
                    f"- Instruction trace: bramble {target} -asm",
                    f"- GDB server: bramble {target} -gdb 3333",
                    f"- Persistent flash: bramble {target} -flash flash.bin",
                    f"- SD card image: bramble {target} -sdcard sd.img -sdcard-size 32",
                    f"- UART bridge: bramble {target} -net-uart0 9999 -stdin",
                    f"- GPIO/UART wiring: bramble {target} -wire-uart0 /tmp/uart.sock",
                    "",
                    "Use this screen when you want emulator-focused actions and command synthesis rather than the generic tool workbench.",
                ]
                self.query_one("#bramble_examples", Static).update("\n".join(examples))

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
                    self.query_one("#bramble_progress", ProgressBar).update(progress=float(progress))
                if message:
                    self._log(message)
                if kind in {"done", "error"}:
                    self._busy = False
                    self._refresh_status()
                    self._refresh_preview()
                    if kind == "error":
                        self.notify(message or "Bramble action failed.", title="Bramble", severity="error")
                    elif message:
                        self.notify(message, title="Bramble", severity="information")

            def _start_background(self, runner, intro: str) -> None:
                if self._busy:
                    self.notify("A Bramble task is already running.", title="Bramble", severity="warning")
                    return
                self._busy = True
                self._current_result = None
                self.query_one("#bramble_progress", ProgressBar).update(progress=0.0)
                self._log(intro)

                def worker():
                    try:
                        result = runner(self._enqueue_event)
                    except Exception as exc:
                        self._enqueue_event({"kind": "error", "message": str(exc), "progress": 100.0})
                    else:
                        done_message = "Bramble task completed."
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
                self._refresh_status()

            def _run_mode(self, mode: str) -> None:
                try:
                    args = self._build_args(mode=mode)
                except Exception as exc:
                    self.notify(str(exc), title="Bramble", severity="warning")
                    self._refresh_preview(mode=mode)
                    return

                def runner(emit):
                    return run_external_tool_command(
                        "bramble",
                        args=args,
                        event_cb=emit,
                    )

                self._refresh_preview(mode=mode)
                self._start_background(runner, f"Running Bramble mode={mode}")

            def _launch_external(self) -> None:
                try:
                    args = self._build_args(mode="run")
                except Exception as exc:
                    self.notify(str(exc), title="Bramble", severity="warning")
                    self._refresh_preview(mode="run")
                    return

                def runner(emit):
                    return launch_external_tool(
                        "bramble",
                        args=args,
                        event_cb=emit,
                    )

                self._refresh_preview(mode="run")
                self._start_background(runner, "Launching Bramble externally")

            def action_close_screen(self) -> None:
                self.dismiss()

            def action_refresh_status(self) -> None:
                self._refresh_status()
                self._refresh_preview()
                self._populate_examples()
                self.notify("Bramble status refreshed.", title="Bramble", severity="information")

            def action_run_firmware(self) -> None:
                self._run_mode("run")

            def action_run_gdb(self) -> None:
                self._run_mode("gdb")

            def action_launch_external(self) -> None:
                self._launch_external()

            def on_input_changed(self, event: Input.Changed) -> None:
                if event.input.id and event.input.id.startswith("bramble_"):
                    self._refresh_status()
                    self._refresh_preview()
                    self._populate_examples()

            def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
                if event.checkbox.id and event.checkbox.id.startswith("bramble_"):
                    self._refresh_preview()

            def on_button_pressed(self, event: Button.Pressed) -> None:
                button_id = event.button.id
                if button_id == "bramble_btn_run":
                    self._run_mode("run")
                elif button_id == "bramble_btn_debug":
                    self._run_mode("debug")
                elif button_id == "bramble_btn_asm":
                    self._run_mode("asm")
                elif button_id == "bramble_btn_status":
                    self._run_mode("status")
                elif button_id == "bramble_btn_gdb":
                    self._run_mode("gdb")
                elif button_id == "bramble_btn_launch":
                    self._launch_external()
                elif button_id == "bramble_btn_clear":
                    self.query_one("#bramble_output", RichLog).clear()

        return _BrambleScreen()
