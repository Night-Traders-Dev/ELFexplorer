from __future__ import annotations

import queue
import threading
from typing import Callable


class BackgroundTaskScreenFactory:
    """Build modal screens that run blocking work on a background thread."""

    @staticmethod
    def build(
        *,
        title: str,
        runner: Callable[[Callable[[dict], None]], object],
        intro: str = "",
        on_complete: Callable[[object, bool], None] | None = None,
        auto_close_on_success: bool = False,
        close_label: str = "Close",
    ):
        from textual.app import ComposeResult
        from textual.containers import Vertical
        from textual.screen import ModalScreen
        from textual.widgets import Button, ProgressBar, RichLog, Static

        class _BackgroundTaskScreen(ModalScreen):
            CSS = """
            ModalScreen {
                align: center middle;
            }
            #task_modal {
                width: 88;
                height: 30;
                border: round $primary;
                background: $surface;
                padding: 1 2;
            }
            #task_title {
                height: auto;
                text-style: bold;
                color: $accent;
                padding-bottom: 1;
                text-align: center;
            }
            #task_intro {
                height: auto;
                color: $text-muted;
                padding-bottom: 1;
                text-align: center;
            }
            #task_status {
                height: auto;
                padding: 1 0 0 0;
                text-align: center;
            }
            #task_progress {
                margin: 1 0;
            }
            #task_log {
                height: 1fr;
                border: round $secondary;
                margin: 1 0;
            }
            #task_actions {
                height: auto;
                align-horizontal: right;
            }
            """

            BINDINGS = [("escape", "close_if_done", "Close")]

            def __init__(self):
                super().__init__()
                self._events: "queue.Queue[dict]" = queue.Queue()
                self._thread: threading.Thread | None = None
                self._complete = False
                self._result = None
                self._success = False

            def compose(self) -> ComposeResult:
                with Vertical(id="task_modal"):
                    yield Static(title, id="task_title")
                    yield Static(intro, id="task_intro")
                    yield Static("Waiting to start...", id="task_status")
                    yield ProgressBar(total=100, show_eta=False, id="task_progress")
                    yield RichLog(id="task_log", wrap=True, markup=False, highlight=False)
                    yield Button(close_label, id="task_close", variant="primary", disabled=True)

            def on_mount(self) -> None:
                self.set_interval(0.1, self._drain_events)
                self._thread = threading.Thread(target=self._run_worker, daemon=True)
                self._thread.start()

            def _emit(self, event: dict) -> None:
                self._events.put(dict(event))

            def _run_worker(self) -> None:
                try:
                    result = runner(self._emit)
                except Exception as exc:
                    self._emit(
                        {
                            "kind": "error",
                            "message": str(exc),
                            "progress": 100.0,
                        }
                    )
                else:
                    done_message = "Task completed."
                    if isinstance(result, dict) and result.get("message"):
                        done_message = str(result["message"])
                    self._emit(
                        {
                            "kind": "done",
                            "message": done_message,
                            "progress": 100.0,
                            "result": result,
                        }
                    )

            def _append_log(self, message: str) -> None:
                self.query_one("#task_log", RichLog).write(message)

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
                    self.query_one("#task_progress", ProgressBar).update(progress=float(progress))
                if message:
                    self.query_one("#task_status", Static).update(message)
                    self._append_log(message)

                if kind == "done":
                    self._complete = True
                    self._success = True
                    self._result = event.get("result")
                    self.query_one("#task_close", Button).disabled = False
                    if on_complete:
                        on_complete(self._result, True)
                    if auto_close_on_success:
                        self.dismiss(self._result)
                elif kind == "error":
                    self._complete = True
                    self._success = False
                    self._result = event.get("result")
                    self.query_one("#task_close", Button).disabled = False
                    if on_complete:
                        on_complete(self._result, False)

            def action_close_if_done(self) -> None:
                if self._complete:
                    self.dismiss(self._result)

            def on_button_pressed(self, event: Button.Pressed) -> None:
                if event.button.id == "task_close" and self._complete:
                    self.dismiss(self._result)

        return _BackgroundTaskScreen()
