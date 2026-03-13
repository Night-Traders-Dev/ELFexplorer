import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from textual.app import App
from textual.widgets import Static

from ui.textual_tasks import BackgroundTaskScreenFactory


class _TaskTestApp(App[None]):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    async def on_mount(self) -> None:
        self.push_screen(self._screen)


class TextualTaskScreenTests(unittest.IsolatedAsyncioTestCase):
    async def test_background_task_screen_uses_centered_modal_layout(self):
        def runner(emit):
            emit({"kind": "log", "message": "Starting", "progress": 25.0})
            return {"message": "Done"}

        screen = BackgroundTaskScreenFactory.build(
            title="ELFexplorer 0.0.0",
            intro="Loading workspace services and checking host integrations.",
            runner=runner,
            auto_close_on_success=False,
        )
        self.assertIn("ModalScreen {", screen.CSS)
        self.assertIn("text-align: center;", screen.CSS)

        app = _TaskTestApp(screen)
        async with app.run_test(headless=True, size=(120, 40)) as pilot:
            await pilot.pause()
            title = str(screen.query_one("#task_title", Static).content)
            intro = str(screen.query_one("#task_intro", Static).content)
            self.assertIn("ELFexplorer", title)
            self.assertIn("Loading workspace services", intro)


if __name__ == "__main__":
    unittest.main()
