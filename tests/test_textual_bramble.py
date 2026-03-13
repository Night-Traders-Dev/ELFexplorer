import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from textual.app import App
from textual.containers import VerticalScroll
from textual.widgets import Input, Static

from ui.textual_bramble import BrambleScreenFactory


class _BrambleTestApp(App[None]):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    async def on_mount(self) -> None:
        self.push_screen(self._screen)


class TextualBrambleTests(unittest.IsolatedAsyncioTestCase):
    async def test_bramble_screen_preview_includes_target(self):
        target = "/tmp/fw.uf2"
        screen = BrambleScreenFactory.build(target_path=target)
        app = _BrambleTestApp(screen)

        async with app.run_test(headless=True, size=(140, 45)) as pilot:
            await pilot.pause()
            preview = str(screen.query_one("#bramble_preview", Static).content)
            self.assertIn("bramble", preview)
            self.assertIn(target, preview)

    async def test_bramble_screen_has_scrollable_controls_and_executable_override(self):
        target = "/tmp/fw.uf2"
        override = "/opt/bramble/bin/bramble"
        screen = BrambleScreenFactory.build(target_path=target)
        app = _BrambleTestApp(screen)

        async with app.run_test(headless=True, size=(140, 45)) as pilot:
            await pilot.pause()
            controls = screen.query_one("#bramble_controls_scroll", VerticalScroll)
            self.assertIsNotNone(controls)

            executable = screen.query_one("#bramble_executable", Input)
            executable.value = override
            screen._refresh_preview()
            await pilot.pause()

            preview = str(screen.query_one("#bramble_preview", Static).content)
            self.assertIn(override, preview)
            self.assertIn(target, preview)

    async def test_bramble_screen_loads_saved_executable_override(self):
        target = "/tmp/fw.uf2"
        saved_override = "/custom/tools/bramble"
        with patch("ui.textual_bramble.load_tool_path", return_value=saved_override):
            screen = BrambleScreenFactory.build(target_path=target)
        app = _BrambleTestApp(screen)

        async with app.run_test(headless=True, size=(140, 45)) as pilot:
            await pilot.pause()
            executable = screen.query_one("#bramble_executable", Input)
            self.assertEqual(executable.value, saved_override)


if __name__ == "__main__":
    unittest.main()
