import asyncio
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from textual.app import App
from textual.widgets import DataTable

from ui.textual_tool_workbench import ToolWorkbenchScreenFactory


class _WorkbenchTestApp(App[None]):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    async def on_mount(self) -> None:
        self.push_screen(self._screen)


class TextualToolWorkbenchTests(unittest.IsolatedAsyncioTestCase):
    async def test_tool_list_row_navigation_updates_active_tool(self):
        repo_root = Path(__file__).resolve().parents[1]
        target = repo_root / "test-bin" / "x86_64" / "hello_c"
        screen = ToolWorkbenchScreenFactory.build(initial_tool="radare2", target_path=str(target))
        app = _WorkbenchTestApp(screen)

        async with app.run_test(headless=True, size=(140, 40)) as pilot:
            await pilot.pause()
            table = screen.query_one("#tool_list", DataTable)
            self.assertEqual(screen.current_tool_key, "radare2")
            self.assertGreaterEqual(len(screen._tool_keys), 2)

            target_index = 0 if screen._tool_keys[0] != "radare2" else 1
            expected_tool = screen._tool_keys[target_index]
            table.move_cursor(row=target_index, column=0)
            await pilot.pause()

            self.assertEqual(screen.current_tool_key, expected_tool)


if __name__ == "__main__":
    unittest.main()
