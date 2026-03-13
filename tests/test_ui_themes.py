import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from textual.app import App

from ui.themes import ELFEXPLORER_THEMES, register_elfexplorer_themes


class _ThemeTestApp(App[None]):
    pass


class TextualThemeTests(unittest.TestCase):
    def test_register_elfexplorer_themes_adds_custom_themes(self):
        app = _ThemeTestApp()
        register_elfexplorer_themes(app)

        available = set(app.available_themes)
        for theme in ELFEXPLORER_THEMES:
            self.assertIn(theme.name, available)


if __name__ == "__main__":
    unittest.main()
