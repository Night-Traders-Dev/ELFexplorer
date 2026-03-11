import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import settings


class SettingsTests(unittest.TestCase):
    def test_load_settings_creates_default_file_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "settings.conf"
            with patch("settings.settings_path", return_value=target):
                loaded = settings.load_settings()
                self.assertEqual(loaded["theme"], "textual-dark")
                self.assertTrue(target.exists())
                on_disk = json.loads(target.read_text(encoding="utf-8"))
                self.assertEqual(on_disk["theme"], "textual-dark")

    def test_save_and_load_theme_preference_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "settings.conf"
            with patch("settings.settings_path", return_value=target):
                settings.save_theme_preference("nord")
                self.assertEqual(settings.load_theme_preference(), "nord")
                on_disk = json.loads(target.read_text(encoding="utf-8"))
                self.assertEqual(on_disk["theme"], "nord")

    def test_load_settings_recovers_from_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "settings.conf"
            target.write_text("{invalid json", encoding="utf-8")
            with patch("settings.settings_path", return_value=target):
                loaded = settings.load_settings()
                self.assertEqual(loaded["theme"], "textual-dark")


if __name__ == "__main__":
    unittest.main()

