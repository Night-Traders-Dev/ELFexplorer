import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ui.textual_diff import _rows_for_delta, _rows_for_summary


class TextualDiffHelpersTests(unittest.TestCase):
    def test_rows_for_summary_marks_changes(self):
        diff = {
            "summary": {
                "language": ["C", "C++"],
                "compiler": ["GCC", "GCC"],
                "build_system": ["CMake", "Meson"],
                "artifact_type": ["Linux User-space Executable", "Linux User-space Executable"],
                "artifact_confidence": [80, 91],
            }
        }
        rows = list(_rows_for_summary(diff))
        by_field = {row[0]: row for row in rows}
        self.assertEqual(by_field["language"][3], "changed")
        self.assertEqual(by_field["compiler"][3], "same")
        self.assertEqual(by_field["artifact_confidence"][1], "80")
        self.assertEqual(by_field["artifact_confidence"][2], "91")

    def test_rows_for_delta_formats_delta(self):
        diff = {
            "language_deltas": [
                {"label": "C", "before": 10, "after": 3, "delta": -7},
                {"label": "C++", "before": 2, "after": 9, "delta": 7},
            ]
        }
        rows = list(_rows_for_delta(diff, "language_deltas"))
        self.assertEqual(rows[0], ("C", "10", "3", "-7"))
        self.assertEqual(rows[1], ("C++", "2", "9", "+7"))


if __name__ == "__main__":
    unittest.main()
