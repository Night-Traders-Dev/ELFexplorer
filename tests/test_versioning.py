import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from version import get_version


class VersioningTests(unittest.TestCase):
    def test_version_file_uses_semver_core(self):
        version = get_version()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")

    def test_elfscan_version_flag(self):
        repo_root = Path(__file__).resolve().parents[1]
        elfscan_script = repo_root / "src" / "elfscan.py"
        completed = subprocess.run(
            [sys.executable, str(elfscan_script), "--version"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        output = (completed.stdout or "") + (completed.stderr or "")
        self.assertIn(f"ELFexplorer {get_version()}", output)


if __name__ == "__main__":
    unittest.main()
