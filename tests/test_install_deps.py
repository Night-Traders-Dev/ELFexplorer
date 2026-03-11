import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path


def _load_install_deps_module():
    repo_root = Path(__file__).resolve().parents[1]
    module_path = repo_root / "install_deps.py"
    spec = importlib.util.spec_from_file_location("install_deps_module", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InstallDepsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_install_deps_module()

    def test_resolve_packages_deduplicates_and_preserves_order(self):
        packages = self.mod.resolve_packages(["core", "ui", "pdf", "ui"])
        self.assertEqual(packages, ["pyelftools", "textual", "reportlab"])

    def test_build_install_cmd_with_upgrade(self):
        command = self.mod.build_install_cmd("python3", ["pyelftools"], upgrade=True)
        self.assertEqual(command, ["python3", "-m", "pip", "install", "--upgrade", "pyelftools"])

    def test_main_dry_run_runtime_profile(self):
        capture = io.StringIO()
        with redirect_stdout(capture):
            rc = self.mod.main(["--dry-run"])
        self.assertEqual(rc, 0)
        output = capture.getvalue()
        self.assertIn("Selected profile: runtime", output)
        self.assertIn("pyelftools", output)
        self.assertIn("textual", output)
        self.assertIn("reportlab", output)

    def test_main_print_groups(self):
        capture = io.StringIO()
        with redirect_stdout(capture):
            rc = self.mod.main(["--print-groups"])
        self.assertEqual(rc, 0)
        output = capture.getvalue()
        self.assertIn("Available dependency groups:", output)
        self.assertIn("core:", output)
        self.assertIn("dev:", output)


if __name__ == "__main__":
    unittest.main()
