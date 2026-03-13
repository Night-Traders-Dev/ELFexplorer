import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


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

    def test_main_print_tools(self):
        capture = io.StringIO()
        with redirect_stdout(capture):
            rc = self.mod.main(["--print-tools"])
        self.assertEqual(rc, 0)
        output = capture.getvalue()
        self.assertIn("Known external tools:", output)
        self.assertIn("ghidra", output)
        self.assertIn("radare2", output)

    def test_main_check_tools_prints_status(self):
        snapshot = {
            "environment": {
                "os_label": "Linux",
                "primary_package_manager_label": "APT",
                "distro": "Ubuntu 24.04 LTS",
            },
            "tools": [
                {"label": "Ghidra", "installed": False, "install_supported": False},
                {
                    "label": "radare2",
                    "installed": False,
                    "install_supported": True,
                    "install_command": "sudo apt-get install -y radare2",
                },
            ],
        }
        capture = io.StringIO()
        with mock.patch.object(self.mod, "collect_external_tool_status", return_value=snapshot), redirect_stdout(
            capture
        ):
            rc = self.mod.main(["--check-tools"])
        self.assertEqual(rc, 0)
        output = capture.getvalue()
        self.assertIn("Host OS: Linux", output)
        self.assertIn("Package manager: APT", output)
        self.assertIn("radare2: missing, install with", output)

    def test_main_install_tool_dry_run(self):
        result = {
            "ok": True,
            "message": "Dry run: sudo apt-get install -y radare2",
            "status": {"label": "radare2"},
            "command": ["sudo", "apt-get", "install", "-y", "radare2"],
            "output": "",
        }
        capture = io.StringIO()
        with mock.patch.object(self.mod, "install_external_tool", return_value=result), redirect_stdout(capture):
            rc = self.mod.main(["--install-tool", "radare2", "--dry-run"])
        self.assertEqual(rc, 0)
        output = capture.getvalue()
        self.assertIn("Tool: radare2", output)
        self.assertIn("Command: sudo apt-get install -y radare2", output)

    def test_main_tool_info_prints_download_and_methods(self):
        detail = {
            "status": {"label": "radare2", "installed": False, "path": None, "version": None},
            "homepage": "https://rada.re/n/",
            "download_url": "https://book.rada.re/install/index.html",
            "host_install_command": ["sudo", "apt-get", "install", "-y", "radare2"],
            "install_methods": [
                {
                    "manager_label": "APT",
                    "command": ["apt-get", "install", "-y", "radare2"],
                }
            ],
            "manual_install": "Build from source if needed.",
        }
        capture = io.StringIO()
        with mock.patch.object(self.mod, "describe_external_tool", return_value=detail), redirect_stdout(
            capture
        ):
            rc = self.mod.main(["--tool-info", "radare2"])
        self.assertEqual(rc, 0)
        output = capture.getvalue()
        self.assertIn("Tool: radare2 (radare2)", output)
        self.assertIn("Download: https://book.rada.re/install/index.html", output)
        self.assertIn("Host install: sudo apt-get install -y radare2", output)
        self.assertIn("Package-manager methods:", output)


if __name__ == "__main__":
    unittest.main()
