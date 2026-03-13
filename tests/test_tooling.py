import unittest
from unittest import mock

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from advanced import tooling


class ToolingTests(unittest.TestCase):
    def test_detect_host_environment_prefers_apt_on_linux(self):
        which_map = {
            "apt-get": "/usr/bin/apt-get",
            "dnf": None,
            "pacman": None,
            "yay": None,
            "paru": None,
            "brew": None,
        }
        with mock.patch("advanced.tooling.platform.system", return_value="Linux"), mock.patch(
            "advanced.tooling.platform.freedesktop_os_release",
            return_value={"PRETTY_NAME": "Ubuntu 24.04 LTS"},
        ), mock.patch(
            "advanced.tooling.shutil.which",
            side_effect=lambda name: which_map.get(name),
        ):
            environment = tooling.detect_host_environment()

        self.assertEqual(environment["os"], "linux")
        self.assertEqual(environment["primary_package_manager"], "apt")
        self.assertEqual(environment["distro"], "Ubuntu 24.04 LTS")

    def test_get_external_tool_status_detects_installed_tool_in_path(self):
        environment = {
            "os": "linux",
            "os_label": "Linux",
            "package_managers": ["apt"],
            "primary_package_manager": "apt",
            "primary_package_manager_label": "APT",
        }

        def fake_which(name):
            if name == "r2":
                return "/usr/bin/r2"
            if name == "sudo":
                return "/usr/bin/sudo"
            return None

        completed = mock.Mock(returncode=0, stdout="radare2 5.9.0 0 @ linux-x86-64\n", stderr="")
        with mock.patch("advanced.tooling.shutil.which", side_effect=fake_which), mock.patch(
            "advanced.tooling.subprocess.run",
            return_value=completed,
        ):
            status = tooling.get_external_tool_status("radare2", environment=environment)

        self.assertTrue(status["installed"])
        self.assertEqual(status["path"], "/usr/bin/r2")
        self.assertIn("5.9.0", status["version"])

    def test_build_install_command_uses_brew_cask_when_recipe_requires_it(self):
        environment = {
            "os": "macos",
            "os_label": "macOS",
            "package_managers": ["brew"],
            "primary_package_manager": "brew",
            "primary_package_manager_label": "Homebrew",
        }
        command, manager = tooling.build_install_command("ghidra", environment=environment, interactive=True)
        self.assertEqual(manager, "brew")
        self.assertEqual(command, ["brew", "install", "--cask", "ghidra"])

    def test_install_external_tool_dry_run_returns_manual_command(self):
        environment = {
            "os": "linux",
            "os_label": "Linux",
            "package_managers": ["apt"],
            "primary_package_manager": "apt",
            "primary_package_manager_label": "APT",
        }

        def fake_which(name):
            if name == "sudo":
                return "/usr/bin/sudo"
            return None

        with mock.patch("advanced.tooling.shutil.which", side_effect=fake_which), mock.patch(
            "advanced.tooling.os.geteuid",
            return_value=1000,
        ):
            result = tooling.install_external_tool("radare2", dry_run=True, environment=environment)

        self.assertTrue(result["ok"])
        self.assertIn("sudo", result["message"])
        self.assertEqual(result["command"], ["sudo", "apt-get", "install", "-y", "radare2"])

    def test_install_external_tool_reports_manual_only_when_unsupported(self):
        environment = {
            "os": "windows",
            "os_label": "Windows",
            "package_managers": ["winget"],
            "primary_package_manager": "winget",
            "primary_package_manager_label": "WinGet",
        }
        with mock.patch("advanced.tooling.shutil.which", return_value=None):
            result = tooling.install_external_tool("ida", dry_run=True, environment=environment)

        self.assertFalse(result["ok"])
        self.assertTrue(result["manual_only"])
        self.assertIn("manual", result["message"].lower())


if __name__ == "__main__":
    unittest.main()
