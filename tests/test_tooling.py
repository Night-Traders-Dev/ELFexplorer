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

    def test_describe_external_tool_includes_download_and_methods(self):
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
            detail = tooling.describe_external_tool("radare2", environment=environment)

        self.assertEqual(detail["status"]["label"], "radare2")
        self.assertTrue(detail["download_url"].startswith("https://"))
        self.assertTrue(detail["homepage"].startswith("https://"))
        self.assertTrue(detail["install_methods"])
        self.assertEqual(detail["install_methods"][0]["manager"], "brew")
        self.assertIn("apt-get", " ".join(detail["host_install_command"]))

    def test_download_external_tool_dry_run_returns_url_and_path(self):
        environment = {
            "os": "linux",
            "os_label": "Linux",
            "arch": "x86_64",
            "package_managers": [],
            "primary_package_manager": None,
            "primary_package_manager_label": "None detected",
        }
        spec = {
            "filename": "ghidra.zip",
            "url": "https://example.invalid/ghidra.zip",
            "install_mode": "zip-extract",
        }
        with mock.patch("advanced.tooling._resolve_download_spec", return_value=spec), mock.patch(
            "advanced.tooling.shutil.which",
            return_value=None,
        ):
            result = tooling.download_external_tool("ghidra", dry_run=True, environment=environment)

        self.assertTrue(result["ok"])
        self.assertEqual(result["download_url"], "https://example.invalid/ghidra.zip")
        self.assertIn("ghidra.zip", result["download_path"])

    def test_download_external_tool_dry_run_emits_progress_events(self):
        environment = {
            "os": "linux",
            "os_label": "Linux",
            "arch": "x86_64",
            "package_managers": [],
            "primary_package_manager": None,
            "primary_package_manager_label": "None detected",
        }
        spec = {
            "filename": "ghidra.zip",
            "url": "https://example.invalid/ghidra.zip",
            "install_mode": "zip-extract",
        }
        events = []
        with mock.patch("advanced.tooling._resolve_download_spec", return_value=spec), mock.patch(
            "advanced.tooling.shutil.which",
            return_value=None,
        ):
            tooling.download_external_tool(
                "ghidra",
                dry_run=True,
                environment=environment,
                event_cb=events.append,
            )

        self.assertGreaterEqual(len(events), 2)
        self.assertEqual(events[-1]["kind"], "progress")
        self.assertEqual(events[-1]["progress"], 100.0)
        self.assertIn("download into", events[-1]["message"])

    def test_install_external_tool_prefers_portable_on_rootless_when_supported(self):
        environment = {
            "os": "linux",
            "os_label": "Linux",
            "arch": "x86_64",
            "package_managers": ["pacman"],
            "primary_package_manager": "pacman",
            "primary_package_manager_label": "pacman",
        }
        portable_result = {
            "ok": True,
            "changed": False,
            "message": "Dry run portable install",
            "status": {"label": "Ghidra"},
            "portable": True,
        }

        def fake_which(name):
            if name == "sudo":
                return "/usr/bin/sudo"
            return None

        with mock.patch("advanced.tooling.shutil.which", side_effect=fake_which), mock.patch(
            "advanced.tooling.os.geteuid",
            return_value=1000,
        ), mock.patch(
            "advanced.tooling._find_tool_path",
            return_value=None,
        ), mock.patch(
            "advanced.tooling._install_portable_tool",
            return_value=portable_result,
        ) as portable_install:
            result = tooling.install_external_tool("ghidra", dry_run=True, environment=environment)

        self.assertTrue(result["ok"])
        self.assertTrue(result["portable"])
        portable_install.assert_called_once()

    def test_install_external_tool_dry_run_emits_progress_events(self):
        environment = {
            "os": "linux",
            "os_label": "Linux",
            "package_managers": ["apt"],
            "primary_package_manager": "apt",
            "primary_package_manager_label": "APT",
        }
        events = []

        def fake_which(name):
            if name == "sudo":
                return "/usr/bin/sudo"
            return None

        with mock.patch("advanced.tooling.shutil.which", side_effect=fake_which), mock.patch(
            "advanced.tooling.os.geteuid",
            return_value=1000,
        ):
            result = tooling.install_external_tool(
                "radare2",
                dry_run=True,
                environment=environment,
                event_cb=events.append,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(events[-1]["kind"], "progress")
        self.assertEqual(events[-1]["progress"], 100.0)
        self.assertIn("apt-get install", events[-1]["message"])

    def test_collect_external_tool_status_handles_probe_failures(self):
        environment = {
            "os": "linux",
            "os_label": "Linux",
            "arch": "x86_64",
            "package_managers": ["apt"],
            "primary_package_manager": "apt",
            "primary_package_manager_label": "APT",
        }

        def fake_status(tool_key, environment=None):
            meta = tooling.THIRD_PARTY_TOOLS[tool_key]
            if tool_key == "ghidra":
                raise RuntimeError("probe boom")
            return {
                "key": tool_key,
                "label": meta["label"],
                "installed": False,
                "path": None,
                "detected_via": None,
                "version": None,
                "install_supported": False,
                "install_manager": None,
                "install_manager_label": None,
                "install_command": None,
                "manual_install": meta.get("manual_install"),
                "homepage": meta.get("homepage"),
                "download_url": meta.get("download_url"),
                "download_supported": False,
                "portable_install_supported": False,
                "local_tool_root": "/tmp/tools",
                "local_bin_root": "/tmp/bin",
            }

        with mock.patch("advanced.tooling.get_external_tool_status", side_effect=fake_status):
            snapshot = tooling.collect_external_tool_status(environment=environment)

        self.assertEqual(len(snapshot["tools"]), len(tooling.THIRD_PARTY_TOOLS))
        ghidra = next(item for item in snapshot["tools"] if item["key"] == "ghidra")
        self.assertIn("Status probe failed", ghidra["manual_install"])

    def test_get_external_tool_workbench_model_exposes_presets(self):
        environment = {
            "os": "linux",
            "os_label": "Linux",
            "arch": "x86_64",
            "package_managers": [],
            "primary_package_manager": None,
            "primary_package_manager_label": "None detected",
        }
        with mock.patch("advanced.tooling.shutil.which", return_value=None):
            model = tooling.get_external_tool_workbench_model(
                "radare2",
                target_path="/tmp/sample.elf",
                environment=environment,
            )

        self.assertEqual(model["tool_key"], "radare2")
        self.assertTrue(model["cli_friendly"])
        self.assertTrue(model["presets"])
        self.assertEqual(model["target_path"], "/tmp/sample.elf")

    def test_run_external_tool_command_dry_run_substitutes_target_path(self):
        environment = {
            "os": "linux",
            "os_label": "Linux",
            "arch": "x86_64",
            "package_managers": [],
            "primary_package_manager": None,
            "primary_package_manager_label": "None detected",
        }
        status = {
            "key": "radare2",
            "label": "radare2",
            "installed": True,
            "path": "/usr/bin/r2",
            "version": "5.9.0",
        }
        events = []
        with mock.patch("advanced.tooling.get_external_tool_status", return_value=status):
            result = tooling.run_external_tool_command(
                "radare2",
                args=["-A", "-q", "-c", "iI", "{file}"],
                target_path="/tmp/hello.elf",
                dry_run=True,
                environment=environment,
                event_cb=events.append,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["command"][-1], "/tmp/hello.elf")
        self.assertEqual(events[-1]["progress"], 100.0)

    def test_launch_external_tool_dry_run_uses_default_launch_args(self):
        environment = {
            "os": "linux",
            "os_label": "Linux",
            "arch": "x86_64",
            "package_managers": [],
            "primary_package_manager": None,
            "primary_package_manager_label": "None detected",
        }
        status = {
            "key": "imhex",
            "label": "ImHex",
            "installed": True,
            "path": "/usr/bin/imhex",
            "version": "1.0",
        }
        with mock.patch("advanced.tooling.get_external_tool_status", return_value=status):
            result = tooling.launch_external_tool(
                "imhex",
                target_path="/tmp/fw.bin",
                dry_run=True,
                environment=environment,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["command"], ["/usr/bin/imhex", "/tmp/fw.bin"])


if __name__ == "__main__":
    unittest.main()
