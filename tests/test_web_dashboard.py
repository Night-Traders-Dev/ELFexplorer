import unittest
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import threading
import urllib.request
import time

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ui.web_dashboard import DashboardRuntime, build_dashboard_html, create_dashboard_server


def _sample_report(path="/tmp/hello_c"):
    return {
        "file": path,
        "mode": "general",
        "version": "0.0.0",
        "metadata_text": "ELF metadata",
        "scan_result": {
            "source_language": "C",
            "compiler": "GCC",
            "build_system": "CMake",
            "language_scores": {"C": 10},
            "compiler_scores": {"GCC": 9},
            "build_scores": {"CMake": 8},
            "artifact_profile": {
                "artifact_type": "Linux User-space Executable",
                "confidence": 91,
                "scores": {"Linux User-space Executable": 91},
                "indicators": ["has PT_INTERP"],
            },
            "hardening_profile": {"signals": ["stripped=False"]},
            "firmware_fingerprint": {"signals": []},
            "plugin_evidence": {"diagnostics": []},
        },
    }


class WebDashboardTests(unittest.TestCase):
    def test_dashboard_runtime_state_includes_reports_and_saved_paths(self):
        runtime = DashboardRuntime(
            callbacks={"list_saved": lambda: [Path("/tmp/report-one.json"), Path("/tmp/report-two.json")]},
            initial_reports=[_sample_report()],
        )

        state = runtime.state()

        self.assertEqual(state["report_count"], 1)
        self.assertEqual(state["selected_index"], 0)
        self.assertEqual(state["summaries"][0]["language"], "C")
        self.assertEqual(state["saved_reports"][0], "/tmp/report-one.json")
        self.assertTrue(state["capabilities"]["list_saved"])

    def test_dashboard_runtime_scan_replaces_reports(self):
        runtime = DashboardRuntime(
            callbacks={"scan": lambda path, mode: _sample_report(path=path)},
            initial_reports=[],
        )

        state = runtime.scan("/tmp/new.elf", "important")

        self.assertEqual(state["report_count"], 1)
        self.assertEqual(state["reports"][0]["file"], "/tmp/new.elf")
        self.assertIn("Scanned /tmp/new.elf", state["message"])

    def test_dashboard_html_contains_bootstrap_and_controls(self):
        runtime = DashboardRuntime(initial_reports=[_sample_report()])
        html = build_dashboard_html(runtime.state())

        self.assertIn("ELFexplorer Web Dashboard", html)
        self.assertIn("id=\"initial-state\"", html)
        self.assertIn("Scan File", html)
        self.assertIn("Crawl Directory", html)
        self.assertIn("Load Saved JSON", html)
        self.assertIn("Compare / Diff", html)
        self.assertIn("Tool Runner", html)
        self.assertIn("Integrations", html)
        self.assertIn("Save Report JSON", html)

    @unittest.skipUnless(shutil.which("node"), "node is required to syntax-check generated dashboard JavaScript")
    def test_dashboard_html_embedded_script_parses_in_node(self):
        runtime = DashboardRuntime(initial_reports=[_sample_report()])
        html = build_dashboard_html(runtime.state())
        script = html.split('<script id="initial-state" type="application/json">', 1)[1]
        script = script.split("</script>", 1)[1].split("<script>", 1)[1].split("</script>", 1)[0]

        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
            handle.write(script)
            temp_path = handle.name
        try:
            subprocess.run(["node", "--check", temp_path], check=True, capture_output=True, text=True)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_dashboard_server_scan_and_export_routes(self):
        callbacks = {
            "scan": lambda path, mode: _sample_report(path=path),
            "export_report_md": lambda report, path: Path(path),
            "save_scan": lambda report, path=None: Path(path or "/tmp/web-scan.json"),
            "save_collection": lambda reports, path=None: Path(path or "/tmp/web-collection.json"),
            "export_collection_md": lambda payload, path: Path(path),
            "list_tool_plugins": lambda: {"ghidra": {"label": "Ghidra", "extension": ".py"}},
            "default_tool_plugin_path": lambda report, fmt: Path(f"/tmp/{fmt}-export.txt"),
            "export_tool_plugin": lambda report, path, fmt: Path(path),
            "tooling_snapshot": lambda: {
                "environment": {"os_label": "Linux"},
                "tools": [{"key": "radare2", "label": "radare2", "installed": True, "path": "/usr/bin/radare2"}],
            },
            "tooling_detail": lambda tool_key: {"key": tool_key, "installed": True, "path": "/usr/bin/radare2"},
            "tool_recommendations": lambda report: {
                "target_path": report["file"],
                "container_kind": "elf",
                "artifact_type": "Linux User-space Executable",
                "tools": [
                    {
                        "tool_key": "radare2",
                        "target_path": report["file"],
                        "status": {
                            "label": "radare2",
                            "installed": True,
                            "path": "/usr/bin/radare2",
                        },
                        "recommended": True,
                        "priority": 95,
                        "reason": "Best quick CLI fit.",
                        "default_action": "run",
                        "default_preset_key": "functions",
                        "default_args": ["-A", "-q", "-c", "afl", "{file}"],
                        "cli_friendly": True,
                        "launch_args": ["{file}"],
                        "presets": [
                            {
                                "key": "functions",
                                "label": "Functions",
                                "args": ["-A", "-q", "-c", "afl", "{file}"],
                            }
                        ],
                    }
                ],
            },
            "tool_execute": lambda report, tool_key, action="run", preset_key=None, args=None, dry_run=False: {
                "ok": True,
                "message": f"{tool_key}:{action}:{'dry' if dry_run else 'live'}",
                "command": ["/usr/bin/radare2", "-A", report["file"]],
                "output": "afl output",
                "returncode": 0,
            },
            "tool_resolve": lambda report, tool_key, action="run", preset_key=None, args=None: {
                "ok": True,
                "message": "resolved",
                "tool_key": tool_key,
                "action": action,
                "status": {"label": tool_key, "installed": True, "path": sys.executable},
                "command": [sys.executable, "-u", "-c", "print('tool route smoke', flush=True)"],
            },
            "list_saved": lambda: [],
        }
        server, url, _runtime = create_dashboard_server(callbacks=callbacks, initial_reports=[], port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            scan_request = urllib.request.Request(
                f"{url}/api/scan",
                data=json.dumps({"path": "/tmp/from-web.elf", "mode": "general"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            scan_state = json.load(urllib.request.urlopen(scan_request))
            self.assertEqual(scan_state["report_count"], 1)
            self.assertEqual(scan_state["reports"][0]["file"], "/tmp/from-web.elf")

            export_request = urllib.request.Request(
                f"{url}/api/export/report",
                data=json.dumps({"index": 0, "format": "markdown"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            export_response = json.load(urllib.request.urlopen(export_request))
            self.assertTrue(export_response["ok"])
            self.assertTrue(export_response["path"].endswith(".md"))

            save_request = urllib.request.Request(
                f"{url}/api/save/report",
                data=json.dumps({"index": 0}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            save_response = json.load(urllib.request.urlopen(save_request))
            self.assertTrue(save_response["ok"])
            self.assertTrue(save_response["path"].endswith(".json"))

            plugin_request = urllib.request.Request(
                f"{url}/api/tool-plugin/export",
                data=json.dumps({"index": 0, "format": "ghidra"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            plugin_response = json.load(urllib.request.urlopen(plugin_request))
            self.assertTrue(plugin_response["ok"])
            self.assertIn("ghidra-export", plugin_response["path"])

            diff_request = urllib.request.Request(
                f"{url}/api/diff",
                data=json.dumps({"index": 0, "path": "/tmp/right.elf", "mode": "general"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            diff_response = json.load(urllib.request.urlopen(diff_request))
            self.assertTrue(diff_response["ok"])
            self.assertEqual(diff_response["diff"]["right_file"], "/tmp/right.elf")

            tooling_snapshot = json.load(urllib.request.urlopen(f"{url}/api/tooling/status"))
            self.assertEqual(tooling_snapshot["tools"][0]["key"], "radare2")

            tooling_detail = json.load(urllib.request.urlopen(f"{url}/api/tooling/radare2/detail"))
            self.assertEqual(tooling_detail["key"], "radare2")

            recommendation_request = urllib.request.Request(
                f"{url}/api/tooling/recommendations",
                data=json.dumps({"index": 0}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            recommendation_response = json.load(urllib.request.urlopen(recommendation_request))
            self.assertEqual(recommendation_response["tools"][0]["tool_key"], "radare2")

            execute_request = urllib.request.Request(
                f"{url}/api/tooling/execute",
                data=json.dumps(
                    {
                        "index": 0,
                        "tool_key": "radare2",
                        "action": "run",
                        "preset_key": "functions",
                        "args": "-A -q -c afl {file}",
                        "dry_run": True,
                    }
                ).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            execute_response = json.load(urllib.request.urlopen(execute_request))
            self.assertTrue(execute_response["ok"])
            self.assertEqual(execute_response["message"], "radare2:run:dry")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_dashboard_server_tool_task_streams_output_and_retains_history(self):
        callbacks = {
            "tool_recommendations": lambda report: {
                "target_path": report["file"],
                "container_kind": "elf",
                "artifact_type": "Linux User-space Executable",
                "tools": [],
            },
            "tool_execute": lambda report, tool_key, action="run", preset_key=None, args=None, dry_run=False: {
                "ok": True,
                "message": "dry preview",
                "command": [sys.executable, "-u", "-c", "print('preview', flush=True)"],
            },
            "tool_resolve": lambda report, tool_key, action="run", preset_key=None, args=None: {
                "ok": True,
                "message": "resolved",
                "tool_key": tool_key,
                "action": action,
                "status": {"label": "python-tool", "installed": True, "path": sys.executable},
                "command": [
                    sys.executable,
                    "-u",
                    "-c",
                    "import time; print('stream-start', flush=True); time.sleep(0.15); print('stream-end', flush=True)",
                ],
            },
        }
        runtime = DashboardRuntime(callbacks=callbacks, initial_reports=[_sample_report()])
        server, url, _runtime = create_dashboard_server(callbacks=callbacks, initial_reports=[_sample_report()], port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            start_request = urllib.request.Request(
                f"{url}/api/tooling/task/start",
                data=json.dumps({"index": 0, "tool_key": "bramble", "action": "run"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            start_response = json.load(urllib.request.urlopen(start_request))
            task_id = start_response["id"]
            deadline = time.time() + 5.0
            while time.time() < deadline:
                task_state = json.load(urllib.request.urlopen(f"{url}/api/tooling/task/{task_id}"))
                if task_state["status"] in {"completed", "failed", "stopped"}:
                    break
                time.sleep(0.1)
            self.assertEqual(task_state["status"], "completed")
            self.assertIn("stream-start", "\n".join(task_state["log_lines"]))
            self.assertIn("stream-end", "\n".join(task_state["log_lines"]))

            history = json.load(urllib.request.urlopen(f"{url}/api/tooling/history"))
            self.assertTrue(history["tasks"])
            self.assertEqual(history["tasks"][0]["id"], task_id)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_dashboard_server_tool_task_stop_and_restart(self):
        callbacks = {
            "tool_recommendations": lambda report: {
                "target_path": report["file"],
                "container_kind": "uf2",
                "artifact_type": "Bare-metal Firmware",
                "tools": [],
            },
            "tool_execute": lambda report, tool_key, action="run", preset_key=None, args=None, dry_run=False: {
                "ok": True,
                "message": "dry preview",
                "command": [sys.executable, "-u", "-c", "print('preview', flush=True)"],
            },
            "tool_resolve": lambda report, tool_key, action="run", preset_key=None, args=None: {
                "ok": True,
                "message": "resolved",
                "tool_key": tool_key,
                "action": action,
                "status": {"label": "python-tool", "installed": True, "path": sys.executable},
                "command": [
                    sys.executable,
                    "-u",
                    "-c",
                    "import time; print('tick', flush=True); time.sleep(1.0); print('done', flush=True)",
                ],
            },
        }
        server, url, _runtime = create_dashboard_server(callbacks=callbacks, initial_reports=[_sample_report()], port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            start_request = urllib.request.Request(
                f"{url}/api/tooling/task/start",
                data=json.dumps({"index": 0, "tool_key": "bramble", "action": "run"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            start_response = json.load(urllib.request.urlopen(start_request))
            task_id = start_response["id"]
            stop_request = urllib.request.Request(
                f"{url}/api/tooling/task/{task_id}/stop",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(stop_request).read()
            deadline = time.time() + 5.0
            while time.time() < deadline:
                task_state = json.load(urllib.request.urlopen(f"{url}/api/tooling/task/{task_id}"))
                if task_state["status"] == "stopped":
                    break
                time.sleep(0.1)
            self.assertEqual(task_state["status"], "stopped")

            restart_request = urllib.request.Request(
                f"{url}/api/tooling/task/{task_id}/restart",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            restart_response = json.load(urllib.request.urlopen(restart_request))
            self.assertNotEqual(restart_response["id"], task_id)
            cleanup_request = urllib.request.Request(
                f"{url}/api/tooling/task/{restart_response['id']}/stop",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(cleanup_request).read()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
