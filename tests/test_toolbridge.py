import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from advanced.toolbridge import (
    build_tool_plugin,
    default_tool_plugin_path,
    export_tool_plugin,
    list_tool_plugin_formats,
)


def _fake_report():
    return {
        "file": "/tmp/demo/hello_c.elf",
        "mode": "general",
        "version": "0.9.0",
        "scan_result": {
            "source_language": "C",
            "compiler": "GCC",
            "build_system": "CMake",
            "artifact_profile": {
                "artifact_type": "Linux User-space Executable",
                "confidence": 92,
            },
            "binary_map": {
                "entry_point": 0x401000,
                "sections": [
                    {
                        "name": ".text",
                        "offset": 0x1000,
                        "size": 0x80,
                        "address": 0x401000,
                        "type": "SHT_PROGBITS",
                    },
                    {
                        "name": ".data",
                        "offset": 0x2000,
                        "size": 0x20,
                        "address": 0x402000,
                        "type": "SHT_PROGBITS",
                    },
                ],
                "symbols": [
                    {"name": "main", "value": 0x401020},
                    {"name": "helper", "value": 0x401060},
                ],
            },
            "re_annotations_merged": {
                "symbols": [{"name": "user_entry", "value": 0x401000}],
                "comments": [{"address": 0x401020, "text": "main entry"}],
            },
        },
    }


class ToolbridgeTests(unittest.TestCase):
    def test_lists_expected_tool_plugin_formats(self):
        formats = list_tool_plugin_formats()
        self.assertIn("binaryninja", formats)
        self.assertIn("ghidra", formats)
        self.assertIn("ida-python", formats)
        self.assertIn("radare2", formats)
        self.assertIn("cutter", formats)
        self.assertIn("imhex", formats)

    def test_build_binaryninja_script_contains_symbols_and_comments(self):
        text = build_tool_plugin(_fake_report(), "binaryninja")
        self.assertIn("Binary Ninja integration script", text)
        self.assertIn("user_entry", text)
        self.assertIn("main entry", text)

    def test_build_ghidra_script_contains_labels_and_comments(self):
        text = build_tool_plugin(_fake_report(), "ghidra")
        self.assertIn("Ghidra import script", text)
        self.assertIn("createLabel", text)
        self.assertIn("setEOLComment", text)

    def test_build_ida_python_script_contains_ida_calls(self):
        text = build_tool_plugin(_fake_report(), "ida-python")
        self.assertIn("IDAPython import script", text)
        self.assertIn("ida_name.set_name", text)
        self.assertIn("ida_bytes.set_cmt", text)

    def test_build_radare2_script_contains_flagspace_and_comments(self):
        text = build_tool_plugin(_fake_report(), "radare2")
        self.assertIn("fs elfexplorer", text)
        self.assertIn("f elfexplorer.user_entry", text)
        self.assertIn("CC main entry", text)

    def test_build_cutter_script_reuses_rizin_format(self):
        text = build_tool_plugin(_fake_report(), "cutter")
        self.assertIn("Cutter/Rizin", text)
        self.assertIn("f elfexplorer.user_entry", text)

    def test_build_imhex_map_contains_sections_and_symbols(self):
        text = build_tool_plugin(_fake_report(), "imhex")
        self.assertIn("kind,name,file_offset,size,virtual_address,type", text)
        self.assertIn("section,.text,0x1000,0x80,0x401000,SHT_PROGBITS", text)
        self.assertIn("symbol,user_entry,,0x0,0x401000,symbol", text)

    def test_default_tool_plugin_path_uses_reports_dir_and_extension(self):
        report = _fake_report()
        path = default_tool_plugin_path(report, "ghidra")
        self.assertEqual(path.name, "hello_c-ghidra.py")
        self.assertEqual(path.parent.name, "reports")

    def test_export_tool_plugin_writes_file(self):
        report = _fake_report()
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir) / "hello-imhex.csv"
            exported = export_tool_plugin(report, out_path, "imhex")
            self.assertTrue(exported.exists())
            self.assertIn(".text", exported.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
