from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Tuple

from advanced.toolbridge import (
    default_tool_plugin_path,
    export_tool_plugin,
    list_tool_plugin_formats,
)
from advanced.tooling import (
    collect_external_tool_status,
    install_external_tool,
    list_external_tools,
    render_external_tool_status_lines,
)
from edit import ElfBinaryEditor, ElfEditError
from reporting.export import export_report_markdown, export_report_pdf
from scancli.scan import build_scan_report
from settings import load_theme_preference, save_theme_preference


def _summary_lines(report: Dict) -> str:
    scan = report["scan_result"]
    artifact = scan["artifact_profile"]
    lines = [
        f"File: {report['file']}",
        f"Mode: {report['mode']}",
        f"Version: {report['version']}",
        "",
        f"Source Language: {scan['source_language']}",
        f"Compiler: {scan['compiler']}",
        f"Build System: {scan['build_system']}",
        "",
        f"Artifact Type: {artifact.get('artifact_type', 'Unknown')}",
        f"Confidence: {artifact.get('confidence', 0)}",
        f"Confidence Raw: {artifact.get('confidence_raw', artifact.get('confidence', 0))}",
        f"Confidence Calibrated: {artifact.get('confidence_calibrated', artifact.get('confidence', 0))}",
        f"Target: {artifact.get('target', 'Unknown')}",
        f"SDK/Framework: {artifact.get('sdk', 'Unknown')}",
        f"RTOS: {artifact.get('rtos', 'None detected')}",
        f"Runtime: {artifact.get('runtime', 'Unknown')}",
        f"Linkage: {artifact.get('linkage_model', 'Unknown')}",
    ]
    return "\n".join(lines)


def _score_rows(scores: Dict[str, int]) -> Iterable[Tuple[str, str]]:
    ordered = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    for label, value in ordered:
        yield label, str(value)


def _integration_rows(report: Dict) -> Iterable[Tuple[str, str, str, str]]:
    for key, meta in sorted(list_tool_plugin_formats().items()):
        yield (
            key,
            meta.get("label", key),
            meta.get("description", ""),
            str(default_tool_plugin_path(report, key)),
        )


def default_report_export_path(
    report: Dict,
    extension: str,
    output_dir: Path | None = None,
    now_utc: datetime | None = None,
) -> Path:
    if not extension.startswith("."):
        extension = f".{extension}"
    timestamp = (now_utc or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    source = Path(report.get("file", "scan"))
    stem = source.stem or "scan"
    mode = str(report.get("mode", "general")).lower()
    safe_stem = "".join(ch if (ch.isalnum() or ch in {"-", "_"}) else "_" for ch in stem)
    target_dir = output_dir or (Path.cwd() / "reports")
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir / f"{safe_stem}-{mode}-{timestamp}{extension}"


def open_report_editor(report: Dict):
    file_value = report.get("file")
    if not file_value:
        raise ValueError("Current report has no source file path.")
    path = Path(str(file_value)).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Binary not found: {path}")
    return ElfBinaryEditor(path)


def run_textual_report(report: Dict):
    from textual.app import App, ComposeResult, SystemCommand
    from textual.containers import Container, VerticalScroll
    from textual.screen import Screen
    from textual.widgets import DataTable, Footer, Header, Static, TabbedContent, TabPane

    class ReportApp(App):
        CSS = """
        #summary {
            height: auto;
            padding: 1 2;
            border: round $primary;
        }
        DataTable {
            height: 1fr;
        }
        #metadata_scroll {
            height: 1fr;
            border: round $secondary;
        }
        #metadata {
            padding: 1 2;
        }
        #evidence_scroll {
            height: 1fr;
            border: round $accent;
        }
        #evidence {
            padding: 1 2;
        }
        #integrations_note {
            height: auto;
            padding: 1 2;
            border: round $primary;
        }
        #tooling_status {
            height: auto;
            padding: 1 2;
            border: round $secondary;
        }
        """

        BINDINGS = [
            ("q", "quit", "Quit"),
            ("r", "rescan_current_mode", "Rescan"),
            ("e", "open_editor_workbench", "Editor"),
            ("1", "set_mode_general", "Mode: General"),
            ("2", "set_mode_important", "Mode: Important"),
            ("3", "set_mode_detailed", "Mode: Detailed"),
        ]

        def __init__(self, initial_report: Dict):
            super().__init__()
            self.report = dict(initial_report)

        def _apply_saved_theme(self):
            saved_theme = load_theme_preference()
            if saved_theme in self.available_themes and self.theme != saved_theme:
                self.theme = saved_theme

        def watch_theme(self, theme: str):
            try:
                save_theme_preference(theme)
            except OSError:
                pass

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Container():
                with TabbedContent():
                    with TabPane("Summary"):
                        yield Static("", id="summary")
                    with TabPane("Scores"):
                        yield DataTable(id="artifact_scores")
                        yield DataTable(id="language_scores")
                        yield DataTable(id="compiler_scores")
                        yield DataTable(id="build_scores")
                    with TabPane("Metadata"):
                        with VerticalScroll(id="metadata_scroll"):
                            yield Static("", id="metadata")
                    with TabPane("Evidence"):
                        with VerticalScroll(id="evidence_scroll"):
                            yield Static("", id="evidence")
                    with TabPane("Integrations"):
                        yield Static("", id="integrations_note")
                        yield DataTable(id="integrations_table")
                        yield Static("", id="tooling_status")
            yield Footer()

        def get_system_commands(self, screen: Screen):
            yield from super().get_system_commands(screen)
            yield SystemCommand(
                "Report: Export Markdown",
                "Save current report as Markdown in ./reports/",
                self.action_export_markdown,
            )
            yield SystemCommand(
                "Report: Export PDF",
                "Save current report as PDF in ./reports/",
                self.action_export_pdf,
            )
            yield SystemCommand(
                "Tooling: Check External Tools",
                "Detect host package manager and installed reverse-engineering tools",
                self.action_check_external_tools,
            )
            for tool_key, meta in sorted(list_external_tools().items()):
                yield SystemCommand(
                    f"Tooling: Install {meta['label']}",
                    f"Install {meta['label']} using the detected package manager when supported",
                    lambda tool_key=tool_key: self.action_install_external_tool(tool_key),
                )
            yield SystemCommand(
                "Integrations: Export Binary Ninja Script",
                "Save Binary Ninja import script in ./reports/",
                self.action_export_tool_binaryninja,
            )
            yield SystemCommand(
                "Integrations: Export Ghidra Script",
                "Save Ghidra import script in ./reports/",
                self.action_export_tool_ghidra,
            )
            yield SystemCommand(
                "Integrations: Export IDA Python Script",
                "Save IDAPython import script in ./reports/",
                self.action_export_tool_ida_python,
            )
            yield SystemCommand(
                "Integrations: Export radare2 Script",
                "Save radare2 import script in ./reports/",
                self.action_export_tool_radare2,
            )
            yield SystemCommand(
                "Integrations: Export Cutter/Rizin Script",
                "Save Cutter/Rizin import script in ./reports/",
                self.action_export_tool_cutter,
            )
            yield SystemCommand(
                "Integrations: Export ImHex Memory Map",
                "Save ImHex section/symbol CSV in ./reports/",
                self.action_export_tool_imhex,
            )
            yield SystemCommand(
                "Report: Rescan Current Mode",
                "Rescan the current file with the same metadata mode",
                self.action_rescan_current_mode,
            )
            yield SystemCommand(
                "Report: Mode General + Rescan",
                "Switch mode to general and rescan current file",
                self.action_set_mode_general,
            )
            yield SystemCommand(
                "Report: Mode Important + Rescan",
                "Switch mode to important and rescan current file",
                self.action_set_mode_important,
            )
            yield SystemCommand(
                "Report: Mode Detailed + Rescan",
                "Switch mode to detailed and rescan current file",
                self.action_set_mode_detailed,
            )
            yield SystemCommand(
                "Report: Open Editor Workbench",
                "Open split-pane editor workbench for current binary",
                self.action_open_editor_workbench,
            )

        def _fill_table(self, table_id: str, title: str, scores: Dict[str, int]):
            table = self.query_one(f"#{table_id}", DataTable)
            table.cursor_type = "row"
            table.clear(columns=True)
            table.add_columns(title, "Score")
            for label, value in _score_rows(scores):
                table.add_row(label, value)

        def _fill_integrations_table(self):
            note = self.query_one("#integrations_note", Static)
            table = self.query_one("#integrations_table", DataTable)
            tooling_status = self.query_one("#tooling_status", Static)
            table.cursor_type = "row"
            table.clear(columns=True)
            table.add_columns("Format", "Label", "Description", "Default Export Path")
            for row in _integration_rows(self.report):
                table.add_row(*row)
            note.update(
                "External-tool exports are generated from the current report's symbols, sections, and "
                "comments. Use the command palette to export scripts for disassemblers and memory-mapping tools."
            )
            snapshot = collect_external_tool_status()
            tooling_status.update("\n".join(render_external_tool_status_lines(snapshot)))

        def _refresh_view(self):
            summary = self.query_one("#summary", Static)
            metadata = self.query_one("#metadata", Static)
            evidence = self.query_one("#evidence", Static)

            summary.update(_summary_lines(self.report))
            metadata.update(self.report.get("metadata_text", ""))

            artifact = self.report["scan_result"]["artifact_profile"]
            indicators = artifact.get("indicators", [])
            evidence.update(
                "\n".join(f"- {line}" for line in indicators)
                if indicators
                else "No explicit artifact indicators collected."
            )

            scan = self.report["scan_result"]
            self._fill_table("artifact_scores", "Artifact", scan["artifact_profile"].get("scores", {}))
            self._fill_table("language_scores", "Language", scan["language_scores"])
            self._fill_table("compiler_scores", "Compiler", scan["compiler_scores"])
            self._fill_table("build_scores", "Build System", scan["build_scores"])
            self._fill_integrations_table()

            evidence_lines = []
            for line in indicators:
                evidence_lines.append(f"- {line}")

            hardening = scan.get("hardening_profile", {})
            if hardening:
                evidence_lines.extend(
                    [
                        "",
                        "Hardening Profile:",
                        f"- risk_level: {hardening.get('risk_level', 'unknown')}",
                        f"- stripped: {hardening.get('stripped', False)}",
                        f"- likely_packed: {hardening.get('likely_packed', False)}",
                        f"- likely_obfuscated: {hardening.get('likely_obfuscated', False)}",
                        f"- text_entropy: {hardening.get('text_entropy', 0.0)}",
                    ]
                )
                for signal in hardening.get("signals", []):
                    evidence_lines.append(f"  - signal: {signal}")

            mixed = scan.get("mixed_attribution", {})
            if mixed:
                evidence_lines.extend(
                    [
                        "",
                        "Mixed Attribution:",
                        f"- dominant_symbol_language: {mixed.get('symbol_dominant_language', 'Unknown')}",
                        f"- dominant_symbol_score: {mixed.get('symbol_dominant_score', 0)}",
                    ]
                )
                for hint in mixed.get("section_hints", [])[:10]:
                    evidence_lines.append(
                        "  - section="
                        f"{hint.get('section')} "
                        f"lang={hint.get('language_hint')}({hint.get('language_score')}) "
                        f"compiler={hint.get('compiler_hint')}({hint.get('compiler_score')})"
                    )

            firmware = scan.get("firmware_fingerprint", {})
            if firmware:
                evidence_lines.extend(
                    [
                        "",
                        "Firmware Fingerprint:",
                        f"- is_firmware_candidate: {firmware.get('is_firmware_candidate', False)}",
                        f"- firmware_confidence: {firmware.get('firmware_confidence', 0)}",
                        f"- likely_mcu: {firmware.get('likely_mcu', 'Unknown')}",
                        f"- likely_vendor: {firmware.get('likely_vendor', 'Unknown')}",
                        f"- sdk_candidates: {', '.join(firmware.get('sdk_candidates', [])) or 'None'}",
                        f"- rtos_candidates: {', '.join(firmware.get('rtos_candidates', [])) or 'None'}",
                    ]
                )
                sdk_versions = firmware.get("sdk_versions", {})
                for sdk_name, versions in sorted(sdk_versions.items()):
                    evidence_lines.append(f"  - sdk_version[{sdk_name}]: {', '.join(versions)}")
                for hint in firmware.get("linker_hints", []):
                    evidence_lines.append(f"  - linker_hint: {hint}")
                vector_profile = firmware.get("vector_table_profile", {})
                if vector_profile:
                    evidence_lines.append(
                        "  - vector_table: "
                        f"present={vector_profile.get('looks_like_vector_table', False)} "
                        f"section={vector_profile.get('section', 'None')} "
                        f"initial_sp={vector_profile.get('initial_sp', 'None')} "
                        f"reset_handler={vector_profile.get('reset_handler', 'None')}"
                    )
                for signal in firmware.get("signals", []):
                    evidence_lines.append(f"  - signal: {signal}")

            explanations = scan.get("explanations", {})
            if explanations:
                evidence_lines.append("")
                evidence_lines.append("Explainability:")
                for key in ("language", "compiler", "build_system", "artifact"):
                    data = explanations.get(key, {})
                    evidence_lines.append(
                        f"- {key}: predicted={data.get('predicted', 'Unknown')} "
                        f"margin={data.get('score_margin', 0)} "
                        f"note={data.get('confidence_note', 'n/a')}"
                    )

            plugin_evidence = scan.get("plugin_evidence", {})
            if plugin_evidence:
                evidence_lines.append("")
                evidence_lines.append("Plugin/Signature Evidence:")
                pack_names = plugin_evidence.get("pack_names", [])
                if pack_names:
                    evidence_lines.append(f"- active_packs: {', '.join(pack_names)}")
                diagnostics = plugin_evidence.get("diagnostics", [])
                for line in diagnostics:
                    evidence_lines.append(f"  - diagnostic: {line}")
                for category in ("languages", "compilers", "build_systems", "artifacts"):
                    hits = plugin_evidence.get(category, [])
                    for hit in hits:
                        evidence_lines.append(
                            f"  - {category}: rule={hit.get('rule')} target={hit.get('target')} "
                            f"delta={hit.get('score_delta')} "
                            f"priority={hit.get('priority', 0)} op={hit.get('operation', 'add')}"
                        )

            re_import = scan.get("re_annotations_imported")
            if re_import:
                evidence_lines.extend(
                    [
                        "",
                        "Imported RE annotations:",
                        f"- source: {re_import.get('source', 'unknown')}",
                        f"- functions: {len(re_import.get('functions', []))}",
                        f"- comments: {len(re_import.get('comments', []))}",
                        f"- labels: {len(re_import.get('labels', []))}",
                        f"- xrefs: {len(re_import.get('xrefs', []))}",
                    ]
                )

            re_merged = scan.get("re_annotations_merged")
            if re_merged:
                evidence_lines.extend(
                    [
                        "",
                        "Merged RE view:",
                        f"- merge_policy: {re_merged.get('policy', 'union')}",
                        f"- source: {re_merged.get('source', 'unknown')}",
                        f"- merged_symbol_count: {re_merged.get('merged_symbol_count', 0)}",
                        f"- imported_comment_count: {re_merged.get('imported_comment_count', 0)}",
                    ]
                )

            evidence.update(
                "\n".join(evidence_lines) if evidence_lines else "No explicit evidence captured."
            )

        def _rescan(self, mode: str | None = None):
            file_path = self.report.get("file")
            if not file_path:
                self.notify("No source file recorded in current report.", title="Rescan", severity="error")
                return

            selected_mode = mode or self.report.get("mode", "general")
            try:
                self.report = build_scan_report(file_path, mode=selected_mode)
                self._refresh_view()
                self.notify(
                    f"Rescanned {Path(file_path).name} using mode '{selected_mode}'.",
                    title="Rescan",
                    severity="information",
                )
            except Exception as exc:
                self.notify(f"Rescan failed: {exc}", title="Rescan", severity="error")

        def _export_markdown(self):
            try:
                target = default_report_export_path(self.report, ".md")
                exported = export_report_markdown(self.report, target)
                self.notify(f"Saved Markdown: {exported}", title="Export", severity="information")
            except Exception as exc:
                self.notify(f"Markdown export failed: {exc}", title="Export", severity="error")

        def _export_pdf(self):
            try:
                target = default_report_export_path(self.report, ".pdf")
                exported = export_report_pdf(self.report, target)
                self.notify(f"Saved PDF: {exported}", title="Export", severity="information")
            except Exception as exc:
                self.notify(f"PDF export failed: {exc}", title="Export", severity="error")

        def _export_tool_plugin(self, tool_format: str):
            try:
                target = default_tool_plugin_path(self.report, tool_format)
                exported = export_tool_plugin(self.report, target, tool_format)
                self.notify(
                    f"Saved {tool_format} integration: {exported}",
                    title="Integrations",
                    severity="information",
                )
            except Exception as exc:
                self.notify(
                    f"{tool_format} export failed: {exc}",
                    title="Integrations",
                    severity="error",
                )

        def _install_external_tool(self, tool_key: str):
            result = install_external_tool(tool_key)
            self._refresh_view()
            if result.get("ok"):
                self.notify(result["message"], title="Tooling", severity="information")
            else:
                command = result.get("command")
                if command:
                    self.notify(
                        f"{result['message']} Command: {' '.join(command)}",
                        title="Tooling",
                        severity="warning",
                    )
                else:
                    self.notify(result["message"], title="Tooling", severity="warning")

        def action_check_external_tools(self):
            self._refresh_view()
            self.notify("External tool status refreshed.", title="Tooling", severity="information")

        def action_export_markdown(self):
            self._export_markdown()

        def action_export_pdf(self):
            self._export_pdf()

        def action_export_tool_binaryninja(self):
            self._export_tool_plugin("binaryninja")

        def action_export_tool_ghidra(self):
            self._export_tool_plugin("ghidra")

        def action_export_tool_ida_python(self):
            self._export_tool_plugin("ida-python")

        def action_export_tool_radare2(self):
            self._export_tool_plugin("radare2")

        def action_export_tool_cutter(self):
            self._export_tool_plugin("cutter")

        def action_export_tool_imhex(self):
            self._export_tool_plugin("imhex")

        def action_install_external_tool(self, tool_key: str):
            self._install_external_tool(tool_key)

        def action_rescan_current_mode(self):
            self._rescan(mode=self.report.get("mode", "general"))

        def action_set_mode_general(self):
            self._rescan(mode="general")

        def action_set_mode_important(self):
            self._rescan(mode="important")

        def action_set_mode_detailed(self):
            self._rescan(mode="detailed")

        def action_open_editor_workbench(self):
            try:
                editor = open_report_editor(self.report)
                from ui.textual_editor import EditorWorkbenchScreen

                self.push_screen(EditorWorkbenchScreen.build(editor))
            except (ValueError, FileNotFoundError, ElfEditError) as exc:
                self.notify(
                    f"Editor unavailable for this file: {exc}",
                    title="Editor",
                    severity="error",
                )

        def on_mount(self) -> None:
            self._apply_saved_theme()
            self._refresh_view()

    ReportApp(report).run()
