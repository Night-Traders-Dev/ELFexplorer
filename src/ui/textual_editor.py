from edit import ElfBinaryEditor, ElfEditError


def _parse_int_literal(text, label):
    raw = str(text).strip()
    if not raw:
        raise ValueError(f"{label} is required.")
    try:
        return int(raw, 0)
    except ValueError as exc:
        raise ValueError(f"{label} must be a numeric literal (examples: 10, 0x20).") from exc


class EditorWorkbenchScreen:
    """Factory wrapper so textual import is delayed until UI launch."""

    @staticmethod
    def build(editor: ElfBinaryEditor):
        from textual.screen import Screen
        from textual.widgets import Button, Footer, Input, RichLog, Static
        from textual.containers import Horizontal, Vertical, VerticalScroll

        class _EditorWorkbenchScreen(Screen):
            CSS = """
            Screen {
                layout: vertical;
            }
            #wb_title {
                height: auto;
                padding: 0 1;
                border: round $primary;
                content-align: left middle;
            }
            #wb_main {
                height: 1fr;
            }
            #wb_hex_col, #wb_disasm_col {
                width: 1fr;
                border: round $secondary;
                margin: 0 1 0 0;
            }
            #wb_disasm_col {
                margin: 0;
            }
            .pane_title {
                height: auto;
                padding: 0 1;
                text-style: bold;
                color: $accent;
            }
            #wb_hex_output, #wb_disasm_output {
                height: 1fr;
                border-top: solid $panel;
                border-bottom: solid $panel;
            }
            #wb_hex_controls, #wb_disasm_controls {
                height: auto;
                padding: 0 1 1 1;
            }
            #wb_hex_controls Input,
            #wb_disasm_controls Input {
                width: 1fr;
                margin-right: 1;
            }
            #wb_bottom {
                height: 1fr;
                margin-top: 1;
            }
            #wb_patch_col, #wb_howto_col, #wb_tips_col {
                width: 1fr;
                border: round $secondary;
                margin: 0 1 0 0;
                padding: 0 1;
            }
            #wb_tips_col {
                margin: 0;
            }
            #wb_patch_col Input {
                margin-bottom: 1;
            }
            #wb_patch_scroll {
                height: 1fr;
            }
            #wb_patch_buttons {
                height: auto;
                margin-bottom: 1;
            }
            #wb_patch_buttons Button {
                margin-right: 1;
            }
            #wb_howto_scroll, #wb_tips_scroll {
                height: 1fr;
            }
            #wb_howto_text, #wb_tip_text {
                padding: 0 0 1 0;
            }
            """

            BINDINGS = [
                ("escape", "close_workbench", "Back"),
                ("f5", "refresh_all", "Refresh"),
                ("ctrl+s", "save_binary", "Save"),
                ("ctrl+r", "revert_changes", "Revert"),
                ("ctrl+h", "refresh_hex", "Hex Refresh"),
                ("ctrl+d", "refresh_disasm", "Disasm Refresh"),
            ]

            HOT_TIPS = {
                "wb_hex_output": "Hex pane: review the current byte stream with offset + ASCII columns.",
                "wb_disasm_output": "Disassembly pane: objdump-based assembly view of selected section/range.",
                "wb_hex_offset": "Hex offset in decimal or hex (e.g. 256 or 0x100).",
                "wb_hex_length": "Hex length controls how many bytes are shown.",
                "wb_hex_width": "Hex width is bytes per row (usually 8/16/32).",
                "wb_disasm_section": "Disassembly section (default .text). Use 'all' for full output.",
                "wb_disasm_max_lines": "Maximum number of instruction lines to render.",
                "wb_disasm_start": "Optional start address for disassembly range.",
                "wb_disasm_stop": "Optional stop address (must be greater than start).",
                "wb_patch_offset": "Patch offset where byte/hex/ascii data will be written.",
                "wb_poke_value": "Single byte to write (e.g. 0x90).",
                "wb_patch_hex_value": "Hex byte sequence: 'de ad be ef' or '0xDE 0xAD 0xBE 0xEF'.",
                "wb_patch_ascii_value": "ASCII/UTF-8 text to write at patch offset.",
                "wb_save_path": "Optional output path. Leave blank to save as <name>.modified.",
                "wb_btn_refresh_hex": "Refresh only the hex pane using current controls.",
                "wb_btn_refresh_disasm": "Refresh only disassembly pane using current controls.",
                "wb_btn_poke": "Apply single-byte write at patch offset.",
                "wb_btn_patch_hex": "Apply multi-byte hex patch at patch offset.",
                "wb_btn_patch_ascii": "Apply ASCII text patch at patch offset.",
                "wb_btn_save": "Save edited binary to output path or default .modified file.",
                "wb_btn_revert": "Discard all pending in-memory changes and restore original bytes.",
                "wb_patch_scroll": "Patch form scroll area. Scroll down for Save/Revert on smaller screens.",
            }

            HOWTO_TEXT = """
[bold]Workbench How-To[/bold]

1. Open with `edit-ui` (workspace) or press `e` in report mode.
2. Set hex controls (`offset`, `length`, `width`) and press [bold]Refresh Hex[/bold].
3. Apply changes from the patch form:
   - [bold]Poke Byte[/bold]: one byte at patch offset.
   - [bold]Patch Hex[/bold]: sequence of bytes at patch offset.
   - [bold]Patch ASCII[/bold]: text bytes at patch offset.
4. Set disassembly controls (`section`, `max_lines`, optional `start/stop`) and press [bold]Refresh Disasm[/bold].
5. Inspect result in hex/disassembly panes, then [bold]Save[/bold].
6. Use [bold]Revert[/bold] to reset all in-memory changes.

[bold]Scrolling and Navigation[/bold]
- Hex and disassembly panes are scrollable with mouse wheel or keyboard focus.
- Patch form is scrollable when the screen height is limited.
- Hover controls for tooltip guidance, and watch Hot Tips for live context.

[bold]Keyboard[/bold]
- [bold]F5[/bold]: refresh all panes
- [bold]Ctrl+H[/bold]: refresh hex
- [bold]Ctrl+D[/bold]: refresh disassembly
- [bold]Ctrl+S[/bold]: save edited binary
- [bold]Ctrl+R[/bold]: revert edits
- [bold]Esc[/bold]: return to workspace
"""

            def __init__(self):
                super().__init__()
                self.editor = editor
                self._tip_message = "Hover over controls for contextual hot tips."

            def compose(self):
                yield Static("", id="wb_title")
                with Horizontal(id="wb_main"):
                    with Vertical(id="wb_hex_col"):
                        yield Static("Hex Pane", classes="pane_title")
                        yield RichLog(
                            id="wb_hex_output",
                            wrap=False,
                            markup=False,
                            auto_scroll=False,
                            highlight=False,
                        )
                        with Horizontal(id="wb_hex_controls"):
                            yield Input(value="0x0", placeholder="offset", id="wb_hex_offset")
                            yield Input(value="0x100", placeholder="length", id="wb_hex_length")
                            yield Input(value="16", placeholder="width", id="wb_hex_width")
                            yield Button("Refresh Hex", id="wb_btn_refresh_hex", variant="primary")
                    with Vertical(id="wb_disasm_col"):
                        yield Static("Disassembly Pane", classes="pane_title")
                        yield RichLog(
                            id="wb_disasm_output",
                            wrap=False,
                            markup=False,
                            auto_scroll=False,
                            highlight=False,
                        )
                        with Horizontal(id="wb_disasm_controls"):
                            yield Input(value=".text", placeholder="section", id="wb_disasm_section")
                            yield Input(value="120", placeholder="max lines", id="wb_disasm_max_lines")
                            yield Input(value="", placeholder="start", id="wb_disasm_start")
                            yield Input(value="", placeholder="stop", id="wb_disasm_stop")
                            yield Button("Refresh Disasm", id="wb_btn_refresh_disasm", variant="primary")

                with Horizontal(id="wb_bottom"):
                    with Vertical(id="wb_patch_col"):
                        yield Static("Patch Form", classes="pane_title")
                        with VerticalScroll(id="wb_patch_scroll"):
                            yield Input(value="0x0", placeholder="patch offset", id="wb_patch_offset")
                            yield Input(value="0x90", placeholder="poke byte", id="wb_poke_value")
                            yield Button("Poke Byte", id="wb_btn_poke", variant="warning")
                            yield Input(
                                value="de ad be ef",
                                placeholder="hex patch bytes",
                                id="wb_patch_hex_value",
                            )
                            yield Button("Patch Hex", id="wb_btn_patch_hex", variant="warning")
                            yield Input(
                                value="",
                                placeholder="ascii patch text",
                                id="wb_patch_ascii_value",
                            )
                            yield Button("Patch ASCII", id="wb_btn_patch_ascii", variant="warning")
                            yield Input(value="", placeholder="save path", id="wb_save_path")
                            with Horizontal(id="wb_patch_buttons"):
                                yield Button("Save", id="wb_btn_save", variant="success")
                                yield Button("Revert", id="wb_btn_revert", variant="error")

                    with Vertical(id="wb_howto_col"):
                        yield Static("How-To", classes="pane_title")
                        with VerticalScroll(id="wb_howto_scroll"):
                            yield Static(self.HOWTO_TEXT.strip(), id="wb_howto_text", markup=True)

                    with Vertical(id="wb_tips_col"):
                        yield Static("Hot Tips", classes="pane_title")
                        with VerticalScroll(id="wb_tips_scroll"):
                            yield Static("", id="wb_tip_text", markup=True)

                yield Footer()

            def _input_value(self, widget_id):
                return self.query_one(f"#{widget_id}", Input).value

            def _set_hot_tip(self, text):
                message = str(text).strip() or "Hover over controls for contextual hot tips."
                if message == self._tip_message:
                    return
                self._tip_message = message
                self.query_one("#wb_tip_text", Static).update(message)

            def _refresh_title(self):
                status = self.editor.status()
                title = (
                    f"[bold]ELF Editor Workbench[/bold]  "
                    f"file={status['path']}  "
                    f"class=ELF{status['elf_class']}  "
                    f"endian={status['endianness']}  "
                    f"dirty={status['dirty']}  "
                    f"changes={status['change_count']}  "
                    f"disassembler={status['disassembler']}"
                )
                self.query_one("#wb_title", Static).update(title)

            def _refresh_hex(self):
                offset = _parse_int_literal(self._input_value("wb_hex_offset"), "hex offset")
                length = _parse_int_literal(self._input_value("wb_hex_length"), "hex length")
                width = _parse_int_literal(self._input_value("wb_hex_width"), "hex width")
                text = self.editor.hex_view(offset=offset, length=length, width=width)
                rendered = text if text else "No bytes to display for this range."
                output = self.query_one("#wb_hex_output", RichLog)
                output.clear()
                for line in rendered.splitlines():
                    output.write(line)
                self._set_hot_tip(
                    f"Hex refreshed: offset=0x{offset:x}, length={length}, width={width}."
                )

            def _optional_int(self, value_text):
                raw = str(value_text).strip()
                if not raw:
                    return None
                return _parse_int_literal(raw, "address")

            def _refresh_disasm(self):
                section = self._input_value("wb_disasm_section").strip() or ".text"
                max_lines = _parse_int_literal(self._input_value("wb_disasm_max_lines"), "max lines")
                start_address = self._optional_int(self._input_value("wb_disasm_start"))
                stop_address = self._optional_int(self._input_value("wb_disasm_stop"))
                text = self.editor.disassemble(
                    section=section,
                    max_lines=max_lines,
                    start_address=start_address,
                    stop_address=stop_address,
                )
                output = self.query_one("#wb_disasm_output", RichLog)
                output.clear()
                for line in text.splitlines():
                    output.write(line)
                msg = f"Disassembly refreshed: section={section}, max_lines={max_lines}."
                if start_address is not None and stop_address is not None:
                    msg = (
                        f"Disassembly refreshed: section={section}, "
                        f"start=0x{start_address:x}, stop=0x{stop_address:x}, max_lines={max_lines}."
                    )
                self._set_hot_tip(msg)

            def _refresh_all(self):
                self._refresh_title()
                self._refresh_hex()
                self._refresh_disasm()

            def _patch_offset(self):
                return _parse_int_literal(self._input_value("wb_patch_offset"), "patch offset")

            def _save_binary(self):
                target = self._input_value("wb_save_path").strip() or None
                saved = self.editor.save(path=target)
                self.notify(f"Saved edited binary: {saved}", severity="information", title="Save")
                self._refresh_title()
                self._set_hot_tip(f"Saved edited binary to: {saved}")

            def _revert_changes(self):
                self.editor.revert()
                self.notify("Reverted all in-memory edits.", severity="information", title="Revert")
                self._refresh_all()
                self._set_hot_tip("Reverted to original file bytes.")

            def _apply_poke(self):
                offset = self._patch_offset()
                value = _parse_int_literal(self._input_value("wb_poke_value"), "poke byte")
                old, new = self.editor.write_byte(offset, value)
                self.notify(
                    f"Patched byte at 0x{offset:x}: {old:#x} -> {new:#x}",
                    severity="information",
                    title="Patch",
                )
                self._refresh_all()

            def _apply_hex_patch(self):
                offset = self._patch_offset()
                payload = self._input_value("wb_patch_hex_value")
                old, new = self.editor.patch_hex(offset, payload)
                self.notify(
                    f"Patched {len(new)} byte(s) at 0x{offset:x}.",
                    severity="information",
                    title="Patch",
                )
                self._set_hot_tip(
                    f"Patched bytes at 0x{offset:x}: old={old.hex()} new={new.hex()}"
                )
                self._refresh_all()

            def _apply_ascii_patch(self):
                offset = self._patch_offset()
                payload = self._input_value("wb_patch_ascii_value")
                old, new = self.editor.write_ascii(offset, payload)
                self.notify(
                    f"Wrote {len(new)} text byte(s) at 0x{offset:x}.",
                    severity="information",
                    title="Patch",
                )
                self._set_hot_tip(
                    f"ASCII patch at 0x{offset:x}: old={old.hex()} new={new.hex()}"
                )
                self._refresh_all()

            def _update_hot_tip_from_focus(self):
                focused = self.app.focused
                focused_id = getattr(focused, "id", None)
                if focused_id and focused_id in self.HOT_TIPS:
                    self._set_hot_tip(self.HOT_TIPS[focused_id])

            def on_mount(self):
                for widget_id, tip in self.HOT_TIPS.items():
                    try:
                        widget = self.query_one(f"#{widget_id}")
                    except Exception:
                        continue
                    try:
                        widget.tooltip = tip
                    except Exception:
                        pass
                self._set_hot_tip("Hover over controls for contextual hot tips.")
                self._refresh_all()

            def on_focus(self, _event):
                self._update_hot_tip_from_focus()

            def on_input_submitted(self, event: Input.Submitted):
                try:
                    if event.input.id in {"wb_hex_offset", "wb_hex_length", "wb_hex_width"}:
                        self._refresh_hex()
                    elif event.input.id in {
                        "wb_disasm_section",
                        "wb_disasm_max_lines",
                        "wb_disasm_start",
                        "wb_disasm_stop",
                    }:
                        self._refresh_disasm()
                    elif event.input.id in {"wb_patch_offset", "wb_poke_value"}:
                        self._apply_poke()
                    elif event.input.id == "wb_patch_hex_value":
                        self._apply_hex_patch()
                    elif event.input.id == "wb_patch_ascii_value":
                        self._apply_ascii_patch()
                    elif event.input.id == "wb_save_path":
                        self._save_binary()
                except (ValueError, ElfEditError) as exc:
                    self.notify(str(exc), severity="error", title="Editor")

            def on_button_pressed(self, event: Button.Pressed):
                button_id = event.button.id
                if button_id in self.HOT_TIPS:
                    self._set_hot_tip(self.HOT_TIPS[button_id])
                try:
                    if button_id == "wb_btn_refresh_hex":
                        self._refresh_hex()
                    elif button_id == "wb_btn_refresh_disasm":
                        self._refresh_disasm()
                    elif button_id == "wb_btn_poke":
                        self._apply_poke()
                    elif button_id == "wb_btn_patch_hex":
                        self._apply_hex_patch()
                    elif button_id == "wb_btn_patch_ascii":
                        self._apply_ascii_patch()
                    elif button_id == "wb_btn_save":
                        self._save_binary()
                    elif button_id == "wb_btn_revert":
                        self._revert_changes()
                except (ValueError, ElfEditError) as exc:
                    self.notify(str(exc), severity="error", title="Editor")

            def action_close_workbench(self):
                self.app.pop_screen()

            def action_refresh_all(self):
                try:
                    self._refresh_all()
                except (ValueError, ElfEditError) as exc:
                    self.notify(str(exc), severity="error", title="Editor")

            def action_refresh_hex(self):
                try:
                    self._refresh_hex()
                except (ValueError, ElfEditError) as exc:
                    self.notify(str(exc), severity="error", title="Editor")

            def action_refresh_disasm(self):
                try:
                    self._refresh_disasm()
                except (ValueError, ElfEditError) as exc:
                    self.notify(str(exc), severity="error", title="Editor")

            def action_save_binary(self):
                try:
                    self._save_binary()
                except (ValueError, ElfEditError) as exc:
                    self.notify(str(exc), severity="error", title="Editor")

            def action_revert_changes(self):
                try:
                    self._revert_changes()
                except (ValueError, ElfEditError) as exc:
                    self.notify(str(exc), severity="error", title="Editor")

        return _EditorWorkbenchScreen()
