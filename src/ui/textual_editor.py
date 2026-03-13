import re

from edit import ElfEditError


def _parse_int_literal(text, label):
    raw = str(text).strip()
    if not raw:
        raise ValueError(f"{label} is required.")
    try:
        return int(raw, 0)
    except ValueError as exc:
        raise ValueError(f"{label} must be a numeric literal (examples: 10, 0x20).") from exc


def _ascii_byte(value):
    return chr(value) if 32 <= value <= 126 else "."


class EditorWorkbenchScreen:
    """Factory wrapper so textual import is delayed until UI launch."""

    @staticmethod
    def build(editor):
        from rich.text import Text
        from textual.containers import Horizontal, Vertical, VerticalScroll
        from textual.coordinate import Coordinate
        from textual.screen import Screen
        from textual.widgets import Button, DataTable, Footer, Input, RichLog, Static

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
                padding: 0 1;
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
            #wb_hex_table, #wb_disasm_output {
                height: 1fr;
                border-top: solid $panel;
                border-bottom: solid $panel;
            }
            #wb_selection_summary {
                height: auto;
                padding: 0 1;
                color: $text-muted;
            }
            #wb_raw_output {
                height: 9;
                border-top: solid $panel;
                border-bottom: solid $panel;
            }
            #wb_hex_controls_primary,
            #wb_hex_controls_secondary,
            #wb_disasm_controls {
                height: auto;
                padding: 0 0 1 0;
            }
            #wb_hex_controls_primary Input,
            #wb_hex_controls_secondary Input,
            #wb_disasm_controls Input {
                width: 1fr;
                margin-right: 1;
            }
            #wb_hex_controls_secondary Button,
            #wb_disasm_controls Button {
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
                ("f6", "follow_selection_disasm", "Follow Sel"),
                ("f7", "toggle_anchor", "Anchor"),
                ("f8", "clear_selection", "Clear Sel"),
                ("ctrl+]", "expand_selection", "Sel +"),
                ("ctrl+[", "shrink_selection", "Sel -"),
            ]

            HOT_TIPS = {
                "wb_hex_table": "Click a byte cell to select it. Use F7 to set anchor, then click another byte for range selection.",
                "wb_raw_output": "Raw binary preview around selection. Selected byte range is highlighted.",
                "wb_disasm_output": "Disassembly pane. Instructions matching selected bytes are highlighted when file offset maps to virtual address.",
                "wb_hex_offset": "Hex offset in decimal or hex (e.g. 256 or 0x100).",
                "wb_hex_length": "Hex length controls how many bytes are shown.",
                "wb_hex_width": "Hex width is bytes per row (usually 8/16/32).",
                "wb_selection_length": "Selection length used for click-select when no anchor range is active.",
                "wb_disasm_section": "ELF section name, or leave the default when disassembling UF2 payload bytes.",
                "wb_disasm_max_lines": "Maximum number of instruction lines to render.",
                "wb_disasm_start": "Optional start address for disassembly range.",
                "wb_disasm_stop": "Optional stop address (must be greater than start).",
                "wb_patch_offset": "Patch offset where byte/hex/ascii data will be written.",
                "wb_poke_value": "Single byte to write (e.g. 0x90).",
                "wb_patch_hex_value": "Hex byte sequence: 'de ad be ef' or '0xDE 0xAD 0xBE 0xEF'.",
                "wb_patch_ascii_value": "ASCII/UTF-8 text to write at patch offset.",
                "wb_save_path": "Optional output path. Leave blank to save as <name>.modified.",
                "wb_btn_refresh_hex": "Refresh hex table and raw-byte preview using current controls.",
                "wb_btn_follow_disasm": "Map selected file range to virtual address and refresh disassembly around that range.",
                "wb_btn_set_anchor": "Set/clear selection anchor. Click another byte to create a range selection.",
                "wb_btn_clear_selection": "Clear current selection and highlights.",
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
2. Press [bold]Refresh Hex[/bold] to load the interactive byte grid.
3. Click any byte in [bold]Hex Pane[/bold] to select it.
4. For range selection:
   - Move cursor to first byte and press [bold]F7[/bold] (anchor), then click destination byte.
   - Or set [bold]sel_len[/bold] and click a byte to select that chunk immediately.
5. Use [bold]Follow Sel[/bold] (button or [bold]F6[/bold]) to sync disassembly range from selected file bytes.
6. Edit bytes in [bold]Patch Form[/bold], inspect synchronized highlights, then [bold]Save[/bold].

[bold]UF2 Notes[/bold]
- UF2 editing works against the reconstructed payload image, not raw 512-byte container blocks.
- Selection summary shows target virtual address ranges when the UF2 block map provides them.
- Disassembly is best-effort and currently optimized for RP2040 UF2 images.

[bold]Disassembler-Style Features[/bold]
- Interactive byte-cell selection in the hex grid.
- Raw-binary preview highlights selected range in context.
- Disassembly highlighting for instructions whose addresses map to selected bytes.
- Auto patch-offset sync from selection.
- Selection growth/shrink: [bold]Ctrl+][/bold] / [bold]Ctrl+[[/bold].

[bold]Keyboard[/bold]
- [bold]F5[/bold]: refresh all panes
- [bold]Ctrl+H[/bold]: refresh hex pane
- [bold]Ctrl+D[/bold]: refresh disassembly pane
- [bold]F6[/bold]: follow selection in disassembly
- [bold]F7[/bold]: toggle selection anchor
- [bold]F8[/bold]: clear selection
- [bold]Ctrl+S[/bold]: save edited binary
- [bold]Ctrl+R[/bold]: revert edits
- [bold]Esc[/bold]: return to workspace
"""

            _DISASM_ADDR_RE = re.compile(r"^\s*([0-9a-fA-F]+):")

            def __init__(self):
                super().__init__()
                self.editor = editor
                self._tip_message = "Hover over controls for contextual hot tips."
                self._hex_rows = []
                self._hex_width = 16
                self._selection_start = None
                self._selection_length = 1
                self._selection_anchor = None
                self._disasm_lines = []

            def compose(self):
                yield Static("", id="wb_title")
                with Horizontal(id="wb_main"):
                    with Vertical(id="wb_hex_col"):
                        yield Static("Hex Pane", classes="pane_title")
                        table = DataTable(id="wb_hex_table")
                        table.cursor_type = "cell"
                        table.zebra_stripes = True
                        yield table
                        yield Static("", id="wb_selection_summary")
                        yield RichLog(
                            id="wb_raw_output",
                            wrap=False,
                            markup=False,
                            auto_scroll=False,
                            highlight=False,
                        )
                        with Horizontal(id="wb_hex_controls_primary"):
                            yield Input(value="0x0", placeholder="offset", id="wb_hex_offset")
                            yield Input(value="0x100", placeholder="length", id="wb_hex_length")
                            yield Input(value="16", placeholder="width", id="wb_hex_width")
                            yield Button("Refresh Hex", id="wb_btn_refresh_hex", variant="primary")
                        with Horizontal(id="wb_hex_controls_secondary"):
                            yield Input(value="1", placeholder="sel_len", id="wb_selection_length")
                            yield Button("Follow Sel", id="wb_btn_follow_disasm", variant="primary")
                            yield Button("Set Anchor", id="wb_btn_set_anchor", variant="warning")
                            yield Button("Clear Sel", id="wb_btn_clear_selection", variant="default")
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
                if status.get("format") == "UF2":
                    families = ", ".join(status.get("family_ids", [])) or "Unknown"
                    title = (
                        f"[bold]Binary Editor Workbench[/bold]  "
                        f"file={status['path']}  "
                        f"format=UF2  "
                        f"blocks={status['blocks']}  "
                        f"base=0x{int(status['base_address']):x}  "
                        f"family={families}  "
                        f"dirty={status['dirty']}  "
                        f"changes={status['change_count']}  "
                        f"disassembler={status['disassembler']}"
                    )
                else:
                    title = (
                        f"[bold]Binary Editor Workbench[/bold]  "
                        f"file={status['path']}  "
                        f"class=ELF{status['elf_class']}  "
                        f"endian={status['endianness']}  "
                        f"dirty={status['dirty']}  "
                        f"changes={status['change_count']}  "
                        f"disassembler={status['disassembler']}"
                    )
                self.query_one("#wb_title", Static).update(title)

            def _selection_range(self):
                if self._selection_start is None:
                    return None
                start = max(0, int(self._selection_start))
                if start >= self.editor.file_size:
                    return None
                length = max(1, int(self._selection_length))
                end = min(self.editor.file_size, start + length)
                return start, end

            def _selected_bytes(self):
                selection = self._selection_range()
                if not selection:
                    return b""
                start, end = selection
                return self.editor.read_bytes(start, end - start)

            def _parse_selection_length(self):
                length = _parse_int_literal(self._input_value("wb_selection_length"), "selection length")
                if length <= 0:
                    raise ValueError("selection length must be > 0.")
                return length

            def _sync_patch_inputs_from_selection(self):
                selection = self._selection_range()
                if not selection:
                    return
                start, end = selection
                self.query_one("#wb_patch_offset", Input).value = f"0x{start:x}"
                payload = self.editor.read_bytes(start, min(16, end - start))
                if payload:
                    self.query_one("#wb_patch_hex_value", Input).value = payload.hex(" ")

            def _update_selection_summary(self):
                summary = self.query_one("#wb_selection_summary", Static)
                selection = self._selection_range()
                if not selection:
                    summary.update(
                        "Selection: none. Click byte cells in Hex Pane to select a chunk for patching/disassembly sync."
                    )
                    return

                start, end = selection
                length = end - start
                payload = self.editor.read_bytes(start, min(length, 16))
                payload_hex = payload.hex(" ")
                payload_ascii = "".join(_ascii_byte(byte) for byte in payload)
                if length > 16:
                    payload_hex += " ..."
                    payload_ascii += "..."

                section = self.editor.section_for_offset(start)
                if section:
                    section_text = (
                        f"{section['name']} (idx={section['index']}, "
                        f"file_off=0x{section['offset']:x}, size=0x{section['size']:x})"
                    )
                else:
                    section_text = "unmapped"

                vaddr_range = self.editor.file_range_to_vaddr_range(start, length)
                if vaddr_range:
                    va_text = f"0x{vaddr_range[0]:x}-0x{vaddr_range[1] - 1:x}"
                else:
                    va_text = "unmapped"

                anchor_text = (
                    f"0x{self._selection_anchor:x}" if self._selection_anchor is not None else "none"
                )
                summary.update(
                    f"Selection: 0x{start:x}-0x{end - 1:x} ({length} byte(s))  "
                    f"VA={va_text}  section={section_text}  anchor={anchor_text}\n"
                    f"bytes={payload_hex}  ascii='{payload_ascii}'"
                )

            def _render_raw_preview(self):
                output = self.query_one("#wb_raw_output", RichLog)
                output.clear()
                selection = self._selection_range()
                if not selection:
                    output.write("No active selection. Click a byte in the hex pane.")
                    return

                start, end = selection
                context = max(16, self._hex_width * 2)
                window_start = max(0, start - context)
                window_end = min(self.editor.file_size, end + context)
                payload = self.editor.read_bytes(window_start, window_end - window_start)
                width = max(8, min(32, self._hex_width))

                for base in range(window_start, window_end, width):
                    chunk_start = base - window_start
                    chunk = payload[chunk_start : chunk_start + width]
                    line = Text(f"{base:08x}  ", style="bold")
                    ascii_block = Text("|")
                    for idx, byte in enumerate(chunk):
                        absolute = base + idx
                        is_selected = start <= absolute < end
                        is_anchor = self._selection_anchor == absolute
                        if is_anchor:
                            style = "bold black on green"
                        elif is_selected:
                            style = "bold black on yellow"
                        else:
                            style = ""
                        if idx:
                            line.append(" ")
                        line.append(f"{byte:02x}", style=style)
                        ascii_block.append(_ascii_byte(byte), style=style)
                    ascii_block.append("|")
                    line.append("  ")
                    line.append(ascii_block)
                    output.write(line)

            def _offset_from_hex_coordinate(self, coordinate):
                row = int(coordinate.row)
                column = int(coordinate.column)
                if row < 0 or row >= len(self._hex_rows):
                    return None
                if column <= 0 or column > self._hex_width:
                    return None
                row_info = self._hex_rows[row]
                index_in_row = column - 1
                if index_in_row >= row_info["length"]:
                    return None
                return row_info["base"] + index_in_row

            def _render_hex_table_selection(self):
                table = self.query_one("#wb_hex_table", DataTable)
                selection = self._selection_range()
                if selection:
                    sel_start, sel_end = selection
                else:
                    sel_start, sel_end = -1, -1

                for row_index, row_info in enumerate(self._hex_rows):
                    ascii_line = Text()
                    for byte_col in range(self._hex_width):
                        coord = Coordinate(row_index, byte_col + 1)
                        if byte_col >= row_info["length"]:
                            table.update_cell_at(coord, "")
                            continue
                        absolute = row_info["base"] + byte_col
                        byte = row_info["bytes"][byte_col]
                        is_selected = sel_start <= absolute < sel_end
                        is_anchor = self._selection_anchor == absolute
                        if is_anchor:
                            style = "bold black on green"
                        elif is_selected:
                            style = "bold black on yellow"
                        else:
                            style = ""
                        table.update_cell_at(coord, Text(f"{byte:02x}", style=style))
                        ascii_line.append(_ascii_byte(byte), style=style)
                    table.update_cell_at(Coordinate(row_index, self._hex_width + 1), ascii_line)

            def _set_selection(self, start, length, sync_patch=True):
                if self.editor.file_size <= 0:
                    self._selection_start = None
                    self._selection_length = 1
                else:
                    bounded_start = max(0, min(int(start), self.editor.file_size - 1))
                    bounded_length = max(1, min(int(length), self.editor.file_size - bounded_start))
                    self._selection_start = bounded_start
                    self._selection_length = bounded_length
                self.query_one("#wb_selection_length", Input).value = str(self._selection_length)
                if sync_patch:
                    self._sync_patch_inputs_from_selection()
                self._update_selection_summary()
                self._render_hex_table_selection()
                self._render_raw_preview()
                self._render_disasm_output()

            def _clear_selection(self):
                self._selection_start = None
                self._selection_anchor = None
                self._selection_length = max(1, self._selection_length)
                self._update_selection_summary()
                self._render_hex_table_selection()
                self._render_raw_preview()
                self._render_disasm_output()

            def _refresh_hex(self):
                offset = _parse_int_literal(self._input_value("wb_hex_offset"), "hex offset")
                length = _parse_int_literal(self._input_value("wb_hex_length"), "hex length")
                width = _parse_int_literal(self._input_value("wb_hex_width"), "hex width")
                if width <= 0 or width > 64:
                    raise ValueError("hex width must be in range 1..64.")

                self._hex_width = width
                table = self.query_one("#wb_hex_table", DataTable)
                table.clear(columns=True)
                columns = ["offset"] + [f"+{index:02x}" for index in range(width)] + ["ascii"]
                table.add_columns(*columns)
                table.cursor_type = "cell"
                table.zebra_stripes = True

                self._hex_rows = []
                if offset < 0:
                    raise ValueError("hex offset must be >= 0.")
                if length < 0:
                    raise ValueError("hex length must be >= 0.")
                end = min(self.editor.file_size, offset + length)

                for base in range(offset, end, width):
                    chunk = self.editor.read_bytes(base, min(width, end - base))
                    row = [f"{base:08x}"]
                    row.extend(f"{byte:02x}" for byte in chunk)
                    row.extend("" for _ in range(width - len(chunk)))
                    row.append("".join(_ascii_byte(byte) for byte in chunk))
                    table.add_row(*row)
                    self._hex_rows.append({"base": base, "length": len(chunk), "bytes": chunk})

                if self._hex_rows:
                    current = self._selection_start
                    in_range = current is not None and offset <= current < end
                    if not in_range:
                        self._set_selection(self._hex_rows[0]["base"], self._selection_length)
                    else:
                        self._set_selection(current, self._selection_length)
                    table.move_cursor(row=0, column=1, animate=False, scroll=True)
                else:
                    self._clear_selection()

                self._set_hot_tip(
                    f"Hex refreshed: offset=0x{offset:x}, length={length}, width={width}. Click bytes to select."
                )

            def _optional_int(self, value_text):
                raw = str(value_text).strip()
                if not raw:
                    return None
                return _parse_int_literal(raw, "address")

            def _render_disasm_output(self):
                output = self.query_one("#wb_disasm_output", RichLog)
                output.clear()
                selection = self._selection_range()
                va_range = None
                if selection:
                    va_range = self.editor.file_range_to_vaddr_range(
                        selection[0], selection[1] - selection[0]
                    )
                anchor_vaddr = (
                    self.editor.file_offset_to_vaddr(self._selection_anchor)
                    if self._selection_anchor is not None
                    else None
                )

                for line in self._disasm_lines:
                    style = ""
                    match = self._DISASM_ADDR_RE.match(line)
                    if match:
                        address = int(match.group(1), 16)
                        if anchor_vaddr is not None and address == anchor_vaddr:
                            style = "bold black on green"
                        elif va_range and va_range[0] <= address < va_range[1]:
                            style = "bold black on yellow"
                    output.write(Text(line, style=style) if style else line)

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
                self._disasm_lines = text.splitlines()
                self._render_disasm_output()
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

            def _follow_selection_disasm(self):
                selection = self._selection_range()
                if not selection:
                    raise ValueError("No active selection to follow.")
                start, end = selection
                va_range = self.editor.file_range_to_vaddr_range(start, end - start)
                if not va_range:
                    raise ValueError(
                        "Selected file range is not mapped to a virtual address range for disassembly."
                    )
                section = self.editor.section_for_offset(start)
                if section:
                    name = str(section.get("name", "")).strip()
                    if name and not name.startswith("<"):
                        self.query_one("#wb_disasm_section", Input).value = name
                self.query_one("#wb_disasm_start", Input).value = f"0x{va_range[0]:x}"
                self.query_one("#wb_disasm_stop", Input).value = f"0x{va_range[1]:x}"
                self._refresh_disasm()
                self._set_hot_tip(
                    f"Disassembly synced to selection: file 0x{start:x}-0x{end - 1:x} -> VA 0x{va_range[0]:x}-0x{va_range[1] - 1:x}."
                )

            def _toggle_anchor(self):
                if self._selection_start is None:
                    raise ValueError("Select a byte before setting anchor.")
                if self._selection_anchor is None:
                    self._selection_anchor = self._selection_start
                    self._set_hot_tip(
                        f"Anchor set at 0x{self._selection_anchor:x}. Click another byte to define a range."
                    )
                else:
                    self._selection_anchor = None
                    self._set_hot_tip("Selection anchor cleared.")
                self._update_selection_summary()
                self._render_hex_table_selection()
                self._render_raw_preview()
                self._render_disasm_output()

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

            def on_data_table_cell_highlighted(self, event: DataTable.CellHighlighted):
                if event.data_table.id != "wb_hex_table":
                    return
                offset = self._offset_from_hex_coordinate(event.coordinate)
                if offset is None:
                    return
                self._set_hot_tip(f"Hex cursor at file offset 0x{offset:x}.")

            def on_data_table_cell_selected(self, event: DataTable.CellSelected):
                if event.data_table.id != "wb_hex_table":
                    return
                try:
                    offset = self._offset_from_hex_coordinate(event.coordinate)
                    if offset is None:
                        return
                    length = self._parse_selection_length()
                    if self._selection_anchor is not None and self._selection_anchor != offset:
                        start = min(self._selection_anchor, offset)
                        end = max(self._selection_anchor, offset) + 1
                        self._selection_anchor = None
                        self._set_selection(start, end - start)
                    else:
                        self._set_selection(offset, length)
                except (ValueError, ElfEditError) as exc:
                    self.notify(str(exc), severity="error", title="Selection")

            def on_input_submitted(self, event: Input.Submitted):
                try:
                    if event.input.id in {"wb_hex_offset", "wb_hex_length", "wb_hex_width"}:
                        self._refresh_hex()
                    elif event.input.id == "wb_selection_length":
                        if self._selection_start is None:
                            self._set_hot_tip(
                                "Selection length updated. Click a byte in Hex Pane to apply."
                            )
                        else:
                            self._set_selection(self._selection_start, self._parse_selection_length())
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
                    elif button_id == "wb_btn_follow_disasm":
                        self._follow_selection_disasm()
                    elif button_id == "wb_btn_set_anchor":
                        self._toggle_anchor()
                    elif button_id == "wb_btn_clear_selection":
                        self._clear_selection()
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

            def action_follow_selection_disasm(self):
                try:
                    self._follow_selection_disasm()
                except (ValueError, ElfEditError) as exc:
                    self.notify(str(exc), severity="error", title="Editor")

            def action_toggle_anchor(self):
                try:
                    self._toggle_anchor()
                except (ValueError, ElfEditError) as exc:
                    self.notify(str(exc), severity="error", title="Editor")

            def action_clear_selection(self):
                self._clear_selection()
                self._set_hot_tip("Selection cleared.")

            def action_expand_selection(self):
                if self._selection_start is None:
                    self.notify("No selection to expand.", severity="warning", title="Selection")
                    return
                self._set_selection(self._selection_start, self._selection_length + 1)
                self._set_hot_tip(
                    f"Selection expanded to {self._selection_length} byte(s)."
                )

            def action_shrink_selection(self):
                if self._selection_start is None:
                    self.notify("No selection to shrink.", severity="warning", title="Selection")
                    return
                self._set_selection(self._selection_start, max(1, self._selection_length - 1))
                self._set_hot_tip(
                    f"Selection shrunk to {self._selection_length} byte(s)."
                )

        return _EditorWorkbenchScreen()
