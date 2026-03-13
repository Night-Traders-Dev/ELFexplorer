import struct
import subprocess
import tempfile
from pathlib import Path
from shutil import which

from .elf_editor import ElfEditError
from uf2.scan import (
    UF2_BLOCK_SIZE,
    UF2_MAGIC_END,
    UF2_MAGIC_START0,
    UF2_MAGIC_START1,
    is_uf2_file,
)


class Uf2BinaryEditor:
    """Editable UF2 view backed by the reconstructed payload image."""

    PAYLOAD_OFFSET = 32
    MAX_PAYLOAD_SIZE = 476
    FAMILY_NAMES = {
        0xE48BFF56: "RP2040",
    }
    DISASM_TARGETS = {
        0xE48BFF56: {
            "arch": "arm",
            "syntax": ["-M", "force-thumb"],
            "name": "ARM Thumb (RP2040)",
        }
    }

    def __init__(self, path):
        self.path = Path(path).expanduser()
        self._original_container = self.path.read_bytes()
        self._changes = []
        self._load_uf2()

    def _load_uf2(self):
        if not is_uf2_file(self.path):
            raise ElfEditError("Magic number does not match UF2.")
        data = self._original_container
        if len(data) < UF2_BLOCK_SIZE or (len(data) % UF2_BLOCK_SIZE) != 0:
            raise ElfEditError("Input is not a valid UF2 file (size is not a UF2 block multiple).")

        self._blocks = []
        self._family_ids = set()
        self._declared_counts = set()

        for raw_offset in range(0, len(data), UF2_BLOCK_SIZE):
            raw_block = data[raw_offset : raw_offset + UF2_BLOCK_SIZE]
            (
                magic0,
                magic1,
                flags,
                target_addr,
                payload_size,
                block_no,
                num_blocks,
                file_size_or_family,
            ) = struct.unpack_from("<IIIIIIII", raw_block, 0)
            magic_end = struct.unpack_from("<I", raw_block, 508)[0]
            if (
                magic0 != UF2_MAGIC_START0
                or magic1 != UF2_MAGIC_START1
                or magic_end != UF2_MAGIC_END
            ):
                raise ElfEditError("Input is not a valid UF2 file (bad UF2 block magic).")
            if payload_size > self.MAX_PAYLOAD_SIZE:
                raise ElfEditError("Input is not a valid UF2 file (invalid payload size in block).")

            family_id = None
            if flags & 0x00002000:
                family_id = file_size_or_family
                self._family_ids.add(family_id)
            if num_blocks:
                self._declared_counts.add(num_blocks)

            self._blocks.append(
                {
                    "raw_offset": raw_offset,
                    "original_index": raw_offset // UF2_BLOCK_SIZE,
                    "raw_block": bytes(raw_block),
                    "flags": flags,
                    "target_addr": target_addr,
                    "payload_size": payload_size,
                    "block_no": block_no,
                    "num_blocks": num_blocks,
                    "family_id": family_id,
                    "payload": bytes(raw_block[self.PAYLOAD_OFFSET : self.PAYLOAD_OFFSET + payload_size]),
                }
            )

        self._blocks_sorted = sorted(
            self._blocks,
            key=lambda block: (
                int(block["target_addr"]),
                int(block["block_no"]),
                int(block["original_index"]),
            ),
        )
        payload = bytearray()
        for index, block in enumerate(self._blocks_sorted):
            block["sorted_index"] = index
            block["payload_offset"] = len(payload)
            payload.extend(block["payload"])
        self._original_payload = bytes(payload)
        self._payload = bytearray(self._original_payload)

        if self._blocks_sorted:
            self.base_address = min(int(block["target_addr"]) for block in self._blocks_sorted)
            self.end_address = max(
                int(block["target_addr"]) + int(block["payload_size"]) for block in self._blocks_sorted
            )
        else:
            self.base_address = 0
            self.end_address = 0

    @property
    def file_size(self):
        return len(self._payload)

    @property
    def is_dirty(self):
        return self._payload != self._original_payload

    @property
    def change_count(self):
        return len(self._changes)

    def get_changes(self):
        return list(self._changes)

    def _record_change(self, scope, index, field, old, new):
        if old == new:
            return
        self._changes.append(
            {
                "scope": scope,
                "index": index,
                "field": field,
                "old": old,
                "new": new,
            }
        )

    def _require_range(self, offset, length):
        offset = int(offset)
        length = int(length)
        if offset < 0:
            raise ElfEditError("Offset must be >= 0.")
        if length <= 0:
            raise ElfEditError("Length must be > 0.")
        end = offset + length
        if end > len(self._payload):
            raise ElfEditError(
                f"Requested range exceeds UF2 payload size: offset=0x{offset:x}, bytes={length}, size={len(self._payload)}"
            )
        return offset, length

    def _block_for_offset(self, offset):
        offset = int(offset)
        if offset < 0 or offset >= len(self._payload):
            return None
        for block in self._blocks_sorted:
            start = int(block["payload_offset"])
            end = start + int(block["payload_size"])
            if start <= offset < end:
                return block
        return None

    def list_blocks(self):
        items = []
        for block in self._blocks_sorted:
            payload_offset = int(block["payload_offset"])
            payload_size = int(block["payload_size"])
            items.append(
                {
                    "index": int(block["sorted_index"]),
                    "block_no": int(block["block_no"]),
                    "raw_index": int(block["original_index"]),
                    "raw_offset": int(block["raw_offset"]),
                    "target_addr": int(block["target_addr"]),
                    "payload_size": payload_size,
                    "payload_offset": payload_offset,
                    "payload_end": payload_offset + payload_size,
                    "num_blocks": int(block["num_blocks"]),
                    "flags": int(block["flags"]),
                    "family_id": block["family_id"],
                    "family_name": self.FAMILY_NAMES.get(block["family_id"], "Unknown")
                    if block["family_id"] is not None
                    else "Unknown",
                }
            )
        return items

    def get_block(self, index):
        index = int(index)
        if index < 0 or index >= len(self._blocks_sorted):
            raise ElfEditError(f"UF2 block index out of range: {index}")
        return self.list_blocks()[index]

    def get_uf2_overview(self):
        return {
            "path": str(self.path),
            "blocks": len(self._blocks_sorted),
            "payload_size": len(self._payload),
            "base_address": self.base_address,
            "end_address": self.end_address,
            "family_ids": sorted(self._family_ids),
            "declared_counts": sorted(self._declared_counts),
        }

    def section_for_offset(self, offset):
        block = self._block_for_offset(offset)
        if not block:
            return None
        return {
            "index": int(block["sorted_index"]),
            "name": f"UF2 block {int(block['block_no'])}",
            "offset": int(block["payload_offset"]),
            "size": int(block["payload_size"]),
            "address": int(block["target_addr"]),
            "raw_offset": int(block["raw_offset"]),
        }

    def file_offset_to_vaddr(self, offset):
        block = self._block_for_offset(offset)
        if not block:
            return None
        return int(block["target_addr"]) + (int(offset) - int(block["payload_offset"]))

    def file_range_to_vaddr_range(self, offset, length):
        offset = int(offset)
        length = int(length)
        if offset < 0 or length <= 0 or offset >= len(self._payload):
            return None
        remaining = min(length, len(self._payload) - offset)
        current_offset = offset
        previous_end = None
        range_start = None
        range_end = None

        while remaining > 0:
            block = self._block_for_offset(current_offset)
            if not block:
                return None
            block_start = int(block["payload_offset"])
            block_size = int(block["payload_size"])
            chunk_end = min(block_start + block_size, current_offset + remaining)
            start_vaddr = int(block["target_addr"]) + (current_offset - block_start)
            end_vaddr = int(block["target_addr"]) + (chunk_end - block_start)
            if range_start is None:
                range_start = start_vaddr
            elif previous_end != start_vaddr:
                return None
            range_end = end_vaddr
            previous_end = end_vaddr
            consumed = chunk_end - current_offset
            current_offset = chunk_end
            remaining -= consumed

        if range_start is None or range_end is None:
            return None
        return range_start, range_end

    def read_bytes(self, offset, length):
        offset, length = self._require_range(offset, length)
        return bytes(self._payload[offset : offset + length])

    def write_byte(self, offset, value):
        offset, _ = self._require_range(offset, 1)
        numeric = int(value)
        if numeric < 0 or numeric > 0xFF:
            raise ElfEditError(f"Byte value out of range: {numeric}")
        old = self._payload[offset]
        self._payload[offset] = numeric
        self._record_change("uf2-payload", offset, "byte", old, numeric)
        return old, numeric

    def write_bytes(self, offset, payload):
        offset = int(offset)
        payload_bytes = bytes(payload)
        if not payload_bytes:
            raise ElfEditError("Payload must contain at least one byte.")
        self._require_range(offset, len(payload_bytes))
        end = offset + len(payload_bytes)
        old = bytes(self._payload[offset:end])
        self._payload[offset:end] = payload_bytes
        self._record_change("uf2-payload", offset, "bytes", old.hex(), payload_bytes.hex())
        return old, payload_bytes

    @staticmethod
    def _decode_hex_text(hex_text):
        text = str(hex_text).strip()
        if not text:
            raise ElfEditError("Hex payload cannot be empty.")
        parts = [token for token in text.replace(",", " ").split() if token]
        if parts and all(part.lower().startswith("0x") for part in parts):
            values = []
            for part in parts:
                numeric = int(part, 0)
                if numeric < 0 or numeric > 0xFF:
                    raise ElfEditError(f"Byte literal out of range: {part}")
                values.append(numeric)
            return bytes(values)
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise ElfEditError(
                "Invalid hex payload. Use forms like 'de ad be ef' or '0xDE 0xAD 0xBE 0xEF'."
            ) from exc

    def patch_hex(self, offset, hex_text):
        return self.write_bytes(offset, self._decode_hex_text(hex_text))

    def write_ascii(self, offset, text, encoding="utf-8"):
        payload = str(text).encode(encoding)
        if not payload:
            raise ElfEditError("ASCII/text payload cannot be empty.")
        return self.write_bytes(offset, payload)

    @staticmethod
    def _looks_like_instruction_line(line):
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            return False
        head = stripped.split(":", 1)[0]
        return bool(head) and all(ch in "0123456789abcdefABCDEF" for ch in head)

    def _render_disassembly_snippet(self, full_text, max_lines):
        lines = full_text.splitlines()
        if max_lines is None or max_lines <= 0:
            return "\n".join(lines).rstrip()
        rendered = []
        instruction_count = 0
        for line in lines:
            rendered.append(line)
            if self._looks_like_instruction_line(line):
                instruction_count += 1
                if instruction_count >= max_lines:
                    break
        if instruction_count >= max_lines:
            rendered.append("... [truncated]")
        return "\n".join(rendered).rstrip()

    @staticmethod
    def _objdump_path():
        return which("objdump")

    def _disasm_target(self):
        for family_id in sorted(self._family_ids):
            if family_id in self.DISASM_TARGETS:
                return self.DISASM_TARGETS[family_id]
        return None

    def disassembler_backend(self):
        if self._objdump_path() and self._disasm_target():
            return "objdump(binary)"
        return "unavailable"

    def disassemble(
        self,
        section=".text",
        max_lines=120,
        start_address=None,
        stop_address=None,
        syntax="intel",
    ):
        del section, syntax
        if (
            start_address is not None
            and stop_address is not None
            and int(stop_address) <= int(start_address)
        ):
            raise ElfEditError("stop_address must be greater than start_address.")

        objdump = self._objdump_path()
        target = self._disasm_target()
        if not objdump or not target:
            return "Disassembly unavailable for this UF2 image. Export the payload for external analysis."

        payload = bytes(self._payload)
        if not payload:
            return "UF2 payload is empty."

        with tempfile.NamedTemporaryFile(prefix="elfexplorer-uf2-", suffix=".bin", delete=False) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)

        try:
            command = [
                objdump,
                "-D",
                "-b",
                "binary",
                "-m",
                target["arch"],
                f"--adjust-vma={self.base_address}",
            ]
            command.extend(target.get("syntax", []))
            if start_address is not None:
                command.append(f"--start-address={int(start_address)}")
            if stop_address is not None:
                command.append(f"--stop-address={int(stop_address)}")
            command.append(str(tmp_path))
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
            stdout = completed.stdout or ""
            stderr = (completed.stderr or "").strip()
            if completed.returncode != 0 and not stdout.strip():
                if stderr:
                    return f"UF2 disassembly failed: {stderr}"
                return "UF2 disassembly failed."
            rendered = self._render_disassembly_snippet(stdout, max_lines=max_lines)
            return rendered or (f"No disassembly output.\n{stderr}" if stderr else "No disassembly output.")
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def hex_view(self, offset=0, length=256, width=16):
        offset = int(offset)
        length = int(length)
        width = int(width)
        if offset < 0:
            raise ElfEditError("hex_view offset must be >= 0.")
        if length < 0:
            raise ElfEditError("hex_view length must be >= 0.")
        if width <= 0:
            raise ElfEditError("hex_view width must be > 0.")
        if offset >= len(self._payload):
            return ""
        end = min(len(self._payload), offset + length)
        lines = []
        for base in range(offset, end, width):
            chunk = self._payload[base : min(base + width, end)]
            hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            vaddr = self.file_offset_to_vaddr(base)
            prefix = f"{base:08x}"
            if vaddr is not None:
                prefix += f" @0x{vaddr:08x}"
            lines.append(f"{prefix}  {hex_bytes:<{(width * 3) - 1}}  |{ascii_text}|")
        return "\n".join(lines)

    def _rebuild_container(self):
        rebuilt = bytearray()
        for block in sorted(self._blocks, key=lambda item: int(item["original_index"])):
            new_block = bytearray(block["raw_block"])
            payload_offset = int(block["payload_offset"])
            payload_size = int(block["payload_size"])
            payload = self._payload[payload_offset : payload_offset + payload_size]
            new_block[self.PAYLOAD_OFFSET : self.PAYLOAD_OFFSET + payload_size] = payload
            rebuilt.extend(new_block)
        return bytes(rebuilt)

    def revert(self):
        self._payload = bytearray(self._original_payload)
        self._changes.clear()

    def save(self, path=None):
        target = Path(path).expanduser() if path else self.path.with_name(f"{self.path.name}.modified")
        target.parent.mkdir(parents=True, exist_ok=True)
        container = self._rebuild_container()
        target.write_bytes(container)
        return target.resolve()

    def export_payload(self, path=None):
        if path:
            target = Path(path).expanduser()
        else:
            target = self.path.with_suffix(".bin")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bytes(self._payload))
        return target.resolve()

    def status(self):
        families = []
        for family_id in sorted(self._family_ids):
            label = self.FAMILY_NAMES.get(family_id)
            families.append(f"0x{family_id:08X}" + (f" ({label})" if label else ""))
        return {
            "path": str(self.path),
            "format": "UF2",
            "size": len(self._payload),
            "dirty": self.is_dirty,
            "change_count": self.change_count,
            "disassembler": self.disassembler_backend(),
            "container_size": len(self._original_container),
            "blocks": len(self._blocks_sorted),
            "base_address": self.base_address,
            "end_address": self.end_address,
            "family_ids": families,
        }
