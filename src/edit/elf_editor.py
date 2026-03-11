import struct
import subprocess
import tempfile
from pathlib import Path
from shutil import which


class ElfEditError(ValueError):
    """Raised when ELF edit operations cannot be completed safely."""


class ElfBinaryEditor:
    ELF_HEADER_FIELDS = (
        "e_type",
        "e_machine",
        "e_version",
        "e_entry",
        "e_phoff",
        "e_shoff",
        "e_flags",
        "e_ehsize",
        "e_phentsize",
        "e_phnum",
        "e_shentsize",
        "e_shnum",
        "e_shstrndx",
    )
    ELF_HEADER_FIELD_BITS_32 = {
        "e_type": 16,
        "e_machine": 16,
        "e_version": 32,
        "e_entry": 32,
        "e_phoff": 32,
        "e_shoff": 32,
        "e_flags": 32,
        "e_ehsize": 16,
        "e_phentsize": 16,
        "e_phnum": 16,
        "e_shentsize": 16,
        "e_shnum": 16,
        "e_shstrndx": 16,
    }
    ELF_HEADER_FIELD_BITS_64 = {
        "e_type": 16,
        "e_machine": 16,
        "e_version": 32,
        "e_entry": 64,
        "e_phoff": 64,
        "e_shoff": 64,
        "e_flags": 32,
        "e_ehsize": 16,
        "e_phentsize": 16,
        "e_phnum": 16,
        "e_shentsize": 16,
        "e_shnum": 16,
        "e_shstrndx": 16,
    }
    ELF_HEADER_ALIASES = {
        "type": "e_type",
        "machine": "e_machine",
        "version": "e_version",
        "entry": "e_entry",
        "phoff": "e_phoff",
        "shoff": "e_shoff",
        "flags": "e_flags",
        "ehsize": "e_ehsize",
        "phentsize": "e_phentsize",
        "phnum": "e_phnum",
        "shentsize": "e_shentsize",
        "shnum": "e_shnum",
        "shstrndx": "e_shstrndx",
        "class": "ei_class",
        "data": "ei_data",
        "ident_class": "ei_class",
        "ident_data": "ei_data",
        "osabi": "ei_osabi",
        "abiversion": "ei_abiversion",
    }
    E_IDENT_OFFSETS = {
        "ei_class": 4,
        "ei_data": 5,
        "ei_version": 6,
        "ei_osabi": 7,
        "ei_abiversion": 8,
    }
    E_IDENT_BITS = {field: 8 for field in E_IDENT_OFFSETS}

    PROGRAM_HEADER_FIELDS_32 = (
        "p_type",
        "p_offset",
        "p_vaddr",
        "p_paddr",
        "p_filesz",
        "p_memsz",
        "p_flags",
        "p_align",
    )
    PROGRAM_HEADER_FIELDS_64 = (
        "p_type",
        "p_flags",
        "p_offset",
        "p_vaddr",
        "p_paddr",
        "p_filesz",
        "p_memsz",
        "p_align",
    )
    PROGRAM_HEADER_BITS_32 = {field: 32 for field in PROGRAM_HEADER_FIELDS_32}
    PROGRAM_HEADER_BITS_64 = {
        "p_type": 32,
        "p_flags": 32,
        "p_offset": 64,
        "p_vaddr": 64,
        "p_paddr": 64,
        "p_filesz": 64,
        "p_memsz": 64,
        "p_align": 64,
    }
    PROGRAM_HEADER_ALIASES = {
        "type": "p_type",
        "flags": "p_flags",
        "offset": "p_offset",
        "vaddr": "p_vaddr",
        "paddr": "p_paddr",
        "filesz": "p_filesz",
        "memsz": "p_memsz",
        "align": "p_align",
    }

    SECTION_HEADER_FIELDS_32 = (
        "sh_name",
        "sh_type",
        "sh_flags",
        "sh_addr",
        "sh_offset",
        "sh_size",
        "sh_link",
        "sh_info",
        "sh_addralign",
        "sh_entsize",
    )
    SECTION_HEADER_FIELDS_64 = (
        "sh_name",
        "sh_type",
        "sh_flags",
        "sh_addr",
        "sh_offset",
        "sh_size",
        "sh_link",
        "sh_info",
        "sh_addralign",
        "sh_entsize",
    )
    SECTION_HEADER_BITS_32 = {
        "sh_name": 32,
        "sh_type": 32,
        "sh_flags": 32,
        "sh_addr": 32,
        "sh_offset": 32,
        "sh_size": 32,
        "sh_link": 32,
        "sh_info": 32,
        "sh_addralign": 32,
        "sh_entsize": 32,
    }
    SECTION_HEADER_BITS_64 = {
        "sh_name": 32,
        "sh_type": 32,
        "sh_flags": 64,
        "sh_addr": 64,
        "sh_offset": 64,
        "sh_size": 64,
        "sh_link": 32,
        "sh_info": 32,
        "sh_addralign": 64,
        "sh_entsize": 64,
    }
    SECTION_HEADER_ALIASES = {
        "name": "sh_name",
        "type": "sh_type",
        "flags": "sh_flags",
        "addr": "sh_addr",
        "offset": "sh_offset",
        "size": "sh_size",
        "link": "sh_link",
        "info": "sh_info",
        "addralign": "sh_addralign",
        "entsize": "sh_entsize",
    }

    def __init__(self, path):
        self.path = Path(path).expanduser()
        self._original_data = self.path.read_bytes()
        self._data = bytearray(self._original_data)
        self._changes = []
        self._load_elf_identity()

    @staticmethod
    def _normalize(field):
        return str(field).strip().lower().replace("-", "_").replace(" ", "_")

    @staticmethod
    def _assert_uint(value, bits, field_name):
        max_value = (1 << bits) - 1
        if value < 0 or value > max_value:
            raise ElfEditError(
                f"Value out of range for {field_name}: {value} (expected 0..{max_value})"
            )

    def _load_elf_identity(self):
        if len(self._data) < 16:
            raise ElfEditError("File is too small to be a valid ELF binary.")
        if bytes(self._data[0:4]) != b"\x7fELF":
            raise ElfEditError("Magic number does not match ELF.")

        ei_class = self._data[4]
        ei_data = self._data[5]
        if ei_class == 1:
            self.elf_class = 32
        elif ei_class == 2:
            self.elf_class = 64
        else:
            raise ElfEditError(f"Unsupported ELF class value: {ei_class}")

        if ei_data == 1:
            self.endian = "<"
            self.endian_name = "little"
        elif ei_data == 2:
            self.endian = ">"
            self.endian_name = "big"
        else:
            raise ElfEditError(f"Unsupported ELF data encoding value: {ei_data}")

        # Validate the primary ELF header is at least present.
        minimum = 0x34 if self.elf_class == 32 else 0x40
        if len(self._data) < minimum:
            raise ElfEditError("File is truncated and does not contain a full ELF header.")

    @property
    def file_size(self):
        return len(self._data)

    @property
    def is_dirty(self):
        return self._data != self._original_data

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

    def _elf_header_fmt(self):
        if self.elf_class == 32:
            return f"{self.endian}HHIIIIIHHHHHH"
        return f"{self.endian}HHIQQQIHHHHHH"

    def _elf_header_bits(self):
        return (
            self.ELF_HEADER_FIELD_BITS_32
            if self.elf_class == 32
            else self.ELF_HEADER_FIELD_BITS_64
        )

    def _program_header_fmt(self):
        if self.elf_class == 32:
            return f"{self.endian}IIIIIIII"
        return f"{self.endian}IIQQQQQQ"

    def _program_header_fields(self):
        if self.elf_class == 32:
            return self.PROGRAM_HEADER_FIELDS_32
        return self.PROGRAM_HEADER_FIELDS_64

    def _program_header_bits(self):
        if self.elf_class == 32:
            return self.PROGRAM_HEADER_BITS_32
        return self.PROGRAM_HEADER_BITS_64

    def _section_header_fmt(self):
        if self.elf_class == 32:
            return f"{self.endian}IIIIIIIIII"
        return f"{self.endian}IIQQQQIIQQ"

    def _section_header_fields(self):
        if self.elf_class == 32:
            return self.SECTION_HEADER_FIELDS_32
        return self.SECTION_HEADER_FIELDS_64

    def _section_header_bits(self):
        if self.elf_class == 32:
            return self.SECTION_HEADER_BITS_32
        return self.SECTION_HEADER_BITS_64

    def _read_struct(self, offset, fmt):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(self._data):
            raise ElfEditError(
                f"Attempted to read beyond file size at offset 0x{offset:x} ({size} bytes)."
            )
        return struct.unpack_from(fmt, self._data, offset)

    def _write_struct(self, offset, fmt, values):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(self._data):
            raise ElfEditError(
                f"Attempted to write beyond file size at offset 0x{offset:x} ({size} bytes)."
            )
        struct.pack_into(fmt, self._data, offset, *values)

    def _require_range(self, offset, length):
        offset = int(offset)
        length = int(length)
        if offset < 0:
            raise ElfEditError("Offset must be >= 0.")
        if length < 0:
            raise ElfEditError("Length must be >= 0.")
        if offset + length > len(self._data):
            raise ElfEditError(
                f"Requested range exceeds file size: offset=0x{offset:x}, length={length}, size={len(self._data)}"
            )
        return offset, length

    def get_elf_header(self):
        fmt = self._elf_header_fmt()
        values = self._read_struct(16, fmt)
        header = {
            "ei_class": self._data[4],
            "ei_data": self._data[5],
            "ei_version": self._data[6],
            "ei_osabi": self._data[7],
            "ei_abiversion": self._data[8],
        }
        for field, value in zip(self.ELF_HEADER_FIELDS, values):
            header[field] = value
        return header

    def _normalize_elf_field(self, field):
        key = self._normalize(field)
        if key in self.ELF_HEADER_ALIASES:
            key = self.ELF_HEADER_ALIASES[key]
        if key in self.E_IDENT_OFFSETS:
            return key
        if not key.startswith("e_"):
            key = f"e_{key}"
        if key not in self.ELF_HEADER_FIELDS:
            valid = sorted(list(self.ELF_HEADER_FIELDS) + list(self.E_IDENT_OFFSETS.keys()))
            raise ElfEditError(f"Unknown ELF header field '{field}'. Valid fields: {', '.join(valid)}")
        return key

    def set_elf_field(self, field, value):
        key = self._normalize_elf_field(field)
        numeric = int(value)

        if key in self.E_IDENT_OFFSETS:
            bits = self.E_IDENT_BITS[key]
            self._assert_uint(numeric, bits, key)
            if key == "ei_class" and numeric not in {1, 2}:
                raise ElfEditError("ei_class must be 1 (ELF32) or 2 (ELF64).")
            if key == "ei_data" and numeric not in {1, 2}:
                raise ElfEditError("ei_data must be 1 (little-endian) or 2 (big-endian).")
            offset = self.E_IDENT_OFFSETS[key]
            old = self._data[offset]
            self._data[offset] = numeric
            self._load_elf_identity()
            self._record_change("elf", None, key, old, numeric)
            return old, numeric

        fmt = self._elf_header_fmt()
        values = list(self._read_struct(16, fmt))
        field_indices = {name: idx for idx, name in enumerate(self.ELF_HEADER_FIELDS)}
        idx = field_indices[key]
        bits = self._elf_header_bits()[key]
        self._assert_uint(numeric, bits, key)
        old = values[idx]
        values[idx] = numeric
        self._write_struct(16, fmt, values)
        self._record_change("elf", None, key, old, numeric)
        return old, numeric

    def _resolve_program_header_bounds(self, index):
        header = self.get_elf_header()
        phoff = header["e_phoff"]
        phentsize = header["e_phentsize"]
        phnum = header["e_phnum"]
        if phnum <= 0:
            raise ElfEditError("ELF contains no program headers.")
        if index < 0 or index >= phnum:
            raise ElfEditError(f"Program header index out of range: {index} (count={phnum})")
        if phentsize <= 0:
            raise ElfEditError("ELF program header entry size is zero.")
        entry_offset = phoff + (index * phentsize)
        if entry_offset + phentsize > len(self._data):
            raise ElfEditError("Program header table is truncated in file data.")
        return entry_offset, phentsize

    def get_program_header(self, index):
        entry_offset, phentsize = self._resolve_program_header_bounds(index)
        fmt = self._program_header_fmt()
        fmt_size = struct.calcsize(fmt)
        if phentsize < fmt_size:
            raise ElfEditError("Program header entry size is smaller than expected structure size.")
        values = struct.unpack_from(fmt, self._data, entry_offset)
        return dict(zip(self._program_header_fields(), values))

    def list_program_headers(self):
        header = self.get_elf_header()
        return [self.get_program_header(index) for index in range(header["e_phnum"])]

    def _normalize_program_header_field(self, field):
        key = self._normalize(field)
        if key in self.PROGRAM_HEADER_ALIASES:
            key = self.PROGRAM_HEADER_ALIASES[key]
        if not key.startswith("p_"):
            key = f"p_{key}"
        if key not in self._program_header_fields():
            valid = ", ".join(self._program_header_fields())
            raise ElfEditError(f"Unknown program header field '{field}'. Valid fields: {valid}")
        return key

    def set_program_header_field(self, index, field, value):
        key = self._normalize_program_header_field(field)
        entry_offset, phentsize = self._resolve_program_header_bounds(index)
        fmt = self._program_header_fmt()
        fmt_size = struct.calcsize(fmt)
        if phentsize < fmt_size:
            raise ElfEditError("Program header entry size is smaller than expected structure size.")

        values = list(struct.unpack_from(fmt, self._data, entry_offset))
        field_indices = {name: idx for idx, name in enumerate(self._program_header_fields())}
        idx = field_indices[key]
        numeric = int(value)
        bits = self._program_header_bits()[key]
        self._assert_uint(numeric, bits, key)
        old = values[idx]
        values[idx] = numeric
        struct.pack_into(fmt, self._data, entry_offset, *values)
        self._record_change("phdr", index, key, old, numeric)
        return old, numeric

    def _resolve_section_header_bounds(self, index):
        header = self.get_elf_header()
        shoff = header["e_shoff"]
        shentsize = header["e_shentsize"]
        shnum = header["e_shnum"]
        if shnum <= 0:
            raise ElfEditError("ELF contains no section headers.")
        if index < 0 or index >= shnum:
            raise ElfEditError(f"Section header index out of range: {index} (count={shnum})")
        if shentsize <= 0:
            raise ElfEditError("ELF section header entry size is zero.")
        entry_offset = shoff + (index * shentsize)
        if entry_offset + shentsize > len(self._data):
            raise ElfEditError("Section header table is truncated in file data.")
        return entry_offset, shentsize

    def _section_name_table_bounds(self):
        header = self.get_elf_header()
        shstrndx = header["e_shstrndx"]
        shnum = header["e_shnum"]
        if shstrndx == 0 or shstrndx >= shnum:
            return None
        shstr = self.get_section_header(shstrndx, resolve_name=False)
        offset = shstr["sh_offset"]
        size = shstr["sh_size"]
        if offset + size > len(self._data):
            return None
        return offset, size

    def _resolve_section_name(self, sh_name):
        bounds = self._section_name_table_bounds()
        if not bounds:
            return "<no-shstrtab>"
        table_offset, table_size = bounds
        if sh_name >= table_size:
            return "<out-of-range>"
        start = table_offset + sh_name
        end = table_offset + table_size
        raw = bytes(self._data[start:end])
        token = raw.split(b"\x00", 1)[0]
        if not token:
            return "<unnamed>"
        return token.decode("utf-8", errors="replace")

    def get_section_header(self, index, resolve_name=True):
        entry_offset, shentsize = self._resolve_section_header_bounds(index)
        fmt = self._section_header_fmt()
        fmt_size = struct.calcsize(fmt)
        if shentsize < fmt_size:
            raise ElfEditError("Section header entry size is smaller than expected structure size.")
        values = struct.unpack_from(fmt, self._data, entry_offset)
        section = dict(zip(self._section_header_fields(), values))
        if resolve_name:
            section["name"] = self._resolve_section_name(section["sh_name"])
        return section

    def list_section_headers(self, resolve_names=True):
        header = self.get_elf_header()
        return [
            self.get_section_header(index, resolve_name=resolve_names)
            for index in range(header["e_shnum"])
        ]

    def section_for_offset(self, offset):
        offset = int(offset)
        if offset < 0 or offset >= len(self._data):
            return None

        for index, section in enumerate(self.list_section_headers(resolve_names=True)):
            sh_offset = int(section.get("sh_offset", 0))
            sh_size = int(section.get("sh_size", 0))
            if sh_size <= 0:
                continue
            if sh_offset <= offset < (sh_offset + sh_size):
                return {
                    "index": index,
                    "name": section.get("name", "<unnamed>"),
                    "offset": sh_offset,
                    "size": sh_size,
                    "address": int(section.get("sh_addr", 0)),
                }
        return None

    def file_offset_to_vaddr(self, offset):
        offset = int(offset)
        if offset < 0 or offset >= len(self._data):
            return None

        section = self.section_for_offset(offset)
        if section and section["address"] > 0:
            return section["address"] + (offset - section["offset"])

        for header in self.list_program_headers():
            p_type = int(header.get("p_type", 0))
            p_offset = int(header.get("p_offset", 0))
            p_filesz = int(header.get("p_filesz", 0))
            p_vaddr = int(header.get("p_vaddr", 0))
            if p_type != 1 or p_filesz <= 0:
                continue
            if p_offset <= offset < (p_offset + p_filesz):
                return p_vaddr + (offset - p_offset)
        return None

    def file_range_to_vaddr_range(self, offset, length):
        offset = int(offset)
        length = int(length)
        if offset < 0 or length <= 0:
            return None
        if offset >= len(self._data):
            return None
        end_offset = min(len(self._data), offset + length) - 1
        start_vaddr = self.file_offset_to_vaddr(offset)
        end_vaddr = self.file_offset_to_vaddr(end_offset)
        if start_vaddr is None or end_vaddr is None:
            return None
        if end_vaddr < start_vaddr:
            return None
        return start_vaddr, end_vaddr + 1

    def read_bytes(self, offset, length):
        offset, length = self._require_range(offset, length)
        return bytes(self._data[offset : offset + length])

    def write_byte(self, offset, value):
        offset, _ = self._require_range(offset, 1)
        numeric = int(value)
        self._assert_uint(numeric, 8, "byte")
        old = self._data[offset]
        self._data[offset] = numeric
        self._record_change("hex", offset, "byte", old, numeric)
        return old, numeric

    def write_bytes(self, offset, payload):
        offset = int(offset)
        if offset < 0:
            raise ElfEditError("Offset must be >= 0.")
        payload_bytes = bytes(payload)
        if not payload_bytes:
            raise ElfEditError("Payload must contain at least one byte.")
        end = offset + len(payload_bytes)
        if end > len(self._data):
            raise ElfEditError(
                f"Payload write exceeds file size: offset=0x{offset:x}, bytes={len(payload_bytes)}, size={len(self._data)}"
            )
        old = bytes(self._data[offset:end])
        self._data[offset:end] = payload_bytes
        self._record_change("hex", offset, "bytes", old.hex(), payload_bytes.hex())
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
        payload = self._decode_hex_text(hex_text)
        return self.write_bytes(offset, payload)

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

    def disassembler_backend(self):
        return "objdump" if self._objdump_path() else "unavailable"

    def disassemble(
        self,
        section=".text",
        max_lines=120,
        start_address=None,
        stop_address=None,
        syntax="intel",
    ):
        objdump = self._objdump_path()
        if not objdump:
            raise ElfEditError("Disassembler unavailable: 'objdump' not found in PATH.")
        if (
            start_address is not None
            and stop_address is not None
            and int(stop_address) <= int(start_address)
        ):
            raise ElfEditError("stop_address must be greater than start_address.")

        with tempfile.NamedTemporaryFile(prefix="elfexplorer-disasm-", suffix=".elf", delete=False) as tmp:
            tmp.write(bytes(self._data))
            tmp_path = Path(tmp.name)

        try:
            command = [objdump, "-d"]
            if syntax:
                command.extend(["-M", str(syntax)])
            if section and str(section).lower() != "all":
                command.extend(["-j", str(section)])
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
                detail = f" {stderr}" if stderr else ""
                raise ElfEditError(f"Disassembly failed with code {completed.returncode}.{detail}")
            rendered = self._render_disassembly_snippet(stdout, max_lines=max_lines)
            if rendered:
                return rendered
            if stderr:
                return f"No disassembly output.\n{stderr}"
            return "No disassembly output."
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _normalize_section_header_field(self, field):
        key = self._normalize(field)
        if key in self.SECTION_HEADER_ALIASES:
            key = self.SECTION_HEADER_ALIASES[key]
        if not key.startswith("sh_"):
            key = f"sh_{key}"
        if key not in self._section_header_fields():
            valid = ", ".join(self._section_header_fields())
            raise ElfEditError(f"Unknown section header field '{field}'. Valid fields: {valid}")
        return key

    def set_section_header_field(self, index, field, value):
        key = self._normalize_section_header_field(field)
        entry_offset, shentsize = self._resolve_section_header_bounds(index)
        fmt = self._section_header_fmt()
        fmt_size = struct.calcsize(fmt)
        if shentsize < fmt_size:
            raise ElfEditError("Section header entry size is smaller than expected structure size.")

        values = list(struct.unpack_from(fmt, self._data, entry_offset))
        field_indices = {name: idx for idx, name in enumerate(self._section_header_fields())}
        idx = field_indices[key]
        numeric = int(value)
        bits = self._section_header_bits()[key]
        self._assert_uint(numeric, bits, key)
        old = values[idx]
        values[idx] = numeric
        struct.pack_into(fmt, self._data, entry_offset, *values)
        self._record_change("shdr", index, key, old, numeric)
        return old, numeric

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
        if offset >= len(self._data):
            return ""

        end = min(len(self._data), offset + length)
        lines = []
        for base in range(offset, end, width):
            chunk = self._data[base : min(base + width, end)]
            hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            lines.append(f"{base:08x}  {hex_bytes:<{(width * 3) - 1}}  |{ascii_text}|")
        return "\n".join(lines)

    def revert(self):
        self._data = bytearray(self._original_data)
        self._changes.clear()
        self._load_elf_identity()

    def save(self, path=None):
        if path:
            target = Path(path).expanduser()
        else:
            target = self.path.with_name(f"{self.path.name}.modified")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bytes(self._data))
        return target.resolve()

    def status(self):
        header = self.get_elf_header()
        return {
            "path": str(self.path),
            "size": len(self._data),
            "elf_class": self.elf_class,
            "endianness": self.endian_name,
            "program_headers": header["e_phnum"],
            "section_headers": header["e_shnum"],
            "dirty": self.is_dirty,
            "change_count": self.change_count,
            "disassembler": self.disassembler_backend(),
        }
