from pathlib import Path


TOOL_PLUGIN_FORMATS = {
    "binaryninja": {
        "label": "Binary Ninja Script",
        "extension": ".py",
        "description": "Python script for Binary Ninja user symbols and comments.",
    },
    "ghidra": {
        "label": "Ghidra Script",
        "extension": ".py",
        "description": "GhidraScript-compatible Python import script.",
    },
    "ida-python": {
        "label": "IDA Python Script",
        "extension": ".py",
        "description": "IDAPython import script for names and comments.",
    },
    "radare2": {
        "label": "radare2 Script",
        "extension": ".r2",
        "description": "radare2 command script for flags and comments.",
    },
    "cutter": {
        "label": "Cutter/Rizin Script",
        "extension": ".rz",
        "description": "Cutter/Rizin command script for labels and comments.",
    },
    "imhex": {
        "label": "ImHex Section Map",
        "extension": ".csv",
        "description": "CSV memory/section map import for ImHex and related tools.",
    },
}


def list_tool_plugin_formats():
    return dict(TOOL_PLUGIN_FORMATS)


def _coerce_int(value, default=None):
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        try:
            return int(str(value), 0)
        except Exception:
            return default


def _sanitize_name(name):
    cleaned = "".join(ch if (ch.isalnum() or ch in {"_", ".", ":"}) else "_" for ch in str(name))
    return cleaned.strip("_") or "unknown_symbol"


def _script_string(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _collect_symbol_entries(report, limit=256):
    scan = report.get("scan_result", {})
    merged = scan.get("re_annotations_merged", {})
    scan_map = scan.get("binary_map", {})
    candidates = merged.get("symbols") or scan_map.get("symbols", [])
    seen = set()
    entries = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("label") or item.get("symbol")
        address = _coerce_int(item.get("value", item.get("address")))
        if not name or address is None or address < 0:
            continue
        key = (str(name), address)
        if key in seen:
            continue
        seen.add(key)
        entries.append({"name": _sanitize_name(name), "address": address})
        if len(entries) >= limit:
            break
    return entries


def _collect_comment_entries(report, limit=128):
    scan = report.get("scan_result", {})
    merged = scan.get("re_annotations_merged", {})
    scan_map = scan.get("binary_map", {})
    comments = []
    seen = set()

    entry_point = _coerce_int(scan_map.get("entry_point"))
    artifact = scan.get("artifact_profile", {})
    summary = (
        "ELFexplorer "
        f"lang={scan.get('source_language', 'Unknown')} "
        f"compiler={scan.get('compiler', 'Unknown')} "
        f"build={scan.get('build_system', 'Unknown')} "
        f"artifact={artifact.get('artifact_type', 'Unknown')} "
        f"confidence={artifact.get('confidence', 0)}"
    )
    if entry_point is not None:
        comments.append({"address": entry_point, "text": summary})
        seen.add((entry_point, summary))

    for item in merged.get("comments", []):
        if not isinstance(item, dict):
            continue
        address = _coerce_int(item.get("address", item.get("value")))
        text = item.get("text") or item.get("comment") or item.get("body") or item.get("contents")
        if address is None or not text:
            continue
        key = (address, str(text))
        if key in seen:
            continue
        seen.add(key)
        comments.append({"address": address, "text": str(text)})
        if len(comments) >= limit:
            break
    return comments[:limit]


def _collect_section_rows(report, limit=512):
    scan = report.get("scan_result", {})
    scan_map = scan.get("binary_map", {})
    rows = []
    for item in scan_map.get("sections", [])[:limit]:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "name": item.get("name", "<unnamed>"),
                "offset": _coerce_int(item.get("offset"), 0),
                "size": _coerce_int(item.get("size"), 0),
                "address": _coerce_int(item.get("address"), 0),
                "type": item.get("type", "unknown"),
            }
        )
    return rows


def _build_binaryninja_script(report):
    symbols = _collect_symbol_entries(report)
    comments = _collect_comment_entries(report)
    symbol_lines = ",\n    ".join(
        f'{{"name": "{_script_string(item["name"])}", "address": 0x{item["address"]:x}}}'
        for item in symbols
    )
    comment_lines = ",\n    ".join(
        f'{{"address": 0x{item["address"]:x}, "text": "{_script_string(item["text"])}"}}'
        for item in comments
    )
    return (
        "# ELFexplorer Binary Ninja integration script\n"
        "# Run this with `bv` bound to the active BinaryView.\n"
        "from binaryninja import Symbol, SymbolType\n\n"
        f"symbols = [{symbol_lines}]\n"
        f"comments = [{comment_lines}]\n\n"
        "current_bv = globals().get('bv')\n"
        "if current_bv is None:\n"
        "    raise RuntimeError('Run this script from Binary Ninja with `bv` available.')\n\n"
        "for item in symbols:\n"
        "    addr = int(item['address'])\n"
        "    name = item['name']\n"
        "    try:\n"
        "        func = current_bv.get_function_at(addr)\n"
        "        if func is not None:\n"
        "            func.name = name\n"
        "        current_bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))\n"
        "    except Exception:\n"
        "        pass\n\n"
        "for item in comments:\n"
        "    try:\n"
        "        current_bv.set_comment_at(int(item['address']), item['text'])\n"
        "    except Exception:\n"
        "        pass\n\n"
        "current_bv.update_analysis_and_wait()\n"
        "print('ELFexplorer import applied.')\n"
    )


def _build_ghidra_script(report):
    symbols = _collect_symbol_entries(report)
    comments = _collect_comment_entries(report)
    symbol_lines = ",\n    ".join(
        f'{{"name": "{_script_string(item["name"])}", "address": 0x{item["address"]:x}}}'
        for item in symbols
    )
    comment_lines = ",\n    ".join(
        f'{{"address": 0x{item["address"]:x}, "text": "{_script_string(item["text"])}"}}'
        for item in comments
    )
    return (
        "#@category ELFexplorer\n"
        "# ELFexplorer Ghidra import script\n"
        "from ghidra.program.model.symbol import SourceType\n\n"
        f"symbols = [{symbol_lines}]\n"
        f"comments = [{comment_lines}]\n\n"
        "for item in symbols:\n"
        "    addr = toAddr(int(item['address']))\n"
        "    try:\n"
        "        createLabel(addr, item['name'], True)\n"
        "    except Exception:\n"
        "        pass\n"
        "    func = getFunctionAt(addr)\n"
        "    if func is not None:\n"
        "        try:\n"
        "            func.setName(item['name'], SourceType.USER_DEFINED)\n"
        "        except Exception:\n"
        "            pass\n\n"
        "for item in comments:\n"
        "    addr = toAddr(int(item['address']))\n"
        "    try:\n"
        "        setEOLComment(addr, item['text'])\n"
        "    except Exception:\n"
        "        pass\n\n"
        "print('ELFexplorer import applied.')\n"
    )


def _build_ida_python_script(report):
    symbols = _collect_symbol_entries(report)
    comments = _collect_comment_entries(report)
    symbol_lines = ",\n    ".join(
        f'{{"name": "{_script_string(item["name"])}", "address": 0x{item["address"]:x}}}'
        for item in symbols
    )
    comment_lines = ",\n    ".join(
        f'{{"address": 0x{item["address"]:x}, "text": "{_script_string(item["text"])}"}}'
        for item in comments
    )
    return (
        "# ELFexplorer IDAPython import script\n"
        "import ida_bytes\n"
        "import ida_kernwin\n"
        "import ida_name\n\n"
        f"symbols = [{symbol_lines}]\n"
        f"comments = [{comment_lines}]\n\n"
        "for item in symbols:\n"
        "    try:\n"
        "        ida_name.set_name(int(item['address']), item['name'], ida_name.SN_NOWARN)\n"
        "    except Exception:\n"
        "        pass\n\n"
        "for item in comments:\n"
        "    try:\n"
        "        ida_bytes.set_cmt(int(item['address']), item['text'], 0)\n"
        "    except Exception:\n"
        "        pass\n\n"
        "ida_kernwin.msg('ELFexplorer import applied.\\n')\n"
    )


def _build_r2_script(report, tool_name):
    symbols = _collect_symbol_entries(report)
    comments = _collect_comment_entries(report)
    lines = [
        f"# ELFexplorer {tool_name} import script",
        "aaa",
        "fs elfexplorer",
    ]
    for item in symbols:
        lines.append(f"f elfexplorer.{_sanitize_name(item['name'])} 0 @ 0x{item['address']:x}")
    for item in comments:
        text = str(item["text"]).replace("\n", " ").replace('"', "'")
        lines.append(f'CC {text} @ 0x{item["address"]:x}')
    lines.append("fs *")
    return "\n".join(lines) + "\n"


def _build_imhex_map(report):
    rows = _collect_section_rows(report)
    symbols = _collect_symbol_entries(report, limit=128)
    lines = ["kind,name,file_offset,size,virtual_address,type"]
    for item in rows:
        lines.append(
            "section,"
            f"{item['name']},0x{item['offset']:x},0x{item['size']:x},0x{item['address']:x},{item['type']}"
        )
    for item in symbols:
        lines.append(f"symbol,{item['name']},,0x0,0x{item['address']:x},symbol")
    return "\n".join(lines) + "\n"


def build_tool_plugin(report, tool_format):
    tool_format = str(tool_format).strip().lower()
    if tool_format not in TOOL_PLUGIN_FORMATS:
        raise ValueError(
            f"Unsupported tool plugin format '{tool_format}'. "
            f"Choose from: {', '.join(sorted(TOOL_PLUGIN_FORMATS))}"
        )
    if tool_format == "binaryninja":
        return _build_binaryninja_script(report)
    if tool_format == "ghidra":
        return _build_ghidra_script(report)
    if tool_format == "ida-python":
        return _build_ida_python_script(report)
    if tool_format == "radare2":
        return _build_r2_script(report, "radare2")
    if tool_format == "cutter":
        return _build_r2_script(report, "Cutter/Rizin")
    if tool_format == "imhex":
        return _build_imhex_map(report)
    raise ValueError(f"Unhandled tool plugin format: {tool_format}")


def default_tool_plugin_path(report, tool_format, output_dir=None):
    tool_format = str(tool_format).strip().lower()
    meta = TOOL_PLUGIN_FORMATS.get(tool_format)
    if not meta:
        raise ValueError(f"Unsupported tool plugin format: {tool_format}")
    source = Path(report.get("file", "scan"))
    stem = "".join(ch if (ch.isalnum() or ch in {"-", "_"}) else "_" for ch in (source.stem or "scan"))
    directory = Path(output_dir) if output_dir else (Path.cwd() / "reports")
    suffix = tool_format.replace("/", "-")
    return directory / f"{stem}-{suffix}{meta['extension']}"


def export_tool_plugin(report, path, tool_format):
    out_path = Path(path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(build_tool_plugin(report, tool_format), encoding="utf-8")
    return out_path
