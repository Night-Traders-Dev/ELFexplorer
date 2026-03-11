import math


def _byte_entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    total = float(len(data))
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log(p, 2)
    return entropy


def detect_binary_hardening(elf):
    signals = []
    section_names = [section.name for section in elf.iter_sections()]
    has_debug = any(name.startswith(".debug") for name in section_names)

    symtab = elf.get_section_by_name(".symtab")
    dynsym = elf.get_section_by_name(".dynsym")
    sym_count = 0
    if symtab:
        try:
            sym_count += max(0, symtab.num_symbols() - 1)
        except Exception:
            pass
    if dynsym:
        try:
            sym_count += max(0, dynsym.num_symbols() - 1)
        except Exception:
            pass
    stripped = sym_count == 0 and not has_debug
    if stripped:
        signals.append("no symbol tables and no debug sections (likely stripped)")

    text = elf.get_section_by_name(".text")
    text_entropy = 0.0
    if text:
        try:
            text_entropy = _byte_entropy(text.data()[:131072])
        except Exception:
            text_entropy = 0.0
    if text_entropy > 7.2:
        signals.append(f"high .text entropy ({text_entropy:.2f})")

    upx_markers = any(name.lower().startswith(".upx") for name in section_names)
    if upx_markers:
        signals.append("UPX section markers found")

    lto_markers = any(".gnu.lto" in name for name in section_names)
    if lto_markers:
        signals.append("LTO section markers found")

    suspicious_names = 0
    for name in section_names:
        if not name:
            continue
        clean = name.replace(".", "").replace("_", "")
        if clean and clean.isalnum() and len(clean) > 10 and clean.lower() == clean:
            suspicious_names += 1

    likely_packed = upx_markers or text_entropy > 7.6
    likely_obfuscated = suspicious_names >= 2 and stripped

    if likely_packed:
        signals.append("binary appears packed/compressed")
    if likely_obfuscated:
        signals.append("binary appears obfuscated/renamed")

    risk_level = "low"
    risk_score = 0
    if stripped:
        risk_score += 1
    if likely_packed:
        risk_score += 2
    if likely_obfuscated:
        risk_score += 2
    if risk_score >= 4:
        risk_level = "high"
    elif risk_score >= 2:
        risk_level = "medium"

    return {
        "stripped": stripped,
        "has_debug": has_debug,
        "symbol_count": sym_count,
        "text_entropy": round(text_entropy, 4),
        "upx_markers": upx_markers,
        "lto_markers": lto_markers,
        "likely_packed": likely_packed,
        "likely_obfuscated": likely_obfuscated,
        "risk_level": risk_level,
        "signals": signals,
    }

