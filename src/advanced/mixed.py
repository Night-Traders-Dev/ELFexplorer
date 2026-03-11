import re


LANGUAGE_MARKERS = {
    "Rust": (b"rustc", b"core::", b"alloc::", b"panicking.rs"),
    "Go": (b"go.buildid", b"runtime.main", b"go.string.", b"go.itab"),
    "C++": (b"_z", b"std::", b"__cxa_", b"typeinfo"),
    "C": (b"__libc_start_main", b"printf", b"scanf"),
    "Dart": (b"dart_", b"isolate", b"libdart"),
    "Nim": (b"nimmain", b"nimrtl"),
    "Zig": (b"zig", b"__zig_"),
    "ASM": (b"nasm", b"fasm", b"masm", b"tasm"),
}

COMPILER_MARKERS = {
    "GCC": (b"gcc", b"collect2"),
    "Clang": (b"clang", b"compiler-rt"),
    "Rustc": (b"rustc",),
    "Go gc": (b"go build", b"go tool"),
    "Zig": (b"zig",),
}

SYMBOL_LANGUAGE_PATTERNS = {
    "Rust": (re.compile(r"^_?ZN"), re.compile(r"^rust_"), re.compile(r"core::|alloc::")),
    "Go": (re.compile(r"^runtime\."), re.compile(r"^go\."), re.compile(r"go\.itab")),
    "C++": (re.compile(r"^_Z"), re.compile(r"std::"), re.compile(r"__cxa_")),
    "Nim": (re.compile(r"^nim"), re.compile(r"nimmain")),
    "Dart": (re.compile(r"dart", re.IGNORECASE),),
    "Zig": (re.compile(r"zig", re.IGNORECASE),),
}


def _best_label(score_map):
    if not score_map:
        return "Unknown", 0
    label, score = max(score_map.items(), key=lambda item: item[1])
    if score <= 0:
        return "Unknown", 0
    return label, score


def _score_blob(blob, marker_map):
    scores = {name: 0 for name in marker_map}
    if not blob:
        return scores
    lower = blob.lower()
    for name, markers in marker_map.items():
        for marker in markers:
            if marker in lower:
                scores[name] += 1
    return scores


def _iter_symbol_names(elf):
    for sec_name in (".symtab", ".dynsym"):
        section = elf.get_section_by_name(sec_name)
        if not section:
            continue
        try:
            for symbol in section.iter_symbols():
                name = symbol.name
                if name:
                    yield name
        except Exception:
            continue


def detect_mixed_attribution(elf, max_sections=24, max_symbols=2000):
    section_hints = []
    for section in elf.iter_sections():
        if len(section_hints) >= max_sections:
            break
        name = section.name or "<unnamed>"
        try:
            size = int(section["sh_size"])
        except Exception:
            size = 0
        if size <= 0:
            continue
        if name.startswith(".debug"):
            continue
        try:
            data = section.data()[:65536]
        except Exception:
            continue
        lang_scores = _score_blob(data, LANGUAGE_MARKERS)
        comp_scores = _score_blob(data, COMPILER_MARKERS)
        lang, lang_score = _best_label(lang_scores)
        compiler, compiler_score = _best_label(comp_scores)
        if lang_score <= 0 and compiler_score <= 0:
            continue
        section_hints.append(
            {
                "section": name,
                "size": size,
                "language_hint": lang,
                "language_score": lang_score,
                "compiler_hint": compiler,
                "compiler_score": compiler_score,
            }
        )

    symbol_scores = {label: 0 for label in SYMBOL_LANGUAGE_PATTERNS}
    symbol_sample = []
    for index, name in enumerate(_iter_symbol_names(elf)):
        if index >= max_symbols:
            break
        lowered = name.lower()
        for label, patterns in SYMBOL_LANGUAGE_PATTERNS.items():
            if any(pattern.search(lowered) for pattern in patterns):
                symbol_scores[label] += 1
        if len(symbol_sample) < 12:
            symbol_sample.append(name)

    lang, lang_score = _best_label(symbol_scores)
    return {
        "section_hints": section_hints,
        "symbol_language_scores": symbol_scores,
        "symbol_dominant_language": lang,
        "symbol_dominant_score": lang_score,
        "symbol_sample": symbol_sample,
    }

