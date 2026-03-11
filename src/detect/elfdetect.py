from symbols.elfsymbols import scan_symbols

SUPPORTED_LANGUAGES = (
    "C",
    "C++",
    "Rust",
    "Go",
    "D",
    "Ada",
    "Fortran",
    "Nim",
    "Swift",
    "Java",
    "Python",
    "SageLang",
)

NOTE_SECTIONS = {
    ".note.go.buildid": "Go",
    ".note.rustc": "Rust",
    ".note.dmd": "D",
    ".note.nim": "Nim",
    ".note.swift": "Swift",
    ".note.java": "Java",
    ".note.python": "Python",
    ".note.sagelang": "SageLang",
}

SAGELANG_STRING_SCAN_SECTIONS = (
    ".rodata",
    ".strtab",
    ".dynstr",
    ".debug_str",
)

SAGELANG_RUNTIME_STRINGS = (
    b"unhandled exception:",
    b"runtime error: undefined variable",
    b"runtime error: method call on non-instance.",
    b"runtime error: no __class__ on instance.",
    b"too many classes",
)

SAGELANG_STRONG_STRING_MARKERS = (
    b"sage_try_stack",
    b"sage_exception_value",
    b"sage_method_table",
    b"sage_class_registry",
    b"sage_slot_undefined",
)


def _empty_scores():
    return {language: 0 for language in SUPPORTED_LANGUAGES}


def _score_comment_section(elf, scores):
    comment_sec = elf.get_section_by_name(".comment")
    if not comment_sec:
        return

    try:
        data = comment_sec.data().decode(errors="ignore").lower()
        if "gcc" in data or "gnu" in data:
            scores["C"] += 3
            scores["C++"] += 1
        if "clang" in data:
            scores["C"] += 3
            scores["C++"] += 1
        if "rustc" in data:
            scores["Rust"] += 3
        if "go build" in data or "golang" in data:
            scores["Go"] += 3
        if "dmd" in data or "ldc" in data:
            scores["D"] += 3
        if "gnat" in data:
            scores["Ada"] += 3
        if "gfortran" in data:
            scores["Fortran"] += 3
        if "nim" in data:
            scores["Nim"] += 3
        if "swift" in data:
            scores["Swift"] += 3
        if "javac" in data or "openjdk" in data:
            scores["Java"] += 3
        if "python" in data:
            scores["Python"] += 3
        if "sagelang" in data or "sage compiler" in data:
            scores["SageLang"] += 6
    except Exception as exc:
        print(f"Error reading .comment section: {exc}")


def _score_note_sections(elf, scores):
    for section_name, language in NOTE_SECTIONS.items():
        if elf.get_section_by_name(section_name):
            scores[language] += 5

    if elf.get_section_by_name(".sagelang") or elf.get_section_by_name(".sage"):
        scores["SageLang"] += 5


def _score_dynamic_section(elf, scores):
    dynamic = elf.get_section_by_name(".dynamic")
    if not dynamic:
        return

    try:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag != "DT_NEEDED":
                continue

            needed = tag.needed.lower()
            if "stdc++" in needed or "libc++" in needed:
                scores["C++"] += 3
            if "c++" in needed:
                scores["C++"] += 2
            if "rust" in needed:
                scores["Rust"] += 3
            if "go" in needed:
                scores["Go"] += 3
            if "dmd" in needed or "libphobos" in needed:
                scores["D"] += 3
            if "gnat" in needed:
                scores["Ada"] += 3
            if "gfortran" in needed:
                scores["Fortran"] += 3
            if "nim" in needed:
                scores["Nim"] += 3
            if "swift" in needed:
                scores["Swift"] += 3
            if "jvm" in needed or "java" in needed:
                scores["Java"] += 3
            if "python" in needed:
                scores["Python"] += 3
            if "libsage" in needed or "sagelang" in needed:
                scores["SageLang"] += 4
    except Exception as exc:
        print(f"Error processing dynamic section: {exc}")


def _score_symbol_tables(elf, scores):
    symtab = elf.get_section_by_name(".symtab")
    if symtab:
        try:
            scan_symbols(symtab.iter_symbols(), scores)
        except Exception as exc:
            print(f"Error processing .symtab: {exc}")

    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym:
        try:
            scan_symbols(dynsym.iter_symbols(), scores)
        except Exception as exc:
            print(f"Error processing .dynsym: {exc}")

    return symtab, dynsym


def _score_sagelang_strings(elf, scores):
    runtime_hits = set()
    strong_hits = set()
    sage_token_score = 0
    sage_substring_count = 0

    for section_name in SAGELANG_STRING_SCAN_SECTIONS:
        section = elf.get_section_by_name(section_name)
        if not section:
            continue

        try:
            data = section.data()[:262144].lower()
        except Exception as exc:
            print(f"Error reading {section_name}: {exc}")
            continue

        for marker in SAGELANG_RUNTIME_STRINGS:
            if marker in data:
                runtime_hits.add(marker)

        for marker in SAGELANG_STRONG_STRING_MARKERS:
            if marker in data:
                strong_hits.add(marker)

        if b"sagelang" in data or b"sage compiler" in data:
            sage_token_score += 2
        if b"sagec_" in data and b".c" in data:
            sage_token_score += 2

        sage_substring_count += data.count(b"sage_")

    if len(runtime_hits) >= 4:
        scores["SageLang"] += 8
    elif len(runtime_hits) >= 2:
        scores["SageLang"] += 4

    if len(strong_hits) >= 4:
        scores["SageLang"] += 8
    elif len(strong_hits) >= 2:
        scores["SageLang"] += 4

    if sage_token_score >= 4:
        scores["SageLang"] += 8
    elif sage_token_score >= 2:
        scores["SageLang"] += 4

    if sage_substring_count >= 20:
        scores["SageLang"] += 8
    elif sage_substring_count >= 8:
        scores["SageLang"] += 4


def _score_debug_info(elf, scores):
    debug_info_sec = elf.get_section_by_name(".debug_info")
    if not debug_info_sec:
        return

    try:
        data = debug_info_sec.data()[:4096].lower()
        if b"rustc" in data:
            scores["Rust"] += 5
        if b"gcc" in data or b"gnu" in data:
            scores["C"] += 2
            scores["C++"] += 1
        if b"clang" in data:
            scores["C"] += 2
            scores["C++"] += 1
        if b"dmd" in data or b"ldc" in data:
            scores["D"] += 2
        if b"gnat" in data:
            scores["Ada"] += 2
        if b"gfortran" in data:
            scores["Fortran"] += 2
        if b"nim" in data:
            scores["Nim"] += 2
        if b"swift" in data:
            scores["Swift"] += 2
        if b"javac" in data or b"openjdk" in data:
            scores["Java"] += 2
        if b"python" in data:
            scores["Python"] += 2
        if b"sagelang" in data or b"sage compiler" in data:
            scores["SageLang"] += 5
    except Exception as exc:
        print(f"Error reading .debug_info: {exc}")


def _score_section_names(elf, scores):
    for section in elf.iter_sections():
        section_name = section.name.lower()
        if section_name in [".eh_frame", ".gcc_except_table"]:
            scores["C++"] += 1
            scores["Rust"] += 1
        if section_name.startswith(".rodata.str1."):
            scores["Go"] += 1
        if section_name == ".dlang":
            scores["D"] += 2
        if section_name == ".gnat":
            scores["Ada"] += 2
        if section_name == ".gfortran":
            scores["Fortran"] += 2
        if section_name == ".nim":
            scores["Nim"] += 2
        if section_name == ".swift":
            scores["Swift"] += 2
        if section_name in [".jvm", ".java"]:
            scores["Java"] += 2
        if section_name == ".python":
            scores["Python"] += 2
        if section_name in [".note.sagelang", ".sagelang", ".sage"]:
            scores["SageLang"] += 4


def detect_source_language(elf):
    """
    Attempt to deduce the original source language of an ELF binary using heuristics.
    Returns a string indicating the detected language.
    """
    scores = _empty_scores()

    _score_comment_section(elf, scores)
    _score_note_sections(elf, scores)
    _score_dynamic_section(elf, scores)
    symtab, dynsym = _score_symbol_tables(elf, scores)
    _score_sagelang_strings(elf, scores)
    _score_debug_info(elf, scores)
    _score_section_names(elf, scores)

    has_symbols = False
    if symtab and symtab.num_symbols() > 0:
        has_symbols = True
    elif dynsym and dynsym.num_symbols() > 0:
        has_symbols = True

    print("Language detection scores:")
    for language, score in scores.items():
        print(f"  {language}: {score}")

    max_score = max(scores.values())
    top_languages = [
        language for language, score in scores.items() if score == max_score and score > 0
    ]

    if not has_symbols and max_score < 2:
        print("Warning: Binary appears stripped; detection may be unreliable.")

    if len(top_languages) == 1:
        return top_languages[0]
    if len(top_languages) > 1:
        return "Ambiguous: " + "/".join(top_languages)
    return "C"
