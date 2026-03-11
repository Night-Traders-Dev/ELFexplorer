import re

from symbols.elfsymbols import scan_symbols

SUPPORTED_LANGUAGES = (
    "ASM",
    "C",
    "C++",
    "C#",
    "Rust",
    "Go",
    "Dart",
    "D",
    "Ada",
    "Fortran",
    "Nim",
    "Zig",
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

COMPILER_HEURISTICS = ("GCC", "Clang")

SAGELANG_STRING_SCAN_SECTIONS = (
    ".rodata",
    ".strtab",
    ".dynstr",
    ".debug_str",
    ".comment",
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

SAGELANG_TOKEN_PATTERN = re.compile(rb"(?<![a-z0-9_])sage_[a-z0-9_]+")
SAGELANG_GENERATED_C_PATTERN = re.compile(rb"(?<![a-z0-9_])sagec_[0-9]+\.c(?![a-z0-9_])")
DART_TOKEN_PATTERN = re.compile(rb"(?<![a-z0-9_])dart_[a-z0-9_]+")
ZIG_TOKEN_PATTERN = re.compile(rb"(?<![a-z0-9_])(?:__)?zig_[a-z0-9_]+")

DART_STRONG_MARKERS = (
    b"dart_initialize",
    b"dart_createisolategroup",
    b"dart_loadscriptfromkernel",
    b"dart_createappaotsnapshotasassembly",
    b"dart_versionstring",
)

CSHARP_STRING_MARKERS = (
    b"system.private.corelib",
    b"microsoft.netcore.app",
    b"coreclr",
    b"hostfxr",
    b"hostpolicy",
    b"mono",
    b"dotnet",
    b"mscorlib",
)

NIM_STRING_MARKERS = (
    b"nimmain",
    b"nimmaininner",
    b"nimrtl",
    b"nim_gc",
    b"nimcache",
)

ZIG_STRING_MARKERS = (
    b"ziglang",
    b"__zig_",
    b"zig_stack",
)


def _empty_scores():
    return {language: 0 for language in SUPPORTED_LANGUAGES}


def _empty_compiler_scores():
    return {compiler: 0 for compiler in COMPILER_HEURISTICS}


def _read_section_data(elf, section_name, max_bytes=262144):
    section = elf.get_section_by_name(section_name)
    if not section:
        return None

    try:
        return section.data()[:max_bytes].lower()
    except Exception as exc:
        print(f"Error reading {section_name}: {exc}")
        return None


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
        if "zig" in data or "ziglang" in data:
            scores["Zig"] += 4
        if "dart" in data:
            scores["Dart"] += 2
        if "dotnet" in data or "coreclr" in data or "mono" in data:
            scores["C#"] += 3
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

    needed_libs = set()
    try:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag != "DT_NEEDED":
                continue

            needed = tag.needed.lower()
            needed_libs.add(needed)
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
            if "coreclr" in needed or "hostfxr" in needed or "hostpolicy" in needed or "mono" in needed:
                scores["C#"] += 6
            if "libdart" in needed:
                scores["Dart"] += 6
            if "libnim" in needed:
                scores["Nim"] += 4
            if "libzig" in needed:
                scores["Zig"] += 4

        # Plain libc-only dynamically linked binaries are usually C/asm programs.
        if needed_libs == {"libc.so.6"}:
            scores["C"] += 2
    except Exception as exc:
        print(f"Error processing dynamic section: {exc}")


def _score_symbol_tables(elf, scores):
    seen_names = set()

    symtab = elf.get_section_by_name(".symtab")
    if symtab:
        try:
            scan_symbols(symtab.iter_symbols(), scores, seen_names=seen_names)
        except Exception as exc:
            print(f"Error processing .symtab: {exc}")

    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym:
        try:
            scan_symbols(dynsym.iter_symbols(), scores, seen_names=seen_names)
        except Exception as exc:
            print(f"Error processing .dynsym: {exc}")

    return symtab, dynsym


def _collect_symbol_names(symtab, dynsym):
    names = set()
    for section in (symtab, dynsym):
        if not section:
            continue
        try:
            for symbol in section.iter_symbols():
                name = symbol.name.lower()
                if name:
                    names.add(name)
        except Exception as exc:
            print(f"Error collecting symbol names: {exc}")
    return names


def _score_general_language_strings(elf, scores):
    dart_markers = set()
    csharp_markers = set()
    nim_markers = set()
    zig_markers = set()
    dart_token_count = 0
    zig_token_count = 0

    for section_name in SAGELANG_STRING_SCAN_SECTIONS:
        data = _read_section_data(elf, section_name)
        if not data:
            continue

        for marker in DART_STRONG_MARKERS:
            if marker in data:
                dart_markers.add(marker)
        for marker in CSHARP_STRING_MARKERS:
            if marker in data:
                csharp_markers.add(marker)
        for marker in NIM_STRING_MARKERS:
            if marker in data:
                nim_markers.add(marker)
        for marker in ZIG_STRING_MARKERS:
            if marker in data:
                zig_markers.add(marker)

        dart_token_count += len(DART_TOKEN_PATTERN.findall(data))
        zig_token_count += len(ZIG_TOKEN_PATTERN.findall(data))

    if len(dart_markers) >= 2:
        scores["Dart"] += 8
    elif len(dart_markers) >= 1:
        scores["Dart"] += 4

    if dart_token_count >= 20:
        scores["Dart"] += 10
    elif dart_token_count >= 6:
        scores["Dart"] += 6
    elif dart_token_count >= 2:
        scores["Dart"] += 3

    if len(csharp_markers) >= 3:
        scores["C#"] += 8
    elif len(csharp_markers) >= 1:
        scores["C#"] += 4

    if len(nim_markers) >= 2:
        scores["Nim"] += 5
    elif len(nim_markers) >= 1:
        scores["Nim"] += 2

    if len(zig_markers) >= 1:
        scores["Zig"] += 4

    if zig_token_count >= 8:
        scores["Zig"] += 6
    elif zig_token_count >= 2:
        scores["Zig"] += 3


def _score_sagelang_strings(elf, scores):
    runtime_hits = set()
    strong_hits = set()
    sage_token_score = 0
    sage_substring_count = 0

    for section_name in SAGELANG_STRING_SCAN_SECTIONS:
        data = _read_section_data(elf, section_name)
        if not data:
            continue

        for marker in SAGELANG_RUNTIME_STRINGS:
            if marker in data:
                runtime_hits.add(marker)

        for marker in SAGELANG_STRONG_STRING_MARKERS:
            if marker in data:
                strong_hits.add(marker)

        if b"sagelang" in data or b"sage compiler" in data:
            sage_token_score += 2
        if SAGELANG_GENERATED_C_PATTERN.search(data):
            sage_token_score += 2

        sage_substring_count += len(SAGELANG_TOKEN_PATTERN.findall(data))

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

    # Runtime error phrases can appear in non-Sage binaries (e.g. other VMs).
    # Only trust them when paired with at least one Sage-specific anchor.
    has_sage_anchor = bool(strong_hits) or sage_token_score > 0 or sage_substring_count > 0
    if has_sage_anchor:
        if len(runtime_hits) >= 4:
            scores["SageLang"] += 8
        elif len(runtime_hits) >= 2:
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
        if b"dart_" in data or b"dart " in data:
            scores["Dart"] += 3
        if b"zig" in data:
            scores["Zig"] += 2
        if b"coreclr" in data or b"dotnet" in data or b"mono" in data:
            scores["C#"] += 3
    except Exception as exc:
        print(f"Error reading .debug_info: {exc}")


def _score_section_names(elf, scores):
    for section in elf.iter_sections():
        section_name = section.name.lower()
        if section_name == ".gcc_except_table":
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
        if section_name in [".note.dart", ".dart", ".dart_aot"]:
            scores["Dart"] += 4
        if section_name in [".cil", ".net", ".dotnet"]:
            scores["C#"] += 4
        if section_name in [".zig", ".zig_info"]:
            scores["Zig"] += 4


def _score_asm_patterns(elf, symtab, dynsym, scores):
    symbol_names = _collect_symbol_names(symtab, dynsym)
    has_start = "_start" in symbol_names
    has_main = "main" in symbol_names
    has_dynamic = elf.get_section_by_name(".dynamic") is not None
    has_interp = elf.get_section_by_name(".interp") is not None
    section_count = sum(1 for _ in elf.iter_sections())

    if has_start and not has_main:
        scores["ASM"] += 3

    if has_start and not has_main and not has_dynamic and not has_interp:
        scores["ASM"] += 8

    if has_start and not has_main and section_count <= 10:
        scores["ASM"] += 6

    if has_main:
        scores["ASM"] = max(0, scores["ASM"] - 2)


def _score_compiler_comment(elf, compiler_scores):
    data = _read_section_data(elf, ".comment", max_bytes=65536)
    if not data:
        return

    if b"clang" in data:
        compiler_scores["Clang"] += 8
    if b"gcc" in data or b"gnu" in data:
        compiler_scores["GCC"] += 6


def _score_compiler_debug_info(elf, compiler_scores):
    data = _read_section_data(elf, ".debug_info", max_bytes=65536)
    if not data:
        return

    if b"clang" in data or b"llvm" in data:
        compiler_scores["Clang"] += 4
    if b"gcc" in data or b"gnu" in data:
        compiler_scores["GCC"] += 4


def _score_compiler_symbols(elf, compiler_scores):
    symbols = _collect_symbol_names(elf.get_section_by_name(".symtab"), elf.get_section_by_name(".dynsym"))
    if not symbols:
        return

    if "__clang_call_terminate" in symbols or any(name.startswith("__llvm_") for name in symbols):
        compiler_scores["Clang"] += 4

    if any("gnu" in name for name in symbols):
        compiler_scores["GCC"] += 1


def _score_compiler_dynamic(elf, compiler_scores):
    dynamic = elf.get_section_by_name(".dynamic")
    if not dynamic:
        return

    try:
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag != "DT_NEEDED":
                continue
            needed = tag.needed.lower()
            if "libc++" in needed:
                compiler_scores["Clang"] += 2
            if "libstdc++" in needed:
                compiler_scores["GCC"] += 1
    except Exception as exc:
        print(f"Error processing dynamic section for compiler detection: {exc}")


def detect_compiler(elf):
    compiler_scores = _empty_compiler_scores()
    _score_compiler_comment(elf, compiler_scores)
    _score_compiler_debug_info(elf, compiler_scores)
    _score_compiler_symbols(elf, compiler_scores)
    _score_compiler_dynamic(elf, compiler_scores)

    print("Compiler detection scores:")
    for compiler, score in compiler_scores.items():
        print(f"  {compiler}: {score}")

    max_score = max(compiler_scores.values())
    top_compilers = [compiler for compiler, score in compiler_scores.items() if score == max_score and score > 0]

    if len(top_compilers) == 1:
        return top_compilers[0]
    if len(top_compilers) > 1:
        return "Ambiguous: " + "/".join(top_compilers)
    return "Unknown"


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
    _score_general_language_strings(elf, scores)
    _score_sagelang_strings(elf, scores)
    _score_debug_info(elf, scores)
    _score_section_names(elf, scores)
    _score_asm_patterns(elf, symtab, dynsym, scores)

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
    return "Unknown"
