from detect.constants import (
    CSHARP_STRING_MARKERS,
    DART_STRONG_MARKERS,
    DART_TOKEN_PATTERN,
    HASKELL_STRING_MARKERS,
    JULIA_STRING_MARKERS,
    LANGUAGE_STRING_SCAN_SECTIONS,
    LUA_STRING_MARKERS,
    NIM_STRING_MARKERS,
    NOTE_SECTIONS,
    OCAML_STRING_MARKERS,
    SAGELANG_GENERATED_C_PATTERN,
    SAGELANG_RUNTIME_STRINGS,
    SAGELANG_STRONG_STRING_MARKERS,
    SAGELANG_TOKEN_PATTERN,
    ZIG_STRING_MARKERS,
    ZIG_TOKEN_PATTERN,
)
from detect.utils import read_section_data
from symbols.elfsymbols import scan_symbols


def score_comment_section(elf, scores):
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
        if "ocaml" in data:
            scores["OCaml"] += 3
        if "haskell" in data or "ghc" in data:
            scores["Haskell"] += 3
        if "julia" in data or "libjulia" in data:
            scores["Julia"] += 3
        if "lua" in data or "luajit" in data:
            scores["Lua"] += 3
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


def score_note_sections(elf, scores):
    for section_name, language in NOTE_SECTIONS.items():
        if elf.get_section_by_name(section_name):
            scores[language] += 5

    if elf.get_section_by_name(".sagelang") or elf.get_section_by_name(".sage"):
        scores["SageLang"] += 5


def score_dynamic_section(elf, scores):
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
            if "libasmrun" in needed or "ocaml" in needed:
                scores["OCaml"] += 4
            if "libhsrts" in needed or needed.startswith("libhs"):
                scores["Haskell"] += 4
            if "libjulia" in needed:
                scores["Julia"] += 6
            if "liblua" in needed or "luajit" in needed:
                scores["Lua"] += 5
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

        if needed_libs == {"libc.so.6"}:
            scores["C"] += 2
    except Exception as exc:
        print(f"Error processing dynamic section: {exc}")


def score_symbol_tables(elf, scores):
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


def score_general_language_strings(elf, scores):
    dart_markers = set()
    csharp_markers = set()
    nim_markers = set()
    zig_markers = set()
    haskell_markers = set()
    ocaml_markers = set()
    julia_markers = set()
    lua_markers = set()
    dart_token_count = 0
    zig_token_count = 0

    for section_name in LANGUAGE_STRING_SCAN_SECTIONS:
        data = read_section_data(elf, section_name)
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
        for marker in HASKELL_STRING_MARKERS:
            if marker in data:
                haskell_markers.add(marker)
        for marker in OCAML_STRING_MARKERS:
            if marker in data:
                ocaml_markers.add(marker)
        for marker in JULIA_STRING_MARKERS:
            if marker in data:
                julia_markers.add(marker)
        for marker in LUA_STRING_MARKERS:
            if marker in data:
                lua_markers.add(marker)

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

    if len(haskell_markers) >= 2:
        scores["Haskell"] += 7
    elif len(haskell_markers) >= 1:
        scores["Haskell"] += 3

    if len(ocaml_markers) >= 2:
        scores["OCaml"] += 7
    elif len(ocaml_markers) >= 1:
        scores["OCaml"] += 3

    if len(julia_markers) >= 2:
        scores["Julia"] += 8
    elif len(julia_markers) >= 1:
        scores["Julia"] += 4

    if len(lua_markers) >= 2:
        scores["Lua"] += 6
    elif len(lua_markers) >= 1:
        scores["Lua"] += 3


def score_sagelang_strings(elf, scores):
    runtime_hits = set()
    strong_hits = set()
    sage_token_score = 0
    sage_substring_count = 0

    for section_name in LANGUAGE_STRING_SCAN_SECTIONS:
        data = read_section_data(elf, section_name)
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

    has_sage_anchor = bool(strong_hits) or sage_token_score > 0 or sage_substring_count > 0
    if has_sage_anchor:
        if len(runtime_hits) >= 4:
            scores["SageLang"] += 8
        elif len(runtime_hits) >= 2:
            scores["SageLang"] += 4


def score_debug_info(elf, scores):
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
        if b"ocaml" in data or b"caml_" in data:
            scores["OCaml"] += 3
        if b"haskell" in data or b"ghc" in data:
            scores["Haskell"] += 3
        if b"julia" in data or b"jl_init" in data:
            scores["Julia"] += 3
        if b"lua" in data or b"luajit" in data:
            scores["Lua"] += 2
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


def score_section_names(elf, scores):
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
        if section_name in [".ocaml", ".caml"]:
            scores["OCaml"] += 3
        if section_name in [".julia", ".julia_consts"]:
            scores["Julia"] += 3
        if section_name in [".lua", ".luajit"]:
            scores["Lua"] += 3
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
