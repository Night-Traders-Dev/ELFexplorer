from detect.constants import (
    CRYSTAL_STRING_MARKERS,
    CSHARP_STRING_MARKERS,
    DART_STRONG_MARKERS,
    DART_TOKEN_PATTERN,
    HASKELL_STRING_MARKERS,
    JULIA_STRING_MARKERS,
    KOTLIN_NATIVE_STRING_MARKERS,
    LANGUAGE_STRING_SCAN_SECTIONS,
    LUA_STRING_MARKERS,
    NIM_STRING_MARKERS,
    OBJC_STRING_MARKERS,
    NOTE_SECTIONS,
    OCAML_STRING_MARKERS,
    PASCAL_STRING_MARKERS,
    PERL_STRING_MARKERS,
    R_STRING_MARKERS,
    RUBY_STRING_MARKERS,
    SAGELANG_GENERATED_C_PATTERN,
    SAGELANG_RUNTIME_STRINGS,
    SAGELANG_STRONG_STRING_MARKERS,
    SAGELANG_TOKEN_PATTERN,
    TCL_STRING_MARKERS,
    ZIG_STRING_MARKERS,
    ZIG_TOKEN_PATTERN,
)
from detect.utils import iter_dwarf_top_die_attributes, normalize_dwarf_attr_value, read_section_data
from symbols.elfsymbols import scan_symbols

DWARF_LANGUAGE_NAME_MAP = {
    "DW_LANG_C89": "C",
    "DW_LANG_C": "C",
    "DW_LANG_C99": "C",
    "DW_LANG_C11": "C",
    "DW_LANG_C17": "C",
    "DW_LANG_C_plus_plus": "C++",
    "DW_LANG_C_plus_plus_03": "C++",
    "DW_LANG_C_plus_plus_11": "C++",
    "DW_LANG_C_plus_plus_14": "C++",
    "DW_LANG_C_plus_plus_17": "C++",
    "DW_LANG_ObjC": "Objective-C",
    "DW_LANG_Rust": "Rust",
    "DW_LANG_Go": "Go",
    "DW_LANG_D": "D",
    "DW_LANG_Python": "Python",
    "DW_LANG_Java": "Java",
    "DW_LANG_Swift": "Swift",
    "DW_LANG_Kotlin": "Kotlin/Native",
    "DW_LANG_Crystal": "Crystal",
    "DW_LANG_Pascal83": "Pascal",
    "DW_LANG_Fortran77": "Fortran",
    "DW_LANG_Fortran90": "Fortran",
    "DW_LANG_Fortran95": "Fortran",
    "DW_LANG_Fortran03": "Fortran",
    "DW_LANG_Fortran08": "Fortran",
    "DW_LANG_Ada83": "Ada",
    "DW_LANG_Ada95": "Ada",
}

DWARF_LANGUAGE_CODE_MAP = {
    0x0001: "DW_LANG_C89",
    0x0002: "DW_LANG_C",
    0x0003: "DW_LANG_Ada83",
    0x0004: "DW_LANG_C_plus_plus",
    0x0007: "DW_LANG_Fortran77",
    0x0008: "DW_LANG_Fortran90",
    0x0009: "DW_LANG_Pascal83",
    0x000B: "DW_LANG_Java",
    0x000C: "DW_LANG_C99",
    0x000E: "DW_LANG_Fortran95",
    0x000F: "DW_LANG_Ada95",
    0x0010: "DW_LANG_ObjC",
    0x0013: "DW_LANG_D",
    0x0014: "DW_LANG_Python",
    0x0016: "DW_LANG_Go",
    0x0019: "DW_LANG_C_plus_plus_03",
    0x001A: "DW_LANG_C_plus_plus_11",
    0x001C: "DW_LANG_Rust",
    0x001D: "DW_LANG_C11",
    0x001E: "DW_LANG_Swift",
    0x0021: "DW_LANG_Fortran03",
    0x0022: "DW_LANG_Fortran08",
    0x0026: "DW_LANG_Kotlin",
    0x0028: "DW_LANG_Crystal",
    0x002A: "DW_LANG_C_plus_plus_17",
    0x002C: "DW_LANG_C17",
}


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
        if "kotlin/native" in data or "konanc" in data or "kotlin root package" in data:
            scores["Kotlin/Native"] += 4
        if "free pascal" in data or "freepascal" in data or "fpc" in data:
            scores["Pascal"] += 3
        if "crystal-lang" in data or "__crystal_main" in data:
            scores["Crystal"] += 3
        if "ocaml" in data:
            scores["OCaml"] += 3
        if "haskell" in data or "ghc" in data:
            scores["Haskell"] += 3
        if "julia" in data or "libjulia" in data:
            scores["Julia"] += 3
        if "lua" in data or "luajit" in data:
            scores["Lua"] += 3
        if "libruby" in data or "ruby_init" in data or "rb_define_method" in data:
            scores["Ruby"] += 3
        if "libperl" in data or "perl_construct" in data or "perl_parse" in data:
            scores["Perl"] += 3
        if "libtcl" in data or "tcl_main" in data or "tcl_createinterp" in data:
            scores["Tcl"] += 3
        if "libr.so" in data or "rf_initembeddedr" in data or "r_inside_r" in data:
            scores["R"] += 3
        if "libobjc" in data or "objc_msgsend" in data or "gnustep" in data:
            scores["Objective-C"] += 3
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
        if (
            "dotnet" in data
            or "coreclr" in data
            or "hostfxr" in data
            or "hostpolicy" in data
            or "libmono" in data
            or "mono runtime" in data
        ):
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
            if "libruby" in needed:
                scores["Ruby"] += 6
            if "libperl" in needed:
                scores["Perl"] += 6
            if "libtcl" in needed:
                scores["Tcl"] += 6
            if needed == "libr.so" or needed.startswith("libr.so.") or needed.startswith("librblas"):
                scores["R"] += 6
            if "libobjc" in needed or "gnustep-base" in needed:
                scores["Objective-C"] += 6
            if "swift" in needed:
                scores["Swift"] += 3
            if "jvm" in needed or "java" in needed:
                scores["Java"] += 3
            if "python" in needed:
                scores["Python"] += 3
            if "libsage" in needed or "sagelang" in needed:
                scores["SageLang"] += 4
            if (
                "coreclr" in needed
                or "hostfxr" in needed
                or "hostpolicy" in needed
                or "libmono" in needed
                or needed.startswith("mono")
            ):
                scores["C#"] += 6
            if "libdart" in needed:
                scores["Dart"] += 6
            if "libnim" in needed:
                scores["Nim"] += 4
            if "libzig" in needed:
                scores["Zig"] += 4
            if "libkotlin" in needed or "libkonan" in needed:
                scores["Kotlin/Native"] += 5
            if "libpas" in needed or "libfpc" in needed or "fpc" in needed:
                scores["Pascal"] += 4
            if "libcrystal" in needed:
                scores["Crystal"] += 5

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
    kotlin_native_markers = set()
    pascal_markers = set()
    crystal_markers = set()
    zig_markers = set()
    haskell_markers = set()
    ocaml_markers = set()
    julia_markers = set()
    lua_markers = set()
    ruby_markers = set()
    perl_markers = set()
    tcl_markers = set()
    r_markers = set()
    objc_markers = set()
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
        for marker in KOTLIN_NATIVE_STRING_MARKERS:
            if marker in data:
                kotlin_native_markers.add(marker)
        for marker in PASCAL_STRING_MARKERS:
            if marker in data:
                pascal_markers.add(marker)
        for marker in CRYSTAL_STRING_MARKERS:
            if marker in data:
                crystal_markers.add(marker)
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
        for marker in RUBY_STRING_MARKERS:
            if marker in data:
                ruby_markers.add(marker)
        for marker in PERL_STRING_MARKERS:
            if marker in data:
                perl_markers.add(marker)
        for marker in TCL_STRING_MARKERS:
            if marker in data:
                tcl_markers.add(marker)
        for marker in R_STRING_MARKERS:
            if marker in data:
                r_markers.add(marker)
        for marker in OBJC_STRING_MARKERS:
            if marker in data:
                objc_markers.add(marker)

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

    if len(kotlin_native_markers) >= 3:
        scores["Kotlin/Native"] += 9
    elif len(kotlin_native_markers) >= 1:
        scores["Kotlin/Native"] += 4

    if len(pascal_markers) >= 2:
        scores["Pascal"] += 7
    elif len(pascal_markers) >= 1:
        scores["Pascal"] += 3

    if len(crystal_markers) >= 2:
        scores["Crystal"] += 7
    elif len(crystal_markers) >= 1:
        scores["Crystal"] += 3

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

    if len(ruby_markers) >= 2:
        scores["Ruby"] += 8
    elif len(ruby_markers) >= 1:
        scores["Ruby"] += 4

    if len(perl_markers) >= 2:
        scores["Perl"] += 8
    elif len(perl_markers) >= 1:
        scores["Perl"] += 4

    if len(tcl_markers) >= 2:
        scores["Tcl"] += 8
    elif len(tcl_markers) >= 1:
        scores["Tcl"] += 4

    if len(r_markers) >= 2:
        scores["R"] += 8
    elif len(r_markers) >= 1:
        scores["R"] += 4

    if len(objc_markers) >= 2:
        scores["Objective-C"] += 8
    elif len(objc_markers) >= 1:
        scores["Objective-C"] += 4


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
        if b"kotlin/native" in data or b"konanc" in data or b"kotlin_root" in data:
            scores["Kotlin/Native"] += 3
        if b"free pascal" in data or b"freepascal" in data or b"fpc_" in data:
            scores["Pascal"] += 3
        if b"crystal" in data or b"__crystal_main" in data:
            scores["Crystal"] += 3
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
        if (
            b"coreclr" in data
            or b"dotnet" in data
            or b"hostfxr" in data
            or b"hostpolicy" in data
            or b"libmono" in data
            or b"mono runtime" in data
        ):
            scores["C#"] += 3
    except Exception as exc:
        print(f"Error reading .debug_info: {exc}")


def score_section_names(elf, scores):
    for section in elf.iter_sections():
        section_name = section.name.lower()
        if section_name == ".gcc_except_table":
            scores["C++"] += 1
            scores["Rust"] += 1
        if section_name in [".gopclntab", ".go.buildinfo", ".gosymtab"]:
            scores["Go"] += 4
        if section_name == ".dlang":
            scores["D"] += 2
        if section_name == ".gnat":
            scores["Ada"] += 2
        if section_name == ".gfortran":
            scores["Fortran"] += 2
        if section_name == ".nim":
            scores["Nim"] += 2
        if section_name in [".kotlin", ".konan", ".note.kotlin.native"]:
            scores["Kotlin/Native"] += 4
        if section_name in [".fpc", ".pascal"]:
            scores["Pascal"] += 3
        if section_name in [".crystal", ".note.crystal"]:
            scores["Crystal"] += 3
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


def score_dwarf_language_attributes(elf, scores):
    for attrs in iter_dwarf_top_die_attributes(elf) or []:
        lang_attr = attrs.get("DW_AT_language")
        if not lang_attr:
            continue

        raw_value = normalize_dwarf_attr_value(lang_attr.value)
        language_name = None
        if isinstance(raw_value, int):
            language_name = DWARF_LANGUAGE_CODE_MAP.get(raw_value)
        else:
            value_text = str(raw_value)
            if value_text.startswith("DW_LANG_"):
                language_name = value_text
            elif value_text.isdigit():
                language_name = DWARF_LANGUAGE_CODE_MAP.get(int(value_text))

        if not language_name:
            continue

        mapped = DWARF_LANGUAGE_NAME_MAP.get(language_name)
        if mapped and mapped in scores:
            scores[mapped] += 8


def apply_artifact_language_bias(artifact_profile, scores):
    if not artifact_profile:
        return

    artifact_type = artifact_profile.get("artifact_type", "")
    signals = artifact_profile.get("signals", {})

    if artifact_type == "Bare-metal Firmware":
        scores["C"] += 3

        if not signals.get("go_runtime_present"):
            scores["Go"] = max(0, scores["Go"] - 6)
        if not signals.get("dart_runtime_present"):
            scores["Dart"] = max(0, scores["Dart"] - 4)
        if not signals.get("dotnet_runtime_present"):
            scores["C#"] = max(0, scores["C#"] - 6)
        if "RP2040" in "".join(artifact_profile.get("target_hints", [])):
            scores["Kotlin/Native"] = max(0, scores["Kotlin/Native"] - 2)
            scores["Crystal"] = max(0, scores["Crystal"] - 2)

        target_hints = set(artifact_profile.get("target_hints", []))
        if any("cortex-m" in hint.lower() for hint in target_hints):
            scores["ASM"] += 1
