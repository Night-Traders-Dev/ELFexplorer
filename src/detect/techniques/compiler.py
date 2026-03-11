from detect.constants import (
    COMPILER_CLANG_STRING_MARKERS,
    COMPILER_CLANG_SYMBOL_MARKERS,
    COMPILER_GDC_STRING_MARKERS,
    COMPILER_GDC_SYMBOL_MARKERS,
    COMPILER_GHC_STRING_MARKERS,
    COMPILER_GHC_SYMBOL_MARKERS,
    COMPILER_GO_STRING_MARKERS,
    COMPILER_GO_SYMBOL_MARKERS,
    COMPILER_GCC_STRING_MARKERS,
    COMPILER_GCC_SYMBOL_MARKERS,
    COMPILER_INTEL_STRING_MARKERS,
    COMPILER_INTEL_SYMBOL_MARKERS,
    COMPILER_LDC_STRING_MARKERS,
    COMPILER_LDC_SYMBOL_MARKERS,
    COMPILER_MASM_STRING_MARKERS,
    COMPILER_MASM_SYMBOL_MARKERS,
    COMPILER_NASM_STRING_MARKERS,
    COMPILER_NASM_SYMBOL_MARKERS,
    COMPILER_OCAMLOPT_STRING_MARKERS,
    COMPILER_OCAMLOPT_SYMBOL_MARKERS,
    COMPILER_RUSTC_STRING_MARKERS,
    COMPILER_RUSTC_SYMBOL_MARKERS,
    COMPILER_STRING_SCAN_SECTIONS,
    COMPILER_TINYCC_STRING_MARKERS,
    COMPILER_TINYCC_SYMBOL_MARKERS,
    COMPILER_TASM_STRING_MARKERS,
    COMPILER_TASM_SYMBOL_MARKERS,
    COMPILER_FASM_STRING_MARKERS,
    COMPILER_FASM_SYMBOL_MARKERS,
    COMPILER_ZIG_STRING_MARKERS,
    COMPILER_ZIG_SYMBOL_MARKERS,
)
from detect.utils import collect_symbol_names, iter_dynamic_needed, read_section_data


def score_compiler_sections(elf, compiler_scores):
    section_names = {section.name.lower() for section in elf.iter_sections()}

    # LLVM-prefixed sections are not Clang-specific (Rust and other toolchains also emit them).
    if ".llvm_addrsig" in section_names and elf.get_section_by_name(".comment"):
        compiler_scores["Clang"] += 1

    if ".gcc.command.line" in section_names:
        compiler_scores["GCC"] += 5
    if ".note.go.buildid" in section_names:
        compiler_scores["Go gc"] += 8
    if ".note.rustc" in section_names:
        compiler_scores["Rustc"] += 8
    if ".note.nasm" in section_names or ".nasm" in section_names:
        compiler_scores["NASM"] += 5
    if ".note.fasm" in section_names or ".fasm" in section_names:
        compiler_scores["FASM"] += 5
    if ".note.masm" in section_names or ".masm" in section_names:
        compiler_scores["MASM"] += 5
    if ".note.tasm" in section_names or ".tasm" in section_names:
        compiler_scores["TASM"] += 5


def score_compiler_strings(elf, compiler_scores):
    clang_hits = 0
    gcc_hits = 0
    intel_hits = 0
    tinycc_hits = 0
    rustc_hits = 0
    go_hits = 0
    zig_hits = 0
    ldc_hits = 0
    gdc_hits = 0
    nasm_hits = 0
    fasm_hits = 0
    masm_hits = 0
    tasm_hits = 0
    ghc_hits = 0
    ocamlopt_hits = 0

    for section_name in COMPILER_STRING_SCAN_SECTIONS:
        data = read_section_data(elf, section_name, max_bytes=262144)
        if not data:
            continue

        for marker in COMPILER_CLANG_STRING_MARKERS:
            if marker in data:
                clang_hits += 1
        for marker in COMPILER_GCC_STRING_MARKERS:
            if marker in data:
                gcc_hits += 1
        for marker in COMPILER_INTEL_STRING_MARKERS:
            if marker in data:
                intel_hits += 1
        for marker in COMPILER_TINYCC_STRING_MARKERS:
            if marker in data:
                tinycc_hits += 1
        for marker in COMPILER_RUSTC_STRING_MARKERS:
            if marker in data:
                rustc_hits += 1
        for marker in COMPILER_GO_STRING_MARKERS:
            if marker in data:
                go_hits += 1
        for marker in COMPILER_ZIG_STRING_MARKERS:
            if marker in data:
                zig_hits += 1
        for marker in COMPILER_LDC_STRING_MARKERS:
            if marker in data:
                ldc_hits += 1
        for marker in COMPILER_GDC_STRING_MARKERS:
            if marker in data:
                gdc_hits += 1
        for marker in COMPILER_NASM_STRING_MARKERS:
            if marker in data:
                nasm_hits += 1
        for marker in COMPILER_FASM_STRING_MARKERS:
            if marker in data:
                fasm_hits += 1
        for marker in COMPILER_MASM_STRING_MARKERS:
            if marker in data:
                masm_hits += 1
        for marker in COMPILER_TASM_STRING_MARKERS:
            if marker in data:
                tasm_hits += 1
        for marker in COMPILER_GHC_STRING_MARKERS:
            if marker in data:
                ghc_hits += 1
        for marker in COMPILER_OCAMLOPT_STRING_MARKERS:
            if marker in data:
                ocamlopt_hits += 1

    if clang_hits >= 3:
        compiler_scores["Clang"] += 10
    elif clang_hits >= 1:
        compiler_scores["Clang"] += 5

    if gcc_hits >= 3:
        compiler_scores["GCC"] += 10
    elif gcc_hits >= 1:
        compiler_scores["GCC"] += 5

    if intel_hits >= 2:
        compiler_scores["Intel ICC/ICX"] += 10
    elif intel_hits >= 1:
        compiler_scores["Intel ICC/ICX"] += 5

    if tinycc_hits >= 2:
        compiler_scores["TinyCC"] += 10
    elif tinycc_hits >= 1:
        compiler_scores["TinyCC"] += 5

    if rustc_hits >= 3:
        compiler_scores["Rustc"] += 10
    elif rustc_hits >= 1:
        compiler_scores["Rustc"] += 5

    if go_hits >= 2:
        compiler_scores["Go gc"] += 10
    elif go_hits >= 1:
        compiler_scores["Go gc"] += 5

    if zig_hits >= 2:
        compiler_scores["Zig"] += 8
    elif zig_hits >= 1:
        compiler_scores["Zig"] += 4

    if ldc_hits >= 2:
        compiler_scores["LDC"] += 8
    elif ldc_hits >= 1:
        compiler_scores["LDC"] += 4

    if gdc_hits >= 2:
        compiler_scores["GDC"] += 8
    elif gdc_hits >= 1:
        compiler_scores["GDC"] += 4

    if nasm_hits >= 2:
        compiler_scores["NASM"] += 8
    elif nasm_hits >= 1:
        compiler_scores["NASM"] += 4

    if fasm_hits >= 2:
        compiler_scores["FASM"] += 8
    elif fasm_hits >= 1:
        compiler_scores["FASM"] += 4

    if masm_hits >= 2:
        compiler_scores["MASM"] += 8
    elif masm_hits >= 1:
        compiler_scores["MASM"] += 4

    if tasm_hits >= 2:
        compiler_scores["TASM"] += 8
    elif tasm_hits >= 1:
        compiler_scores["TASM"] += 4

    if ghc_hits >= 2:
        compiler_scores["GHC"] += 8
    elif ghc_hits >= 1:
        compiler_scores["GHC"] += 4

    if ocamlopt_hits >= 2:
        compiler_scores["OCamlopt"] += 8
    elif ocamlopt_hits >= 1:
        compiler_scores["OCamlopt"] += 4


def score_compiler_dwarf_producer(elf, compiler_scores):
    try:
        has_dwarf_info = getattr(elf, "has_dwarf_info", None)
        if not callable(has_dwarf_info) or not elf.has_dwarf_info():
            return

        dwarf_info = elf.get_dwarf_info()
        for compile_unit in dwarf_info.iter_CUs():
            top_die = compile_unit.get_top_DIE()
            producer = top_die.attributes.get("DW_AT_producer")
            if not producer:
                continue

            value = producer.value
            if isinstance(value, bytes):
                value = value.decode(errors="ignore")
            value = str(value).lower()

            if "clang" in value:
                compiler_scores["Clang"] += 10
            if "gcc" in value or "gnu c" in value or "gnu c++" in value:
                compiler_scores["GCC"] += 10
            if "intel(r) oneapi" in value or "intel c++" in value or " icx" in value:
                compiler_scores["Intel ICC/ICX"] += 10
            if "tiny c compiler" in value or value.startswith("tcc"):
                compiler_scores["TinyCC"] += 10
            if "rustc" in value:
                compiler_scores["Rustc"] += 10
            if "go cmd/compile" in value or "golang" in value:
                compiler_scores["Go gc"] += 10
            if "zig" in value:
                compiler_scores["Zig"] += 8
            if "ldc2" in value or "llvm-based d compiler" in value:
                compiler_scores["LDC"] += 8
            if "gdc" in value or "gnu d compiler" in value:
                compiler_scores["GDC"] += 8
            if "nasm" in value or "netwide assembler" in value:
                compiler_scores["NASM"] += 8
            if "fasm" in value or "flat assembler" in value:
                compiler_scores["FASM"] += 8
            if "masm" in value or "macro assembler" in value:
                compiler_scores["MASM"] += 8
            if "tasm" in value or "turbo assembler" in value:
                compiler_scores["TASM"] += 8
            if "the glorious glasgow haskell compilation system" in value or "ghc" in value:
                compiler_scores["GHC"] += 8
            if "ocamlopt" in value:
                compiler_scores["OCamlopt"] += 8
    except Exception as exc:
        print(f"Error processing DWARF producer for compiler detection: {exc}")


def score_compiler_symbols(elf, compiler_scores):
    symbols = collect_symbol_names(elf.get_section_by_name(".symtab"), elf.get_section_by_name(".dynsym"))
    if not symbols:
        return

    for marker in COMPILER_CLANG_SYMBOL_MARKERS:
        if marker in symbols:
            compiler_scores["Clang"] += 4

    for marker in COMPILER_GCC_SYMBOL_MARKERS:
        if marker in symbols:
            compiler_scores["GCC"] += 4

    if any(marker in name for marker in COMPILER_INTEL_SYMBOL_MARKERS for name in symbols):
        compiler_scores["Intel ICC/ICX"] += 5

    if any(marker in name for marker in COMPILER_TINYCC_SYMBOL_MARKERS for name in symbols):
        compiler_scores["TinyCC"] += 5

    if any(marker in name for marker in COMPILER_RUSTC_SYMBOL_MARKERS for name in symbols):
        compiler_scores["Rustc"] += 5

    if any(name.startswith(marker) for marker in COMPILER_GO_SYMBOL_MARKERS for name in symbols):
        compiler_scores["Go gc"] += 5

    if any(marker in name for marker in COMPILER_ZIG_SYMBOL_MARKERS for name in symbols):
        compiler_scores["Zig"] += 5

    if any(marker in name for marker in COMPILER_LDC_SYMBOL_MARKERS for name in symbols):
        compiler_scores["LDC"] += 4

    if any(marker in name for marker in COMPILER_GDC_SYMBOL_MARKERS for name in symbols):
        compiler_scores["GDC"] += 4

    if any(marker in name for marker in COMPILER_NASM_SYMBOL_MARKERS for name in symbols):
        compiler_scores["NASM"] += 5

    if any(marker in name for marker in COMPILER_FASM_SYMBOL_MARKERS for name in symbols):
        compiler_scores["FASM"] += 5

    if any(marker in name for marker in COMPILER_MASM_SYMBOL_MARKERS for name in symbols):
        compiler_scores["MASM"] += 5

    if any(marker in name for marker in COMPILER_TASM_SYMBOL_MARKERS for name in symbols):
        compiler_scores["TASM"] += 5

    if any(name.startswith(marker) for marker in COMPILER_GHC_SYMBOL_MARKERS for name in symbols):
        compiler_scores["GHC"] += 5

    if any(name.startswith(marker) for marker in COMPILER_OCAMLOPT_SYMBOL_MARKERS for name in symbols):
        compiler_scores["OCamlopt"] += 5


def score_compiler_dynamic_libs(elf, compiler_scores):
    dynamic = elf.get_section_by_name(".dynamic")
    if not dynamic:
        return

    needed_libs = list(iter_dynamic_needed(dynamic))
    for needed in needed_libs:
        if "libclang_rt" in needed or "compiler_rt" in needed:
            compiler_scores["Clang"] += 4
        if "libc++" in needed or "libc++abi" in needed:
            compiler_scores["Clang"] += 2

        if "libgcc" in needed:
            compiler_scores["GCC"] += 4
        if "libstdc++" in needed:
            compiler_scores["GCC"] += 2
        if "libirc" in needed or "libimf" in needed or "libintlc" in needed:
            compiler_scores["Intel ICC/ICX"] += 4
        if "libhsrts" in needed:
            compiler_scores["GHC"] += 6
        if "libasmrun" in needed:
            compiler_scores["OCamlopt"] += 6
        if "libzig" in needed:
            compiler_scores["Zig"] += 4
        if "libphobos" in needed:
            compiler_scores["LDC"] += 3
            compiler_scores["GDC"] += 3


def score_compiler_artifact_context(artifact_profile, compiler_scores):
    if not artifact_profile:
        return

    artifact_type = artifact_profile.get("artifact_type", "")
    runtime_hints = set(artifact_profile.get("runtime_hints", []))
    signals = artifact_profile.get("signals", {})

    if artifact_type == "Bare-metal Firmware":
        compiler_scores["GCC"] += 2
        compiler_scores["Clang"] += 1
        if not signals.get("go_runtime_present"):
            compiler_scores["Go gc"] = max(0, compiler_scores["Go gc"] - 4)
        if "newlib" in runtime_hints:
            compiler_scores["GCC"] += 2

    if artifact_type == "Linux User-space Executable" and "glibc" in runtime_hints:
        compiler_scores["GCC"] += 1
