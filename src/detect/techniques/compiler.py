from detect.constants import (
    COMPILER_CLANG_STRING_MARKERS,
    COMPILER_CLANG_SYMBOL_MARKERS,
    COMPILER_GCC_STRING_MARKERS,
    COMPILER_GCC_SYMBOL_MARKERS,
    COMPILER_STRING_SCAN_SECTIONS,
)
from detect.utils import collect_symbol_names, iter_dynamic_needed, read_section_data


def score_compiler_sections(elf, compiler_scores):
    section_names = {section.name.lower() for section in elf.iter_sections()}

    # LLVM-prefixed sections are not Clang-specific (Rust and other toolchains also emit them).
    if ".llvm_addrsig" in section_names and elf.get_section_by_name(".comment"):
        compiler_scores["Clang"] += 1

    if ".gcc.command.line" in section_names:
        compiler_scores["GCC"] += 5


def score_compiler_strings(elf, compiler_scores):
    clang_hits = 0
    gcc_hits = 0

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

    if clang_hits >= 3:
        compiler_scores["Clang"] += 10
    elif clang_hits >= 1:
        compiler_scores["Clang"] += 5

    if gcc_hits >= 3:
        compiler_scores["GCC"] += 10
    elif gcc_hits >= 1:
        compiler_scores["GCC"] += 5


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
