from detect.utils import collect_symbol_names


def score_asm_patterns(elf, symtab, dynsym, scores):
    symbol_names = collect_symbol_names(symtab, dynsym)
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
