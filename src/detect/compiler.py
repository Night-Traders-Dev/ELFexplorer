from detect.constants import COMPILER_HEURISTICS
from detect.techniques.compiler import (
    score_compiler_dwarf_producer,
    score_compiler_dynamic_libs,
    score_compiler_sections,
    score_compiler_strings,
    score_compiler_symbols,
)
from detect.utils import empty_scores


def _is_c_family_language(source_language):
    if not source_language:
        return True
    if source_language.startswith("Ambiguous:"):
        return True
    return source_language in {"ASM", "C", "C++", "Unknown"}


def _has_explicit_compiler_banner(elf):
    comment = elf.get_section_by_name(".comment")
    if not comment:
        return False
    try:
        data = comment.data().decode(errors="ignore").lower()
    except Exception:
        return False
    return (
        "clang version" in data
        or "apple clang" in data
        or "gcc version" in data
        or "gcc: (gnu)" in data
    )


def detect_compiler(elf, source_language=None):
    compiler_scores = empty_scores(COMPILER_HEURISTICS)

    score_compiler_sections(elf, compiler_scores)
    score_compiler_strings(elf, compiler_scores)
    score_compiler_dwarf_producer(elf, compiler_scores)
    score_compiler_symbols(elf, compiler_scores)
    score_compiler_dynamic_libs(elf, compiler_scores)

    print("Compiler detection scores:")
    for compiler, score in compiler_scores.items():
        print(f"  {compiler}: {score}")

    max_score = max(compiler_scores.values())
    top_compilers = [
        compiler for compiler, score in compiler_scores.items() if score == max_score and score > 0
    ]

    if not _is_c_family_language(source_language) and not _has_explicit_compiler_banner(elf):
        return "Unknown"

    if max_score < 3:
        return "Unknown"
    if len(top_compilers) == 1:
        return top_compilers[0]
    if len(top_compilers) > 1:
        return "Ambiguous: " + "/".join(top_compilers)
    return "Unknown"
