from detect.constants import COMPILER_HEURISTICS
from detect.techniques.compiler import (
    score_compiler_dwarf_producer,
    score_compiler_dynamic_libs,
    score_compiler_sections,
    score_compiler_strings,
    score_compiler_symbols,
)
from detect.utils import empty_scores


def detect_compiler(elf):
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

    if max_score < 3:
        return "Unknown"
    if len(top_compilers) == 1:
        return top_compilers[0]
    if len(top_compilers) > 1:
        return "Ambiguous: " + "/".join(top_compilers)
    return "Unknown"
