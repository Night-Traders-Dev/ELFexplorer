from detect.constants import COMPILER_HEURISTICS
from detect.techniques.compiler import (
    score_compiler_artifact_context,
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
    return source_language in {"ASM", "C", "C++", "Pascal", "Unknown"}


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


def _allowed_compilers_for_language(source_language):
    if not source_language or source_language == "Unknown" or source_language.startswith("Ambiguous:"):
        return None

    language_compiler_map = {
        "ASM": {"GCC", "Clang", "Intel ICC/ICX", "Zig", "YASM", "NASM", "FASM", "MASM", "TASM"},
        "C": {"GCC", "Clang", "Intel ICC/ICX", "TinyCC", "Zig"},
        "C++": {"GCC", "Clang", "Intel ICC/ICX", "TinyCC", "Zig"},
        "Objective-C": {"GCC", "Clang"},
        "D": {"LDC", "GDC", "DMD"},
        "Ada": {"GNAT"},
        "Fortran": {"GFortran"},
        "Pascal": {"FreePascal"},
        "Rust": {"Rustc"},
        "Go": {"Go gc"},
        "Zig": {"Zig"},
        "Kotlin/Native": {"Clang"},
        "Crystal": {"Clang", "GCC"},
        "Haskell": {"GHC"},
        "OCaml": {"OCamlopt"},
    }
    return language_compiler_map.get(source_language)


def detect_compiler(
    elf,
    source_language=None,
    artifact_profile=None,
    emit_report=True,
    return_details=False,
):
    compiler_scores = empty_scores(COMPILER_HEURISTICS)

    score_compiler_sections(elf, compiler_scores)
    score_compiler_strings(elf, compiler_scores)
    score_compiler_dwarf_producer(elf, compiler_scores)
    score_compiler_symbols(elf, compiler_scores)
    score_compiler_dynamic_libs(elf, compiler_scores)
    score_compiler_artifact_context(artifact_profile, compiler_scores)

    if emit_report:
        print("Compiler detection scores:")
        for compiler, score in compiler_scores.items():
            print(f"  {compiler}: {score}")

    explicit_banner = _has_explicit_compiler_banner(elf)
    allowed = _allowed_compilers_for_language(source_language)

    selected_scores = dict(compiler_scores)
    if allowed is not None:
        selected_scores = {
            compiler: score
            for compiler, score in compiler_scores.items()
            if compiler in allowed or (explicit_banner and compiler in {"GCC", "Clang"})
        }
        if not selected_scores:
            if return_details:
                return "Unknown", compiler_scores
            return "Unknown"

    max_score = max(selected_scores.values())
    top_compilers = [
        compiler for compiler, score in selected_scores.items() if score == max_score and score > 0
    ]

    if not _is_c_family_language(source_language) and allowed is None and not explicit_banner:
        result = "Unknown"
    elif max_score < 3:
        result = "Unknown"
    elif len(top_compilers) == 1:
        result = top_compilers[0]
    elif len(top_compilers) > 1:
        result = "Ambiguous: " + "/".join(top_compilers)
    else:
        result = "Unknown"

    if return_details:
        return result, compiler_scores
    return result
