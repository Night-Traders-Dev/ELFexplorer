from detect.arch.asm import score_asm_patterns
from detect.constants import SUPPORTED_LANGUAGES
from detect.techniques.language import (
    apply_artifact_language_bias,
    score_comment_section,
    score_dwarf_language_attributes,
    score_debug_info,
    score_dynamic_section,
    score_general_language_strings,
    score_note_sections,
    score_sagelang_strings,
    score_section_names,
    score_symbol_tables,
)
from detect.techniques.disassembly import score_disassembly_patterns
from detect.utils import empty_scores


def detect_source_language(elf, artifact_profile=None, emit_report=True, return_details=False):
    """
    Attempt to deduce the original source language of an ELF binary using heuristics.
    Returns a string indicating the detected language.
    """
    scores = empty_scores(SUPPORTED_LANGUAGES)

    score_comment_section(elf, scores)
    score_note_sections(elf, scores)
    score_dynamic_section(elf, scores)
    symtab, dynsym = score_symbol_tables(elf, scores)
    score_general_language_strings(elf, scores)
    score_sagelang_strings(elf, scores)
    score_debug_info(elf, scores)
    score_dwarf_language_attributes(elf, scores)
    score_section_names(elf, scores)
    score_asm_patterns(elf, symtab, dynsym, scores)
    score_disassembly_patterns(elf, scores)
    apply_artifact_language_bias(artifact_profile, scores)

    has_symbols = False
    if symtab and symtab.num_symbols() > 0:
        has_symbols = True
    elif dynsym and dynsym.num_symbols() > 0:
        has_symbols = True

    if emit_report:
        print("Language detection scores:")
        for language, score in scores.items():
            print(f"  {language}: {score}")

    max_score = max(scores.values())
    top_languages = [
        language for language, score in scores.items() if score == max_score and score > 0
    ]

    if not has_symbols and max_score < 2:
        if emit_report:
            print("Warning: Binary appears stripped; detection may be unreliable.")

    if len(top_languages) == 1:
        result = top_languages[0]
    elif len(top_languages) > 1:
        result = "Ambiguous: " + "/".join(top_languages)
    else:
        result = "Unknown"

    if return_details:
        return result, scores
    return result
