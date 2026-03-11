from detect.constants import BUILD_SYSTEM_HEURISTICS
from detect.techniques.build_system import (
    score_build_system_artifact_context,
    score_build_system_dwarf_paths,
    score_build_system_dynamic_libs,
    score_build_system_sections,
    score_build_system_strings,
    score_build_system_symbols,
)
from detect.utils import empty_scores


def detect_build_system(elf, artifact_profile=None, emit_report=True, return_details=False):
    scores = empty_scores(BUILD_SYSTEM_HEURISTICS)

    score_build_system_strings(elf, scores)
    score_build_system_sections(elf, scores)
    score_build_system_symbols(elf, scores)
    score_build_system_dynamic_libs(elf, scores)
    score_build_system_dwarf_paths(elf, scores)
    score_build_system_artifact_context(artifact_profile, scores)

    if emit_report:
        print("Build system detection scores:")
        for build_system, score in scores.items():
            print(f"  {build_system}: {score}")

    max_score = max(scores.values())
    top_systems = [
        build_system for build_system, score in scores.items() if score == max_score and score > 0
    ]

    if max_score < 3:
        result = "Unknown"
    elif len(top_systems) == 1:
        result = top_systems[0]
    elif len(top_systems) > 1:
        result = "Ambiguous: " + "/".join(top_systems)
    else:
        result = "Unknown"

    if return_details:
        return result, scores
    return result
