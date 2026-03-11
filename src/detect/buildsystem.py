from detect.constants import BUILD_SYSTEM_HEURISTICS
from detect.techniques.build_system import (
    score_build_system_dynamic_libs,
    score_build_system_sections,
    score_build_system_strings,
    score_build_system_symbols,
)
from detect.utils import empty_scores


def detect_build_system(elf):
    scores = empty_scores(BUILD_SYSTEM_HEURISTICS)

    score_build_system_strings(elf, scores)
    score_build_system_sections(elf, scores)
    score_build_system_symbols(elf, scores)
    score_build_system_dynamic_libs(elf, scores)

    print("Build system detection scores:")
    for build_system, score in scores.items():
        print(f"  {build_system}: {score}")

    max_score = max(scores.values())
    top_systems = [
        build_system for build_system, score in scores.items() if score == max_score and score > 0
    ]

    if max_score < 3:
        return "Unknown"
    if len(top_systems) == 1:
        return top_systems[0]
    if len(top_systems) > 1:
        return "Ambiguous: " + "/".join(top_systems)
    return "Unknown"
