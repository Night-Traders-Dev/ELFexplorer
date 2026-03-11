from detect.constants import ARTIFACT_HEURISTICS
from detect.techniques.artifact import (
    score_artifact_memory_map,
    score_artifact_program_headers,
    score_artifact_sections,
    score_artifact_strings,
    score_artifact_symbols,
)
from detect.utils import empty_scores


def _interpreter_path(elf):
    section = elf.get_section_by_name(".interp")
    if not section:
        return None

    try:
        data = section.data().split(b"\x00", maxsplit=1)[0]
        text = data.decode(errors="ignore").strip()
        return text or None
    except Exception:
        return None


def _select_artifact(scores):
    max_score = max(scores.values())
    top = [name for name, value in scores.items() if value == max_score and value > 0]
    if max_score < 4:
        return "Unknown", max_score, top
    if len(top) == 1:
        return top[0], max_score, top
    return "Ambiguous: " + "/".join(top), max_score, top


def _compute_confidence(scores, label):
    ordered = sorted(scores.values(), reverse=True)
    top_score = ordered[0] if ordered else 0
    second_score = ordered[1] if len(ordered) > 1 else 0
    margin = max(0, top_score - second_score)

    if label == "Unknown":
        return 20
    if label.startswith("Ambiguous:"):
        return max(35, min(80, 45 + top_score + margin))

    return max(45, min(99, 50 + top_score + (margin * 2)))


def _pick_hint(profile, key):
    values = sorted(profile.get(key, set()))
    if not values:
        return "Unknown"
    if len(values) == 1:
        return values[0]
    return ", ".join(values)


def _pick_rtos_hint(profile):
    values = sorted(profile.get("rtos_hints", set()))
    if not values:
        return "None detected"
    if len(values) == 1:
        return values[0]
    return ", ".join(values)


def _pick_runtime_hint(profile):
    values = set(profile.get("runtime_hints", set()))
    artifact_type = profile.get("artifact_type", "")

    if artifact_type.startswith("Linux") and "glibc" in values:
        return "glibc"
    if artifact_type == "Bare-metal Firmware" and "newlib" in values:
        return "newlib"
    if not values:
        return "Unknown"
    if len(values) == 1:
        return next(iter(values))
    return ", ".join(sorted(values))


def _linkage_model(profile):
    if profile.get("signals", {}).get("has_interp"):
        return "Dynamic user-space"
    if profile.get("signals", {}).get("has_dynamic_needed"):
        return "Dynamic linked"
    if profile.get("artifact_type") == "Bare-metal Firmware":
        return "Static bare-metal"
    if profile.get("artifact_type") == "Linux Kernel Module":
        return "Kernel module"
    if profile.get("artifact_type") == "Relocatable Object":
        return "Relocatable object"
    return "Static/Unknown"


def detect_artifact_profile(elf, emit_report=True):
    scores = empty_scores(ARTIFACT_HEURISTICS)
    profile = {
        "indicators": [],
        "target_hints": set(),
        "sdk_hints": set(),
        "rtos_hints": set(),
        "runtime_hints": set(),
        "build_hints": set(),
        "signals": {},
        "needed_libs": [],
        "machine": "Unknown",
        "elf_type": "Unknown",
    }

    score_artifact_program_headers(elf, scores, profile)
    score_artifact_sections(elf, scores, profile)
    score_artifact_symbols(elf, scores, profile)
    score_artifact_strings(elf, scores, profile)
    score_artifact_memory_map(elf, scores, profile)

    artifact_type, _, _ = _select_artifact(scores)
    profile["artifact_type"] = artifact_type
    profile["confidence"] = _compute_confidence(scores, artifact_type)
    profile["target"] = _pick_hint(profile, "target_hints")
    profile["sdk"] = _pick_hint(profile, "sdk_hints")
    profile["rtos"] = _pick_rtos_hint(profile)
    profile["runtime"] = _pick_runtime_hint(profile)
    profile["build_hints_text"] = _pick_hint(profile, "build_hints")
    profile["loader"] = _interpreter_path(elf) or "None"
    profile["linkage_model"] = _linkage_model(profile)
    profile["scores"] = dict(scores)

    for key in ("target_hints", "sdk_hints", "rtos_hints", "runtime_hints", "build_hints"):
        profile[key] = sorted(profile.get(key, set()))

    if emit_report:
        print("Artifact detection scores:")
        for artifact, score in scores.items():
            print(f"  {artifact}: {score}")
        print("Artifact profile details:")
        print(f"  Artifact Type: {profile['artifact_type']}")
        print(f"  Confidence: {profile['confidence']}")
        print(f"  Linkage Model: {profile['linkage_model']}")
        print(f"  Target Hint: {profile['target']}")
        print(f"  SDK Hint: {profile['sdk']}")
        print(f"  RTOS Hint: {profile['rtos']}")
        print(f"  Runtime Hint: {profile['runtime']}")
        print(f"  Loader: {profile['loader']}")

    return profile
