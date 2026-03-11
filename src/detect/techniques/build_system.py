from detect.constants import BUILD_SYSTEM_MARKERS, BUILD_SYSTEM_STRING_SCAN_SECTIONS
from detect.utils import collect_symbol_names, iter_dynamic_needed, read_section_data


def score_build_system_strings(elf, scores):
    marker_hits = {build_system: 0 for build_system in BUILD_SYSTEM_MARKERS}

    for section_name in BUILD_SYSTEM_STRING_SCAN_SECTIONS:
        data = read_section_data(elf, section_name, max_bytes=262144)
        if not data:
            continue

        for build_system, markers in BUILD_SYSTEM_MARKERS.items():
            for marker in markers:
                if marker in data:
                    marker_hits[build_system] += 1

    for build_system, hit_count in marker_hits.items():
        if hit_count >= 3:
            scores[build_system] += 8
        elif hit_count >= 2:
            scores[build_system] += 5
        elif hit_count >= 1:
            scores[build_system] += 3


def score_build_system_sections(elf, scores):
    if elf.get_section_by_name(".note.go.buildid"):
        scores["Go Toolchain"] += 10


def score_build_system_symbols(elf, scores):
    symbols = collect_symbol_names(elf.get_section_by_name(".symtab"), elf.get_section_by_name(".dynsym"))
    if not symbols:
        return

    if any(name.startswith("go.") or name.startswith("runtime.") for name in symbols):
        scores["Go Toolchain"] += 4

    if any("dart" in name for name in symbols):
        scores["Dart/Flutter"] += 3


def score_build_system_dynamic_libs(elf, scores):
    dynamic = elf.get_section_by_name(".dynamic")
    if not dynamic:
        return

    needed_libs = list(iter_dynamic_needed(dynamic))
    for needed in needed_libs:
        if "libdart" in needed:
            scores["Dart/Flutter"] += 4
        if "coreclr" in needed or "hostfxr" in needed or "hostpolicy" in needed:
            scores["MSBuild"] += 4
        if "libzig" in needed:
            scores["Zig Build"] += 4
