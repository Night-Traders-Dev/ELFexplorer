from detect.constants import BUILD_SYSTEM_MARKERS, BUILD_SYSTEM_STRING_SCAN_SECTIONS
from detect.utils import (
    collect_symbol_names,
    iter_dwarf_top_die_attributes,
    iter_dynamic_needed,
    normalize_dwarf_attr_value,
    read_section_data,
)


def _is_go_build_symbol(name):
    if name.startswith(("go.", "go.func.", "go.itab.", "go:")):
        return True
    if name.startswith("main.main"):
        return True
    if name.startswith("runtime.main") or name.startswith("runtime.rt0_"):
        return True
    return False


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

    if any(_is_go_build_symbol(name) for name in symbols):
        scores["Go Toolchain"] += 4

    if any("dart" in name for name in symbols):
        scores["Dart/Flutter"] += 3

    if any("rust" in name or name.startswith("_r") for name in symbols):
        scores["Cargo"] += 2

    if any("platformio" in name for name in symbols):
        scores["PlatformIO"] += 3
    if any("zephyr" in name or name.startswith("z_impl_") for name in symbols):
        scores["Zephyr West"] += 3
    if any("esp_" in name or "idf_" in name for name in symbols):
        scores["ESP-IDF"] += 3


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
        if "libgradle" in needed:
            scores["Gradle"] += 4
        if "libzephyr" in needed:
            scores["Zephyr West"] += 4
        if "libespidf" in needed:
            scores["ESP-IDF"] += 4


def _dwarf_path_strings(attrs):
    for key in ("DW_AT_comp_dir", "DW_AT_name"):
        attribute = attrs.get(key)
        if not attribute:
            continue
        value = normalize_dwarf_attr_value(attribute.value)
        if isinstance(value, bytes):
            value = value.decode(errors="ignore")
        if value is None:
            continue
        text = str(value).strip().lower()
        if text:
            yield text


def score_build_system_dwarf_paths(elf, scores):
    for attrs in iter_dwarf_top_die_attributes(elf) or []:
        for path in _dwarf_path_strings(attrs):
            if "cmakefiles" in path:
                scores["CMake"] += 4
            if "meson-private" in path:
                scores["Meson"] += 4
            if "bazel-out" in path:
                scores["Bazel"] += 4
            if "/target/debug" in path or "/target/release" in path:
                scores["Cargo"] += 4
            if "build.ninja" in path:
                scores["Ninja"] += 4
            if "output/build/" in path or "buildroot" in path:
                scores["Buildroot"] += 6
            if "tmp/work/" in path or "tmp/work-shared/" in path or "poky" in path:
                scores["Yocto/OpenEmbedded"] += 6
            if "/.pio/" in path or "platformio.ini" in path or "platformio" in path:
                scores["PlatformIO"] += 6
            if "esp-idf" in path or "idf.py" in path or "/components/esp" in path:
                scores["ESP-IDF"] += 6
            if ".west/" in path or "west build" in path or "zephyrproject" in path:
                scores["Zephyr West"] += 6


def score_build_system_artifact_context(artifact_profile, scores):
    if not artifact_profile:
        return

    artifact_type = artifact_profile.get("artifact_type", "")
    sdk_hints = set(artifact_profile.get("sdk_hints", []))
    build_hints = set(artifact_profile.get("build_hints", []))
    rtos_hints = set(artifact_profile.get("rtos_hints", []))
    signals = artifact_profile.get("signals", {})

    if artifact_type == "Bare-metal Firmware":
        if "Pico SDK" in sdk_hints or "Pico SDK" in build_hints:
            scores["Pico SDK"] += 8
        if not signals.get("go_runtime_present"):
            scores["Go Toolchain"] = max(0, scores["Go Toolchain"] - 4)
        if "CMake" in build_hints:
            scores["CMake"] += 3
        if "Zephyr" in rtos_hints:
            scores["Zephyr West"] += 5

    if artifact_type.startswith("Linux"):
        if signals.get("go_runtime_present"):
            scores["Go Toolchain"] += 2
