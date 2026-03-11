import struct

from detect.constants import (
    ARTIFACT_CMSIS_MARKERS,
    ARTIFACT_EMBEDDED_MACHINES,
    ARTIFACT_FREERTOS_MARKERS,
    ARTIFACT_GLIBC_MARKERS,
    ARTIFACT_KERNEL_MODULE_SYMBOL_MARKERS,
    ARTIFACT_NEWLIB_MARKERS,
    ARTIFACT_PICO_STRING_MARKERS,
    ARTIFACT_PICO_SYMBOL_MARKERS,
    ARTIFACT_RTTHREAD_MARKERS,
    ARTIFACT_SECTION_MARKERS,
    ARTIFACT_STRING_SCAN_SECTIONS,
    ARTIFACT_ZEPHYR_MARKERS,
    BUILD_SYSTEM_MARKERS,
    CSHARP_STRING_MARKERS,
    DART_STRONG_MARKERS,
)
from detect.utils import collect_symbol_names, iter_dynamic_needed, read_section_data


def _header_value(header, key, default=None):
    if header is None:
        return default

    if hasattr(header, key):
        return getattr(header, key)

    try:
        return header[key]
    except Exception:
        return default


def _add_indicator(profile, message):
    indicators = profile.setdefault("indicators", [])
    if message not in indicators:
        indicators.append(message)


def _add_hint(profile, bucket, value):
    hints = profile.setdefault(bucket, set())
    hints.add(value)


def _set_signal(profile, key, value=True):
    signals = profile.setdefault("signals", {})
    signals[key] = value


def _iter_segments(elf):
    iterator = getattr(elf, "iter_segments", None)
    if not callable(iterator):
        return []

    try:
        return list(iterator())
    except Exception:
        return []


def _entry_address(elf):
    try:
        return int(elf.header["e_entry"])
    except Exception:
        return 0


def _machine_name(elf):
    try:
        return str(elf.header["e_machine"])
    except Exception:
        return "Unknown"


def _etype_name(elf):
    try:
        return str(elf.header["e_type"])
    except Exception:
        return "Unknown"


def _scan_vector_candidate(data, machine):
    if machine != "EM_ARM" or len(data) < 8:
        return None

    scan_limit = min(len(data) - 8, 0x1000)
    for offset in range(0, scan_limit + 1, 4):
        stack_ptr, reset_handler = struct.unpack_from("<II", data, offset)
        reset_addr = reset_handler & ~1

        if not (0x20000000 <= stack_ptr <= 0x3FFFFFFF):
            continue
        if (reset_handler & 1) == 0:
            continue

        in_known_code_range = (
            0x00000000 <= reset_addr < 0x01000000
            or 0x08000000 <= reset_addr < 0x10000000
            or 0x10000000 <= reset_addr < 0x20000000
        )
        if not in_known_code_range:
            continue

        return offset, stack_ptr, reset_addr

    return None


def score_artifact_program_headers(elf, scores, profile):
    etype = _etype_name(elf)
    machine = _machine_name(elf)
    segments = _iter_segments(elf)
    dynamic = elf.get_section_by_name(".dynamic")
    needed_libs = list(iter_dynamic_needed(dynamic))

    has_interp = any(_header_value(segment.header, "p_type") == "PT_INTERP" for segment in segments)
    has_dynamic_segment = any(
        _header_value(segment.header, "p_type") == "PT_DYNAMIC" for segment in segments
    )

    profile["machine"] = machine
    profile["elf_type"] = etype
    profile["needed_libs"] = needed_libs
    _set_signal(profile, "has_interp", has_interp)
    _set_signal(profile, "has_dynamic_segment", has_dynamic_segment)
    _set_signal(profile, "has_dynamic_needed", bool(needed_libs))

    if has_interp:
        scores["Linux User-space Executable"] += 18
        _add_indicator(profile, "PT_INTERP present (dynamic loader required)")

    if has_dynamic_segment:
        scores["Linux User-space Executable"] += 6
        scores["Linux Shared Library"] += 4
        _add_indicator(profile, "PT_DYNAMIC present")

    if needed_libs:
        scores["Linux User-space Executable"] += 8
        scores["Linux Shared Library"] += 8
        _add_indicator(profile, f"DT_NEEDED entries present ({len(needed_libs)})")
    else:
        _add_indicator(profile, "No DT_NEEDED entries found")

    if etype == "ET_DYN" and has_interp:
        scores["Linux User-space Executable"] += 8
        _add_indicator(profile, "ET_DYN + PT_INTERP (PIE executable shape)")
    elif etype == "ET_DYN" and needed_libs and not has_interp:
        scores["Linux Shared Library"] += 12
        _add_indicator(profile, "ET_DYN + DT_NEEDED without interpreter (shared library shape)")
    elif etype == "ET_EXEC" and has_interp:
        scores["Linux User-space Executable"] += 10
        _add_indicator(profile, "ET_EXEC + PT_INTERP (classic executable shape)")
    elif etype == "ET_REL":
        scores["Relocatable Object"] += 14
        _add_indicator(profile, "ET_REL relocatable object")

    if not has_interp and not needed_libs:
        if machine in ARTIFACT_EMBEDDED_MACHINES:
            scores["Bare-metal Firmware"] += 8
        elif machine in {"EM_X86_64", "EM_386", "EM_486"}:
            scores["Static User-space Executable"] += 8
        else:
            scores["Bare-metal Firmware"] += 4
        _set_signal(profile, "static_no_loader", True)
        _add_indicator(profile, "No interpreter and no dynamic dependencies")

    if (
        etype == "ET_EXEC"
        and machine in {"EM_X86_64", "EM_386", "EM_486"}
        and not has_interp
        and not needed_libs
    ):
        scores["Static User-space Executable"] += 8
        _add_indicator(profile, "ET_EXEC static x86/x86_64 executable shape")


def score_artifact_sections(elf, scores, profile):
    section_names = {section.name.lower() for section in elf.iter_sections()}

    for marker in ARTIFACT_SECTION_MARKERS["firmware"]:
        if marker in section_names:
            scores["Bare-metal Firmware"] += 5
            _add_indicator(profile, f"Firmware section marker: {marker}")

    for marker in ARTIFACT_SECTION_MARKERS["kernel_module"]:
        if marker in section_names:
            scores["Linux Kernel Module"] += 16
            _add_indicator(profile, f"Kernel module section marker: {marker}")

    if ".note.go.buildid" in section_names:
        _set_signal(profile, "go_runtime_present", True)
        _add_indicator(profile, "Go build note present")

    if ".note.abi-tag" in section_names:
        scores["Linux User-space Executable"] += 2
    if ".note.gnu.build-id" in section_names:
        machine = profile.get("machine", "Unknown")
        if machine in {"EM_X86_64", "EM_386", "EM_486"} and profile.get("signals", {}).get(
            "static_no_loader", False
        ):
            scores["Static User-space Executable"] += 3

    if ".binary_info" in section_names:
        _add_hint(profile, "sdk_hints", "Pico SDK")
        _add_hint(profile, "target_hints", "RP2040 (ARM Cortex-M0+)")


def _count_marker_hits(data_blobs, markers):
    hits = set()
    for data in data_blobs:
        for marker in markers:
            if marker in data:
                hits.add(marker)
    return hits


def score_artifact_strings(elf, scores, profile):
    blobs = []
    build_system_hits = {name: 0 for name in BUILD_SYSTEM_MARKERS}
    machine = profile.get("machine", "Unknown")
    embedded_machine = machine in ARTIFACT_EMBEDDED_MACHINES

    for section_name in ARTIFACT_STRING_SCAN_SECTIONS:
        data = read_section_data(elf, section_name)
        if not data:
            continue
        blobs.append(data)

        for build_system, markers in BUILD_SYSTEM_MARKERS.items():
            for marker in markers:
                if marker in data:
                    build_system_hits[build_system] += 1

    pico_hits = _count_marker_hits(blobs, ARTIFACT_PICO_STRING_MARKERS)
    cmsis_hits = _count_marker_hits(blobs, ARTIFACT_CMSIS_MARKERS)
    freertos_hits = _count_marker_hits(blobs, ARTIFACT_FREERTOS_MARKERS)
    zephyr_hits = _count_marker_hits(blobs, ARTIFACT_ZEPHYR_MARKERS)
    rtthread_hits = _count_marker_hits(blobs, ARTIFACT_RTTHREAD_MARKERS)
    newlib_hits = _count_marker_hits(blobs, ARTIFACT_NEWLIB_MARKERS)
    glibc_hits = _count_marker_hits(blobs, ARTIFACT_GLIBC_MARKERS)
    csharp_hits = _count_marker_hits(blobs, CSHARP_STRING_MARKERS)
    dart_hits = _count_marker_hits(blobs, DART_STRONG_MARKERS)

    if len(pico_hits) >= 2:
        scores["Bare-metal Firmware"] += 12
        if embedded_machine:
            _add_hint(profile, "sdk_hints", "Pico SDK")
        _add_hint(profile, "target_hints", "RP2040 (ARM Cortex-M0+)")
        _add_indicator(profile, f"Pico SDK string markers: {len(pico_hits)}")
    elif len(pico_hits) == 1:
        scores["Bare-metal Firmware"] += 6
        if embedded_machine:
            _add_hint(profile, "sdk_hints", "Pico SDK")
        _add_indicator(profile, "Single Pico SDK string marker")

    if len(cmsis_hits) >= 2:
        scores["Bare-metal Firmware"] += 6
        _add_hint(profile, "target_hints", "ARM Cortex-M")
        _add_indicator(profile, f"CMSIS/Cortex-M strings: {len(cmsis_hits)}")

    if len(freertos_hits) >= 2:
        scores["Bare-metal Firmware"] += 6
        _add_hint(profile, "rtos_hints", "FreeRTOS")
        _add_indicator(profile, f"FreeRTOS strings: {len(freertos_hits)}")
    elif len(freertos_hits) == 1:
        scores["Bare-metal Firmware"] += 3
        _add_hint(profile, "rtos_hints", "FreeRTOS")

    if len(zephyr_hits) >= 2:
        scores["Bare-metal Firmware"] += 6
        _add_hint(profile, "rtos_hints", "Zephyr")
        _add_indicator(profile, f"Zephyr strings: {len(zephyr_hits)}")

    if len(rtthread_hits) >= 2:
        scores["Bare-metal Firmware"] += 6
        _add_hint(profile, "rtos_hints", "RT-Thread")
        _add_indicator(profile, f"RT-Thread strings: {len(rtthread_hits)}")

    if len(newlib_hits) >= 3:
        scores["Bare-metal Firmware"] += 5
        _add_hint(profile, "runtime_hints", "newlib")
        _add_indicator(profile, f"newlib/syscall stub strings: {len(newlib_hits)}")
    elif len(newlib_hits) >= 1:
        _add_hint(profile, "runtime_hints", "newlib")

    if len(glibc_hits) >= 1:
        scores["Linux User-space Executable"] += 6
        _add_hint(profile, "runtime_hints", "glibc")
        _add_indicator(profile, "glibc runtime marker present")

    if csharp_hits:
        _set_signal(profile, "dotnet_runtime_present", True)
    if dart_hits:
        _set_signal(profile, "dart_runtime_present", True)

    for build_system, hit_count in build_system_hits.items():
        if hit_count:
            _add_hint(profile, "build_hints", build_system)


def score_artifact_symbols(elf, scores, profile):
    symbols = collect_symbol_names(elf.get_section_by_name(".symtab"), elf.get_section_by_name(".dynsym"))
    if not symbols:
        return
    machine = profile.get("machine", "Unknown")
    embedded_machine = machine in ARTIFACT_EMBEDDED_MACHINES

    if "__libc_start_main" in symbols:
        scores["Linux User-space Executable"] += 10
        scores["Static User-space Executable"] += 6
        _add_hint(profile, "runtime_hints", "glibc")
        _add_indicator(profile, "__libc_start_main symbol present")

    kernel_module_hits = 0
    for marker in ARTIFACT_KERNEL_MODULE_SYMBOL_MARKERS:
        if marker in symbols:
            kernel_module_hits += 1
    if kernel_module_hits >= 2:
        scores["Linux Kernel Module"] += 14
        _add_indicator(profile, f"Kernel module symbols: {kernel_module_hits}")

    pico_symbol_hits = 0
    for name in symbols:
        if any(marker in name for marker in ARTIFACT_PICO_SYMBOL_MARKERS):
            pico_symbol_hits += 1

    if pico_symbol_hits >= 4:
        scores["Bare-metal Firmware"] += 10
        if embedded_machine:
            _add_hint(profile, "sdk_hints", "Pico SDK")
        _add_hint(profile, "target_hints", "RP2040 (ARM Cortex-M0+)")
        _add_indicator(profile, f"Pico SDK symbol markers: {pico_symbol_hits}")
    elif pico_symbol_hits >= 1:
        scores["Bare-metal Firmware"] += 4
        if embedded_machine:
            _add_hint(profile, "sdk_hints", "Pico SDK")

    if any(name.startswith(("go.", "go.func.", "go.itab.", "go:")) for name in symbols):
        _set_signal(profile, "go_runtime_present", True)
    if any("hostfxr" in name or "coreclr" in name or "dotnet" in name or "mono_" in name for name in symbols):
        _set_signal(profile, "dotnet_runtime_present", True)
    if any(name.startswith("dart_") for name in symbols):
        _set_signal(profile, "dart_runtime_present", True)

    syscall_stubs = {
        "_sbrk",
        "_sbrk_r",
        "_write",
        "_write_r",
        "_read",
        "_read_r",
        "_fstat",
        "_fstat_r",
        "_isatty",
        "_isatty_r",
        "_close",
        "_close_r",
        "_exit",
    }
    syscall_hit_count = sum(1 for name in syscall_stubs if name in symbols)
    if syscall_hit_count >= 5:
        scores["Bare-metal Firmware"] += 6
        _add_hint(profile, "runtime_hints", "newlib")
        _add_indicator(profile, f"newlib syscall stubs: {syscall_hit_count}")


def score_artifact_memory_map(elf, scores, profile):
    machine = _machine_name(elf)
    entry = _entry_address(elf)
    signals = profile.setdefault("signals", {})
    has_interp = bool(signals.get("has_interp", False))
    needed_libs = bool(signals.get("has_dynamic_needed", False))

    if machine == "EM_ARM" and not has_interp and not needed_libs:
        if 0x10000000 <= entry < 0x11000000:
            scores["Bare-metal Firmware"] += 8
            _add_hint(profile, "target_hints", "RP2040 (ARM Cortex-M0+)")
            _add_indicator(profile, f"Entry address in XIP-like flash region: {entry:#x}")
        elif 0x08000000 <= entry < 0x10000000:
            scores["Bare-metal Firmware"] += 6
            _add_hint(profile, "target_hints", "ARM Cortex-M")
            _add_indicator(profile, f"Entry address in MCU flash region: {entry:#x}")

    for segment in _iter_segments(elf):
        p_type = _header_value(segment.header, "p_type")
        if p_type != "PT_LOAD":
            continue

        try:
            data = segment.data()
        except Exception:
            continue

        candidate = _scan_vector_candidate(data, machine)
        if not candidate:
            continue

        offset, stack_ptr, reset_addr = candidate
        scores["Bare-metal Firmware"] += 12
        _add_hint(profile, "target_hints", "ARM Cortex-M")
        _add_indicator(
            profile,
            f"Vector-table-like pattern at PT_LOAD+0x{offset:x} "
            f"(SP={stack_ptr:#x}, Reset={reset_addr:#x})",
        )

        if 0x20000000 <= stack_ptr < 0x20042000 and 0x10000000 <= reset_addr < 0x11000000:
            scores["Bare-metal Firmware"] += 10
            _add_hint(profile, "target_hints", "RP2040 (ARM Cortex-M0+)")
            _add_hint(profile, "sdk_hints", "Pico SDK")
            _add_indicator(profile, "Vector pattern aligns with RP2040 SRAM/flash ranges")
        break

    if machine in {"EM_X86_64", "EM_386", "EM_486"} and not has_interp and not needed_libs:
        if 0x400000 <= entry < 0x800000:
            scores["Static User-space Executable"] += 8
            _add_indicator(profile, f"Entry address in typical Linux static text range: {entry:#x}")
