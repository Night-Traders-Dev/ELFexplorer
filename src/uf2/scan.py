import struct
from datetime import datetime, timezone
from pathlib import Path

from detect.constants import (
    ARTIFACT_CMSIS_MARKERS,
    ARTIFACT_FREERTOS_MARKERS,
    ARTIFACT_GLIBC_MARKERS,
    ARTIFACT_HEURISTICS,
    ARTIFACT_NEWLIB_MARKERS,
    ARTIFACT_PICO_STRING_MARKERS,
    ARTIFACT_RTTHREAD_MARKERS,
    ARTIFACT_ZEPHYR_MARKERS,
    BUILD_SYSTEM_HEURISTICS,
    BUILD_SYSTEM_MARKERS,
    COMPILER_CLANG_STRING_MARKERS,
    COMPILER_DMD_STRING_MARKERS,
    COMPILER_FASM_STRING_MARKERS,
    COMPILER_FREEPASCAL_STRING_MARKERS,
    COMPILER_GCC_STRING_MARKERS,
    COMPILER_GDC_STRING_MARKERS,
    COMPILER_GFORTRAN_STRING_MARKERS,
    COMPILER_GHC_STRING_MARKERS,
    COMPILER_GO_STRING_MARKERS,
    COMPILER_HEURISTICS,
    COMPILER_INTEL_STRING_MARKERS,
    COMPILER_LDC_STRING_MARKERS,
    COMPILER_MASM_STRING_MARKERS,
    COMPILER_NASM_STRING_MARKERS,
    COMPILER_GNAT_STRING_MARKERS,
    COMPILER_OCAMLOPT_STRING_MARKERS,
    COMPILER_RUSTC_STRING_MARKERS,
    COMPILER_TASM_STRING_MARKERS,
    COMPILER_TINYCC_STRING_MARKERS,
    COMPILER_YASM_STRING_MARKERS,
    COMPILER_ZIG_STRING_MARKERS,
    CRYSTAL_STRING_MARKERS,
    CSHARP_STRING_MARKERS,
    DART_STRONG_MARKERS,
    DART_TOKEN_PATTERN,
    HASKELL_STRING_MARKERS,
    JULIA_STRING_MARKERS,
    KOTLIN_NATIVE_STRING_MARKERS,
    LUA_STRING_MARKERS,
    NIM_STRING_MARKERS,
    OBJC_STRING_MARKERS,
    OCAML_STRING_MARKERS,
    PASCAL_STRING_MARKERS,
    PERL_STRING_MARKERS,
    R_STRING_MARKERS,
    RUBY_STRING_MARKERS,
    SAGELANG_GENERATED_C_PATTERN,
    SAGELANG_RUNTIME_STRINGS,
    SAGELANG_STRONG_STRING_MARKERS,
    SAGELANG_TOKEN_PATTERN,
    SUPPORTED_LANGUAGES,
    TCL_STRING_MARKERS,
    ZIG_STRING_MARKERS,
    ZIG_TOKEN_PATTERN,
)
from detect.utils import empty_scores
from version import get_version

UF2_BLOCK_SIZE = 512
UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_FLAG_FAMILY_ID_PRESENT = 0x00002000

UF2_FAMILY_NAMES = {
    0xE48BFF56: "RP2040",
}


def _report_timestamp():
    return datetime.now(timezone.utc).isoformat()


def _as_hex_family(family_id):
    name = UF2_FAMILY_NAMES.get(family_id)
    if name:
        return f"0x{family_id:08X} ({name})"
    return f"0x{family_id:08X}"


def is_uf2_file(path):
    try:
        with open(path, "rb") as handle:
            header = handle.read(UF2_BLOCK_SIZE)
    except Exception:
        return False

    if len(header) < UF2_BLOCK_SIZE:
        return False

    magic0, magic1 = struct.unpack_from("<II", header, 0)
    magic_end = struct.unpack_from("<I", header, 508)[0]
    return magic0 == UF2_MAGIC_START0 and magic1 == UF2_MAGIC_START1 and magic_end == UF2_MAGIC_END


def _parse_uf2_blocks(path):
    data = Path(path).read_bytes()
    if len(data) < UF2_BLOCK_SIZE or (len(data) % UF2_BLOCK_SIZE) != 0:
        raise ValueError("Input is not a valid UF2 file (size is not a UF2 block multiple).")

    blocks = []
    family_ids = set()
    declared_counts = set()

    for offset in range(0, len(data), UF2_BLOCK_SIZE):
        block = data[offset : offset + UF2_BLOCK_SIZE]
        (
            magic0,
            magic1,
            flags,
            target_addr,
            payload_size,
            block_no,
            num_blocks,
            file_size_or_family,
        ) = struct.unpack_from("<IIIIIIII", block, 0)
        magic_end = struct.unpack_from("<I", block, 508)[0]

        if (
            magic0 != UF2_MAGIC_START0
            or magic1 != UF2_MAGIC_START1
            or magic_end != UF2_MAGIC_END
        ):
            raise ValueError("Input is not a valid UF2 file (bad UF2 block magic).")

        if payload_size > 476:
            raise ValueError("Input is not a valid UF2 file (invalid payload size in block).")

        payload = block[32 : 32 + payload_size]
        family_id = None
        if flags & UF2_FLAG_FAMILY_ID_PRESENT:
            family_id = file_size_or_family
            family_ids.add(family_id)

        if num_blocks:
            declared_counts.add(num_blocks)

        blocks.append(
            {
                "flags": flags,
                "target_addr": target_addr,
                "payload_size": payload_size,
                "block_no": block_no,
                "num_blocks": num_blocks,
                "family_id": family_id,
                "payload": payload,
            }
        )

    return blocks, family_ids, declared_counts


def _marker_hits(blob, markers):
    return {marker for marker in markers if marker in blob}


def _token_hits(blob, pattern):
    try:
        return len(pattern.findall(blob))
    except Exception:
        return 0


def _detect_artifact_profile(blob, family_ids):
    scores = empty_scores(ARTIFACT_HEURISTICS)
    profile = {
        "indicators": [],
        "target_hints": [],
        "sdk_hints": [],
        "rtos_hints": [],
        "runtime_hints": [],
        "build_hints": [],
        "signals": {"uf2_image": True},
        "needed_libs": [],
        "machine": "Unknown",
        "elf_type": "UF2",
        "loader": "None",
    }

    scores["Bare-metal Firmware"] += 30
    profile["indicators"].append("UF2 container format detected")

    pico_hits = _marker_hits(blob, ARTIFACT_PICO_STRING_MARKERS)
    cmsis_hits = _marker_hits(blob, ARTIFACT_CMSIS_MARKERS)
    freertos_hits = _marker_hits(blob, ARTIFACT_FREERTOS_MARKERS)
    zephyr_hits = _marker_hits(blob, ARTIFACT_ZEPHYR_MARKERS)
    rtthread_hits = _marker_hits(blob, ARTIFACT_RTTHREAD_MARKERS)
    newlib_hits = _marker_hits(blob, ARTIFACT_NEWLIB_MARKERS)
    glibc_hits = _marker_hits(blob, ARTIFACT_GLIBC_MARKERS)

    if pico_hits:
        scores["Bare-metal Firmware"] += 12
        profile["sdk_hints"].append("Pico SDK")
        profile["target_hints"].append("RP2040 (ARM Cortex-M0+)")
        profile["indicators"].append(f"Pico SDK markers: {len(pico_hits)}")

    if cmsis_hits:
        scores["Bare-metal Firmware"] += 6
        profile["target_hints"].append("ARM Cortex-M")
        profile["indicators"].append(f"CMSIS markers: {len(cmsis_hits)}")

    if freertos_hits:
        scores["Bare-metal Firmware"] += 6
        profile["rtos_hints"].append("FreeRTOS")
    if zephyr_hits:
        scores["Bare-metal Firmware"] += 6
        profile["rtos_hints"].append("Zephyr")
    if rtthread_hits:
        scores["Bare-metal Firmware"] += 6
        profile["rtos_hints"].append("RT-Thread")

    if newlib_hits:
        profile["runtime_hints"].append("newlib")
        scores["Bare-metal Firmware"] += 3
    if glibc_hits:
        profile["runtime_hints"].append("glibc")
        scores["Linux User-space Executable"] += 4

    for family_id in sorted(family_ids):
        if family_id == 0xE48BFF56:
            profile["target_hints"].append("RP2040 (ARM Cortex-M0+)")
            profile["sdk_hints"].append("Pico SDK (likely)")
            profile["build_hints"].append("CMake (likely)")
            scores["Bare-metal Firmware"] += 10
            profile["indicators"].append("UF2 family id indicates RP2040")

    artifact_type = max(scores, key=scores.get)
    ordered_scores = sorted(scores.values(), reverse=True)
    top_score = ordered_scores[0] if ordered_scores else 0
    second_score = ordered_scores[1] if len(ordered_scores) > 1 else 0
    margin = max(0, top_score - second_score)
    confidence = max(45, min(99, 50 + top_score + (margin * 2)))

    profile["artifact_type"] = artifact_type
    profile["confidence"] = confidence
    profile["target"] = ", ".join(sorted(set(profile["target_hints"]))) or "Unknown"
    profile["sdk"] = ", ".join(sorted(set(profile["sdk_hints"]))) or "Unknown"
    profile["rtos"] = ", ".join(sorted(set(profile["rtos_hints"]))) or "None detected"
    profile["runtime"] = ", ".join(sorted(set(profile["runtime_hints"]))) or "Unknown"
    profile["build_hints_text"] = ", ".join(sorted(set(profile["build_hints"]))) or "Unknown"
    profile["linkage_model"] = "Static bare-metal"
    profile["scores"] = dict(scores)
    return profile


def _detect_language(blob, artifact_profile):
    scores = empty_scores(SUPPORTED_LANGUAGES)

    scores["C"] += 2
    if artifact_profile.get("artifact_type") == "Bare-metal Firmware":
        scores["C"] += 4

    sagelang_strong_hits = _marker_hits(blob, SAGELANG_STRONG_STRING_MARKERS)
    sagelang_runtime_hits = _marker_hits(blob, SAGELANG_RUNTIME_STRINGS)
    sagelang_token_hits = _token_hits(blob, SAGELANG_TOKEN_PATTERN)
    sagelang_generated_c_hits = _token_hits(blob, SAGELANG_GENERATED_C_PATTERN)

    if len(sagelang_strong_hits) >= 2:
        scores["SageLang"] += 22
    elif len(sagelang_strong_hits) == 1 and len(sagelang_runtime_hits) >= 1:
        scores["SageLang"] += 12

    if sagelang_token_hits >= 8:
        scores["SageLang"] += 8
    elif sagelang_token_hits >= 3:
        scores["SageLang"] += 4

    if sagelang_generated_c_hits:
        scores["C"] += 8
        if len(sagelang_strong_hits) == 0:
            scores["SageLang"] = max(0, scores["SageLang"] - 6)

    dart_strong_hits = _marker_hits(blob, DART_STRONG_MARKERS)
    dart_token_hits = _token_hits(blob, DART_TOKEN_PATTERN)
    if len(dart_strong_hits) >= 2 or (len(dart_strong_hits) >= 1 and dart_token_hits >= 3):
        scores["Dart"] += 20
    elif len(dart_strong_hits) == 1:
        scores["Dart"] += 8

    csharp_hits = _marker_hits(blob, CSHARP_STRING_MARKERS)
    if len(csharp_hits) >= 2:
        scores["C#"] += 18
    elif len(csharp_hits) == 1:
        scores["C#"] += 4

    nim_hits = _marker_hits(blob, NIM_STRING_MARKERS)
    if len(nim_hits) >= 2:
        scores["Nim"] += 14
    elif len(nim_hits) == 1:
        scores["Nim"] += 6

    zig_hits = _marker_hits(blob, ZIG_STRING_MARKERS)
    zig_token_hits = _token_hits(blob, ZIG_TOKEN_PATTERN)
    if len(zig_hits) >= 2 or zig_token_hits >= 3:
        scores["Zig"] += 14
    elif len(zig_hits) == 1:
        scores["Zig"] += 6

    kotlin_hits = _marker_hits(blob, KOTLIN_NATIVE_STRING_MARKERS)
    if len(kotlin_hits) >= 2:
        scores["Kotlin/Native"] += 14
    elif len(kotlin_hits) == 1:
        scores["Kotlin/Native"] += 6

    pascal_hits = _marker_hits(blob, PASCAL_STRING_MARKERS)
    if len(pascal_hits) >= 2:
        scores["Pascal"] += 12
    elif len(pascal_hits) == 1:
        scores["Pascal"] += 5

    crystal_hits = _marker_hits(blob, CRYSTAL_STRING_MARKERS)
    if len(crystal_hits) >= 2:
        scores["Crystal"] += 12
    elif len(crystal_hits) == 1:
        scores["Crystal"] += 5

    haskell_hits = _marker_hits(blob, HASKELL_STRING_MARKERS)
    if len(haskell_hits) >= 2:
        scores["Haskell"] += 12
    elif len(haskell_hits) == 1:
        scores["Haskell"] += 5

    ocaml_hits = _marker_hits(blob, OCAML_STRING_MARKERS)
    if len(ocaml_hits) >= 2:
        scores["OCaml"] += 12
    elif len(ocaml_hits) == 1:
        scores["OCaml"] += 5

    julia_hits = _marker_hits(blob, JULIA_STRING_MARKERS)
    if len(julia_hits) >= 2:
        scores["Julia"] += 12
    elif len(julia_hits) == 1:
        scores["Julia"] += 5

    lua_hits = _marker_hits(blob, LUA_STRING_MARKERS)
    if len(lua_hits) >= 2:
        scores["Lua"] += 12
    elif len(lua_hits) == 1:
        scores["Lua"] += 5

    ruby_hits = _marker_hits(blob, RUBY_STRING_MARKERS)
    if len(ruby_hits) >= 2:
        scores["Ruby"] += 12
    elif len(ruby_hits) == 1:
        scores["Ruby"] += 5

    perl_hits = _marker_hits(blob, PERL_STRING_MARKERS)
    if len(perl_hits) >= 2:
        scores["Perl"] += 12
    elif len(perl_hits) == 1:
        scores["Perl"] += 5

    tcl_hits = _marker_hits(blob, TCL_STRING_MARKERS)
    if len(tcl_hits) >= 2:
        scores["Tcl"] += 12
    elif len(tcl_hits) == 1:
        scores["Tcl"] += 5

    r_hits = _marker_hits(blob, R_STRING_MARKERS)
    if len(r_hits) >= 2:
        scores["R"] += 12
    elif len(r_hits) == 1:
        scores["R"] += 5

    objc_hits = _marker_hits(blob, OBJC_STRING_MARKERS)
    if len(objc_hits) >= 2:
        scores["Objective-C"] += 12
    elif len(objc_hits) == 1:
        scores["Objective-C"] += 5

    if b"runtime.main" in blob or b"runtime.rt0_go" in blob or b"go build id" in blob:
        scores["Go"] += 14
    if b"rust_begin_unwind" in blob or b"__rust_alloc" in blob or b"_zn4core" in blob:
        scores["Rust"] += 14

    cpp_markers = (
        b"std::",
        b"__cxa_",
        b"__gxx_personality_v0",
        b"_zti",
        b"_ztv",
    )
    cpp_hits = _marker_hits(blob, cpp_markers)
    if len(cpp_hits) >= 2:
        scores["C++"] += 10
    elif len(cpp_hits) == 1:
        scores["C++"] += 4

    if scores["C++"] == 0 and scores["Go"] == 0 and scores["Rust"] == 0:
        if not csharp_hits and not dart_strong_hits and not nim_hits and not zig_hits:
            scores["C"] += 4

    max_score = max(scores.values())
    top = [lang for lang, score in scores.items() if score == max_score and score > 0]
    if max_score < 3:
        return "Unknown", scores
    if len(top) == 1:
        return top[0], scores
    return "Ambiguous: " + "/".join(top), scores


def _score_compiler_markers(blob, marker_map, scores):
    for compiler, markers in marker_map.items():
        hits = _marker_hits(blob, markers)
        count = len(hits)
        if count >= 3:
            scores[compiler] += 10
        elif count >= 2:
            scores[compiler] += 7
        elif count == 1:
            scores[compiler] += 4


def _detect_compiler(blob, source_language, artifact_profile):
    scores = empty_scores(COMPILER_HEURISTICS)
    marker_map = {
        "GCC": COMPILER_GCC_STRING_MARKERS,
        "Clang": COMPILER_CLANG_STRING_MARKERS,
        "Intel ICC/ICX": COMPILER_INTEL_STRING_MARKERS,
        "TinyCC": COMPILER_TINYCC_STRING_MARKERS,
        "FreePascal": COMPILER_FREEPASCAL_STRING_MARKERS,
        "DMD": COMPILER_DMD_STRING_MARKERS,
        "GNAT": COMPILER_GNAT_STRING_MARKERS,
        "GFortran": COMPILER_GFORTRAN_STRING_MARKERS,
        "Rustc": COMPILER_RUSTC_STRING_MARKERS,
        "Go gc": COMPILER_GO_STRING_MARKERS,
        "Zig": COMPILER_ZIG_STRING_MARKERS,
        "LDC": COMPILER_LDC_STRING_MARKERS,
        "GDC": COMPILER_GDC_STRING_MARKERS,
        "YASM": COMPILER_YASM_STRING_MARKERS,
        "NASM": COMPILER_NASM_STRING_MARKERS,
        "FASM": COMPILER_FASM_STRING_MARKERS,
        "MASM": COMPILER_MASM_STRING_MARKERS,
        "TASM": COMPILER_TASM_STRING_MARKERS,
        "GHC": COMPILER_GHC_STRING_MARKERS,
        "OCamlopt": COMPILER_OCAMLOPT_STRING_MARKERS,
    }
    _score_compiler_markers(blob, marker_map, scores)

    if source_language in {"C", "C++", "ASM"}:
        if scores["GCC"] > 0 and scores["Clang"] == 0:
            scores["GCC"] += 2
        if scores["Clang"] > 0 and scores["GCC"] == 0:
            scores["Clang"] += 2

    target_hint = artifact_profile.get("target", "")
    runtime_hint = artifact_profile.get("runtime", "")
    if (
        scores["GCC"] == 0
        and scores["Clang"] == 0
        and source_language in {"C", "C++", "ASM"}
        and "RP2040" in target_hint
        and runtime_hint in {"newlib", "newlib, glibc"}
    ):
        scores["GCC"] += 3

    max_score = max(scores.values())
    top = [compiler for compiler, score in scores.items() if score == max_score and score > 0]
    if max_score < 3:
        return "Unknown", scores
    if len(top) == 1:
        return top[0], scores
    return "Ambiguous: " + "/".join(top), scores


def _detect_build_system(blob, artifact_profile):
    scores = empty_scores(BUILD_SYSTEM_HEURISTICS)

    for build_system, markers in BUILD_SYSTEM_MARKERS.items():
        hits = _marker_hits(blob, markers)
        if len(hits) >= 2:
            scores[build_system] += 8
        elif len(hits) == 1:
            scores[build_system] += 4

    pico_hits = _marker_hits(blob, ARTIFACT_PICO_STRING_MARKERS)
    if pico_hits:
        scores["Pico SDK"] += 8
        scores["CMake"] += 4

    if artifact_profile.get("sdk") == "Pico SDK":
        scores["Pico SDK"] += 4
    if "Pico SDK (likely)" in artifact_profile.get("sdk", ""):
        scores["Pico SDK"] += 3
        scores["CMake"] += 2
    if "RP2040" in artifact_profile.get("target", ""):
        scores["Pico SDK"] += 2

    max_score = max(scores.values())
    top = [system for system, score in scores.items() if score == max_score and score > 0]
    if max_score < 3:
        return "Unknown", scores
    if len(top) == 1:
        return top[0], scores
    return "Ambiguous: " + "/".join(top), scores


def _render_uf2_metadata(blocks, family_ids, declared_counts):
    total_payload = sum(block["payload_size"] for block in blocks)
    min_addr = min((block["target_addr"] for block in blocks), default=None)
    max_addr = max(
        (block["target_addr"] + block["payload_size"] for block in blocks),
        default=None,
    )

    lines = [
        "----- General UF2 Information -----",
        "File Type: UF2",
        f"Blocks: {len(blocks)}",
        f"Payload Bytes: {total_payload}",
    ]
    if declared_counts:
        declared = ", ".join(str(value) for value in sorted(declared_counts))
        lines.append(f"Declared Block Count: {declared}")
    if min_addr is not None and max_addr is not None:
        lines.append(f"Address Range: 0x{min_addr:08x} - 0x{max_addr:08x}")
    if family_ids:
        families = ", ".join(_as_hex_family(family_id) for family_id in sorted(family_ids))
        lines.append(f"Family IDs: {families}")
    else:
        lines.append("Family IDs: None")
    return "\n".join(lines)


def scan_uf2_file(filepath, mode="general"):
    input_path = Path(filepath).expanduser()
    resolved_path = str(input_path.resolve()) if input_path.exists() else str(input_path)

    blocks, family_ids, declared_counts = _parse_uf2_blocks(input_path)
    payload_blob = b"\x00".join(
        block["payload"].lower()
        for block in sorted(blocks, key=lambda block: (block["block_no"], block["target_addr"]))
    )

    artifact_profile = _detect_artifact_profile(payload_blob, family_ids)
    source_language, language_scores = _detect_language(payload_blob, artifact_profile)
    compiler, compiler_scores = _detect_compiler(payload_blob, source_language, artifact_profile)
    build_system, build_scores = _detect_build_system(payload_blob, artifact_profile)

    scan_result = {
        "artifact_profile": artifact_profile,
        "source_language": source_language,
        "language_scores": language_scores,
        "compiler": compiler,
        "compiler_scores": compiler_scores,
        "build_system": build_system,
        "build_scores": build_scores,
    }

    metadata_text = _render_uf2_metadata(blocks, family_ids, declared_counts)
    return {
        "file": resolved_path,
        "mode": mode,
        "version": get_version(),
        "generated_at": _report_timestamp(),
        "scan_result": scan_result,
        "metadata_text": metadata_text,
    }
