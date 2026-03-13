import re
import struct
from datetime import datetime, timezone
from pathlib import Path

from advanced.explain import build_scan_explanations
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
UF2_FLAG_NOT_MAIN_FLASH = 0x00000001
UF2_FLAG_FILE_CONTAINER = 0x00001000
UF2_FLAG_FAMILY_ID_PRESENT = 0x00002000
UF2_FLAG_MD5_PRESENT = 0x00004000
UF2_FLAG_EXTENSION_TAGS_PRESENT = 0x00008000

UF2_EXTENSION_TAG_FIRMWARE_VERSION = 0x9FC7BC
UF2_EXTENSION_TAG_DEVICE_DESCRIPTION = 0x650D9D
UF2_EXTENSION_TAG_PAGE_SIZE = 0x0BE9F7
UF2_EXTENSION_TAG_SHA2 = 0xB46DB0
UF2_EXTENSION_TAG_DEVICE_TYPE = 0xC8A729

UF2_FAMILY_INFO = {
    0x16573617: ("ATMEGA32", "Microchip (Atmel) ATmega32"),
    0x1851780A: ("SAML21", "Microchip (Atmel) SAML21"),
    0x1B57745F: ("NRF52", "Nordic NRF52"),
    0x1C5F21B0: ("ESP32", "ESP32"),
    0x1E1F432D: ("STM32L1", "ST STM32L1xx"),
    0x202E3A91: ("STM32L0", "ST STM32L0xx"),
    0x21460FF0: ("STM32WL", "ST STM32WLxx"),
    0x2ABC77EC: ("LPC55", "NXP LPC55xx"),
    0x300F5633: ("STM32G0", "ST STM32G0xx"),
    0x31D228C6: ("GD32F350", "GD32F350"),
    0x4FB2D5BD: ("MIMXRT10XX", "NXP i.MX RT10XX"),
    0x53B80F00: ("STM32F7", "ST STM32F7xx"),
    0x55114460: ("SAMD51", "Microchip (Atmel) SAMD51"),
    0x57755A57: ("STM32F4", "ST STM32F4xx"),
    0x5A18069B: ("FX2", "Cypress FX2"),
    0x5D1A0A2E: ("STM32F2", "ST STM32F2xx"),
    0x5EE21072: ("STM32F1", "ST STM32F103"),
    0x621E937A: ("NRF52833", "Nordic NRF52833"),
    0x647824B6: ("STM32F0", "ST STM32F0xx"),
    0x68ED2B88: ("SAMD21", "Microchip (Atmel) SAMD21"),
    0x6B846188: ("STM32F3", "ST STM32F3xx"),
    0x6D0922FA: ("STM32F407", "ST STM32F407"),
    0x6DB66082: ("STM32H7", "ST STM32H7xx"),
    0x70D16653: ("STM32WB", "ST STM32WBxx"),
    0x7EAB61ED: ("ESP8266", "ESP8266"),
    0x820D9A5F: ("NRF52820", "Nordic NRF52820_xxAA"),
    0xADA52840: ("NRF52840", "Nordic NRF52840"),
    0xBFDD4EEE: ("ESP32S2", "ESP32-S2"),
    0xC47E5767: ("ESP32S3", "ESP32-S3"),
    0xD42BA06C: ("ESP32C3", "ESP32-C3"),
    0x2B88D29C: ("ESP32C2", "ESP32-C2"),
    0x332726F6: ("ESP32H2", "ESP32-H2"),
    0x540DDF62: ("ESP32C6", "ESP32-C6"),
    0x3D308E94: ("ESP32P4", "ESP32-P4"),
    0xF71C0343: ("ESP32C5", "ESP32-C5"),
    0x77D850C4: ("ESP32C61", "ESP32-C61"),
    0xB6DD00AF: ("ESP32H21", "ESP32-H21"),
    0x9E0BAA8A: ("ESP32H4", "ESP32-H4"),
    0x3101F7C1: ("ESP32S31", "ESP32-S31"),
    0xE48BFF56: ("RP2040", "Raspberry Pi RP2040"),
    0xE48BFF57: ("RP2XXX_ABSOLUTE", "Raspberry Pi Microcontrollers: Absolute (unpartitioned) download"),
    0xE48BFF58: ("RP2XXX_DATA", "Raspberry Pi Microcontrollers: Data partition download"),
    0xE48BFF59: ("RP2350_ARM_S", "Raspberry Pi RP2350, Secure Arm image"),
    0xE48BFF5A: ("RP2350_RISCV", "Raspberry Pi RP2350, RISC-V image"),
    0xE48BFF5B: ("RP2350_ARM_NS", "Raspberry Pi RP2350, Non-secure Arm image"),
    0x00FF6919: ("STM32L4", "ST STM32L4xx"),
    0x9AF03E33: ("GD32VF103", "GigaDevice GD32VF103"),
    0x72721D4E: ("NRF52832xxAA", "Nordic NRF52832xxAA"),
    0x6F752678: ("NRF52832xxAB", "Nordic NRF52832xxAB"),
    0x699B62EC: ("CH32V", "WCH CH32V2xx and CH32V3xx"),
    0x7BE8976D: ("RA4M1", "Renesas RA4M1"),
}
UF2_FAMILY_NAMES = {family_id: info[0] for family_id, info in UF2_FAMILY_INFO.items()}

UF2_PICO_BOARD_TOKENS = {
    "pico": "Raspberry Pi Pico",
    "pico-w": "Raspberry Pi Pico W",
    "pico2": "Raspberry Pi Pico 2",
    "pico2-w": "Raspberry Pi Pico 2 W",
}

UF2_BOARD_ID_PATTERN = re.compile(rb"Board-ID:\s*([^\r\n]+)")
UF2_MODEL_PATTERN = re.compile(rb"Model:\s*([^\r\n]+)")
UF2_BOOTLOADER_PATTERN = re.compile(rb"UF2 Bootloader[^\r\n]*")
UF2_PICO_BOARD_PATTERN = re.compile(rb"(?:PICO_BOARD|pico_board)\s*[:=]\s*([A-Za-z0-9_.-]+)")


def _report_timestamp():
    return datetime.now(timezone.utc).isoformat()


def _as_hex_family(family_id):
    name = UF2_FAMILY_NAMES.get(family_id)
    if name:
        return f"0x{family_id:08X} ({name})"
    return f"0x{family_id:08X}"


def _decode_utf8(value):
    try:
        return value.decode("utf-8", errors="ignore").strip("\x00 ").strip()
    except Exception:
        return ""


def _align4(value):
    return (value + 3) & ~0x3


def _decode_extension_tag(tag_type, raw_value):
    if tag_type in {UF2_EXTENSION_TAG_FIRMWARE_VERSION, UF2_EXTENSION_TAG_DEVICE_DESCRIPTION}:
        return _decode_utf8(raw_value)
    if tag_type == UF2_EXTENSION_TAG_PAGE_SIZE and len(raw_value) >= 4:
        return struct.unpack_from("<I", raw_value, 0)[0]
    if tag_type == UF2_EXTENSION_TAG_DEVICE_TYPE:
        if len(raw_value) >= 8:
            return f"0x{struct.unpack_from('<Q', raw_value[:8], 0)[0]:016X}"
        if len(raw_value) >= 4:
            return f"0x{struct.unpack_from('<I', raw_value[:4], 0)[0]:08X}"
    if tag_type == UF2_EXTENSION_TAG_SHA2:
        return raw_value.hex()
    return raw_value.hex()


def _parse_extension_tags(block, payload_size):
    tags = []
    offset = 32 + _align4(payload_size)
    end = 32 + 476
    while offset + 4 <= end:
        size = block[offset]
        tag_type = block[offset + 1] | (block[offset + 2] << 8) | (block[offset + 3] << 16)
        if size == 0 and tag_type == 0:
            break
        if size < 4 or offset + size > end:
            break
        raw_value = bytes(block[offset + 4 : offset + size])
        tags.append(
            {
                "type": tag_type,
                "size": size,
                "raw": raw_value.hex(),
                "value": _decode_extension_tag(tag_type, raw_value),
            }
        )
        offset += _align4(size)
    return tags


def _parse_file_container_name(block, payload_size):
    name_start = 32 + payload_size
    if name_start >= 32 + 476:
        return None
    try:
        raw = bytes(block[name_start : 32 + 476]).split(b"\x00", 1)[0]
    except Exception:
        return None
    name = _decode_utf8(raw)
    return name or None


def _extract_text_hints(blob):
    hints = {
        "board_ids": [],
        "models": [],
        "bootloader_lines": [],
        "pico_boards": [],
    }
    for pattern, key in (
        (UF2_BOARD_ID_PATTERN, "board_ids"),
        (UF2_MODEL_PATTERN, "models"),
        (UF2_BOOTLOADER_PATTERN, "bootloader_lines"),
        (UF2_PICO_BOARD_PATTERN, "pico_boards"),
    ):
        matches = []
        for match in pattern.findall(blob):
            if isinstance(match, tuple):
                match = match[0]
            decoded = _decode_utf8(match if isinstance(match, (bytes, bytearray)) else str(match).encode())
            if decoded:
                matches.append(decoded)
        hints[key] = sorted(set(matches))
    return hints


def _derive_board_hint(text_hints):
    models = text_hints.get("models") or []
    if models:
        return models[0]

    for value in (text_hints.get("board_ids") or []) + (text_hints.get("pico_boards") or []):
        normalized = value.lower()
        for token, label in UF2_PICO_BOARD_TOKENS.items():
            if token in normalized:
                return label

    board_ids = text_hints.get("board_ids") or []
    if board_ids:
        return board_ids[0]
    return "Unknown"


def _family_profile(family_id):
    info = UF2_FAMILY_INFO.get(family_id)
    if not info:
        return None

    short_name, description = info
    profile = {
        "short_name": short_name,
        "description": description,
        "target": description,
        "vendor": "Unknown",
        "arch": "Unknown",
    }

    if short_name.startswith("RP2040"):
        profile.update(
            {
                "target": "RP2040 (ARM Cortex-M0+)",
                "vendor": "Raspberry Pi",
                "arch": "ARM Cortex-M0+",
            }
        )
    elif short_name.startswith("RP2350_ARM_S"):
        profile.update(
            {
                "target": "RP2350 Secure Arm image",
                "vendor": "Raspberry Pi",
                "arch": "ARM Cortex-M33",
            }
        )
    elif short_name.startswith("RP2350_ARM_NS"):
        profile.update(
            {
                "target": "RP2350 Non-secure Arm image",
                "vendor": "Raspberry Pi",
                "arch": "ARM Cortex-M33",
            }
        )
    elif short_name.startswith("RP2350_RISCV"):
        profile.update(
            {
                "target": "RP2350 RISC-V image",
                "vendor": "Raspberry Pi",
                "arch": "RISC-V",
            }
        )
    elif short_name.startswith("RP2XXX_"):
        profile.update(
            {
                "target": description,
                "vendor": "Raspberry Pi",
                "arch": "Unknown",
            }
        )
    elif short_name in {"SAMD21", "SAML21"}:
        profile.update(
            {
                "target": f"{short_name} (ARM Cortex-M0+)",
                "vendor": "Microchip",
                "arch": "ARM Cortex-M0+",
            }
        )
    elif short_name == "SAMD51":
        profile.update(
            {
                "target": "SAMD51 (ARM Cortex-M4F)",
                "vendor": "Microchip",
                "arch": "ARM Cortex-M4F",
            }
        )
    elif short_name.startswith("NRF"):
        profile.update(
            {
                "target": description,
                "vendor": "Nordic",
                "arch": "ARM Cortex-M",
            }
        )
    elif short_name.startswith("ESP32") or short_name == "ESP8266":
        profile.update(
            {
                "target": description,
                "vendor": "Espressif",
                "arch": "Xtensa / RISC-V",
            }
        )
    elif short_name.startswith("STM32"):
        profile.update(
            {
                "target": description,
                "vendor": "STMicroelectronics",
                "arch": "ARM Cortex-M",
            }
        )
    elif short_name == "ATMEGA32":
        profile.update(
            {
                "target": "ATmega32 (AVR)",
                "vendor": "Microchip",
                "arch": "AVR",
            }
        )
    elif short_name in {"LPC55", "KL32L2", "MIMXRT10XX"}:
        profile.update(
            {
                "target": description,
                "vendor": "NXP",
                "arch": "ARM Cortex-M",
            }
        )
    elif short_name == "RA4M1":
        profile.update(
            {
                "target": "Renesas RA4M1 (ARM Cortex-M4)",
                "vendor": "Renesas",
                "arch": "ARM Cortex-M4",
            }
        )
    elif short_name in {"GD32VF103", "CH32V"}:
        profile.update(
            {
                "target": description,
                "vendor": "GigaDevice / WCH",
                "arch": "RISC-V",
            }
        )
    return profile


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
    context = {
        "flag_counts": {
            "not_main_flash": 0,
            "file_container": 0,
            "family_id_present": 0,
            "md5_present": 0,
            "extension_tags_present": 0,
        },
        "file_names": set(),
        "extension_tags": {
            "firmware_versions": set(),
            "device_descriptions": set(),
            "page_sizes": set(),
            "sha2_checksums": set(),
            "device_type_ids": set(),
        },
        "md5_regions": set(),
    }

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
        if flags & UF2_FLAG_NOT_MAIN_FLASH:
            context["flag_counts"]["not_main_flash"] += 1
        if flags & UF2_FLAG_FILE_CONTAINER:
            context["flag_counts"]["file_container"] += 1
        if flags & UF2_FLAG_FAMILY_ID_PRESENT:
            context["flag_counts"]["family_id_present"] += 1
        if flags & UF2_FLAG_FAMILY_ID_PRESENT:
            family_id = file_size_or_family
            family_ids.add(family_id)
        if flags & UF2_FLAG_MD5_PRESENT:
            context["flag_counts"]["md5_present"] += 1
            start, length = struct.unpack_from("<II", block, 32 + 476 - 24)
            context["md5_regions"].add((start, length))
        extension_tags = []
        if flags & UF2_FLAG_EXTENSION_TAGS_PRESENT:
            context["flag_counts"]["extension_tags_present"] += 1
            extension_tags = _parse_extension_tags(block, payload_size)
            for tag in extension_tags:
                tag_type = tag["type"]
                value = tag["value"]
                if tag_type == UF2_EXTENSION_TAG_FIRMWARE_VERSION and value:
                    context["extension_tags"]["firmware_versions"].add(str(value))
                elif tag_type == UF2_EXTENSION_TAG_DEVICE_DESCRIPTION and value:
                    context["extension_tags"]["device_descriptions"].add(str(value))
                elif tag_type == UF2_EXTENSION_TAG_PAGE_SIZE and value:
                    context["extension_tags"]["page_sizes"].add(int(value))
                elif tag_type == UF2_EXTENSION_TAG_SHA2 and value:
                    context["extension_tags"]["sha2_checksums"].add(str(value))
                elif tag_type == UF2_EXTENSION_TAG_DEVICE_TYPE and value:
                    context["extension_tags"]["device_type_ids"].add(str(value))

        file_name = None
        if flags & UF2_FLAG_FILE_CONTAINER:
            file_name = _parse_file_container_name(block, payload_size)
            if file_name:
                context["file_names"].add(file_name)

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
                "file_name": file_name,
                "extension_tags": extension_tags,
            }
        )

    context["file_names"] = sorted(context["file_names"])
    context["md5_regions"] = [
        {"start": start, "length": length}
        for start, length in sorted(context["md5_regions"])
    ]
    for key in context["extension_tags"]:
        values = context["extension_tags"][key]
        if key == "page_sizes":
            context["extension_tags"][key] = sorted(values)
        else:
            context["extension_tags"][key] = sorted(values)

    return blocks, family_ids, declared_counts, context


def _marker_hits(blob, markers):
    return {marker for marker in markers if marker in blob}


def _token_hits(blob, pattern):
    try:
        return len(pattern.findall(blob))
    except Exception:
        return 0


def _detect_artifact_profile(blob, family_ids, uf2_context=None, text_hints=None):
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
    uf2_context = uf2_context or {}
    text_hints = text_hints or {}

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

    family_labels = []
    for family_id in sorted(family_ids):
        family_profile = _family_profile(family_id)
        if family_profile:
            family_labels.append(family_profile["description"])
            profile["target_hints"].append(family_profile["target"])
            profile["uf2_vendor"] = family_profile["vendor"]
            profile["uf2_arch"] = family_profile["arch"]
            profile["indicators"].append(f"UF2 family id indicates {family_profile['description']}")
            scores["Bare-metal Firmware"] += 8
            if family_profile["short_name"].startswith("RP2040"):
                profile["sdk_hints"].append("Pico SDK (likely)")
                profile["build_hints"].append("CMake (likely)")
                scores["Bare-metal Firmware"] += 4
        else:
            family_labels.append(f"0x{family_id:08X}")

    board_hint = _derive_board_hint(text_hints)
    if board_hint != "Unknown":
        profile["board"] = board_hint
        profile["indicators"].append(f"Board hint extracted: {board_hint}")
        scores["Bare-metal Firmware"] += 3

    if text_hints.get("bootloader_lines"):
        profile["indicators"].append("Embedded UF2 bootloader info text detected")
    if text_hints.get("pico_boards"):
        profile["sdk_hints"].append("Pico SDK (likely)")
        profile["build_hints"].append("CMake (likely)")
        scores["Bare-metal Firmware"] += 3

    extension_tags = uf2_context.get("extension_tags", {})
    if extension_tags.get("firmware_versions"):
        profile["firmware_versions"] = list(extension_tags["firmware_versions"])
        profile["indicators"].append("UF2 extension tag: firmware version")
    if extension_tags.get("device_descriptions"):
        profile["device_description"] = extension_tags["device_descriptions"][0]
        profile["indicators"].append("UF2 extension tag: device description")
    if extension_tags.get("page_sizes"):
        profile["page_size"] = extension_tags["page_sizes"][0]
        profile["indicators"].append("UF2 extension tag: page size")
    if extension_tags.get("device_type_ids"):
        profile["device_type"] = extension_tags["device_type_ids"][0]
        profile["indicators"].append("UF2 extension tag: device type")

    if uf2_context.get("flag_counts", {}).get("file_container"):
        profile["uf2_payload_mode"] = "File container"
        profile["indicators"].append("UF2 file-container blocks detected")
    else:
        profile["uf2_payload_mode"] = "Flash image"

    if uf2_context.get("flag_counts", {}).get("not_main_flash"):
        profile["indicators"].append("UF2 not-main-flash blocks present")
    if uf2_context.get("flag_counts", {}).get("md5_present"):
        profile["indicators"].append("UF2 MD5 region tags present")
    if family_labels:
        profile["family"] = ", ".join(sorted(set(family_labels)))

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
    if "Arduino" in artifact_profile.get("board", "") or "Arduino" in artifact_profile.get(
        "device_description", ""
    ):
        scores["Arduino"] += 8
    if "Raspberry Pi Pico" in artifact_profile.get("board", ""):
        scores["Pico SDK"] += 4
        scores["CMake"] += 2

    max_score = max(scores.values())
    top = [system for system, score in scores.items() if score == max_score and score > 0]
    if max_score < 3:
        return "Unknown", scores
    if len(top) == 1:
        return top[0], scores
    return "Ambiguous: " + "/".join(top), scores


def _render_uf2_metadata(blocks, family_ids, declared_counts, context, text_hints, artifact_profile):
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
    flag_counts = context.get("flag_counts", {})
    lines.append(
        "Flags: "
        f"not_main_flash={flag_counts.get('not_main_flash', 0)}, "
        f"file_container={flag_counts.get('file_container', 0)}, "
        f"family_id={flag_counts.get('family_id_present', 0)}, "
        f"md5={flag_counts.get('md5_present', 0)}, "
        f"extension_tags={flag_counts.get('extension_tags_present', 0)}"
    )
    if context.get("file_names"):
        lines.append("Container Files: " + ", ".join(context["file_names"][:8]))
    extension_tags = context.get("extension_tags", {})
    if extension_tags.get("firmware_versions"):
        lines.append("Firmware Versions: " + ", ".join(extension_tags["firmware_versions"]))
    if extension_tags.get("device_descriptions"):
        lines.append("Device Descriptions: " + ", ".join(extension_tags["device_descriptions"]))
    if extension_tags.get("page_sizes"):
        lines.append(
            "Page Sizes: " + ", ".join(f"{value} bytes" for value in extension_tags["page_sizes"])
        )
    if extension_tags.get("device_type_ids"):
        lines.append("Device Type IDs: " + ", ".join(extension_tags["device_type_ids"]))
    if text_hints.get("models"):
        lines.append("Models: " + ", ".join(text_hints["models"]))
    if text_hints.get("board_ids"):
        lines.append("Board IDs: " + ", ".join(text_hints["board_ids"]))
    if artifact_profile.get("board") and artifact_profile.get("board") != "Unknown":
        lines.append(f"Detected Board: {artifact_profile['board']}")
    return "\n".join(lines)


def _build_uf2_firmware_fingerprint(artifact_profile, context):
    target = artifact_profile.get("target", "Unknown")
    vendor = artifact_profile.get("uf2_vendor", "Unknown")
    sdk = artifact_profile.get("sdk", "Unknown")
    board = artifact_profile.get("board", "Unknown")
    family = artifact_profile.get("family", "Unknown")
    signals = list(artifact_profile.get("indicators", []))
    if family != "Unknown":
        signals.append(f"UF2 family match: {family}")
    extension_tags = context.get("extension_tags", {})
    if extension_tags.get("device_descriptions"):
        signals.append("Device description available via UF2 extension tag")
    if context.get("flag_counts", {}).get("file_container"):
        signals.append("UF2 file-container mode present")
    return {
        "is_firmware_candidate": artifact_profile.get("artifact_type") == "Bare-metal Firmware",
        "firmware_confidence": artifact_profile.get("confidence", 0),
        "likely_mcu": target,
        "likely_vendor": vendor,
        "sdk_candidates": [] if sdk in {"Unknown", ""} else [sdk],
        "rtos_candidates": []
        if artifact_profile.get("rtos", "None detected") in {"Unknown", "None detected", ""}
        else [artifact_profile.get("rtos")],
        "board_candidates": [] if board in {"Unknown", ""} else [board],
        "signals": signals[:20],
    }


def scan_uf2_file(filepath, mode="general"):
    input_path = Path(filepath).expanduser()
    resolved_path = str(input_path.resolve()) if input_path.exists() else str(input_path)

    blocks, family_ids, declared_counts, context = _parse_uf2_blocks(input_path)
    payload_blob_raw = b"\x00".join(
        block["payload"] for block in sorted(blocks, key=lambda block: (block["block_no"], block["target_addr"]))
    )
    payload_blob = payload_blob_raw.lower()
    text_hints = _extract_text_hints(payload_blob_raw)

    artifact_profile = _detect_artifact_profile(
        payload_blob,
        family_ids,
        uf2_context=context,
        text_hints=text_hints,
    )
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
        "firmware_fingerprint": _build_uf2_firmware_fingerprint(artifact_profile, context),
        "uf2_context": context,
    }
    scan_result["explanations"] = build_scan_explanations(scan_result)

    metadata_text = _render_uf2_metadata(
        blocks,
        family_ids,
        declared_counts,
        context,
        text_hints,
        artifact_profile,
    )
    return {
        "file": resolved_path,
        "mode": mode,
        "version": get_version(),
        "generated_at": _report_timestamp(),
        "scan_result": scan_result,
        "metadata_text": metadata_text,
    }
