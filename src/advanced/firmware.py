import re


LINKER_HINT_PATTERNS = (
    (re.compile(r"\bmemory\b", re.IGNORECASE), "linker-script MEMORY block marker"),
    (re.compile(r"\bsections\b", re.IGNORECASE), "linker-script SECTIONS block marker"),
    (re.compile(r"\borigin\s*=", re.IGNORECASE), "linker-script ORIGIN assignment marker"),
    (re.compile(r"\blength\s*=", re.IGNORECASE), "linker-script LENGTH assignment marker"),
    (re.compile(r"\bldscripts?\b", re.IGNORECASE), "ldscripts path marker"),
)

SDK_VERSION_PATTERNS = (
    (re.compile(r"pico[\s_-]?sdk[^0-9]{0,8}(v?\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), "Pico SDK"),
    (re.compile(r"esp[\s_-]?idf[^0-9]{0,8}(v?\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), "ESP-IDF"),
    (re.compile(r"zephyr[^0-9]{0,8}(v?\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), "Zephyr"),
    (re.compile(r"freertos[^0-9]{0,8}(v?\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), "FreeRTOS"),
)


def _collect_section_blobs(elf, section_names):
    blobs = []
    for name in section_names:
        section = elf.get_section_by_name(name)
        if not section:
            continue
        try:
            blobs.append(section.data()[:1048576])
        except Exception:
            continue
    return blobs


def _collect_strings(elf, section_names):
    return b"\n".join(blob.lower() for blob in _collect_section_blobs(elf, section_names))


def _detect_linker_hints(decoded_blob):
    hints = []
    for pattern, hint in LINKER_HINT_PATTERNS:
        if pattern.search(decoded_blob):
            hints.append(hint)
    return hints


def _extract_sdk_versions(decoded_blob):
    versions = {}
    for pattern, sdk_name in SDK_VERSION_PATTERNS:
        for match in pattern.finditer(decoded_blob):
            version = match.group(1)
            if not version:
                continue
            versions.setdefault(sdk_name, set()).add(version.lstrip("vV"))
    return {name: sorted(values) for name, values in versions.items()}


def _probe_vector_table(elf, machine):
    candidate_section_names = (".isr_vector", ".vector_table", ".vectors", ".text")
    for name in candidate_section_names:
        section = elf.get_section_by_name(name)
        if not section:
            continue
        try:
            data = section.data()
        except Exception:
            continue
        if len(data) < 32:
            continue
        # Basic Cortex-M vector table shape:
        #   initial SP in SRAM (0x2000_0000 range) and reset vector in flash (low address)
        initial_sp = int.from_bytes(data[0:4], "little", signed=False)
        reset_handler = int.from_bytes(data[4:8], "little", signed=False)
        looks_cortex_m = (
            0x20000000 <= initial_sp <= 0x20080000
            and 0x00000000 <= (reset_handler & ~1) <= 0x20000000
            and machine in {"EM_ARM", "EM_AARCH64"}
        )
        if looks_cortex_m:
            return {
                "looks_like_vector_table": True,
                "section": name,
                "initial_sp": f"0x{initial_sp:x}",
                "reset_handler": f"0x{reset_handler:x}",
            }
    return {
        "looks_like_vector_table": False,
        "section": None,
        "initial_sp": None,
        "reset_handler": None,
    }


def detect_firmware_fingerprint(elf, artifact_profile):
    signals = []
    score = 0
    sdk_candidates = set()
    rtos_candidates = set()
    mcu_candidates = set()
    vendor_candidates = set()

    try:
        machine = elf["e_machine"]
    except Exception:
        machine = "Unknown"

    try:
        entry = int(elf.header.get("e_entry", 0))
    except Exception:
        entry = 0

    artifact_type = artifact_profile.get("artifact_type", "Unknown")
    if artifact_type == "Bare-metal Firmware":
        score += 35
        signals.append("artifact profile indicates bare-metal firmware")

    if machine in {"EM_ARM", "EM_AARCH64", "EM_RISCV", "EM_RISCV64"}:
        score += 15
        signals.append(f"embedded-friendly machine type: {machine}")

    if 0 < entry < 0x20000000:
        score += 8
        signals.append(f"low entry-point address 0x{entry:x}")

    for vector_name in (".isr_vector", ".vector_table", ".vectors"):
        if elf.get_section_by_name(vector_name):
            score += 12
            signals.append(f"vector table section detected: {vector_name}")
            mcu_candidates.add("Cortex-M")
            break

    scan_sections = (".comment", ".rodata", ".debug_str", ".strtab", ".dynstr")
    strings_blob = _collect_strings(elf, scan_sections)
    decoded_blob = strings_blob.decode("utf-8", errors="ignore")

    def _has(token):
        return token in strings_blob

    if _has(b"rp2040") or _has(b"pico-sdk") or _has(b"pico stdio"):
        score += 20
        mcu_candidates.add("RP2040")
        vendor_candidates.add("Raspberry Pi")
        sdk_candidates.add("Pico SDK")
        signals.append("RP2040/Pico SDK markers found")

    if _has(b"stm32") or _has(b"cubeide") or _has(b"hal_"):
        score += 16
        mcu_candidates.add("STM32")
        vendor_candidates.add("STMicroelectronics")
        sdk_candidates.add("STM32Cube")
        signals.append("STM32 markers found")

    if _has(b"nrf52") or _has(b"nordic") or _has(b"softdevice"):
        score += 16
        mcu_candidates.add("nRF52")
        vendor_candidates.add("Nordic")
        sdk_candidates.add("nRF5 SDK")
        signals.append("Nordic nRF markers found")

    if _has(b"esp32") or _has(b"esp-idf"):
        score += 16
        mcu_candidates.add("ESP32")
        vendor_candidates.add("Espressif")
        sdk_candidates.add("ESP-IDF")
        signals.append("ESP32/ESP-IDF markers found")

    if _has(b"freertos"):
        rtos_candidates.add("FreeRTOS")
        score += 8
        signals.append("FreeRTOS markers found")

    if _has(b"zephyr"):
        rtos_candidates.add("Zephyr")
        score += 8
        signals.append("Zephyr markers found")

    if _has(b"threadx"):
        rtos_candidates.add("ThreadX")
        score += 8
        signals.append("ThreadX markers found")

    linker_hints = _detect_linker_hints(decoded_blob)
    if linker_hints:
        score += min(10, len(linker_hints) * 2)
        signals.append("linker script markers found")

    sdk_versions = _extract_sdk_versions(decoded_blob)
    if sdk_versions:
        score += min(10, len(sdk_versions) * 2)
        signals.append("SDK version strings found")

    vector_profile = _probe_vector_table(elf, machine)
    if vector_profile.get("looks_like_vector_table"):
        score += 12
        signals.append(f"vector table shape confirmed in {vector_profile.get('section')}")
        mcu_candidates.add("Cortex-M")

    loader = artifact_profile.get("loader", "None")
    if loader and loader != "None":
        score -= 10
        signals.append("dynamic loader present (less firmware-like)")

    firmware_confidence = max(0, min(99, score))
    profile = {
        "is_firmware_candidate": firmware_confidence >= 35,
        "firmware_confidence": firmware_confidence,
        "likely_mcu": ", ".join(sorted(mcu_candidates)) if mcu_candidates else "Unknown",
        "likely_vendor": ", ".join(sorted(vendor_candidates)) if vendor_candidates else "Unknown",
        "sdk_candidates": sorted(sdk_candidates),
        "rtos_candidates": sorted(rtos_candidates),
        "sdk_versions": sdk_versions,
        "linker_hints": linker_hints,
        "vector_table_profile": vector_profile,
        "entry_point": f"0x{entry:x}",
        "machine": str(machine),
        "signals": signals,
    }
    return profile
