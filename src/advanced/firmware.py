def _collect_strings(elf, section_names):
    blobs = []
    for name in section_names:
        section = elf.get_section_by_name(name)
        if not section:
            continue
        try:
            blobs.append(section.data()[:524288].lower())
        except Exception:
            continue
    return b"\n".join(blobs)


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

    strings_blob = _collect_strings(elf, (".comment", ".rodata", ".debug_str", ".strtab", ".dynstr"))

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
        "entry_point": f"0x{entry:x}",
        "machine": str(machine),
        "signals": signals,
    }
    return profile

