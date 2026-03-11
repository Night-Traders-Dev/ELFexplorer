import math
from pathlib import Path

from uf2.scan import (
    _detect_artifact_profile,
    _detect_build_system,
    _detect_compiler,
    _detect_language,
    _report_timestamp,
)
from version import get_version

IHEX_SUFFIXES = {".hex", ".ihex", ".ihx"}
SREC_SUFFIXES = {".srec", ".s19", ".s28", ".s37", ".mot"}
RAW_BIN_SUFFIXES = {".bin", ".fw", ".rom", ".img", ".raw", ".blob"}


def _merge_segments(segments):
    merged = []
    for address, payload in sorted(segments, key=lambda item: item[0]):
        if not payload:
            continue

        if not merged:
            merged.append([address, bytearray(payload)])
            continue

        last_addr, last_payload = merged[-1]
        last_end = last_addr + len(last_payload)
        if address <= last_end:
            overlap = last_end - address
            if overlap < len(payload):
                last_payload.extend(payload[overlap:])
        else:
            merged.append([address, bytearray(payload)])

    return [(address, bytes(payload)) for address, payload in merged]


def _entropy(data):
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    total = float(len(data))
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _scan_blob_as_firmware(
    filepath,
    mode,
    blob,
    metadata_text,
    container_indicator,
    family_ids=None,
):
    resolved_path = str(Path(filepath).expanduser().resolve())
    payload_blob = blob.lower()
    artifact_profile = _detect_artifact_profile(payload_blob, family_ids or set())

    indicators = artifact_profile.setdefault("indicators", [])
    if indicators and indicators[0] == "UF2 container format detected":
        indicators[0] = container_indicator
    else:
        indicators.insert(0, container_indicator)

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
    return {
        "file": resolved_path,
        "mode": mode,
        "version": get_version(),
        "generated_at": _report_timestamp(),
        "scan_result": scan_result,
        "metadata_text": metadata_text,
    }


def is_intel_hex_file(path):
    candidate = Path(path)
    if candidate.suffix.lower() in IHEX_SUFFIXES:
        return True

    try:
        with open(candidate, "r", encoding="utf-8", errors="ignore") as handle:
            for _ in range(12):
                line = handle.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                if line.startswith(":") and len(line) >= 11:
                    return True
                return False
    except Exception:
        return False
    return False


def _parse_intel_hex(path):
    lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    linear_base = 0
    segment_base = 0
    segments = []
    record_count = 0
    data_record_count = 0

    for line_no, line in enumerate(lines, start=1):
        text = line.strip()
        if not text:
            continue
        if not text.startswith(":"):
            raise ValueError(f"Invalid Intel HEX record at line {line_no}: missing ':' prefix.")

        payload = text[1:]
        if len(payload) % 2 != 0:
            raise ValueError(f"Invalid Intel HEX record at line {line_no}: odd hex length.")

        try:
            record = bytes.fromhex(payload)
        except ValueError as exc:
            raise ValueError(f"Invalid Intel HEX record at line {line_no}: non-hex data.") from exc

        if len(record) < 5:
            raise ValueError(f"Invalid Intel HEX record at line {line_no}: too short.")

        count = record[0]
        if len(record) != count + 5:
            raise ValueError(f"Invalid Intel HEX record at line {line_no}: length mismatch.")
        if (sum(record) & 0xFF) != 0:
            raise ValueError(f"Invalid Intel HEX record at line {line_no}: checksum mismatch.")

        addr = (record[1] << 8) | record[2]
        rec_type = record[3]
        data = record[4 : 4 + count]
        record_count += 1

        if rec_type == 0x00:
            base = linear_base if linear_base else segment_base
            segments.append((base + addr, data))
            data_record_count += 1
        elif rec_type == 0x01:
            break
        elif rec_type == 0x02:
            if count != 2:
                raise ValueError(f"Invalid Intel HEX record at line {line_no}: bad type-02 length.")
            segment_base = ((data[0] << 8) | data[1]) << 4
            linear_base = 0
        elif rec_type == 0x04:
            if count != 2:
                raise ValueError(f"Invalid Intel HEX record at line {line_no}: bad type-04 length.")
            linear_base = ((data[0] << 8) | data[1]) << 16
            segment_base = 0
        elif rec_type in {0x03, 0x05}:
            continue

    if not segments:
        raise ValueError("Intel HEX file contains no data records.")

    merged = _merge_segments(segments)
    blob = b"\x00".join(payload for _, payload in merged)
    min_addr = min(address for address, _ in merged)
    max_addr = max(address + len(payload) for address, payload in merged)
    return {
        "blob": blob,
        "record_count": record_count,
        "data_record_count": data_record_count,
        "data_bytes": sum(len(payload) for _, payload in merged),
        "min_addr": min_addr,
        "max_addr": max_addr,
    }


def scan_intel_hex_file(filepath, mode="general"):
    parsed = _parse_intel_hex(filepath)
    metadata_text = "\n".join(
        [
            "----- General Intel HEX Information -----",
            "File Type: Intel HEX",
            f"Records: {parsed['record_count']}",
            f"Data Records: {parsed['data_record_count']}",
            f"Data Bytes: {parsed['data_bytes']}",
            f"Address Range: 0x{parsed['min_addr']:08x} - 0x{parsed['max_addr']:08x}",
            f"Payload Entropy: {_entropy(parsed['blob']):.3f} bits/byte",
        ]
    )
    return _scan_blob_as_firmware(
        filepath,
        mode,
        parsed["blob"],
        metadata_text,
        container_indicator="Intel HEX container format detected",
    )


def is_srec_file(path):
    candidate = Path(path)
    if candidate.suffix.lower() in SREC_SUFFIXES:
        return True

    try:
        with open(candidate, "r", encoding="utf-8", errors="ignore") as handle:
            for _ in range(12):
                line = handle.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                if line.startswith("S") and len(line) >= 10 and line[1] in "0123456789":
                    return True
                return False
    except Exception:
        return False
    return False


def _parse_srec(path):
    lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    address_lengths = {
        "0": 2,
        "1": 2,
        "2": 3,
        "3": 4,
        "5": 2,
        "7": 4,
        "8": 3,
        "9": 2,
    }
    data_types = {"1", "2", "3"}
    termination_types = {"7", "8", "9"}

    segments = []
    record_count = 0
    data_record_count = 0

    for line_no, line in enumerate(lines, start=1):
        text = line.strip()
        if not text:
            continue
        if not text.startswith("S") or len(text) < 4:
            raise ValueError(f"Invalid S-record at line {line_no}.")

        rec_type = text[1]
        payload = text[2:]
        if len(payload) % 2 != 0:
            raise ValueError(f"Invalid S-record at line {line_no}: odd hex length.")

        try:
            record = bytes.fromhex(payload)
        except ValueError as exc:
            raise ValueError(f"Invalid S-record at line {line_no}: non-hex data.") from exc

        if not record:
            raise ValueError(f"Invalid S-record at line {line_no}: empty record.")

        count = record[0]
        if len(record) != count + 1:
            raise ValueError(f"Invalid S-record at line {line_no}: length mismatch.")
        if (sum(record) & 0xFF) != 0xFF:
            raise ValueError(f"Invalid S-record at line {line_no}: checksum mismatch.")

        address_len = address_lengths.get(rec_type)
        if address_len is None:
            continue
        if count < address_len + 1:
            raise ValueError(f"Invalid S-record at line {line_no}: invalid count for type S{rec_type}.")

        addr_bytes = record[1 : 1 + address_len]
        address = 0
        for value in addr_bytes:
            address = (address << 8) | value

        data_len = count - address_len - 1
        data_start = 1 + address_len
        data = record[data_start : data_start + data_len]
        record_count += 1

        if rec_type in data_types:
            segments.append((address, data))
            data_record_count += 1
        elif rec_type in termination_types:
            break

    if not segments:
        raise ValueError("S-record file contains no data records.")

    merged = _merge_segments(segments)
    blob = b"\x00".join(payload for _, payload in merged)
    min_addr = min(address for address, _ in merged)
    max_addr = max(address + len(payload) for address, payload in merged)
    return {
        "blob": blob,
        "record_count": record_count,
        "data_record_count": data_record_count,
        "data_bytes": sum(len(payload) for _, payload in merged),
        "min_addr": min_addr,
        "max_addr": max_addr,
    }


def scan_srec_file(filepath, mode="general"):
    parsed = _parse_srec(filepath)
    metadata_text = "\n".join(
        [
            "----- General Motorola S-Record Information -----",
            "File Type: Motorola S-Record",
            f"Records: {parsed['record_count']}",
            f"Data Records: {parsed['data_record_count']}",
            f"Data Bytes: {parsed['data_bytes']}",
            f"Address Range: 0x{parsed['min_addr']:08x} - 0x{parsed['max_addr']:08x}",
            f"Payload Entropy: {_entropy(parsed['blob']):.3f} bits/byte",
        ]
    )
    return _scan_blob_as_firmware(
        filepath,
        mode,
        parsed["blob"],
        metadata_text,
        container_indicator="Motorola S-record container format detected",
    )


def is_raw_firmware_bin_file(path):
    candidate = Path(path)
    if not candidate.is_file():
        return False
    if candidate.suffix.lower() in RAW_BIN_SUFFIXES:
        return True

    try:
        head = candidate.read_bytes()[:4096]
    except Exception:
        return False

    if not head:
        return False

    non_text = sum(1 for byte in head if byte < 9 or (13 < byte < 32) or byte > 126)
    has_nuls = b"\x00" in head
    return has_nuls and (non_text / len(head)) > 0.30


def scan_raw_binary_file(filepath, mode="general"):
    payload = Path(filepath).read_bytes()
    metadata_text = "\n".join(
        [
            "----- General Raw Binary Information -----",
            "File Type: Raw Binary",
            f"Size Bytes: {len(payload)}",
            f"Payload Entropy: {_entropy(payload):.3f} bits/byte",
            "Address Range: Unknown (raw image has no explicit load address)",
        ]
    )
    return _scan_blob_as_firmware(
        filepath,
        mode,
        payload,
        metadata_text,
        container_indicator="Raw binary firmware image detected",
    )

