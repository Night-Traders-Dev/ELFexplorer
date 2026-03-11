import io
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from elftools.elf.elffile import ELFFile

from detect.constants import (
    ARTIFACT_HEURISTICS,
    BUILD_SYSTEM_HEURISTICS,
    COMPILER_HEURISTICS,
    SUPPORTED_LANGUAGES,
)
from detect.elfdetect import (
    detect_artifact_profile,
    detect_build_system,
    detect_compiler,
    detect_source_language,
)
from detect.utils import empty_scores
from version import get_version

AR_MAGIC = b"!<arch>\n"


def _report_timestamp():
    return datetime.now(timezone.utc).isoformat()


def is_ar_archive(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(len(AR_MAGIC)) == AR_MAGIC
    except Exception:
        return False


def _resolve_gnu_name(name_table, offset):
    if offset >= len(name_table):
        return f"offset_{offset}"
    end = name_table.find(b"/\n", offset)
    if end == -1:
        end = name_table.find(b"\n", offset)
    if end == -1:
        end = len(name_table)
    return name_table[offset:end].decode("utf-8", errors="ignore").strip() or f"offset_{offset}"


def _parse_archive_members(path):
    data = Path(path).read_bytes()
    if not data.startswith(AR_MAGIC):
        raise ValueError("Input is not a valid GNU ar archive.")

    offset = len(AR_MAGIC)
    name_table = b""
    members = []

    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        offset += 60
        if header[58:60] != b"`\n":
            raise ValueError("Invalid ar archive member header terminator.")

        raw_name = header[0:16].decode("utf-8", errors="ignore").strip()
        size_text = header[48:58].decode("utf-8", errors="ignore").strip()
        try:
            size = int(size_text) if size_text else 0
        except ValueError as exc:
            raise ValueError("Invalid ar archive member size field.") from exc

        payload = data[offset : offset + size]
        offset += size
        if offset % 2 == 1:
            offset += 1

        member_name = raw_name
        if raw_name == "//":
            name_table = payload
            continue
        if raw_name in {"/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"}:
            continue
        if raw_name.startswith("#1/"):
            try:
                name_len = int(raw_name[3:].strip())
            except ValueError:
                name_len = 0
            name_bytes = payload[:name_len]
            member_name = name_bytes.decode("utf-8", errors="ignore").strip()
            payload = payload[name_len:]
        elif raw_name.startswith("/") and raw_name[1:].isdigit() and name_table:
            member_name = _resolve_gnu_name(name_table, int(raw_name[1:]))
        else:
            member_name = raw_name.rstrip("/")

        members.append({"name": member_name or "unnamed", "data": payload})

    return members


def _select_top(scores, minimum):
    max_score = max(scores.values()) if scores else 0
    winners = [name for name, score in scores.items() if score == max_score and score > 0]
    if max_score < minimum:
        return "Unknown"
    if len(winners) == 1:
        return winners[0]
    return "Ambiguous: " + "/".join(winners)


def _artifact_from_scores(scores):
    max_score = max(scores.values()) if scores else 0
    winners = [name for name, score in scores.items() if score == max_score and score > 0]
    if max_score < 4:
        return "Unknown"
    if len(winners) == 1:
        return winners[0]
    return "Ambiguous: " + "/".join(winners)


def _artifact_confidence(scores, artifact_type):
    ordered = sorted(scores.values(), reverse=True)
    top = ordered[0] if ordered else 0
    second = ordered[1] if len(ordered) > 1 else 0
    margin = max(0, top - second)

    if artifact_type == "Unknown":
        return 20
    if artifact_type.startswith("Ambiguous:"):
        return max(35, min(80, 45 + top + margin))
    return max(45, min(99, 50 + top + (margin * 2)))


def _pick_majority(values, default):
    filtered = [value for value in values if value and value != default]
    if not filtered:
        return default
    top = Counter(filtered).most_common(1)
    return top[0][0] if top else default


def scan_ar_archive(filepath, mode="general"):
    input_path = Path(filepath).expanduser()
    resolved_path = str(input_path.resolve()) if input_path.exists() else str(input_path)
    members = _parse_archive_members(input_path)

    elf_members = [member for member in members if member["data"][:4] == b"\x7fELF"]
    if not elf_members:
        raise ValueError("Archive contains no ELF members.")

    language_scores = empty_scores(SUPPORTED_LANGUAGES)
    compiler_scores = empty_scores(COMPILER_HEURISTICS)
    build_scores = empty_scores(BUILD_SYSTEM_HEURISTICS)
    artifact_scores = empty_scores(ARTIFACT_HEURISTICS)

    artifact_values = {
        "target": [],
        "sdk": [],
        "rtos": [],
        "runtime": [],
    }
    machines = []

    for member in elf_members:
        handle = io.BytesIO(member["data"])
        elf = ELFFile(handle)
        artifact = detect_artifact_profile(elf, emit_report=False)
        source_language, member_lang_scores = detect_source_language(
            elf,
            artifact_profile=artifact,
            emit_report=False,
            return_details=True,
        )
        compiler, member_compiler_scores = detect_compiler(
            elf,
            source_language=source_language,
            artifact_profile=artifact,
            emit_report=False,
            return_details=True,
        )
        build_system, member_build_scores = detect_build_system(
            elf,
            artifact_profile=artifact,
            emit_report=False,
            return_details=True,
        )

        for key, value in member_lang_scores.items():
            language_scores[key] += value
        for key, value in member_compiler_scores.items():
            compiler_scores[key] += value
        for key, value in member_build_scores.items():
            build_scores[key] += value
        for key, value in artifact.get("scores", {}).items():
            if key in artifact_scores:
                artifact_scores[key] += value

        artifact_values["target"].append(artifact.get("target", "Unknown"))
        artifact_values["sdk"].append(artifact.get("sdk", "Unknown"))
        artifact_values["rtos"].append(artifact.get("rtos", "None detected"))
        artifact_values["runtime"].append(artifact.get("runtime", "Unknown"))
        machines.append(artifact.get("machine", "Unknown"))

        _ = compiler, build_system

    source_language = _select_top(language_scores, minimum=2)
    compiler = _select_top(compiler_scores, minimum=3)
    build_system = _select_top(build_scores, minimum=3)
    artifact_type = _artifact_from_scores(artifact_scores)
    confidence = _artifact_confidence(artifact_scores, artifact_type)

    artifact_profile = {
        "artifact_type": artifact_type,
        "confidence": confidence,
        "target": _pick_majority(artifact_values["target"], "Unknown"),
        "sdk": _pick_majority(artifact_values["sdk"], "Unknown"),
        "rtos": _pick_majority(artifact_values["rtos"], "None detected"),
        "runtime": _pick_majority(artifact_values["runtime"], "Unknown"),
        "linkage_model": "Static archive (ELF members)",
        "loader": "None",
        "scores": artifact_scores,
        "indicators": [
            f"GNU ar archive with {len(members)} members",
            f"ELF members analyzed: {len(elf_members)}",
        ],
        "machine": _pick_majority(machines, "Unknown"),
        "elf_type": "AR",
        "needed_libs": [],
    }

    metadata_lines = [
        "----- General GNU ar Archive Information -----",
        "File Type: GNU ar Archive",
        f"Members: {len(members)}",
        f"ELF Members: {len(elf_members)}",
        f"Primary ELF Machine: {artifact_profile['machine']}",
        "ELF Member Names:",
    ]
    for member in elf_members[:20]:
        metadata_lines.append(f"  - {member['name']}")
    if len(elf_members) > 20:
        metadata_lines.append(f"  ... ({len(elf_members) - 20} more)")

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
        "metadata_text": "\n".join(metadata_lines),
    }

