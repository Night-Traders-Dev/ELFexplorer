import io
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from elftools.elf.elffile import ELFFile

from detect.elfdetect import (
    detect_artifact_profile,
    detect_build_system,
    detect_compiler,
    detect_source_language,
)
from info.elfinfo import print_detailed_info, print_general_info, print_important_info
from version import get_version


def render_metadata(elf, output_mode):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        if output_mode == "general":
            print_general_info(elf)
        elif output_mode == "important":
            print_important_info(elf)
        elif output_mode == "detailed":
            print_detailed_info(elf)
        else:
            print("Unknown output mode selected.")
    return buffer.getvalue().rstrip()


def scan_heuristics(elf):
    artifact_profile = detect_artifact_profile(elf, emit_report=False)
    source_language, language_scores = detect_source_language(
        elf,
        artifact_profile=artifact_profile,
        emit_report=False,
        return_details=True,
    )
    compiler, compiler_scores = detect_compiler(
        elf,
        source_language=source_language,
        artifact_profile=artifact_profile,
        emit_report=False,
        return_details=True,
    )
    build_system, build_scores = detect_build_system(
        elf,
        artifact_profile=artifact_profile,
        emit_report=False,
        return_details=True,
    )
    return {
        "artifact_profile": artifact_profile,
        "source_language": source_language,
        "language_scores": language_scores,
        "compiler": compiler,
        "compiler_scores": compiler_scores,
        "build_system": build_system,
        "build_scores": build_scores,
    }


def report_timestamp():
    return datetime.now(timezone.utc).isoformat()


def build_scan_report(filepath, mode="general"):
    input_path = Path(filepath).expanduser()
    resolved_path = str(input_path.resolve()) if input_path.exists() else str(input_path)

    with open(input_path, "rb") as handle:
        elf = ELFFile(handle)
        scan_result = scan_heuristics(elf)
        metadata_text = render_metadata(elf, mode)

    return {
        "file": resolved_path,
        "mode": mode,
        "version": get_version(),
        "generated_at": report_timestamp(),
        "scan_result": scan_result,
        "metadata_text": metadata_text,
    }


def is_elf_file(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except Exception:
        return False

