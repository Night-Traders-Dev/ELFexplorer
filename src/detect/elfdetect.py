# Functions for detecting the source language of an ELF binary
from symbols.elfsymbols import scan_symbols
from elftools.elf.elffile import ELFFile

def detect_source_language(elf):
    """
    Attempt to deduce the original source language of an ELF binary using heuristics.
    Returns: A string indicating the detected language.
    """
    scores = {
        "C": 0,
        "C++": 0,
        "Rust": 0,
        "Go": 0,
        "D": 0,
        "Ada": 0,
        "Fortran": 0,
        "Nim": 0,
        "Swift": 0,
        "Java": 0,
        "Python": 0
    }
    # ...existing code for section, dynamic, debug_info, etc...
    # (Copy from elfscan.py)
    # --- Check for .comment section ---
    comment_sec = elf.get_section_by_name('.comment')
    if comment_sec:
        try:
            data = comment_sec.data().decode(errors="ignore").lower()
            if "gcc" in data or "gnu" in data:
                scores["C"] += 3
                scores["C++"] += 1
            if "clang" in data:
                scores["C"] += 3
                scores["C++"] += 1
            if "rustc" in data:
                scores["Rust"] += 3
            if "go build" in data or "golang" in data:
                scores["Go"] += 3
            if "dmd" in data or "ldc" in data:
                scores["D"] += 3
            if "gnat" in data:
                scores["Ada"] += 3
            if "gfortran" in data:
                scores["Fortran"] += 3
            if "nim" in data:
                scores["Nim"] += 3
            if "swift" in data:
                scores["Swift"] += 3
            if "javac" in data or "openjdk" in data:
                scores["Java"] += 3
            if "python" in data:
                scores["Python"] += 3
        except Exception as e:
            print(f"Error reading .comment section: {e}")
    # ...existing code for other checks...
    # (Copy all detection logic from elfscan.py)
    # --- Print confidence scores ---
    print("Language detection scores:")
    for lang, score in scores.items():
        print(f"  {lang}: {score}")
    # --- Determine language based on scoring ---
    detected_language = "Unknown"
    max_score = max(scores.values())
    top_langs = [lang for lang, score in scores.items() if score == max_score and score > 0]
    # ...existing code for ambiguous/stripped/fallback...
    if len(top_langs) == 1:
        detected_language = top_langs[0]
    elif len(top_langs) > 1:
        detected_language = "Ambiguous: " + "/".join(top_langs)
    else:
        detected_language = "C"  # Fallback: common for simple binaries
    return detected_language
