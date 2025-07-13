#!/usr/bin/env python3

"""
elfscan.py

A Python script to analyze an ELF file using pyelftools with selectable output modes.
Output modes:
  - general: Basic information overview.
  - important: Key header and segment information.
  - detailed: All available information including section details.

Usage:
  python3 elfscan.py [-m {general,important,detailed}] <path-to-elf-file>
"""

import sys
import argparse
from elftools.elf.elffile import ELFFile
from symbol.elfsymbols import scan_symbols
from detect.elfdetect import detect_source_language
from info.elfinfo import print_general_info, print_important_info, print_detailed_info

def detect_source_language(elf):
    """
    Attempt to deduce the original source language of an ELF binary using heuristics.
    Scored languages: C, C++, Rust, and Go.

    Heuristics used:
      - .comment section: Looks for compiler strings.
      - Note sections: e.g. .note.go.buildid, .note.rustc.
      - Dynamic section DT_NEEDED entries for language‑specific libraries.
      - Scanning both .symtab and .dynsym for language‑specific symbols.
      - Checking the first 4 KB of .debug_info for "rustc".
    
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
    
    # --- Check for special note sections indicating Go or Rust ---
    note_go = elf.get_section_by_name('.note.go.buildid')
    if note_go:
        scores["Go"] += 5
    note_rust = elf.get_section_by_name('.note.rustc')
    if note_rust:
        scores["Rust"] += 5
    note_d = elf.get_section_by_name('.note.dmd')
    if note_d:
        scores["D"] += 5
    note_nim = elf.get_section_by_name('.note.nim')
    if note_nim:
        scores["Nim"] += 5
    note_swift = elf.get_section_by_name('.note.swift')
    if note_swift:
        scores["Swift"] += 5
    note_java = elf.get_section_by_name('.note.java')
    if note_java:
        scores["Java"] += 5
    note_python = elf.get_section_by_name('.note.python')
    if note_python:
        scores["Python"] += 5

    # --- Check Dynamic Section (DT_NEEDED) ---
    dynamic = elf.get_section_by_name('.dynamic')
    if dynamic:
        try:
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    needed = tag.needed.lower()
                    if "stdc++" in needed or "libc++" in needed:
                        scores["C++"] += 3
                    if "c++" in needed:
                        scores["C++"] += 2
                    if "rust" in needed:
                        scores["Rust"] += 3
                    if "go" in needed:
                        scores["Go"] += 3
                    if "dmd" in needed or "libphobos" in needed:
                        scores["D"] += 3
                    if "gnat" in needed:
                        scores["Ada"] += 3
                    if "gfortran" in needed:
                        scores["Fortran"] += 3
                    if "nim" in needed:
                        scores["Nim"] += 3
                    if "swift" in needed:
                        scores["Swift"] += 3
                    if "jvm" in needed or "java" in needed:
                        scores["Java"] += 3
                    if "python" in needed:
                        scores["Python"] += 3
        except Exception as e:
            print(f"Error processing dynamic section: {e}")

    # --- Check symbol tables (.symtab and .dynsym) for language-specific symbols ---
    symtab = elf.get_section_by_name('.symtab')
    if symtab:
        try:
            scan_symbols(symtab.iter_symbols(), scores)
        except Exception as e:
            print(f"Error processing .symtab: {e}")
    
    dynsym = elf.get_section_by_name('.dynsym')
    if dynsym:
        try:
            scan_symbols(dynsym.iter_symbols(), scores)
        except Exception as e:
            print(f"Error processing .dynsym: {e}")

    # --- Check .debug_info section for a "rustc" signature ---
    debug_info_sec = elf.get_section_by_name('.debug_info')
    if debug_info_sec:
        try:
            # Read only the first 4096 bytes to avoid loading huge data
            ddata = debug_info_sec.data()[:4096].lower()
            if b"rustc" in ddata:
                scores["Rust"] += 5
            # DWARF producer string (compiler info)
            if b"gcc" in ddata or b"gnu" in ddata:
                scores["C"] += 2
                scores["C++"] += 1
            if b"clang" in ddata:
                scores["C"] += 2
                scores["C++"] += 1
            if b"dmd" in ddata or b"ldc" in ddata:
                scores["D"] += 2
            if b"gnat" in ddata:
                scores["Ada"] += 2
            if b"gfortran" in ddata:
                scores["Fortran"] += 2
            if b"nim" in ddata:
                scores["Nim"] += 2
            if b"swift" in ddata:
                scores["Swift"] += 2
            if b"javac" in ddata or b"openjdk" in ddata:
                scores["Java"] += 2
            if b"python" in ddata:
                scores["Python"] += 2
        except Exception as e:
            print(f"Error reading .debug_info: {e}")

    # --- Check for language-specific sections ---
    for section in elf.iter_sections():
        sname = section.name.lower()
        if sname in ['.eh_frame', '.gcc_except_table']:
            scores["C++"] += 1
            scores["Rust"] += 1
        if sname.startswith('.rodata.str1.'):
            scores["Go"] += 1
        if sname == '.dlang':
            scores["D"] += 2
        if sname == '.gnat':
            scores["Ada"] += 2
        if sname == '.gfortran':
            scores["Fortran"] += 2
        if sname == '.nim':
            scores["Nim"] += 2
        if sname == '.swift':
            scores["Swift"] += 2
        if sname == '.jvm' or sname == '.java':
            scores["Java"] += 2
        if sname == '.python':
            scores["Python"] += 2

    # --- Handle stripped binaries ---
    has_symbols = False
    if symtab and symtab.num_symbols() > 0:
        has_symbols = True
    elif dynsym and dynsym.num_symbols() > 0:
        has_symbols = True

    # --- Print confidence scores ---
    print("Language detection scores:")
    for lang, score in scores.items():
        print(f"  {lang}: {score}")

    # --- Determine language based on scoring ---
    detected_language = "Unknown"
    max_score = max(scores.values())
    top_langs = [lang for lang, score in scores.items() if score == max_score and score > 0]
    if not has_symbols and max_score < 2:
        print("Warning: Binary appears stripped; detection may be unreliable.")
    if len(top_langs) == 1:
        detected_language = top_langs[0]
    elif len(top_langs) > 1:
        detected_language = "Ambiguous: " + "/".join(top_langs)
    else:
        detected_language = "C"  # Fallback: common for simple binaries
    return detected_language

def print_general_info(elf):
    print("----- General ELF Information -----")
    header = elf.header
    print(f"File Type: {header['e_type']}")
    print(f"Machine: {header['e_machine']}")
    print(f"Entry Point: {hex(header['e_entry'])}")

def print_important_info(elf):
    print("----- Important ELF Information -----")
    header = elf.header
    for key in ['e_type', 'e_machine', 'e_version', 'e_entry']:
        print(f"{key}: {header.get(key)}")
    
    print("\n----- Program Headers (Segments) -----")
    for segment in elf.iter_segments():
        h = segment.header
        print(f"\nSegment Type: {h['p_type']}")
        print(f"  Virtual Address: {hex(h['p_vaddr'])}")
        print(f"  File Size: {h['p_filesz']} bytes")
        print(f"  Memory Size: {h['p_memsz']} bytes")
        print(f"  Flags: {h['p_flags']}")

def print_detailed_info(elf):
    print("----- Detailed ELF Header -----")
    for key, value in elf.header.items():
        print(f"{key}: {value}")

    print("\n----- Program Headers (Segments) -----")
    for segment in elf.iter_segments():
        h = segment.header
        print(f"\nSegment Type: {h['p_type']}")
        print(f"  Virtual Address: {hex(h['p_vaddr'])}")
        print(f"  Physical Address: {hex(h['p_paddr'])}")
        print(f"  File Offset: {h['p_offset']}")
        print(f"  File Size: {h['p_filesz']} bytes")
        print(f"  Memory Size: {h['p_memsz']} bytes")
        print(f"  Flags: {h['p_flags']}")
        print(f"  Alignment: {h['p_align']}")

    print("\n----- Section Headers -----")
    for section in elf.iter_sections():
        h = section.header
        print(f"\nSection: {section.name}")
        print(f"  Type: {h['sh_type']}")
        print(f"  Address: {hex(h['sh_addr'])}")
        print(f"  Offset: {h['sh_offset']}")
        print(f"  Size: {h['sh_size']} bytes")
        print(f"  Flags: {h['sh_flags']}")
        print(f"  Link: {h['sh_link']}")
        print(f"  Info: {h['sh_info']}")
        print(f"  Address Alignment: {h['sh_addralign']}")
        print(f"  Entry Size: {h['sh_entsize']}")

def analyze_elf(filepath, output_mode):
    try:
        with open(filepath, 'rb') as file:
            elf = ELFFile(file)
            source_language = detect_source_language(elf)
            print(f"Detected Source Language (heuristic): {source_language}\n")
            if output_mode == 'general':
                print_general_info(elf)
            elif output_mode == 'important':
                print_important_info(elf)
            elif output_mode == 'detailed':
                print_detailed_info(elf)
            else:
                print("Unknown output mode selected.")
    except Exception as e:
        print(f"Error processing ELF file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Analyze an ELF file with selectable output modes.")
    parser.add_argument("filepath", help="Path to the ELF file to analyze.")
    parser.add_argument(
        "-m", "--mode",
        choices=["general", "important", "detailed"],
        default="general",
        help="Output mode: general (default), important, or detailed."
    )
    args = parser.parse_args()
    analyze_elf(args.filepath, args.mode)

if __name__ == '__main__':
    main()
