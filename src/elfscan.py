#!/usr/bin/env python3
"""
elf_analyzer.py

A Python script to analyze an ELF file using pyelftools with selectable output modes.
Output modes:
  - general: Basic information overview.
  - important: Key header and segment information.
  - detailed: All available information including section details.

This script includes improved heuristics for detecting the original source language
(e.g., C, C++, Rust, Go). It now scans:
  - The .comment section (for compiler info),
  - Special note sections (e.g. .note.go.buildid, .note.rustc),
  - The dynamic section (DT_NEEDED entries),
  - Both the static (.symtab) and dynamic (.dynsym) symbol tables for language‑specific symbols,
  - And up to the first 4 KB of .debug_info for a "rustc" substring.
  
If no strong evidence is found, it falls back to assuming C, which is common for simple binaries.

Usage:
  python3 elf_analyzer.py [-m {general,important,detailed}] <path-to-elf-file>
"""

import sys
import argparse
from elftools.elf.elffile import ELFFile

def scan_symbols(symbol_iter, scores):
    """
    Scan the given iterator of symbols and update the scores dictionary based on:
      - Rust-specific substrings: e.g. "rust_eh_personality", "__rust_alloc"
      - Occurrences of "rust" anywhere in the symbol name.
      - C++ mangled names (starting with _Z) that do not contain "rust"
    """
    for symbol in symbol_iter:
        name = symbol.name.lower()
        if not name:
            continue
        # Rust-specific symbols increase Rust's score.
        if "rust_eh_personality" in name:
            scores["Rust"] += 5
        if "__rust_alloc" in name or "__rust_dealloc" in name or "__rust_realloc" in name:
            scores["Rust"] += 5
        # General check: any appearance of "rust" gives a small boost.
        if "rust" in name:
            scores["Rust"] += 1
        # Check for C++ mangled names (typically starting with _Z)
        if name.startswith('_z') and "rust" not in name:
            scores["C++"] += 2

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
        "Go": 0
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
        except Exception as e:
            print(f"Error reading .comment section: {e}")
    
    # --- Check for special note sections indicating Go or Rust ---
    note_go = elf.get_section_by_name('.note.go.buildid')
    if note_go:
        scores["Go"] += 5
    note_rust = elf.get_section_by_name('.note.rustc')
    if note_rust:
        scores["Rust"] += 5

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
        except Exception as e:
            print(f"Error reading .debug_info: {e}")

    # --- Determine language based on scoring ---
    detected_language = "Unknown"
    max_score = 0
    for lang, score in scores.items():
        if score > max_score:
            max_score = score
            detected_language = lang

    # Fallback: if no strong evidence found, assume C (common for simple binaries)
    if max_score < 2:
        detected_language = "C"
    
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

            # Detect and print source language using improved heuristics.
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
