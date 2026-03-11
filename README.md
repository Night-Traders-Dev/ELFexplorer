# ELFexplorer

**ELFexplorer** is a lightweight, modular Python utility for parsing and inspecting ELF (Executable and Linkable Format) binaries. It supports detailed analysis modes to display ELF headers, program headers, section headers, and detect the likely source language of the binary using advanced heuristic techniques.

## Modular Design

ELFexplorer is now split into maintainable modules:
- `elfscan.py`: Main CLI entry point
- `elfdetect.py`: Source language detection logic
- `elfsymbols.py`: Symbol table scanning and scoring
- `elfinfo.py`: ELF header/segment/section output functions

## Features

- Displays ELF headers with parsed `e_ident` values
- Prints program header segments with virtual/physical address mapping
- Outputs detailed section headers with names, types, sizes, and flags
- Heuristically detects source language (C, C++, Rust, Go, D, Ada, Fortran, Nim, Swift, Java, Python, SageLang)
- Modularized for easier updates and extension
- Supports 64-bit ELF files (currently tested on AArch64/ARM64)
- Compatible with Python 3.12+

## Usage

```bash
python3.12 src/elfscan.py -m detailed <elf_binary>
```

## Example:

```bash
python3.12 src/elfscan.py -m detailed hello_rust
```

## Output:

```bash
Language detection scores:
  C: 6
  C++: 1058
  Rust: 169
  ...
Detected Source Language (heuristic): Rust

ELF Type: ET_DYN (Shared Object)
Machine: EM_AARCH64 (ARM 64-bit)
Entry Point: 0x6300
Lists all segments including PT_LOAD, PT_DYNAMIC, PT_GNU_STACK, etc.
Detailed section headers including .text, .data, .bss, .rodata, .dynsym, .debug_*, etc.
```


## Output Sections

• ELF Header – Identifies basic ELF metadata (architecture, type, entry point, etc.)
• Program Headers – Maps how the binary will be loaded into memory
• Section Headers – Contains code, data, symbol tables, debug info, etc.
• Source Language Detection – Heuristics for C, C++, Rust, Go, D, Ada, Fortran, Nim, Swift, Java, Python, SageLang


## Requirements

• Python 3.12+
• pyelftools (install via pip install pyelftools)
• Modular Python files in `src/`


## Example Output (Trimmed)

```bash
----- Detailed ELF Header -----
e_machine: EM_AARCH64
e_entry: 25216
...

----- Program Headers (Segments) -----
Segment Type: PT_LOAD
  Virtual Address: 0x0
  Physical Address: 0x0
  File Offset: 0
...

----- Section Headers -----
Section: .text
  Type: SHT_PROGBITS
  Size: 247060 bytes
...

Detected Source Language (heuristic): C++
```

## TODO

• Add support for 32-bit ELF files

• Improve source language detection for stripped or heavily optimized binaries

• Add JSON or colorized output mode

• Support for symbol demangling


## License

**MIT License**
