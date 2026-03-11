# ELFexplorer

[![Version](https://img.shields.io/badge/version-0.6.0-blue)](#versioning)
[![Python](https://img.shields.io/badge/python-3.12%2B-informational)](#requirements)
[![UI](https://img.shields.io/badge/ui-textual%20default-0ea5e9)](#textual-workspace-default-ux)
[![Reports](https://img.shields.io/badge/reports-markdown%20%7C%20pdf-16a34a)](#report-export)
[![Tests](https://img.shields.io/badge/tests-unittest%20heuristics%20%2B%20corpus-brightgreen)](#testing)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](#license)

`ELFexplorer` is a modular binary analysis and heuristic fingerprinting tool focused on:
- source language inference
- compiler/assembler inference
- host build-system inference
- artifact classification (firmware, userspace executable, shared library, module, object)
- evidence-oriented reporting with score breakdowns

## What Changed in 0.6.0

- Added native scanning support for Intel HEX firmware files (`.hex`, `.ihex`, `.ihx`).
- Added native scanning support for Motorola S-record firmware files (`.srec`, `.s19`, `.s28`, `.s37`, `.mot`).
- Added native scanning support for raw firmware binaries (`.bin`, `.fw`, `.rom`, `.img`, `.raw`, `.blob`).
- Added GNU ar (`.a`) archive scanning with ELF member aggregation.
- Extended crawl support to include all supported formats.
- Added format regression tests in `tests/test_format_support.py`.
- Added Textual report command-palette actions (`Ctrl+P`) for:
  - exporting the current report to Markdown/PDF
  - switching metadata mode (`general`/`important`/`detailed`) and rescanning in-place
- Added `settings.conf` (JSON) persistence for Textual theme selection from the command palette.

## What Changed in 0.5.0

- Textual is now the default UI mode (`--ui textual`) when available.
- Calling the CLI without a binary can launch a Textual workspace UX for iterative workflows.
- Added report persistence (`save`/`load`) and collection persistence.
- Added directory crawling and task-file execution for batch scanning.
- Added Markdown and PDF export for single reports and collections.
- Added stronger false-positive guardrails across language/compiler/build-system layers.
- Added artifact feedback loop to reduce cross-domain misclassification (for example, firmware vs hosted runtime).
- Added DWARF language-attribute scoring (`DW_AT_language`) for stronger language attribution.
- Added DWARF path-based build-system inference (`DW_AT_comp_dir`, `DW_AT_name`).
- Added new language heuristics: `Kotlin/Native`, `Pascal`, `Crystal`.
- Added new compiler heuristics: `Intel ICC/ICX`, `TinyCC`, `LDC`, `GDC`.
- Added new build-system heuristics: `Buildroot`, `Yocto/OpenEmbedded`, `PlatformIO`, `ESP-IDF`, `Zephyr West`.
- Added `install_deps.py` profile/group dependency installer.

## Detection Coverage

### Languages

`ASM`, `C`, `C++`, `C#`, `Rust`, `Go`, `Dart`, `Kotlin/Native`, `Pascal`, `Crystal`, `D`, `Ada`, `Fortran`, `Nim`, `Zig`, `Haskell`, `OCaml`, `Julia`, `Lua`, `Swift`, `Java`, `Python`, `SageLang`

### Compilers/Assemblers

`GCC`, `Clang`, `Intel ICC/ICX`, `TinyCC`, `Rustc`, `Go gc`, `Zig`, `LDC`, `GDC`, `NASM`, `FASM`, `MASM`, `TASM`, `GHC`, `OCamlopt`, `Ambiguous: ...`, `Unknown`

### Build Systems

`CMake`, `Meson`, `Bazel`, `Cargo`, `Ninja`, `Make`, `Autotools`, `MSBuild`, `Gradle`, `SCons`, `XMake`, `Buck2`, `Go Toolchain`, `Dart/Flutter`, `Zig Build`, `Pico SDK`, `Buildroot`, `Yocto/OpenEmbedded`, `PlatformIO`, `ESP-IDF`, `Zephyr West`, `Ambiguous: ...`, `Unknown`

### Artifact Types

`Bare-metal Firmware`, `Linux User-space Executable`, `Static User-space Executable`, `Linux Shared Library`, `Linux Kernel Module`, `Relocatable Object`, `Ambiguous: ...`, `Unknown`

## Supported Input Formats

- ELF binaries (`.elf`, executables/shared objects/object files with ELF magic)
- UF2 firmware images (`.uf2`)
- GNU ar archives (`.a`) with ELF members
- Intel HEX firmware files (`.hex`, `.ihex`, `.ihx`)
- Motorola S-record firmware files (`.srec`, `.s19`, `.s28`, `.s37`, `.mot`)
- raw firmware binaries (`.bin`, `.fw`, `.rom`, `.img`, `.raw`, `.blob`)

## Reliability Design

Current reliability strategy combines multiple signal classes:
- ELF structure (`ET_*`, `PT_*`, `DT_NEEDED`, interpreter/loader presence)
- sections, symbols, note sections, comment/debug strings
- DWARF compile unit attributes (`DW_AT_language`, `DW_AT_comp_dir`, `DW_AT_name`, `DW_AT_producer`)
- architecture-shape and disassembly-inspired instruction patterns
- artifact-first context propagation into language/compiler/build-system scorers
- conservative tie handling (`Ambiguous`) and weak-signal fallback (`Unknown`)

Current false-positive guardrails include:
- Go requires Go-runtime symbol families and ignores generic `runtime.c` file symbols.
- C# uses explicit CLR/Mono runtime markers and avoids weak generic `mono` substrings.
- C gets boosts from real `.c` file symbol density to outvote incidental embedded runtime markers.
- SageLang runtime signals are weighted with anchor requirements to avoid accidental promotion.

## Project Layout

- `src/elfscan.py`: thin CLI entrypoint/facade
- `src/scancli/`: CLI args, render, workflow, and format dispatch orchestration
- `src/detect/`: language/compiler/build-system/artifact detection orchestration + heuristics
- `src/detect/techniques/`: evidence-specific heuristic modules
- `src/detect/arch/`: architecture-shape heuristics
- `src/info/elfinfo.py`: metadata printers (`general`, `important`, `detailed`)
- `src/symbols/elfsymbols.py`: symbol-driven heuristic scoring
- `src/uf2/`: UF2 parsing and UF2-backed firmware scanning
- `src/baremetal/`: Intel HEX, S-record, and raw firmware scanners
- `src/elfarchive/`: GNU ar archive scanners for ELF member aggregation
- `src/settings.py`: JSON settings loader/saver
- `src/ui/textual_report.py`: Textual report viewer
- `src/ui/textual_workspace.py`: Textual workspace UX (no-arg interactive mode)
- `src/reporting/persistence.py`: JSON save/load/list for reports and collections
- `src/reporting/export.py`: Markdown/PDF export helpers
- `src/reporting/tasks.py`: task-file batch runner (`scan` + `crawl`)
- `install_deps.py`: dependency installer (profile/group based)
- `tests/`: regression and unit tests
- `test-bin/`: multi-arch corpus fixtures
- `settings.conf`: persisted user settings (currently Textual theme)

## Requirements

- Python `3.12+`
- `pyelftools`
- optional `textual` for default Textual UX/report UI
- optional `reportlab` for PDF export

Install:

```bash
python3 -m pip install pyelftools
python3 -m pip install textual
python3 -m pip install reportlab
```

Or use the project installer:

```bash
python3 install_deps.py --profile runtime
python3 install_deps.py --profile all --upgrade
python3 install_deps.py --print-groups
```

## CLI Usage

```bash
python3 src/elfscan.py [filepath] [options]
```

Core options:

- `--ui plain|textual` (default: `textual`)
- `-m, --mode general|important|detailed`
- `--crawl <directory>`
- `--no-recursive`
- `--max-files <n>`
- `--task-file <tasks.json>`
- `--load-scan <scan.json>`
- `--load-collection <collection.json>`
- `--save-scan [path]`
- `--save-collection [path]`
- `--store-dir <dir>`
- `--export-md <path>`
- `--export-pdf <path>`
- `--export-collection-md <path>`
- `--export-collection-pdf <path>`
- `--show-each`
- `--version`

Examples:

```bash
python3 src/elfscan.py test-bin/x86_64/hello_rust
python3 src/elfscan.py ../littleOS/littleos.uf2
python3 src/elfscan.py firmware.hex
python3 src/elfscan.py firmware.srec
python3 src/elfscan.py firmware.bin
python3 src/elfscan.py libdrivers.a
python3 src/elfscan.py --ui plain -m detailed test-bin/aarch64/hello_go
python3 src/elfscan.py --crawl test-bin --max-files 20 --save-collection
python3 src/elfscan.py --task-file tasks.json --export-collection-md reports/batch.md
python3 src/elfscan.py --load-scan ~/.elfexplorer/scans/hello_rust-20260311T020000Z.json
python3 src/elfscan.py --load-collection ~/.elfexplorer/scans/collection-20260311T020500Z.json --show-each
```

## Textual Workspace (Default UX)

If you run without a binary/workload and `textual` is installed:

```bash
python3 src/elfscan.py
```

The workspace supports:
- scanning (`scan <file> [mode]`)
- crawling (`crawl <dir> [mode] [recursive:true/false] [max_files]`)
- save/load (`save`, `load`, `save-collection`, `load-collection`, `list-saved`)
- export (`export-md`, `export-pdf`, `export-collection-md`, `export-collection-pdf`)
- summary display (`show`)

If Textual is unavailable, use `--ui plain` with explicit CLI options.

## Textual Report Palette

Inside the Textual report viewer (`--ui textual` with a file path), use `Ctrl+P` to open the command palette.

Custom report commands include:
- `Report: Export Markdown`
- `Report: Export PDF`
- `Report: Rescan Current Mode`
- `Report: Mode General + Rescan`
- `Report: Mode Important + Rescan`
- `Report: Mode Detailed + Rescan`

Quick keys in report view:
- `r`: rescan current mode
- `1`: switch to `general` and rescan
- `2`: switch to `important` and rescan
- `3`: switch to `detailed` and rescan

## Settings

ELFexplorer stores user UI preferences in JSON:
- file: `settings.conf` (repository root)
- current persisted key: `theme`

When you change theme from Textual command palette (`Ctrl+P` -> Theme), the selected theme is saved and automatically reused in both Textual workspace and Textual report views.

## Task Files

Task files are JSON:

```json
{
  "tasks": [
    {"type": "scan", "path": "test-bin/x86_64/hello_c", "mode": "general"},
    {"type": "crawl", "path": "test-bin", "recursive": true, "max_files": 50}
  ]
}
```

Run:

```bash
python3 src/elfscan.py --task-file tasks.json --save-collection --export-collection-md reports/corpus.md
```

## Report Persistence

Default storage location:

- `~/.elfexplorer/scans/`

Usage examples:

```bash
python3 src/elfscan.py test-bin/x86_64/hello_go --save-scan
python3 src/elfscan.py test-bin/x86_64/hello_go --save-scan reports/hello_go.json
python3 src/elfscan.py --crawl test-bin --save-collection
```

## Report Export

Single report:

```bash
python3 src/elfscan.py test-bin/x86_64/hello_cpp --export-md reports/hello_cpp.md
python3 src/elfscan.py test-bin/x86_64/hello_cpp --export-pdf reports/hello_cpp.pdf
```

Collection export:

```bash
python3 src/elfscan.py --crawl test-bin --export-collection-md reports/corpus.md
python3 src/elfscan.py --crawl test-bin --export-collection-pdf reports/corpus.pdf
```

Markdown and PDF outputs include:
- structured summary table
- top score tables
- artifact evidence
- captured metadata block

## Testing

Run all tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'
```

Includes:
- CLI/corpus tests
- heuristic detector unit tests
- reporting workflow tests
- dependency installer tests

Corpus test verbosity levels:
- default/no switch: level 1
- `-v`: level 1
- `-vv`: level 2
- `-vvv`: level 3
- `-vvvv`: level 4 (full captured scanner output)
- `-q`: level 0

## Rebuilding Corpus from `hello-multilang`

`build_hello.py` orchestrates Docker build + fixture sync into `test-bin/`.

```bash
python3 build_hello.py --all
python3 build_hello.py --arch x86_64,rv64
python3 build_hello.py --skip-image-build
python3 build_hello.py --dry-run
```

## Additional Reliability Backlog

Useful next steps to increase precision further:
- disassembly-level prologue/epilogue signature libraries per compiler and architecture
- DWARF lineage and CU-level build command extraction (`DW_AT_producer`, compilation dir, macro tables)
- relocation-pattern classifiers for static firmware vs static userspace
- ABI fingerprinting by symbol versioning and PLT/GOT shape families
- confidence calibration on a larger labeled corpus with per-class thresholds
- probabilistic ensemble layer with abstention when confidence gap is small

## Expansion Backlog (Languages, Compilers, Build Systems)

High-value additions:
- languages: `Zig`/`Nim` corpus coverage across all arches, `V`, `Odin`, `Pascal/FreePascal` corpus expansion, `Erlang/Elixir NIF hosts`
- compilers/toolchains: `MSVC (ELF cross-host traces)`, `PCC`, `DMD`, `GNAT variants`
- assemblers: `YASM`, `GNU as` profile split from generic GCC paths
- build systems: `QMake`, `Waf`, `Premake`, `Bazel`/`Buck2` confidence refinement, BSP-layer attribution over detected SDK/toolchain

See [`ELFexplored_Guide.md`](ELFexplored_Guide.md) for method-level details and extension strategy.

## Versioning

- Canonical version source: [`VERSION`](VERSION)
- Current version: `0.6.0`
- CLI check:

```bash
python3 src/elfscan.py --version
```

When updating versioned behavior, keep these synchronized:
- [`VERSION`](VERSION)
- `README.md` (badge + current version line)
- [`ELFexplored_Guide.md`](ELFexplored_Guide.md)

## License

MIT. See [`LICENSE`](LICENSE).
