# ELFexplorer

[![Version](https://img.shields.io/badge/version-0.11.9-blue)](#versioning)
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

## What Changed in 0.11.9

- Persisted third-party tool path overrides in `settings.conf` so the Bramble executable path survives app restarts.
- Applied saved tool-path overrides to external-tool status snapshots, install-detail views, the generic tool workbench, and the dedicated Bramble workspace.
- Added custom ELFexplorer Textual themes:
  - `elfexplorer-cinder`
  - `elfexplorer-oceanic`
  - `elfexplorer-forge`
  - `elfexplorer-verdant`

## What Changed in 0.11.8

- Made the dedicated Bramble session page scrollable so the full control surface remains usable on smaller terminals.
- Added a Bramble executable override field so users can point ELFexplorer at a specific `bramble` binary location.
- Routed Bramble status, preview, run, and launch paths through the selected executable override when provided.

## What Changed in 0.11.7

- Added a dedicated Bramble screen with Bramble-specific tabs, command synthesis, preview, progress, and live console output.
- Added a dedicated `Bramble` tab to the report UI with install status, firmware suitability hints, and emulator capability summary.
- Added direct Bramble entry points in Textual:
  - report binding `b`
  - workspace binding `Ctrl+B`
  - workspace command `bramble-ui [path]`

## What Changed in 0.11.6

- Added Bramble (`Night-Traders-Dev/Bramble`) as a supported third-party integration.
- Added Bramble Tool Workbench presets for firmware run, debug, status, GDB server, and ASM trace flows.
- Added one-click ELFexplorer-managed Bramble source builds on supported hosts using `git` + `cmake`.

## What Changed in 0.11.5

- Fixed the Textual Tool Workbench tool catalog so mouse and keyboard row changes immediately switch the active tool instead of remaining stuck on `radare2`.
- Added a regression test covering workbench row-navigation tool switching.

## What Changed in 0.11.4

- Added an in-app third-party Tool Workbench:
  - open per-tool workbench screens from the Textual report view and workspace
  - run capturable CLI/headless commands for tools such as `radare2` and `rizin`
  - launch GUI-centric tools such as Binary Ninja, Ghidra, Cutter, IDA, and ImHex from inside ELFexplorer
  - display live command output inside the workbench and export matching integration scripts from the same screen
- Updated `install_deps.py` pip installs to always pass `--break-system-packages`.

## What Changed in 0.11.3

- Added threaded Textual task modals for long-running tooling operations:
  - popup install/download window with progress bar
  - live verbose log for download, extraction, wrapper creation, and package-manager output
  - shared background-task runner so the UI stays responsive while work continues
- Added Textual startup splash flow:
  - application name + version display
  - progress bar for startup checks
  - host-tool snapshot preload so the integrations tab can render without blocking
- Parallelized external-tool status collection with a thread pool.
- Added regression coverage for progress-event emission and probe-failure isolation.

## What Changed in 0.10.0

- Added host tooling detection and install management for external integrations:
  - OS detection
  - package-manager detection
  - installed-tool status checks
  - best-effort automatic install when a verified package recipe is available
  - manual-install guidance for vendor-managed tools
- Added Textual palette/system-command integration for tooling:
  - `Tooling: Check External Tools`
  - `Tooling: Install <tool>`
- Added workspace commands:
  - `tool-status`
  - `tool-install <tool>`
- Extended `install_deps.py` with external-tool management:
  - `--print-tools`
  - `--check-tools`
  - `--install-tool <tool>`
- Added host-tool manager module and regression tests for detection/install-command synthesis.

## What Changed in 0.9.0

- Added external-tool integration exports for well-known reverse-engineering and binary-inspection tools:
  - Binary Ninja Python script export
  - Ghidra Python script export
  - IDAPython script export
  - radare2 command script export
  - Cutter/Rizin command script export
  - ImHex CSV memory/section map export
- Added CLI integration controls:
  - `--list-tool-plugins`
  - `--tool-plugin-format <format>`
  - `--tool-plugin-export [path]`
- Expanded Textual UX integration surface:
  - report viewer now includes an `Integrations` tab
  - command-palette export actions for every supported tool format
  - workspace commands `tool-list` and `tool-export <format> [path]`
- Expanded language heuristics:
  - `Objective-C`, `Ruby`, `Perl`, `Tcl`, `R`
- Expanded compiler/assembler heuristics:
  - `FreePascal`, `DMD`, `GNAT`, `GFortran`, `YASM`
- Expanded build-system heuristics:
  - `Waf`, `QMake`, `Premake`, `Cabal`, `Stack`, `Nix`, `Arduino`
- Extended Markdown/PDF/plain reports to surface available tool integrations and default export targets.

## What Changed in 0.8.0

- Added confidence calibration pipeline for artifact confidence:
  - benchmark-derived calibration export (`--benchmark-export-calibration`)
  - runtime calibration application (`--calibration-model`)
  - calibrated/raw confidence surfaced in plain, Textual, Markdown, and PDF outputs
- Expanded benchmark output quality:
  - per-architecture accuracy slices
  - failing-case summary in benchmark render output
  - CI benchmark reliability check now uses bin midpoint expectation
- Strengthened firmware fingerprinting:
  - linker-script marker detection (`MEMORY`, `SECTIONS`, `ORIGIN`, `LENGTH`)
  - SDK version extraction (Pico SDK, ESP-IDF, Zephyr, FreeRTOS markers)
  - vector-table shape probing for Cortex-M style images
- Added RE merge policy control (`--re-merge-policy union|prefer-import|prefer-scan`)
  - merged RE view now included in evidence/report output
- Added dedicated Textual diff screen:
  - workspace commands `diff <other-file> [mode]` and `diff-ui <other-file> [mode]`
  - tabbed diff visualization for summary, score deltas, and indicator changes
- Hardened signature rule-pack handling:
  - schema validation
  - conflict/duplicate diagnostics
  - rule priority + operation metadata surfaced in reports

## What Changed in 0.7.0

- Added benchmark suite support:
  - manifest-driven benchmark mode (`--benchmark-manifest`)
  - corpus auto-discovery benchmark mode (`--benchmark-corpus`)
  - accuracy/confusion/per-label precision-recall output with optional JSON export (`--benchmark-out`)
- Added explainability mode (`--explain`) with:
  - top positive class evidence
  - top competitor evidence
  - score-margin confidence notes
- Added plugin/signature rule system for score overrides:
  - runtime rule packs (`--signature-pack`)
  - managed signature channel (`--install-signature-pack`, `--update-signatures`, `--list-signature-packs`)
- Added mixed-binary attribution:
  - section-level language/compiler hints
  - symbol-pattern dominant-language hints
- Added firmware fingerprinting profile:
  - likely MCU/vendor/SDK/RTOS candidates with confidence + signals
- Added stripped/packed/obfuscated risk profiling:
  - entropy and marker-based hardening/packing indicators
- Added cross-binary diff mode:
  - compare two scans (`--diff`) with score deltas and indicator changes
  - optional Markdown diff export (`--export-diff-md`)
- Added CI policy mode:
  - policy file support (`--policy-file`)
  - compliance gate (`--ci`) with non-zero exit on violations
- Added reverse-engineering interop:
  - import RE annotations (`--re-import`)
  - export RE payloads (`--re-export`, `--re-export-format`)

## What Changed in 0.6.1

- Reworked Textual split-pane editor with disassembler-style byte interaction:
  - interactive clickable hex byte grid (cell selection)
  - selection-range workflow with anchor mode (`Set Anchor` / `F7`)
  - synchronized raw-binary preview with highlighted selected bytes
  - disassembly highlight sync for mapped selection ranges
  - `Follow Sel` workflow (`F6`) to auto-fill disassembly start/stop from file-offset selection
  - selection sizing hotkeys (`Ctrl+]` expand, `Ctrl+[` shrink)
- Added backend mapping helpers in `ElfBinaryEditor`:
  - file offset -> section
  - file offset -> virtual address
  - file range -> virtual address range
- Added regression tests for new mapping helpers in `tests/test_elf_editor.py`.

## What Changed in 0.6.0

- Added native scanning support for Intel HEX firmware files (`.hex`, `.ihex`, `.ihx`).
- Added native scanning support for Motorola S-record firmware files (`.srec`, `.s19`, `.s28`, `.s37`, `.mot`).
- Added native scanning support for raw firmware binaries (`.bin`, `.fw`, `.rom`, `.img`, `.raw`, `.blob`).
- Added GNU ar (`.a`) archive scanning with ELF member aggregation.
- Extended crawl support to include all supported formats.
- Added format regression tests in `tests/test_format_support.py`.
- Added advanced ELF editing commands in Textual workspace:
  - modify ELF header fields
  - modify program header entries
  - modify section header entries
  - edit raw bytes (`edit-poke`, `edit-patch`, `edit-write-ascii`)
  - view disassembler-style hex dump ranges
  - disassemble ELF sections/ranges directly in Textual (`edit-disasm`, `edit-disasm-range`)
  - dedicated split-pane editor workbench (`edit-ui` / `Ctrl+E`) with:
    - hex pane
    - disassembly pane
    - patch form
    - built-in workflow how-to
    - contextual hover/focus hot tips
  - inspect pending edits, revert edits, and save edited binaries
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

`ASM`, `C`, `C++`, `C#`, `Rust`, `Go`, `Dart`, `Kotlin/Native`, `Pascal`, `Crystal`, `D`, `Ada`, `Fortran`, `Nim`, `Zig`, `Haskell`, `OCaml`, `Julia`, `Lua`, `Swift`, `Java`, `Python`, `Objective-C`, `Ruby`, `Perl`, `Tcl`, `R`, `SageLang`

### Compilers/Assemblers

`GCC`, `Clang`, `Intel ICC/ICX`, `TinyCC`, `Rustc`, `Go gc`, `Zig`, `LDC`, `GDC`, `FreePascal`, `DMD`, `GNAT`, `GFortran`, `NASM`, `FASM`, `MASM`, `TASM`, `YASM`, `GHC`, `OCamlopt`, `Ambiguous: ...`, `Unknown`

### Build Systems

`CMake`, `Meson`, `Bazel`, `Cargo`, `Ninja`, `Make`, `Autotools`, `MSBuild`, `Gradle`, `SCons`, `XMake`, `Buck2`, `Go Toolchain`, `Dart/Flutter`, `Zig Build`, `Pico SDK`, `Buildroot`, `Yocto/OpenEmbedded`, `PlatformIO`, `ESP-IDF`, `Zephyr West`, `Waf`, `QMake`, `Premake`, `Cabal`, `Stack`, `Nix`, `Arduino`, `Ambiguous: ...`, `Unknown`

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
- `src/advanced/`: benchmark, explainability, plugin/signature, mixed attribution, firmware fingerprinting, hardening, diff, CI, and RE interop
- `src/advanced/toolbridge.py`: external-tool export bridge for Binary Ninja, Ghidra, IDA, radare2/Cutter, and ImHex
- `src/advanced/tooling.py`: host OS/package-manager detection, installed-tool checks, and best-effort external-tool install orchestration
- `src/info/elfinfo.py`: metadata printers (`general`, `important`, `detailed`)
- `src/symbols/elfsymbols.py`: symbol-driven heuristic scoring
- `src/uf2/`: UF2 parsing and UF2-backed firmware scanning
- `src/baremetal/`: Intel HEX, S-record, and raw firmware scanners
- `src/elfarchive/`: GNU ar archive scanners for ELF member aggregation
- `src/settings.py`: JSON settings loader/saver
- `src/ui/textual_report.py`: Textual report viewer with integrations tab and export palette actions
- `src/ui/textual_workspace.py`: Textual workspace UX (no-arg interactive mode, plus tool export commands)
- `src/ui/textual_editor.py`: split-pane Textual editor workbench (interactive hex selection, raw preview, synchronized disassembly highlighting)
- `src/ui/textual_diff.py`: dedicated Textual diff screen for side-by-side classification/evidence deltas
- `src/edit/elf_editor.py`: safe in-memory ELF header editor + disassembler-aligned file-offset/VA mapping utilities
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
python3 install_deps.py --print-tools
python3 install_deps.py --check-tools
python3 install_deps.py --tool-info ghidra
python3 install_deps.py --download-tool ghidra --dry-run
python3 install_deps.py --install-tool radare2 --dry-run
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
- `--explain`
- `--diff <other_binary>`
- `--export-diff-md <path>`
- `--ci`
- `--policy-file <policy.json>`
- `--benchmark-manifest <manifest.json>`
- `--benchmark-corpus <dir>`
- `--benchmark-out <path.json>`
- `--benchmark-export-calibration <path.json>`
- `--calibration-model <path.json>`
- `--signature-pack <pack.json>` (repeatable)
- `--install-signature-pack <pack.json>`
- `--update-signatures <url>`
- `--list-signature-packs`
- `--signatures-dir <dir>`
- `--re-import <annotations.json>`
- `--re-export <path.json>`
- `--re-export-format generic|ghidra|ida|rizin`
- `--re-merge-policy union|prefer-import|prefer-scan`
- `--list-tool-plugins`
- `--tool-plugin-format binaryninja|ghidra|ida-python|radare2|cutter|imhex`
- `--tool-plugin-export [path-or-dir]`
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
python3 src/elfscan.py --benchmark-corpus test-bin --benchmark-out reports/bench.json
python3 src/elfscan.py --benchmark-corpus test-bin --benchmark-out reports/bench.json --benchmark-export-calibration reports/calibration.json
python3 src/elfscan.py --benchmark-manifest benchmarks/cases.json
python3 src/elfscan.py test-bin/x86_64/hello_c --calibration-model reports/calibration.json
python3 src/elfscan.py test-bin/x86_64/hello_c --diff test-bin/x86_64/hello_cpp --export-diff-md reports/c_vs_cpp.md
python3 src/elfscan.py test-bin/x86_64/hello_go --ci --policy-file ci-policy.json
python3 src/elfscan.py test-bin/x86_64/hello_c --signature-pack rules/custom-pack.json --explain
python3 src/elfscan.py test-bin/x86_64/hello_c --re-import re.json --re-merge-policy prefer-import
python3 src/elfscan.py --install-signature-pack rules/custom-pack.json --signatures-dir ~/.elfexplorer/signatures
python3 src/elfscan.py --update-signatures https://example.com/elfexplorer-signatures.json
python3 src/elfscan.py --list-signature-packs
python3 src/elfscan.py test-bin/x86_64/hello_c --re-import re-notes.json --re-export reports/re-export.json --re-export-format ghidra
python3 src/elfscan.py --list-tool-plugins
python3 src/elfscan.py test-bin/x86_64/hello_c --tool-plugin-format ghidra --tool-plugin-export
python3 src/elfscan.py test-bin/x86_64/hello_c --tool-plugin-format binaryninja --tool-plugin-export reports/hello_c-bn.py
python3 src/elfscan.py --crawl test-bin --tool-plugin-format imhex --tool-plugin-export reports/imhex-maps
```

## Textual Workspace (Default UX)

If you run without a binary/workload and `textual` is installed:

```bash
python3 src/elfscan.py
```

The workspace supports:
- startup splash with application name, version, and background startup checks
- scanning (`scan <file> [mode]`)
- crawling (`crawl <dir> [mode] [recursive:true/false] [max_files]`)
- save/load (`save`, `load`, `save-collection`, `load-collection`, `list-saved`)
- export (`export-md`, `export-pdf`, `export-collection-md`, `export-collection-pdf`)
- tool integrations (`tool-list`, `tool-export <format> [path]`)
- in-app tool workbench (`tool-ui [tool] [path]`, or `Ctrl+T`)
- host tooling checks/install (`tool-status`, `tool-info <tool>`, `tool-download <tool>`, `tool-install <tool>`)
- summary display (`show`)
- advanced ELF editing:
  - open dedicated workbench: `edit-ui` (or `Ctrl+E`)
  - `edit-open <path>` / `edit-close` / `edit-status`
  - `edit-show-elf` / `edit-set-elf <field> <value>`
  - `edit-show-uf2` / `edit-list-blocks` / `edit-show-block <idx>` / `edit-export-payload [path]`
  - `edit-list-phdr` / `edit-show-phdr <idx>` / `edit-set-phdr <idx> <field> <value>`
  - `edit-list-shdr` / `edit-show-shdr <idx>` / `edit-set-shdr <idx> <field> <value>`
  - `edit-hex [offset] [length] [width]`
  - `edit-poke <offset> <byte>`
  - `edit-patch <offset> <hex-bytes...>`
  - `edit-write-ascii <offset> <text>`
  - `edit-disasm [section] [max_lines]`
  - `edit-disasm-range <start> <stop> [section] [max_lines]`
  - `edit-diff` / `edit-revert` / `edit-save [path]`

### Split-Pane Editor Workbench

After `edit-open <path>`, run:

```bash
edit-ui
```

Workbench layout:
- left: interactive hex pane + raw binary preview + selection controls
- right: disassembly pane + section/range controls
- bottom-left: patch form (poke/hex/ascii/save/revert)
- bottom-middle: in-app step-by-step how-to
- bottom-right: hot tips panel (updates from hovered/focused controls)

UF2 behavior:
- `edit-open` now accepts ELF or UF2 images
- for UF2, the editable byte stream is the reconstructed firmware payload, not the raw 512-byte UF2 container blocks
- selection summaries include mapped target addresses when the UF2 block map provides them
- `edit-show-uf2`, `edit-list-blocks`, and `edit-show-block` expose UF2 container metadata
- `edit-export-payload` writes the reconstructed raw firmware image to disk for external tooling
- UF2 disassembly is best-effort and currently tuned for RP2040-family images through `objdump -b binary`

Hotkeys inside workbench:
- `F5`: refresh hex + disassembly
- `Ctrl+H`: refresh hex
- `Ctrl+D`: refresh disassembly
- `F6`: follow current byte selection in disassembly
- `F7`: toggle selection anchor (for click-range selection)
- `F8`: clear selection
- `Ctrl+]`: expand selection length
- `Ctrl+[` shrink selection length
- `Ctrl+S`: save
- `Ctrl+R`: revert all in-memory edits
- `Esc`: return to workspace

If Textual is unavailable, use `--ui plain` with explicit CLI options.

Tooling UX details:
- `tool-status` runs in a background modal and refreshes the cached host-tool snapshot
- `tool-download <tool>` opens a popup with a progress bar and live download log
- `tool-install <tool>` opens a popup with a progress bar and live install log
- the workspace startup splash preloads host-tool status so the first tooling view does not block
- `tool-ui [tool] [path]` opens the integrated Tool Workbench for launching tools, running commands, and reviewing output
- `bramble-ui [path]` opens the dedicated Bramble firmware-emulation workspace

### Tool Workbench

The Tool Workbench provides an in-app control surface for third-party integrations:
- tool catalog with install/mode/status summary
- preset catalog for CLI/headless tools
- target-path field and raw-args field
- launch button for GUI-centric tools
- run-preset / run-args actions for tools that can produce capturable terminal output
- live output log and progress bar
- export button for matching integration scripts when a scan report is active

Current built-in command presets focus on tools that have stable CLI output:
- `bramble`: run firmware, debug core 0, status stream, GDB server, ASM trace
- `radare2`: file info, sections, symbols, functions, strings
- `rizin`: file info, sections, symbols, functions, strings
- `cutter`: version
- `imhex`: version

GUI-centric tools still integrate through the same screen, but they are launched externally rather than embedded as native panes inside the terminal UI.

### Bramble Workspace

ELFexplorer also includes a dedicated Bramble screen for RP2040 firmware workflows.

It provides:
- a Bramble-specific session tab with structured controls instead of raw flags
- a scrollable settings pane so long Bramble forms remain accessible
- an executable override field for selecting a non-default `bramble` binary location
- command preview generated from form fields
- emulator run modes for firmware run, debug, ASM trace, status, and GDB server
- flash / mount / SD / eMMC / UART / wire-link fields
- live console capture and progress updates
- reference and example tabs focused on Bramble capabilities

Example editor session:

```bash
python3 src/elfscan.py
# inside workspace:
edit-open test-bin/x86_64/hello_c
edit-show-elf
edit-set-elf e_flags 0x1
edit-list-phdr
edit-show-shdr 1
edit-hex 0x0 0x100 16
edit-patch 0x40 de ad be ef
edit-disasm .text 80
edit-diff
edit-save reports/hello_c.edited.elf
```

UF2 example:

```bash
python3 src/elfscan.py
# inside workspace:
edit-open /path/to/firmware.uf2
edit-show-uf2
edit-list-blocks
edit-hex 0x0 0x100 16
edit-patch 0x40 de ad be ef
edit-disasm .text 80
edit-export-payload reports/firmware.bin
edit-save reports/firmware.edited.uf2
```

## Textual Report Palette

Inside the Textual report viewer (`--ui textual` with a file path), use `Ctrl+P` to open the command palette.

Custom report commands include:
- `Tooling: Check External Tools`
- `Tooling: Show Install Methods for Binary Ninja`
- `Tooling: Show Install Methods for Ghidra`
- `Tooling: Show Install Methods for IDA Pro`
- `Tooling: Show Install Methods for radare2`
- `Tooling: Show Install Methods for Cutter`
- `Tooling: Show Install Methods for Rizin`
- `Tooling: Show Install Methods for ImHex`
- `Tooling: Download Binary Ninja`
- `Tooling: Download Ghidra`
- `Tooling: Download IDA Pro`
- `Tooling: Download radare2`
- `Tooling: Download Cutter`
- `Tooling: Download Rizin`
- `Tooling: Download ImHex`
- `Tooling: Install Binary Ninja`
- `Tooling: Install Ghidra`
- `Tooling: Install IDA Pro`
- `Tooling: Install radare2`
- `Tooling: Install Cutter`
- `Tooling: Install Rizin`
- `Tooling: Install ImHex`
- `Bramble: Open Dedicated Workbench`
- `Report: Export Markdown`
- `Report: Export PDF`
- `Integrations: Export Binary Ninja Script`
- `Integrations: Export Ghidra Script`
- `Integrations: Export IDA Python Script`
- `Integrations: Export radare2 Script`
- `Integrations: Export Cutter/Rizin Script`
- `Integrations: Export ImHex Memory Map`
- `Report: Open Editor Workbench`
- `Bramble: Open Dedicated Workbench`
- `Report: Rescan Current Mode`
- `Report: Mode General + Rescan`
- `Report: Mode Important + Rescan`
- `Report: Mode Detailed + Rescan`

Quick keys in report view:
- `e`: open split-pane editor workbench for current binary
- `r`: rescan current mode
- `b`: open the dedicated Bramble workspace for the current binary
- `1`: switch to `general` and rescan
- `2`: switch to `important` and rescan
- `3`: switch to `detailed` and rescan

## Settings

ELFexplorer stores user UI preferences in JSON:
- file: `settings.conf` (repository root)
- current persisted keys:
  - `theme`
  - `tool_paths.bramble`

When you change theme from Textual command palette (`Ctrl+P` -> Theme), the selected theme is saved and automatically reused in both Textual workspace and Textual report views.

Custom ELFexplorer themes now available in the Textual theme palette:
- `elfexplorer-cinder`
- `elfexplorer-oceanic`
- `elfexplorer-forge`
- `elfexplorer-verdant`

When you set the Bramble executable override in the dedicated Bramble workspace, the selected path is also persisted and reused across:
- the dedicated Bramble workspace
- external-tool status snapshots
- install/detail panels
- the generic tool workbench when `bramble` is selected

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
- tool integration export inventory

Tool plugin/script export:

```bash
python3 src/elfscan.py --list-tool-plugins
python3 src/elfscan.py test-bin/x86_64/hello_c --tool-plugin-format ghidra --tool-plugin-export
python3 src/elfscan.py test-bin/x86_64/hello_c --tool-plugin-format ida-python --tool-plugin-export reports/hello_c-ida.py
python3 src/elfscan.py --crawl test-bin --tool-plugin-format imhex --tool-plugin-export reports/imhex
```

Supported integrations:
- Bramble
- Binary Ninja
- Ghidra
- IDA Pro
- radare2
- Cutter/Rizin
- ImHex

For multi-report runs, `--tool-plugin-export` should be omitted or pointed at a directory so ELFexplorer can emit one integration file per report.

## External Tool Management

Host tooling detection and install support:

```bash
python3 install_deps.py --print-tools
python3 install_deps.py --check-tools
python3 install_deps.py --tool-info radare2
python3 install_deps.py --download-tool ghidra --dry-run
python3 install_deps.py --install-tool radare2 --dry-run
python3 install_deps.py --install-tool ghidra
```

Python dependency installation now always uses `pip install --break-system-packages ...` through `install_deps.py`.

Current behavior:
- detects host OS and primary package manager
- checks whether supported third-party tools are already installed
- prints official homepage/download locations for supported tools
- prints host-aware install commands when the current OS/package manager is supported
- prints all known package-manager install methods for each supported tool
- downloads official release assets or vendor packages when a supported download path exists
- performs one-click user-local installs under `~/.elfexplorer/tools` when a portable package is available
- uses verified package-manager recipes where available
- falls back to manual-install guidance for tools such as vendor-managed commercial distributions
- drives Textual install/download/check actions through background worker threads so progress bars and logs stay live

Textual integrations/report UI behavior:
- report mode shows a startup splash with `ELFexplorer <version>` and a live startup progress bar
- the `Integrations` tab remains scrollable while showing long install-detail sections
- palette installs/downloads use a popup modal with:
  - determinate progress bar
  - current status line
  - verbose step log
  - non-blocking worker thread execution

Current automatic-install coverage is intentionally conservative:
- `radare2`: `brew`, `apt`, `dnf`, `pacman`
- `ghidra`: `brew`, `pacman`
- `binaryninja`: `brew`
- `cutter`: `dnf`, `pacman`
- `rizin`: `dnf`, `pacman`
- `imhex`: `brew`, `dnf`, `yay`, `paru`

Current one-click local-install coverage on Linux:
- `bramble`: source clone + recursive submodules + CMake build under `~/.elfexplorer/tools/bramble/...`
- `ghidra`: official release ZIP -> extracted under `~/.elfexplorer/tools/ghidra/...`
- `binaryninja`: Binary Ninja Free Linux ZIP -> extracted under `~/.elfexplorer/tools/binaryninja/...`
- `cutter`: upstream AppImage -> installed under `~/.elfexplorer/tools/cutter/...`
- `imhex`: upstream AppImage -> installed under `~/.elfexplorer/tools/imhex/...`
- `rizin`: upstream static tarball -> extracted under `~/.elfexplorer/tools/rizin/...`

Launch wrappers for local installs are created in:
- `~/.elfexplorer/bin`

Official download/home pages used by the tooling layer:
- `bramble`: `https://github.com/Night-Traders-Dev/Bramble`
- `binaryninja`: `https://binary.ninja/free/`
- `ghidra`: `https://ghidra-sre.org/`
- `ida`: `https://hex-rays.com/ida-pro/`
- `radare2`: `https://book.rada.re/install/index.html`
- `cutter`: `https://cutter.re/`
- `rizin`: `https://rizin.re/`
- `imhex`: `https://imhex.werwolv.net/`

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
- compilers/toolchains: `MSVC (ELF cross-host traces)`, `PCC`, `GNU as` profile split from GCC, `clang-cl` cross-toolchain traces
- assemblers: deeper `GNU as` vs compiler-driver differentiation, macro package detection
- build systems: `Bazel`/`Buck2` confidence refinement, BSP-layer attribution over detected SDK/toolchain, generator-chain separation (`CMake` -> `Ninja` vs `CMake` -> `Make`)
- integrations: bidirectional import/export with Binary Ninja, Ghidra, IDA, radare2/Cutter, and richer ImHex pattern generation

See [`ELFexplored_Guide.md`](ELFexplored_Guide.md) for method-level details and extension strategy.

## Versioning

- Canonical version source: [`VERSION`](VERSION)
- Current version: `0.10.0`
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
