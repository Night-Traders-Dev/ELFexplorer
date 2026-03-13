# ELFexplored Guide

## 1. Overview

`ELFexplorer` is an evidence-driven binary analysis framework that performs:
- source-language inference
- compiler/assembler inference
- host build-system inference
- artifact classification (firmware/userspace/library/module/object)
- structured reporting and export for single scans and scan collections

The project is intentionally heuristic. It does not claim perfect provenance reconstruction from arbitrary stripped binaries. It is designed to provide:
- transparent score breakdowns
- inspectable evidence markers
- deterministic regression tests
- conservative fallback (`Ambiguous` or `Unknown`) when evidence is weak or conflicting

Current release: `0.12.1` (see `VERSION`).

Supported input containers currently include:
- ELF binaries
- UF2 firmware images
- Intel HEX firmware files
- Motorola S-record firmware files
- raw firmware binaries
- GNU ar archives containing ELF members

## 2. Analysis Layers

### 2.1 Binary Structural Layer

For ELF-family inputs, structural extraction is based on `pyelftools` and includes:
- ELF type (`ET_EXEC`, `ET_DYN`, `ET_REL`)
- machine (`EM_*`)
- entry point (`e_entry`)
- program headers (`PT_INTERP`, `PT_DYNAMIC`, load segment map)
- section names and section payload scans
- dynamic dependencies (`DT_NEEDED`)

For firmware containers (UF2/Intel HEX/S-record/raw):
- container-level parse/validation (record and checksum checks where applicable)
- payload reconstruction into contiguous data blobs
- address-range extraction when available
- family/target hints (for example RP2040 UF2 family ID)

This layer supplies hard constraints and shape hints used by all upper layers.

### 2.2 Heuristic Evidence Layer

Evidence classes:
- section-name markers
- symbol-name markers (`.symtab`, `.dynsym`)
- note sections (`.note.*`)
- compiler/build comments (`.comment`)
- debug strings (`.debug_str`, string-bearing sections)
- DWARF compile-unit metadata (`DW_AT_language`, `DW_AT_producer`, `DW_AT_comp_dir`, `DW_AT_name`)
- runtime library dependencies
- architecture-specific text-pattern checks

### 2.3 Cross-Layer Context Layer

Artifact profile is computed first and fed into:
- language scoring
- compiler scoring
- build-system scoring

This context feedback helps suppress false positives such as hosted-runtime signatures inside bare-metal firmware.

### 2.4 Presentation and Workflow Layer

Outputs are available as:
- plain CLI report
- Textual report UI
- Textual workspace UX (interactive multi-scan workflow)
- Textual workspace advanced ELF edit mode (in-memory header mutation + save/revert)
- Markdown export
- PDF export
- external-tool integration export (Binary Ninja, Ghidra, IDA, radare2/Cutter, ImHex)

## 3. Repository Architecture

- `src/elfscan.py`
  - thin CLI entrypoint/facade
- `src/scancli/`
  - argument parsing
  - dispatch and workflow orchestration
  - plain/textual report rendering
- `src/uf2/`
  - UF2 parser
  - UF2-backed firmware scan pipeline
- `src/baremetal/`
  - Intel HEX parser + scanner
  - Motorola S-record parser + scanner
  - raw binary firmware scanner
- `src/elfarchive/`
  - GNU ar parser + ELF member aggregation scanner
- `src/settings.py`
  - JSON settings persistence for UI preferences
- `src/detect/elfdetect.py`
  - compatibility re-export of detector entrypoints
- `src/detect/language/core.py`
  - language scoring orchestration and final selection
- `src/detect/compiler.py`
  - compiler scoring orchestration and final selection
- `src/detect/buildsystem.py`
  - build-system scoring orchestration and final selection
- `src/detect/artifact.py`
  - artifact profile orchestration (confidence + hints)
- `src/advanced/`
  - benchmark runner (accuracy, confusion matrix, precision/recall)
  - per-architecture benchmark slicing + reliability-curve output
  - calibration model generation/application for artifact confidence
  - score explainability generation (top positives/competitors + confidence notes)
  - plugin/signature rule application + schema validation/conflict diagnostics
  - mixed-binary attribution (section + symbol hints)
  - firmware fingerprinting layer (MCU/vendor/SDK/RTOS + linker/vector hints)
  - stripped/packed/obfuscated hardening profile
  - cross-binary diff model/rendering
  - CI policy evaluation
  - reverse-engineering import/export interop + merge policies
  - external-tool bridge for disassemblers/memory tools
  - host-tool detection and install orchestration
- `src/detect/techniques/`
  - technique modules grouped by evidence type
- `src/detect/techniques/artifact.py`
  - firmware/userspace/shared/module/object heuristics
- `src/symbols/elfsymbols.py`
  - symbol-pattern scoring helpers
- `src/info/elfinfo.py`
  - metadata renderers (`general`, `important`, `detailed`)
- `src/ui/textual_report.py`
  - tabbed Textual report viewer
- `src/ui/textual_workspace.py`
  - interactive Textual workspace for scan/load/export workflows and advanced ELF edit mode
- `src/ui/textual_diff.py`
  - dedicated tabbed diff screen for summary/delta/indicator comparisons
- `src/ui/textual_editor.py`
  - dedicated split-pane editor workbench screen
  - interactive disassembler-style hex table (click selection + anchor/range behavior)
  - synchronized raw-binary preview + disassembly highlighting for selected byte ranges
  - patch form, in-app how-to, and contextual hot tips
- `src/edit/elf_editor.py`
  - safe in-memory ELF editing backend
  - ELF/program/section header field mutation
  - disassembler-style hex dump rendering + byte patching
  - file-offset to section / virtual-address mapping helpers
  - integrated disassembly via `objdump` backend
  - change tracking + revert + save
- `src/reporting/persistence.py`
  - JSON persistence APIs
- `src/reporting/export.py`
  - Markdown/PDF formatting and export
- `src/reporting/tasks.py`
  - JSON task-file runner for batch operations
- `install_deps.py`
  - dependency installer with profile/group modes (`core`, `runtime`, `all`)
  - external-tool inspection/install management (`--print-tools`, `--check-tools`, `--install-tool`)
- `tests/`
  - corpus integration and focused heuristic unit tests

## 4. Scoring and Decision Model

Each detector uses additive weighted scoring.

### 4.1 Score Inputs

A score bucket receives increments from multiple independent signals.
Example dimensions:
- strong direct marker (high weight)
- supporting marker cluster (medium)
- weak generic marker (low)

### 4.2 Final Label Selection

1. Identify top score.
2. If top <= 0, output `Unknown`.
3. If multiple labels share top score, output `Ambiguous: ...`.
4. Otherwise return highest bucket label.

### 4.3 Reliability Principles

- prefer positive evidence over large negative penalty matrices
- avoid overfitting to a single marker class
- maintain explicit abstention paths (`Unknown`/`Ambiguous`)
- keep parser-critical output lines stable for automation
- optionally apply benchmark-derived confidence calibration to artifact confidence output

## 5. Language Detection Coverage

Current labels:
- `ASM`, `C`, `C++`, `C#`, `Rust`, `Go`, `Dart`, `Kotlin/Native`, `Pascal`, `Crystal`, `D`, `Ada`, `Fortran`, `Nim`, `Zig`, `Haskell`, `OCaml`, `Julia`, `Lua`, `Swift`, `Java`, `Python`, `Objective-C`, `Ruby`, `Perl`, `Tcl`, `R`, `SageLang`

### 5.1 High-value language cues

- ASM: `_start` startup shape, minimal runtime profile, section/entry alignment
- C: real `.c` FILE symbol density, libc shape, lack of stronger language signatures
- C++: `_Z*`, RTTI/vtable/typeinfo patterns, stdlib linkage hints
- Rust: `rust_*`, panic/unwind/runtime markers, mangling patterns
- Go: `go.*` runtime/program symbols, `.note.go.buildid`, runtime graph markers
- Dart: `Dart_*` APIs and runtime symbols
- Kotlin/Native: exported-symbol conventions (`ExportedSymbols`, `DisposeStablePointer`, `DisposeString`, Kotlin root symbols) and DWARF Kotlin language tags
- Pascal: FreePascal-style `fpc_*` runtime markers and Pascal DWARF language tags
- Crystal: Crystal runtime entry patterns and DWARF Crystal language tags
- Nim/Zig: runtime/toolchain symbol and comment markers
- Objective-C: `objc_*/OBJC_*` runtime markers, `libobjc` linkage, GNUstep/runtime support strings
- Ruby: `ruby_*`, `rb_*`, `libruby` runtime linkage, embedded VM strings
- Perl: `Perl_*`, `PL_*`, `libperl` runtime linkage
- Tcl: `Tcl_*`, `Tclp*` API/runtime markers
- R: `Rf_*`, `R_*`, `libR.so` embedding/runtime markers
- C#: explicit CLR/Mono host/runtime markers
- SageLang: generated C pattern (`sagec_<n>.c`) + Sage runtime clusters with anchor checks

## 6. Compiler/Assembler Detection Coverage

Current labels:
- `GCC`, `Clang`, `Intel ICC/ICX`, `TinyCC`, `Rustc`, `Go gc`, `Zig`, `LDC`, `GDC`, `FreePascal`, `DMD`, `GNAT`, `GFortran`, `NASM`, `FASM`, `MASM`, `TASM`, `YASM`, `GHC`, `OCamlopt`, `Ambiguous: ...`, `Unknown`

Evidence sources:
- `.comment`
- DWARF `DW_AT_producer`
- note/section markers (`.note.go.buildid`, `.note.rustc`)
- toolchain-specific symbol families
- runtime dependency signals

Assembler family detection for ELF currently recognizes NASM/FASM/MASM/TASM/YASM marker families when present in producer/comment/debug contexts.

## 7. Build-System Detection Coverage

Current labels:
- `CMake`, `Meson`, `Bazel`, `Cargo`, `Ninja`, `Make`, `Autotools`, `MSBuild`, `Gradle`, `SCons`, `XMake`, `Buck2`, `Go Toolchain`, `Dart/Flutter`, `Zig Build`, `Pico SDK`, `Buildroot`, `Yocto/OpenEmbedded`, `PlatformIO`, `ESP-IDF`, `Zephyr West`, `Waf`, `QMake`, `Premake`, `Cabal`, `Stack`, `Nix`, `Arduino`, `Ambiguous: ...`, `Unknown`

Evidence sources:
- path fragments in debug strings
- DWARF compile-unit paths (`DW_AT_comp_dir`, `DW_AT_name`)
- section/note markers
- runtime and dependency hints
- artifact-context biasing (for example, firmware + Pico markers)

## 8. Artifact Profiling

Current labels:
- `Bare-metal Firmware`
- `Linux User-space Executable`
- `Static User-space Executable`
- `Linux Shared Library`
- `Linux Kernel Module`
- `Relocatable Object`
- `Ambiguous: ...`
- `Unknown`

Profile fields include:
- confidence score
- raw/calibrated confidence (when calibration model is applied)
- target hint
- SDK/framework hint
- RTOS hint
- runtime C library hint
- linkage model
- loader information
- indicator list

### 8.1 Firmware cues

- missing interpreter + low dynamic dependency profile
- MCU/embedded machine types
- vector-table-like load content and memory-map alignment
- linker-script marker families (`MEMORY`, `SECTIONS`, `ORIGIN`, `LENGTH`, `ldscripts`)
- SDK version extraction from embedded strings
- firmware-centric sections (`.boot2`, `.binary_info`, etc.)
- SDK/runtime markers (Pico SDK, CMSIS/syscall stubs)

### 8.2 Userspace cues

- `PT_INTERP` presence
- dynamic linker and `DT_NEEDED`
- runtime entry symbols (`__libc_start_main`)
- executable/shared layout consistency

## 9. False-Positive Control

Implemented controls:
- Go classification requires explicit Go runtime/program fingerprints and ignores weak generic file-symbol collisions.
- C# weak substring logic was tightened to runtime-host markers (`coreclr`, `hostfxr`, `hostpolicy`, `libmono`, `dotnet`).
- C receives evidence boost from real C source symbol density.
- SageLang runtime signal weighting requires stronger anchor combinations.
- Artifact context is propagated into language/compiler/build-system scoring to reduce cross-domain misclassification.

## 10. CLI and UX Behavior

`elfscan.py` supports single or batch workflows.

### 10.1 UI mode

- default: `--ui textual`
- alternatives: `--ui plain`, `--ui web`

### 10.2 No-input behavior

When called without `filepath`, `--crawl`, `--task-file`, `--load-scan`, or `--load-collection`:
- attempts to launch Textual workspace UX
- can launch the web dashboard workspace with `--ui web`
- if unavailable, prints guidance and exits non-zero

### 10.3 Workload modes

- single-file scan: positional supported binary path
- directory crawl: `--crawl`
- task-file batch: `--task-file`
- load existing report(s): `--load-scan`, `--load-collection`
- benchmark mode: `--benchmark-manifest` or `--benchmark-corpus`
- benchmark calibration export: `--benchmark-export-calibration`
- binary diff mode: `--diff`

### 10.4 Persistence and export

- save scan JSON: `--save-scan [path]`
- save collection JSON: `--save-collection [path]`
- export report: `--export-md`, `--export-pdf`
- export collection: `--export-collection-md`, `--export-collection-pdf`
- export diff markdown: `--export-diff-md`
- export RE payload: `--re-export` (`--re-export-format` supports `generic`, `ghidra`, `ida`, `rizin`)
- list external-tool export formats: `--list-tool-plugins`
- select external-tool export format: `--tool-plugin-format binaryninja|ghidra|ida-python|radare2|cutter|imhex`
- export external-tool plugin/script: `--tool-plugin-export [path-or-dir]`
- runtime confidence calibration model input: `--calibration-model`
- RE merge policy control: `--re-merge-policy union|prefer-import|prefer-scan`
- print known host-managed external tools: `python3 install_deps.py --print-tools`
- inspect host OS/package manager + tool status: `python3 install_deps.py --check-tools`
- print download/install methods for a specific tool: `python3 install_deps.py --tool-info <tool>`
- download a tool package without installing it: `python3 install_deps.py --download-tool <tool>`
- install external tool when supported: `python3 install_deps.py --install-tool <tool>`
- Python dependency installs via `install_deps.py` always use `pip install --break-system-packages ...`

External-tool export notes:
- Binary Ninja / Ghidra / IDA outputs are Python scripts that reapply inferred names and comments.
- radare2 / Cutter outputs are command scripts that create a dedicated flagspace and attach comments.
- ImHex output is a CSV memory/section map suitable for visual offset navigation and memory-map review.
- For multi-report runs, `--tool-plugin-export` should target a directory or be omitted so ELFexplorer can emit one file per report.

### 10.5 Textual Report Palette

When running report UI mode (`--ui textual` with a filepath), the Textual command palette (`Ctrl+P`) provides:
- external tool status refresh command
- per-tool install-method commands (homepage, download URL, host install route)
- per-tool download commands
- install commands for known external tools (auto-install where supported, manual guidance otherwise)
- Markdown export command
- PDF export command
- Binary Ninja export command
- Ghidra export command
- IDA Python export command
- radare2 export command
- Cutter/Rizin export command
- ImHex export command
- editor workbench command (`Report: Open Editor Workbench`)
- rescan command using current mode
- mode-switch-and-rescan commands (`general`, `important`, `detailed`)

Startup/report UX behavior:
- report mode opens with a startup splash showing the application name, current version, and a determinate progress bar
- startup checks preload the host-tool snapshot in the background before the integrations panel is fully populated
- tooling downloads/installs open a dedicated modal window with:
  - live progress bar
  - current operation/status line
  - verbose log of downloads, extraction, wrapper creation, and package-manager output
  - threaded execution so the Textual application remains responsive
- report mode also exposes per-tool workbench commands so the current binary can be sent directly into the integrated Tool Workbench
- report mode includes a dedicated `Bramble` tab with install status, firmware suitability hints, and emulator capability summary

Additional quick bindings in report view:
- `e` for opening the split-pane editor workbench
- `r` for rescan current mode
- `t` for opening the default tool workbench
- `b` for opening the dedicated Bramble workspace
- `1` / `2` / `3` for mode switch + rescan

### 10.6 Settings Persistence

User-facing Textual UI preferences are stored in `settings.conf` (JSON, repository root).

Current persisted preference:
- `theme`: Textual theme selected via command palette
- `tool_paths.bramble`: persisted executable override for the Bramble emulator binary

Behavior:
- on Textual app startup (workspace/report), saved theme is loaded and applied if available
- on theme change, new value is written back to `settings.conf`
- on Bramble executable override save, the selected path is written back to `settings.conf`
- startup splash is shown after theme application so background checks can run without freezing the UI
- startup splash and background task/install modal are centered on screen, with centered title/status presentation

Custom ELFexplorer themes:
- `elfexplorer-cinder`
- `elfexplorer-oceanic`
- `elfexplorer-forge`
- `elfexplorer-verdant`

Web dashboard theme selection is client-side and stored in browser local storage.

### 10.7 Advanced Analysis Flags

- explainability: `--explain`
- CI policy gate: `--ci` with optional `--policy-file`
- RE import: `--re-import`
- RE merge policy: `--re-merge-policy`
- runtime custom signature packs: `--signature-pack <pack.json>` (repeatable)
- confidence calibration model: `--calibration-model <model.json>`

### 10.8 Signature Update Channel

- install local pack and activate: `--install-signature-pack <pack.json>`
- update active pack from URL: `--update-signatures <url>`
- list installed packs: `--list-signature-packs`
- set managed pack directory: `--signatures-dir <dir>`

### 10.9 Host Tooling Management

ELFexplorer now has a host-tooling layer for third-party reverse-engineering tools.

Current behavior:
- detect host OS (`Linux`, `macOS`, `Windows`)
- detect available package managers in host-priority order
- choose a primary package manager for install suggestions
- check whether external tools are already installed via PATH/common install locations
- expose official homepage/download URLs for supported tools
- expose host-aware install commands when the current environment supports package-managed install
- expose all known package-manager install methods for each tool
- download official release assets or vendor packages when a supported source is known
- perform one-click user-local installs for tools with portable packages on supported hosts
- emit structured progress/log events for check, download, and install operations
- collect tool status in parallel via a thread pool to reduce startup and refresh latency
- synthesize install commands only when a verified package recipe exists
- fall back to manual vendor/install guidance for tools that are not safely package-managed on the current host

Current automatic-install coverage is conservative by design:
- `radare2`: `brew`, `apt`, `dnf`, `pacman`
- `ghidra`: `brew`, `pacman`
- `binaryninja`: `brew`
- `cutter`: `dnf`, `pacman`
- `rizin`: `dnf`, `pacman`
- `imhex`: `brew`, `dnf`, `yay`, `paru`

Current one-click local-install coverage on Linux:
- `bramble`: source clone + recursive submodules + CMake build
- `ghidra`: official release ZIP
- `binaryninja`: Binary Ninja Free Linux ZIP
- `cutter`: upstream AppImage
- `imhex`: upstream AppImage
- `rizin`: upstream static tarball

Local-install layout:
- packages download into `~/.elfexplorer/downloads/<tool>/`
- extracted/installed tools live under `~/.elfexplorer/tools/<tool>/`
- launcher wrappers are written to `~/.elfexplorer/bin/`

Commercial/vendor-distributed tools such as `IDA Pro` are still status-checked, but installation remains manual.

Official download/home pages currently surfaced by the tooling layer:
- `bramble`: `https://github.com/Night-Traders-Dev/Bramble`
- `binaryninja`: `https://binary.ninja/free/`
- `ghidra`: `https://ghidra-sre.org/`
- `ida`: `https://hex-rays.com/ida-pro/`
- `radare2`: `https://book.rada.re/install/index.html`
- `cutter`: `https://cutter.re/`
- `rizin`: `https://rizin.re/`
- `imhex`: `https://imhex.werwolv.net/`

## 11. Textual Workspace Command Surface

Workspace commands:
- `scan <file> [mode]`
- `crawl <dir> [mode] [recursive:true/false] [max_files]`
- `load <scan.json>`
- `load-collection <collection.json>`
- `list-saved`
- `save [path]`
- `save-collection [path]`
- `export-md <path>`
- `export-pdf <path>`
- `export-collection-md <path>`
- `export-collection-pdf <path>`
- `tool-status`
- `tool-info <tool>`
- `tool-download <tool>`
- `tool-install <tool>`
- `tool-list`
- `tool-export <format> [path]`
- `tool-ui [tool] [path]`
- `diff <other-file> [mode]`
- `diff-ui <other-file> [mode]`
- `show`
- `edit-open <path>`
- `edit-ui`
- `edit-close`
- `edit-status`
- `edit-show-elf`
- `edit-show-uf2`
- `edit-set-elf <field> <value>`
- `edit-list-phdr`
- `edit-show-phdr <index>`
- `edit-set-phdr <index> <field> <value>`
- `edit-list-shdr`
- `edit-show-shdr <index>`
- `edit-set-shdr <index> <field> <value>`
- `edit-list-blocks`
- `edit-show-block <index>`
- `edit-hex [offset] [length] [width]`
- `edit-poke <offset> <byte>`
- `edit-patch <offset> <hex-bytes...>`
- `edit-write-ascii <offset> <text>`
- `edit-disasm [section] [max_lines]`
- `edit-disasm-range <start> <stop> [section] [max_lines]`
- `edit-diff`
- `edit-revert`
- `edit-save [path]`
- `edit-export-payload [path]`
- `help`
- `quit`

### 11.1 Advanced ELF Edit Mode Behavior

Edit mode is session-based:
1. open an ELF or UF2 image with `edit-open`
2. optionally launch the dedicated split-pane workbench via `edit-ui`
3. inspect/update headers in memory
4. review pending edits with `edit-diff`
5. persist with `edit-save`, or discard with `edit-revert`

Format-specific behavior:
- ELF sessions expose ELF/program/section header mutation commands.
- UF2 sessions expose UF2 block inspection/export commands.
- For UF2, the editable byte stream is the reconstructed payload image, while block/container metadata remains available through dedicated UF2 commands.

Workspace UX behavior:
- workspace mode starts with a splash screen that shows `ELFexplorer <version>` and a progress bar while integrations are checked
- `tool-status` uses the same background task system instead of blocking the command loop
- `tool-download` and `tool-install` use a popup task window with live logs and a determinate progress bar
- `tool-ui` opens the integrated Tool Workbench, and `Ctrl+T` opens the default workbench quickly
- `bramble-ui [path]` opens the dedicated Bramble workspace, and `Ctrl+B` opens it for the current report/editor target

### 11.1a Tool Workbench

The Tool Workbench is a dedicated Textual screen for third-party integrations.

Layout:
- left pane: tool catalog, install/status summary, preset catalog, launch/export actions
- right pane: target path, raw args field, progress bar, live output log, preset/command execution controls

Behavior:
- CLI/headless-friendly tools can run commands directly from the workbench and stream results into the output log
- GUI-centric tools are launched from the workbench, but remain external windows rather than embedded terminal panes
- when a scan report is available, the workbench can export the matching integration script for the selected tool
- clicking or navigating the tool catalog changes the active tool immediately, then refreshes presets, launch state, and command context for that integration

Built-in presets currently focus on stable command-line tools:
- `bramble`: run firmware, debug core 0, status stream, GDB server, ASM trace
- `radare2`: file info, sections, symbols, functions, strings
- `rizin`: file info, sections, symbols, functions, strings
- `cutter`: version
- `imhex`: version

### 11.1b Bramble Workspace

The Bramble workspace is a dedicated Textual screen for RP2040 firmware emulation flows.

Tabs:
- `Session`: structured Bramble controls, command preview, run/debug buttons, progress, live console
- `Reference`: Bramble capability summary surfaced from upstream emulator behavior
- `Examples`: common command patterns for smoke-test, tracing, storage, and GDB workflows

Controls currently exposed:
- scrollable settings pane for smaller terminals and laptops
- Bramble executable override field so a custom binary path can be selected explicitly
- persisted Bramble executable override so the selected binary path survives app restarts and is reused in status/tooling views
- target UF2/ELF path
- clock override
- GDB port
- flash image and mount directory
- SD/eMMC image paths and sizes
- UART bridge port / connect target
- wire socket paths for UART0 / GPIO
- toggles for `stdin`, core 1 debug, memory debug, `no-boot2`, and `jit`

### 11.1c Web Dashboard

ELFexplorer now also exposes a web-native dashboard mode through `--ui web`.

Startup model:
- starts an internal threaded HTTP server
- prints the dashboard URL to stdout
- optionally opens the default browser when `--web-open-browser` is used
- supports custom bind address and port through `--web-host` and `--web-port`

Current dashboard capabilities:
- responsive two-column shell with browser-side theme switching
- scan form for a single supported binary path
- crawl form for directory-based batch scans
- load saved scan JSON
- load saved collection JSON
- saved-report list populated from the managed scan store
- report switcher for multi-report dashboards
- active-report overview cards
- score tables for artifact/language/compiler/build-system layers
- metadata, evidence, and raw JSON panels
- Markdown/PDF export for the active report
- direct JSON download for the active report

Validation and regression coverage now include:
- generated dashboard JavaScript syntax validation via `node --check`
- local HTTP server tests for web `scan` and `export` routes
- direct verification that the web action buttons map onto working API endpoints

The web dashboard is intentionally dependency-light:
- Python stdlib HTTP server backend
- no mandatory Flask/FastAPI dependency
- existing scan/export callbacks are reused from the CLI workflow layer

### 11.2 Split-Pane Editor Workbench

`edit-ui` opens a dedicated Textual editor screen composed of:
- hex pane (left): interactive byte grid with click selection, selection length, and anchor-based range selection
- raw binary preview (left): contextual bytes around selection with highlighted selected range
- disassembly pane (right): section or address-range disassembly rendering with selected-range highlighting
- patch form (bottom-left): byte poke, hex patch, ASCII patch, save, revert
- workflow guide (bottom-middle): step-by-step operational how-to
- hot tips panel (bottom-right): contextual guidance from hovered/focused controls

Keyboard actions in workbench:
- `F5`: refresh hex + disassembly panes
- `Ctrl+H`: refresh hex pane
- `Ctrl+D`: refresh disassembly pane
- `F6`: follow selected hex bytes in disassembly
- `F7`: toggle selection anchor
- `F8`: clear selection
- `Ctrl+]`: expand selection length
- `Ctrl+[` shrink selection length
- `Ctrl+S`: save edited binary
- `Ctrl+R`: revert in-memory edits
- `Esc`: return to workspace

UF2-specific workbench notes:
- the title bar switches to UF2 mode and displays block count, base address, and family identifiers
- selection summaries include mapped target virtual addresses when a selected payload range maps cleanly to UF2 target addresses
- disassembly is best-effort for raw payload images and is currently optimized for RP2040 UF2 inputs
- `edit-show-uf2`, `edit-list-blocks`, `edit-show-block`, and `edit-export-payload` support container-oriented inspection workflows outside the split-pane editor

Safety and constraints:
- edits are in-memory until explicitly saved
- integer range checks are enforced per field width
- index bounds are enforced for program/section header operations
- UF2 payload edits are bounds-checked against the reconstructed payload image
- default save target is `<original_name>.modified`
- unsupported/invalid operations raise explicit edit errors

Hex viewer:
- `edit-hex` prints offset/byte/ascii rows similar to disassembler hex panes
- accepts decimal or `0x` numeric literals for offset/length/width
- byte-level patching is supported through `edit-poke`, `edit-patch`, and `edit-write-ascii`

Disassembler:
- `edit-disasm` and `edit-disasm-range` render section/range disassembly in Textual workspace
- current backend uses GNU `objdump` when available

## 12. Report Layout Strategy

### 12.1 Plain report

Sections:
- `ELF Scan Report`
- `Heuristic Scoring`
- `Detection Summary`
- `ELF Metadata`
- optional `Explainability` (with `--explain`)
- optional `Hardening / Packing Signals` (with `--explain`)
- optional `Mixed Attribution` (with `--explain`)
- optional `Firmware Fingerprint` (with `--explain`)
- optional `Plugin / Signature Evidence` (when rules are active)

Summary lines are intentionally stable for parser tooling:
- `Detected Source Language (heuristic): ...`
- `Detected Compiler (heuristic): ...`
- `Detected Host Build System (heuristic): ...`
- `Detected Artifact Type (heuristic): ...`

### 12.2 Markdown export

Includes:
- report header metadata
- summary table
- top score tables (language/compiler/build/artifact)
- artifact evidence bullets
- metadata code block
- explainability blocks (language/compiler/build/artifact)
- hardening profile
- mixed attribution profile
- firmware fingerprint profile
- plugin/signature evidence (if active)
- imported RE annotation summary (if provided)

Collection Markdown includes global index + per-report sections.

### 12.3 PDF export

Requires `reportlab`.

Includes professional tabular layout:
- styled summary tables
- score tables
- artifact evidence
- metadata block
- multi-page collection reports (index + per-report pages)

## 13. Task Files and Automation

Task file format (`JSON`):

```json
{
  "tasks": [
    {"type": "scan", "path": "test-bin/x86_64/hello_c", "mode": "general"},
    {"type": "crawl", "path": "test-bin", "recursive": true, "max_files": 50}
  ]
}
```

Execution:

```bash
python3 src/elfscan.py --task-file tasks.json --save-collection --export-collection-md reports/corpus.md
```

## 14. Testing Architecture

### 14.1 Corpus CLI integration (`tests/test_elfscan_cli.py`)

- validates corpus inventory shape by architecture folder
- executes scanner over each fixture
- infers expected language from filename (`hello_<lang>`)
- checks detected language line in actual CLI output
- prints colorized `[PASS]/[FAIL]`
- supports verbosity levels 0..4 (`-q`, `-v`, `-vv`, `-vvv`, `-vvvv`)

### 14.2 Heuristic unit tests (`tests/test_elfdetect_heuristics.py`)

Uses synthetic fake ELF objects to test:
- language heuristics
- compiler/build-system heuristics
- artifact profile logic
- key false-positive regressions

### 14.3 Reporting tests (`tests/test_reporting.py`)

Covers:
- save/load round trips
- collection persistence
- markdown export contents
- PDF export behavior
- task-file orchestration

### 14.4 Dependency Installer tests (`tests/test_install_deps.py`)

Covers:
- profile/group package resolution
- pip command construction
- dry-run and group-list output behavior

Run all tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'
```

## 15. Reliability Roadmap

High-impact additions for better accuracy:
- compiler prologue/epilogue fingerprint banks per architecture
- relocation-pattern families for static firmware vs static userspace separation
- symbol version graph inference (`GLIBC_*`, `GCC_*`, `CXXABI_*`) weighting
- richer DWARF harvesting (`DW_AT_comp_dir`, line program path clusters)
- class-specific confidence calibration and abstention thresholds
- larger labeled benchmark sets by architecture, optimization level, strip level, and linker

## 16. Expansion Roadmap

### 16.1 Languages

Recommended next additions:
- `V`
- `Nim` + `Zig` deep corpus on all architectures
- `Kotlin/Native` + `Crystal` corpus fixtures on x86_64/aarch64
- `Pascal/FreePascal` corpus fixtures
- stronger multi-arch corpus coverage for existing `Nim`, `Zig`, `SageLang`, `C#`

### 16.2 Compilers/toolchains

Recommended next additions:
- `PCC`
- `DMD`
- `GNU as`/`YASM` explicit compiler bucket split
- split `GNU as` vs generic GCC pipelines where evidence allows

### 16.3 Build systems

Recommended next additions:
- `QMake`
- `Waf`
- `Premake`
- richer `BSP/SDK` attribution layered on top of `Buildroot`/`Yocto` detection

## 17. Versioning and Documentation Policy

Version source of truth:
- root `VERSION`

Release/update checklist:
1. Update `VERSION`.
2. Update `README.md` version badge and version section.
3. Update this guide with new methods/heuristics/workflows.
4. Run full tests.
5. Verify `python3 src/elfscan.py --version` matches `VERSION`.

Project policy:
- Functional changes should ship with synchronized `README.md` and `ELFexplored_Guide.md` updates.

## 18. Commands Reference

Single scan:

```bash
python3 src/elfscan.py test-bin/x86_64/hello_rust
```

Plain mode detailed:

```bash
python3 src/elfscan.py --ui plain -m detailed test-bin/aarch64/hello_go
```

Interactive workspace:

```bash
python3 src/elfscan.py
```

Batch crawl + collection export:

```bash
python3 src/elfscan.py --crawl test-bin --export-collection-md reports/corpus.md
```

External-tool plugin/script export:

```bash
python3 src/elfscan.py --list-tool-plugins
python3 src/elfscan.py test-bin/x86_64/hello_c --tool-plugin-format ghidra --tool-plugin-export
python3 src/elfscan.py test-bin/x86_64/hello_c --tool-plugin-format binaryninja --tool-plugin-export reports/hello_c-bn.py
python3 src/elfscan.py --crawl test-bin --tool-plugin-format imhex --tool-plugin-export reports/imhex
```

Task-file batch:

```bash
python3 src/elfscan.py --task-file tasks.json --save-collection
```

Install dependencies:

```bash
python3 install_deps.py --profile runtime
python3 install_deps.py --profile all --upgrade
python3 install_deps.py --print-groups
```

Inspect/install external tools:

```bash
python3 install_deps.py --print-tools
python3 install_deps.py --check-tools
python3 install_deps.py --install-tool radare2 --dry-run
python3 install_deps.py --install-tool ghidra
```

Version check:

```bash
python3 src/elfscan.py --version
```

## 19. External References

- ELF man page: https://man7.org/linux/man-pages/man5/elf.5.html
- System V ABI (ELF): https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html
- RP2040 datasheet: https://datasheets.raspberrypi.com/rp2040/rp2040-datasheet.pdf
- CMSIS docs: https://arm-software.github.io/CMSIS_6/latest/Core/
- Textual docs: https://textual.textualize.io/
- FreeRTOS API reference: https://www.freertos.org/a00106.html
- Zephyr kernel services: https://docs.zephyrproject.org/latest/kernel/services/index.html
- Rust symbol mangling: https://doc.rust-lang.org/rustc/symbol-mangling/index.html
- Go build IDs: https://pkg.go.dev/cmd/internal/buildid
- Cargo build cache layout: https://doc.rust-lang.org/cargo/guide/build-cache.html
- CMake buildsystem docs: https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html
- GCC `-frecord-gcc-switches` (`.GCC.command.line`): https://gcc.gnu.org/onlinedocs/gcc-4.3.2/gcc/Code-Gen-Options.html
- DWARF language table (`DW_LANG_*`, including Kotlin and Crystal): https://dwarfstd.org/languages-v6.html
- Kotlin/Native exported symbol conventions: https://kotlinlang.org/docs/native-dynamic-libraries.html
- Buildroot output directory structure (`output/build`, `output/host`): https://buildroot.org/downloads/manual/manual.html
- Yocto build/work tree (`tmp/work`): https://docs.yoctoproject.org/2.5.2/ref-manual/ref-manual.html
- PlatformIO workspace/build directory defaults: https://docs.platformio.org/en/latest/projectconf/sections/platformio/options/directory/build_dir.html
- ESP-IDF build system and `idf.py build`: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html
- Zephyr `west build` workflow: https://docs.zephyrproject.org/latest/develop/west/build-flash-debug.html
- TinyCC reference/docs: https://bellard.org/tcc/tcc-doc.html
- GDC manual: https://gcc.gnu.org/onlinedocs/gdc/
- Intel oneAPI `icx` docs: https://www.intel.com/content/www/us/en/docs/dpcpp-cpp-compiler/developer-guide-reference/current/compiler-reference.html
- LDC project README (`ldc2` compiler): https://github.com/ldc-developers/ldc

## 20. Closing Notes

`ELFexplorer` is designed as a growing heuristic intelligence stack:
- add evidence
- calibrate weights
- lock regressions with tests
- expose rationale in reports

The fastest path to better reliability is broad, labeled corpora across architectures/toolchains and strict regression gates on every heuristic change.
