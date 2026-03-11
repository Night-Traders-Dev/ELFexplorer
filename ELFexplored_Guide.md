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

Current release: `0.6.0` (see `VERSION`).

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
- Markdown export
- PDF export

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
  - interactive Textual workspace for scan/load/export workflows
- `src/reporting/persistence.py`
  - JSON persistence APIs
- `src/reporting/export.py`
  - Markdown/PDF formatting and export
- `src/reporting/tasks.py`
  - JSON task-file runner for batch operations
- `install_deps.py`
  - dependency installer with profile/group modes (`core`, `runtime`, `all`)
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

## 5. Language Detection Coverage

Current labels:
- `ASM`, `C`, `C++`, `C#`, `Rust`, `Go`, `Dart`, `Kotlin/Native`, `Pascal`, `Crystal`, `D`, `Ada`, `Fortran`, `Nim`, `Zig`, `Haskell`, `OCaml`, `Julia`, `Lua`, `Swift`, `Java`, `Python`, `SageLang`

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
- C#: explicit CLR/Mono host/runtime markers
- SageLang: generated C pattern (`sagec_<n>.c`) + Sage runtime clusters with anchor checks

## 6. Compiler/Assembler Detection Coverage

Current labels:
- `GCC`, `Clang`, `Intel ICC/ICX`, `TinyCC`, `Rustc`, `Go gc`, `Zig`, `LDC`, `GDC`, `NASM`, `FASM`, `MASM`, `TASM`, `GHC`, `OCamlopt`, `Ambiguous: ...`, `Unknown`

Evidence sources:
- `.comment`
- DWARF `DW_AT_producer`
- note/section markers (`.note.go.buildid`, `.note.rustc`)
- toolchain-specific symbol families
- runtime dependency signals

Assembler family detection for ELF currently recognizes NASM/FASM/MASM/TASM marker families when present in producer/comment/debug contexts.

## 7. Build-System Detection Coverage

Current labels:
- `CMake`, `Meson`, `Bazel`, `Cargo`, `Ninja`, `Make`, `Autotools`, `MSBuild`, `Gradle`, `SCons`, `XMake`, `Buck2`, `Go Toolchain`, `Dart/Flutter`, `Zig Build`, `Pico SDK`, `Buildroot`, `Yocto/OpenEmbedded`, `PlatformIO`, `ESP-IDF`, `Zephyr West`, `Ambiguous: ...`, `Unknown`

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
- fallback: `--ui plain`

### 10.2 No-input behavior

When called without `filepath`, `--crawl`, `--task-file`, `--load-scan`, or `--load-collection`:
- attempts to launch Textual workspace UX
- if unavailable, prints guidance and exits non-zero

### 10.3 Workload modes

- single-file scan: positional supported binary path
- directory crawl: `--crawl`
- task-file batch: `--task-file`
- load existing report(s): `--load-scan`, `--load-collection`

### 10.4 Persistence and export

- save scan JSON: `--save-scan [path]`
- save collection JSON: `--save-collection [path]`
- export report: `--export-md`, `--export-pdf`
- export collection: `--export-collection-md`, `--export-collection-pdf`

### 10.5 Textual Report Palette

When running report UI mode (`--ui textual` with a filepath), the Textual command palette (`Ctrl+P`) provides:
- Markdown export command
- PDF export command
- rescan command using current mode
- mode-switch-and-rescan commands (`general`, `important`, `detailed`)

Additional quick bindings in report view:
- `r` for rescan current mode
- `1` / `2` / `3` for mode switch + rescan

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
- `show`
- `help`
- `quit`

## 12. Report Layout Strategy

### 12.1 Plain report

Sections:
- `ELF Scan Report`
- `Heuristic Scoring`
- `Detection Summary`
- `ELF Metadata`

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
