# ELFexplored Guide

## 1. Project Purpose

`ELFexplorer` is a static ELF analysis utility that combines:
- structural ELF parsing
- heuristic language inference
- heuristic compiler inference
- heuristic host build-system inference
- corpus-based regression testing across architectures

This project is intentionally heuristic-first. It does not claim perfect language attribution for every ELF. Instead, it provides defensible, inspectable evidence-based guesses.

## 2. What the Tool Produces

For each ELF input, the CLI provides:
- language scoring table
- compiler scoring table
- build-system scoring table
- selected best language label
- selected best compiler label
- selected best build-system label
- ELF metadata output in one of three modes

Modes:
- `general`: concise header-centric view
- `important`: key segments and fields
- `detailed`: expanded section/header details

## 3. Repository Layout

- `src/elfscan.py`
  - top-level CLI
  - structured and colorized report framing
  - invokes detection and metadata modules
- `src/detect/elfdetect.py`
  - compatibility import path
  - re-exports modular detectors
- `src/detect/language/core.py`
  - language detector orchestration and final tie-breaking
- `src/detect/compiler.py`
  - compiler detector orchestration and final tie-breaking
- `src/detect/buildsystem.py`
  - build-system detector orchestration and final tie-breaking
- `src/detect/arch/`
  - architecture/binary-shape heuristics (ASM-focused currently)
- `src/detect/techniques/`
  - grouped heuristic implementations by evidence type
- `src/detect/constants.py` and `src/detect/utils.py`
  - shared marker catalogs and reusable readers/helpers
- `src/symbols/elfsymbols.py`
  - symbol-table heuristics
  - cross-language symbol markers and pattern checks
- `src/info/elfinfo.py`
  - metadata renderers for ELF header/program headers/sections
- `tests/test_elfscan_cli.py`
  - integration tests that run the CLI over `test-bin/*`
  - pass/fail status lines with color and verbosity levels
- `tests/test_elfdetect_heuristics.py`
  - focused unit tests for heuristic behavior with fake ELF fixtures
- `test-bin/`
  - architecture-segmented corpus used for regression validation

## 4. Detection Pipeline

High-level flow:

1. Open ELF with `pyelftools`.
2. Initialize per-language score dictionary.
3. Score by evidence type:
   - `.comment` compiler/build strings
   - note sections
   - dynamic dependencies (`DT_NEEDED`)
   - symbols (`.symtab` and `.dynsym`)
   - string markers in relevant sections
   - debug information snippets
   - section-name patterns
   - binary-shape heuristics (ASM)
   - disassembly-inspired opcode pattern scans in `.text`
4. Print score tables.
5. Pick label with highest score.
6. Resolve ties as `Ambiguous: ...`.
7. If no positive evidence, return `Unknown`.

Compiler detection follows a similar but separate scoring pass and returns:
- `GCC`
- `Clang`
- `Rustc`
- `Go gc`
- `Zig`
- `NASM`
- `FASM`
- `MASM`
- `TASM`
- `GHC`
- `OCamlopt`
- `Ambiguous: ...`
- `Unknown`

Build-system detection follows another independent scoring pass and returns labels like:
- `CMake`, `Meson`, `Bazel`, `Cargo`, `Ninja`, `Make`, `Autotools`, `MSBuild`, `Gradle`, `SCons`, `XMake`, `Buck2`, `Go Toolchain`, `Dart/Flutter`, `Zig Build`, `Pico SDK`
- or `Ambiguous: ...` / `Unknown`

## 5. Scoring Strategy

The engine uses additive scoring with weighted signals:
- strong runtime/API markers: high weight
- generic markers: low weight
- cluster/combination signals: bonus weight
- contradiction or ambiguity handled by top-score tie reporting

Important design choices:
- Symbol deduplication across `.symtab` and `.dynsym` to avoid accidental double-counting.
- Runtime-string evidence for SageLang is gated behind Sage anchors to prevent false positives.
- ASM detection uses shape rules, not only symbol names.
- Dart detection uses explicit `Dart_*` API signatures and marker density.
- Go attribution requires explicit Go runtime/program symbols and does not treat generic file symbols such as `runtime.c` as Go evidence.
- C scoring includes source-file density boosts from `.c` FILE symbols (excluding Sage-generated `sagec_<n>.c`) to reduce embedded-runtime false positives.
- C# scoring avoids generic `mono` substring hits and prefers explicit runtime markers (`libmono`, `coreclr`, `hostfxr`, `hostpolicy`, `dotnet`).

## 6. Language Heuristic Catalog

### 6.1 ASM

Main logic:
- `_start` present
- `main` absent
- often no `.dynamic` and no `.interp` for static minimalist binaries
- small section count and startup-only shape

Why this matters:
- Assembly hello-world binaries often contain `_start` directly and bypass C runtime entry conventions.

### 6.2 C

Common evidence:
- GCC/Clang comment markers
- libc-only dynamic linkage (`libc.so.6`) boost
- high volume of real `.c` source file symbols in symbol tables
- absence of stronger C++/Rust/Dart/etc. signatures

### 6.3 C++

Common evidence:
- mangled `_Z*` symbols
- `std::`, `typeinfo`, RTTI/vtable patterns
- `libstdc++`/`libc++` dynamic dependencies
- guarded handling of `__cxa_finalize` so it does not over-trigger by itself

### 6.4 C#

Common evidence:
- runtime/library markers: `coreclr`, `hostfxr`, `hostpolicy`, `libmono`, `dotnet`, `mscorlib`
- dynamic dependencies referencing .NET runtime components
- strings and symbols linked to managed runtime hosting

### 6.5 Rust

Common evidence:
- `rust_*`, allocator/runtime symbols, panic/unwind hints
- Rust-style mangling patterns
- debug string mentions of `rustc`

### 6.6 Go

Common evidence:
- `go.func.`, `go.itab.`, `main.main`, `runtime.main`/`runtime.rt0_*` symbol conventions
- `.note.go.buildid`
- characteristic runtime symbol volume
- explicit filtering of generic file symbols like `runtime.c`

### 6.7 Dart

Common evidence:
- large presence of `Dart_*` symbols/functions
- marker density (`dart_initialize`, isolate/kernel/AOT strings)
- dynamic/runtime hints such as embedded Dart runtime APIs

Why prior versions failed:
- Without Dart-specific markers, generic C++ artifacts tended to win.

### 6.8 D

Common evidence:
- D runtime markers such as `_dmain`, `_dmodule`, `dmd`/`phobos` references

### 6.9 Ada

Common evidence:
- `ada__` symbol patterns
- GNAT-linked markers

### 6.10 Fortran

Common evidence:
- `_gfortran*` symbols or gfortran build/runtime markers

### 6.11 Nim

Common evidence:
- `nimrtl`, `nim_gc`, `NimMain`, `nimInit`, related strings
- `.note.nim` or nim-specific tokens

### 6.12 Zig

Common evidence:
- zig comment markers (`zig`, `ziglang`)
- zig symbol signatures (`__zig_*`, `zig_*`)
- zig-specific string patterns

### 6.13 Swift

Common evidence:
- `swift` symbol/string markers
- swift-specific notes/sections

### 6.14 Java

Common evidence:
- `jni_`, `jvm`, `javac`, OpenJDK markers
- Java/JVM-ish section/string clues

### 6.15 Python

Common evidence:
- `pyinit`, python symbol references
- python-specific build/debug strings

### 6.16 SageLang

Common evidence:
- `sagec_<digits>.c` generated C file symbols
- dense `sage_*` runtime symbol families
- Sage runtime marker clusters (`sage_try_stack`, `sage_exception_value`, `sage_method_table`, `sage_class_registry`)
- Sage-specific runtime error strings plus anchors

### 6.17 Haskell

Common evidence:
- `hs_init`, `stg_*`, `rts_*` symbol families
- `libHSrts` runtime linkage and GHC string markers

### 6.18 OCaml

Common evidence:
- `caml_startup`, `caml_main`, `caml_*` symbols
- runtime linkage markers such as `libasmrun`

### 6.19 Julia

Common evidence:
- embedding/runtime symbols (`jl_init`, `jl_atexit_hook`, `julia_*`)
- `libjulia` markers in strings/dependencies

### 6.20 Lua

Common evidence:
- Lua C API symbols (`lua_*`, `luaL_*`, `lua_pcall*`)
- `liblua` / `luajit` runtime markers

## 7. Compiler and Assembler Detection

Compiler detection is separate from language detection.

Evidence sources:
- `.comment` and debug strings (GCC/Clang/Rustc/Go/Zig and assembler markers)
- DWARF compile-unit producers (`DW_AT_producer`)
- `.GCC.command.line` and note/section hints (`.note.go.buildid`, `.note.rustc`, assembler note sections)
- marker symbols (`__clang_call_terminate`, `__gcov_*`, Rust/Go/Zig/runtime and assembler-specific markers)
- dynamic libs (`libclang_rt`/`libc++` vs `libgcc`/`libstdc++`, plus `libHSrts`, `libasmrun`)

Output:
- strongest positive bucket wins
- tie -> ambiguous
- weak/no signal -> unknown (minimum confidence threshold applied)

Scope note:
- compiler selection is language-aware when language detection is decisive
- ASM binaries can now resolve assembler toolchains (`NASM`, `FASM`, `MASM`, `TASM`) when producer/comment/debug markers exist

## 8. Build-System Detection

Build-system detection is intentionally best-effort and relies on embedded clues.

Evidence sources:
- debug/string path fragments (for example `CMakeFiles`, `meson-private`, `bazel-out`, `target/debug`)
- note sections (for example `.note.go.buildid`)
- language-runtime symbols and dynamic dependencies (Go, Dart/Flutter, .NET, Zig)

Outputs include:
- `CMake`, `Meson`, `Bazel`, `Cargo`, `Ninja`, `Make`, `Autotools`, `MSBuild`, `Gradle`, `SCons`, `XMake`, `Buck2`, `Go Toolchain`, `Dart/Flutter`, `Zig Build`, `Pico SDK`
- `Ambiguous: ...` or `Unknown`

## 9. CLI Visual Design

`src/elfscan.py` now prints structured blocks:
- `ELF Scan Report`
- `Heuristic Scoring`
- `Detection Summary`
- `ELF Metadata`

Color/styling:
- uses ANSI formatting when stdout is a TTY
- disabled automatically when `NO_COLOR` is set
- keeps parser-critical lines stable:
  - `Detected Source Language (heuristic): ...`
  - `Detected Compiler (heuristic): ...`
  - `Detected Host Build System (heuristic): ...`

## 10. Corpus Testing

`tests/test_elfscan_cli.py` validates corpus binaries by executing `elfscan.py` directly.

Test behavior:
- verifies expected file inventory per architecture directory
- infers expected language from filename (`hello_<lang>`)
- captures CLI output
- checks detected language line
- prints colorized `[PASS]`/`[FAIL]` status per binary

Verbosity levels:
- Level 0: quiet (`-q`)
- Level 1: default and `-v` (same behavior)
- Level 2: `-vv`
- Level 3: `-vvv`
- Level 4: `-vvvv` (full captured output per binary)

## 11. Unit Heuristic Testing

`tests/test_elfdetect_heuristics.py` uses fake ELF objects to isolate and validate:
- ASM shape detection
- Dart symbol detection
- C# runtime dependency detection
- Zig marker detection
- Nim symbol detection
- Haskell/OCaml/Julia/Lua language inference
- GCC/Clang/Rustc/Go/NASM/FASM/MASM/TASM compiler inference
- build-system inference basics
- disassembly-pattern ASM boosting
- false-positive regressions (`runtime.c` should not imply Go, weak `mono*` text should not imply C#, mixed C + embedded Sage symbols should still classify as C when C evidence dominates)

Benefits:
- fast execution
- no dependency on external toolchains for every heuristic case
- deterministic regression checks

## 12. Current Boundaries and Tradeoffs

1. Heuristic confidence depends on available symbols/strings/sections.
2. Stripped binaries reduce evidence quality.
3. Static links can hide library-based hints.
4. Some ecosystems share C/C++ runtime artifacts, requiring strong disambiguators.
5. Compiler detection is best-effort and can be unknown/ambiguous.

## 13. Extending to New Languages

When adding a language:

1. Add language key to `SUPPORTED_LANGUAGES`.
2. Add note/section markers if available.
3. Add dynamic dependency hints.
4. Add symbol-level hints in `elfsymbols.py`.
5. Add string/debug markers.
6. Add disambiguation rules if overlaps are likely.
7. Add focused unit tests in `test_elfdetect_heuristics.py`.
8. Add corpus samples and CLI test expectations.

## 14. Recommended Workflow for Heuristic Changes

1. Add or update binary samples under `test-bin/<arch>/`.
2. Run:
   - `PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v`
3. Inspect score tables for false-positive contributors.
4. Prefer adding strong positive markers before adding penalties.
5. Ensure tie handling stays explainable.
6. Update README and this guide with any behavioral changes.
7. If behavior or features changed, update project version metadata.

## 15. Versioning and Documentation Discipline

Current project version is tracked in the root `VERSION` file and exposed by:
- `python3 src/elfscan.py --version`

Release/update checklist:
1. Update `VERSION` with the new SemVer value.
2. Update `README.md`:
   - version badge
   - current version line
   - any changed commands/behavior
3. Update `ELFexplored_Guide.md`:
   - methods/heuristics/architecture updates
   - release-impact notes
4. Run full tests:
   - `PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v`
5. Confirm CLI version output matches `VERSION`.

Policy:
- Every feature or heuristic change must finish with synchronized updates to both `README.md` and `ELFexplored_Guide.md`.

## 16. Practical Commands

Single binary scan:

```bash
PYTHONPATH=src python3 src/elfscan.py test-bin/x86_64/hello_rust
```

Detailed metadata:

```bash
PYTHONPATH=src python3 src/elfscan.py -m detailed test-bin/aarch64/hello_go
```

Run full tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v
```

High-verbosity corpus diagnostics:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -vvvv
```

Check current project version:

```bash
python3 src/elfscan.py --version
```

Rebuild and sync hello corpus fixtures:

```bash
python3 build_hello.py --all
```

## 17. Research References

The current heuristic expansion was informed by official/toolchain docs:
- Rust symbol mangling: https://doc.rust-lang.org/rustc/symbol-mangling/index.html
- Go build IDs and ELF note behavior: https://pkg.go.dev/cmd/internal/buildid
- GHC FFI runtime init (`hs_init`): https://downloads.haskell.org/ghc/latest/docs/users_guide/exts/ffi.html
- OCaml C interface/runtime startup (`caml_startup`): https://ocaml.org/manual/intfc.html
- Julia embedding (`jl_init`, `jl_atexit_hook`): https://docs.julialang.org/en/v1/manual/embedding/
- Lua C API reference: https://www.lua.org/manual/5.4/manual.html
- NASM documentation: https://www.nasm.us/doc/
- MASM reference: https://learn.microsoft.com/en-us/cpp/assembler/masm/microsoft-macro-assembler-reference
- GNU objdump disassembly options: https://sourceware.org/binutils/docs/binutils/objdump.html
- Cargo build output directories: https://doc.rust-lang.org/cargo/guide/build-cache.html
- CMake build system conventions: https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html
- Bazel output directories: https://bazel.build/remote/output-directories
- Gradle directory layout: https://docs.gradle.org/current/userguide/directory_layout.html

## 18. Summary

`ELFexplorer` is an evidence-driven ELF fingerprinting framework with:
- broad multi-language heuristics
- compiler attribution
- architecture-diverse corpus regression
- explicit, inspectable score reporting

The project is designed to be incrementally extensible: add new language/toolchain evidence, lock behavior with tests, and keep scoring rationale visible.
