# ELFexplorer

[![Version](https://img.shields.io/badge/version-0.2.1-blue)](#versioning)
[![Python](https://img.shields.io/badge/python-3.12%2B-informational)](#requirements)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](#license)
[![Tests](https://img.shields.io/badge/tests-unittest%20heuristics%20%2B%20corpus-brightgreen)](#testing)

`ELFexplorer` is a modular ELF analysis and heuristic fingerprinting tool focused on language, compiler, and build-system inference.

It currently provides:
- Structured ELF metadata reporting (general/important/detailed modes)
- Heuristic source-language detection
- Heuristic compiler/assembler detection
- Heuristic host build-system detection
- Corpus-driven validation over multi-architecture test binaries

## Supported Language Detection

Current language labels:
- `ASM`
- `C`
- `C++`
- `C#`
- `Rust`
- `Go`
- `Dart`
- `D`
- `Ada`
- `Fortran`
- `Nim`
- `Zig`
- `Haskell`
- `OCaml`
- `Julia`
- `Lua`
- `Swift`
- `Java`
- `Python`
- `SageLang`

## Compiler Detection

Current compiler labels:
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

Compiler inference is language-aware when language detection is decisive, and falls back to `Unknown` when evidence is weak or conflicting.

## Build-System Detection

Current host build-system labels:
- `CMake`
- `Meson`
- `Bazel`
- `Cargo`
- `Ninja`
- `Make`
- `Autotools`
- `MSBuild`
- `Gradle`
- `SCons`
- `XMake`
- `Buck2`
- `Go Toolchain`
- `Dart/Flutter`
- `Zig Build`
- `Pico SDK`
- `Ambiguous: ...`
- `Unknown`

## Project Layout

- `src/elfscan.py`: CLI entry point and formatted report output
- `src/detect/elfdetect.py`: compatibility entrypoint re-exporting detectors
- `src/detect/language/`: language detection orchestration
- `src/detect/compiler.py`: compiler detection orchestration
- `src/detect/buildsystem.py`: build-system detection orchestration
- `src/detect/arch/`: architecture-shape heuristics (ASM-focused today)
- `src/detect/techniques/`: section/symbol/string heuristic modules
- `src/symbols/elfsymbols.py`: symbol-level heuristic scoring
- `src/info/elfinfo.py`: ELF metadata display helpers
- `tests/test_elfscan_cli.py`: corpus integration tests
- `tests/test_elfdetect_heuristics.py`: focused unit tests for heuristic rules
- `test-bin/`: architecture folders with known hello-world ELF samples

## Requirements

- Python 3.12+
- `pyelftools`

Install dependency:

```bash
python3 -m pip install pyelftools
```

## CLI Usage

```bash
python3 src/elfscan.py [--version] [-m general|important|detailed] <elf_binary>
```

Examples:

```bash
python3 src/elfscan.py test-bin/x86_64/hello_rust
python3 src/elfscan.py -m detailed test-bin/aarch64/hello_go
python3 src/elfscan.py --version
```

## Versioning

- Canonical project version is tracked in the root [`VERSION`](VERSION) file.
- Current version: `0.2.1`
- The CLI reports this via:

```bash
python3 src/elfscan.py --version
```

When bumping versions, update all three together:
- [`VERSION`](VERSION)
- README badges/current version line
- [`ELFexplored_Guide.md`](ELFexplored_Guide.md) release notes section

## Styled Output

The CLI prints:
- A structured report header
- Heuristic score sections
- Language/compiler/build-system summary lines
- Selected ELF metadata block by mode

If stdout is a TTY and `NO_COLOR` is not set, styled ANSI output is enabled automatically.

## Testing

Run all tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'
```

Verbose corpus output levels in `tests/test_elfscan_cli.py`:
- no switch: level 1
- `-v`: level 1 (same as default)
- `-vv`: level 2
- `-vvv`: level 3
- `-vvvv`: level 4 (full per-binary captured output)
- `-q`: level 0 (quiet mode)

Example:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -vvv
```

## Rebuilding Corpus with hello-multilang

`build_hello.py` orchestrates the `hello-multilang` Docker workflow and then syncs produced ELF binaries into `test-bin/`.

Build all architectures and sync:

```bash
python3 build_hello.py --all
```

Build selected architectures and sync:

```bash
python3 build_hello.py --arch x86_64,rv64
```

Useful options:
- `--skip-image-build`: reuse existing Docker image
- `--skip-docker-run`: only sync existing `hello-multilang/output/`
- `--dry-run`: print actions without executing commands or changing files

## Corpus Expectations

Current corpus shape expected by tests:
- `aarch64`: `hello_asm`, `hello_c`, `hello_cpp`, `hello_dart`, `hello_go`
- `arm32`: `hello_asm`, `hello_c`, `hello_cpp`, `hello_dart`, `hello_go`
- `rv64`: `hello_asm`, `hello_c`, `hello_cpp`, `hello_dart`, `hello_go`
- `x86`: `hello_asm`, `hello_c`, `hello_cpp`, `hello_dart`, `hello_go`
- `x86_64`: `hello_asm`, `hello_c`, `hello_cpp`, `hello_dart`, `hello_go`, `hello_rust`

Future additions (Nim, Zig, SageLang, C#) should be added to both:
- `test-bin/<arch>/`
- `tests/test_elfscan_cli.py` expected corpus list

## Heuristic Scope

Detection is heuristic, not ground truth. It combines:
- section-name patterns
- symbol-name patterns
- dynamic dependency hints
- debug/comment string hints
- DWARF producer detection (for GCC/Clang inference)
- runtime API marker strings
- disassembly-inspired opcode pattern scanning in `.text` for stripped/minimal binaries
- binary-shape rules (for ASM)
- assembler-family marker detection (`NASM`, `FASM`, `MASM`, `TASM`) from producer/comment/string evidence

False-positive guardrails include:
- Go scoring now requires Go-specific symbol fingerprints (`go.*`, `go.itab.*`, `main.main`, `runtime.main`/`runtime.rt0_*`) and ignores generic file symbols like `runtime.c`.
- C scoring now incorporates volume of real `.c` file symbols (excluding Sage-generated `sagec_<n>.c`), which improves mixed firmware attribution where embedded runtimes coexist.
- C# weak `mono` substring checks were tightened to explicit runtime markers (`libmono`, `coreclr`, `hostfxr`, `hostpolicy`, `dotnet`).

See `ELFexplored_Guide.md` for full details.

## Research Sources

Recent heuristics were derived from official/toolchain documentation, including:
- Rust symbol mangling and compiler details: https://doc.rust-lang.org/rustc/symbol-mangling/index.html
- Go build ID note behavior in ELF (`.note.go.buildid`): https://pkg.go.dev/cmd/internal/buildid
- GHC runtime embedding (`hs_init` / `hs_exit`): https://downloads.haskell.org/ghc/latest/docs/users_guide/exts/ffi.html
- OCaml native/runtime entry points (`caml_startup`, `caml_main`): https://ocaml.org/manual/intfc.html
- Julia embedding API (`jl_init`, `jl_atexit_hook`): https://docs.julialang.org/en/v1/manual/embedding/
- Lua C API (`luaL_newstate`, `lua_pcall`): https://www.lua.org/manual/5.4/manual.html
- NASM reference (`Netwide Assembler`): https://www.nasm.us/doc/
- MASM reference (`Microsoft Macro Assembler`): https://learn.microsoft.com/en-us/cpp/assembler/masm/microsoft-macro-assembler-reference
- GNU objdump disassembly options: https://sourceware.org/binutils/docs/binutils/objdump.html
- Cargo output directory conventions (`target/debug`, `target/release`): https://doc.rust-lang.org/cargo/guide/build-cache.html
- CMake generated build tree conventions (`CMakeFiles`): https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html
- Bazel output paths (`bazel-out`): https://bazel.build/remote/output-directories
- Gradle project cache directory (`.gradle`): https://docs.gradle.org/current/userguide/directory_layout.html

## License

MIT License
