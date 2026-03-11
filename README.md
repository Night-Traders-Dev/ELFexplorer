# ELFexplorer

`ELFexplorer` is a modular ELF analysis and heuristic fingerprinting tool focused on language and compiler inference.

It currently provides:
- Structured ELF metadata reporting (general/important/detailed modes)
- Heuristic source-language detection
- Heuristic compiler detection (GCC vs Clang)
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
- `Swift`
- `Java`
- `Python`
- `SageLang`

## Compiler Detection

Current compiler labels:
- `GCC`
- `Clang`
- `Ambiguous: GCC/Clang`
- `Unknown`

## Project Layout

- `src/elfscan.py`: CLI entry point and formatted report output
- `src/detect/elfdetect.py`: language/compiler scoring engine
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
python3 src/elfscan.py [-m general|important|detailed] <elf_binary>
```

Examples:

```bash
python3 src/elfscan.py test-bin/x86_64/hello_rust
python3 src/elfscan.py -m detailed test-bin/aarch64/hello_go
```

## Styled Output

The CLI prints:
- A structured report header
- Heuristic score sections
- Language/compiler summary lines
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
- runtime API marker strings
- binary-shape rules (for ASM)

See `ELFexplored_Guide.md` for full details.

## License

MIT License
