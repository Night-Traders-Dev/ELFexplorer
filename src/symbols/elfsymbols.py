# Functions for scanning ELF symbol tables and updating language scores

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
        # Rust-specific symbols
        if "rust_eh_personality" in name:
            scores["Rust"] += 5
        if "__rust_alloc" in name or "__rust_dealloc" in name or "__rust_realloc" in name:
            scores["Rust"] += 5
        if "core::" in name or "alloc::" in name or "panic_" in name or "rust_begin_unwind" in name:
            scores["Rust"] += 2
        # Rust mangled names: _ZN... (Itanium ABI, used by Rust)
        if name.startswith('_zn') or name.startswith('__zn'):
            scores["Rust"] += 2
        # Go-specific symbols
        if name.startswith("go.func.") or name.startswith("runtime.") or name.startswith("type.") or name.startswith("go.itab."):
            scores["Go"] += 2
        # C++ mangled names and STL (stricter: only if not Rust)
        if name.startswith('_z') and "rust" not in name and not name.startswith('_zn'):
            scores["C++"] += 2
        if "std::" in name or "__cxx" in name or "typeinfo" in name:
            scores["C++"] += 2
        # C++ vtable, RTTI, exception
        if "vtable for" in name or "rtti" in name or "__cxa" in name:
            scores["C++"] += 2
        # D language
        if "_dmain" in name or "_dmodule" in name:
            scores["D"] += 3
        # Ada
        if "ada__" in name:
            scores["Ada"] += 3
        # Fortran
        if "_gfortran" in name:
            scores["Fortran"] += 3
        # Nim
        if "nimrtl" in name or "nim_gc" in name:
            scores["Nim"] += 3
        # Swift
        if "swift" in name:
            scores["Swift"] += 3
        # Java JNI
        if "jni_" in name or "jvm" in name:
            scores["Java"] += 2
        # Python embedded
        if "pyinit" in name or "python" in name:
            scores["Python"] += 2
        # Additional checks for Rust and C++
        if "rust" in name:
            scores["Rust"] += 1
        if "rust" in name and (name.startswith('_z') or name.startswith('_zn')):
            scores["Rust"] += 2  # Rust mangled names with rust substring
        # Check for common Rust crate prefixes
        if name.startswith('alloc_') or name.startswith('core_') or name.startswith('std_'):
            scores["Rust"] += 1
        # Check for common Go runtime symbols
        if name.startswith('runtime.') or name.startswith('main.main'):
            scores["Go"] += 1
        # Check for common C++ STL containers
        if "std::vector" in name or "std::string" in name or "std::map" in name:
            scores["C++"] += 2
