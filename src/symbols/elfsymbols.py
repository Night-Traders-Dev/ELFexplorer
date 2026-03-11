# Functions for scanning ELF symbol tables and updating language scores

SAGELANG_EXACT_SYMBOLS = {
    "sage_try_stack",
    "sage_exception_value",
    "sage_method_table",
    "sage_class_registry",
    "sage_nil",
    "sage_number",
    "sage_bool",
    "sage_string",
    "sage_array",
    "sage_make_dict",
    "sage_make_tuple",
    "sage_truthy",
    "sage_print_value",
    "sage_load_slot",
    "sage_define_slot",
    "sage_assign_slot",
    "sage_register_class",
    "sage_register_method",
    "sage_call_method",
}

SAGELANG_PREFIXES = (
    "sage_fn_",
    "sage_global_",
    "sage_dict_",
    "sage_struct_",
    "sage_method_",
    "sage_class_",
)


def scan_symbols(symbol_iter, scores):
    """
    Scan symbols and update language scores based on naming heuristics.
    """
    for symbol in symbol_iter:
        name = symbol.name.lower()
        if not name:
            continue

        if "SageLang" in scores:
            if name.startswith("sagec_") and name.endswith(".c"):
                scores["SageLang"] += 8
            if name in SAGELANG_EXACT_SYMBOLS:
                scores["SageLang"] += 4
            if any(name.startswith(prefix) for prefix in SAGELANG_PREFIXES):
                scores["SageLang"] += 4

        if "rust_eh_personality" in name:
            scores["Rust"] += 5
        if "__rust_alloc" in name or "__rust_dealloc" in name or "__rust_realloc" in name:
            scores["Rust"] += 5
        if "core::" in name or "alloc::" in name or "panic_" in name or "rust_begin_unwind" in name:
            scores["Rust"] += 2
        if name.startswith("_zn") or name.startswith("__zn"):
            scores["Rust"] += 2

        if name.startswith("go.func.") or name.startswith("runtime.") or name.startswith("type.") or name.startswith("go.itab."):
            scores["Go"] += 2

        if name.startswith("_z") and "rust" not in name and not name.startswith("_zn"):
            scores["C++"] += 2
        if "std::" in name or "__cxx" in name or "typeinfo" in name:
            scores["C++"] += 2
        if "vtable for" in name or "rtti" in name or "__cxa" in name:
            scores["C++"] += 2

        if "_dmain" in name or "_dmodule" in name:
            scores["D"] += 3
        if "ada__" in name:
            scores["Ada"] += 3
        if "_gfortran" in name:
            scores["Fortran"] += 3
        if "nimrtl" in name or "nim_gc" in name:
            scores["Nim"] += 3
        if "swift" in name:
            scores["Swift"] += 3
        if "jni_" in name or "jvm" in name:
            scores["Java"] += 2
        if "pyinit" in name or "python" in name:
            scores["Python"] += 2

        if "rust" in name:
            scores["Rust"] += 1
        if "rust" in name and (name.startswith("_z") or name.startswith("_zn")):
            scores["Rust"] += 2
        if name.startswith("alloc_") or name.startswith("core_") or name.startswith("std_"):
            scores["Rust"] += 1
        if name.startswith("runtime.") or name.startswith("main.main"):
            scores["Go"] += 1
        if "std::vector" in name or "std::string" in name or "std::map" in name:
            scores["C++"] += 2
