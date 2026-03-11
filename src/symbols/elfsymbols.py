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

SAGELANG_RUNTIME_PREFIXES = (
    "sage_mem_",
    "sage_struct_",
    "sage_bit_",
    "sage_range",
    "sage_input_",
    "sage_clock_",
    "sage_arch_",
)

SAGELANG_CLUSTER_SENTINELS = {
    "sage_try_stack",
    "sage_exception_value",
    "sage_method_table",
    "sage_class_registry",
    "sage_slot_undefined",
}


def _is_sage_generated_c_file_symbol(name):
    if not name.endswith(".c"):
        return False

    basename = name.rsplit("/", maxsplit=1)[-1]
    if not basename.startswith("sagec_"):
        return False

    sequence = basename[len("sagec_") : -2]
    return sequence.isdigit()


def _is_go_symbol_fingerprint(name):
    if name.startswith(("go.func.", "go.itab.", "go:", "go.")):
        return True

    if name.startswith("main.main"):
        return True

    if name.startswith("runtime."):
        if name.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".s", ".asm", ".o")):
            return False

        member = name.split(".", maxsplit=1)[1] if "." in name else ""
        if member == "main" or member.startswith("rt0_"):
            return True
        if member.startswith(("mstart", "morestack", "newproc", "newobject", "gcenable", "sched", "gc")):
            return True
        return False

    if name.startswith("type."):
        return name.startswith("type..")

    return False


def _is_c_source_file_symbol(name):
    if not name.endswith(".c"):
        return False
    return not _is_sage_generated_c_file_symbol(name)


def _is_cpp_source_file_symbol(name):
    return name.endswith((".cc", ".cpp", ".cxx", ".c++", ".cp"))


def scan_symbols(symbol_iter, scores, seen_names=None):
    """
    Scan symbols and update language scores based on naming heuristics.
    """
    sage_symbol_count = 0
    sage_runtime_family_count = 0
    sage_cluster_hits = set()
    go_symbol_fingerprint_count = 0
    c_source_file_count = 0
    cpp_source_file_count = 0

    for symbol in symbol_iter:
        name = symbol.name.lower()
        if not name:
            continue
        if seen_names is not None:
            if name in seen_names:
                continue
            seen_names.add(name)

        if "SageLang" in scores:
            if _is_sage_generated_c_file_symbol(name):
                scores["SageLang"] += 8
            if name.startswith("sage_"):
                sage_symbol_count += 1
            if name in SAGELANG_EXACT_SYMBOLS:
                scores["SageLang"] += 4
                sage_cluster_hits.add(name)
            if any(name.startswith(prefix) for prefix in SAGELANG_PREFIXES):
                scores["SageLang"] += 4
            if any(name.startswith(prefix) for prefix in SAGELANG_RUNTIME_PREFIXES):
                sage_runtime_family_count += 1
                scores["SageLang"] += 2
            if name in SAGELANG_CLUSTER_SENTINELS:
                sage_cluster_hits.add(name)

        if _is_c_source_file_symbol(name):
            c_source_file_count += 1
        if _is_cpp_source_file_symbol(name):
            cpp_source_file_count += 1

        if "rust_eh_personality" in name:
            scores["Rust"] += 5
        if "__rust_alloc" in name or "__rust_dealloc" in name or "__rust_realloc" in name:
            scores["Rust"] += 5
        if "core::" in name or "alloc::" in name or "panic_" in name or "rust_begin_unwind" in name:
            scores["Rust"] += 2
        if name.startswith("_zn") or name.startswith("__zn"):
            scores["Rust"] += 2

        if _is_go_symbol_fingerprint(name):
            go_symbol_fingerprint_count += 1

        if name.startswith("dart_"):
            scores["Dart"] += 3
        if name.startswith("dart") and ("isolate" in name or "snapshot" in name):
            scores["Dart"] += 2

        if name.startswith("__zig_") or name.startswith("zig_") or "ziglang" in name:
            scores["Zig"] += 3

        if "coreclr" in name or "mono_" in name or "hostfxr" in name or "dotnet" in name or "mscorlib" in name:
            scores["C#"] += 3

        if name.startswith("_z") and "rust" not in name and not name.startswith("_zn"):
            scores["C++"] += 2
        if "std::" in name or "__cxx" in name or "typeinfo" in name:
            scores["C++"] += 2
        if "vtable for" in name or "rtti" in name:
            scores["C++"] += 2
        if "__cxa" in name and "__cxa_finalize" not in name:
            scores["C++"] += 2
        if "glibcxx" in name:
            scores["C++"] += 2

        if "_dmain" in name or "_dmodule" in name:
            scores["D"] += 3
        if "ada__" in name:
            scores["Ada"] += 3
        if "_gfortran" in name:
            scores["Fortran"] += 3
        if "nimrtl" in name or "nim_gc" in name or "nimmain" in name or "niminit" in name:
            scores["Nim"] += 3
        if "swift" in name:
            scores["Swift"] += 3
        if "jni_" in name or "jvm" in name:
            scores["Java"] += 2
        if "pyinit" in name or "python" in name:
            scores["Python"] += 2
        if name.startswith("hs_") or name.startswith("stg_") or name.startswith("rts_") or "ghczm" in name:
            scores["Haskell"] += 3
        if name.startswith("caml_") or name.startswith("caml"):
            scores["OCaml"] += 3
        if name.startswith("jl_") or name.startswith("julia_"):
            scores["Julia"] += 3
        if name.startswith("lua_") or name.startswith("lual_") or "luajit" in name:
            scores["Lua"] += 3

        if "rust" in name:
            scores["Rust"] += 1
        if "rust" in name and (name.startswith("_z") or name.startswith("_zn")):
            scores["Rust"] += 2
        if name.startswith("alloc_") or name.startswith("core_") or name.startswith("std_"):
            scores["Rust"] += 1
        if "std::vector" in name or "std::string" in name or "std::map" in name:
            scores["C++"] += 2

    if go_symbol_fingerprint_count >= 6:
        scores["Go"] += 10
    elif go_symbol_fingerprint_count >= 3:
        scores["Go"] += 6
    elif go_symbol_fingerprint_count >= 1:
        scores["Go"] += 3

    if c_source_file_count >= 64:
        scores["C"] += 30
    elif c_source_file_count >= 24:
        scores["C"] += 18
    elif c_source_file_count >= 8:
        scores["C"] += 10
    elif c_source_file_count >= 3:
        scores["C"] += 5
    elif c_source_file_count >= 1:
        scores["C"] += 2

    if cpp_source_file_count >= 24:
        scores["C++"] += 20
    elif cpp_source_file_count >= 8:
        scores["C++"] += 12
    elif cpp_source_file_count >= 3:
        scores["C++"] += 6
    elif cpp_source_file_count >= 1:
        scores["C++"] += 3

    if "SageLang" in scores:
        if sage_symbol_count >= 20:
            scores["SageLang"] += 10
        elif sage_symbol_count >= 8:
            scores["SageLang"] += 6
        elif sage_symbol_count >= 4:
            scores["SageLang"] += 3

        if sage_runtime_family_count >= 6:
            scores["SageLang"] += 6
        elif sage_runtime_family_count >= 3:
            scores["SageLang"] += 3

        if len(sage_cluster_hits) >= 3:
            scores["SageLang"] += 6
