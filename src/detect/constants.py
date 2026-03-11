import re

SUPPORTED_LANGUAGES = (
    "ASM",
    "C",
    "C++",
    "C#",
    "Rust",
    "Go",
    "Dart",
    "D",
    "Ada",
    "Fortran",
    "Nim",
    "Zig",
    "Haskell",
    "OCaml",
    "Julia",
    "Lua",
    "Swift",
    "Java",
    "Python",
    "SageLang",
)

NOTE_SECTIONS = {
    ".note.go.buildid": "Go",
    ".note.rustc": "Rust",
    ".note.dmd": "D",
    ".note.nim": "Nim",
    ".note.swift": "Swift",
    ".note.java": "Java",
    ".note.python": "Python",
    ".note.sagelang": "SageLang",
}

BUILD_SYSTEM_HEURISTICS = (
    "CMake",
    "Meson",
    "Bazel",
    "Cargo",
    "Ninja",
    "Make",
    "Autotools",
    "MSBuild",
    "Gradle",
    "SCons",
    "XMake",
    "Buck2",
    "Go Toolchain",
    "Dart/Flutter",
    "Zig Build",
    "Pico SDK",
)

ARTIFACT_HEURISTICS = (
    "Bare-metal Firmware",
    "Static User-space Executable",
    "Linux User-space Executable",
    "Linux Shared Library",
    "Linux Kernel Module",
    "Relocatable Object",
)

LANGUAGE_STRING_SCAN_SECTIONS = (
    ".rodata",
    ".strtab",
    ".dynstr",
    ".debug_str",
    ".comment",
)

COMPILER_STRING_SCAN_SECTIONS = (
    ".comment",
    ".debug_info",
    ".debug_str",
    ".strtab",
    ".dynstr",
    ".GCC.command.line",
)

BUILD_SYSTEM_STRING_SCAN_SECTIONS = (
    ".comment",
    ".debug_info",
    ".debug_str",
    ".rodata",
    ".strtab",
    ".dynstr",
)

ARTIFACT_STRING_SCAN_SECTIONS = (
    ".comment",
    ".debug_str",
    ".rodata",
    ".strtab",
    ".dynstr",
)

SAGELANG_RUNTIME_STRINGS = (
    b"unhandled exception:",
    b"runtime error: undefined variable",
    b"runtime error: method call on non-instance.",
    b"runtime error: no __class__ on instance.",
    b"too many classes",
)

SAGELANG_STRONG_STRING_MARKERS = (
    b"sage_try_stack",
    b"sage_exception_value",
    b"sage_method_table",
    b"sage_class_registry",
    b"sage_slot_undefined",
)

SAGELANG_TOKEN_PATTERN = re.compile(rb"(?<![a-z0-9_])sage_[a-z0-9_]+")
SAGELANG_GENERATED_C_PATTERN = re.compile(rb"(?<![a-z0-9_])sagec_[0-9]+\.c(?![a-z0-9_])")
DART_TOKEN_PATTERN = re.compile(rb"(?<![a-z0-9_])dart_[a-z0-9_]+")
ZIG_TOKEN_PATTERN = re.compile(rb"(?<![a-z0-9_])(?:__)?zig_[a-z0-9_]+")

DART_STRONG_MARKERS = (
    b"dart_initialize",
    b"dart_createisolategroup",
    b"dart_loadscriptfromkernel",
    b"dart_createappaotsnapshotasassembly",
    b"dart_versionstring",
)

CSHARP_STRING_MARKERS = (
    b"system.private.corelib",
    b"microsoft.netcore.app",
    b"coreclr",
    b"hostfxr",
    b"hostpolicy",
    b"dotnet",
    b"mscorlib",
)

NIM_STRING_MARKERS = (
    b"nimmain",
    b"nimmaininner",
    b"nimrtl",
    b"nim_gc",
    b"nimcache",
)

ZIG_STRING_MARKERS = (
    b"ziglang",
    b"__zig_",
    b"zig_stack",
)

HASKELL_STRING_MARKERS = (
    b"libhsrts",
    b"ghczmprim",
    b"ghc",
    b"hs_init",
    b"stg_",
)

OCAML_STRING_MARKERS = (
    b"caml_startup",
    b"caml_main",
    b"libasmrun",
    b"ocamlrun",
    b"ocamlopt",
)

JULIA_STRING_MARKERS = (
    b"libjulia",
    b"jl_init",
    b"jl_atexit_hook",
    b"julia_main",
)

LUA_STRING_MARKERS = (
    b"lua_pcall",
    b"lual_newstate",
    b"lua_tolstring",
    b"luajit",
)

COMPILER_HEURISTICS = (
    "GCC",
    "Clang",
    "Rustc",
    "Go gc",
    "Zig",
    "NASM",
    "FASM",
    "MASM",
    "TASM",
    "GHC",
    "OCamlopt",
)

COMPILER_CLANG_STRING_MARKERS = (
    b"clang version",
    b"apple clang",
    b"clang-",
    b"clang++",
    b"libclang_rt",
    b"compiler-rt",
)

COMPILER_GCC_STRING_MARKERS = (
    b"gcc: (gnu)",
    b"gcc version",
    b"gnu c",
    b"gnu c++",
    b"collect2",
    b" cc1",
)

COMPILER_RUSTC_STRING_MARKERS = (
    b"rustc version",
    b"rustc ",
    b"rust_begin_unwind",
)

COMPILER_GO_STRING_MARKERS = (
    b"go build id",
    b"cmd/go",
    b"golang.org/",
)

COMPILER_ZIG_STRING_MARKERS = (
    b"ziglang",
    b"zig ",
    b"__zig_",
)

COMPILER_GHC_STRING_MARKERS = (
    b"the glorious glasgow haskell compilation system",
    b"ghc-",
    b"libhsrts",
)

COMPILER_OCAMLOPT_STRING_MARKERS = (
    b"ocamlopt",
    b"libasmrun",
    b"caml_startup",
)

COMPILER_NASM_STRING_MARKERS = (
    b"netwide assembler",
    b"nasm",
)

COMPILER_FASM_STRING_MARKERS = (
    b"flat assembler",
    b"fasm",
)

COMPILER_MASM_STRING_MARKERS = (
    b"microsoft macro assembler",
    b"masm",
    b"ml.exe",
)

COMPILER_TASM_STRING_MARKERS = (
    b"turbo assembler",
    b"tasm",
    b"tasm32",
)

COMPILER_CLANG_SYMBOL_MARKERS = (
    "__clang_call_terminate",
    "___clang_call_terminate",
    "__llvm_profile_runtime",
    "___llvm_profile_runtime",
    "__sanitizer_cov_trace_pc_guard",
)

COMPILER_GCC_SYMBOL_MARKERS = (
    "__gcov_init",
    "__gcov_exit",
    "__gcov_merge_add",
    "__gcov_merge_single",
)

COMPILER_RUSTC_SYMBOL_MARKERS = (
    "rust_eh_personality",
    "__rust_alloc",
    "__rust_dealloc",
    "rust_begin_unwind",
)

COMPILER_GO_SYMBOL_MARKERS = (
    "runtime.main",
    "runtime.rt0_go",
    "go.itab.",
)

COMPILER_ZIG_SYMBOL_MARKERS = (
    "__zig_probe_stack",
    "__zig_return_error",
    "zig_panic",
)

COMPILER_GHC_SYMBOL_MARKERS = (
    "hs_init",
    "stg_ap_",
    "rts_",
)

COMPILER_OCAMLOPT_SYMBOL_MARKERS = (
    "caml_startup",
    "caml_main",
    "caml_alloc",
)

COMPILER_NASM_SYMBOL_MARKERS = (
    "__nasm",
    "nasm_",
)

COMPILER_FASM_SYMBOL_MARKERS = (
    "__fasm",
    "fasm_",
)

COMPILER_MASM_SYMBOL_MARKERS = (
    "__masm",
    "masm_",
)

COMPILER_TASM_SYMBOL_MARKERS = (
    "__tasm",
    "tasm_",
)

BUILD_SYSTEM_MARKERS = {
    "CMake": (
        b"/cmakefiles/",
        b"cmakelists.txt",
        b"cmakecache.txt",
    ),
    "Meson": (
        b"/meson-private/",
        b"meson.build",
        b"meson-info",
    ),
    "Bazel": (
        b"bazel-out/",
        b"bazel-bin/",
        b"@bazel_tools",
    ),
    "Cargo": (
        b"/target/debug/",
        b"/target/release/",
        b"/cargo/registry",
    ),
    "Ninja": (
        b"build.ninja",
        b".ninja_log",
        b".ninja_deps",
    ),
    "Make": (
        b"/makefile",
        b"makefile.in",
        b"gnumakefile",
    ),
    "Autotools": (
        b"configure.ac",
        b"autom4te.cache",
        b"libtool",
    ),
    "MSBuild": (
        b".csproj",
        b"microsoft.net.sdk",
        b"/obj/debug/",
    ),
    "Gradle": (
        b"/.gradle/",
        b"build.gradle",
        b"gradle/wrapper",
    ),
    "SCons": (
        b"sconstruct",
        b"sconsign",
        b"/.sconsign",
    ),
    "XMake": (
        b"xmake.lua",
        b"/.xmake/",
        b"xmake-repo",
    ),
    "Buck2": (
        b"buck-out/",
        b"buck2",
        b"buckconfig",
    ),
    "Go Toolchain": (
        b"go build id",
        b"cmd/go",
    ),
    "Dart/Flutter": (
        b"pubspec.yaml",
        b".dart_tool/",
        b"flutter_tools",
    ),
    "Zig Build": (
        b"build.zig",
        b".zig-cache/",
    ),
    "Pico SDK": (
        b"/pico-sdk/",
        b"pico_platform",
        b"hardware_regs/include/hardware/regs",
    ),
}

ARTIFACT_SECTION_MARKERS = {
    "firmware": (
        ".boot2",
        ".binary_info",
        ".ram_vector_table",
        ".vector_table",
        ".isr_vector",
        ".scratch_x",
        ".scratch_y",
    ),
    "kernel_module": (
        ".modinfo",
        ".gnu.linkonce.this_module",
    ),
}

ARTIFACT_EMBEDDED_MACHINES = {
    "EM_ARM",
    "EM_AARCH64",
    "EM_RISCV",
    "EM_MIPS",
    "EM_MICROBLAZE",
    "EM_AVR",
}

ARTIFACT_PICO_STRING_MARKERS = (
    b"/pico-sdk/",
    b"pico_platform",
    b"hardware_regs/include/hardware/regs",
    b"hardware_structs/include/hardware/structs",
    b"pico_stdio",
)

ARTIFACT_PICO_SYMBOL_MARKERS = (
    "multicore_launch_core1",
    "multicore_reset_core1",
    "hardware_alarm_",
    "pico_get_unique_board_id",
    "reset_usb_boot",
    "pio_sm_",
)

ARTIFACT_CMSIS_MARKERS = (
    b"cmsis",
    b"systeminit",
    b"__isr_vector",
    b"hardfault_handler",
    b"pendsv_handler",
    b"systick_handler",
)

ARTIFACT_FREERTOS_MARKERS = (
    b"freertos",
    b"xtaskcreate",
    b"vtaskstartscheduler",
    b"xqueue",
    b"xsemaphore",
    b"pvportmalloc",
)

ARTIFACT_ZEPHYR_MARKERS = (
    b"zephyr",
    b"k_thread_create",
    b"z_impl_",
    b"z_kernel",
    b"k_sem_take",
)

ARTIFACT_RTTHREAD_MARKERS = (
    b"rt-thread",
    b"rt_thread_create",
    b"rt_kprintf",
    b"rt_device_",
)

ARTIFACT_NEWLIB_MARKERS = (
    b"newlib",
    b"newlib_interface",
    b"_sbrk_r",
    b"_write_r",
    b"_read_r",
    b"_fstat_r",
    b"_isatty_r",
    b"_close_r",
    b"_exit",
)

ARTIFACT_GLIBC_MARKERS = (
    b"glibc",
    b"gnu c library",
    b"__libc_start_main",
)

ARTIFACT_KERNEL_MODULE_SYMBOL_MARKERS = (
    "__this_module",
    "module_layout",
    "init_module",
    "cleanup_module",
)
