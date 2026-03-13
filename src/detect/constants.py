import re

SUPPORTED_LANGUAGES = (
    "ASM",
    "C",
    "C++",
    "Objective-C",
    "C#",
    "Rust",
    "Go",
    "Dart",
    "Kotlin/Native",
    "Pascal",
    "Crystal",
    "D",
    "Ada",
    "Fortran",
    "Nim",
    "Zig",
    "Haskell",
    "OCaml",
    "Julia",
    "Lua",
    "Ruby",
    "Perl",
    "Tcl",
    "R",
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
    ".note.kotlin.native": "Kotlin/Native",
    ".note.crystal": "Crystal",
    ".note.objc": "Objective-C",
    ".note.ruby": "Ruby",
    ".note.perl": "Perl",
    ".note.tcl": "Tcl",
    ".note.r.language": "R",
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
    "Waf",
    "QMake",
    "Premake",
    "Cabal",
    "Stack",
    "Nix",
    "Arduino",
    "SCons",
    "XMake",
    "Buck2",
    "Go Toolchain",
    "Dart/Flutter",
    "Zig Build",
    "Pico SDK",
    "Buildroot",
    "Yocto/OpenEmbedded",
    "PlatformIO",
    "ESP-IDF",
    "Zephyr West",
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

KOTLIN_NATIVE_STRING_MARKERS = (
    b"kotlin/native",
    b"exportedsymbols",
    b"disposestablepointer",
    b"disposestring",
    b"kref_kotlin_",
    b"kotlin.root.",
    b"kotlin_initruntimeifneeded",
)

PASCAL_STRING_MARKERS = (
    b"freepascal",
    b"fpc_initializeunits",
    b"fpc_finalizeunits",
    b"fpc_do_exit",
    b"fpc_",
)

CRYSTAL_STRING_MARKERS = (
    b"crystal",
    b"__crystal_main",
    b"crystal_main",
    b"crystal_gc",
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

RUBY_STRING_MARKERS = (
    b"libruby",
    b"ruby_init",
    b"ruby_run_node",
    b"rb_funcall",
    b"rb_define_method",
)

PERL_STRING_MARKERS = (
    b"libperl",
    b"perl_alloc",
    b"perl_construct",
    b"perl_parse",
    b"perl_run",
)

TCL_STRING_MARKERS = (
    b"libtcl",
    b"tcl_main",
    b"tcl_createinterp",
    b"tcl_init",
    b"tcl_eval",
)

R_STRING_MARKERS = (
    b"libr.so",
    b"rf_initembeddedr",
    b"rf_endembeddedr",
    b"r_inside_r",
    b"rprintf",
)

OBJC_STRING_MARKERS = (
    b"libobjc",
    b"objc_msgsend",
    b"objc_msg_lookup",
    b"__objc_exec_class",
    b"gnustep",
)

COMPILER_HEURISTICS = (
    "GCC",
    "Clang",
    "Intel ICC/ICX",
    "TinyCC",
    "FreePascal",
    "DMD",
    "GNAT",
    "GFortran",
    "Rustc",
    "Go gc",
    "Zig",
    "LDC",
    "GDC",
    "YASM",
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
    b"-frecord-gcc-switches",
)

COMPILER_INTEL_STRING_MARKERS = (
    b"intel(r) oneapi dpc++/c++ compiler",
    b"intel c++ compiler",
    b" icx",
    b" icpx",
    b" icc",
)

COMPILER_TINYCC_STRING_MARKERS = (
    b"tiny c compiler",
    b"tinycc",
    b" tcc ",
)

COMPILER_FREEPASCAL_STRING_MARKERS = (
    b"free pascal compiler",
    b"freepascal",
    b"fpc ",
)

COMPILER_DMD_STRING_MARKERS = (
    b"digital mars d",
    b" dmd ",
    b"dmd v",
)

COMPILER_GNAT_STRING_MARKERS = (
    b"gnat ",
    b"gnu ada",
    b"gnatbind",
)

COMPILER_GFORTRAN_STRING_MARKERS = (
    b"gfortran",
    b"gnu fortran",
    b"libgfortran",
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

COMPILER_LDC_STRING_MARKERS = (
    b"ldc - the llvm-based d compiler",
    b"ldc2",
)

COMPILER_GDC_STRING_MARKERS = (
    b"gnu d compiler",
    b"gdc",
    b"libphobos",
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

COMPILER_YASM_STRING_MARKERS = (
    b"yasm",
    b"yasm version",
    b"yet another assembler",
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

COMPILER_INTEL_SYMBOL_MARKERS = (
    "__intel_cpu_features_init",
    "__intel_new_feature_proc_init",
    "__intel_sse2_strcpy",
)

COMPILER_TINYCC_SYMBOL_MARKERS = (
    "__bound_ptr_add",
    "__bound_ptr_indir1",
    "__bound_ptr_indir4",
)

COMPILER_FREEPASCAL_SYMBOL_MARKERS = (
    "fpc_",
    "__fpc_",
    "system_$$_",
)

COMPILER_DMD_SYMBOL_MARKERS = (
    "_dmain",
    "_dmodule_ref",
    "__dmd_",
)

COMPILER_GNAT_SYMBOL_MARKERS = (
    "ada__",
    "__gnat_",
    "system__",
)

COMPILER_GFORTRAN_SYMBOL_MARKERS = (
    "_gfortran",
    "__gfortran",
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

COMPILER_LDC_SYMBOL_MARKERS = (
    "ldc.register_dso",
    "__ldc_",
)

COMPILER_GDC_SYMBOL_MARKERS = (
    "_d_dso_registry",
    "__gdc_",
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

COMPILER_YASM_SYMBOL_MARKERS = (
    "__yasm",
    "yasm_",
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
    "Waf": (
        b"wscript",
        b"waflib",
        b"/.waf",
    ),
    "QMake": (
        b".qmake.stash",
        b"mkspecs/",
        b".pro.user",
    ),
    "Premake": (
        b"premake5.lua",
        b"premake4.lua",
        b"/.premake/",
    ),
    "Cabal": (
        b"dist-newstyle/",
        b"cabal.project",
        b".cabal",
    ),
    "Stack": (
        b"stack.yaml",
        b".stack-work/",
        b"stack snapshot",
    ),
    "Nix": (
        b"/nix/store/",
        b"flake.nix",
        b"default.nix",
    ),
    "Arduino": (
        b"arduino",
        b"sketch.ino",
        b"platform.txt",
        b"boards.txt",
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
    "Buildroot": (
        b"output/build/",
        b"output/host/",
        b"buildroot",
    ),
    "Yocto/OpenEmbedded": (
        b"tmp/work/",
        b"tmp/work-shared/",
        b"poky",
        b"openembedded",
    ),
    "PlatformIO": (
        b"platformio.ini",
        b"/.pio/",
        b"platformio",
        b"workspace_dir/build",
    ),
    "ESP-IDF": (
        b"idf.py",
        b"esp-idf",
        b"build/bootloader",
        b"esptool.py",
    ),
    "Zephyr West": (
        b"west build",
        b".west/",
        b"zephyr.elf",
        b"zephyrproject",
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
