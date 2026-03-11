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

COMPILER_HEURISTICS = ("GCC", "Clang")

BUILD_SYSTEM_HEURISTICS = (
    "CMake",
    "Meson",
    "Bazel",
    "Cargo",
    "Ninja",
    "Make",
    "Autotools",
    "MSBuild",
    "Go Toolchain",
    "Dart/Flutter",
    "Zig Build",
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
    b"mono",
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
}
