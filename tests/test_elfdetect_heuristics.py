import io
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from detect.elfdetect import detect_build_system, detect_compiler, detect_source_language


class FakeSymbol:
    def __init__(self, name):
        self.name = name


class FakeSection:
    def __init__(self, name, data=b"", symbols=None, tags=None):
        self.name = name
        self._data = data
        self._symbols = list(symbols or [])
        self._tags = list(tags or [])

    def data(self):
        return self._data

    def iter_symbols(self):
        return iter(self._symbols)

    def num_symbols(self):
        return len(self._symbols)

    def iter_tags(self):
        return iter(self._tags)


class FakeTagEntry:
    def __init__(self, d_tag):
        self.d_tag = d_tag


class FakeTag:
    def __init__(self, needed):
        self.entry = FakeTagEntry("DT_NEEDED")
        self.needed = needed


class FakeELF:
    def __init__(self, sections, dwarf_info=None, machine="EM_X86_64"):
        self._sections = list(sections)
        self._by_name = {section.name: section for section in self._sections}
        self._dwarf_info = dwarf_info
        self.header = {"e_machine": machine}

    def get_section_by_name(self, name):
        return self._by_name.get(name)

    def iter_sections(self):
        return iter(self._sections)

    def has_dwarf_info(self):
        return self._dwarf_info is not None

    def get_dwarf_info(self):
        return self._dwarf_info


class FakeDwarfAttribute:
    def __init__(self, value):
        self.value = value


class FakeTopDIE:
    def __init__(self, producer):
        self.attributes = {"DW_AT_producer": FakeDwarfAttribute(producer)}


class FakeCU:
    def __init__(self, producer):
        self._producer = producer

    def get_top_DIE(self):
        return FakeTopDIE(self._producer)


class FakeDwarfInfo:
    def __init__(self, producers):
        self._producers = list(producers)

    def iter_CUs(self):
        return iter(FakeCU(producer) for producer in self._producers)


class HeuristicDetectionTests(unittest.TestCase):
    @staticmethod
    def detect_language(elf):
        with io.StringIO() as capture, mock.patch("sys.stdout", capture):
            return detect_source_language(elf)

    @staticmethod
    def detect_compiler_name(elf, source_language=None):
        with io.StringIO() as capture, mock.patch("sys.stdout", capture):
            return detect_compiler(elf, source_language=source_language)

    @staticmethod
    def detect_build_system_name(elf):
        with io.StringIO() as capture, mock.patch("sys.stdout", capture):
            return detect_build_system(elf)

    def test_detects_asm_from_minimal_startup_shape(self):
        elf = FakeELF(
            [
                FakeSection(".note.gnu.build-id"),
                FakeSection(".text"),
                FakeSection(".rodata"),
                FakeSection(".symtab", symbols=[FakeSymbol("_start"), FakeSymbol("__bss_start")]),
                FakeSection(".strtab"),
            ]
        )
        self.assertEqual(self.detect_language(elf), "ASM")

    def test_detects_dart_from_api_symbols(self):
        elf = FakeELF(
            [
                FakeSection(
                    ".dynsym",
                    symbols=[
                        FakeSymbol("Dart_Initialize"),
                        FakeSymbol("Dart_CreateIsolateGroup"),
                        FakeSymbol("Dart_LoadScriptFromKernel"),
                        FakeSymbol("Dart_VersionString"),
                    ],
                )
            ]
        )
        self.assertEqual(self.detect_language(elf), "Dart")

    def test_detects_csharp_from_runtime_libraries(self):
        elf = FakeELF(
            [
                FakeSection(
                    ".dynamic",
                    tags=[
                        FakeTag("libcoreclr.so"),
                        FakeTag("libhostfxr.so"),
                        FakeTag("libhostpolicy.so"),
                    ],
                )
            ]
        )
        self.assertEqual(self.detect_language(elf), "C#")

    def test_detects_zig_from_comment_marker(self):
        elf = FakeELF(
            [
                FakeSection(".comment", data=b"zig 0.13.0"),
                FakeSection(".symtab", symbols=[FakeSymbol("_start"), FakeSymbol("main"), FakeSymbol("__zig_probe_stack")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "Zig")

    def test_detects_nim_from_nimmain_symbols(self):
        elf = FakeELF(
            [
                FakeSection(".symtab", symbols=[FakeSymbol("NimMain"), FakeSymbol("nimInit")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "Nim")

    def test_detects_haskell_from_rts_symbols(self):
        elf = FakeELF(
            [
                FakeSection(".symtab", symbols=[FakeSymbol("hs_init"), FakeSymbol("stg_ap_p_fast")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "Haskell")

    def test_detects_ocaml_from_runtime_library(self):
        elf = FakeELF(
            [
                FakeSection(".dynamic", tags=[FakeTag("libasmrun.so")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "OCaml")

    def test_detects_julia_from_embedding_symbols(self):
        elf = FakeELF(
            [
                FakeSection(".dynsym", symbols=[FakeSymbol("jl_init"), FakeSymbol("jl_atexit_hook")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "Julia")

    def test_detects_lua_from_api_symbols(self):
        elf = FakeELF(
            [
                FakeSection(".dynsym", symbols=[FakeSymbol("luaL_newstate"), FakeSymbol("lua_pcallk")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "Lua")

    def test_detects_gcc_compiler_from_comment(self):
        elf = FakeELF([FakeSection(".comment", data=b"GCC: (GNU) 13.2.0")])
        self.assertEqual(self.detect_compiler_name(elf), "GCC")

    def test_detects_clang_compiler_from_comment(self):
        elf = FakeELF([FakeSection(".comment", data=b"clang version 18.1.0")])
        self.assertEqual(self.detect_compiler_name(elf), "Clang")

    def test_detects_clang_compiler_from_symbol(self):
        elf = FakeELF([FakeSection(".symtab", symbols=[FakeSymbol("__clang_call_terminate")])])
        self.assertEqual(self.detect_compiler_name(elf), "Clang")

    def test_detects_clang_compiler_from_dwarf_producer(self):
        elf = FakeELF([], dwarf_info=FakeDwarfInfo([b"clang version 18.1.2"]))
        self.assertEqual(self.detect_compiler_name(elf), "Clang")

    def test_detects_gcc_compiler_from_gcov_symbol(self):
        elf = FakeELF([FakeSection(".symtab", symbols=[FakeSymbol("__gcov_init")])])
        self.assertEqual(self.detect_compiler_name(elf), "GCC")

    def test_detects_rustc_compiler_from_symbols_when_language_is_rust(self):
        elf = FakeELF([FakeSection(".symtab", symbols=[FakeSymbol("rust_eh_personality"), FakeSymbol("__rust_alloc")])])
        self.assertEqual(self.detect_compiler_name(elf, source_language="Rust"), "Rustc")

    def test_detects_go_gc_compiler_from_note(self):
        elf = FakeELF([FakeSection(".note.go.buildid")])
        self.assertEqual(self.detect_compiler_name(elf, source_language="Go"), "Go gc")

    def test_detects_nasm_compiler_from_comment(self):
        elf = FakeELF([FakeSection(".comment", data=b"Netwide Assembler 2.16")])
        self.assertEqual(self.detect_compiler_name(elf, source_language="ASM"), "NASM")

    def test_detects_fasm_compiler_from_comment(self):
        elf = FakeELF([FakeSection(".comment", data=b"flat assembler version 1.73")])
        self.assertEqual(self.detect_compiler_name(elf, source_language="ASM"), "FASM")

    def test_detects_masm_compiler_from_dwarf_producer(self):
        elf = FakeELF([], dwarf_info=FakeDwarfInfo([b"Microsoft Macro Assembler Version 14.0"]))
        self.assertEqual(self.detect_compiler_name(elf, source_language="ASM"), "MASM")

    def test_detects_tasm_compiler_from_comment(self):
        elf = FakeELF([FakeSection(".comment", data=b"Turbo Assembler 5.0")])
        self.assertEqual(self.detect_compiler_name(elf, source_language="ASM"), "TASM")

    def test_detects_ghc_compiler_from_runtime_library(self):
        elf = FakeELF([FakeSection(".dynamic", tags=[FakeTag("libHSrts-ghc9.6.5.so")])])
        self.assertEqual(self.detect_compiler_name(elf, source_language="Haskell"), "GHC")

    def test_detects_ocamlopt_compiler_from_symbols(self):
        elf = FakeELF([FakeSection(".symtab", symbols=[FakeSymbol("caml_startup"), FakeSymbol("caml_alloc1")])])
        self.assertEqual(self.detect_compiler_name(elf, source_language="OCaml"), "OCamlopt")

    def test_detects_build_system_cmake_from_debug_path(self):
        elf = FakeELF([FakeSection(".debug_str", data=b"/tmp/build/CMakeFiles/main.c.o")])
        self.assertEqual(self.detect_build_system_name(elf), "CMake")

    def test_detects_build_system_go_toolchain_from_note(self):
        elf = FakeELF([FakeSection(".note.go.buildid")])
        self.assertEqual(self.detect_build_system_name(elf), "Go Toolchain")

    def test_detects_build_system_gradle_from_debug_path(self):
        elf = FakeELF([FakeSection(".debug_str", data=b"/workspace/.gradle/caches/modules/main.o")])
        self.assertEqual(self.detect_build_system_name(elf), "Gradle")

    def test_disassembly_pattern_boosts_asm_on_x86_64(self):
        elf = FakeELF(
            [
                FakeSection(".text", data=b"\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05"),
            ],
            machine="EM_X86_64",
        )
        self.assertEqual(self.detect_language(elf), "ASM")


if __name__ == "__main__":
    unittest.main()
