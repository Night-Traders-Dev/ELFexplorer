import io
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from detect.elfdetect import (
    detect_artifact_profile,
    detect_build_system,
    detect_compiler,
    detect_source_language,
)


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


class FakeSegmentHeader:
    def __init__(self, p_type, p_vaddr=0, p_paddr=0, p_offset=0, p_filesz=0, p_memsz=0, p_flags=0):
        self.p_type = p_type
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_offset = p_offset
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_flags = p_flags

    def __getitem__(self, key):
        return getattr(self, key)


class FakeSegment:
    def __init__(self, p_type, data=b"", p_vaddr=0, p_paddr=0, p_offset=0, p_filesz=None, p_memsz=None, p_flags=0):
        if p_filesz is None:
            p_filesz = len(data)
        if p_memsz is None:
            p_memsz = len(data)
        self._data = data
        self.header = FakeSegmentHeader(
            p_type=p_type,
            p_vaddr=p_vaddr,
            p_paddr=p_paddr,
            p_offset=p_offset,
            p_filesz=p_filesz,
            p_memsz=p_memsz,
            p_flags=p_flags,
        )

    def data(self):
        return self._data


class FakeELF:
    def __init__(self, sections, dwarf_info=None, machine="EM_X86_64", etype="ET_EXEC", entry=0, segments=None):
        self._sections = list(sections)
        self._by_name = {section.name: section for section in self._sections}
        self._dwarf_info = dwarf_info
        self._segments = list(segments or [])
        self.header = {"e_machine": machine, "e_type": etype, "e_entry": entry}

    def get_section_by_name(self, name):
        return self._by_name.get(name)

    def iter_sections(self):
        return iter(self._sections)

    def iter_segments(self):
        return iter(self._segments)

    def has_dwarf_info(self):
        return self._dwarf_info is not None

    def get_dwarf_info(self):
        return self._dwarf_info


class FakeDwarfAttribute:
    def __init__(self, value):
        self.value = value


class FakeTopDIE:
    def __init__(self, producer=None, attributes=None):
        attrs = dict(attributes or {})
        if producer is not None:
            attrs["DW_AT_producer"] = producer
        self.attributes = {
            key: value if isinstance(value, FakeDwarfAttribute) else FakeDwarfAttribute(value)
            for key, value in attrs.items()
        }


class FakeCU:
    def __init__(self, producer=None, attributes=None):
        self._producer = producer
        self._attributes = dict(attributes or {})

    def get_top_DIE(self):
        return FakeTopDIE(producer=self._producer, attributes=self._attributes)


class FakeDwarfInfo:
    def __init__(self, producers=None, cus=None):
        self._producers = list(producers or [])
        self._cus = list(cus or [])

    def iter_CUs(self):
        cu_list = [FakeCU(producer=producer) for producer in self._producers]
        for attrs in self._cus:
            cu_list.append(FakeCU(attributes=attrs))
        return iter(cu_list)


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

    @staticmethod
    def detect_artifact(elf):
        with io.StringIO() as capture, mock.patch("sys.stdout", capture):
            return detect_artifact_profile(elf, emit_report=False)

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

    def test_detects_kotlin_native_from_runtime_symbols(self):
        elf = FakeELF(
            [
                FakeSection(
                    ".dynsym",
                    symbols=[
                        FakeSymbol("libnative_ExportedSymbols"),
                        FakeSymbol("DisposeStablePointer"),
                        FakeSymbol("kotlin_root_foo"),
                    ],
                )
            ]
        )
        self.assertEqual(self.detect_language(elf), "Kotlin/Native")

    def test_detects_pascal_from_dwarf_language_code(self):
        elf = FakeELF([], dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_language": 0x0009}]))
        self.assertEqual(self.detect_language(elf), "Pascal")

    def test_detects_crystal_from_dwarf_language_code(self):
        elf = FakeELF([], dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_language": 0x0028}]))
        self.assertEqual(self.detect_language(elf), "Crystal")

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

    def test_detects_ruby_from_runtime_library(self):
        elf = FakeELF([FakeSection(".dynamic", tags=[FakeTag("libruby.so.3.3")])])
        self.assertEqual(self.detect_language(elf), "Ruby")

    def test_detects_perl_from_runtime_symbols(self):
        elf = FakeELF(
            [
                FakeSection(".dynsym", symbols=[FakeSymbol("perl_alloc"), FakeSymbol("perl_parse")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "Perl")

    def test_detects_tcl_from_runtime_symbols(self):
        elf = FakeELF(
            [
                FakeSection(".dynsym", symbols=[FakeSymbol("Tcl_Main"), FakeSymbol("Tcl_CreateInterp")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "Tcl")

    def test_detects_r_from_embedding_symbols(self):
        elf = FakeELF(
            [
                FakeSection(".dynsym", symbols=[FakeSymbol("Rf_initEmbeddedR"), FakeSymbol("Rprintf")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "R")

    def test_detects_objective_c_from_runtime_symbols(self):
        elf = FakeELF(
            [
                FakeSection(".dynamic", tags=[FakeTag("libobjc.so.4")]),
                FakeSection(".dynsym", symbols=[FakeSymbol("objc_msgSend"), FakeSymbol("__objc_exec_class")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "Objective-C")

    def test_detects_gcc_compiler_from_comment(self):
        elf = FakeELF([FakeSection(".comment", data=b"GCC: (GNU) 13.2.0")])
        self.assertEqual(self.detect_compiler_name(elf), "GCC")

    def test_detects_clang_compiler_from_comment(self):
        elf = FakeELF([FakeSection(".comment", data=b"clang version 18.1.0")])
        self.assertEqual(self.detect_compiler_name(elf), "Clang")

    def test_detects_clang_compiler_from_symbol(self):
        elf = FakeELF([FakeSection(".symtab", symbols=[FakeSymbol("__clang_call_terminate")])])
        self.assertEqual(self.detect_compiler_name(elf), "Clang")

    def test_detects_tinycc_compiler_from_comment(self):
        elf = FakeELF([FakeSection(".comment", data=b"Tiny C Compiler 0.9.27")])
        self.assertEqual(self.detect_compiler_name(elf, source_language="C"), "TinyCC")

    def test_detects_freepascal_compiler_from_comment(self):
        elf = FakeELF([FakeSection(".comment", data=b"Free Pascal Compiler version 3.2.2")])
        self.assertEqual(self.detect_compiler_name(elf, source_language="Pascal"), "FreePascal")

    def test_detects_dmd_compiler_from_dwarf_producer(self):
        elf = FakeELF([], dwarf_info=FakeDwarfInfo(producers=[b"Digital Mars D 2.109.1"]))
        self.assertEqual(self.detect_compiler_name(elf, source_language="D"), "DMD")

    def test_detects_gnat_compiler_from_dwarf_producer(self):
        elf = FakeELF([], dwarf_info=FakeDwarfInfo(producers=[b"GNAT 13.2.1"]))
        self.assertEqual(self.detect_compiler_name(elf, source_language="Ada"), "GNAT")

    def test_detects_gfortran_compiler_from_runtime_library(self):
        elf = FakeELF([FakeSection(".dynamic", tags=[FakeTag("libgfortran.so.5")])])
        self.assertEqual(self.detect_compiler_name(elf, source_language="Fortran"), "GFortran")

    def test_detects_yasm_compiler_from_comment(self):
        elf = FakeELF([FakeSection(".comment", data=b"yasm version 1.3.0")])
        self.assertEqual(self.detect_compiler_name(elf, source_language="ASM"), "YASM")

    def test_detects_intel_compiler_from_dwarf_producer(self):
        elf = FakeELF([], dwarf_info=FakeDwarfInfo(producers=[b"Intel(R) oneAPI DPC++/C++ Compiler"]))
        self.assertEqual(self.detect_compiler_name(elf, source_language="C++"), "Intel ICC/ICX")

    def test_detects_ldc_compiler_from_dwarf_producer(self):
        elf = FakeELF([], dwarf_info=FakeDwarfInfo(producers=[b"LDC - the LLVM-based D compiler"]))
        self.assertEqual(self.detect_compiler_name(elf, source_language="D"), "LDC")

    def test_detects_gdc_compiler_from_dwarf_producer(self):
        elf = FakeELF([], dwarf_info=FakeDwarfInfo(producers=[b"GNU D Compiler (GDC) 14.1"]))
        self.assertEqual(self.detect_compiler_name(elf, source_language="D"), "GDC")

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

    def test_detects_build_system_buildroot_from_dwarf_path(self):
        elf = FakeELF(
            [],
            dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_comp_dir": "/home/buildroot/output/build/app-1.0"}]),
        )
        self.assertEqual(self.detect_build_system_name(elf), "Buildroot")

    def test_detects_build_system_yocto_from_dwarf_path(self):
        elf = FakeELF(
            [],
            dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_comp_dir": "/work/poky/build/tmp/work/cortexa7/app"}]),
        )
        self.assertEqual(self.detect_build_system_name(elf), "Yocto/OpenEmbedded")

    def test_detects_build_system_platformio_from_dwarf_path(self):
        elf = FakeELF(
            [],
            dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_comp_dir": "/workspace/.pio/build/esp32dev"}]),
        )
        self.assertEqual(self.detect_build_system_name(elf), "PlatformIO")

    def test_detects_build_system_esp_idf_from_dwarf_path(self):
        elf = FakeELF(
            [],
            dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_comp_dir": "/opt/esp-idf/components/esp_system"}]),
        )
        self.assertEqual(self.detect_build_system_name(elf), "ESP-IDF")

    def test_detects_build_system_zephyr_west_from_dwarf_path(self):
        elf = FakeELF(
            [],
            dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_comp_dir": "/work/.west/zephyrproject/zephyr/build"}]),
        )
        self.assertEqual(self.detect_build_system_name(elf), "Zephyr West")

    def test_runtime_c_file_symbol_does_not_trigger_go(self):
        elf = FakeELF(
            [
                FakeSection(
                    ".symtab",
                    symbols=[
                        FakeSymbol("runtime.c"),
                        FakeSymbol("main.c"),
                        FakeSymbol("platform.c"),
                        FakeSymbol("driver.c"),
                    ],
                )
            ]
        )
        self.assertEqual(self.detect_language(elf), "C")
        self.assertEqual(self.detect_build_system_name(elf), "Unknown")

    def test_many_c_file_symbols_outweigh_embedded_sagelang_symbols(self):
        c_file_symbols = [FakeSymbol(f"/firmware/src/module_{index}.c") for index in range(90)]
        sage_symbols = [
            FakeSymbol("sage_gpio_set_pull"),
            FakeSymbol("sage_gpio_toggle"),
            FakeSymbol("sage_gpio_read"),
            FakeSymbol("sage_gpio_write"),
            FakeSymbol("sage_gpio_init"),
            FakeSymbol("sage_sys_print"),
            FakeSymbol("sage_sys_version"),
            FakeSymbol("sage_sys_temp"),
            FakeSymbol("sage_sys_info"),
            FakeSymbol("sage_sys_clock"),
            FakeSymbol("sage_sys_free_ram"),
            FakeSymbol("sage_sys_uptime"),
        ]
        elf = FakeELF([FakeSection(".symtab", symbols=c_file_symbols + sage_symbols)])
        self.assertEqual(self.detect_language(elf), "C")

    def test_comment_with_mono_substring_does_not_trigger_csharp(self):
        elf = FakeELF(
            [
                FakeSection(".comment", data=b"monolithic monitor firmware build"),
                FakeSection(".symtab", symbols=[FakeSymbol("main.c"), FakeSymbol("board.c"), FakeSymbol("uart.c")]),
            ]
        )
        self.assertEqual(self.detect_language(elf), "C")

    def test_detects_build_system_gradle_from_debug_path(self):
        elf = FakeELF([FakeSection(".debug_str", data=b"/workspace/.gradle/caches/modules/main.o")])
        self.assertEqual(self.detect_build_system_name(elf), "Gradle")

    def test_detects_build_system_waf_from_debug_path(self):
        elf = FakeELF([FakeSection(".debug_str", data=b"/workspace/.waf3-2.0.25/wscript")])
        self.assertEqual(self.detect_build_system_name(elf), "Waf")

    def test_detects_build_system_qmake_from_debug_path(self):
        elf = FakeELF([FakeSection(".debug_str", data=b"/workspace/build/.qmake.stash")])
        self.assertEqual(self.detect_build_system_name(elf), "QMake")

    def test_detects_build_system_premake_from_debug_path(self):
        elf = FakeELF([FakeSection(".debug_str", data=b"/workspace/scripts/premake5.lua")])
        self.assertEqual(self.detect_build_system_name(elf), "Premake")

    def test_detects_build_system_cabal_from_dwarf_path(self):
        elf = FakeELF(
            [],
            dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_comp_dir": "/work/project/dist-newstyle/build/x86_64-linux"}]),
        )
        self.assertEqual(self.detect_build_system_name(elf), "Cabal")

    def test_detects_build_system_stack_from_dwarf_path(self):
        elf = FakeELF(
            [],
            dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_comp_dir": "/work/project/.stack-work/dist/x86_64-linux"}]),
        )
        self.assertEqual(self.detect_build_system_name(elf), "Stack")

    def test_detects_build_system_nix_from_dwarf_path(self):
        elf = FakeELF(
            [],
            dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_comp_dir": "/nix/store/abc123-toolchain/src"}]),
        )
        self.assertEqual(self.detect_build_system_name(elf), "Nix")

    def test_detects_build_system_arduino_from_dwarf_path(self):
        elf = FakeELF(
            [],
            dwarf_info=FakeDwarfInfo(cus=[{"DW_AT_comp_dir": "/home/user/Arduino/sketch/sketch.ino"}]),
        )
        self.assertEqual(self.detect_build_system_name(elf), "Arduino")

    def test_detects_build_system_pico_sdk_from_debug_paths(self):
        elf = FakeELF(
            [
                FakeSection(
                    ".debug_str",
                    data=(
                        b"/home/kraken/pico-sdk/src/rp2040/pico_platform/include/pico\x00"
                        b"/home/kraken/pico-sdk/src/rp2040/hardware_regs/include/hardware/regs\x00"
                    ),
                )
            ]
        )
        self.assertEqual(self.detect_build_system_name(elf), "Pico SDK")

    def test_disassembly_pattern_boosts_asm_on_x86_64(self):
        elf = FakeELF(
            [
                FakeSection(".text", data=b"\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05"),
            ],
            machine="EM_X86_64",
        )
        self.assertEqual(self.detect_language(elf), "ASM")

    def test_detects_artifact_bare_metal_rp2040_profile(self):
        vector = (0x20001000).to_bytes(4, "little") + (0x10000101).to_bytes(4, "little")
        code = vector + b"\x00" * 256
        elf = FakeELF(
            [
                FakeSection(".boot2", data=b"\x00" * 256),
                FakeSection(".binary_info", data=b"pico-sdk"),
                FakeSection(".symtab", symbols=[FakeSymbol("_sbrk"), FakeSymbol("_write"), FakeSymbol("multicore_launch_core1")]),
                FakeSection(".strtab", data=b"/home/dev/pico-sdk/src/rp2040/pico_platform"),
            ],
            machine="EM_ARM",
            etype="ET_EXEC",
            entry=0x10000101,
            segments=[FakeSegment("PT_LOAD", data=code, p_vaddr=0x10000000, p_paddr=0x10000000)],
        )
        profile = self.detect_artifact(elf)
        self.assertEqual(profile["artifact_type"], "Bare-metal Firmware")
        self.assertIn("RP2040", profile["target"])
        self.assertEqual(profile["sdk"], "Pico SDK")

    def test_detects_artifact_linux_userspace_profile(self):
        elf = FakeELF(
            [
                FakeSection(".interp", data=b"/lib64/ld-linux-x86-64.so.2\x00"),
                FakeSection(".dynamic", tags=[FakeTag("libc.so.6")]),
                FakeSection(".dynsym", symbols=[FakeSymbol("__libc_start_main")]),
            ],
            machine="EM_X86_64",
            etype="ET_DYN",
            entry=0x1060,
            segments=[FakeSegment("PT_INTERP"), FakeSegment("PT_DYNAMIC")],
        )
        profile = self.detect_artifact(elf)
        self.assertEqual(profile["artifact_type"], "Linux User-space Executable")
        self.assertEqual(profile["linkage_model"], "Dynamic user-space")

    def test_detects_artifact_linux_shared_library_profile(self):
        elf = FakeELF(
            [
                FakeSection(".dynamic", tags=[FakeTag("libc.so.6"), FakeTag("libm.so.6")]),
            ],
            machine="EM_X86_64",
            etype="ET_DYN",
            entry=0,
            segments=[FakeSegment("PT_DYNAMIC")],
        )
        profile = self.detect_artifact(elf)
        self.assertEqual(profile["artifact_type"], "Linux Shared Library")

    def test_detects_artifact_static_userspace_profile(self):
        elf = FakeELF(
            [
                FakeSection(".note.gnu.build-id", data=b"\x01\x02"),
            ],
            machine="EM_X86_64",
            etype="ET_EXEC",
            entry=0x401000,
            segments=[FakeSegment("PT_LOAD", data=b"\x90" * 64, p_vaddr=0x400000, p_paddr=0x400000)],
        )
        profile = self.detect_artifact(elf)
        self.assertEqual(profile["artifact_type"], "Static User-space Executable")


if __name__ == "__main__":
    unittest.main()
