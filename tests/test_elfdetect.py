import io
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from detect.elfdetect import detect_source_language


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
    def __init__(self, sections):
        self._sections = list(sections)
        self._by_name = {section.name: section for section in self._sections}

    def get_section_by_name(self, name):
        return self._by_name.get(name)

    def iter_sections(self):
        return iter(self._sections)


class DetectSourceLanguageTests(unittest.TestCase):
    EXPECTED_BY_BINARY_NAME = {
        "hello_asm": "C",
        "hello_c": "C",
        "hello_cpp": "C++",
        "hello_dart": "C++",  # Dart native AOT artifacts currently map closest to C++ heuristics.
        "hello_go": "Go",
        "hello_rust": "Rust",
        "hello_sage": "SageLang",
    }

    def detect(self, elf):
        with io.StringIO() as capture, mock.patch("sys.stdout", capture):
            return detect_source_language(elf)

    def test_detects_sagelang_from_generated_symbols(self):
        elf = FakeELF(
            [
                FakeSection(".comment", data=b"GCC: (Ubuntu) 15.2.0"),
                FakeSection(
                    ".symtab",
                    symbols=[
                        FakeSymbol("sagec_12345.c"),
                        FakeSymbol("sage_fn_main_1"),
                        FakeSymbol("sage_global_answer_1"),
                        FakeSymbol("sage_number"),
                        FakeSymbol("main"),
                    ],
                ),
            ]
        )

        self.assertEqual(self.detect(elf), "SageLang")

    def test_detects_sagelang_from_note_section(self):
        elf = FakeELF(
            [
                FakeSection(".note.sagelang"),
                FakeSection(".symtab", symbols=[]),
            ]
        )

        self.assertEqual(self.detect(elf), "SageLang")

    def test_detects_sagelang_from_runtime_symbol_cluster(self):
        elf = FakeELF(
            [
                FakeSection(
                    ".symtab",
                    symbols=[
                        FakeSymbol("sage_mem_alloc"),
                        FakeSymbol("sage_mem_free"),
                        FakeSymbol("sage_struct_def"),
                        FakeSymbol("sage_struct_set"),
                        FakeSymbol("sage_bit_and"),
                        FakeSymbol("sage_range1"),
                        FakeSymbol("main"),
                    ],
                )
            ]
        )

        self.assertEqual(self.detect(elf), "SageLang")

    def test_detects_sagelang_from_runtime_strings(self):
        elf = FakeELF(
            [
                FakeSection(
                    ".rodata",
                    data=(
                        b"Unhandled exception: Runtime Error: Undefined variable '%s'. "
                        b"Runtime Error: method call on non-instance. "
                        b"Runtime Error: no __class__ on instance. "
                        b"too many classes "
                        b"sage_try_stack"
                    ),
                ),
                FakeSection(".dynsym", symbols=[]),
            ]
        )

        self.assertEqual(self.detect(elf), "SageLang")

    def test_detects_generated_c_symbol_with_path(self):
        elf = FakeELF(
            [
                FakeSection(
                    ".symtab",
                    symbols=[
                        FakeSymbol("/tmp/build/sagec_987654.c"),
                    ],
                )
            ]
        )

        self.assertEqual(self.detect(elf), "SageLang")

    def test_detects_provided_sage_sample_binaries(self):
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError:
            self.skipTest("pyelftools is not installed")

        repo_root = Path(__file__).resolve().parents[1]
        sample_binaries = ("for_loop", "guess", "hello", "logical")

        missing = [name for name in sample_binaries if not (repo_root / name).exists()]
        if missing:
            self.skipTest(f"missing sample binaries: {', '.join(missing)}")

        for name in sample_binaries:
            with self.subTest(binary=name):
                with open(repo_root / name, "rb") as handle:
                    elf = ELFFile(handle)
                    self.assertEqual(self.detect(elf), "SageLang")

    def test_detects_language_for_test_bin_corpus(self):
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError:
            self.skipTest("pyelftools is not installed")

        repo_root = Path(__file__).resolve().parents[1]
        corpus_root = repo_root / "test-bin"
        if not corpus_root.exists():
            self.skipTest("test-bin directory is missing")

        arch_dirs = sorted(path for path in corpus_root.iterdir() if path.is_dir())
        if not arch_dirs:
            self.skipTest("no architecture directories found under test-bin")

        saw_binary = False
        for arch_dir in arch_dirs:
            for binary_path in sorted(path for path in arch_dir.iterdir() if path.is_file()):
                saw_binary = True
                expected = self.EXPECTED_BY_BINARY_NAME.get(binary_path.name)
                self.assertIsNotNone(
                    expected,
                    f"missing expected language mapping for test binary '{binary_path.name}'",
                )

                with self.subTest(arch=arch_dir.name, binary=binary_path.name):
                    with open(binary_path, "rb") as handle:
                        elf = ELFFile(handle)
                        detected = self.detect(elf)
                        self.assertEqual(detected, expected)

        if not saw_binary:
            self.skipTest("no ELF binaries found under test-bin/*")


if __name__ == "__main__":
    unittest.main()
