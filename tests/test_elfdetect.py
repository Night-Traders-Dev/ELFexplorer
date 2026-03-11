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


if __name__ == "__main__":
    unittest.main()
