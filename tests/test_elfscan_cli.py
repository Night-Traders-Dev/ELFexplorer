import re
import subprocess
import sys
import unittest
from pathlib import Path


class ElfscanCorpusCLITests(unittest.TestCase):
    GREEN = "\033[92m"
    RED = "\033[91m"
    RESET = "\033[0m"
    DETECTED_LANGUAGE_PATTERN = re.compile(r"Detected Source Language \(heuristic\):\s*(.+)")
    DETECTED_BUILD_SYSTEM_PATTERN = re.compile(
        r"Detected Host Build System \(heuristic\):\s*(.+)"
    )
    EXPECTED_CORPUS = {
        "aarch64": ("hello_asm", "hello_c", "hello_cpp", "hello_dart", "hello_go"),
        "arm32": ("hello_asm", "hello_c", "hello_cpp", "hello_dart", "hello_go"),
        "rv64": ("hello_asm", "hello_c", "hello_cpp", "hello_dart", "hello_go"),
        "x86": ("hello_asm", "hello_c", "hello_cpp", "hello_dart", "hello_go"),
        "x86_64": ("hello_asm", "hello_c", "hello_cpp", "hello_dart", "hello_go", "hello_rust"),
    }

    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.elfscan_script = cls.repo_root / "src" / "elfscan.py"
        cls.corpus_root = cls.repo_root / "test-bin"
        cls.verbosity_level = cls._resolve_verbosity_level()

    @staticmethod
    def _resolve_verbosity_level():
        """
        Verbosity levels (5 total):
          0: quiet (-q/--quiet)
          1: default output (no switch, -v, or --verbose)
          2: extra summary (-vv)
          3: detailed summary (-vvv)
          4: everything (-vvvv)
        """
        args = sys.argv[1:]
        if "-q" in args or "--quiet" in args:
            return 0

        v_count = 0
        for arg in args:
            if arg == "--verbose":
                v_count += 1
            elif arg.startswith("-") and set(arg) <= {"-", "v"} and "v" in arg:
                v_count += arg.count("v")

        if v_count <= 1:
            return 1
        if v_count == 2:
            return 2
        if v_count == 3:
            return 3
        return 4

    def _assert_prerequisites(self):
        if not self.elfscan_script.exists():
            self.skipTest(f"elfscan script not found at {self.elfscan_script}")
        if not self.corpus_root.exists():
            self.skipTest(f"test corpus not found at {self.corpus_root}")

    @staticmethod
    def _expected_language_from_binary_name(binary_name):
        if not binary_name.startswith("hello_"):
            return None

        language_suffix = binary_name.removeprefix("hello_").lower()
        mapping = {
            "asm": "ASM",
            "c": "C",
            "cpp": "C++",
            "go": "Go",
            "dart": "Dart",
            "rust": "Rust",
            "nim": "Nim",
            "zig": "Zig",
            "haskell": "Haskell",
            "ocaml": "OCaml",
            "julia": "Julia",
            "lua": "Lua",
            "sage": "SageLang",
            "sagelang": "SageLang",
        }
        return mapping.get(language_suffix)

    def _run_and_assert_binary(self, arch, binary_name):
        self._assert_prerequisites()
        binary = self.corpus_root / arch / binary_name
        self.assertTrue(binary.is_file(), f"missing binary: {binary}")
        expected_language = self._expected_language_from_binary_name(binary_name)
        self.assertIsNotNone(
            expected_language,
            f"cannot infer expected language from file name: {binary_name}",
        )

        completed = subprocess.run(
            [sys.executable, str(self.elfscan_script), "--ui", "plain", str(binary)],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        output = (completed.stdout or "") + (completed.stderr or "")

        self.assertNotIn("Error processing ELF file:", output, output)
        match = self.DETECTED_LANGUAGE_PATTERN.search(output)
        self.assertIsNotNone(match, output)
        detected_language = match.group(1).strip()
        is_pass = detected_language == expected_language
        status = "[PASS]" if is_pass else "[FAIL]"
        color = self.GREEN if is_pass else self.RED

        compiler_match = re.search(r"Detected Compiler \(heuristic\):\s*(.+)", output)
        detected_compiler = compiler_match.group(1).strip() if compiler_match else "Unknown"
        build_system_match = self.DETECTED_BUILD_SYSTEM_PATTERN.search(output)
        detected_build_system = (
            build_system_match.group(1).strip() if build_system_match else "Unknown"
        )

        if self.verbosity_level >= 1:
            print(
                f"{color}{status}{self.RESET} {arch}/{binary_name} "
                f"expected={expected_language} detected={detected_language}"
            )

        if self.verbosity_level >= 2:
            print(
                f"  compiler={detected_compiler} "
                f"build_system={detected_build_system} "
                f"exit_code={completed.returncode} path={binary}"
            )

        if self.verbosity_level >= 3:
            score_lines = []
            in_scores = False
            for line in output.splitlines():
                if line.startswith("Language detection scores:"):
                    in_scores = True
                    continue
                if in_scores:
                    if line.startswith("Compiler detection scores:") or not line.strip():
                        break
                    score_lines.append(line.strip())
            if score_lines:
                print("  top language scores:")
                for line in score_lines[:6]:
                    print(f"    {line}")

        if self.verbosity_level >= 4:
            print("  full elfscan output:")
            for line in output.splitlines():
                print(f"    {line}")

        self.assertEqual(detected_language, expected_language, output)

    def test_corpus_inventory_matches_expected(self):
        self._assert_prerequisites()
        for arch in self.EXPECTED_CORPUS:
            arch_dir = self.corpus_root / arch
            self.assertTrue(arch_dir.is_dir(), f"missing architecture directory: {arch_dir}")
            actual_files = {path.name for path in arch_dir.iterdir() if path.is_file()}
            expected_files = set(self.EXPECTED_CORPUS[arch])
            self.assertEqual(
                actual_files,
                expected_files,
                f"unexpected file set for {arch}. update EXPECTED_CORPUS if corpus changed.",
            )


def _install_per_binary_tests():
    def make_test(arch, binary_name):
        def _test(self):
            self._run_and_assert_binary(arch, binary_name)

        safe_arch = arch.replace("-", "_")
        safe_name = binary_name.replace(".", "_").replace("-", "_")
        _test.__name__ = f"test_detect_{safe_arch}_{safe_name}"
        _test.__qualname__ = f"{ElfscanCorpusCLITests.__name__}.{_test.__name__}"
        return _test

    for arch, binaries in ElfscanCorpusCLITests.EXPECTED_CORPUS.items():
        for binary_name in sorted(binaries):
            test_fn = make_test(arch, binary_name)
            setattr(ElfscanCorpusCLITests, test_fn.__name__, test_fn)


_install_per_binary_tests()


if __name__ == "__main__":
    unittest.main()
