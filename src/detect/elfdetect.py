"""Compatibility entry points for detection APIs.

This module keeps the legacy import path (`detect.elfdetect`) stable while
internally delegating to the modular detection implementation.
"""

from detect.buildsystem import detect_build_system
from detect.compiler import detect_compiler
from detect.constants import BUILD_SYSTEM_HEURISTICS, COMPILER_HEURISTICS, SUPPORTED_LANGUAGES
from detect.language.core import detect_source_language

__all__ = [
    "SUPPORTED_LANGUAGES",
    "COMPILER_HEURISTICS",
    "BUILD_SYSTEM_HEURISTICS",
    "detect_source_language",
    "detect_compiler",
    "detect_build_system",
]
