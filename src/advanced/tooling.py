from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


PACKAGE_MANAGERS = {
    "brew": {
        "label": "Homebrew",
        "probe": "brew",
        "install_prefix": ["brew", "install"],
        "cask_prefix": ["brew", "install", "--cask"],
        "requires_root": False,
    },
    "apt": {
        "label": "APT",
        "probe": "apt-get",
        "install_prefix": ["apt-get", "install", "-y"],
        "requires_root": True,
    },
    "dnf": {
        "label": "DNF",
        "probe": "dnf",
        "install_prefix": ["dnf", "install", "-y"],
        "requires_root": True,
    },
    "pacman": {
        "label": "pacman",
        "probe": "pacman",
        "install_prefix": ["pacman", "-S", "--noconfirm"],
        "requires_root": True,
    },
    "yay": {
        "label": "yay (AUR)",
        "probe": "yay",
        "install_prefix": ["yay", "-S", "--noconfirm"],
        "requires_root": False,
    },
    "paru": {
        "label": "paru (AUR)",
        "probe": "paru",
        "install_prefix": ["paru", "-S", "--noconfirm"],
        "requires_root": False,
    },
    "winget": {
        "label": "WinGet",
        "probe": "winget",
        "install_prefix": [
            "winget",
            "install",
            "--accept-package-agreements",
            "--accept-source-agreements",
            "--disable-interactivity",
        ],
        "requires_root": False,
    },
    "choco": {
        "label": "Chocolatey",
        "probe": "choco",
        "install_prefix": ["choco", "install", "-y"],
        "requires_root": True,
    },
    "scoop": {
        "label": "Scoop",
        "probe": "scoop",
        "install_prefix": ["scoop", "install"],
        "requires_root": False,
    },
}

PACKAGE_MANAGER_PRIORITY = {
    "linux": ("apt", "dnf", "pacman", "yay", "paru", "brew"),
    "macos": ("brew",),
    "windows": ("winget", "choco", "scoop"),
}

ELFEXPLORER_HOME = Path.home() / ".elfexplorer"
LOCAL_TOOLS_ROOT = ELFEXPLORER_HOME / "tools"
LOCAL_DOWNLOADS_ROOT = ELFEXPLORER_HOME / "downloads"
LOCAL_BIN_ROOT = ELFEXPLORER_HOME / "bin"
HTTP_USER_AGENT = "ELFexplorer/0.11.8 (+https://github.com/)"

THIRD_PARTY_TOOLS = {
    "bramble": {
        "label": "Bramble",
        "homepage": "https://github.com/Night-Traders-Dev/Bramble",
        "download_url": "https://github.com/Night-Traders-Dev/Bramble",
        "executables": ("bramble",),
        "path_hints": (),
        "version_args": None,
        "install": {},
        "manual_install": (
            "Build from source with git, CMake, a native C toolchain, and recursive submodules. "
            "Upstream flow: git clone --recursive https://github.com/Night-Traders-Dev/Bramble.git "
            "&& ./build.sh"
        ),
    },
    "binaryninja": {
        "label": "Binary Ninja",
        "homepage": "https://binary.ninja/free/",
        "download_url": "https://binary.ninja/free/",
        "executables": ("binaryninja", "binaryninja-free"),
        "path_hints": (
            "~/Applications/Binary Ninja.app/Contents/MacOS/binaryninja",
            "/Applications/Binary Ninja.app/Contents/MacOS/binaryninja",
            "/Applications/Binary Ninja Free.app/Contents/MacOS/binaryninja",
            "C:/Program Files/Vector35/BinaryNinja/binaryninja.exe",
            "C:/Program Files/Vector35/BinaryNinjaFree/binaryninja.exe",
        ),
        "version_args": None,
        "install": {
            "brew": {"package": "binary-ninja-free", "cask": True},
        },
        "manual_install": (
            "Vector35 distributes Binary Ninja directly on Linux/Windows. "
            "Download the platform package and complete the vendor setup."
        ),
    },
    "ghidra": {
        "label": "Ghidra",
        "homepage": "https://ghidra-sre.org/",
        "download_url": "https://github.com/NationalSecurityAgency/ghidra/releases",
        "executables": ("ghidraRun", "ghidra"),
        "path_hints": (
            "/opt/ghidra*/ghidraRun",
            "/usr/share/ghidra*/ghidraRun",
            "/Applications/Ghidra.app/Contents/MacOS/ghidra",
            "C:/Program Files/ghidra*/ghidraRun.bat",
        ),
        "version_args": None,
        "install": {
            "brew": {"package": "ghidra", "cask": True},
            "pacman": {"package": "ghidra"},
        },
        "manual_install": (
            "Ghidra is otherwise installed from the official release ZIP and requires a supported Java runtime."
        ),
    },
    "ida": {
        "label": "IDA Pro",
        "homepage": "https://hex-rays.com/ida-pro/",
        "download_url": "https://hex-rays.com/ida-pro/",
        "executables": ("ida64", "ida", "idat64", "idaq64"),
        "path_hints": (
            "/Applications/IDA Professional*/ida64.app/Contents/MacOS/ida64",
            "C:/Program Files/IDA Professional*/ida64.exe",
            "/opt/ida*/ida64",
        ),
        "version_args": None,
        "install": {},
        "manual_install": "IDA Pro is vendor-distributed and must be installed manually.",
    },
    "radare2": {
        "label": "radare2",
        "homepage": "https://rada.re/n/",
        "download_url": "https://book.rada.re/install/index.html",
        "executables": ("r2", "radare2"),
        "path_hints": (),
        "version_args": ("-v",),
        "install": {
            "brew": {"package": "radare2"},
            "apt": {"package": "radare2"},
            "dnf": {"package": "radare2"},
            "pacman": {"package": "radare2"},
        },
        "manual_install": "Build radare2 from source if your package manager does not ship it.",
    },
    "cutter": {
        "label": "Cutter",
        "homepage": "https://cutter.re/",
        "download_url": "https://github.com/rizinorg/cutter/releases",
        "executables": ("cutter",),
        "path_hints": (
            "/Applications/Cutter.app/Contents/MacOS/cutter",
            "C:/Program Files/Cutter/cutter.exe",
        ),
        "version_args": ("--version",),
        "install": {
            "dnf": {"package": "cutter-re"},
            "pacman": {"package": "rz-cutter"},
        },
        "manual_install": (
            "Cutter packaging varies by distro. Install the upstream release or a supported distro package."
        ),
    },
    "rizin": {
        "label": "Rizin",
        "homepage": "https://rizin.re/",
        "download_url": "https://github.com/rizinorg/rizin/releases",
        "executables": ("rizin", "rz-bin"),
        "path_hints": (),
        "version_args": ("-v",),
        "install": {
            "dnf": {"package": "rizin"},
            "pacman": {"package": "rizin"},
        },
        "manual_install": "Rizin can be installed from upstream packages or built from source.",
    },
    "imhex": {
        "label": "ImHex",
        "homepage": "https://imhex.werwolv.net/",
        "download_url": "https://github.com/WerWolv/ImHex/releases",
        "executables": ("imhex",),
        "path_hints": (
            "/Applications/ImHex.app/Contents/MacOS/imhex",
            "C:/Program Files/ImHex/imhex.exe",
        ),
        "version_args": ("--version",),
        "install": {
            "brew": {"package": "imhex", "cask": True},
            "dnf": {"package": "imhex"},
            "yay": {"package": "imhex"},
            "paru": {"package": "imhex"},
        },
        "manual_install": "ImHex is also available from upstream release assets such as AppImage/DMG.",
    },
}

TOOL_WORKBENCH_PROFILES = {
    "bramble": {
        "launch_args": ["{file}"],
        "cli_friendly": True,
        "presets": [
            {
                "key": "run-firmware",
                "label": "Run Firmware",
                "description": "Run the selected UF2 or ELF firmware in Bramble.",
                "args": ["{file}"],
            },
            {
                "key": "debug-core0",
                "label": "Debug Core0",
                "description": "Run with core 0 debug output enabled.",
                "args": ["-debug", "{file}"],
            },
            {
                "key": "status",
                "label": "Status Stream",
                "description": "Run with periodic dual-core status updates.",
                "args": ["{file}", "-status"],
            },
            {
                "key": "gdb-server",
                "label": "GDB Server",
                "description": "Start Bramble with the GDB remote server on port 3333.",
                "args": ["{file}", "-gdb"],
            },
            {
                "key": "asm-trace",
                "label": "ASM Trace",
                "description": "Enable instruction trace output while running firmware.",
                "args": ["-asm", "{file}"],
            },
        ],
    },
    "binaryninja": {
        "launch_args": ["{file}"],
        "cli_friendly": False,
        "presets": [],
    },
    "ghidra": {
        "launch_args": [],
        "cli_friendly": False,
        "presets": [],
    },
    "ida": {
        "launch_args": ["{file}"],
        "cli_friendly": False,
        "presets": [],
    },
    "radare2": {
        "launch_args": ["{file}"],
        "cli_friendly": True,
        "presets": [
            {
                "key": "file-info",
                "label": "File Info",
                "description": "Run radare2 metadata summary (`iI`).",
                "args": ["-A", "-q", "-c", "iI", "{file}"],
            },
            {
                "key": "sections",
                "label": "Sections",
                "description": "List sections (`iS`).",
                "args": ["-A", "-q", "-c", "iS", "{file}"],
            },
            {
                "key": "symbols",
                "label": "Symbols",
                "description": "List symbols (`is`).",
                "args": ["-A", "-q", "-c", "is", "{file}"],
            },
            {
                "key": "functions",
                "label": "Functions",
                "description": "Analyze and list functions (`afl`).",
                "args": ["-A", "-q", "-c", "afl", "{file}"],
            },
            {
                "key": "strings",
                "label": "Strings",
                "description": "List strings (`iz`).",
                "args": ["-A", "-q", "-c", "iz", "{file}"],
            },
        ],
    },
    "cutter": {
        "launch_args": ["{file}"],
        "cli_friendly": False,
        "presets": [
            {
                "key": "version",
                "label": "Version",
                "description": "Print Cutter version and exit.",
                "args": ["--version"],
            }
        ],
    },
    "rizin": {
        "launch_args": ["{file}"],
        "cli_friendly": True,
        "presets": [
            {
                "key": "file-info",
                "label": "File Info",
                "description": "Run Rizin metadata summary (`iI`).",
                "args": ["-A", "-q", "-c", "iI", "{file}"],
            },
            {
                "key": "sections",
                "label": "Sections",
                "description": "List sections (`iS`).",
                "args": ["-A", "-q", "-c", "iS", "{file}"],
            },
            {
                "key": "symbols",
                "label": "Symbols",
                "description": "List symbols (`is`).",
                "args": ["-A", "-q", "-c", "is", "{file}"],
            },
            {
                "key": "functions",
                "label": "Functions",
                "description": "Analyze and list functions (`afl`).",
                "args": ["-A", "-q", "-c", "afl", "{file}"],
            },
            {
                "key": "strings",
                "label": "Strings",
                "description": "List strings (`iz`).",
                "args": ["-A", "-q", "-c", "iz", "{file}"],
            },
        ],
    },
    "imhex": {
        "launch_args": ["{file}"],
        "cli_friendly": False,
        "presets": [
            {
                "key": "version",
                "label": "Version",
                "description": "Print ImHex version and exit.",
                "args": ["--version"],
            }
        ],
    },
}

BRAMBLE_FEATURES = {
    "Firmware Inputs": [
        "Runs RP2040 UF2 firmware images.",
        "Runs RP2040 ELF firmware images.",
        "Supports adjustable RP2040 clock configuration.",
        "Supports optional boot2 bypass for firmware experiments.",
    ],
    "Debugging": [
        "Core 0 debug trace output via -debug.",
        "Core 1 debug trace output via -debug1.",
        "Instruction trace output via -asm.",
        "Periodic machine status output via -status.",
        "GDB remote server via -gdb [port].",
        "Unmapped-memory diagnostics via -debug-mem.",
    ],
    "Persistence and Storage": [
        "Persistent flash backing via -flash <path>.",
        "Flash filesystem mounting via -mount <dir> when flash backing is enabled.",
        "SPI SD card images via -sdcard <path> with configurable size/spi bus.",
        "eMMC images via -emmc <path> with configurable size/spi bus.",
    ],
    "I/O and Wiring": [
        "stdin to UART0 bridging via -stdin.",
        "Network UART bridges via -net-uart0/-net-uart1 and connect modes.",
        "Unix socket wire links via -wire-uart0/-wire-uart1/-wire-gpio.",
    ],
    "Acceleration": [
        "Optional JIT mode via -jit.",
        "Useful as an in-app RP2040 firmware smoke-test harness before hardware deployment.",
    ],
}


def render_bramble_feature_lines():
    lines = []
    for section, items in BRAMBLE_FEATURES.items():
        lines.append(f"{section}:")
        for item in items:
            lines.append(f"- {item}")
        lines.append("")
    return lines[:-1]


def _append_bramble_arg_pair(args, flag, value):
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    args.extend([flag, text])


def build_bramble_command_args(
    target_path,
    *,
    debug=False,
    debug1=False,
    asm_trace=False,
    status=False,
    stdin_enabled=False,
    gdb=False,
    gdb_port=None,
    clock_mhz=None,
    no_boot2=False,
    debug_mem=False,
    flash_path=None,
    mount_path=None,
    sdcard_path=None,
    sdcard_spi=None,
    sdcard_size_mb=None,
    emmc_path=None,
    emmc_spi=None,
    emmc_size_mb=None,
    uart0_port=None,
    uart0_connect=None,
    wire_uart0=None,
    wire_gpio=None,
    jit=False,
):
    if not target_path:
        raise ValueError("Bramble requires a target UF2 or ELF path.")

    args = [str(Path(target_path).expanduser())]
    if debug:
        args.append("-debug")
    if debug1:
        args.append("-debug1")
    if asm_trace:
        args.append("-asm")
    if status:
        args.append("-status")
    if stdin_enabled:
        args.append("-stdin")
    if gdb:
        args.append("-gdb")
        if gdb_port not in (None, "", 3333, "3333"):
            args.append(str(gdb_port).strip())
    _append_bramble_arg_pair(args, "-clock", clock_mhz)
    if no_boot2:
        args.append("-no-boot2")
    if debug_mem:
        args.append("-debug-mem")
    _append_bramble_arg_pair(args, "-flash", flash_path)
    _append_bramble_arg_pair(args, "-mount", mount_path)
    _append_bramble_arg_pair(args, "-sdcard", sdcard_path)
    _append_bramble_arg_pair(args, "-sdcard-spi", sdcard_spi)
    _append_bramble_arg_pair(args, "-sdcard-size", sdcard_size_mb)
    _append_bramble_arg_pair(args, "-emmc", emmc_path)
    _append_bramble_arg_pair(args, "-emmc-spi", emmc_spi)
    _append_bramble_arg_pair(args, "-emmc-size", emmc_size_mb)
    _append_bramble_arg_pair(args, "-net-uart0", uart0_port)
    _append_bramble_arg_pair(args, "-net-uart0-connect", uart0_connect)
    _append_bramble_arg_pair(args, "-wire-uart0", wire_uart0)
    _append_bramble_arg_pair(args, "-wire-gpio", wire_gpio)
    if jit:
        args.append("-jit")
    return args


def list_external_tools():
    return dict(THIRD_PARTY_TOOLS)


def _get_tool_workbench_profile(tool_key):
    return TOOL_WORKBENCH_PROFILES.get(
        tool_key,
        {"launch_args": ["{file}"], "cli_friendly": False, "presets": []},
    )


def _normalize_os(system_name: str | None = None):
    value = (system_name or platform.system() or "").strip().lower()
    if value == "darwin":
        return "macos"
    if value == "windows":
        return "windows"
    if value == "linux":
        return "linux"
    return value or "unknown"


def _normalize_arch(machine_name: str | None = None):
    value = (machine_name or platform.machine() or "").strip().lower()
    mapping = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "arm64": "arm64",
        "aarch64": "arm64",
        "x86": "x86",
        "i386": "x86",
        "i686": "x86",
    }
    return mapping.get(value, value or "unknown")


def _detect_linux_distro():
    try:
        release = platform.freedesktop_os_release()
    except Exception:
        return None
    pretty_name = release.get("PRETTY_NAME")
    if pretty_name:
        return pretty_name
    return release.get("NAME") or None


def detect_host_environment():
    os_key = _normalize_os()
    available = []
    for manager_key in PACKAGE_MANAGER_PRIORITY.get(os_key, ()):
        probe = PACKAGE_MANAGERS[manager_key]["probe"]
        if shutil.which(probe):
            available.append(manager_key)
    environment = {
        "os": os_key,
        "os_label": {"linux": "Linux", "macos": "macOS", "windows": "Windows"}.get(os_key, os_key),
        "arch": _normalize_arch(),
        "package_managers": available,
        "primary_package_manager": available[0] if available else None,
        "primary_package_manager_label": (
            PACKAGE_MANAGERS[available[0]]["label"] if available else "None detected"
        ),
    }
    if os_key == "linux":
        environment["distro"] = _detect_linux_distro()
    return environment


def _iter_hint_paths(path_hints):
    for hint in path_hints:
        expanded = Path(hint).expanduser()
        if any(token in hint for token in ("*", "?", "[")):
            parent = expanded.parent
            if parent.exists():
                yield from parent.glob(expanded.name)
            continue
        yield expanded


def _local_wrapper_paths(tool_key):
    wrappers = []
    for executable in THIRD_PARTY_TOOLS[tool_key].get("executables", ()):
        wrappers.append(LOCAL_BIN_ROOT / executable)
    return wrappers


def _probe_version(executable_path, version_args):
    if not version_args:
        return None
    try:
        completed = subprocess.run(
            [str(executable_path), *version_args],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return None
    text = (completed.stdout or completed.stderr or "").strip()
    if not text:
        return None
    return text.splitlines()[0].strip()


def _find_tool_path(tool_key):
    meta = THIRD_PARTY_TOOLS[tool_key]
    for executable in meta.get("executables", ()):
        found = shutil.which(executable)
        if found:
            return {"path": found, "source": "PATH"}
    for wrapper in _local_wrapper_paths(tool_key):
        if wrapper.exists():
            return {"path": str(wrapper), "source": "elfexplorer-local"}
    for path in _iter_hint_paths(meta.get("path_hints", ())):
        if path.exists():
            return {"path": str(path), "source": "hint"}
    return None


def _resolve_override_candidate(executable_override):
    if not executable_override:
        return None
    candidate = Path(str(executable_override)).expanduser()
    return {
        "requested_path": str(candidate),
        "path": str(candidate) if candidate.exists() else None,
        "source": "override" if candidate.exists() else "override-missing",
    }


def _build_command_for_recipe(manager_key, recipe, interactive=False):
    manager = PACKAGE_MANAGERS[manager_key]
    base = list(manager["cask_prefix"] if recipe.get("cask") else manager["install_prefix"])
    if manager["requires_root"] and os.name == "posix" and getattr(os, "geteuid", lambda: 1)() != 0:
        if not shutil.which("sudo"):
            return None
        sudo_cmd = ["sudo"]
        if not interactive:
            sudo_cmd.append("-n")
        base = sudo_cmd + base
    base.append(recipe["package"])
    return base


def build_install_command(tool_key, environment=None, interactive=False):
    if tool_key not in THIRD_PARTY_TOOLS:
        raise ValueError(f"Unsupported external tool '{tool_key}'.")
    environment = environment or detect_host_environment()
    for manager_key in environment.get("package_managers", []):
        recipe = THIRD_PARTY_TOOLS[tool_key].get("install", {}).get(manager_key)
        if recipe:
            command = _build_command_for_recipe(manager_key, recipe, interactive=interactive)
            if command:
                return command, manager_key
    return None, None


def _portable_install_supported(tool_key, environment=None):
    environment = environment or detect_host_environment()
    os_key = environment.get("os")
    arch = environment.get("arch")
    if tool_key == "bramble":
        return os_key in {"linux", "macos"} and all(shutil.which(name) for name in ("git", "cmake", "make"))
    if tool_key == "ghidra":
        return os_key == "linux" and arch == "x86_64"
    if tool_key == "binaryninja":
        return os_key == "linux" and arch == "x86_64"
    if tool_key == "cutter":
        return os_key == "linux" and arch == "x86_64"
    if tool_key == "imhex":
        return os_key == "linux" and arch in {"x86_64", "arm64"}
    if tool_key == "rizin":
        return os_key == "linux" and arch == "x86_64"
    return False


def _download_supported(tool_key, environment=None):
    environment = environment or detect_host_environment()
    os_key = environment.get("os")
    if tool_key == "bramble":
        return os_key in {"linux", "macos", "windows"}
    if tool_key == "binaryninja":
        return os_key in {"linux", "macos", "windows"}
    if tool_key == "ghidra":
        return os_key in {"linux", "macos", "windows"}
    if tool_key == "cutter":
        return os_key in {"linux", "macos", "windows"}
    if tool_key == "imhex":
        return os_key in {"linux", "macos", "windows"}
    if tool_key == "rizin":
        return os_key in {"linux", "macos", "windows"}
    return False


def _http_request(url, accept=None):
    headers = {"User-Agent": HTTP_USER_AGENT}
    if accept:
        headers["Accept"] = accept
    return urllib.request.Request(url, headers=headers)


def _emit_tool_event(event_cb, kind, message, progress=None, **payload):
    if not event_cb:
        return
    event = {"kind": kind, "message": str(message)}
    if progress is not None:
        event["progress"] = float(progress)
    event.update(payload)
    event_cb(event)


def _load_json(url):
    with urllib.request.urlopen(_http_request(url, accept="application/vnd.github+json"), timeout=20) as handle:
        return json.load(handle)


def _download_file(url, target_path, event_cb=None, progress_range=None):
    target = Path(target_path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    start_progress, end_progress = progress_range or (0.0, 100.0)
    with urllib.request.urlopen(_http_request(url), timeout=120) as response:
        total = 0
        try:
            total = int(response.headers.get("Content-Length", "0") or "0")
        except Exception:
            total = 0
        downloaded = 0
        _emit_tool_event(
            event_cb,
            "log",
            f"Downloading {url}",
            progress=start_progress,
            total_bytes=total,
        )
        with target.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 256)
                if not chunk:
                    break
                handle.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    ratio = min(1.0, downloaded / total)
                    progress = start_progress + ((end_progress - start_progress) * ratio)
                    _emit_tool_event(
                        event_cb,
                        "progress",
                        f"Downloaded {downloaded}/{total} bytes",
                        progress=progress,
                        downloaded_bytes=downloaded,
                        total_bytes=total,
                    )
        _emit_tool_event(
            event_cb,
            "log",
            f"Download complete: {target}",
            progress=end_progress,
            downloaded_bytes=downloaded,
            total_bytes=total,
        )
    return target


def _run_logged_subprocess(command, event_cb=None, progress_range=(20.0, 90.0)):
    start_progress, end_progress = progress_range
    _emit_tool_event(
        event_cb,
        "log",
        f"Running command: {' '.join(command)}",
        progress=start_progress,
        command=command,
    )
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    lines = []
    progress = start_progress
    step = max(0.2, (end_progress - start_progress) / 100.0)
    try:
        if process.stdout is not None:
            for line in process.stdout:
                stripped = line.rstrip()
                lines.append(stripped)
                progress = min(end_progress, progress + step)
                _emit_tool_event(
                    event_cb,
                    "log",
                    stripped,
                    progress=progress,
                )
        returncode = process.wait()
    finally:
        if process.stdout is not None:
            process.stdout.close()
    return returncode, "\n".join(lines).strip()


def _download_filename_from_url(url):
    parsed = urllib.parse.urlparse(url)
    filename = Path(parsed.path).name
    return filename or "download.bin"


def _github_latest_release(repo):
    data = _load_json(f"https://api.github.com/repos/{repo}/releases/latest")
    return {
        "repo": repo,
        "tag_name": data.get("tag_name"),
        "assets": data.get("assets", []),
    }


def _choose_github_asset(repo, patterns):
    release = _github_latest_release(repo)
    compiled = [re.compile(pattern) for pattern in patterns]
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        for pattern in compiled:
            if pattern.search(name):
                return {
                    "source": "github-release",
                    "repo": repo,
                    "tag_name": release.get("tag_name"),
                    "filename": name,
                    "url": asset.get("browser_download_url"),
                }
    return None


def _resolve_binary_ninja_free_asset(environment):
    os_key = environment.get("os")
    suffix_map = {
        "linux": "binaryninja_free_linux.zip",
        "macos": "binaryninja_free_macosx.dmg",
        "windows": "binaryninja_free_win64.exe",
    }
    suffix = suffix_map.get(os_key)
    if not suffix:
        return None
    with urllib.request.urlopen(_http_request("https://binary.ninja/free/"), timeout=20) as handle:
        html = handle.read().decode("utf-8", "replace")
    marker = f"https://cdn.binary.ninja/installers/{suffix}"
    index = html.find(marker)
    if index < 0:
        return None
    return {
        "source": "vendor-page",
        "filename": suffix,
        "url": marker,
    }


def _resolve_download_spec(tool_key, environment=None):
    environment = environment or detect_host_environment()
    os_key = environment.get("os")
    arch = environment.get("arch")

    if tool_key == "bramble":
        return {
            "source": "github-archive",
            "repo": "Night-Traders-Dev/Bramble",
            "filename": "Bramble-main.zip",
            "url": "https://github.com/Night-Traders-Dev/Bramble/archive/refs/heads/main.zip",
            "tool_key": tool_key,
            "install_mode": "download-only",
            "entry_globs": [],
        }

    if tool_key == "binaryninja":
        asset = _resolve_binary_ninja_free_asset(environment)
        if not asset:
            return None
        install_mode = "zip-extract" if os_key == "linux" else "download-only"
        entry_globs = ["**/binaryninja"] if install_mode == "zip-extract" else []
        return {
            **asset,
            "tool_key": tool_key,
            "install_mode": install_mode,
            "entry_globs": entry_globs,
        }

    if tool_key == "ghidra":
        asset = _choose_github_asset(
            "NationalSecurityAgency/ghidra",
            [r"^ghidra_.*_PUBLIC_.*\.zip$"],
        )
        if not asset:
            return None
        install_mode = "zip-extract" if os_key == "linux" and arch == "x86_64" else "download-only"
        return {
            **asset,
            "tool_key": tool_key,
            "install_mode": install_mode,
            "entry_globs": ["**/ghidraRun"],
        }

    if tool_key == "cutter":
        pattern_map = {
            ("linux", "x86_64"): [r"^Cutter-v.*-Linux-x86_64\.AppImage$", r"^Cutter-v.*-Linux-Qt5-x86_64\.AppImage$"],
            ("windows", "x86_64"): [r"^Cutter-v.*-Windows-x86_64\.zip$"],
            ("macos", "x86_64"): [r"^Cutter-v.*-macOS-x86_64\.dmg$"],
            ("macos", "arm64"): [r"^Cutter-v.*-macOS-arm64\.dmg$"],
        }
        patterns = pattern_map.get((os_key, arch))
        if not patterns:
            return None
        asset = _choose_github_asset("rizinorg/cutter", patterns)
        if not asset:
            return None
        install_mode = "appimage" if os_key == "linux" else "download-only"
        return {
            **asset,
            "tool_key": tool_key,
            "install_mode": install_mode,
            "entry_globs": [],
        }

    if tool_key == "imhex":
        pattern_map = {
            ("linux", "x86_64"): [r"^imhex-.*-x86_64\.AppImage$"],
            ("linux", "arm64"): [r"^imhex-.*-arm64\.AppImage$"],
            ("windows", "x86_64"): [r"^imhex-.*-Windows-Portable-x86_64\.zip$"],
            ("windows", "arm64"): [r"^imhex-.*-Windows-Portable-arm64\.zip$"],
            ("macos", "x86_64"): [r"^imhex-.*-macOS-x86_64\.dmg$", r"^imhex-.*-macOS-NoGPU-x86_64\.dmg$"],
            ("macos", "arm64"): [r"^imhex-.*-macOS-arm64\.dmg$"],
        }
        patterns = pattern_map.get((os_key, arch))
        if not patterns:
            return None
        asset = _choose_github_asset("WerWolv/ImHex", patterns)
        if not asset:
            return None
        install_mode = "appimage" if os_key == "linux" else "download-only"
        return {
            **asset,
            "tool_key": tool_key,
            "install_mode": install_mode,
            "entry_globs": [],
        }

    if tool_key == "rizin":
        pattern_map = {
            ("linux", "x86_64"): [r"^rizin-v.*-static-x86_64\.tar\.xz$"],
            ("windows", "x86_64"): [r"^rizin-windows-static-v.*\.zip$"],
            ("macos", "x86_64"): [r"^rizin-macos-v.*\.pkg$"],
            ("macos", "arm64"): [r"^rizin-macos-v.*\.pkg$"],
        }
        patterns = pattern_map.get((os_key, arch))
        if not patterns:
            return None
        asset = _choose_github_asset("rizinorg/rizin", patterns)
        if not asset:
            return None
        install_mode = "tar-extract" if os_key == "linux" else "download-only"
        return {
            **asset,
            "tool_key": tool_key,
            "install_mode": install_mode,
            "entry_globs": ["**/bin/rizin"],
        }

    return None


def _write_wrapper(tool_key, executable_path):
    executable = Path(executable_path).expanduser().resolve()
    LOCAL_BIN_ROOT.mkdir(parents=True, exist_ok=True)
    wrappers = []
    for name in THIRD_PARTY_TOOLS[tool_key].get("executables", ()):
        wrapper = LOCAL_BIN_ROOT / name
        wrapper.write_text(f"#!/bin/sh\nexec \"{executable}\" \"$@\"\n", encoding="utf-8")
        wrapper.chmod(0o755)
        wrappers.append(wrapper)
    return wrappers


def _find_first_match(root, patterns):
    root = Path(root)
    for pattern in patterns:
        matches = sorted(root.glob(pattern))
        if matches:
            return matches[0]
    return None


def _tool_install_root(tool_key, spec):
    tag = spec.get("tag_name") or Path(spec["filename"]).stem
    safe_tag = re.sub(r"[^A-Za-z0-9._-]+", "_", str(tag))
    return LOCAL_TOOLS_ROOT / tool_key / safe_tag


def _portable_requires_download_only(spec):
    return spec.get("install_mode") == "download-only"


def _install_bramble_from_source(environment=None, dry_run=False, event_cb=None):
    environment = environment or detect_host_environment()
    status = get_external_tool_status("bramble", environment=environment)
    install_root = (LOCAL_TOOLS_ROOT / "bramble" / "main").expanduser()
    repo_root = install_root / "repo"
    build_root = repo_root / "build"
    binary_path = build_root / "bramble"
    clone_url = "https://github.com/Night-Traders-Dev/Bramble.git"
    clone_command = ["git", "clone", "--recursive", clone_url, str(repo_root)]
    update_command = ["git", "-C", str(repo_root), "pull", "--ff-only", "origin", "main"]
    submodule_command = ["git", "-C", str(repo_root), "submodule", "update", "--init", "--recursive"]
    configure_command = ["cmake", "-S", str(repo_root), "-B", str(build_root)]
    build_command = ["cmake", "--build", str(build_root), "--parallel", str(max(1, os.cpu_count() or 1))]
    _emit_tool_event(
        event_cb,
        "log",
        f"Preparing source build for {status['label']} under {install_root}",
        progress=6.0,
        install_path=str(install_root),
    )
    if dry_run:
        planned = [update_command if repo_root.exists() else clone_command, submodule_command, configure_command, build_command]
        _emit_tool_event(
            event_cb,
            "progress",
            f"Dry run: would source-build {status['label']} into {install_root}",
            progress=100.0,
            install_path=str(install_root),
            command=planned,
        )
        return {
            "ok": True,
            "changed": False,
            "message": f"Dry run: would source-build {status['label']} into {install_root}",
            "status": status,
            "install_path": str(install_root),
            "command": planned,
            "portable": True,
        }

    install_root.mkdir(parents=True, exist_ok=True)
    if repo_root.exists():
        _emit_tool_event(event_cb, "log", "Updating existing Bramble checkout", progress=12.0)
        command = update_command
    else:
        _emit_tool_event(event_cb, "log", "Cloning Bramble repository with submodules", progress=12.0)
        command = clone_command
    returncode, output = _run_logged_subprocess(command, event_cb=event_cb, progress_range=(15.0, 40.0))
    if returncode != 0:
        return {
            "ok": False,
            "changed": False,
            "message": f"Failed to fetch Bramble sources. Command: {' '.join(command)}",
            "status": status,
            "install_path": str(install_root),
            "command": command,
            "output": output,
        }

    returncode, submodule_output = _run_logged_subprocess(
        submodule_command,
        event_cb=event_cb,
        progress_range=(42.0, 58.0),
    )
    combined_output = "\n".join(chunk for chunk in [output, submodule_output] if chunk).strip()
    if returncode != 0:
        return {
            "ok": False,
            "changed": False,
            "message": "Failed to sync Bramble submodules.",
            "status": status,
            "install_path": str(install_root),
            "command": submodule_command,
            "output": combined_output,
        }

    returncode, configure_output = _run_logged_subprocess(
        configure_command,
        event_cb=event_cb,
        progress_range=(60.0, 76.0),
    )
    combined_output = "\n".join(chunk for chunk in [combined_output, configure_output] if chunk).strip()
    if returncode != 0:
        return {
            "ok": False,
            "changed": False,
            "message": "Failed to configure the Bramble build with CMake.",
            "status": status,
            "install_path": str(install_root),
            "command": configure_command,
            "output": combined_output,
        }

    returncode, build_output = _run_logged_subprocess(
        build_command,
        event_cb=event_cb,
        progress_range=(78.0, 94.0),
    )
    combined_output = "\n".join(chunk for chunk in [combined_output, build_output] if chunk).strip()
    if returncode != 0:
        return {
            "ok": False,
            "changed": False,
            "message": "Failed to build Bramble.",
            "status": status,
            "install_path": str(install_root),
            "command": build_command,
            "output": combined_output,
        }

    if not binary_path.exists():
        return {
            "ok": False,
            "changed": False,
            "message": f"Bramble build completed but no executable was found at {binary_path}.",
            "status": status,
            "install_path": str(install_root),
            "output": combined_output,
        }

    wrappers = _write_wrapper("bramble", binary_path)
    _emit_tool_event(
        event_cb,
        "progress",
        f"Installed {status['label']} locally from source",
        progress=100.0,
        install_path=str(install_root),
    )
    return {
        "ok": True,
        "changed": True,
        "message": (
            f"Installed {status['label']} locally in {install_root}. "
            f"Launcher wrapper: {wrappers[0]}"
        ),
        "status": status,
        "install_path": str(install_root),
        "wrapper_paths": [str(path) for path in wrappers],
        "command": [clone_command, submodule_command, configure_command, build_command],
        "output": combined_output,
        "portable": True,
    }


def download_external_tool(tool_key, dry_run=False, environment=None, output_dir=None, event_cb=None):
    if tool_key not in THIRD_PARTY_TOOLS:
        raise ValueError(f"Unsupported external tool '{tool_key}'.")
    environment = environment or detect_host_environment()
    status = get_external_tool_status(tool_key, environment=environment)
    _emit_tool_event(event_cb, "log", f"Preparing download for {status['label']}", progress=2.0)
    spec = _resolve_download_spec(tool_key, environment=environment)
    if not spec:
        _emit_tool_event(
            event_cb,
            "log",
            status.get("manual_install") or "No downloadable package is defined for this tool on this host.",
            progress=100.0,
        )
        return {
            "ok": False,
            "changed": False,
            "message": status.get("manual_install") or "No downloadable package is defined for this tool on this host.",
            "status": status,
            "manual_only": True,
        }

    destination_dir = Path(output_dir).expanduser() if output_dir else (LOCAL_DOWNLOADS_ROOT / tool_key)
    archive_path = destination_dir / spec["filename"]
    _emit_tool_event(
        event_cb,
        "log",
        f"Resolved package {spec['filename']} from {spec['url']}",
        progress=10.0,
        download_url=spec["url"],
        download_path=str(archive_path),
    )
    if dry_run:
        _emit_tool_event(
            event_cb,
            "progress",
            f"Dry run: would download into {archive_path}",
            progress=100.0,
            download_url=spec["url"],
            download_path=str(archive_path),
        )
        return {
            "ok": True,
            "changed": False,
            "message": f"Dry run: download {spec['url']} -> {archive_path}",
            "status": status,
            "download_url": spec["url"],
            "download_path": str(archive_path),
            "portable": not _portable_requires_download_only(spec),
        }

    downloaded = _download_file(spec["url"], archive_path, event_cb=event_cb, progress_range=(15.0, 100.0))
    return {
        "ok": True,
        "changed": True,
        "message": f"Downloaded {status['label']} package to {downloaded}",
        "status": status,
        "download_url": spec["url"],
        "download_path": str(downloaded),
        "portable": not _portable_requires_download_only(spec),
    }


def _install_portable_tool(tool_key, environment=None, dry_run=False, event_cb=None):
    environment = environment or detect_host_environment()
    status = get_external_tool_status(tool_key, environment=environment)
    _emit_tool_event(event_cb, "log", f"Preparing local install for {status['label']}", progress=2.0)
    spec = _resolve_download_spec(tool_key, environment=environment)
    if not spec:
        _emit_tool_event(
            event_cb,
            "log",
            status.get("manual_install") or "Portable install is not available on this host.",
            progress=100.0,
        )
        return {
            "ok": False,
            "changed": False,
            "message": status.get("manual_install") or "Portable install is not available on this host.",
            "status": status,
            "manual_only": True,
        }

    install_root = _tool_install_root(tool_key, spec)
    archive_path = (LOCAL_DOWNLOADS_ROOT / tool_key / spec["filename"]).expanduser()
    _emit_tool_event(
        event_cb,
        "log",
        f"Install root: {install_root}",
        progress=8.0,
        install_path=str(install_root),
    )
    if _portable_requires_download_only(spec):
        if dry_run:
            _emit_tool_event(
                event_cb,
                "progress",
                f"Dry run: package download only for {status['label']}",
                progress=100.0,
                download_url=spec["url"],
                download_path=str(archive_path),
            )
            return {
                "ok": True,
                "changed": False,
                "message": f"Dry run: download-only package {spec['url']} -> {archive_path}",
                "status": status,
                "download_url": spec["url"],
                "download_path": str(archive_path),
                "manual_only": True,
            }
        downloaded = _download_file(spec["url"], archive_path, event_cb=event_cb, progress_range=(15.0, 100.0))
        return {
            "ok": False,
            "changed": True,
            "message": (
                f"Downloaded {status['label']} installer package to {downloaded}. "
                "Manual completion is still required on this platform."
            ),
            "status": status,
            "download_url": spec["url"],
            "download_path": str(downloaded),
            "manual_only": True,
        }

    if dry_run:
        _emit_tool_event(
            event_cb,
            "progress",
            (
                f"Dry run: would download {spec['filename']} and install it locally under "
                f"{install_root}"
            ),
            progress=100.0,
            download_url=spec["url"],
            download_path=str(archive_path),
            install_path=str(install_root),
        )
        return {
            "ok": True,
            "changed": False,
            "message": (
                f"Dry run: download {spec['url']} -> {archive_path} and install into "
                f"{install_root}"
            ),
            "status": status,
            "download_url": spec["url"],
            "download_path": str(archive_path),
            "install_path": str(install_root),
            "portable": True,
        }

    downloaded = _download_file(spec["url"], archive_path, event_cb=event_cb, progress_range=(10.0, 55.0))
    install_root.mkdir(parents=True, exist_ok=True)
    _emit_tool_event(
        event_cb,
        "log",
        f"Installing {status['label']} using mode {spec['install_mode']}",
        progress=60.0,
    )

    actual_executable = None
    install_mode = spec["install_mode"]
    if install_mode == "zip-extract":
        _emit_tool_event(event_cb, "log", f"Extracting ZIP archive into {install_root}", progress=68.0)
        with zipfile.ZipFile(downloaded) as archive:
            archive.extractall(install_root)
        actual_executable = _find_first_match(install_root, spec.get("entry_globs", []))
    elif install_mode == "tar-extract":
        _emit_tool_event(event_cb, "log", f"Extracting tar archive into {install_root}", progress=68.0)
        with tarfile.open(downloaded, mode="r:*") as archive:
            archive.extractall(install_root)
        actual_executable = _find_first_match(install_root, spec.get("entry_globs", []))
    elif install_mode == "appimage":
        binary_path = install_root / spec["filename"]
        _emit_tool_event(event_cb, "log", f"Copying AppImage into {binary_path}", progress=72.0)
        shutil.copy2(downloaded, binary_path)
        binary_path.chmod(0o755)
        actual_executable = binary_path
    else:
        return {
            "ok": False,
            "changed": False,
            "message": f"Unsupported portable install mode: {install_mode}",
            "status": status,
        }

    if not actual_executable or not Path(actual_executable).exists():
        return {
            "ok": False,
            "changed": False,
            "message": f"Installed package for {status['label']} but could not locate the executable.",
            "status": status,
            "download_path": str(downloaded),
            "install_path": str(install_root),
        }

    _emit_tool_event(
        event_cb,
        "log",
        f"Creating local launcher wrappers for {actual_executable}",
        progress=88.0,
    )
    wrappers = _write_wrapper(tool_key, actual_executable)
    _emit_tool_event(
        event_cb,
        "progress",
        f"Installed {status['label']} locally",
        progress=100.0,
        install_path=str(install_root),
    )
    return {
        "ok": True,
        "changed": True,
        "message": (
            f"Installed {status['label']} locally in {install_root}. "
            f"Launcher wrapper: {wrappers[0]}"
        ),
        "status": status,
        "download_url": spec["url"],
        "download_path": str(downloaded),
        "install_path": str(install_root),
        "wrapper_paths": [str(path) for path in wrappers],
        "portable": True,
    }


def get_external_tool_status(tool_key, environment=None, executable_override=None):
    if tool_key not in THIRD_PARTY_TOOLS:
        raise ValueError(f"Unsupported external tool '{tool_key}'.")
    environment = environment or detect_host_environment()
    meta = THIRD_PARTY_TOOLS[tool_key]
    override = _resolve_override_candidate(executable_override)
    found = override if override and override.get("path") else _find_tool_path(tool_key)
    install_command, manager_key = build_install_command(tool_key, environment=environment, interactive=True)
    status = {
        "key": tool_key,
        "label": meta["label"],
        "installed": bool(found),
        "path": found["path"] if found else (override.get("requested_path") if override else None),
        "detected_via": found["source"] if found else (override.get("source") if override else None),
        "version": _probe_version(found["path"], meta.get("version_args")) if found else None,
        "install_supported": bool(install_command),
        "install_manager": manager_key,
        "install_manager_label": PACKAGE_MANAGERS[manager_key]["label"] if manager_key else None,
        "install_command": " ".join(install_command) if install_command else None,
        "manual_install": meta.get("manual_install"),
        "homepage": meta.get("homepage"),
        "download_url": meta.get("download_url"),
        "download_supported": _download_supported(tool_key, environment=environment),
        "portable_install_supported": _portable_install_supported(tool_key, environment=environment),
        "local_tool_root": str((LOCAL_TOOLS_ROOT / tool_key).expanduser()),
        "local_bin_root": str(LOCAL_BIN_ROOT.expanduser()),
        "override_active": bool(override),
        "override_path": override.get("requested_path") if override else None,
    }
    return status


def list_external_tool_install_methods(tool_key):
    if tool_key not in THIRD_PARTY_TOOLS:
        raise ValueError(f"Unsupported external tool '{tool_key}'.")
    meta = THIRD_PARTY_TOOLS[tool_key]
    methods = []
    for manager_key, recipe in meta.get("install", {}).items():
        manager = PACKAGE_MANAGERS[manager_key]
        prefix = list(manager["cask_prefix"] if recipe.get("cask") else manager["install_prefix"])
        command = prefix + [recipe["package"]]
        methods.append(
            {
                "manager": manager_key,
                "manager_label": manager["label"],
                "package": recipe["package"],
                "command": command,
            }
        )
    return methods


def list_external_tool_presets(tool_key):
    if tool_key not in THIRD_PARTY_TOOLS:
        raise ValueError(f"Unsupported external tool '{tool_key}'.")
    profile = _get_tool_workbench_profile(tool_key)
    return [dict(item) for item in profile.get("presets", [])]


def _resolve_tool_args(arg_tokens, target_path=None):
    resolved = []
    target_text = str(Path(target_path).expanduser()) if target_path else None
    for token in arg_tokens:
        value = str(token)
        if "{file}" in value:
            if not target_text:
                raise ValueError("This command requires a target binary path.")
            value = value.replace("{file}", target_text)
        resolved.append(value)
    return resolved


def _normalize_tool_args(args):
    if args is None:
        return []
    if isinstance(args, str):
        return shlex.split(args)
    return [str(item) for item in args]


def get_external_tool_workbench_model(tool_key, target_path=None, environment=None, executable_override=None):
    if tool_key not in THIRD_PARTY_TOOLS:
        raise ValueError(f"Unsupported external tool '{tool_key}'.")
    environment = environment or detect_host_environment()
    status = get_external_tool_status(
        tool_key,
        environment=environment,
        executable_override=executable_override,
    )
    profile = _get_tool_workbench_profile(tool_key)
    return {
        "tool_key": tool_key,
        "status": status,
        "target_path": str(Path(target_path).expanduser()) if target_path else "",
        "executable_override": str(Path(executable_override).expanduser()) if executable_override else "",
        "cli_friendly": bool(profile.get("cli_friendly")),
        "launch_args": list(profile.get("launch_args", [])),
        "presets": list_external_tool_presets(tool_key),
    }


def run_external_tool_command(
    tool_key,
    args=None,
    target_path=None,
    dry_run=False,
    environment=None,
    event_cb=None,
    cwd=None,
    executable_override=None,
):
    environment = environment or detect_host_environment()
    status = get_external_tool_status(
        tool_key,
        environment=environment,
        executable_override=executable_override,
    )
    if not status.get("installed"):
        _emit_tool_event(
            event_cb,
            "log",
            f"{status['label']} is not installed on this host.",
            progress=100.0,
        )
        return {
            "ok": False,
            "changed": False,
            "message": f"{status['label']} is not installed on this host.",
            "status": status,
        }

    arg_tokens = _normalize_tool_args(args)
    if not arg_tokens:
        return {
            "ok": False,
            "changed": False,
            "message": "No command arguments provided.",
            "status": status,
        }
    resolved_args = _resolve_tool_args(arg_tokens, target_path=target_path)
    command = [status["path"], *resolved_args]
    _emit_tool_event(
        event_cb,
        "log",
        f"Preparing tool command for {status['label']}",
        progress=5.0,
        command=command,
    )
    if dry_run:
        _emit_tool_event(
            event_cb,
            "progress",
            f"Dry run: {' '.join(command)}",
            progress=100.0,
            command=command,
        )
        return {
            "ok": True,
            "changed": False,
            "message": f"Dry run: {' '.join(command)}",
            "status": status,
            "command": command,
        }

    start_progress, end_progress = 10.0, 100.0
    _emit_tool_event(
        event_cb,
        "log",
        f"Running {status['label']} command",
        progress=start_progress,
        command=command,
    )
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
    )
    output = "\n".join(
        chunk for chunk in [(completed.stdout or "").strip(), (completed.stderr or "").strip()] if chunk
    ).strip()
    if output:
        for line in output.splitlines():
            _emit_tool_event(event_cb, "log", line, progress=80.0)
    ok = completed.returncode == 0
    _emit_tool_event(
        event_cb,
        "progress",
        f"{status['label']} command {'completed' if ok else 'failed'}",
        progress=end_progress,
        returncode=completed.returncode,
    )
    return {
        "ok": ok,
        "changed": False,
        "message": f"{status['label']} command {'completed' if ok else 'failed'}.",
        "status": status,
        "command": command,
        "returncode": completed.returncode,
        "output": output,
    }


def launch_external_tool(
    tool_key,
    target_path=None,
    args=None,
    dry_run=False,
    environment=None,
    event_cb=None,
    cwd=None,
    executable_override=None,
):
    environment = environment or detect_host_environment()
    status = get_external_tool_status(
        tool_key,
        environment=environment,
        executable_override=executable_override,
    )
    if not status.get("installed"):
        _emit_tool_event(
            event_cb,
            "log",
            f"{status['label']} is not installed on this host.",
            progress=100.0,
        )
        return {
            "ok": False,
            "changed": False,
            "message": f"{status['label']} is not installed on this host.",
            "status": status,
        }

    profile = _get_tool_workbench_profile(tool_key)
    arg_tokens = _normalize_tool_args(args)
    if not arg_tokens:
        arg_tokens = list(profile.get("launch_args", []))
    resolved_args = _resolve_tool_args(arg_tokens, target_path=target_path)
    command = [status["path"], *resolved_args]
    _emit_tool_event(
        event_cb,
        "log",
        f"Preparing external launch for {status['label']}",
        progress=10.0,
        command=command,
    )
    if dry_run:
        _emit_tool_event(
            event_cb,
            "progress",
            f"Dry run: {' '.join(command)}",
            progress=100.0,
            command=command,
        )
        return {
            "ok": True,
            "changed": False,
            "message": f"Dry run: {' '.join(command)}",
            "status": status,
            "command": command,
        }

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        cwd=cwd,
        start_new_session=(os.name != "nt"),
        creationflags=creationflags,
    )
    _emit_tool_event(
        event_cb,
        "progress",
        f"Launched {status['label']} (pid={process.pid})",
        progress=100.0,
        pid=process.pid,
    )
    return {
        "ok": True,
        "changed": False,
        "message": f"Launched {status['label']} (pid={process.pid}).",
        "status": status,
        "command": command,
        "pid": process.pid,
    }


def describe_external_tool(tool_key, environment=None):
    environment = environment or detect_host_environment()
    status = get_external_tool_status(tool_key, environment=environment)
    meta = THIRD_PARTY_TOOLS[tool_key]
    host_command, host_manager = build_install_command(tool_key, environment=environment, interactive=True)
    download_spec = None
    try:
        download_spec = _resolve_download_spec(tool_key, environment=environment)
    except Exception:
        download_spec = None
    return {
        "status": status,
        "homepage": meta.get("homepage"),
        "download_url": meta.get("download_url"),
        "manual_install": meta.get("manual_install"),
        "host_install_command": host_command,
        "host_install_manager": host_manager,
        "install_methods": list_external_tool_install_methods(tool_key),
        "download_supported": status["download_supported"],
        "portable_install_supported": status["portable_install_supported"],
        "local_tool_root": status["local_tool_root"],
        "local_bin_root": status["local_bin_root"],
        "resolved_download_url": download_spec.get("url") if download_spec else None,
        "resolved_download_filename": download_spec.get("filename") if download_spec else None,
    }


def render_external_tool_detail_lines(tool_key, environment=None):
    detail = describe_external_tool(tool_key, environment=environment)
    status = detail["status"]
    lines = [f"{status['label']} ({tool_key})"]
    lines.append(f"  installed: {'yes' if status['installed'] else 'no'}")
    if status.get("path"):
        lines.append(f"  path: {status['path']}")
    if status.get("version"):
        lines.append(f"  version: {status['version']}")
    if detail.get("homepage"):
        lines.append(f"  homepage: {detail['homepage']}")
    if detail.get("download_url"):
        lines.append(f"  download_page: {detail['download_url']}")
    if detail.get("resolved_download_url"):
        lines.append(f"  resolved_package: {detail['resolved_download_url']}")
    if detail.get("resolved_download_filename"):
        lines.append(f"  package_name: {detail['resolved_download_filename']}")
    if detail.get("host_install_command"):
        lines.append(
            "  host_install: "
            f"{PACKAGE_MANAGERS[detail['host_install_manager']]['label']} -> {' '.join(detail['host_install_command'])}"
        )
    else:
        lines.append("  host_install: unavailable on this host")
    lines.append(
        f"  one_click_local_install: {'yes' if detail.get('portable_install_supported') else 'no'}"
    )
    if detail.get("portable_install_supported"):
        lines.append(f"  local_install_root: {detail['local_tool_root']}")
        lines.append(f"  local_launcher_root: {detail['local_bin_root']}")
    methods = detail.get("install_methods", [])
    if methods:
        lines.append("  package_methods:")
        for method in methods:
            lines.append(f"    - {method['manager_label']}: {' '.join(method['command'])}")
    manual_install = detail.get("manual_install")
    if manual_install:
        lines.append(f"  manual: {manual_install}")
    return lines


def collect_external_tool_status(environment=None):
    environment = environment or detect_host_environment()
    tool_keys = list(THIRD_PARTY_TOOLS)
    max_workers = min(4, max(1, len(tool_keys)))
    indexed = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(get_external_tool_status, tool_key, environment=environment): (index, tool_key)
            for index, tool_key in enumerate(tool_keys)
        }
        for future, (index, tool_key) in futures.items():
            try:
                indexed[index] = future.result()
            except Exception as exc:
                meta = THIRD_PARTY_TOOLS[tool_key]
                indexed[index] = {
                    "key": tool_key,
                    "label": meta["label"],
                    "installed": False,
                    "path": None,
                    "detected_via": None,
                    "version": None,
                    "install_supported": False,
                    "install_manager": None,
                    "install_manager_label": None,
                    "install_command": None,
                    "manual_install": f"Status probe failed: {exc}",
                    "homepage": meta.get("homepage"),
                    "download_url": meta.get("download_url"),
                    "download_supported": _download_supported(tool_key, environment=environment),
                    "portable_install_supported": _portable_install_supported(tool_key, environment=environment),
                    "local_tool_root": str((LOCAL_TOOLS_ROOT / tool_key).expanduser()),
                    "local_bin_root": str(LOCAL_BIN_ROOT.expanduser()),
                }
    tools = [indexed[index] for index in range(len(tool_keys))]
    return {"environment": environment, "tools": tools}


def render_external_tool_status_lines(snapshot):
    environment = snapshot.get("environment", {})
    lines = [
        f"Host OS: {environment.get('os_label', 'Unknown')}",
        f"Architecture: {environment.get('arch', 'Unknown')}",
        f"Package manager: {environment.get('primary_package_manager_label', 'None detected')}",
    ]
    distro = environment.get("distro")
    if distro:
        lines.append(f"Linux distro: {distro}")
    lines.append("")
    lines.append("External tools:")
    for item in snapshot.get("tools", []):
        if item.get("installed"):
            detail = item.get("path") or "installed"
            version = item.get("version")
            suffix = f" version={version}" if version else ""
            lines.append(f"- {item['label']}: installed ({detail}){suffix}")
            continue
        if item.get("portable_install_supported"):
            lines.append(
                f"- {item['label']}: missing, one-click local install available under {item['local_tool_root']}"
            )
        elif item.get("install_supported"):
            lines.append(
                f"- {item['label']}: missing, install via {item.get('install_manager_label')} -> "
                f"{item.get('install_command')}"
            )
        elif item.get("download_supported"):
            lines.append(
                f"- {item['label']}: missing, downloadable package available from {item.get('download_url')}"
            )
        else:
            lines.append(
                f"- {item['label']}: missing, manual install required. {item.get('manual_install')}"
            )
    return lines


def install_external_tool(tool_key, dry_run=False, environment=None, event_cb=None):
    environment = environment or detect_host_environment()
    status = get_external_tool_status(tool_key, environment=environment)
    _emit_tool_event(event_cb, "log", f"Preparing install for {status['label']}", progress=2.0)
    if status["installed"]:
        _emit_tool_event(
            event_cb,
            "progress",
            f"{status['label']} is already installed at {status['path']}",
            progress=100.0,
        )
        return {
            "ok": True,
            "changed": False,
            "message": f"{status['label']} is already installed.",
            "status": status,
        }

    if tool_key == "bramble" and status["portable_install_supported"]:
        _emit_tool_event(
            event_cb,
            "log",
            f"Using ELFexplorer-managed source build path for {status['label']}",
            progress=10.0,
        )
        return _install_bramble_from_source(
            environment=environment,
            dry_run=dry_run,
            event_cb=event_cb,
        )

    command, manager_key = build_install_command(tool_key, environment=environment, interactive=False)
    display_command, _ = build_install_command(tool_key, environment=environment, interactive=True)
    prefer_portable = status["portable_install_supported"] and (
        not command
        or (
            manager_key
            and PACKAGE_MANAGERS[manager_key]["requires_root"]
            and os.name == "posix"
            and getattr(os, "geteuid", lambda: 1)() != 0
        )
    )

    if prefer_portable:
        _emit_tool_event(
            event_cb,
            "log",
            f"Using ELFexplorer-managed local install path for {status['label']}",
            progress=10.0,
        )
        return _install_portable_tool(
            tool_key,
            environment=environment,
            dry_run=dry_run,
            event_cb=event_cb,
        )

    if not command:
        if status["portable_install_supported"]:
            _emit_tool_event(
                event_cb,
                "log",
                f"No package-manager recipe selected; falling back to local install for {status['label']}",
                progress=10.0,
            )
            return _install_portable_tool(
                tool_key,
                environment=environment,
                dry_run=dry_run,
                event_cb=event_cb,
            )
        _emit_tool_event(
            event_cb,
            "log",
            status.get("manual_install") or "Automatic install is not available on this host.",
            progress=100.0,
        )
        return {
            "ok": False,
            "changed": False,
            "message": status.get("manual_install") or "Automatic install is not available on this host.",
            "status": status,
            "manual_only": True,
        }

    if dry_run:
        _emit_tool_event(
            event_cb,
            "progress",
            f"Dry run: {' '.join(display_command)}",
            progress=100.0,
            command=display_command,
        )
        return {
            "ok": True,
            "changed": False,
            "message": f"Dry run: {' '.join(display_command)}",
            "status": status,
            "command": display_command,
            "manager": manager_key,
        }

    returncode, output = _run_logged_subprocess(
        command,
        event_cb=event_cb,
        progress_range=(15.0, 95.0),
    )
    ok = returncode == 0
    _emit_tool_event(
        event_cb,
        "progress",
        f"{status['label']} install {'completed' if ok else 'failed'}",
        progress=100.0,
        command=display_command,
    )
    if ok:
        return {
            "ok": True,
            "changed": True,
            "message": f"Installed {status['label']} using {PACKAGE_MANAGERS[manager_key]['label']}.",
            "status": status,
            "command": display_command,
            "manager": manager_key,
            "returncode": returncode,
            "output": output,
        }

    if status["portable_install_supported"]:
        _emit_tool_event(
            event_cb,
            "log",
            f"Package-manager install failed; attempting local fallback for {status['label']}",
            progress=96.0,
        )
        fallback = _install_portable_tool(
            tool_key,
            environment=environment,
            dry_run=dry_run,
            event_cb=event_cb,
        )
        fallback_output = output
        if fallback.get("output"):
            fallback_output = "\n".join([fallback_output, fallback["output"]]).strip()
        fallback["message"] = (
            f"Package-manager install failed; attempted local install fallback. {fallback['message']}"
        )
        if fallback_output:
            fallback["output"] = fallback_output
        return fallback

    return {
        "ok": False,
        "changed": False,
        "message": (
            f"Install failed for {status['label']}. "
            f"Run manually if needed: {' '.join(display_command)}"
        ),
        "status": status,
        "command": display_command,
        "manager": manager_key,
        "returncode": returncode,
        "output": output,
    }
