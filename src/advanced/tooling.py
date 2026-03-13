from __future__ import annotations

import os
import platform
import shutil
import subprocess
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

THIRD_PARTY_TOOLS = {
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


def list_external_tools():
    return dict(THIRD_PARTY_TOOLS)


def _normalize_os(system_name: str | None = None):
    value = (system_name or platform.system() or "").strip().lower()
    if value == "darwin":
        return "macos"
    if value == "windows":
        return "windows"
    if value == "linux":
        return "linux"
    return value or "unknown"


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
            yield from expanded.parent.glob(expanded.name)
            continue
        yield expanded


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
    for path in _iter_hint_paths(meta.get("path_hints", ())):
        if path.exists():
            return {"path": str(path), "source": "hint"}
    return None


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


def get_external_tool_status(tool_key, environment=None):
    if tool_key not in THIRD_PARTY_TOOLS:
        raise ValueError(f"Unsupported external tool '{tool_key}'.")
    environment = environment or detect_host_environment()
    meta = THIRD_PARTY_TOOLS[tool_key]
    found = _find_tool_path(tool_key)
    install_command, manager_key = build_install_command(tool_key, environment=environment, interactive=True)
    status = {
        "key": tool_key,
        "label": meta["label"],
        "installed": bool(found),
        "path": found["path"] if found else None,
        "detected_via": found["source"] if found else None,
        "version": _probe_version(found["path"], meta.get("version_args")) if found else None,
        "install_supported": bool(install_command),
        "install_manager": manager_key,
        "install_manager_label": PACKAGE_MANAGERS[manager_key]["label"] if manager_key else None,
        "install_command": " ".join(install_command) if install_command else None,
        "manual_install": meta.get("manual_install"),
        "homepage": meta.get("homepage"),
        "download_url": meta.get("download_url"),
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


def describe_external_tool(tool_key, environment=None):
    status = get_external_tool_status(tool_key, environment=environment)
    meta = THIRD_PARTY_TOOLS[tool_key]
    host_command, host_manager = build_install_command(tool_key, environment=environment, interactive=True)
    return {
        "status": status,
        "homepage": meta.get("homepage"),
        "download_url": meta.get("download_url"),
        "manual_install": meta.get("manual_install"),
        "host_install_command": host_command,
        "host_install_manager": host_manager,
        "install_methods": list_external_tool_install_methods(tool_key),
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
        lines.append(f"  download: {detail['download_url']}")
    if detail.get("host_install_command"):
        lines.append(
            "  host_install: "
            f"{PACKAGE_MANAGERS[detail['host_install_manager']]['label']} -> {' '.join(detail['host_install_command'])}"
        )
    else:
        lines.append("  host_install: unavailable on this host")
    methods = detail.get("install_methods", [])
    if methods:
        lines.append("  package_methods:")
        for method in methods:
            lines.append(
                f"    - {method['manager_label']}: {' '.join(method['command'])}"
            )
    manual_install = detail.get("manual_install")
    if manual_install:
        lines.append(f"  manual: {manual_install}")
    return lines


def collect_external_tool_status(environment=None):
    environment = environment or detect_host_environment()
    tools = [get_external_tool_status(tool_key, environment=environment) for tool_key in THIRD_PARTY_TOOLS]
    return {"environment": environment, "tools": tools}


def render_external_tool_status_lines(snapshot):
    environment = snapshot.get("environment", {})
    lines = [
        f"Host OS: {environment.get('os_label', 'Unknown')}",
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
        if item.get("install_supported"):
            lines.append(
                f"- {item['label']}: missing, install via {item.get('install_manager_label')} -> "
                f"{item.get('install_command')}"
            )
        else:
            lines.append(
                f"- {item['label']}: missing, manual install required. {item.get('manual_install')}"
            )
    return lines


def install_external_tool(tool_key, dry_run=False, environment=None):
    environment = environment or detect_host_environment()
    status = get_external_tool_status(tool_key, environment=environment)
    if status["installed"]:
        return {
            "ok": True,
            "changed": False,
            "message": f"{status['label']} is already installed.",
            "status": status,
        }

    command, manager_key = build_install_command(tool_key, environment=environment, interactive=False)
    if not command:
        return {
            "ok": False,
            "changed": False,
            "message": status.get("manual_install") or "Automatic install is not available on this host.",
            "status": status,
            "manual_only": True,
        }

    display_command, _ = build_install_command(tool_key, environment=environment, interactive=True)
    if dry_run:
        return {
            "ok": True,
            "changed": False,
            "message": f"Dry run: {' '.join(display_command)}",
            "status": status,
            "command": display_command,
            "manager": manager_key,
        }

    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    ok = completed.returncode == 0
    output = (completed.stdout or completed.stderr or "").strip()
    if ok:
        message = f"Installed {status['label']} using {PACKAGE_MANAGERS[manager_key]['label']}."
    else:
        message = (
            f"Install failed for {status['label']}. "
            f"Run manually if needed: {' '.join(display_command)}"
        )
    return {
        "ok": ok,
        "changed": ok,
        "message": message,
        "status": status,
        "command": display_command,
        "manager": manager_key,
        "returncode": completed.returncode,
        "output": output,
    }
