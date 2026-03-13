#!/usr/bin/env python3

"""
install_deps.py

Install ELFexplorer dependencies by profile/group.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from advanced.tooling import (
    collect_external_tool_status,
    install_external_tool,
    describe_external_tool,
    list_external_tools,
)


DEPENDENCY_GROUPS = {
    "core": [
        "pyelftools",
    ],
    "ui": [
        "textual",
    ],
    "pdf": [
        "reportlab",
    ],
    "dev": [
        "ruff",
    ],
}

PROFILE_GROUPS = {
    "core": ("core",),
    "runtime": ("core", "ui", "pdf"),
    "all": ("core", "ui", "pdf", "dev"),
}


def resolve_packages(groups):
    ordered = []
    seen = set()
    for group in groups:
        for package in DEPENDENCY_GROUPS[group]:
            if package in seen:
                continue
            seen.add(package)
            ordered.append(package)
    return ordered


def build_install_cmd(python_executable, packages, upgrade=False):
    command = [python_executable, "-m", "pip", "install"]
    if upgrade:
        command.append("--upgrade")
    command.extend(packages)
    return command


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Install ELFexplorer dependencies.")
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILE_GROUPS.keys()),
        default="runtime",
        help="Dependency profile: core, runtime (default), or all.",
    )
    parser.add_argument(
        "--group",
        action="append",
        choices=tuple(DEPENDENCY_GROUPS.keys()),
        default=[],
        help="Additional dependency group(s) to install.",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable to use for pip install (default: current interpreter).",
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Pass --upgrade to pip.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the install command without executing it.",
    )
    parser.add_argument(
        "--print-groups",
        action="store_true",
        help="Print available groups and packages, then exit.",
    )
    parser.add_argument(
        "--print-tools",
        action="store_true",
        help="Print known external tool integrations and exit.",
    )
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Detect host OS/package manager and print external tool status.",
    )
    parser.add_argument(
        "--install-tool",
        action="append",
        choices=tuple(sorted(list_external_tools())),
        default=[],
        help="Install one or more external tools if supported on this host.",
    )
    parser.add_argument(
        "--tool-info",
        action="append",
        choices=tuple(sorted(list_external_tools())),
        default=[],
        help="Print download/install methods for one or more external tools.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.print_groups:
        print("Available dependency groups:")
        for group_name, packages in DEPENDENCY_GROUPS.items():
            print(f"  {group_name}: {', '.join(packages)}")
        return 0

    if args.print_tools:
        print("Known external tools:")
        for key, meta in sorted(list_external_tools().items()):
            print(f"  {key}: {meta['label']}")
        if not args.check_tools and not args.install_tool:
            return 0

    if args.check_tools:
        snapshot = collect_external_tool_status()
        environment = snapshot["environment"]
        print(f"Host OS: {environment.get('os_label', 'Unknown')}")
        print(f"Package manager: {environment.get('primary_package_manager_label', 'None detected')}")
        if environment.get("distro"):
            print(f"Linux distro: {environment['distro']}")
        print("External tool status:")
        for item in snapshot["tools"]:
            if item["installed"]:
                version = f" version={item['version']}" if item.get("version") else ""
                print(f"  - {item['label']}: installed at {item['path']}{version}")
            elif item["install_supported"]:
                print(f"  - {item['label']}: missing, install with {item['install_command']}")
            else:
                print(f"  - {item['label']}: missing, manual install required")
        if not args.install_tool:
            if not args.tool_info:
                return 0

    if args.tool_info:
        for tool_key in args.tool_info:
            detail = describe_external_tool(tool_key)
            status = detail["status"]
            print(f"Tool: {status['label']} ({tool_key})")
            print(f"Installed: {'yes' if status['installed'] else 'no'}")
            if status.get("path"):
                print(f"Path: {status['path']}")
            if status.get("version"):
                print(f"Version: {status['version']}")
            if detail.get("homepage"):
                print(f"Homepage: {detail['homepage']}")
            if detail.get("download_url"):
                print(f"Download: {detail['download_url']}")
            host_install = detail.get("host_install_command")
            if host_install:
                print("Host install:", " ".join(host_install))
            else:
                print("Host install: unavailable on this host")
            methods = detail.get("install_methods", [])
            if methods:
                print("Package-manager methods:")
                for method in methods:
                    print(f"  - {method['manager_label']}: {' '.join(method['command'])}")
            if detail.get("manual_install"):
                print("Manual:", detail["manual_install"])
            print()
        if not args.install_tool:
            return 0

    install_failures = 0
    for tool_key in args.install_tool:
        result = install_external_tool(tool_key, dry_run=args.dry_run)
        print(f"Tool: {result['status']['label']}")
        print(f"Result: {result['message']}")
        command = result.get("command")
        if command:
            print("Command:", " ".join(command))
        output = result.get("output")
        if output:
            print(output)
        if not result["ok"]:
            install_failures += 1

    if args.install_tool:
        return 1 if install_failures else 0

    selected_groups = list(PROFILE_GROUPS[args.profile])
    for group in args.group:
        if group not in selected_groups:
            selected_groups.append(group)

    packages = resolve_packages(selected_groups)
    command = build_install_cmd(args.python, packages, upgrade=args.upgrade)

    print(f"Selected profile: {args.profile}")
    print(f"Selected groups: {', '.join(selected_groups)}")
    print(f"Packages: {', '.join(packages)}")
    print("Command:", " ".join(command))

    if args.dry_run:
        return 0

    completed = subprocess.run(command, check=False)
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
