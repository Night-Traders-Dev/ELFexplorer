#!/usr/bin/env python3

"""
install_deps.py

Install ELFexplorer dependencies by profile/group.
"""

from __future__ import annotations

import argparse
import subprocess
import sys


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
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.print_groups:
        print("Available dependency groups:")
        for group_name, packages in DEPENDENCY_GROUPS.items():
            print(f"  {group_name}: {', '.join(packages)}")
        return 0

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
