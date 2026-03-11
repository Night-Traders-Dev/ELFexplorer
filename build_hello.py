#!/usr/bin/env python3

"""
Build and sync hello-multilang ELF fixtures into test-bin/.

Workflow:
1. Build Docker image for hello-multilang.
2. Run hello-multilang build.sh inside Docker for selected architectures.
3. Copy produced hello_* ELFs from hello-multilang/output/<arch>/ to test-bin/<arch>/.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ALL_ARCHES = ("x86", "x86_64", "arm32", "aarch64", "rv32", "rv64")


def run_cmd(cmd: list[str], cwd: Path, dry_run: bool) -> None:
    print(f"[run] ({cwd}) {' '.join(cmd)}")
    if dry_run:
        return
    subprocess.run(cmd, cwd=str(cwd), check=True)


def parse_arches(raw_arches: list[str] | None, include_all: bool) -> list[str]:
    if include_all or not raw_arches:
        return list(ALL_ARCHES)

    seen = set()
    selected = []
    for raw in raw_arches:
        for arch in (part.strip() for part in raw.split(",")):
            if not arch:
                continue
            if arch not in ALL_ARCHES:
                raise ValueError(f"Unsupported arch: {arch}. Allowed: {', '.join(ALL_ARCHES)}")
            if arch in seen:
                continue
            seen.add(arch)
            selected.append(arch)
    return selected


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def sync_arch_outputs(
    hello_output_root: Path,
    test_bin_root: Path,
    arches: list[str],
    dry_run: bool,
) -> tuple[int, list[str]]:
    copied = 0
    warnings: list[str] = []

    for arch in arches:
        src_dir = hello_output_root / arch
        dst_dir = test_bin_root / arch

        if not src_dir.is_dir():
            warnings.append(f"Missing output directory for arch '{arch}': {src_dir}")
            continue

        print(f"[sync] {arch}: {src_dir} -> {dst_dir}")
        if not dry_run:
            dst_dir.mkdir(parents=True, exist_ok=True)

            for stale in dst_dir.glob("hello_*"):
                if stale.is_file():
                    stale.unlink()

        sources = sorted(path for path in src_dir.glob("hello_*") if path.is_file())
        if not sources:
            warnings.append(f"No hello_* binaries produced for arch '{arch}'")
            continue

        for src in sources:
            if not is_elf(src):
                warnings.append(f"Skipping non-ELF artifact: {src}")
                continue

            dst = dst_dir / src.name
            print(f"  - {src.name}")
            if not dry_run:
                shutil.copy2(src, dst)
            copied += 1

    return copied, warnings


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Build hello-multilang in Docker and sync hello_* ELFs into test-bin/",
    )
    parser.add_argument(
        "--arch",
        action="append",
        help="Architecture name, repeatable or comma-separated (example: --arch x86_64,rv64).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Build all supported architectures (default if --arch is omitted).",
    )
    parser.add_argument(
        "--skip-image-build",
        action="store_true",
        help="Skip docker-build.sh.",
    )
    parser.add_argument(
        "--skip-docker-run",
        action="store_true",
        help="Skip docker-run.sh and only sync existing output/ artifacts.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without executing commands or writing files.",
    )
    parser.add_argument(
        "--hello-root",
        type=Path,
        default=script_dir / "hello-multilang",
        help="Path to hello-multilang project root.",
    )
    parser.add_argument(
        "--test-bin-root",
        type=Path,
        default=script_dir / "test-bin",
        help="Destination root for corpus binaries.",
    )

    args = parser.parse_args()

    try:
        arches = parse_arches(args.arch, args.all)
    except ValueError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    hello_root = args.hello_root.resolve()
    output_root = hello_root / "output"
    test_bin_root = args.test_bin_root.resolve()

    if not hello_root.is_dir():
        print(f"[error] hello-multilang root not found: {hello_root}", file=sys.stderr)
        return 2

    if not args.skip_image_build:
        run_cmd(["bash", "./docker-build.sh"], cwd=hello_root, dry_run=args.dry_run)

    if not args.skip_docker_run:
        if arches == list(ALL_ARCHES):
            run_args = ["bash", "./docker-run.sh", "--all"]
        else:
            run_args = ["bash", "./docker-run.sh", "--arch", ",".join(arches)]
        run_cmd(run_args, cwd=hello_root, dry_run=args.dry_run)

    copied, warnings = sync_arch_outputs(
        hello_output_root=output_root,
        test_bin_root=test_bin_root,
        arches=arches,
        dry_run=args.dry_run,
    )

    print(f"[done] copied {copied} ELF binaries into {test_bin_root}")
    for warning in warnings:
        print(f"[warn] {warning}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
