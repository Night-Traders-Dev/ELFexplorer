#!/usr/bin/env bash
set -euo pipefail

ARCH="${1:?arch required}"
BIN="${2:?binary path required}"

case "$ARCH" in
    x86)
        exec qemu-i386 "$BIN"
        ;;
    x86_64)
        exec qemu-x86_64 "$BIN"
        ;;
    arm32)
        exec qemu-arm "$BIN"
        ;;
    aarch64)
        exec qemu-aarch64 "$BIN"
        ;;
    rv32)
        exec qemu-riscv32 "$BIN"
        ;;
    rv64)
        exec qemu-riscv64 "$BIN"
        ;;
    *)
        echo "unsupported arch: $ARCH" >&2
        exit 1
        ;;
esac
