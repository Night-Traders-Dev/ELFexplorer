#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
TOOLCHAIN_DIR="$SCRIPT_DIR/cmake/toolchains"
BUILD_ROOT="$SRC_DIR/build"
OUT_ROOT="$SCRIPT_DIR/output"

ALL_ARCHES=(x86 x86_64 arm32 aarch64 rv32 rv64)

usage() {
    cat <<EOF
Usage:
  ./build.sh --all
  ./build.sh --arch x86_64
  ./build.sh --arch x86_64,aarch64
  ./build.sh x86_64 aarch64
EOF
}

die() {
    echo "[!] $*" >&2
    exit 1
}

info() {
    echo "[*] $*"
}

warn() {
    echo "[!] $*" >&2
}

is_valid_arch() {
    local a="$1"
    for valid in "${ALL_ARCHES[@]}"; do
        [[ "$a" == "$valid" ]] && return 0
    done
    return 1
}

toolchain_file_for_arch() {
    echo "$TOOLCHAIN_DIR/$1.cmake"
}

goarch_for_arch() {
    case "$1" in
        x86) echo "386" ;;
        x86_64) echo "amd64" ;;
        arm32) echo "arm" ;;
        aarch64) echo "arm64" ;;
        rv32) echo "riscv64" ;;
        rv64) echo "riscv64" ;;
        *) return 1 ;;
    esac
}

rust_target_for_arch() {
    case "$1" in
        x86) echo "i686-unknown-linux-gnu" ;;
        x86_64) echo "x86_64-unknown-linux-gnu" ;;
        arm32) echo "armv7-unknown-linux-gnueabihf" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
        rv32) echo "riscv32gc-unknown-linux-gnu" ;;
        rv64) echo "riscv64gc-unknown-linux-gnu" ;;
        *) return 1 ;;
    esac
}

configure_cross_env() {
    local arch="$1"

    export TARGET_ARCH="$arch"
    export GOOS=linux
    export GOARCH="$(goarch_for_arch "$arch" || true)"
    export RUST_TARGET="$(rust_target_for_arch "$arch" || true)"

    case "$arch" in
        arm32) export GOARM=7 ;;
        *) unset GOARM 2>/dev/null || true ;;
    esac
}

build_one_arch() {
    local arch="$1"
    local build_dir="$BUILD_ROOT/$arch"
    local out_dir="$OUT_ROOT/$arch"
    local toolchain

    toolchain="$(toolchain_file_for_arch "$arch")"
    [[ -f "$toolchain" ]] || die "Missing toolchain file for '$arch': $toolchain"

    rm -rf "$build_dir" "$out_dir"
    mkdir -p "$build_dir" "$out_dir"

    configure_cross_env "$arch"

    info "Configuring $arch"
    cmake -S "$SRC_DIR" -B "$build_dir" \
        -DCMAKE_TOOLCHAIN_FILE="$toolchain" \
        -DTARGET_ARCH="$arch"

    info "Building $arch"
    cmake --build "$build_dir" -j"$(nproc)"

    for bin in hello_c hello_cpp hello_go hello_rust hello_dart hello_asm; do
        if [[ -f "$build_dir/$bin" ]]; then
            cp "$build_dir/$bin" "$out_dir/"
        fi
    done

    info "Output -> $out_dir"
    ls -1 "$out_dir" 2>/dev/null || true
    echo
}

main() {
    local -a selected=()
    local -a arches=()
    local seen=""
    local a

    [[ $# -gt 0 ]] || { usage; exit 1; }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all)
                selected=("${ALL_ARCHES[@]}")
                shift
                ;;
            --arch)
                [[ $# -ge 2 ]] || die "--arch requires a value"
                IFS=',' read -r -a tmp <<< "$2"
                selected+=("${tmp[@]}")
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                selected+=("$1")
                shift
                ;;
        esac
    done

    [[ ${#selected[@]} -gt 0 ]] || die "No architectures selected"

    for a in "${selected[@]}"; do
        is_valid_arch "$a" || die "Unsupported arch: $a"
        if [[ " $seen " != *" $a "* ]]; then
            arches+=("$a")
            seen="$seen $a"
        fi
    done

    rm -rf "$OUT_ROOT"
    mkdir -p "$OUT_ROOT"

    for a in "${arches[@]}"; do
        build_one_arch "$a"
    done

    info "Done."
}

main "$@"
