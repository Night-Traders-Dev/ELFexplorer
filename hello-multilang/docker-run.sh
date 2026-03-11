#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="hello-multilang-builder"

docker run --rm -it \
    -v "$(pwd):/work" \
    -w /work \
    "$IMAGE_NAME" \
    bash ./build.sh "$@"
