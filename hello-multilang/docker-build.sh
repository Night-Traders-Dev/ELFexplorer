#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="hello-multilang-builder"

docker build -t "$IMAGE_NAME" .
