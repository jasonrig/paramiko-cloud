#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

command -v docker >/dev/null
command -v ssh >/dev/null
docker info >/dev/null

uv sync --frozen --no-build --no-install-project --inexact --group dev
uv run --frozen --no-build --no-sync python scripts/build_proto.py

RUN_OPENSSH_INTEGRATION=1 \
    uv run --frozen --no-build --no-sync \
    pytest -m integration tests/integration "$@"
