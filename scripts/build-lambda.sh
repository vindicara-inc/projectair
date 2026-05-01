#!/usr/bin/env bash
# Build the Lambda deployment artifact at lambda_package/ for VindicaraAPI.
#
# Produces a directory containing the `vindicara` package and all runtime
# dependencies from the [api] extra, targeting Amazon Linux 2023 (Python 3.13
# Lambda runtime, x86_64). Run from anywhere; resolves to repo root.
#
# Output: <repo>/lambda_package/  (gitignored)
# Consumed by: src/vindicara/infra/stacks/api_stack.py:34
#              lambda_.Code.from_asset("lambda_package")
#
# Why --platform manylinux2014_x86_64: bcrypt and cryptography ship native
# wheels. Building on macOS without --platform produces darwin wheels that
# fail to import inside the Linux Lambda runtime. manylinux2014_x86_64 wheels
# are forward-compatible with Amazon Linux 2023's glibc.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="$REPO_ROOT/lambda_package"

cd "$REPO_ROOT"

echo "==> Cleaning $PKG_DIR"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"

echo "==> Installing vindicara[api] into $PKG_DIR (manylinux2014_x86_64, py3.13)"
pip install \
  --target "$PKG_DIR" \
  --platform manylinux2014_x86_64 \
  --only-binary=:all: \
  --python-version 3.13 \
  --implementation cp \
  --upgrade \
  ".[api]"

echo "==> Trimming bytecode caches and test directories"
find "$PKG_DIR" -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
find "$PKG_DIR" -type d -name "tests" -prune -exec rm -rf {} + 2>/dev/null || true
find "$PKG_DIR" -type d -name "*.dist-info" -prune -exec sh -c 'rm -rf "$1"/RECORD' _ {} \; 2>/dev/null || true

SIZE=$(du -sh "$PKG_DIR" | awk '{print $1}')
echo "==> lambda_package built: $SIZE"
echo "==> Sanity check: handler import path"
test -f "$PKG_DIR/vindicara/lambda_handler.py" \
  && echo "    found vindicara/lambda_handler.py" \
  || { echo "ERROR: vindicara/lambda_handler.py missing in $PKG_DIR" >&2; exit 1; }
