#!/usr/bin/env bash
set -euo pipefail
echo "==> ruff check"
ruff check src/ tests/
echo "==> ruff format check"
ruff format --check src/ tests/
echo "==> mypy"
mypy src/
echo "==> All checks passed"
