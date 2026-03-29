#!/usr/bin/env bash
set -euo pipefail
pytest tests/ -v --cov=vindicara --cov-report=term-missing "$@"
