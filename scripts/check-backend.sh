#!/usr/bin/env bash
# Canonical backend validation commands. Run locally after
# `pip install -e ".[dev]"` (see README.md), and invoked verbatim by
# .github/workflows/ci.yml so local and CI checks never drift apart.
#
# Covers: docs/IMPLEMENTATION-ROADMAP.md Phase 1.2 backend CI requirements
# (Ruff, Ruff format, Pyright, pytest, import-linter). pytest already
# includes tests/architecture/test_layer_boundaries.py, which itself also
# runs import-linter (docs/ADR/0001-..., docs/ADR/0011-...); `lint-imports`
# is run again here directly per the explicit Phase 1.2 CI requirement.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== ruff check =="
ruff check .

echo "== ruff format --check =="
ruff format --check .

echo "== pyright =="
pyright

echo "== pytest =="
pytest

echo "== import-linter (lint-imports) =="
lint-imports
