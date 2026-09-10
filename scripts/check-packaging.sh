#!/usr/bin/env bash
# Packaging validation gate (SaaS OS packaging implementation phase):
# builds a real, non-editable `saas-os` wheel and proves it actually
# ships every nested subpackage and the migration environment -- the
# defect class `tests/test_wheel_contents.py` exists to catch (a flat,
# top-level-only `[tool.setuptools] packages` list silently built wheels
# missing every subpackage; `pip install -e .` never surfaced this).
#
# Kept OUT of check-all.sh, matching check-docker.sh/check-migrations.sh's
# own precedent: builds a real wheel and a real venv via subprocesses,
# unlike everything else check-all.sh runs. Run explicitly, or via CI's
# `packaging` job.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== packaging: wheel contents + isolated non-editable install =="
pytest -m packaging tests/test_wheel_contents.py
