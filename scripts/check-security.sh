#!/usr/bin/env bash
# Dependency vulnerability scan + secret scan. Kept separate from
# check-backend.sh/check-frontend.sh: these are supply-chain/security
# checks (not correctness checks) and need the optional `security` extra
# (pip-audit, detect-secrets), not installed by `pip install -e ".[dev]"`
# alone -- see README.md. Still fast/deterministic enough to belong in
# check-all.sh (unlike check-docker.sh, see that script's header).
#
# docs/IMPLEMENTATION-ROADMAP.md Phase 1.4.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== pip-audit (Python dependency vulnerabilities: full resolved environment, i.e. pyproject.toml's dependencies + dev + security groups) =="
pip-audit

echo "== npm audit (frontend dependency vulnerabilities: frontend/package.json + package-lock.json) =="
(cd frontend && npm audit --audit-level=high)

echo "== detect-secrets (repository secret scan, tracked files only, against .secrets.baseline) =="
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
