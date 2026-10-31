#!/usr/bin/env bash
# Dependency vulnerability scan + secret scan. Kept separate from
# check-backend.sh/check-frontend.sh: these are supply-chain/security
# checks (not correctness checks) and need the optional `security` extra
# (pip-audit, detect-secrets), not installed by `pip install -e ".[dev]"`
# alone -- see README.md. Still fast/deterministic enough to belong in
# check-all.sh (unlike check-docker.sh, see that script's header).
#
# docs/IMPLEMENTATION-ROADMAP.md Phase 1.4.
#
# Every check runs and reports: a failing dependency audit must not hide the
# secret scan's result. The two audits record their failure and the script
# goes on; the secret scan runs last, unguarded, under `set -e`
# (tests/architecture/test_secrets_gate.py requires exactly that), so its
# failure still aborts the script at once. The script fails if any one of
# the three fails -- nothing here is advisory.
#
# The frontend audit is scripts/npm_audit_gate.py: the same threshold as
# `npm audit --audit-level=high`, minus the advisories listed in
# scripts/security-exceptions.json -- each one a single advisory id, with an
# expiry, void the moment it reaches production dependencies or a
# non-breaking fix exists. An accepted advisory is printed on every run and
# is never reported as fixed.
set -euo pipefail
cd "$(dirname "$0")/.."

PY="$(command -v python || command -v python3)"
AUDITS_FAILED=()

echo "== pip-audit (Python dependency vulnerabilities: full resolved environment, i.e. pyproject.toml's dependencies + dev + security groups) =="
pip-audit || AUDITS_FAILED+=("pip-audit")

echo "== npm audit (frontend dependency vulnerabilities: frontend/package.json + package-lock.json; high and critical, minus scripts/security-exceptions.json) =="
"$PY" scripts/npm_audit_gate.py frontend || AUDITS_FAILED+=("npm audit")

FILE_LIST="$(mktemp)"
report_audits() {
    rm -f "$FILE_LIST"
    for CHECK in ${AUDITS_FAILED[@]+"${AUDITS_FAILED[@]}"}; do
        echo "FAIL: $CHECK"
    done
}
# If the secret scan below aborts the script, still name the failed audits.
trap report_audits EXIT

echo "== detect-secrets (repository secret scan, tracked files only, against .secrets.baseline) =="
# The file names go through a list and xargs, not onto one command line:
# every tracked path together exceeds the 32,767-character limit of a
# Windows command line ("Argument list too long"). xargs splits the list
# into as many invocations as the platform needs and exits non-zero if any
# of them does; NUL separators keep unusual file names intact.
#
# detect-secrets opens each file in the locale's encoding. On Windows that
# is cp1252, which cannot decode some UTF-8 characters (the box-drawing
# characters in docs/P-ROADMAP.md, for instance), and a file that fails to
# decode is skipped with no finding and no failure. UTF-8 mode makes the
# scan read every file as UTF-8, as it does on Linux CI.
export PYTHONUTF8=1
# detect-secrets-hook rewrites the baseline it is given when its findings
# do not match (new line numbers, a new finding). The check must never edit
# the committed file, so the hook gets a copy; a mismatch still fails here,
# and the copy shows what changed. Update the real baseline deliberately
# (docs/SECURITY.md section 10), never as a side effect of this check.
# The hook skips the file it is given as the baseline; since that is now
# the copy, `.secrets.baseline` itself (whose content is the hashes of the
# accepted findings) is left out of the list, exactly as before.
git ls-files -z | grep -zvx '.secrets.baseline' > "$FILE_LIST"
BASELINE_COPY="$(mktemp)"
cp .secrets.baseline "$BASELINE_COPY"
if ! xargs -0 detect-secrets-hook --baseline "$BASELINE_COPY" < "$FILE_LIST"; then
    echo "FAIL: detect-secrets found a secret-shaped string or a stale .secrets.baseline;"
    echo "      .secrets.baseline was not modified (the hook's rewrite is in $BASELINE_COPY)."
    exit 1
fi
rm -f "$BASELINE_COPY"

if [ "${#AUDITS_FAILED[@]}" -gt 0 ]; then
    exit 1
fi
echo "All security checks passed."
