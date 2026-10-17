#!/usr/bin/env bash
# Security integration gate (PRIV-03 privacy re-audit RA-11, finding F1).
#
# Every lifecycle, RLS, TOCTOU, job-fencing, purge, authorization, result-
# retention, reference-consumer, invitation-lifecycle and log-redaction
# regression test in this repository is marked `integration` (it needs a
# real PostgreSQL and a real Redis), and pyproject.toml's default
# `-m "not integration and not packaging"` keeps every one of them out of
# `check-backend.sh`. Until RA-11 nothing in CI ran them, so any of those
# invariants could regress under a green build. This script is that gate:
# `.github/workflows/ci.yml`'s `security-integration` job runs it verbatim
# against disposable service containers (postgres:16-alpine +
# redis:7-alpine), exactly like `check-migrations.sh` and the `migrations`
# job.
#
# Assumes `MIGRATIONS_DATABASE_URL`/`DATABASE_URL` point at a disposable,
# migrated-or-empty PostgreSQL instance whose restricted application role
# already exists (`saas_os/infra/db/init/01-create-app-role.sh` -- run automatically
# by `docker compose up -d db`, explicitly by the CI job) and `REDIS_URL` at
# a disposable Redis -- never a developer's persistent database. The
# integration tests themselves create and remove their own rows.
#
# Skip enforcement: every integration module `pytest.skip()`s itself when
# PostgreSQL or Redis is unreachable, which is the right behavior for a
# developer's bare `pytest -m integration` but would let an infrastructure
# failure in CI produce a green result with nothing executed. So the suite
# writes a JUnit report and the check below fails the gate unless at least
# one integration test ran and exactly zero were skipped. What is excluded
# on the command line below is exactly the set of integration tests that
# cannot run here by design -- not because of a missing service -- so a
# skip from any of them would be permanent noise, never a signal:
#   - tests/test_reference_consumer_integration.py: the packaging/migration
#     end-to-end flow (real wheel build + isolated venv) that
#     `check-migrations.sh` / CI's `migrations` job already run -- never
#     the same expensive test twice;
#   - tests/core/billing/test_billing_stripe_integration.py: a live Stripe
#     test-mode API key; tests/core/identity/test_live_zitadel_integration.py:
#     a live ZITADEL tenant; tests/control_plane/development/
#     test_development_github_integration.py: a live GitHub token and
#     sandbox repository. None of those credentials may exist in CI
#     (docs/ADR/0012-secrets-management.md);
#   - the eleven `@pytest.mark.skip(reason="PRIV-01: ...")` tests in
#     tests/core/identity/test_invitation_integration.py: statically
#     skipped by design while `accept_invitation()`'s untenanted token
#     lookup is dormant under FORCE RLS, so they execute nowhere; they are
#     deselected by node id (the rest of that module runs) and these lines
#     must go when PRIV-01 is resolved and the markers come off (RA-11-F5).
# Everything else that skips is a defect in the environment, and the gate
# says so.
#
# ADR-0056: `TEST_PLATFORM_CONFIG_DATABASE_URL` must name the disposable
# database's platform-configuration login role
# (`saas_os/infra/db/init/02-create-platform-config-role.sh`). Tests that
# change AI configuration receive it as `PLATFORM_CONFIG_DATABASE_URL` for
# their own duration only (the root conftest's `platform_config_database`);
# exporting `PLATFORM_CONFIG_DATABASE_URL` itself would make every API and
# worker startup in the suite refuse, as it must in a deployment.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${TEST_PLATFORM_CONFIG_DATABASE_URL:-}" ]; then
    echo "FAIL: TEST_PLATFORM_CONFIG_DATABASE_URL is not set (ADR-0056)." >&2
    exit 1
fi
if [ -n "${PLATFORM_CONFIG_DATABASE_URL:-}" ] || [ -n "${PLATFORM_CONFIG_DATABASE_URL_FILE:-}" ]; then
    echo "FAIL: export TEST_PLATFORM_CONFIG_DATABASE_URL, not PLATFORM_CONFIG_DATABASE_URL." >&2
    exit 1
fi

echo "== SaaS OS migrations -> head (real, disposable database) =="
saas-os-migrate upgrade

# ADR-0016 step 2: several `integration`-marked tests below (tenant purge,
# job lifecycle fencing, job result retention, the reference consumer's own
# route security suite) exercise `reference_consumer`'s `WidgetPurgeParticipant`
# fixture (examples/reference-consumer/), which reads/writes the
# `reference_consumer.widgets` table -- a schema `saas-os-migrate upgrade`
# above never touches (its own docstring: "Never touches a consuming
# project's own migrations"). Without this, every one of those tests fails
# with `UndefinedTable: relation "reference_consumer.widgets" does not
# exist`. `check-migrations.sh` already covers the same two-step ordering
# end to end via the (expensive, wheel-building) test_reference_consumer_integration.py,
# which this script deliberately excludes below -- this is the same second
# step, applied directly against the one disposable database this job
# already migrated, so the tests that need the schema (but not that
# expensive end-to-end proof) actually have it.
echo "== reference consumer: project migrations (ADR-0016 step 2, same disposable database) =="
python - <<'PYEOF'
from pathlib import Path

from alembic import command
from alembic.config import Config

ref_migrations_dir = Path("examples/reference-consumer/reference_consumer/migrations")
project_cfg = Config()
project_cfg.set_main_option("script_location", str(ref_migrations_dir))
command.upgrade(project_cfg, "head")
PYEOF

JUNIT_DIR="$(mktemp -d)"
JUNIT_REPORT="$JUNIT_DIR/integration-junit.xml"

_PRIV01_STATIC_SKIPS=tests/core/identity/test_invitation_integration.py

echo "== security integration suite: pytest -m integration (real PostgreSQL + Redis) =="
pytest_failed=0
if ! pytest -m integration --strict-markers -rfEs --junitxml="$JUNIT_REPORT" tests \
    --ignore=tests/test_reference_consumer_integration.py \
    --ignore=tests/core/billing/test_billing_stripe_integration.py \
    --ignore=tests/core/identity/test_live_zitadel_integration.py \
    --ignore=tests/control_plane/development/test_development_github_integration.py \
    --deselect "$_PRIV01_STATIC_SKIPS::test_accept_invitation_activates_membership_for_new_user" \
    --deselect "$_PRIV01_STATIC_SKIPS::test_accept_invitation_writes_audit_entry" \
    --deselect "$_PRIV01_STATIC_SKIPS::test_accept_invitation_is_one_time_use" \
    --deselect "$_PRIV01_STATIC_SKIPS::test_accept_invitation_does_not_verify_accepting_identity_matches_invited_email" \
    --deselect "$_PRIV01_STATIC_SKIPS::test_accept_invitation_is_tenant_bound" \
    --deselect "$_PRIV01_STATIC_SKIPS::test_accept_invitation_with_existing_active_membership_is_idempotent" \
    --deselect "$_PRIV01_STATIC_SKIPS::test_accept_invitation_with_suspended_existing_membership_fails_closed" \
    --deselect "$_PRIV01_STATIC_SKIPS::test_accept_invitation_with_revoked_existing_membership_fails_closed" \
    --deselect "$_PRIV01_STATIC_SKIPS::test_accept_invitation_cannot_produce_duplicate_membership_row" \
    --deselect "$_PRIV01_STATIC_SKIPS::test_revoke_already_accepted_invitation_raises" \
    --deselect "$_PRIV01_STATIC_SKIPS::test_concurrent_acceptance_attempts_only_one_succeeds"; then
    pytest_failed=1
fi

echo "== skip enforcement: integration tests run > 0 and skipped == 0 =="
python - "$JUNIT_REPORT" <<'EOF'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
tests = sum(int(s.get("tests", 0)) for s in suites)
skipped = sum(int(s.get("skipped", 0)) for s in suites)
print(f"integration tests collected and run: {tests}; skipped: {skipped}")
for case in root.iter("testcase"):
    skip = case.find("skipped")
    if skip is not None:
        print(f"SKIPPED {case.get('classname')}::{case.get('name')}: {skip.get('message')}")
if tests == 0:
    sys.exit("FAIL: no integration test ran -- the suite must execute, not merely collect")
if skipped != 0:
    sys.exit(
        f"FAIL: {skipped} integration test(s) skipped -- an unreachable PostgreSQL/Redis "
        "or a missing host tool must fail this gate, never turn it green"
    )
EOF

if [ "$pytest_failed" -ne 0 ]; then
    echo "FAIL: the integration suite reported failures (see pytest output above)"
    exit 1
fi
echo "All security integration checks passed."
