#!/usr/bin/env bash
# CI migration gate (P1.7, docs/IMPLEMENTATION-ROADMAP.md): proves a clean
# PostgreSQL database can be migrated from the repository's initial schema
# state to the current Alembic head via the real migration/admin path, and
# that the resulting schema is compatible with the application.
#
# Kept OUT of check-all.sh, matching check-docker.sh's own precedent: this
# needs a real, reachable PostgreSQL instance (MIGRATIONS_DATABASE_URL/
# DATABASE_URL pointed at a disposable database -- never the developer's
# own saas-os-db-1), unlike everything else check-all.sh runs, which needs
# no external service. Run explicitly (or via CI's `migrations` job).
#
# How to run locally:
#
#   docker compose up -d db
#   MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \  # pragma: allowlist secret
#       DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \  # pragma: allowlist secret
#       bash scripts/check-migrations.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== migration graph validation (no database needed) =="
pytest -m "not integration" tests/infra/db/test_migration_graph_unit.py

echo "== migration gate: clean PostgreSQL -> alembic head (real, disposable database) =="
pytest -m integration tests/infra/db/test_migration_gate_integration.py

# ADR-0016/ADR-0018; docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md
# section 13: also run the reference consumer's own migrations after SaaS
# OS's, against the same disposable database, proving the two-environment
# ordering works end-to-end (not just SaaS OS's own migrations in
# isolation).
echo "== reference consumer: SaaS OS migrations -> project migrations, end to end =="
pytest -m integration tests/test_reference_consumer_integration.py
