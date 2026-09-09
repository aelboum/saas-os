"""Migration reversibility test for the Phase 5.2 usage_events migration
(docs/IMPLEMENTATION-ROADMAP.md Phase 5.2 Rollback Strategy: "aggregation
can be recomputed from raw events; raw events are the source of truth" --
schema reversibility itself is validated against real disposable
PostgreSQL, not merely documented).

**Destructive**: this test downgrades past, then re-applies,
`757d55add12a` (the usage_events-table migration) on whatever database
`MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`core.usage_events`, then recreates it empty. Run this only against a
disposable database, never a shared development or production database.
Marked `integration` and excluded from the default `pytest` run for
exactly this reason, mirroring
`tests/infra/db/test_notifications_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_usage_migration_rollback.py
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from core.usage.service import aggregate_usage
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_USAGE_REVISION = "757d55add12a"
_BILLING_REVISION = "2d0730e14a7f"


@pytest.fixture(autouse=True)
def _require_reachable_privileged_database() -> None:
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured MIGRATIONS_DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    finally:
        probe_engine.dispose()


def _alembic_config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _table_exists(table: str) -> bool:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'core' AND table_name = :t)"
                ),
                {"t": table},
            ).scalar_one()
        return bool(row)
    finally:
        engine.dispose()


def _rls_flags(table: str) -> tuple[bool, bool] | None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = :t"),
                {"t": table},
            ).one_or_none()
        return (row[0], row[1]) if row is not None else None
    finally:
        engine.dispose()


def _insert_usage_event(tenant_id: uuid.UUID, metric: str) -> None:
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text(
                "INSERT INTO core.usage_events "
                "(id, tenant_id, metric, quantity, occurred_at) "
                "VALUES (:id, :tid, :metric, :qty, :occurred_at)"
            ),
            {
                "id": str(uuid.uuid4()),
                "tid": str(tenant_id),
                "metric": metric,
                "qty": "1",
                "occurred_at": datetime.now(UTC),
            },
        )


def test_usage_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _table_exists("usage_events")
    assert _rls_flags("usage_events") == (True, True)

    # --- seed a real usage event through direct insertion (mirrors
    # tests/infra/db/test_notifications_migration_rollback.py's approach
    # for an async-ingested entity) before downgrading, proving the
    # schema this migration created is genuinely usable, not merely
    # structurally present ---
    tenant = create_tenant(f"usage-rollback-{uuid.uuid4().hex[:8]}")
    try:
        _insert_usage_event(tenant.id, "rollback-metric")
        assert aggregate_usage(
            tenant.id,
            "rollback-metric",
            since=datetime(2020, 1, 1, tzinfo=UTC),
            until=datetime(2030, 1, 1, tzinfo=UTC),
        ) == Decimal("1")

        try:
            # --- downgrade past the usage migration ---
            command.downgrade(cfg, _BILLING_REVISION)
            assert not _table_exists("usage_events")
            # Phase 3.1-5.1's own tables must be untouched.
            assert _table_exists("tenants")
            assert _table_exists("users")
            assert _table_exists("tenant_memberships")
            assert _table_exists("roles")
            assert _table_exists("audit_log")
            assert _table_exists("api_keys")
            assert _table_exists("feature_flags")
            assert _table_exists("feature_flag_tenant_overrides")
            assert _table_exists("webhook_subscriptions")
            assert _table_exists("notifications")
            assert _table_exists("billing_plans")
            assert _table_exists("billing_subscriptions")

            # --- re-apply the usage migration ---
            command.upgrade(cfg, _USAGE_REVISION)
            assert _table_exists("usage_events")
            assert _rls_flags("usage_events") == (True, True)

            # usage_events is usable again post-re-upgrade: a fresh insert
            # + aggregation cycle works (the old row was dropped with the
            # table, which is expected -- this proves the *schema* is
            # usable again, not that data survived a destructive
            # downgrade; aggregation is recomputed from raw events, the
            # exact guarantee this phase's Rollback Strategy names).
            _insert_usage_event(tenant.id, "rollback-reseed-metric")
            assert aggregate_usage(
                tenant.id,
                "rollback-reseed-metric",
                since=datetime(2020, 1, 1, tzinfo=UTC),
                until=datetime(2030, 1, 1, tzinfo=UTC),
            ) == Decimal("1")
        finally:
            command.upgrade(cfg, "head")
    finally:
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.usage_events WHERE tenant_id = :t"), {"t": str(tenant.id)}
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
