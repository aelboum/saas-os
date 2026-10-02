"""Migration reversibility test for the RE-1 transactional-outbox migration
(`8d3f1a6c2e70`, `core.outbox_events`), against real PostgreSQL.

**Destructive**: this test downgrades past, then re-applies, `8d3f1a6c2e70`
on whatever database `MIGRATIONS_DATABASE_URL` points at -- it temporarily
drops `core.outbox_events`, then recreates it empty. Run this only against
a disposable database. Marked `integration` and excluded from the default
`pytest` run for exactly this reason, mirroring
`tests/infra/db/test_notifications_migration_rollback.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from core.outbox import append_event
from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_OUTBOX_REVISION = "8d3f1a6c2e70"  # pragma: allowlist secret
_PREVIOUS_REVISION = "41e8273a685d"  # pragma: allowlist secret
_CLAIM_TOKEN_REVISION = "c4e8b2a71f93"  # pragma: allowlist secret


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
        pytest.skip(f"PostgreSQL not reachable at the configured MIGRATIONS_DATABASE_URL: {exc}")
    finally:
        probe_engine.dispose()


def _admin(sql: str, params: Mapping[str, object] | None = None) -> list[tuple[object, ...]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            result = session.execute(text(sql), params or {})
            return (
                [tuple(row) for row in result] if sql.lstrip().upper().startswith("SELECT") else []
            )
    finally:
        engine.dispose()


def _table_exists() -> bool:
    return bool(
        _admin(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'core' AND table_name = 'outbox_events')"
        )[0][0]
    )


def _rls_flags() -> tuple[object, ...]:
    return _admin(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE oid = 'core.outbox_events'::regclass"
    )[0]


def _pending_index_definition() -> str:
    rows = _admin(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'core' "
        "AND indexname = 'ix_outbox_events_pending'"
    )
    return str(rows[0][0]) if rows else ""


def _append_one(tenant_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        append_event(
            session,
            tenant_id=tenant_id,
            event_type="migration_test.happened",
            aggregate_type="probe",
            aggregate_id="1",
            payload={"ok": True},
        )


def test_outbox_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    command.upgrade(cfg, "head")
    assert _table_exists()
    assert _rls_flags() == (True, True)
    assert "WHERE ((status)::text = 'pending'::text)" in _pending_index_definition()

    tenant = create_tenant(f"outbox-rollback-{uuid.uuid4().hex[:8]}")
    try:
        _append_one(tenant.id)
        try:
            command.downgrade(cfg, _PREVIOUS_REVISION)
            assert not _table_exists()
            # Every pre-existing table is untouched.
            for table in ("tenants", "notifications", "usage_events", "webhook_subscriptions"):
                assert _admin(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'core' AND table_name = :t)",
                    {"t": table},
                )[0][0]

            command.upgrade(cfg, _OUTBOX_REVISION)
            assert _table_exists()
            assert _rls_flags() == (True, True)
            # Usable again at this revision (raw SQL: the ORM model is head's,
            # which has a later column); the old row went with the table.
            with tenant_session_scope(tenant.id) as session:
                session.execute(
                    text(
                        "INSERT INTO core.outbox_events "
                        "(id, tenant_id, event_type, aggregate_type, aggregate_id, payload) "
                        "VALUES (:id, :t, 'migration_test.happened', 'probe', '1', '{}')"
                    ),
                    {"id": str(uuid.uuid4()), "t": str(tenant.id)},
                )
            assert (
                _admin(
                    "SELECT count(*) FROM core.outbox_events WHERE tenant_id = :t",
                    {"t": str(tenant.id)},
                )[0][0]
                == 1
            )
        finally:
            command.upgrade(cfg, "head")
    finally:
        params = {"t": str(tenant.id)}
        _admin("DELETE FROM core.outbox_events WHERE tenant_id = :t", params)
        _admin(
            "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t", params
        )
        _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
        _admin("DELETE FROM core.tenants WHERE id = :t", params)


def _claim_token_column_exists() -> bool:
    return bool(
        _admin(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = "
            "'core' AND table_name = 'outbox_events' AND column_name = 'claim_token')"
        )[0][0]
    )


def test_claim_token_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    """RE-2 (`c4e8b2a71f93`): adds the nullable `claim_token` and its
    pending-only CHECK; existing rows are untouched (left unclaimed)."""
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    command.upgrade(cfg, "head")
    tenant = create_tenant(f"outbox-claim-rollback-{uuid.uuid4().hex[:8]}")
    try:
        _append_one(tenant.id)
        try:
            command.downgrade(cfg, _OUTBOX_REVISION)
            assert not _claim_token_column_exists()
            # The RE-1 row survives the downgrade untouched.
            assert (
                _admin(
                    "SELECT count(*) FROM core.outbox_events WHERE tenant_id = :t",
                    {"t": str(tenant.id)},
                )[0][0]
                == 1
            )

            command.upgrade(cfg, _CLAIM_TOKEN_REVISION)
            assert _claim_token_column_exists()
            assert _admin(
                "SELECT claim_token FROM core.outbox_events WHERE tenant_id = :t",
                {"t": str(tenant.id)},
            ) == [(None,)]
            # Only a pending event may carry a claim.
            with pytest.raises(Exception, match="ck_outbox_events_claim_only_pending"):  # noqa: PT011
                _admin(
                    "UPDATE core.outbox_events SET status = 'published', "
                    "claim_token = gen_random_uuid() WHERE tenant_id = :t",
                    {"t": str(tenant.id)},
                )
        finally:
            command.upgrade(cfg, "head")
    finally:
        params = {"t": str(tenant.id)}
        _admin("DELETE FROM core.outbox_events WHERE tenant_id = :t", params)
        _admin(
            "DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t", params
        )
        _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", params)
        _admin("DELETE FROM core.tenants WHERE id = :t", params)
