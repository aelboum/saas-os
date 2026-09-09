"""Migration reversibility test for the Phase 4.2 feature_flags migration
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.2 Rollback Strategy: "revert code"
-- validated against real disposable PostgreSQL, not merely documented).

**Destructive**: this test downgrades past, then re-applies, `5d8c7a635e62`
(the feature_flags-tables migration) on whatever database
`MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`core.feature_flags`/`core.feature_flag_tenant_overrides`, then recreates
them empty. Run this only against a disposable database, never a shared
development or production database. Marked `integration` and excluded
from the default `pytest` run for exactly this reason, mirroring
`tests/infra/db/test_api_keys_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_feature_flags_migration_rollback.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

# Registers core.users on the shared declarative Base.metadata -- see
# tests/core/feature_flags/test_feature_flags_isolation_integration.py's
# identical import for the full rationale.
import core.identity.models  # noqa: F401
import pytest
from alembic import command
from alembic.config import Config
from core.feature_flags.service import create_flag, evaluate_flag, set_tenant_override
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_FEATURE_FLAGS_REVISION = "5d8c7a635e62"
_API_KEYS_REVISION = "3a2522ccb9ea"


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


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    # core.audit_log DELETE is REVOKEd from the restricted runtime role
    # entirely (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4) -- test cleanup
    # must use the privileged migrations role here (set_tenant_override()
    # writes an audit entry, which would otherwise block deleting the
    # tenant via its audit_log.tenant_id foreign key).
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
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


def test_feature_flags_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _table_exists("feature_flags")
    assert _table_exists("feature_flag_tenant_overrides")
    assert _rls_flags("feature_flags") == (False, False)
    assert _rls_flags("feature_flag_tenant_overrides") == (True, True)

    # --- seed real feature-flag data through the actual service layer
    # (not raw SQL) before downgrading, proving the schema this migration
    # created is genuinely usable, not merely structurally present ---
    tenant = create_tenant(f"ff-rollback-{uuid.uuid4().hex[:8]}")
    key = f"rollback-flag-{uuid.uuid4().hex[:8]}"
    new_key: str | None = None
    try:
        create_flag(key, enabled_by_default=False)
        set_tenant_override(tenant.id, key, True)
        assert evaluate_flag(tenant.id, key) is True

        try:
            # --- downgrade past the feature_flags migration ---
            command.downgrade(cfg, _API_KEYS_REVISION)
            assert not _table_exists("feature_flags")
            assert not _table_exists("feature_flag_tenant_overrides")
            # Phase 3.1-4.1's own tables must be untouched.
            assert _table_exists("tenants")
            assert _table_exists("users")
            assert _table_exists("tenant_memberships")
            assert _table_exists("roles")
            assert _table_exists("audit_log")
            assert _table_exists("api_keys")

            # --- re-apply the feature_flags migration ---
            command.upgrade(cfg, _FEATURE_FLAGS_REVISION)
            assert _table_exists("feature_flags")
            assert _table_exists("feature_flag_tenant_overrides")
            assert _rls_flags("feature_flags") == (False, False)
            assert _rls_flags("feature_flag_tenant_overrides") == (True, True)

            # feature_flags is usable again post-re-upgrade: a fresh
            # flag+override cycle works (the old rows were dropped with
            # the tables, which is expected -- this proves the *schema* is
            # usable again, not that data survived a destructive
            # downgrade).
            new_key = f"rollback-reseed-flag-{uuid.uuid4().hex[:8]}"
            create_flag(new_key, enabled_by_default=False)
            set_tenant_override(tenant.id, new_key, True)
            assert evaluate_flag(tenant.id, new_key) is True
        finally:
            command.upgrade(cfg, "head")
    finally:
        # Delete overrides before the flags they reference (FK), and
        # audit-log entries (set_tenant_override() writes one per call, via
        # the privileged role since Phase 3.4 revokes DELETE from the
        # runtime role) before the tenant those entries reference.
        with tenant_session_scope(tenant.id) as session:
            session.execute(
                text("DELETE FROM core.feature_flag_tenant_overrides WHERE tenant_id = :t"),
                {"t": str(tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(tenant.id)
        with session_scope() as session:
            session.execute(text("DELETE FROM core.feature_flags WHERE key = :k"), {"k": key})
            if new_key is not None:
                session.execute(
                    text("DELETE FROM core.feature_flags WHERE key = :k"), {"k": new_key}
                )
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
