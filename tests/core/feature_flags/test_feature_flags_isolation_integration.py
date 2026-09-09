"""Cross-tenant isolation integration tests for
`core.feature_flag_tenant_overrides` against a real PostgreSQL instance
with the Phase 4.2 tables actually migrated (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.1's standing rule: "No phase touching tenant data may merge
without the cross-tenant isolation suite ... passing against the new
code").

Two isolation postures proven here, mirroring
`tests/core/rbac/test_rbac_isolation_integration.py`'s structure:

- `core.feature_flag_tenant_overrides` is tenant-owned and RLS-protected
  -- proven the same way every other tenant-owned table's isolation is
  proven (RLS-alone, missing-context, and forged-session-setting proofs).
- `core.feature_flags` is deliberately GLOBAL, not RLS-scoped (the flag
  catalog is a platform capability declaration, not tenant-owned data,
  `core/feature_flags/models.py`'s own docstring) -- proven as a
  regression guard the same way `tests/core/api_keys/test_api_keys_isolation_integration.py`
  proves `core.api_keys` deliberately has none.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/feature_flags/test_feature_flags_isolation_integration.py
"""

from __future__ import annotations

import uuid

# Registers core.users on the shared declarative Base.metadata -- this
# file never otherwise imports core.identity, but
# AuditLogEntry.actor_user_id's ForeignKey("core.users.id") needs that
# table's mapping present for set_tenant_override()'s audit write to
# resolve it (mirrors tests/core/audit_log/test_audit_log_isolation_integration.py's
# identical import).
import core.identity.models  # noqa: F401
import pytest
from core.feature_flags.service import (
    create_flag,
    evaluate_flag,
    get_tenant_override,
    set_tenant_override,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_feature_flags_tables() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.feature_flag_tenant_overrides LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.feature_flag_tenant_overrides does not exist yet -- "
            f"run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _unique_key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _TenantRig:
    def __init__(self, label: str) -> None:
        self.tenant = create_tenant(f"tenant-{label}-{uuid.uuid4().hex[:8]}")
        self.key = _unique_key(f"flag-{label}")
        self.flag = create_flag(self.key, enabled_by_default=False)


@pytest.fixture
def rig_a():
    return _TenantRig("a")


@pytest.fixture
def rig_b():
    return _TenantRig("b")


def _cleanup(rig: _TenantRig) -> None:
    with tenant_session_scope(rig.tenant.id) as session:
        session.execute(
            text("DELETE FROM core.feature_flag_tenant_overrides WHERE tenant_id = :t"),
            {"t": str(rig.tenant.id)},
        )
    _admin_delete_audit_log_for_tenant(rig.tenant.id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.feature_flags WHERE key = :k"), {"k": rig.key})
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(rig.tenant.id)})


@pytest.fixture(autouse=True)
def _cleanup_rigs(rig_a: _TenantRig, rig_b: _TenantRig):
    yield
    _cleanup(rig_a)
    _cleanup(rig_b)


# --- Setup correctness -----------------------------------------------------


def test_feature_flag_tenant_overrides_has_force_row_level_security(rig_a: _TenantRig) -> None:
    with _admin_session() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'feature_flag_tenant_overrides'"
            )
        ).one()
    assert row[0] is True
    assert row[1] is True


def test_feature_flags_catalog_deliberately_has_no_rls(rig_a: _TenantRig) -> None:
    """The global flag catalog is intentionally NOT RLS-protected (every
    tenant must be able to resolve every flag's global default) -- this
    test exists so an accidental future "let's add RLS here too" is caught
    as a regression, mirroring
    `tests/core/api_keys/test_api_keys_isolation_integration.py`'s
    equivalent regression guard for `core.api_keys`.
    """
    with _admin_session() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'feature_flags'"
            )
        ).one()
    assert row[0] is False
    assert row[1] is False


# --- Cross-tenant: A cannot read/modify B's overrides -----------------------


def test_tenant_a_cannot_read_tenant_bs_override(rig_a: _TenantRig, rig_b: _TenantRig) -> None:
    set_tenant_override(rig_b.tenant.id, rig_b.key, True)

    with tenant_session_scope(rig_a.tenant.id) as session:
        rows = session.execute(
            text("SELECT id FROM core.feature_flag_tenant_overrides WHERE flag_id = :f"),
            {"f": str(rig_b.flag.id)},
        ).all()
    assert rows == []

    assert get_tenant_override(rig_a.tenant.id, rig_b.key) is None


def test_tenant_a_evaluating_tenant_bs_targeted_flag_sees_global_default_not_bs_override(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    """rig_b's flag has a global default of False; rig_b overrides it to
    True for itself. Evaluating that same flag *key* for rig_a must never
    see rig_b's tenant-specific override -- only the flag's global
    default (there is no flag of that key targeted for rig_a at all).
    """
    set_tenant_override(rig_b.tenant.id, rig_b.key, True)
    assert evaluate_flag(rig_b.tenant.id, rig_b.key) is True
    assert evaluate_flag(rig_a.tenant.id, rig_b.key) is False


def test_tenant_a_cannot_modify_tenant_bs_override_via_raw_sql(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    set_tenant_override(rig_b.tenant.id, rig_b.key, True)

    with tenant_session_scope(rig_a.tenant.id) as session:
        result = session.execute(
            text(
                "UPDATE core.feature_flag_tenant_overrides SET enabled = false WHERE flag_id = :f"
            ),
            {"f": str(rig_b.flag.id)},
        )
        assert result.rowcount == 0  # type: ignore[attr-defined]

    assert evaluate_flag(rig_b.tenant.id, rig_b.key) is True


# --- Non-vacuous DB-boundary proof ------------------------------------------


def test_rls_alone_blocks_cross_tenant_read_with_no_application_filter(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    """Deliberately issue a query with NO tenant_id predicate at all --
    exactly what a bug that forgot the application-level filter would
    produce -- under tenant A's session context, and confirm RLS alone
    still limits every result to tenant A's own rows.
    """
    set_tenant_override(rig_a.tenant.id, rig_a.key, True)
    set_tenant_override(rig_b.tenant.id, rig_b.key, True)

    with tenant_session_scope(rig_a.tenant.id) as session:
        tenant_ids = {
            row[0]
            for row in session.execute(
                text("SELECT tenant_id FROM core.feature_flag_tenant_overrides")
            ).all()  # no WHERE clause
        }
    assert tenant_ids == {rig_a.tenant.id}


def test_missing_tenant_context_sees_zero_override_rows(rig_a: _TenantRig) -> None:
    set_tenant_override(rig_a.tenant.id, rig_a.key, True)

    with session_scope() as session:
        rows = session.execute(text("SELECT id FROM core.feature_flag_tenant_overrides")).all()
    assert rows == []


def test_manually_forged_session_setting_cannot_grant_extra_access(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    set_tenant_override(rig_a.tenant.id, rig_a.key, True)

    with session_scope() as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": str(uuid.uuid4())}
        )
        rows = session.execute(text("SELECT id FROM core.feature_flag_tenant_overrides")).all()
    assert rows == []
