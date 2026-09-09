"""Cross-tenant isolation integration tests for `core.tenant_memberships`
against a real PostgreSQL instance with the Phase 3.2 tables actually
migrated (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 section 6 "Tenancy
Integration" / section 12 "Security Test Matrix > RLS / adversarial").

Mirrors `tests/core/tenancy/test_tenant_isolation_integration.py`'s
structure and discipline (real `saas_os_app` runtime role, not a
manufactured test-only role), but exercises the real, migrated
`core.tenant_memberships` table directly instead of a scratch table --
this is the one identity table that is actually RLS-protected
(`core/identity/models.py`'s docstring; `core.users`, `core.sessions`, and
`core.external_identities` are deliberately global and not RLS-scoped, the
same way `core.tenants` itself is not).

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/identity/test_identity_isolation_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.service import add_tenant_membership, create_user, list_tenant_members
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_identity_tables() -> None:
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
            conn.execute(text("SELECT 1 FROM core.tenant_memberships LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.tenant_memberships does not exist yet -- run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _new_tenant() -> uuid.UUID:
    return create_tenant(f"identity-rls-{uuid.uuid4().hex[:8]}").id


def _new_user() -> uuid.UUID:
    return create_user().id


def _cleanup(*, tenant_ids: list[uuid.UUID], user_ids: list[uuid.UUID]) -> None:
    for tenant_id in tenant_ids:
        with tenant_session_scope(tenant_id) as session:
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :tid"),
                {"tid": str(tenant_id)},
            )
    with session_scope() as session:
        for user_id in user_ids:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})
        for tenant_id in tenant_ids:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_id)})


# --- Setup correctness (proves the real table, not a stand-in, is protected) ---


def _admin_session():
    """A short-lived session on the privileged bootstrap/migration role --
    used only to inspect Postgres's own catalog (`pg_class`), exactly
    mirroring `admin_session_factory` in
    `test_tenant_isolation_integration.py`.
    """
    from infra.db.session import build_session_factory
    from infra.db.session import session_scope as _session_scope

    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return _session_scope(session_factory=factory)


def test_force_row_level_security_is_actually_enabled_on_tenant_memberships() -> None:
    """Non-vacuous proof, against Postgres's own catalog, that the real
    migration (not just this test file's assumption) actually applied
    `infra.db.rls.tenant_rls_statements()` to `core.tenant_memberships`."""
    with _admin_session() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'tenant_memberships'"
            )
        ).one()
    assert row[0] is True
    assert row[1] is True


# --- Core isolation: A sees A's members, B sees B's, neither sees the other ---


def test_tenant_a_can_read_its_own_membership() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    user_a, user_b = _new_user(), _new_user()
    try:
        add_tenant_membership(tenant_a, user_a)
        add_tenant_membership(tenant_b, user_b)

        members = list_tenant_members(tenant_a)
        assert [m.user_id for m in members] == [user_a]
    finally:
        _cleanup(tenant_ids=[tenant_a, tenant_b], user_ids=[user_a, user_b])


def test_tenant_a_cannot_read_tenant_b_membership_rows() -> None:
    """The literal Phase 3.2 requirement: 'tenant A cannot read tenant B
    users' -- proven at the membership-linkage level, since `core.users`
    itself is global (docs/MULTI-TENANCY.md section 1) and the tenant
    boundary that actually protects "which users belong to tenant B" is
    `core.tenant_memberships`'s RLS policy.
    """
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    user_a, user_b = _new_user(), _new_user()
    try:
        add_tenant_membership(tenant_a, user_a)
        add_tenant_membership(tenant_b, user_b)

        members_of_a = list_tenant_members(tenant_a)
        assert user_b not in {m.user_id for m in members_of_a}
    finally:
        _cleanup(tenant_ids=[tenant_a, tenant_b], user_ids=[user_a, user_b])


def test_tenant_b_cannot_read_tenant_a_membership_rows() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    user_a, user_b = _new_user(), _new_user()
    try:
        add_tenant_membership(tenant_a, user_a)
        add_tenant_membership(tenant_b, user_b)

        members_of_b = list_tenant_members(tenant_b)
        assert user_a not in {m.user_id for m in members_of_b}
    finally:
        _cleanup(tenant_ids=[tenant_a, tenant_b], user_ids=[user_a, user_b])


# --- Missing / adversarial context ----------------------------------------


def test_missing_tenant_context_sees_zero_membership_rows() -> None:
    tenant_a = _new_tenant()
    user_a = _new_user()
    try:
        add_tenant_membership(tenant_a, user_a)

        with session_scope() as session:
            rows = session.execute(
                text("SELECT user_id FROM core.tenant_memberships WHERE tenant_id = :tid"),
                {"tid": str(tenant_a)},
            ).all()
        assert rows == []
    finally:
        _cleanup(tenant_ids=[tenant_a], user_ids=[user_a])


def test_manually_forged_session_setting_cannot_grant_extra_access() -> None:
    tenant_a = _new_tenant()
    user_a = _new_user()
    forged_tenant_id = uuid.uuid4()
    try:
        add_tenant_membership(tenant_a, user_a)

        with session_scope() as session:
            session.execute(
                text("SELECT set_config('app.tenant_id', :tid, true)"),
                {"tid": str(forged_tenant_id)},
            )
            rows = session.execute(text("SELECT user_id FROM core.tenant_memberships")).all()
        assert rows == []
    finally:
        _cleanup(tenant_ids=[tenant_a], user_ids=[user_a])


# --- Writes cannot cross tenant boundaries --------------------------------


def test_cross_tenant_membership_insert_is_rejected() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    user_x = _new_user()
    try:
        with pytest.raises(Exception) as excinfo:  # noqa: PT011
            with tenant_session_scope(tenant_a) as session:
                session.execute(
                    text(
                        "INSERT INTO core.tenant_memberships (id, tenant_id, user_id) "
                        "VALUES (:id, :tid, :uid)"
                    ),
                    {"id": str(uuid.uuid4()), "tid": str(tenant_b), "uid": str(user_x)},
                )
        assert "row-level security" in str(excinfo.value).lower()

        with_b = list_tenant_members(tenant_b)
        assert with_b == []
    finally:
        _cleanup(tenant_ids=[tenant_a, tenant_b], user_ids=[user_x])


def test_cross_tenant_membership_delete_affects_zero_rows() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    user_b = _new_user()
    try:
        membership = add_tenant_membership(tenant_b, user_b)

        with tenant_session_scope(tenant_a) as session:
            result = session.execute(
                text("DELETE FROM core.tenant_memberships WHERE id = :id"),
                {"id": str(membership.id)},
            )
            assert result.rowcount == 0  # type: ignore[attr-defined]

        still_there = list_tenant_members(tenant_b)
        assert [m.user_id for m in still_there] == [user_b]
    finally:
        _cleanup(tenant_ids=[tenant_a, tenant_b], user_ids=[user_b])
