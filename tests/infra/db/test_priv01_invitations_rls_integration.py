"""Privacy Architecture Audit finding PRIV-01 -- dynamic regression proof
against a real PostgreSQL instance that `core.invitations` is now
RLS-protected (migration `cb7120cfa806`), and that `core.api_keys` is
deliberately, explicitly left unchanged by this same remediation.

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/tenancy/test_tenant_isolation_integration.py` and this
session's own `tests/infra/db/test_func_export_removed_integration.py` --
same fixtures, same real-role setup (the application's own `DATABASE_URL`
role, never a role manufactured only for this test file).

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_priv01_invitations_rls_integration.py

**Scope decision this file exists to prove, not just assert**: applying
`ENABLE`/`FORCE ROW LEVEL SECURITY` to a table makes *every* query against
it -- via *any* function, regardless of which other call sites were
updated -- subject to the policy. A live test during implementation
proved this breaks any bearer-credential bootstrap lookup that must
resolve a row before its tenant is known. `core.api_keys`'s
`validate_api_key()` is live production authentication; `core.invitations`'s
`accept_invitation()` has no HTTP route calling it anywhere in this
codebase (confirmed by the Privacy Architecture Audit). RLS was therefore
applied to `core.invitations` only -- `core.api_keys` is deliberately
untouched by this remediation, and this file proves that explicitly
(not just by omission) so a future change cannot silently assume otherwise.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from core.api_keys.service import create_api_key, validate_api_key
from core.identity.service import (
    add_tenant_membership,
    create_invitation,
    create_user,
    list_invitations_for_tenant,
)
from core.rbac.scope import RoleScope
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_APP_ROLE = os.environ.get("APP_DB_USER", "saas_os_app")


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
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
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


@pytest.fixture
def admin_session_factory() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


def _new_tenant_with_invitation_capability() -> tuple[uuid.UUID, uuid.UUID]:
    """A real tenant plus a real user holding the "create invitation"
    capability -- the exact shape `create_invitation()` requires."""
    tenant_id = create_tenant(f"priv01-{uuid.uuid4().hex[:8]}").id
    user_id = create_user().id
    membership = add_tenant_membership(tenant_id, user_id)
    role = create_role(tenant_id, f"invite-admin-{uuid.uuid4().hex[:8]}")
    permission = register_permission("invitation", "create")
    grant_permission(tenant_id, role.id, permission.id)
    assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, scope=RoleScope.SELF)
    return tenant_id, user_id


def _cleanup(admin_session_factory: sessionmaker[Session], *tenant_ids: uuid.UUID) -> None:
    with session_scope(session_factory=admin_session_factory) as session:
        for tenant_id in tenant_ids:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    for tenant_id in tenant_ids:
        with tenant_session_scope(tenant_id) as session:
            session.execute(
                text("DELETE FROM core.invitations WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
            session.execute(
                text("DELETE FROM core.membership_roles WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM core.role_permissions WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
            session.execute(
                text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    with session_scope(session_factory=admin_session_factory) as session:
        for tenant_id in tenant_ids:
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})
        session.execute(
            text("DELETE FROM core.permissions WHERE resource = 'invitation' AND action = 'create'")
        )


# --- Static: RLS is actually enabled, forced, and the expected policy exists ---


def test_invitations_has_the_expected_rls_posture(
    admin_session_factory: sessionmaker[Session],
) -> None:
    with session_scope(session_factory=admin_session_factory) as session:
        row = session.execute(
            text(
                "SELECT c.relrowsecurity, c.relforcerowsecurity "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'core' AND c.relname = 'invitations'"
            )
        ).one()
        row_security, force_row_security = row
        assert row_security is True, "core.invitations must have ROW LEVEL SECURITY enabled"
        assert force_row_security is True, "core.invitations must FORCE ROW LEVEL SECURITY"

        policy_names = (
            session.execute(
                text(
                    "SELECT p.polname FROM pg_policy p "
                    "JOIN pg_class c ON c.oid = p.polrelid "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'core' AND c.relname = 'invitations'"
                )
            )
            .scalars()
            .all()
        )
        assert policy_names == ["invitations_tenant_isolation"], (
            f"expected exactly the one standard tenant-isolation policy, got {policy_names!r}"
        )


def test_api_keys_deliberately_still_has_no_rls(
    admin_session_factory: sessionmaker[Session],
) -> None:
    """Explicit, not just by omission: this remediation does not touch
    `core.api_keys` -- `validate_api_key()`'s bootstrap lookup is live
    production authentication (see module docstring). A future change
    that silently enables RLS here without also solving that bootstrap
    problem would break authentication; this test exists so that change
    is never silent."""
    with session_scope(session_factory=admin_session_factory) as session:
        row = session.execute(
            text(
                "SELECT c.relrowsecurity, c.relforcerowsecurity "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'core' AND c.relname = 'api_keys'"
            )
        ).one()
        row_security, force_row_security = row
        assert row_security is False
        assert force_row_security is False

        policy_count = session.execute(
            text(
                "SELECT count(*) FROM pg_policy p "
                "JOIN pg_class c ON c.oid = p.polrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'core' AND c.relname = 'api_keys'"
            )
        ).scalar_one()
        assert policy_count == 0


# --- Dynamic: the actual cross-tenant privacy invariant -------------------


def test_untenanted_select_against_invitations_sees_nothing(
    admin_session_factory: sessionmaker[Session],
) -> None:
    """The exact class of future developer mistake PRIV-01 exists to
    catch: `SELECT ... FROM core.invitations` with no tenant predicate,
    executed under the application's own restricted role with no tenant
    context set, must never expose any tenant's rows -- not because the
    query happened to filter correctly, but because the database itself
    refuses to show anything."""
    tenant_a, inviter_a = _new_tenant_with_invitation_capability()
    tenant_b, inviter_b = _new_tenant_with_invitation_capability()
    try:
        create_invitation(tenant_a, inviter_a, f"a-{uuid.uuid4().hex[:8]}@example.com")
        create_invitation(tenant_b, inviter_b, f"b-{uuid.uuid4().hex[:8]}@example.com")

        with session_scope() as session:  # untenanted -- no app.tenant_id set
            rows = session.execute(text("SELECT id FROM core.invitations")).scalars().all()
        assert rows == [], (
            "an untenanted query saw invitation rows -- RLS did not fail closed "
            f"as expected (rows={rows!r})"
        )
    finally:
        _cleanup(admin_session_factory, tenant_a, tenant_b)


def test_tenant_scoped_session_cannot_see_the_other_tenants_invitation_without_a_filter(
    admin_session_factory: sessionmaker[Session],
) -> None:
    """Two tenants, each with a real invitation. Within tenant_a's own
    `tenant_session_scope()`, a bare `SELECT ... FROM core.invitations`
    with *no* explicit `WHERE tenant_id = ...` predicate -- the literal
    scenario PRIV-01 describes -- must return only tenant_a's row, never
    tenant_b's, and tenant_a's row must remain visible (fail-closed, not
    fail-empty)."""
    tenant_a, inviter_a = _new_tenant_with_invitation_capability()
    tenant_b, inviter_b = _new_tenant_with_invitation_capability()
    try:
        email_a = f"a-{uuid.uuid4().hex[:8]}@example.com"
        email_b = f"b-{uuid.uuid4().hex[:8]}@example.com"
        create_invitation(tenant_a, inviter_a, email_a)
        create_invitation(tenant_b, inviter_b, email_b)

        with tenant_session_scope(tenant_a) as session:
            visible_emails = (
                session.execute(text("SELECT invited_email FROM core.invitations")).scalars().all()
            )
        assert visible_emails == [email_a], (
            f"tenant_a's untenanted-predicate session saw {visible_emails!r}, "
            f"expected only [{email_a!r}]"
        )

        with tenant_session_scope(tenant_b) as session:
            visible_emails = (
                session.execute(text("SELECT invited_email FROM core.invitations")).scalars().all()
            )
        assert visible_emails == [email_b], (
            f"tenant_b's untenanted-predicate session saw {visible_emails!r}, "
            f"expected only [{email_b!r}]"
        )
    finally:
        _cleanup(admin_session_factory, tenant_a, tenant_b)


def test_list_invitations_for_tenant_service_function_remains_correctly_isolated(
    admin_session_factory: sessionmaker[Session],
) -> None:
    """Non-vacuous end-to-end proof at the public service layer (not just
    raw SQL): `list_invitations_for_tenant()`, now running under
    `tenant_session_scope()`, still returns only its own tenant's rows."""
    tenant_a, inviter_a = _new_tenant_with_invitation_capability()
    tenant_b, inviter_b = _new_tenant_with_invitation_capability()
    try:
        email_a = f"a-{uuid.uuid4().hex[:8]}@example.com"
        email_b = f"b-{uuid.uuid4().hex[:8]}@example.com"
        create_invitation(tenant_a, inviter_a, email_a)
        create_invitation(tenant_b, inviter_b, email_b)

        invitations_a = list_invitations_for_tenant(tenant_a)
        invitations_b = list_invitations_for_tenant(tenant_b)

        assert [i.invited_email for i in invitations_a] == [email_a]
        assert [i.invited_email for i in invitations_b] == [email_b]
    finally:
        _cleanup(admin_session_factory, tenant_a, tenant_b)


# --- Confirm the deliberately-unchanged api_keys bootstrap still works ----


def test_validate_api_key_bootstrap_is_unaffected_by_this_migration(
    admin_session_factory: sessionmaker[Session],
) -> None:
    """`core.api_keys` was not touched by this remediation -- confirm the
    live authentication path genuinely still works end to end, not just
    that the table's RLS flags are unchanged (the two static checks
    above)."""
    tenant_id = create_tenant(f"priv01-apikey-{uuid.uuid4().hex[:8]}").id
    try:
        user_id = create_user().id
        add_tenant_membership(tenant_id, user_id)
        _, raw_key = create_api_key(tenant_id, user_id, "priv01-regression-key")

        resolved = validate_api_key(raw_key)
        assert resolved.tenant_id == tenant_id
        assert resolved.user_id == user_id
    finally:
        # core.audit_log revokes DELETE from the application role for
        # immutability (create_api_key() writes an audit entry) -- the
        # privileged migrations role is required here, mirroring every
        # other cleanup helper in this file/suite.
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
        with session_scope() as session:
            session.execute(
                text("DELETE FROM core.api_keys WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
        with tenant_session_scope(tenant_id) as session:
            session.execute(
                text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"),
                {"t": str(tenant_id)},
            )
        with session_scope() as session:
            session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})
