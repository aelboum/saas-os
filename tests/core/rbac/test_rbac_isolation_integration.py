"""Cross-tenant isolation integration tests for `core.roles`,
`core.role_permissions`, and `core.membership_roles` against a real
PostgreSQL instance with the Phase 3.3 tables actually migrated
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 sections 13-15, 27-28).

Mirrors `tests/core/identity/test_identity_isolation_integration.py`'s
structure and discipline (real `saas_os_app` runtime role, not a
manufactured test-only role) -- exercises the real, migrated tables
directly, not scratch tables.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_rbac_isolation_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.service import add_tenant_membership, create_user
from core.rbac.errors import RoleNotFoundError
from core.rbac.service import (
    assign_role,
    create_role,
    grant_permission,
    list_membership_roles,
    list_roles,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_rbac_tables() -> None:
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
            conn.execute(text("SELECT 1 FROM core.membership_roles LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.membership_roles does not exist yet -- run `alembic upgrade head` first: {exc}"
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


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _cleanup(
    *, tenant_ids: list[uuid.UUID], user_ids: list[uuid.UUID], permissions: list[tuple[str, str]]
) -> None:
    for tenant_id in tenant_ids:
        with tenant_session_scope(tenant_id) as session:
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
    with session_scope() as session:
        for user_id in user_ids:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})
        for tenant_id in tenant_ids:
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant_id)})
        for resource, action in permissions:
            session.execute(
                text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
                {"r": resource, "a": action},
            )


class _TenantRig:
    """One tenant with a user, membership, role, permission, grant, and
    assignment -- the "Tenant A / Tenant B" fixture the roadmap's adversarial
    test matrix (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 13) asks
    for, built twice (once per tenant) by the tests below.
    """

    def __init__(self, label: str) -> None:
        self.resource = _unique_name(f"resource-{label}")
        self.action = "read"
        self.tenant = create_tenant(_unique_name(f"tenant-{label}"))
        self.user = create_user()
        self.membership = add_tenant_membership(self.tenant.id, self.user.id)
        self.role = create_role(self.tenant.id, f"role-{label}")
        self.permission = register_permission(self.resource, self.action)
        grant_permission(self.tenant.id, self.role.id, self.permission.id)
        assign_role(self.tenant.id, self.membership.id, self.role.id)


@pytest.fixture
def rig_a():
    return _TenantRig("a")


@pytest.fixture
def rig_b():
    return _TenantRig("b")


@pytest.fixture(autouse=True)
def _cleanup_rigs(rig_a: _TenantRig, rig_b: _TenantRig):
    yield
    _cleanup(
        tenant_ids=[rig_a.tenant.id, rig_b.tenant.id],
        user_ids=[rig_a.user.id, rig_b.user.id],
        permissions=[(rig_a.resource, rig_a.action), (rig_b.resource, rig_b.action)],
    )


# --- Setup correctness -----------------------------------------------------


def test_force_row_level_security_is_actually_enabled(rig_a: _TenantRig) -> None:
    """Non-vacuous proof, against Postgres's own catalog, that the real
    migration applied RLS to all three tenant-owned RBAC tables."""
    with _admin_session() as session:
        rows = session.execute(
            text(
                "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname IN ('roles', 'role_permissions', 'membership_roles')"
            )
        ).all()
    by_name = {r[0]: (r[1], r[2]) for r in rows}
    assert by_name == {
        "roles": (True, True),
        "role_permissions": (True, True),
        "membership_roles": (True, True),
    }


# --- Roles: A cannot read/modify B's -----------------------------------


def test_tenant_a_cannot_read_tenant_b_roles(rig_a: _TenantRig, rig_b: _TenantRig) -> None:
    roles_visible_from_a = list_roles(rig_a.tenant.id)
    assert rig_b.role.id not in {r.id for r in roles_visible_from_a}


def test_tenant_a_cannot_modify_tenant_b_roles(rig_a: _TenantRig, rig_b: _TenantRig) -> None:
    with tenant_session_scope(rig_a.tenant.id) as session:
        result = session.execute(
            text("UPDATE core.roles SET name = :n WHERE id = :id"),
            {"n": "tampered-by-a", "id": str(rig_b.role.id)},
        )
        assert result.rowcount == 0  # type: ignore[attr-defined]

    with tenant_session_scope(rig_b.tenant.id) as session:
        row = session.execute(
            text("SELECT name FROM core.roles WHERE id = :id"), {"id": str(rig_b.role.id)}
        ).one()
    assert row.name == rig_b.role.name


# --- Role assignments: A cannot read/assign B's -------------------------


def test_tenant_a_cannot_read_tenant_b_role_assignments(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    assignments_visible_from_a = list_membership_roles(rig_a.tenant.id, rig_a.membership.id)
    assert all(a.tenant_id == rig_a.tenant.id for a in assignments_visible_from_a)

    with tenant_session_scope(rig_a.tenant.id) as session:
        rows = session.execute(
            text("SELECT id FROM core.membership_roles WHERE membership_id = :m"),
            {"m": str(rig_b.membership.id)},
        ).all()
    assert rows == []


def test_tenant_a_cannot_assign_a_tenant_b_role_to_a_tenant_a_membership(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    """`assign_role` is called *as tenant A* (tenant_id=rig_a.tenant.id)
    but with rig_b's role_id -- the composite FK
    `(tenant_id, role_id) -> roles(tenant_id, id)` rejects this at the
    database level (no row in `core.roles` has
    `(rig_a.tenant.id, rig_b.role.id)`); `core/rbac/service.py::assign_role`
    translates that raw `IntegrityError` into the same typed
    `RoleNotFoundError` a genuinely-nonexistent role_id would raise --
    proven directly against the database in
    `test_tenant_a_cannot_grant_a_tenant_b_permission_via_a_tenant_b_role`
    below and in `test_rbac_integration.py`'s duplicate/not-found tests.
    """
    with pytest.raises(RoleNotFoundError):
        assign_role(rig_a.tenant.id, rig_a.membership.id, rig_b.role.id)

    # The rejection is real, not merely raised: no assignment row exists.
    with tenant_session_scope(rig_a.tenant.id) as session:
        rows = session.execute(
            text("SELECT id FROM core.membership_roles WHERE role_id = :r"),
            {"r": str(rig_b.role.id)},
        ).all()
    assert rows == []


def test_tenant_a_cannot_grant_a_tenant_b_permission_via_a_tenant_b_role(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    """Tenant A attempts to grant its own registered permission to
    tenant B's role while operating under tenant A's own tenant context --
    the composite FK on `role_permissions.(tenant_id, role_id)` rejects it
    at the database level (rig_b.role.id does not belong to
    rig_a.tenant.id); confirmed here via the *raw* driver exception
    (bypassing the service layer's own translation) so this test proves
    the database constraint itself, not just that the service layer
    raises something.
    """
    with pytest.raises(RoleNotFoundError):
        grant_permission(rig_a.tenant.id, rig_b.role.id, rig_a.permission.id)

    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        with tenant_session_scope(rig_a.tenant.id) as session:
            session.execute(
                text(
                    "INSERT INTO core.role_permissions (id, tenant_id, role_id, permission_id) "
                    "VALUES (:id, :tid, :rid, :pid)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tid": str(rig_a.tenant.id),
                    "rid": str(rig_b.role.id),
                    "pid": str(rig_a.permission.id),
                },
            )
    assert "foreign key" in str(excinfo.value).lower()


def test_tenant_a_cannot_use_tenant_b_authorization_state(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    """The end-to-end authorization outcome: rig_a's user must not be
    authorized for rig_b's (resource, action), even though rig_b's role
    genuinely grants that permission -- to someone in rig_b's tenant."""
    from core.rbac import can

    assert (
        can(
            actor_id=rig_a.user.id,
            tenant_id=rig_b.tenant.id,
            action=rig_b.action,
            resource=rig_b.resource,
        )
        is False
    )


# --- Non-vacuous DB-boundary proof (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 15) --


def test_rls_alone_blocks_cross_tenant_read_with_no_application_filter(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    """Deliberately issue a query with NO `tenant_id`/`role_id`/`membership_id`
    predicate at all -- i.e. exactly what a bug that forgot the
    application-level filter would produce -- under tenant A's session
    context, and confirm RLS alone still limits every result to tenant A's
    own rows. This is the regression the roadmap asks for: it fails if RLS
    is ever disabled or the runtime role gains BYPASSRLS, independent of
    whether `core/rbac`'s own Python code still filters correctly.
    """
    with tenant_session_scope(rig_a.tenant.id) as session:
        role_tenant_ids = {
            row[0]
            for row in session.execute(
                text("SELECT tenant_id FROM core.roles")
            ).all()  # no WHERE clause
        }
        membership_role_tenant_ids = {
            row[0]
            for row in session.execute(text("SELECT tenant_id FROM core.membership_roles")).all()
        }
        role_perm_tenant_ids = {
            row[0]
            for row in session.execute(text("SELECT tenant_id FROM core.role_permissions")).all()
        }

    assert role_tenant_ids == {rig_a.tenant.id}
    assert membership_role_tenant_ids == {rig_a.tenant.id}
    assert role_perm_tenant_ids == {rig_a.tenant.id}


def test_missing_tenant_context_sees_zero_rbac_rows(rig_a: _TenantRig) -> None:
    with session_scope() as session:
        roles = session.execute(text("SELECT id FROM core.roles")).all()
        memberships = session.execute(text("SELECT id FROM core.membership_roles")).all()
        grants = session.execute(text("SELECT id FROM core.role_permissions")).all()
    assert roles == []
    assert memberships == []
    assert grants == []


def test_manually_forged_session_setting_cannot_grant_extra_access(
    rig_a: _TenantRig, rig_b: _TenantRig
) -> None:
    with session_scope() as session:
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": str(uuid.uuid4())}
        )
        rows = session.execute(text("SELECT id FROM core.roles")).all()
    assert rows == []
