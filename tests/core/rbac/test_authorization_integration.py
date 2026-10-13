"""`saas_os/core/rbac.can()` authorization-evaluation integration tests against a
real PostgreSQL instance (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3
section 27 "Authorization": allowed, denied, unknown user, no membership,
wrong tenant, missing role, missing permission, revoked permission,
revoked role, cross-tenant attempt).

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_authorization_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from lifecycle_callers import PROVISIONING
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.rbac import can
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
    remove_role,
    revoke_permission,
)
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import session_scope, tenant_session_scope


def _authority_admin(tenant_id: uuid.UUID, *capabilities: tuple[str, str]) -> UserCaller:
    """An active user holding exactly `capabilities` in `tenant_id` -- the
    explicit, authorized typed caller an authority-changing Core operation
    requires (ADR-0031). Provisioned with explicit provisioning authority."""
    from saas_os.core.authority import SystemAuthority, SystemCaller
    from saas_os.core.identity import add_tenant_membership, create_user
    from saas_os.core.rbac import (
        assign_first_role_for_new_tenant,
        create_role,
        grant_permission,
        register_permission,
    )

    provisioning = SystemCaller(SystemAuthority.PROVISIONING)
    user = create_user()
    membership = add_tenant_membership(tenant_id, user.id, caller=provisioning)
    role = create_role(tenant_id, f"authority-admin-{uuid.uuid4().hex[:8]}", caller=provisioning)
    for resource, action in capabilities:
        permission = register_permission(resource, action)
        grant_permission(tenant_id, role.id, permission.id, caller=provisioning)
    assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=provisioning)
    return UserCaller(user.id)


def _admin_clear_audit_references(params: object, *, table: str) -> None:
    """Test cleanup only. Core writes its audit evidence in the same
    transaction as every authority change (ADR-0031), and `core.audit_log`
    rows reference `core.tenants`/`core.users` while the runtime role can
    never delete them -- so before a test deletes tenants or users, their
    audit rows are cleared with the privileged migrations role."""
    from sqlalchemy import text

    from saas_os.infra.db.config import get_migrations_database_config
    from saas_os.infra.db.engine import build_engine
    from saas_os.infra.db.session import build_session_factory, session_scope

    raw = params.values() if isinstance(params, dict) else [params]
    values: list[str] = []
    for value in raw:
        items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        values.extend(str(item) for item in items)
    if table == "tenants":
        where = "tenant_id::text = ANY(:v) OR acting_as_tenant_id::text = ANY(:v)"
    else:
        where = "actor_user_id::text = ANY(:v)"
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            # Rows another open transaction already holds (e.g. a teardown that
            # deleted them itself, not yet committed) are being removed by it:
            # skip them rather than wait on that transaction.
            session.execute(
                text(
                    "DELETE FROM core.audit_log WHERE id IN (SELECT id FROM core.audit_log "
                    f"WHERE {where} FOR UPDATE SKIP LOCKED)"
                ),
                {"v": values},
            )
            # ADR-0045 Phase C: lifecycle changes also write platform audit
            # rows, which reference the tenant or the acting user and which
            # the runtime role can never delete.
            platform_where = (
                "target_tenant_id::text = ANY(:v)"
                if table == "tenants"
                else "actor_user_id::text = ANY(:v)"
            )
            # A migration test may be cleaning up below the revision that
            # creates the table.
            if session.execute(text("SELECT to_regclass('core.platform_audit_log')")).scalar():
                session.execute(
                    text(f"DELETE FROM core.platform_audit_log WHERE {platform_where}"),  # noqa: S608
                    {"v": values},
                )
    finally:
        engine.dispose()


_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_rbac_tables() -> None:
    get_database_config.cache_clear()
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


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.membership_roles WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.role_permissions WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(text("DELETE FROM core.roles WHERE tenant_id = :t"), {"t": str(tenant_id)})
    with session_scope() as session:
        _admin_clear_audit_references({"t": str(tenant_id)}, table="tenants")
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _cleanup_permission(resource: str, action: str) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
            {"r": resource, "a": action},
        )


def _cleanup_user(user_id: uuid.UUID) -> None:
    with session_scope() as session:
        _admin_clear_audit_references({"id": str(user_id)}, table="users")
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


class _Fixture:
    """A fully-wired tenant/user/membership/role/permission/grant/assignment
    -- the "allowed" baseline every denial test starts from and removes
    exactly one link of the chain."""

    def __init__(self) -> None:
        self.resource = _unique_name("resource")
        self.action = "read"
        self.tenant = create_tenant(_unique_name("tenant"), caller=PROVISIONING)
        self.user = create_user()
        self.membership = add_tenant_membership(self.tenant.id, self.user.id, caller=_PROVISIONING)
        self.role = create_role(self.tenant.id, "editor", caller=_PROVISIONING)
        self.permission = register_permission(self.resource, self.action)
        grant_permission(self.tenant.id, self.role.id, self.permission.id, caller=_PROVISIONING)
        assign_first_role_for_new_tenant(
            self.tenant.id, self.membership.id, self.role.id, caller=_PROVISIONING
        )

    def can(self) -> bool:
        return can(
            actor_id=self.user.id,
            tenant_id=self.tenant.id,
            action=self.action,
            resource=self.resource,
        )

    def cleanup(self) -> None:
        _cleanup_tenant(self.tenant.id)
        _cleanup_user(self.user.id)
        _cleanup_permission(self.resource, self.action)


@pytest.fixture
def fixture():
    f = _Fixture()
    try:
        yield f
    finally:
        f.cleanup()


# --- Allowed -----------------------------------------------------------


def test_fully_wired_chain_is_allowed(fixture: _Fixture) -> None:
    assert fixture.can() is True


# --- Denied: each single missing link ---------------------------------


def test_unknown_user_is_denied(fixture: _Fixture) -> None:
    assert (
        can(
            actor_id=uuid.uuid4(),
            tenant_id=fixture.tenant.id,
            action=fixture.action,
            resource=fixture.resource,
        )
        is False
    )


def test_unknown_tenant_is_denied(fixture: _Fixture) -> None:
    assert (
        can(
            actor_id=fixture.user.id,
            tenant_id=uuid.uuid4(),
            action=fixture.action,
            resource=fixture.resource,
        )
        is False
    )


def test_no_membership_is_denied(fixture: _Fixture) -> None:
    other_user = create_user()
    try:
        assert (
            can(
                actor_id=other_user.id,
                tenant_id=fixture.tenant.id,
                action=fixture.action,
                resource=fixture.resource,
            )
            is False
        )
    finally:
        _cleanup_user(other_user.id)


def test_membership_with_no_role_is_denied(fixture: _Fixture) -> None:
    remove_role(
        fixture.tenant.id,
        fixture.membership.id,
        fixture.role.id,
        caller=_authority_admin(
            fixture.tenant.id,
            ("role", "delete"),
            ("role_permission", "revoke"),
            ("membership_role", "delete"),
        ),
    )
    assert fixture.can() is False


def test_role_with_no_matching_permission_is_denied(fixture: _Fixture) -> None:
    assert (
        can(
            actor_id=fixture.user.id,
            tenant_id=fixture.tenant.id,
            action="delete",  # a real action, just never granted
            resource=fixture.resource,
        )
        is False
    )


def test_unregistered_resource_action_pair_is_denied(fixture: _Fixture) -> None:
    assert (
        can(
            actor_id=fixture.user.id,
            tenant_id=fixture.tenant.id,
            action="never-registered-action",
            resource="never-registered-resource",
        )
        is False
    )


def test_revoked_permission_is_denied(fixture: _Fixture) -> None:
    revoke_permission(
        fixture.tenant.id,
        fixture.role.id,
        fixture.permission.id,
        caller=_authority_admin(
            fixture.tenant.id,
            ("role", "delete"),
            ("role_permission", "revoke"),
            ("membership_role", "delete"),
        ),
    )
    assert fixture.can() is False


def test_revoked_role_assignment_is_denied(fixture: _Fixture) -> None:
    remove_role(
        fixture.tenant.id,
        fixture.membership.id,
        fixture.role.id,
        caller=_authority_admin(
            fixture.tenant.id,
            ("role", "delete"),
            ("role_permission", "revoke"),
            ("membership_role", "delete"),
        ),
    )
    assert fixture.can() is False


# --- Cross-tenant attempts -----------------------------------------------


def test_role_granted_in_tenant_a_does_not_authorize_in_tenant_b(fixture: _Fixture) -> None:
    """A role assignment in tenant A MUST NOT imply authorization in
    tenant B (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 13)."""
    tenant_b = create_tenant(_unique_name("tenant-b"), caller=PROVISIONING)
    try:
        assert (
            can(
                actor_id=fixture.user.id,
                tenant_id=tenant_b.id,
                action=fixture.action,
                resource=fixture.resource,
            )
            is False
        )
    finally:
        _cleanup_tenant(tenant_b.id)


def test_same_global_user_two_memberships_authorized_independently_per_tenant() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 13: the same
    global user, member of two tenants, must be evaluated independently in
    each -- granted in A, not granted in B."""
    resource, action = _unique_name("resource"), "read"
    tenant_a = create_tenant(_unique_name("tenant-a"), caller=PROVISIONING)
    tenant_b = create_tenant(_unique_name("tenant-b"), caller=PROVISIONING)
    user = create_user()
    try:
        membership_a = add_tenant_membership(tenant_a.id, user.id, caller=_PROVISIONING)
        add_tenant_membership(
            tenant_b.id, user.id, caller=_PROVISIONING
        )  # member of B too, but never granted anything there

        role_a = create_role(tenant_a.id, "editor", caller=_PROVISIONING)
        permission = register_permission(resource, action)
        grant_permission(tenant_a.id, role_a.id, permission.id, caller=_PROVISIONING)
        assign_first_role_for_new_tenant(
            tenant_a.id, membership_a.id, role_a.id, caller=_PROVISIONING
        )

        assert (
            can(actor_id=user.id, tenant_id=tenant_a.id, action=action, resource=resource) is True
        )
        assert (
            can(actor_id=user.id, tenant_id=tenant_b.id, action=action, resource=resource) is False
        )
    finally:
        _cleanup_tenant(tenant_a.id)
        _cleanup_tenant(tenant_b.id)
        _cleanup_user(user.id)
        _cleanup_permission(resource, action)
