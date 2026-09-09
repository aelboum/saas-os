"""`core/rbac.can()` authorization-evaluation integration tests against a
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
from core.identity.service import add_tenant_membership, create_user
from core.rbac.service import (
    assign_role,
    create_role,
    grant_permission,
    register_permission,
    remove_role,
    revoke_permission,
)
from infra.db.config import get_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.rbac import can
from core.tenancy import create_tenant

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
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


def _cleanup_permission(resource: str, action: str) -> None:
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.permissions WHERE resource = :r AND action = :a"),
            {"r": resource, "a": action},
        )


def _cleanup_user(user_id: uuid.UUID) -> None:
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


class _Fixture:
    """A fully-wired tenant/user/membership/role/permission/grant/assignment
    -- the "allowed" baseline every denial test starts from and removes
    exactly one link of the chain."""

    def __init__(self) -> None:
        self.resource = _unique_name("resource")
        self.action = "read"
        self.tenant = create_tenant(_unique_name("tenant"))
        self.user = create_user()
        self.membership = add_tenant_membership(self.tenant.id, self.user.id)
        self.role = create_role(self.tenant.id, "editor")
        self.permission = register_permission(self.resource, self.action)
        grant_permission(self.tenant.id, self.role.id, self.permission.id)
        assign_role(self.tenant.id, self.membership.id, self.role.id)

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
    remove_role(fixture.tenant.id, fixture.membership.id, fixture.role.id)
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
    revoke_permission(fixture.tenant.id, fixture.role.id, fixture.permission.id)
    assert fixture.can() is False


def test_revoked_role_assignment_is_denied(fixture: _Fixture) -> None:
    remove_role(fixture.tenant.id, fixture.membership.id, fixture.role.id)
    assert fixture.can() is False


# --- Cross-tenant attempts -----------------------------------------------


def test_role_granted_in_tenant_a_does_not_authorize_in_tenant_b(fixture: _Fixture) -> None:
    """A role assignment in tenant A MUST NOT imply authorization in
    tenant B (docs/IMPLEMENTATION-ROADMAP.md Phase 3.3 section 13)."""
    tenant_b = create_tenant(_unique_name("tenant-b"))
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
    tenant_a = create_tenant(_unique_name("tenant-a"))
    tenant_b = create_tenant(_unique_name("tenant-b"))
    user = create_user()
    try:
        membership_a = add_tenant_membership(tenant_a.id, user.id)
        add_tenant_membership(
            tenant_b.id, user.id
        )  # member of B too, but never granted anything there

        role_a = create_role(tenant_a.id, "editor")
        permission = register_permission(resource, action)
        grant_permission(tenant_a.id, role_a.id, permission.id)
        assign_role(tenant_a.id, membership_a.id, role_a.id)

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
