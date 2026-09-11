"""Membership-lifecycle authorization integration tests against a real
PostgreSQL instance (architecture research: universal multi-tenant
tenancy, Phase G -- "Invitation / Membership Lifecycle").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/rbac/test_deny_authorization_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_membership_lifecycle_authorization_integration.py

The central property under test throughout this file: `can()`'s ordinary
membership-role path requires `TenantMembership.status == ACTIVE`, and its
delegated-authorization path applies the identical requirement whenever
the delegate genuinely holds a membership at the tenant the delegation
concerns -- see `core/rbac/authorization.py`'s module docstring,
"Membership lifecycle" paragraph.
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.service import (
    add_tenant_membership,
    create_service_account,
    create_user,
    reactivate_membership,
    revoke_membership,
    suspend_membership,
)
from core.rbac.errors import DelegationNotAuthorizedError
from core.rbac.service import (
    assign_role,
    assign_service_account_role,
    create_delegation,
    create_deny,
    create_role,
    grant_permission,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.rbac import PrincipalType, RoleScope, can
from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_membership_status_column() -> None:
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
            conn.execute(text("SELECT status FROM core.tenant_memberships LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            "core.tenant_memberships.status does not exist yet -- run "
            f"`alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    with _admin_session() as session:
        session.execute(
            text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.delegation_grants WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.service_account_roles WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        )
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
        session.execute(
            text("DELETE FROM core.service_accounts WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
    with session_scope() as session:
        session.execute(
            text("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t OR ancestor_id = :t"),
            {"t": str(tenant_id)},
        )
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


def _new_tenant(*, parent_id: uuid.UUID | None = None) -> uuid.UUID:
    return create_tenant(_unique_name("tenant"), parent_id=parent_id).id


def _grant_delegation_create_capability(tenant_id: uuid.UUID, membership_id: uuid.UUID) -> None:
    role = create_role(tenant_id, _unique_name("delegation-admin-role"))
    permission = register_permission("delegation_grant", "create")
    grant_permission(tenant_id, role.id, permission.id)
    assign_role(tenant_id, membership_id, role.id, scope=RoleScope.SELF)


def _member_with_role(
    tenant_id: uuid.UUID, *, resource: str, action: str, scope: RoleScope = RoleScope.SELF
) -> tuple[uuid.UUID, uuid.UUID]:
    """A fresh user, an ACTIVE membership, and a role granting
    `(resource, action)` at `scope`. Returns (user_id, membership_id)."""
    user_id = create_user().id
    membership = add_tenant_membership(tenant_id, user_id)
    role = create_role(tenant_id, _unique_name("role"))
    permission = register_permission(resource, action)
    grant_permission(tenant_id, role.id, permission.id)
    assign_role(tenant_id, membership.id, role.id, scope=scope)
    return user_id, membership.id


# --- Ordinary membership-role authorization ---------------------------------


def test_active_membership_authorizes() -> None:
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        user_id, _ = _member_with_role(tenant_id, resource=resource, action=action)
        assert can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission(resource, action)


def test_suspended_membership_does_not_authorize() -> None:
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        user_id, membership_id = _member_with_role(tenant_id, resource=resource, action=action)
        suspend_membership(tenant_id, membership_id, actor_user_id=user_id)
        assert not can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission(resource, action)


def test_revoked_membership_does_not_authorize() -> None:
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        user_id, membership_id = _member_with_role(tenant_id, resource=resource, action=action)
        revoke_membership(tenant_id, membership_id, actor_user_id=user_id)
        assert not can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission(resource, action)


def test_role_row_survives_suspension_but_no_longer_authorizes() -> None:
    """The `MembershipRole` row itself is never deleted by suspension --
    `status` alone is the authoritative switch (architecture research
    Phase G)."""
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        user_id, membership_id = _member_with_role(tenant_id, resource=resource, action=action)
        suspend_membership(tenant_id, membership_id, actor_user_id=user_id)

        with tenant_session_scope(tenant_id) as session:
            count = session.execute(
                text("SELECT COUNT(*) FROM core.membership_roles WHERE membership_id = :m"),
                {"m": str(membership_id)},
            ).scalar_one()
        assert count == 1
        assert not can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission(resource, action)


def test_reactivated_membership_authorizes_again() -> None:
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        user_id, membership_id = _member_with_role(tenant_id, resource=resource, action=action)
        suspend_membership(tenant_id, membership_id, actor_user_id=user_id)
        assert not can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)

        reactivate_membership(tenant_id, membership_id, actor_user_id=user_id)
        assert can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission(resource, action)


def test_suspended_subtree_membership_does_not_authorize_descendant() -> None:
    parent_id = _new_tenant()
    child_id = _new_tenant(parent_id=parent_id)
    try:
        resource, action = _unique_name("resource"), "read"
        user_id, membership_id = _member_with_role(
            parent_id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        assert can(actor_id=user_id, tenant_id=child_id, action=action, resource=resource)

        suspend_membership(parent_id, membership_id, actor_user_id=user_id)
        assert not can(actor_id=user_id, tenant_id=child_id, action=action, resource=resource)
    finally:
        _cleanup_tenant(child_id)
        _cleanup_tenant(parent_id)
        _cleanup_permission(resource, action)


# --- Delegated authorization -------------------------------------------------


def test_delegate_without_membership_is_unaffected_by_membership_status() -> None:
    """A delegate who has never been a member of the delegation's own
    tenant at all is unaffected by Phase G -- delegation remains
    intentionally separate from membership (architecture research Phase C,
    preserved unchanged)."""
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        delegator_id, delegator_membership_id = _member_with_role(
            tenant_id, resource=resource, action=action, scope=RoleScope.SELF
        )
        _grant_delegation_create_capability(tenant_id, delegator_membership_id)
        delegate_id = create_user().id  # never a member of tenant_id
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator_id,
            delegate_user_id=delegate_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert can(actor_id=delegate_id, tenant_id=tenant_id, action=action, resource=resource)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(delegate_id)
        _cleanup_permission(resource, action)
        _cleanup_permission("delegation_grant", "create")


def test_delegate_with_suspended_membership_in_same_tenant_is_blocked() -> None:
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        delegator_id, delegator_membership_id = _member_with_role(
            tenant_id, resource=resource, action=action, scope=RoleScope.SELF
        )
        _grant_delegation_create_capability(tenant_id, delegator_membership_id)
        delegate_id = create_user().id
        delegate_membership = add_tenant_membership(tenant_id, delegate_id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator_id,
            delegate_user_id=delegate_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        assert can(actor_id=delegate_id, tenant_id=tenant_id, action=action, resource=resource)

        suspend_membership(tenant_id, delegate_membership.id, actor_user_id=delegator_id)
        assert not can(actor_id=delegate_id, tenant_id=tenant_id, action=action, resource=resource)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(delegate_id)
        _cleanup_permission(resource, action)
        _cleanup_permission("delegation_grant", "create")


def test_delegator_with_suspended_membership_cannot_create_new_delegation() -> None:
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        delegator_id, delegator_membership_id = _member_with_role(
            tenant_id, resource=resource, action=action, scope=RoleScope.SELF
        )
        _grant_delegation_create_capability(tenant_id, delegator_membership_id)
        delegate_id = create_user().id
        permission = register_permission(resource, action)

        suspend_membership(tenant_id, delegator_membership_id, actor_user_id=delegator_id)

        with pytest.raises(DelegationNotAuthorizedError):
            create_delegation(
                delegator_user_id=delegator_id,
                delegate_user_id=delegate_id,
                tenant_id=tenant_id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(delegate_id)
        _cleanup_permission(resource, action)
        _cleanup_permission("delegation_grant", "create")


# --- Explicit deny remains unconditional ------------------------------------


def test_deny_still_overrides_active_membership_allow() -> None:
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        user_id, membership_id = _member_with_role(tenant_id, resource=resource, action=action)
        assert can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)

        deny_role = create_role(tenant_id, _unique_name("deny-admin-role"))
        deny_create_permission = register_permission("deny_grant", "create")
        grant_permission(tenant_id, deny_role.id, deny_create_permission.id)
        assign_role(tenant_id, membership_id, deny_role.id, scope=RoleScope.SELF)

        permission = register_permission(resource, action)
        create_deny(
            grantor_user_id=user_id,
            principal_user_id=user_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        assert not can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)
    finally:
        with tenant_session_scope(tenant_id) as session:
            session.execute(
                text("DELETE FROM core.deny_grants WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
        _cleanup_tenant(tenant_id)
        _cleanup_permission(resource, action)
        _cleanup_permission("deny_grant", "create")


# --- Service account / SYSTEM principals are unaffected ---------------------


def test_service_account_authorization_is_unaffected_by_membership_status() -> None:
    """A `ServiceAccount` has no `TenantMembership` row at all -- Phase G
    must not accidentally require one (architecture research Phase G:
    "do not accidentally require a membership for SYSTEM principals... do
    not change service-account semantics unnecessarily")."""
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        admin_id, admin_membership_id = _member_with_role(
            tenant_id, resource=resource, action=action
        )
        svc_role_admin_role = create_role(tenant_id, _unique_name("svc-role-admin-role"))
        svc_role_create_permission = register_permission("service_account_role", "create")
        grant_permission(tenant_id, svc_role_admin_role.id, svc_role_create_permission.id)
        assign_role(tenant_id, admin_membership_id, svc_role_admin_role.id, scope=RoleScope.SELF)

        service_account = create_service_account(tenant_id, _unique_name("svc"))
        role = create_role(tenant_id, _unique_name("svc-role"))
        permission = register_permission(resource, action)
        grant_permission(tenant_id, role.id, permission.id)
        assign_service_account_role(
            actor_user_id=admin_id,
            tenant_id=tenant_id,
            service_account_id=service_account.id,
            role_id=role.id,
            scope=RoleScope.SELF,
        )

        assert can(
            actor_id=service_account.id,
            tenant_id=tenant_id,
            action=action,
            resource=resource,
            actor_type=PrincipalType.SERVICE_ACCOUNT,
            actor_tenant_id=tenant_id,
        )

        # Even suspending the *admin's own* human membership must not
        # affect the service account's own, independent authorization.
        suspend_membership(tenant_id, admin_membership_id, actor_user_id=admin_id)
        assert can(
            actor_id=service_account.id,
            tenant_id=tenant_id,
            action=action,
            resource=resource,
            actor_type=PrincipalType.SERVICE_ACCOUNT,
            actor_tenant_id=tenant_id,
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission(resource, action)
        _cleanup_permission("service_account_role", "create")


def test_system_principal_type_remains_denied() -> None:
    """No code path constructs a `SYSTEM` actor for `can()` -- it must
    remain unconditionally denied, unrelated to membership status
    (unchanged from Phase E)."""
    tenant_id = _new_tenant()
    try:
        assert not can(
            actor_id=uuid.uuid4(),
            tenant_id=tenant_id,
            action="read",
            resource=_unique_name("resource"),
            actor_type=PrincipalType.SYSTEM,
        )
    finally:
        _cleanup_tenant(tenant_id)
