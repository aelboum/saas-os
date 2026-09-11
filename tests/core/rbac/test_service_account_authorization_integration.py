"""Service-account (machine principal) authorization integration tests
against a real PostgreSQL instance (architecture research: universal
multi-tenant tenancy, Phase E -- "Principal + Service Accounts + API Key
Hardening").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/rbac/test_deny_authorization_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_service_account_authorization_integration.py

Covers, per the Phase E checkpoint's own testing requirements:

A. Principal types (USER/SERVICE_ACCOUNT/SYSTEM validity, typed pairing).
B. Service account authentication gating (ACTIVE/DISABLED) through can().
C. RBAC via ServiceAccountRole -- SELF/SUBTREE, going through can().
E. Tenant binding: a service account never automatically reaches a
   different tenant merely by hierarchy relationship.
F. Ordinary allow, deny-overrides-allow, delegated-allow-still-subject-
   to-deny, no implicit permission from mere creation.
G. Multiple human memberships do not transfer to a service account.
H. Privilege amplification (SELF cannot create SUBTREE machine
   authority; delegated authority cannot bootstrap a broader grant).
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.service import (
    add_tenant_membership,
    create_service_account,
    create_user,
    disable_service_account,
)
from core.rbac.errors import (
    InvalidPrincipalError,
    ServiceAccountRoleNotAuthorizedError,
)
from core.rbac.principal import PrincipalType
from core.rbac.service import (
    assign_role,
    assign_service_account_role,
    create_delegation_to_service_account,
    create_deny_for_service_account,
    create_role,
    grant_permission,
    register_permission,
    revoke_deny,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.rbac import RoleScope, can
from core.tenancy import create_tenant, move_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_service_account_roles_table() -> None:
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
            conn.execute(text("SELECT 1 FROM core.service_account_roles LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            "core.service_account_roles does not exist yet -- run `alembic upgrade head` "
            f"first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _new_tenant() -> uuid.UUID:
    return create_tenant(_unique_name("tenant")).id


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.service_account_roles WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        )
        session.execute(
            text("DELETE FROM core.deny_grants WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.delegation_grants WHERE tenant_id = :t"), {"t": str(tenant_id)}
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


def _cleanup_audit_log_for(tenant_id: uuid.UUID) -> None:
    from infra.db.session import build_session_factory

    engine = build_engine(get_migrations_database_config())
    try:
        admin_session_factory = build_session_factory(engine)
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _sa_can(
    service_account_id: uuid.UUID,
    service_account_tenant_id: uuid.UUID,
    tenant_id: uuid.UUID,
    *,
    action: str,
    resource: str,
) -> bool:
    return can(
        actor_id=service_account_id,
        tenant_id=tenant_id,
        action=action,
        resource=resource,
        actor_type=PrincipalType.SERVICE_ACCOUNT,
        actor_tenant_id=service_account_tenant_id,
    )


def _grant_role_to_service_account(
    *,
    actor_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    service_account_id: uuid.UUID,
    resource: str,
    action: str,
    scope: RoleScope,
) -> uuid.UUID:
    role = create_role(tenant_id, _unique_name("role"))
    permission = register_permission(resource, action)
    grant_permission(tenant_id, role.id, permission.id)
    assign_service_account_role(
        actor_user_id=actor_user_id,
        tenant_id=tenant_id,
        service_account_id=service_account_id,
        role_id=role.id,
        scope=scope,
    )
    return role.id


def _admin_user_with_role(tenant_id: uuid.UUID, *, resource: str, action: str) -> uuid.UUID:
    """A human user who already holds ordinary membership-role authority
    for `(resource, action)` at `tenant_id`, `scope=SUBTREE` -- AND every
    management capability this test file's helpers need to grant onward
    (`service_account_role`/`deny_grant`/`delegation_grant`
    "create"/"revoke") -- used as the `actor_user_id` for management
    operations. Bundled onto a single role/membership for test-fixture
    convenience only; production code never assumes an actor holding one
    of these capabilities holds the others."""
    user_id = create_user().id
    membership = add_tenant_membership(tenant_id, user_id)
    role = create_role(tenant_id, _unique_name("admin-role"))
    permission = register_permission(resource, action)
    grant_permission(tenant_id, role.id, permission.id)
    for mgmt_resource, mgmt_action in (
        ("service_account_role", "create"),
        ("deny_grant", "create"),
        ("deny_grant", "revoke"),
        ("delegation_grant", "create"),
    ):
        if (mgmt_resource, mgmt_action) == (resource, action):
            continue  # already granted above -- avoid a duplicate grant.
        mgmt_permission = register_permission(mgmt_resource, mgmt_action)
        grant_permission(tenant_id, role.id, mgmt_permission.id)
    assign_role(tenant_id, membership.id, role.id, scope=RoleScope.SUBTREE)
    return user_id


# --- A. Principal types -----------------------------------------------------


def test_user_actor_type_remains_the_default_and_unaffected() -> None:
    """architecture research Phase E: every pre-Phase-E `can()` call site
    is unaffected -- omitting `actor_type` still evaluates a `User`."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        user_id = _admin_user_with_role(tenant_id, resource=resource, action=action)
        assert can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource) is True
    finally:
        _cleanup_audit_log_for(tenant_id)
        _cleanup_tenant(tenant_id)
        _cleanup_user(user_id)
        _cleanup_permission(resource, action)


def test_system_actor_type_fails_closed() -> None:
    """No code path in this phase constructs a SYSTEM actor for `can()`
    to evaluate -- it must fail closed, never raise, never allow."""
    tenant_id = _new_tenant()
    try:
        assert (
            can(
                actor_id=uuid.uuid4(),
                tenant_id=tenant_id,
                action="read",
                resource="anything",
                actor_type=PrincipalType.SYSTEM,
            )
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)


def test_service_account_actor_without_actor_tenant_id_fails_closed() -> None:
    """Omitting the required `actor_tenant_id` for a SERVICE_ACCOUNT actor
    must fail closed, never guess or default to `tenant_id`."""
    tenant_id = _new_tenant()
    try:
        assert (
            can(
                actor_id=uuid.uuid4(),
                tenant_id=tenant_id,
                action="read",
                resource="anything",
                actor_type=PrincipalType.SERVICE_ACCOUNT,
            )
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)


def test_unknown_service_account_id_fails_closed() -> None:
    tenant_id = _new_tenant()
    try:
        assert (
            _sa_can(uuid.uuid4(), tenant_id, tenant_id, action="read", resource="anything") is False
        )
    finally:
        _cleanup_tenant(tenant_id)


# --- B/C. Service account RBAC, ACTIVE/DISABLED gating ----------------------


def test_service_account_with_self_scope_role_is_allowed_at_its_own_tenant() -> None:
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        admin = _admin_user_with_role(tenant_id, resource=resource, action=action)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        _grant_role_to_service_account(
            actor_user_id=admin,
            tenant_id=tenant_id,
            service_account_id=sa.id,
            resource=resource,
            action=action,
            scope=RoleScope.SELF,
        )
        assert _sa_can(sa.id, tenant_id, tenant_id, action=action, resource=resource) is True
    finally:
        _cleanup_audit_log_for(tenant_id)
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)


def test_service_account_with_no_role_is_denied() -> None:
    """No implicit permission from merely creating a service account."""
    tenant_id = _new_tenant()
    try:
        sa = create_service_account(tenant_id, _unique_name("svc"))
        assert _sa_can(sa.id, tenant_id, tenant_id, action="read", resource="anything") is False
    finally:
        _cleanup_tenant(tenant_id)


def test_disabled_service_account_is_denied_even_with_a_self_scope_role() -> None:
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        admin = _admin_user_with_role(tenant_id, resource=resource, action=action)
        sa = create_service_account(tenant_id, _unique_name("svc"))
        _grant_role_to_service_account(
            actor_user_id=admin,
            tenant_id=tenant_id,
            service_account_id=sa.id,
            resource=resource,
            action=action,
            scope=RoleScope.SELF,
        )
        disable_service_account(tenant_id, sa.id)
        assert _sa_can(sa.id, tenant_id, tenant_id, action=action, resource=resource) is False
    finally:
        _cleanup_audit_log_for(tenant_id)
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)


def test_service_account_role_assignment_requires_authorization() -> None:
    """An actor with no "manage service account roles" capability at all
    cannot assign a role to a service account."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        unauthorized_user = create_user().id
        sa = create_service_account(tenant_id, _unique_name("svc"))
        role = create_role(tenant_id, _unique_name("role"))
        permission = register_permission(resource, action)
        grant_permission(tenant_id, role.id, permission.id)
        with pytest.raises(ServiceAccountRoleNotAuthorizedError):
            assign_service_account_role(
                actor_user_id=unauthorized_user,
                tenant_id=tenant_id,
                service_account_id=sa.id,
                role_id=role.id,
                scope=RoleScope.SELF,
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(unauthorized_user)
        _cleanup_permission(resource, action)


def test_service_account_role_assignment_rejects_unknown_service_account() -> None:
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        admin = _admin_user_with_role(tenant_id, resource="service_account_role", action="create")
        role = create_role(tenant_id, _unique_name("role"))
        permission = register_permission(resource, action)
        grant_permission(tenant_id, role.id, permission.id)
        with pytest.raises(InvalidPrincipalError):
            assign_service_account_role(
                actor_user_id=admin,
                tenant_id=tenant_id,
                service_account_id=uuid.uuid4(),
                role_id=role.id,
                scope=RoleScope.SELF,
            )
    finally:
        _cleanup_audit_log_for(tenant_id)
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission("service_account_role", "create")
        _cleanup_permission(resource, action)


# --- E. Hierarchy / tenant binding ------------------------------------------


def test_service_account_in_child_cannot_access_parent_without_explicit_grant() -> None:
    parent_id, child_id = _new_tenant(), _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        move_tenant(child_id, new_parent_id=parent_id)
        admin = _admin_user_with_role(child_id, resource=resource, action=action)
        sa = create_service_account(child_id, _unique_name("svc"))
        _grant_role_to_service_account(
            actor_user_id=admin,
            tenant_id=child_id,
            service_account_id=sa.id,
            resource=resource,
            action=action,
            scope=RoleScope.SUBTREE,
        )
        # SUBTREE at the child reaches the child's own descendants, never
        # upward to the parent.
        assert _sa_can(sa.id, child_id, parent_id, action=action, resource=resource) is False
    finally:
        _cleanup_audit_log_for(child_id)
        _cleanup_tenant(child_id)
        _cleanup_tenant(parent_id)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)


def test_service_account_subtree_role_at_parent_reaches_child() -> None:
    """Explicit SUBTREE at the service account's OWN tenant (the parent)
    reaches the child -- this is deliberate, explicit RBAC scope, never
    implicit hierarchy access."""
    parent_id, child_id = _new_tenant(), _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        move_tenant(child_id, new_parent_id=parent_id)
        admin = _admin_user_with_role(parent_id, resource=resource, action=action)
        sa = create_service_account(parent_id, _unique_name("svc"))
        _grant_role_to_service_account(
            actor_user_id=admin,
            tenant_id=parent_id,
            service_account_id=sa.id,
            resource=resource,
            action=action,
            scope=RoleScope.SUBTREE,
        )
        assert _sa_can(sa.id, parent_id, child_id, action=action, resource=resource) is True
    finally:
        _cleanup_audit_log_for(parent_id)
        _cleanup_tenant(child_id)
        _cleanup_tenant(parent_id)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)


def test_service_account_self_scope_at_parent_does_not_reach_child() -> None:
    parent_id, child_id = _new_tenant(), _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        move_tenant(child_id, new_parent_id=parent_id)
        admin = _admin_user_with_role(parent_id, resource=resource, action=action)
        sa = create_service_account(parent_id, _unique_name("svc"))
        _grant_role_to_service_account(
            actor_user_id=admin,
            tenant_id=parent_id,
            service_account_id=sa.id,
            resource=resource,
            action=action,
            scope=RoleScope.SELF,
        )
        assert _sa_can(sa.id, parent_id, child_id, action=action, resource=resource) is False
    finally:
        _cleanup_audit_log_for(parent_id)
        _cleanup_tenant(child_id)
        _cleanup_tenant(parent_id)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)


def test_service_account_in_one_tenant_cannot_access_sibling_tenant() -> None:
    parent_id, child_a, child_b = _new_tenant(), _new_tenant(), _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        move_tenant(child_a, new_parent_id=parent_id)
        move_tenant(child_b, new_parent_id=parent_id)
        admin = _admin_user_with_role(child_a, resource=resource, action=action)
        sa = create_service_account(child_a, _unique_name("svc"))
        _grant_role_to_service_account(
            actor_user_id=admin,
            tenant_id=child_a,
            service_account_id=sa.id,
            resource=resource,
            action=action,
            scope=RoleScope.SUBTREE,
        )
        assert _sa_can(sa.id, child_a, child_b, action=action, resource=resource) is False
    finally:
        _cleanup_audit_log_for(child_a)
        _cleanup_tenant(child_a)
        _cleanup_tenant(child_b)
        _cleanup_tenant(parent_id)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)


def test_service_account_role_at_one_tenant_does_not_leak_to_unrelated_tenant() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        admin = _admin_user_with_role(tenant_a, resource=resource, action=action)
        sa = create_service_account(tenant_a, _unique_name("svc"))
        _grant_role_to_service_account(
            actor_user_id=admin,
            tenant_id=tenant_a,
            service_account_id=sa.id,
            resource=resource,
            action=action,
            scope=RoleScope.SELF,
        )
        assert _sa_can(sa.id, tenant_a, tenant_b, action=action, resource=resource) is False
    finally:
        _cleanup_audit_log_for(tenant_a)
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)


# --- F. Deny / delegation with a service-account principal ------------------


def test_deny_overrides_service_account_ordinary_allow() -> None:
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        admin = _admin_user_with_role(tenant_id, resource=resource, action=action)

        sa = create_service_account(tenant_id, _unique_name("svc"))
        _grant_role_to_service_account(
            actor_user_id=admin,
            tenant_id=tenant_id,
            service_account_id=sa.id,
            resource=resource,
            action=action,
            scope=RoleScope.SELF,
        )
        assert _sa_can(sa.id, tenant_id, tenant_id, action=action, resource=resource) is True

        permission = register_permission(resource, action)
        deny = create_deny_for_service_account(
            grantor_user_id=admin,
            service_account_id=sa.id,
            service_account_tenant_id=tenant_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        assert _sa_can(sa.id, tenant_id, tenant_id, action=action, resource=resource) is False

        # Revoking the deny restores the independent allow path.
        revoke_deny(revoker_user_id=admin, tenant_id=tenant_id, deny_grant_id=deny.id)
        assert _sa_can(sa.id, tenant_id, tenant_id, action=action, resource=resource) is True
    finally:
        _cleanup_audit_log_for(tenant_id)
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)
        _cleanup_permission("deny_grant", "create")
        _cleanup_permission("deny_grant", "revoke")


def test_service_account_delegated_allow_works_and_is_still_subject_to_deny() -> None:
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        # A single human holds real SELF authority over (resource, action)
        # plus every management capability this test needs (delegation_grant
        # and deny_grant "create") -- `_admin_user_with_role()`'s own
        # docstring: bundled for test-fixture convenience only.
        admin = _admin_user_with_role(tenant_id, resource=resource, action=action)

        sa = create_service_account(tenant_id, _unique_name("svc"))
        permission = register_permission(resource, action)
        grant = create_delegation_to_service_account(
            delegator_user_id=admin,
            service_account_id=sa.id,
            service_account_tenant_id=tenant_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        assert _sa_can(sa.id, tenant_id, tenant_id, action=action, resource=resource) is True

        deny = create_deny_for_service_account(
            grantor_user_id=admin,
            service_account_id=sa.id,
            service_account_tenant_id=tenant_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        assert _sa_can(sa.id, tenant_id, tenant_id, action=action, resource=resource) is False
        assert grant.delegate_principal_type == PrincipalType.SERVICE_ACCOUNT.value
        assert deny.principal_type == PrincipalType.SERVICE_ACCOUNT.value
    finally:
        _cleanup_audit_log_for(tenant_id)
        _cleanup_tenant(tenant_id)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)
        _cleanup_permission("delegation_grant", "create")
        _cleanup_permission("deny_grant", "create")


def test_creating_a_delegation_to_an_unknown_service_account_fails_closed() -> None:
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        delegator = _admin_user_with_role(tenant_id, resource=resource, action=action)

        permission = register_permission(resource, action)
        with pytest.raises(InvalidPrincipalError):
            create_delegation_to_service_account(
                delegator_user_id=delegator,
                service_account_id=uuid.uuid4(),
                service_account_tenant_id=tenant_id,
                tenant_id=tenant_id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
            )
    finally:
        _cleanup_audit_log_for(tenant_id)
        _cleanup_tenant(tenant_id)
        _cleanup_user(delegator)
        _cleanup_permission(resource, action)
        _cleanup_permission("delegation_grant", "create")


# --- G. Multiple human memberships do not transfer to a service account ----


def test_users_unrelated_membership_does_not_grant_the_service_account_anything() -> None:
    tenant_a, tenant_b = _new_tenant(), _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        # admin is a member of BOTH tenants, with real authority in each.
        admin = _admin_user_with_role(tenant_a, resource=resource, action=action)
        membership_b = add_tenant_membership(tenant_b, admin)
        role_b = create_role(tenant_b, _unique_name("role-b"))
        permission_b = register_permission(resource, action)
        grant_permission(tenant_b, role_b.id, permission_b.id)
        assign_role(tenant_b, membership_b.id, role_b.id, scope=RoleScope.SELF)
        assert can(actor_id=admin, tenant_id=tenant_b, action=action, resource=resource) is True

        # A service account belonging only to tenant_a, granted a role
        # only in tenant_a, must not somehow inherit admin's authority
        # in tenant_b merely because admin manages it.
        sa = create_service_account(tenant_a, _unique_name("svc"))
        _grant_role_to_service_account(
            actor_user_id=admin,
            tenant_id=tenant_a,
            service_account_id=sa.id,
            resource=resource,
            action=action,
            scope=RoleScope.SELF,
        )
        assert _sa_can(sa.id, tenant_a, tenant_b, action=action, resource=resource) is False
    finally:
        _cleanup_audit_log_for(tenant_a)
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_user(admin)
        _cleanup_permission(resource, action)


# --- H. Privilege amplification ---------------------------------------------


def test_self_only_actor_cannot_create_a_subtree_service_account_role() -> None:
    """architecture research Phase E: "SELF cannot create broader SUBTREE
    machine authority"."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        # actor has SELF-only authority over (resource, action), plus the
        # separate "manage service account roles" capability.
        actor = create_user().id
        membership = add_tenant_membership(tenant_id, actor)
        self_role = create_role(tenant_id, _unique_name("self-role"))
        permission = register_permission(resource, action)
        grant_permission(tenant_id, self_role.id, permission.id)
        assign_role(tenant_id, membership.id, self_role.id, scope=RoleScope.SELF)

        mgmt_role = create_role(tenant_id, _unique_name("mgmt-role"))
        mgmt_permission = register_permission("service_account_role", "create")
        grant_permission(tenant_id, mgmt_role.id, mgmt_permission.id)
        assign_role(tenant_id, membership.id, mgmt_role.id, scope=RoleScope.SELF)

        sa = create_service_account(tenant_id, _unique_name("svc"))
        target_role = create_role(tenant_id, _unique_name("target-role"))
        grant_permission(tenant_id, target_role.id, permission.id)

        with pytest.raises(ServiceAccountRoleNotAuthorizedError):
            assign_service_account_role(
                actor_user_id=actor,
                tenant_id=tenant_id,
                service_account_id=sa.id,
                role_id=target_role.id,
                scope=RoleScope.SUBTREE,
            )
    finally:
        _cleanup_audit_log_for(tenant_id)
        _cleanup_tenant(tenant_id)
        _cleanup_user(actor)
        _cleanup_permission(resource, action)
        _cleanup_permission("service_account_role", "create")


def test_actor_cannot_grant_a_permission_it_does_not_itself_hold() -> None:
    """ "service account cannot grant itself permissions" -- generalized:
    no actor can use `assign_service_account_role()` to hand out a
    permission it does not itself, ordinarily, possess."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        actor = create_user().id
        membership = add_tenant_membership(tenant_id, actor)
        mgmt_role = create_role(tenant_id, _unique_name("mgmt-role"))
        mgmt_permission = register_permission("service_account_role", "create")
        grant_permission(tenant_id, mgmt_role.id, mgmt_permission.id)
        assign_role(tenant_id, membership.id, mgmt_role.id, scope=RoleScope.SUBTREE)
        # actor has the management capability but NOT (resource, action)
        # itself.
        permission = register_permission(resource, action)

        sa = create_service_account(tenant_id, _unique_name("svc"))
        target_role = create_role(tenant_id, _unique_name("target-role"))
        grant_permission(tenant_id, target_role.id, permission.id)

        with pytest.raises(ServiceAccountRoleNotAuthorizedError):
            assign_service_account_role(
                actor_user_id=actor,
                tenant_id=tenant_id,
                service_account_id=sa.id,
                role_id=target_role.id,
                scope=RoleScope.SELF,
            )
        assert _sa_can(sa.id, tenant_id, tenant_id, action=action, resource=resource) is False
    finally:
        _cleanup_audit_log_for(tenant_id)
        _cleanup_tenant(tenant_id)
        _cleanup_user(actor)
        _cleanup_permission(resource, action)
        _cleanup_permission("service_account_role", "create")


def test_delegated_authority_cannot_be_used_to_grant_a_service_account_role() -> None:
    """ "service account cannot use delegated authority to create broader
    machine authority" -- `assign_service_account_role()`'s
    anti-amplification check reuses `_actor_reaches_tenant_at_scope()`,
    which never consults `DelegationGrant` rows, exactly like
    `create_delegation()`'s own redelegation-prevention."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        # A real holder of (resource, action) at SUBTREE, who delegates
        # it onward to `delegate_user` (never via ordinary membership).
        holder = _admin_user_with_role(tenant_id, resource=resource, action=action)

        delegate_user = create_user().id
        permission = register_permission(resource, action)
        from core.rbac.service import create_delegation

        create_delegation(
            delegator_user_id=holder,
            delegate_user_id=delegate_user,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        # delegate_user can now act via delegation...
        assert (
            can(actor_id=delegate_user, tenant_id=tenant_id, action=action, resource=resource)
            is True
        )

        # ...but also needs the "manage service account roles" capability
        # to attempt granting it onward to a service account.
        delegate_membership = add_tenant_membership(tenant_id, delegate_user)
        mgmt_role = create_role(tenant_id, _unique_name("mgmt-role"))
        mgmt_permission = register_permission("service_account_role", "create")
        grant_permission(tenant_id, mgmt_role.id, mgmt_permission.id)
        assign_role(tenant_id, delegate_membership.id, mgmt_role.id, scope=RoleScope.SELF)

        sa = create_service_account(tenant_id, _unique_name("svc"))
        target_role = create_role(tenant_id, _unique_name("target-role"))
        grant_permission(tenant_id, target_role.id, permission.id)

        with pytest.raises(ServiceAccountRoleNotAuthorizedError):
            assign_service_account_role(
                actor_user_id=delegate_user,
                tenant_id=tenant_id,
                service_account_id=sa.id,
                role_id=target_role.id,
                scope=RoleScope.SELF,
            )
        assert _sa_can(sa.id, tenant_id, tenant_id, action=action, resource=resource) is False
    finally:
        _cleanup_audit_log_for(tenant_id)
        _cleanup_tenant(tenant_id)
        _cleanup_user(holder)
        _cleanup_user(delegate_user)
        _cleanup_permission(resource, action)
        _cleanup_permission("delegation_grant", "create")
        _cleanup_permission("service_account_role", "create")
