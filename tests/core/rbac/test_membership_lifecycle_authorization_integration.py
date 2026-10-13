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
concerns -- see `saas_os/core/rbac/authorization.py`'s module docstring,
"Membership lifecycle" paragraph.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from lifecycle_callers import platform_operator
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity.service import (
    add_tenant_membership,
    create_service_account,
    create_user,
    reactivate_membership,
    revoke_membership,
    suspend_membership,
)
from saas_os.core.rbac import PrincipalType, RoleScope, can
from saas_os.core.rbac.errors import DelegationNotAuthorizedError
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    assign_service_account_role,
    create_delegation,
    create_deny,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope


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


def _new_tenant(*, parent_id: uuid.UUID | None = None) -> uuid.UUID:
    return create_tenant(_unique_name("tenant"), parent_id=parent_id, caller=platform_operator()).id


def _grant_delegation_create_capability(tenant_id: uuid.UUID, membership_id: uuid.UUID) -> None:
    role = create_role(tenant_id, _unique_name("delegation-admin-role"), caller=_PROVISIONING)
    permission = register_permission("delegation_grant", "create")
    grant_permission(tenant_id, role.id, permission.id, caller=_PROVISIONING)
    assign_first_role_for_new_tenant(
        tenant_id, membership_id, role.id, scope=RoleScope.SELF, caller=_PROVISIONING
    )


def _member_with_role(
    tenant_id: uuid.UUID, *, resource: str, action: str, scope: RoleScope = RoleScope.SELF
) -> tuple[uuid.UUID, uuid.UUID]:
    """A fresh user, an ACTIVE membership, and a role granting
    `(resource, action)` at `scope`. Returns (user_id, membership_id)."""
    user_id = create_user().id
    membership = add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
    role = create_role(tenant_id, _unique_name("role"), caller=_PROVISIONING)
    permission = register_permission(resource, action)
    grant_permission(tenant_id, role.id, permission.id, caller=_PROVISIONING)
    assign_first_role_for_new_tenant(
        tenant_id, membership.id, role.id, scope=scope, caller=_PROVISIONING
    )
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
        suspend_membership(
            tenant_id,
            membership_id,
            caller=_authority_admin(
                tenant_id,
                ("membership", "suspend"),
                ("membership", "reactivate"),
                ("membership", "revoke"),
            ),
        )
        assert not can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_permission(resource, action)


def test_revoked_membership_does_not_authorize() -> None:
    tenant_id = _new_tenant()
    try:
        resource, action = _unique_name("resource"), "read"
        user_id, membership_id = _member_with_role(tenant_id, resource=resource, action=action)
        revoke_membership(
            tenant_id,
            membership_id,
            caller=_authority_admin(
                tenant_id,
                ("membership", "suspend"),
                ("membership", "reactivate"),
                ("membership", "revoke"),
            ),
        )
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
        suspend_membership(
            tenant_id,
            membership_id,
            caller=_authority_admin(
                tenant_id,
                ("membership", "suspend"),
                ("membership", "reactivate"),
                ("membership", "revoke"),
            ),
        )

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
        suspend_membership(
            tenant_id,
            membership_id,
            caller=_authority_admin(
                tenant_id,
                ("membership", "suspend"),
                ("membership", "reactivate"),
                ("membership", "revoke"),
            ),
        )
        assert not can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)

        reactivate_membership(
            tenant_id,
            membership_id,
            caller=_authority_admin(
                tenant_id,
                ("membership", "suspend"),
                ("membership", "reactivate"),
                ("membership", "revoke"),
            ),
        )
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

        suspend_membership(
            parent_id,
            membership_id,
            caller=_authority_admin(
                parent_id,
                ("membership", "suspend"),
                ("membership", "reactivate"),
                ("membership", "revoke"),
            ),
        )
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
            delegate_user_id=delegate_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
            caller=UserCaller(delegator_id),
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
        delegate_membership = add_tenant_membership(tenant_id, delegate_id, caller=_PROVISIONING)
        permission = register_permission(resource, action)

        create_delegation(
            delegate_user_id=delegate_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
            caller=UserCaller(delegator_id),
        )
        assert can(actor_id=delegate_id, tenant_id=tenant_id, action=action, resource=resource)

        suspend_membership(
            tenant_id,
            delegate_membership.id,
            caller=_authority_admin(
                tenant_id,
                ("membership", "suspend"),
                ("membership", "reactivate"),
                ("membership", "revoke"),
            ),
        )
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

        suspend_membership(
            tenant_id,
            delegator_membership_id,
            caller=_authority_admin(
                tenant_id,
                ("membership", "suspend"),
                ("membership", "reactivate"),
                ("membership", "revoke"),
            ),
        )

        with pytest.raises(DelegationNotAuthorizedError):
            create_delegation(
                delegate_user_id=delegate_id,
                tenant_id=tenant_id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
                caller=UserCaller(delegator_id),
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

        deny_role = create_role(tenant_id, _unique_name("deny-admin-role"), caller=_PROVISIONING)
        deny_create_permission = register_permission("deny_grant", "create")
        grant_permission(tenant_id, deny_role.id, deny_create_permission.id, caller=_PROVISIONING)
        assign_first_role_for_new_tenant(
            tenant_id, membership_id, deny_role.id, scope=RoleScope.SELF, caller=_PROVISIONING
        )

        permission = register_permission(resource, action)
        create_deny(
            principal_user_id=user_id,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
            caller=UserCaller(user_id),
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
        svc_role_admin_role = create_role(
            tenant_id, _unique_name("svc-role-admin-role"), caller=_PROVISIONING
        )
        svc_role_create_permission = register_permission("service_account_role", "create")
        grant_permission(
            tenant_id, svc_role_admin_role.id, svc_role_create_permission.id, caller=_PROVISIONING
        )
        assign_first_role_for_new_tenant(
            tenant_id,
            admin_membership_id,
            svc_role_admin_role.id,
            scope=RoleScope.SELF,
            caller=_PROVISIONING,
        )

        service_account = create_service_account(
            tenant_id, _unique_name("svc"), caller=_PROVISIONING
        )
        role = create_role(tenant_id, _unique_name("svc-role"), caller=_PROVISIONING)
        permission = register_permission(resource, action)
        grant_permission(tenant_id, role.id, permission.id, caller=_PROVISIONING)
        assign_service_account_role(
            tenant_id=tenant_id,
            service_account_id=service_account.id,
            role_id=role.id,
            scope=RoleScope.SELF,
            caller=UserCaller(admin_id),
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
        suspend_membership(
            tenant_id,
            admin_membership_id,
            caller=_authority_admin(
                tenant_id,
                ("membership", "suspend"),
                ("membership", "reactivate"),
                ("membership", "revoke"),
            ),
        )
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
