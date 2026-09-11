"""`DelegationGrant` authorization integration tests against a real
PostgreSQL instance (architecture research: universal multi-tenant
tenancy, Phase C -- "Delegation").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/rbac/test_scoped_role_authorization_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_delegation_authorization_integration.py

Builds real tenants/users/roles/grants for every test -- `can()`'s
delegation path reads `core.delegation_grants` through a real
`tenant_session_scope()` query, so these tests exercise the real RLS
policy, the real advisory-lock-protected hierarchy primitives
(`core.tenancy.create_tenant`/`move_tenant`), and the real anti-
amplification check, never a stub.

Cleanup ordering (lesson learned in the Phase B test suite):
`delegation_grants.delegator_principal_id`/`delegate_principal_id` are
plain (non-cascading) foreign keys to `core.users.id`, so a delegation
grant referencing a user must be deleted before that user is -- unlike
`delegation_grants.tenant_id` (`ON DELETE CASCADE`), which needs no
explicit cleanup at all when the *tenant* itself is torn down.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from core.identity.service import add_tenant_membership, create_user
from core.rbac.errors import (
    DelegationNotAuthorizedError,
    DelegationNotFoundError,
    InvalidDelegationTimeRangeError,
    InvalidPrincipalError,
    PermissionNotFoundError,
)
from core.rbac.service import (
    assign_role,
    create_delegation,
    create_role,
    grant_permission,
    register_permission,
    revoke_delegation,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.identity import get_membership
from core.rbac import RoleScope, can
from core.tenancy import create_tenant, move_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_delegation_grants_table() -> None:
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
            conn.execute(text("SELECT 1 FROM core.delegation_grants LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.delegation_grants does not exist yet -- run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    """`delegation_grants.tenant_id` cascades, so no explicit cleanup of
    that table is needed here -- only the tables Phase A/B already clean
    up this way."""
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


def _can(user_id: uuid.UUID, tenant_id: uuid.UUID, *, action: str, resource: str) -> bool:
    return can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)


def _cleanup_role(tenant_id: uuid.UUID, role_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.role_permissions WHERE tenant_id = :t AND role_id = :r"),
            {"t": str(tenant_id), "r": str(role_id)},
        )
        session.execute(
            text("DELETE FROM core.membership_roles WHERE tenant_id = :t AND role_id = :r"),
            {"t": str(tenant_id), "r": str(role_id)},
        )
        session.execute(
            text("DELETE FROM core.roles WHERE tenant_id = :t AND id = :r"),
            {"t": str(tenant_id), "r": str(role_id)},
        )


def _cleanup_membership(tenant_id: uuid.UUID, user_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t AND user_id = :u"),
            {"t": str(tenant_id), "u": str(user_id)},
        )


def _cleanup_audit_log_for(tenant_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """`core.audit_log.actor_user_id` is a plain (non-cascading) FK to
    `core.users.id` -- `create_delegation()`/`revoke_delegation()` write a
    real audit entry on every successful call (using the existing
    `core.audit_log` mechanism, architecture research Phase C), so any
    user who ever successfully acted as a delegator/revoker must have
    their audit rows cleared before `_cleanup_user()`, exactly the same
    FK-ordering lesson as `_cleanup_delegations_involving()` above. A
    harmless no-op when no such row exists (a rejected/failed attempt
    never reaches the audit write).

    Uses the privileged migrations role, not the ordinary runtime
    `tenant_session_scope()` -- `core.audit_log`'s own migration
    (`2e7cb8c64903`) deliberately `REVOKE`s UPDATE/DELETE on this table
    from the restricted runtime role entirely (immutability enforced at
    the privilege level, docs/IMPLEMENTATION-ROADMAP.md Phase 3.4's own
    Security Requirement), so the runtime role genuinely cannot delete
    these rows -- by design, not a bug this phase should route around.
    """
    engine = build_engine(get_migrations_database_config())
    try:
        admin_session_factory = build_session_factory(engine)
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t AND actor_user_id = :u"),
                {"t": str(tenant_id), "u": str(user_id)},
            )
    finally:
        engine.dispose()


def _cleanup_delegations_involving(tenant_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """`delegation_grants.delegator_principal_id`/`delegate_principal_id`
    are plain FKs to `core.users.id` -- must be cleared before
    `_cleanup_user()`, exactly the lesson Phase B's own test suite
    learned for `tenant_memberships`/`role_permissions`."""
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text(
                "DELETE FROM core.delegation_grants WHERE tenant_id = :t "
                "AND (delegator_principal_id = :u OR delegate_principal_id = :u)"
            ),
            {"t": str(tenant_id), "u": str(user_id)},
        )


def _grant_role(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    *,
    resource: str,
    action: str,
    scope: RoleScope,
) -> uuid.UUID:
    """Give `user_id` a role in `tenant_id` granting `(resource, action)`
    at `scope`, reusing an existing membership if `user_id` already has
    one in `tenant_id` (a test may grant more than one role/permission to
    the same delegator -- a user has at most one membership per tenant).
    Returns the role id (for cleanup)."""
    membership = get_membership(tenant_id, user_id)
    if membership is None:
        membership = add_tenant_membership(tenant_id, user_id)
    role = create_role(tenant_id, _unique_name("role"))
    permission = register_permission(resource, action)
    grant_permission(tenant_id, role.id, permission.id)
    assign_role(tenant_id, membership.id, role.id, scope=scope)
    return role.id


def _grant_delegation_management(tenant_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
    """Give `user_id` the dedicated delegation-management capability
    (`create_delegation()`'s own gate) in `tenant_id`, at SELF scope --
    returns the role id."""
    return _grant_role(
        tenant_id, user_id, resource="delegation_grant", action="create", scope=RoleScope.SELF
    )


def _grant_delegation_revoke(tenant_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
    return _grant_role(
        tenant_id, user_id, resource="delegation_grant", action="revoke", scope=RoleScope.SELF
    )


# --- Hierarchy fixture (mirrors test_scoped_role_authorization_integration) -


class _Hierarchy:
    """
        root
        ├── a
        │   └── b
        └── sibling
    plus a wholly unrelated second root, `unrelated`.
    """

    def __init__(self) -> None:
        self.root = create_tenant(_unique_name("root"))
        self.a = create_tenant(_unique_name("a"), parent_id=self.root.id)
        self.b = create_tenant(_unique_name("b"), parent_id=self.a.id)
        self.sibling = create_tenant(_unique_name("sibling"), parent_id=self.root.id)
        self.unrelated = create_tenant(_unique_name("unrelated"))

    def cleanup(self) -> None:
        for tenant_id in (self.b.id, self.a.id, self.sibling.id, self.root.id, self.unrelated.id):
            _cleanup_tenant(tenant_id)


@pytest.fixture
def hierarchy():
    h = _Hierarchy()
    try:
        yield h
    finally:
        h.cleanup()


# --- Creation ----------------------------------------------------------


def test_valid_delegation_creation_authorizes_the_delegate(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is False

        grant = create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert grant.revoked_at is None
        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is True
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_invalid_delegator_principal_rejected(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegate = create_user()
    try:
        permission = register_permission(resource, action)
        with pytest.raises(InvalidPrincipalError):
            create_delegation(
                delegator_user_id=uuid.uuid4(),
                delegate_user_id=delegate.id,
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
            )
    finally:
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_invalid_delegate_principal_rejected(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        with pytest.raises(InvalidPrincipalError):
            create_delegation(
                delegator_user_id=delegator.id,
                delegate_user_id=uuid.uuid4(),
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
            )
    finally:
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_permission(resource, action)


def test_invalid_time_range_rejected(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        now = datetime.now(UTC)
        with pytest.raises(InvalidDelegationTimeRangeError):
            create_delegation(
                delegator_user_id=delegator.id,
                delegate_user_id=delegate.id,
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
                starts_at=now,
                expires_at=now - timedelta(seconds=1),
            )
    finally:
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_nonexistent_permission_rejected(hierarchy: _Hierarchy) -> None:
    delegator = create_user()
    delegate = create_user()
    try:
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)

        with pytest.raises(PermissionNotFoundError):
            create_delegation(
                delegator_user_id=delegator.id,
                delegate_user_id=delegate.id,
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SELF,
                permission_id=uuid.uuid4(),
            )
    finally:
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)


# --- Scope ---------------------------------------------------------------


def test_self_mode_delegation_authorizes_only_target_tenant(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is True
        assert _can(delegate.id, hierarchy.b.id, action=action, resource=resource) is False
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_subtree_mode_delegation_authorizes_descendants(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )

        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is True
        assert _can(delegate.id, hierarchy.b.id, action=action, resource=resource) is True
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_unrelated_tenant_is_denied(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )

        assert (
            can(
                actor_id=delegate.id,
                tenant_id=hierarchy.unrelated.id,
                action=action,
                resource=resource,
            )
            is False
        )
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_sibling_tenant_denied_unless_explicitly_delegated(hierarchy: _Hierarchy) -> None:
    """A delegation scoped to `a` (even SUBTREE) must not reach `sibling`
    -- siblings share a parent, not a descendant relationship."""
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )

        assert _can(delegate.id, hierarchy.sibling.id, action=action, resource=resource) is False
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


# --- Validity (time) -------------------------------------------------------


def test_delegation_before_starts_at_is_denied(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        future_start = datetime.now(UTC) + timedelta(hours=1)
        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
            starts_at=future_start,
        )

        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_delegation_after_expires_at_is_denied(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        past_start = datetime.now(UTC) - timedelta(hours=2)
        past_expiry = datetime.now(UTC) - timedelta(hours=1)
        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
            starts_at=past_start,
            expires_at=past_expiry,
        )

        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_active_grant_within_window_is_allowed(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
            starts_at=datetime.now(UTC) - timedelta(minutes=5),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is True
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


# --- Revocation ------------------------------------------------------------


def test_grant_works_before_revoke_and_fails_immediately_after(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        grant = create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is True

        revoke_delegation(
            revoker_user_id=delegator.id, tenant_id=hierarchy.a.id, delegation_grant_id=grant.id
        )

        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_revoke_is_idempotent(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        grant = create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        revoke_delegation(
            revoker_user_id=delegator.id, tenant_id=hierarchy.a.id, delegation_grant_id=grant.id
        )
        first_revoked_at = revoke_delegation(
            revoker_user_id=delegator.id, tenant_id=hierarchy.a.id, delegation_grant_id=grant.id
        ).revoked_at

        assert first_revoked_at is not None
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_revoke_unknown_grant_raises(hierarchy: _Hierarchy) -> None:
    delegator = create_user()
    try:
        with pytest.raises(DelegationNotFoundError):
            revoke_delegation(
                revoker_user_id=delegator.id,
                tenant_id=hierarchy.a.id,
                delegation_grant_id=uuid.uuid4(),
            )
    finally:
        _cleanup_user(delegator.id)


def test_non_delegator_without_revoke_permission_cannot_revoke(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    bystander = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        grant = create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        with pytest.raises(DelegationNotAuthorizedError):
            revoke_delegation(
                revoker_user_id=bystander.id, tenant_id=hierarchy.a.id, delegation_grant_id=grant.id
            )
        # Untouched: still valid.
        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is True
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_user(bystander.id)
        _cleanup_permission(resource, action)


def test_authorized_third_party_can_revoke(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    admin = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        revoke_role_id = _grant_delegation_revoke(hierarchy.a.id, admin.id)
        permission = register_permission(resource, action)

        grant = create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        revoke_delegation(
            revoker_user_id=admin.id, tenant_id=hierarchy.a.id, delegation_grant_id=grant.id
        )

        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, admin.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_role(hierarchy.a.id, revoke_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_membership(hierarchy.a.id, admin.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_user(admin.id)
        _cleanup_permission(resource, action)


# --- Hierarchy dynamics: live, not snapshotted -----------------------------


def test_moving_descendant_out_of_subtree_removes_delegated_authorization_live() -> None:
    resource, action = _unique_name("resource"), "read"
    a = create_tenant(_unique_name("a"))
    b = create_tenant(_unique_name("b"), parent_id=a.id)
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        management_role_id = _grant_delegation_management(a.id, delegator.id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=a.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )

        assert _can(delegate.id, b.id, action=action, resource=resource) is True

        move_tenant(b.id, None)

        assert _can(delegate.id, b.id, action=action, resource=resource) is False
        assert _can(delegate.id, a.id, action=action, resource=resource) is True
    finally:
        _cleanup_delegations_involving(a.id, delegator.id)
        _cleanup_audit_log_for(a.id, delegator.id)
        _cleanup_role(a.id, role_id)
        _cleanup_role(a.id, management_role_id)
        _cleanup_membership(a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)
        _cleanup_tenant(b.id)
        _cleanup_tenant(a.id)


# --- Privilege amplification -------------------------------------------


def test_cannot_delegate_a_permission_the_delegator_does_not_possess(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        # The delegator is never granted (resource, action) at all.
        permission = register_permission(resource, action)

        with pytest.raises(DelegationNotAuthorizedError):
            create_delegation(
                delegator_user_id=delegator.id,
                delegate_user_id=delegate.id,
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
            )
    finally:
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_cannot_delegate_subtree_with_only_self_level_authority(hierarchy: _Hierarchy) -> None:
    """The delegator holds (resource, action) at `a` only via a SELF-scoped
    role -- a SUBTREE-mode delegation from `a` would reach `b` too, which
    the delegator themselves cannot reach. Must be rejected."""
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        with pytest.raises(DelegationNotAuthorizedError):
            create_delegation(
                delegator_user_id=delegator.id,
                delegate_user_id=delegate.id,
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SUBTREE,
                permission_id=permission.id,
            )

        # Nothing was authorized on b as a result of the rejected attempt.
        assert _can(delegate.id, hierarchy.b.id, action=action, resource=resource) is False
    finally:
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_cannot_create_delegation_without_the_management_permission(hierarchy: _Hierarchy) -> None:
    """The delegator genuinely possesses (resource, action) at `a`, but was
    never granted the dedicated `delegation_grant`/`create` capability --
    must still be rejected (two independent gates, both required)."""
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        permission = register_permission(resource, action)

        with pytest.raises(DelegationNotAuthorizedError):
            create_delegation(
                delegator_user_id=delegator.id,
                delegate_user_id=delegate.id,
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
            )
    finally:
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


# --- Redelegation: default false, no implicit chaining -----------------


def test_default_allow_redelegate_is_false(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        grant = create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert grant.allow_redelegate is False
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


def test_delegate_cannot_use_delegated_authority_to_create_a_further_delegation(
    hierarchy: _Hierarchy,
) -> None:
    """No implicit redelegation: a delegate with ONLY delegated authority
    (no ordinary membership/role of their own, and specifically no
    ordinary grant of the `delegation_grant`/`create` capability) cannot
    call `create_delegation()` at all -- `_actor_reaches_tenant_at_scope()`
    never consults `DelegationGrant` rows, so the delegate's delegated
    permission (even the delegation-management one, if somehow delegated)
    does not satisfy the ordinary-authorization gate."""
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    third_party = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)
        management_permission = register_permission("delegation_grant", "create")

        # Delegate the *management* capability itself to `delegate` --
        # even so, `delegate` must not be able to use it to create a new
        # delegation, because create_delegation()'s own authorization gate
        # never consults DelegationGrant rows in the first place.
        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=management_permission.id,
        )
        # Confirm the delegation itself is real and effective for `can()`.
        assert (
            can(
                actor_id=delegate.id,
                tenant_id=hierarchy.a.id,
                action="create",
                resource="delegation_grant",
            )
            is True
        )

        # Yet using it to call create_delegation() directly still fails --
        # create_delegation()'s gate is ordinary-authorization-only.
        with pytest.raises(DelegationNotAuthorizedError):
            create_delegation(
                delegator_user_id=delegate.id,
                delegate_user_id=third_party.id,
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
            )
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_delegations_involving(hierarchy.a.id, delegate.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegate.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_user(third_party.id)
        _cleanup_permission(resource, action)
        _cleanup_permission("delegation_grant", "create")


# --- Multiple delegations ---------------------------------------------


def test_one_revoked_grant_does_not_invalidate_a_separate_valid_grant(
    hierarchy: _Hierarchy,
) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        grant_1 = create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        revoke_delegation(
            revoker_user_id=delegator.id, tenant_id=hierarchy.a.id, delegation_grant_id=grant_1.id
        )

        # A second, independent grant for the same delegate/permission/scope.
        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is True
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


# --- Membership independence --------------------------------------------


def test_delegate_needs_no_membership_in_the_target_tenant(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    delegate = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=delegate.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        with tenant_session_scope(hierarchy.a.id) as session:
            membership_count = session.execute(
                text(
                    "SELECT COUNT(*) FROM core.tenant_memberships "
                    "WHERE tenant_id = :t AND user_id = :u"
                ),
                {"t": str(hierarchy.a.id), "u": str(delegate.id)},
            ).scalar_one()
        assert membership_count == 0

        assert _can(delegate.id, hierarchy.a.id, action=action, resource=resource) is True
    finally:
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_user(delegator.id)
        _cleanup_user(delegate.id)
        _cleanup_permission(resource, action)


# --- RLS: delegation does not alter existing tenant isolation ------------


def test_delegation_grants_table_has_force_row_level_security() -> None:
    with session_scope() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'delegation_grants'"
            )
        ).one()
    assert row[0] is True
    assert row[1] is True
