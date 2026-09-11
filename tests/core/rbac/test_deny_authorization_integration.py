"""`DenyGrant` authorization integration tests against a real PostgreSQL
instance (architecture research: universal multi-tenant tenancy, Phase D
-- "Explicit Deny": "DENY overrides ALLOW").

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/rbac/test_delegation_authorization_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_deny_authorization_integration.py

Builds real tenants/users/roles/grants/delegations for every test --
`can()`'s deny check reads `core.deny_grants` through a real
`tenant_session_scope()` query, so these tests exercise the real RLS
policy, the real advisory-lock-protected hierarchy primitives, and the
real allow paths (ordinary membership-role, inherited SUBTREE, and
delegation) a deny must override, never a stub.

The central property under test throughout this file: a matching,
unrevoked `DenyGrant` makes `can()` return `False`, no matter which allow
path (or combination of allow paths) would otherwise have returned
`True` -- see `core/rbac/authorization.py`'s module docstring, step 0.

Cleanup ordering (lesson learned in the Phase C test suite):
`deny_grants.principal_id` is a plain (non-cascading) foreign key to
`core.users.id`, so a deny grant naming a user must be deleted before
that user is -- unlike `deny_grants.tenant_id` (`ON DELETE CASCADE`),
which needs no explicit cleanup at all when the *tenant* itself is torn
down.
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.service import add_tenant_membership, create_user
from core.rbac.errors import (
    DenyNotAuthorizedError,
    DenyNotFoundError,
    InvalidPrincipalError,
    PermissionNotFoundError,
)
from core.rbac.service import (
    assign_role,
    create_delegation,
    create_deny,
    create_role,
    grant_permission,
    register_permission,
    revoke_deny,
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
def _require_reachable_database_with_deny_grants_table() -> None:
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
            conn.execute(text("SELECT 1 FROM core.deny_grants LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.deny_grants does not exist yet -- run `alembic upgrade head` first: {exc}"
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
    """`deny_grants.tenant_id`/`delegation_grants.tenant_id` both cascade,
    so no explicit cleanup of those tables is needed here -- only the
    tables Phase A/B already clean up this way."""
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
    `core.users.id` -- `create_deny()`/`revoke_deny()` write a real audit
    entry on every successful call, exactly like `create_delegation()`/
    `revoke_delegation()` -- see that test file's own docstring for the
    full FK-ordering rationale."""
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


def _cleanup_denies_involving(tenant_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """`deny_grants.principal_id` is a plain FK to `core.users.id` --
    must be cleared before `_cleanup_user()`."""
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.deny_grants WHERE tenant_id = :t AND principal_id = :u"),
            {"t": str(tenant_id), "u": str(user_id)},
        )


def _cleanup_delegations_involving(tenant_id: uuid.UUID, user_id: uuid.UUID) -> None:
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
    one in `tenant_id`. Returns the role id (for cleanup)."""
    membership = get_membership(tenant_id, user_id)
    if membership is None:
        membership = add_tenant_membership(tenant_id, user_id)
    role = create_role(tenant_id, _unique_name("role"))
    permission = register_permission(resource, action)
    grant_permission(tenant_id, role.id, permission.id)
    assign_role(tenant_id, membership.id, role.id, scope=scope)
    return role.id


def _grant_deny_management(tenant_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
    """Give `user_id` the dedicated deny-management capability
    (`create_deny()`'s own gate) in `tenant_id`, at SELF scope -- returns
    the role id."""
    return _grant_role(
        tenant_id, user_id, resource="deny_grant", action="create", scope=RoleScope.SELF
    )


def _grant_deny_revoke(tenant_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
    return _grant_role(
        tenant_id, user_id, resource="deny_grant", action="revoke", scope=RoleScope.SELF
    )


def _grant_delegation_management(tenant_id: uuid.UUID, user_id: uuid.UUID) -> uuid.UUID:
    return _grant_role(
        tenant_id, user_id, resource="delegation_grant", action="create", scope=RoleScope.SELF
    )


# --- Hierarchy fixture (mirrors test_delegation_authorization_integration) -


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


def test_valid_deny_creation_blocks_a_previously_allowed_actor(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is True

        deny = create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert deny.revoked_at is None
        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_invalid_principal_rejected(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    try:
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        with pytest.raises(InvalidPrincipalError):
            create_deny(
                grantor_user_id=grantor.id,
                principal_user_id=uuid.uuid4(),
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
            )
    finally:
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_permission(resource, action)


def test_nonexistent_permission_rejected(hierarchy: _Hierarchy) -> None:
    grantor = create_user()
    actor = create_user()
    try:
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)

        with pytest.raises(PermissionNotFoundError):
            create_deny(
                grantor_user_id=grantor.id,
                principal_user_id=actor.id,
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SELF,
                permission_id=uuid.uuid4(),
            )
    finally:
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)


def test_cannot_create_deny_without_the_management_permission(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        permission = register_permission(resource, action)

        with pytest.raises(DenyNotAuthorizedError):
            create_deny(
                grantor_user_id=grantor.id,
                principal_user_id=actor.id,
                tenant_id=hierarchy.a.id,
                scope_mode=RoleScope.SELF,
                permission_id=permission.id,
            )
    finally:
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_grantor_need_not_possess_the_permission_being_denied(hierarchy: _Hierarchy) -> None:
    """No anti-amplification check on deny creation -- a deny can only
    remove authority, never grant it (`DenyGrant`'s own docstring). The
    grantor here never holds `(resource, action)` at all, only the
    dedicated deny-management capability."""
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        actor_role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        permission = register_permission(resource, action)

        deny = create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert deny.revoked_at is None
        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_role(hierarchy.a.id, actor_role_id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


# --- Scope ---------------------------------------------------------------


def test_self_scope_deny_affects_only_target_tenant(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        assert _can(actor.id, hierarchy.b.id, action=action, resource=resource) is True

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
        # Unaffected: the SELF-scoped deny at `a` does not reach `b`.
        assert _can(actor.id, hierarchy.b.id, action=action, resource=resource) is True
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_subtree_scope_deny_at_ancestor_affects_descendants(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        assert _can(actor.id, hierarchy.b.id, action=action, resource=resource) is True

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
        assert _can(actor.id, hierarchy.b.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_deny_at_unrelated_tenant_does_not_affect_authorization(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_deny_management(hierarchy.unrelated.id, grantor.id)
        permission = register_permission(resource, action)

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.unrelated.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is True
    finally:
        _cleanup_denies_involving(hierarchy.unrelated.id, actor.id)
        _cleanup_audit_log_for(hierarchy.unrelated.id, grantor.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.unrelated.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.unrelated.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_sibling_tenant_unaffected_by_deny_scoped_to_a(hierarchy: _Hierarchy) -> None:
    """A deny scoped to `a` (even SUBTREE) must not reach `sibling` --
    siblings share a parent, not a descendant relationship, mirroring
    `test_sibling_tenant_denied_unless_explicitly_delegated`'s own
    reasoning for allow."""
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.sibling.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.sibling.id, action=action, resource=resource) is True
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.sibling.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.sibling.id, actor.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


# --- DENY overrides ALLOW: every combination required by architecture
# research Phase D ---------------------------------------------------------


def test_ordinary_self_allow_plus_deny_is_denied(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)
        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is True

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_ordinary_subtree_allow_plus_deny_at_target_is_denied(hierarchy: _Hierarchy) -> None:
    """The actor holds a SUBTREE role at `a` (reaching `b`); a SELF-scoped
    deny placed directly at `b` overrides it there, without affecting `a`
    itself."""
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        management_role_id = _grant_deny_management(hierarchy.b.id, grantor.id)
        permission = register_permission(resource, action)
        assert _can(actor.id, hierarchy.b.id, action=action, resource=resource) is True

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.b.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.b.id, action=action, resource=resource) is False
        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is True
    finally:
        _cleanup_denies_involving(hierarchy.b.id, actor.id)
        _cleanup_audit_log_for(hierarchy.b.id, grantor.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.b.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.b.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_inherited_subtree_allow_plus_ancestor_deny_is_denied(hierarchy: _Hierarchy) -> None:
    """The actor's SUBTREE role lives at `a`, authorizing descendant `b`
    (inherited allow). A SUBTREE deny placed at `a` itself must override
    that inherited allow at `b`."""
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)
        assert _can(actor.id, hierarchy.b.id, action=action, resource=resource) is True

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.b.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_delegated_self_allow_plus_deny_is_denied(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    grantor = create_user()
    actor = create_user()
    try:
        delegator_role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        delegation_mgmt_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        deny_mgmt_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is True

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, delegator_role_id)
        _cleanup_role(hierarchy.a.id, delegation_mgmt_role_id)
        _cleanup_role(hierarchy.a.id, deny_mgmt_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(delegator.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_delegated_subtree_allow_plus_ancestor_deny_is_denied(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    grantor = create_user()
    actor = create_user()
    try:
        delegator_role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        delegation_mgmt_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        deny_mgmt_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )
        assert _can(actor.id, hierarchy.b.id, action=action, resource=resource) is True

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
        assert _can(actor.id, hierarchy.b.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, delegator_role_id)
        _cleanup_role(hierarchy.a.id, delegation_mgmt_role_id)
        _cleanup_role(hierarchy.a.id, deny_mgmt_role_id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(delegator.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_ordinary_allow_plus_delegated_allow_plus_deny_is_denied(hierarchy: _Hierarchy) -> None:
    """The actor holds the permission through BOTH an ordinary role AND an
    independent delegation grant at the same tenant -- an explicit deny
    must still override the combination, not just one of the two paths."""
    resource, action = _unique_name("resource"), "read"
    delegator = create_user()
    grantor = create_user()
    actor = create_user()
    try:
        actor_role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        delegator_role_id = _grant_role(
            hierarchy.a.id, delegator.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        delegation_mgmt_role_id = _grant_delegation_management(hierarchy.a.id, delegator.id)
        deny_mgmt_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        create_delegation(
            delegator_user_id=delegator.id,
            delegate_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is True

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_delegations_involving(hierarchy.a.id, delegator.id)
        _cleanup_audit_log_for(hierarchy.a.id, delegator.id)
        _cleanup_role(hierarchy.a.id, actor_role_id)
        _cleanup_role(hierarchy.a.id, delegator_role_id)
        _cleanup_role(hierarchy.a.id, delegation_mgmt_role_id)
        _cleanup_role(hierarchy.a.id, deny_mgmt_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.a.id, delegator.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(delegator.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


# --- Hierarchy dynamics: live, not snapshotted -----------------------------


def test_moving_descendant_out_of_denied_subtree_restores_authorization_live() -> None:
    """`b`'s allow at itself is a *local* `SELF`-scoped role (never
    inherited from `a`), so it is unaffected by `move_tenant()` -- the
    only thing that changes is whether `a`'s `SUBTREE` deny still reaches
    `b`. This isolates the deny-specific hierarchy-dynamics property from
    the (already independently covered) allow-side one."""
    resource, action = _unique_name("resource"), "read"
    a = create_tenant(_unique_name("a"))
    b = create_tenant(_unique_name("b"), parent_id=a.id)
    grantor = create_user()
    actor = create_user()
    try:
        role_at_a_id = _grant_role(
            a.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        role_at_b_id = _grant_role(
            b.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_deny_management(a.id, grantor.id)
        permission = register_permission(resource, action)

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=a.id,
            scope_mode=RoleScope.SUBTREE,
            permission_id=permission.id,
        )

        assert _can(actor.id, a.id, action=action, resource=resource) is False
        assert _can(actor.id, b.id, action=action, resource=resource) is False

        move_tenant(b.id, None)

        # `b` is no longer a descendant of `a` -- the SUBTREE deny at `a`
        # no longer reaches it, so `b`'s own local SELF-scoped role
        # authorizes it again.
        assert _can(actor.id, b.id, action=action, resource=resource) is True
        # `a` itself is unaffected by the move -- still denied.
        assert _can(actor.id, a.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(a.id, actor.id)
        _cleanup_audit_log_for(a.id, grantor.id)
        _cleanup_role(a.id, role_at_a_id)
        _cleanup_role(b.id, role_at_b_id)
        _cleanup_role(a.id, management_role_id)
        _cleanup_membership(a.id, actor.id)
        _cleanup_membership(b.id, actor.id)
        _cleanup_membership(a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)
        _cleanup_tenant(b.id)
        _cleanup_tenant(a.id)


# --- Revocation ------------------------------------------------------------


def test_deny_blocks_before_revoke_and_allows_again_immediately_after(
    hierarchy: _Hierarchy,
) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        # `revoke_deny()` deliberately has no self-revocation shortcut
        # (its own docstring) -- `grantor` needs the "revoke" capability
        # independently of "create" to be able to undo their own deny.
        revoke_role_id = _grant_deny_revoke(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        deny = create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False

        revoke_deny(revoker_user_id=grantor.id, tenant_id=hierarchy.a.id, deny_grant_id=deny.id)

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is True
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_role(hierarchy.a.id, revoke_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_revoke_is_idempotent(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        revoke_role_id = _grant_deny_revoke(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        deny = create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        revoke_deny(revoker_user_id=grantor.id, tenant_id=hierarchy.a.id, deny_grant_id=deny.id)
        first_revoked_at = revoke_deny(
            revoker_user_id=grantor.id, tenant_id=hierarchy.a.id, deny_grant_id=deny.id
        ).revoked_at

        assert first_revoked_at is not None
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_role(hierarchy.a.id, revoke_role_id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_revoke_unknown_grant_raises(hierarchy: _Hierarchy) -> None:
    grantor = create_user()
    try:
        with pytest.raises(DenyNotFoundError):
            revoke_deny(
                revoker_user_id=grantor.id,
                tenant_id=hierarchy.a.id,
                deny_grant_id=uuid.uuid4(),
            )
    finally:
        _cleanup_user(grantor.id)


def test_creator_without_revoke_permission_cannot_revoke_own_deny(hierarchy: _Hierarchy) -> None:
    """Deliberately different from `revoke_delegation()`'s self-revocation
    shortcut -- a `DenyGrant` does not record who created it, so even the
    original grantor needs the dedicated `deny_grant`/`revoke` capability
    (`revoke_deny()`'s own docstring)."""
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        # Only "create" is granted -- deliberately not "revoke".
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        deny = create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        with pytest.raises(DenyNotAuthorizedError):
            revoke_deny(revoker_user_id=grantor.id, tenant_id=hierarchy.a.id, deny_grant_id=deny.id)

        # Untouched: still denied.
        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


def test_authorized_revoker_can_revoke_someone_elses_deny(hierarchy: _Hierarchy) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    admin = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        revoke_role_id = _grant_deny_revoke(hierarchy.a.id, admin.id)
        permission = register_permission(resource, action)

        deny = create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        revoke_deny(revoker_user_id=admin.id, tenant_id=hierarchy.a.id, deny_grant_id=deny.id)

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is True
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_audit_log_for(hierarchy.a.id, admin.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_role(hierarchy.a.id, revoke_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_membership(hierarchy.a.id, admin.id)
        _cleanup_user(grantor.id)
        _cleanup_user(admin.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


# --- Multiple denies -------------------------------------------------------


def test_one_revoked_deny_does_not_restore_access_blocked_by_a_separate_active_deny(
    hierarchy: _Hierarchy,
) -> None:
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        role_id = _grant_role(
            hierarchy.a.id, actor.id, resource=resource, action=action, scope=RoleScope.SELF
        )
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        revoke_role_id = _grant_deny_revoke(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        deny_1 = create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        revoke_deny(revoker_user_id=grantor.id, tenant_id=hierarchy.a.id, deny_grant_id=deny_1.id)
        # Access restored after the first deny is revoked.
        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is True

        # A second, independent deny for the same principal/permission/scope.
        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, role_id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_role(hierarchy.a.id, revoke_role_id)
        _cleanup_membership(hierarchy.a.id, actor.id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


# --- Deny never itself grants -----------------------------------------------


def test_deny_with_no_underlying_allow_path_is_simply_denied(hierarchy: _Hierarchy) -> None:
    """A `DenyGrant` with no corresponding allow anywhere must never flip
    `can()` to `True` -- a deny only ever subtracts, it cannot add
    (`DenyGrant`'s own docstring)."""
    resource, action = _unique_name("resource"), "read"
    grantor = create_user()
    actor = create_user()
    try:
        management_role_id = _grant_deny_management(hierarchy.a.id, grantor.id)
        permission = register_permission(resource, action)

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False

        create_deny(
            grantor_user_id=grantor.id,
            principal_user_id=actor.id,
            tenant_id=hierarchy.a.id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )

        assert _can(actor.id, hierarchy.a.id, action=action, resource=resource) is False
    finally:
        _cleanup_denies_involving(hierarchy.a.id, actor.id)
        _cleanup_audit_log_for(hierarchy.a.id, grantor.id)
        _cleanup_role(hierarchy.a.id, management_role_id)
        _cleanup_membership(hierarchy.a.id, grantor.id)
        _cleanup_user(grantor.id)
        _cleanup_user(actor.id)
        _cleanup_permission(resource, action)


# --- RLS: deny does not alter existing tenant isolation ---------------------


def test_deny_grants_table_has_force_row_level_security() -> None:
    with session_scope() as session:
        row = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = 'deny_grants'"
            )
        ).one()
    assert row[0] is True
    assert row[1] is True
