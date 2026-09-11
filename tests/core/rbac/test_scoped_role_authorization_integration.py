"""Scoped-role (`RoleScope.SELF` / `RoleScope.SUBTREE`) authorization
integration tests against a real PostgreSQL instance (architecture
research: universal multi-tenant tenancy, Phase B).

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/rbac/test_authorization_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_scoped_role_authorization_integration.py

Builds a small real hierarchy per test (via `core.tenancy.create_tenant`/
`move_tenant`, real `core.tenant_ancestry` rows) rather than mocking
ancestry -- `can()`'s scoped-role evaluation reads that table through
`core.tenancy.get_ancestor_ids()`, so these tests exercise the real
closure table, the real advisory-lock-protected move, and the real
per-candidate `tenant_session_scope()` RBAC queries, never a stub.
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.service import add_tenant_membership, create_user
from core.rbac.service import assign_role, create_role, grant_permission, register_permission
from infra.db.config import get_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.rbac import RoleScope, can
from core.tenancy import create_tenant, move_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_scope_column() -> None:
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT scope FROM core.membership_roles LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.membership_roles.scope does not exist yet -- "
            f"run `alembic upgrade head` first: {exc}"
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


def _cleanup_role(tenant_id: uuid.UUID, role_id: uuid.UUID) -> None:
    """Delete a single role's `role_permissions`/`membership_roles` rows,
    then the role itself, ahead of `_cleanup_permission()` --
    `core.role_permissions.permission_id` has no `ON DELETE CASCADE`, and
    the `hierarchy` fixture's own teardown (which would otherwise remove
    these rows via `_cleanup_tenant()`) runs *after* each test's own
    `finally` block, not before it -- so a test that shares the
    `hierarchy` fixture must clean up its own role explicitly, in this
    order, rather than rely on fixture teardown ordering across two
    independent fixtures (same reasoning as `_cleanup_membership()`
    below, one FK chain over)."""
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
    """Delete a single membership ahead of `_cleanup_user()` --
    `core.tenant_memberships.user_id` has no `ON DELETE CASCADE` (see
    `_cleanup_role()` docstring for the fixture-ordering reasoning this
    mirrors). Call `_cleanup_role()` for this membership's role(s) first
    -- `core.membership_roles` rows referencing this membership must
    already be gone, which `_cleanup_role()` (not this function) removes.
    """
    with tenant_session_scope(tenant_id) as session:
        session.execute(
            text("DELETE FROM core.tenant_memberships WHERE tenant_id = :t AND user_id = :u"),
            {"t": str(tenant_id), "u": str(user_id)},
        )


def _cleanup_user(user_id: uuid.UUID) -> None:
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(user_id)})


def _can(user_id: uuid.UUID, tenant_id: uuid.UUID, *, action: str, resource: str) -> bool:
    return can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource)


class _Hierarchy:
    """
        root
        ├── a
        │   └── b
        │       └── c
        └── d

    plus a wholly unrelated second root, `unrelated`. `a`/`b`/`c`/`d` are
    the child/grandchild/sibling relationships the SELF/SUBTREE test
    matrix needs relative to `a`.
    """

    def __init__(self) -> None:
        self.root = create_tenant(_unique_name("root"))
        self.a = create_tenant(_unique_name("a"), parent_id=self.root.id)
        self.b = create_tenant(_unique_name("b"), parent_id=self.a.id)
        self.c = create_tenant(_unique_name("c"), parent_id=self.b.id)
        self.d = create_tenant(_unique_name("d"), parent_id=self.root.id)
        self.unrelated = create_tenant(_unique_name("unrelated"))

    def cleanup(self) -> None:
        # Leaves first -- Tenant.parent_id's FK blocks deleting a tenant
        # with a living child (Phase A).
        for tenant_id in (
            self.c.id,
            self.b.id,
            self.a.id,
            self.d.id,
            self.root.id,
            self.unrelated.id,
        ):
            _cleanup_tenant(tenant_id)


@pytest.fixture
def hierarchy():
    h = _Hierarchy()
    try:
        yield h
    finally:
        h.cleanup()


class _ScopedGrant:
    """One user, one membership in `hierarchy.a`, one role granting
    `(resource, action)` at the given `scope` -- the fixture every
    SELF/SUBTREE assertion below starts from."""

    def __init__(self, hierarchy: _Hierarchy, scope: RoleScope) -> None:
        self.resource = _unique_name("resource")
        self.action = "read"
        self.hierarchy = hierarchy
        self.user = create_user()
        self.membership = add_tenant_membership(hierarchy.a.id, self.user.id)
        self.role = create_role(hierarchy.a.id, "scoped-role")
        self.permission = register_permission(self.resource, self.action)
        grant_permission(hierarchy.a.id, self.role.id, self.permission.id)
        assign_role(hierarchy.a.id, self.membership.id, self.role.id, scope=scope)

    def can_on(self, tenant_id: uuid.UUID) -> bool:
        return can(
            actor_id=self.user.id, tenant_id=tenant_id, action=self.action, resource=self.resource
        )

    def cleanup(self) -> None:
        _cleanup_role(self.hierarchy.a.id, self.role.id)
        _cleanup_membership(self.hierarchy.a.id, self.user.id)
        _cleanup_user(self.user.id)
        _cleanup_permission(self.resource, self.action)


# --- SELF --------------------------------------------------------------


def test_self_scope_allows_own_tenant(hierarchy: _Hierarchy) -> None:
    grant = _ScopedGrant(hierarchy, RoleScope.SELF)
    try:
        assert grant.can_on(hierarchy.a.id) is True
    finally:
        grant.cleanup()


def test_self_scope_denies_child(hierarchy: _Hierarchy) -> None:
    grant = _ScopedGrant(hierarchy, RoleScope.SELF)
    try:
        assert grant.can_on(hierarchy.b.id) is False
    finally:
        grant.cleanup()


def test_self_scope_denies_grandchild(hierarchy: _Hierarchy) -> None:
    grant = _ScopedGrant(hierarchy, RoleScope.SELF)
    try:
        assert grant.can_on(hierarchy.c.id) is False
    finally:
        grant.cleanup()


def test_self_scope_denies_sibling(hierarchy: _Hierarchy) -> None:
    grant = _ScopedGrant(hierarchy, RoleScope.SELF)
    try:
        assert grant.can_on(hierarchy.d.id) is False
    finally:
        grant.cleanup()


# --- SUBTREE -------------------------------------------------------------


def test_subtree_scope_allows_own_tenant(hierarchy: _Hierarchy) -> None:
    grant = _ScopedGrant(hierarchy, RoleScope.SUBTREE)
    try:
        assert grant.can_on(hierarchy.a.id) is True
    finally:
        grant.cleanup()


def test_subtree_scope_allows_direct_child(hierarchy: _Hierarchy) -> None:
    grant = _ScopedGrant(hierarchy, RoleScope.SUBTREE)
    try:
        assert grant.can_on(hierarchy.b.id) is True
    finally:
        grant.cleanup()


def test_subtree_scope_allows_deeper_descendant(hierarchy: _Hierarchy) -> None:
    grant = _ScopedGrant(hierarchy, RoleScope.SUBTREE)
    try:
        assert grant.can_on(hierarchy.c.id) is True
    finally:
        grant.cleanup()


def test_subtree_scope_denies_sibling(hierarchy: _Hierarchy) -> None:
    grant = _ScopedGrant(hierarchy, RoleScope.SUBTREE)
    try:
        assert grant.can_on(hierarchy.d.id) is False
    finally:
        grant.cleanup()


def test_subtree_scope_denies_unrelated_root(hierarchy: _Hierarchy) -> None:
    grant = _ScopedGrant(hierarchy, RoleScope.SUBTREE)
    try:
        assert grant.can_on(hierarchy.unrelated.id) is False
    finally:
        grant.cleanup()


# --- Hierarchy alone grants nothing ----------------------------------------


def test_membership_in_ancestor_with_no_role_is_still_denied(hierarchy: _Hierarchy) -> None:
    """A membership in an ancestor tenant, with zero role assignments at
    all, must not authorize a descendant merely because the tenant
    relationship exists (structural hierarchy grants nothing by itself)."""
    resource, action = _unique_name("resource"), "read"
    user = create_user()
    try:
        add_tenant_membership(hierarchy.a.id, user.id)
        register_permission(resource, action)
        assert _can(user.id, hierarchy.b.id, action=action, resource=resource) is False
    finally:
        _cleanup_membership(hierarchy.a.id, user.id)
        _cleanup_user(user.id)
        _cleanup_permission(resource, action)


# --- Dynamic hierarchy: live, not snapshotted -------------------------------


def test_moving_the_descendant_out_of_the_subtree_removes_authorization_live() -> None:
    """
        a          a       b
        └── b  -->          (b moved to become a new root)

    SUBTREE from `a` authorizes `b` while `b` is a's child; the instant
    `b` is moved out (via `core.tenancy.move_tenant()`, never touching
    the `MembershipRole` row itself), the same `can()` call for the same
    actor/tenant/action/resource denies -- proving evaluation reads the
    *live* `core.tenant_ancestry`, not a value captured when the role was
    assigned.
    """
    resource, action = _unique_name("resource"), "read"
    a = create_tenant(_unique_name("a"))
    b = create_tenant(_unique_name("b"), parent_id=a.id)
    try:
        user = create_user()
        try:
            membership = add_tenant_membership(a.id, user.id)
            role = create_role(a.id, "subtree-role")
            permission = register_permission(resource, action)
            grant_permission(a.id, role.id, permission.id)
            assign_role(a.id, membership.id, role.id, scope=RoleScope.SUBTREE)

            assert can(actor_id=user.id, tenant_id=b.id, action=action, resource=resource) is True

            move_tenant(b.id, None)  # b becomes its own root -- no longer a's descendant

            assert can(actor_id=user.id, tenant_id=b.id, action=action, resource=resource) is False
            # The assignment itself was never touched.
            assert can(actor_id=user.id, tenant_id=a.id, action=action, resource=resource) is True
        finally:
            _cleanup_role(a.id, role.id)
            _cleanup_membership(a.id, user.id)
            _cleanup_user(user.id)
            _cleanup_permission(resource, action)
    finally:
        _cleanup_tenant(b.id)
        _cleanup_tenant(a.id)


# --- Multiple memberships ---------------------------------------------------


def test_one_user_two_memberships_different_scopes_authorized_independently_per_tenant(
    hierarchy: _Hierarchy,
) -> None:
    """One global user: membership in `a` with SELF, membership in `b`
    (a's own child, but the two memberships/roles are otherwise
    unrelated) with SUBTREE. Authorization must be evaluated correctly
    per target tenant, not by assuming one tenant per user
    (docs/MULTI-TENANCY.md section 1: "a user is never modeled as
    belonging to exactly one tenant")."""
    resource, action = _unique_name("resource"), "read"
    user = create_user()
    try:
        permission = register_permission(resource, action)

        membership_a = add_tenant_membership(hierarchy.a.id, user.id)
        role_a = create_role(hierarchy.a.id, "self-role")
        grant_permission(hierarchy.a.id, role_a.id, permission.id)
        assign_role(hierarchy.a.id, membership_a.id, role_a.id, scope=RoleScope.SELF)

        membership_b = add_tenant_membership(hierarchy.b.id, user.id)
        role_b = create_role(hierarchy.b.id, "subtree-role")
        grant_permission(hierarchy.b.id, role_b.id, permission.id)
        assign_role(hierarchy.b.id, membership_b.id, role_b.id, scope=RoleScope.SUBTREE)

        # a's own tenant: allowed via the SELF membership in a.
        assert _can(user.id, hierarchy.a.id, action=action, resource=resource) is True
        # b's own tenant: allowed via the SUBTREE membership in b.
        assert _can(user.id, hierarchy.b.id, action=action, resource=resource) is True
        # c (b's child): allowed -- reached via b's SUBTREE scope.
        assert _can(user.id, hierarchy.c.id, action=action, resource=resource) is True
        # d (a's child, a *different* subtree than b): denied -- a's role
        # is SELF-only, and the user has no membership in d itself.
        assert _can(user.id, hierarchy.d.id, action=action, resource=resource) is False
    finally:
        _cleanup_role(hierarchy.a.id, role_a.id)
        _cleanup_role(hierarchy.b.id, role_b.id)
        _cleanup_membership(hierarchy.a.id, user.id)
        _cleanup_membership(hierarchy.b.id, user.id)
        _cleanup_user(user.id)
        _cleanup_permission(resource, action)


# --- Backward compatibility: default scope --------------------------------


def test_assign_role_without_scope_defaults_to_self(hierarchy: _Hierarchy) -> None:
    """The pre-Phase-B call shape, `assign_role(tenant_id, membership_id,
    role_id)` with no `scope` keyword at all, must still work identically
    -- allowed in its own tenant, denied in a child -- exactly SELF."""
    resource, action = _unique_name("resource"), "read"
    user = create_user()
    try:
        membership = add_tenant_membership(hierarchy.a.id, user.id)
        role = create_role(hierarchy.a.id, "default-scope-role")
        permission = register_permission(resource, action)
        grant_permission(hierarchy.a.id, role.id, permission.id)
        assign_role(hierarchy.a.id, membership.id, role.id)  # no scope kwarg

        assert _can(user.id, hierarchy.a.id, action=action, resource=resource) is True
        assert _can(user.id, hierarchy.b.id, action=action, resource=resource) is False
    finally:
        _cleanup_role(hierarchy.a.id, role.id)
        _cleanup_membership(hierarchy.a.id, user.id)
        _cleanup_user(user.id)
        _cleanup_permission(resource, action)
