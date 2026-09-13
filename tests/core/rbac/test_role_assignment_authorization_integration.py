"""`assign_role()` anti-amplification authorization integration tests
against a real PostgreSQL instance (Phase J-RBAC-01: "assign_role() lacks
its own anti-amplification authorization check"; Final Hardening: the
bootstrap exception must not be reachable as a generic bypass through
`assign_role()`'s own normal signature).

Marked `integration` and excluded from the default `pytest` run, mirroring
`tests/core/rbac/test_service_account_authorization_integration.py`, whose
"H. Privilege amplification" tests this file's tests are modeled on --
`assign_role()` now carries the identical `can()` capability check +
`_actor_reaches_tenant_at_scope()` per-permission discipline
`assign_service_account_role()` already had, and always requires a real,
checked `actor_user_id` -- there is no `actor_type` (or any other)
parameter on it that selects an unchecked path. Tenant bootstrap's own
first-role need is served by the structurally separate
`assign_first_role_for_new_tenant()` (`core/rbac/service.py`'s own
docstring), never by a parameter on `assign_role()` itself.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/rbac/test_role_assignment_authorization_integration.py

Covers:

1.  SELF-only actor cannot create a SUBTREE assignment (SELF != SUBTREE).
2.  Actor cannot assign a role granting a permission it does not itself
    hold (no broader-than-self reach).
3.  Actor cannot assign a role reaching a sibling tenant.
4.  Actor cannot assign a role reaching a parent tenant (no child->parent).
5.  Actor with SUBTREE authority from a parent CAN assign a role in a
    child tenant (valid parent->child positive case).
6.  Delegated authority cannot be used to assign a role (no delegation
    amplification -- `_actor_reaches_tenant_at_scope()` never consults
    `DelegationGrant` rows).
7.  `assign_role()` accepts no `actor_type` parameter at all -- passing
    `actor_type=PrincipalType.SYSTEM` (or `SERVICE_ACCOUNT`) through the
    normal role-assignment path raises `TypeError` (an unexpected keyword
    argument), not a quiet bypass. This is the Final Hardening property:
    there is no argument a caller can supply to this function that skips
    its authorization check.
8.  Explicit deny on the "manage role assignments" capability still
    overrides an otherwise-sufficient allow.
9.  `assign_first_role_for_new_tenant()` -- the structurally separate
    bootstrap function, never a parameter on `assign_role()` -- still
    assigns the very first role in a brand-new tenant (the one
    legitimate exception, `api/tenant_bootstrap.py`'s own use).
10. Ordinary, already-tested role-assignment behavior (an authorized
    actor assigning a SELF role) still works end-to-end through `can()`.
11. `actor_user_id` is a required keyword argument on `assign_role()` --
    omitting it raises `TypeError` before any authorization or database
    logic runs at all (fails closed structurally, not just logically).
12. Dynamic hierarchy: moving a tenant out of an actor's SUBTREE reach
    live removes that actor's authority to assign a role there,
    mirroring `test_scoped_role_authorization_integration.py`'s own
    `move_tenant` regression.

Anomaly (informational, pre-existing, not a Phase J-RBAC-01 regression):
`_actor_reaches_tenant_at_scope()`'s `required_scope=SELF` branch checks
only for a role held directly AT the target tenant -- it does not walk
ancestors the way its own `required_scope=SUBTREE` branch does. This
means an actor whose only authority over `(resource, action)` is a
SUBTREE-scoped role at a *parent* tenant cannot use that authority to
create a SELF-scoped `assign_role()` assignment at a *child* tenant, even
though the actor's ordinary `can()` reach already covers the child
tenant. Tests 5 and 12 below request `scope=RoleScope.SUBTREE` for the
new assignment specifically to exercise the ancestor walk that does
exist. This asymmetry predates this phase -- `assign_service_account_role()`,
`create_delegation()`, and `create_deny_for_service_account()` reuse the
identical primitive and would exhibit the identical limitation for a
cross-tenant SELF-scoped grant -- so fixing it is out of this phase's
scope (reusing, not modifying, the shared anti-amplification primitive);
it makes the check strictly more conservative, never less, so it is a
missed-positive-case tightness, never a security gap.
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.service import add_tenant_membership, create_user
from core.rbac.errors import RoleAssignmentNotAuthorizedError
from core.rbac.principal import PrincipalType
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    assign_role,
    create_delegation,
    create_deny,
    create_role,
    grant_permission,
    register_permission,
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
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
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


def _unique_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _new_tenant(*, parent_id: uuid.UUID | None = None) -> uuid.UUID:
    return create_tenant(_unique_name("tenant"), parent_id=parent_id).id


def _admin_session():
    engine = build_engine(get_migrations_database_config())
    from infra.db.session import build_session_factory

    factory = build_session_factory(engine)
    return session_scope(session_factory=factory)


def _cleanup_tenant(tenant_id: uuid.UUID) -> None:
    """`create_deny()`/`create_delegation()` (called by several tests
    below) each record an audit-log entry -- `core.audit_log.tenant_id`'s
    own FK blocks deleting the tenant while that row still references it,
    so it must be removed first, via the privileged migrations session
    (mirrors `tests/core/rbac/test_support_access_integration.py`'s own
    `_cleanup_tenant()`)."""
    with _admin_session() as session:
        session.execute(
            text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
    with tenant_session_scope(tenant_id) as session:
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


def _bootstrap_membership_with_role(
    tenant_id: uuid.UUID, *, resource: str, action: str, scope: RoleScope
) -> tuple[uuid.UUID, uuid.UUID]:
    """Fixture setup only (never the behavior under test): a fresh user,
    an ACTIVE membership, and a role granting `(resource, action)` at
    `scope`, assigned via `assign_first_role_for_new_tenant()` -- exactly
    how `api/tenant_bootstrap.py` provisions a brand-new tenant's very
    first role. Returns (user_id, membership_id)."""
    user_id = create_user().id
    membership = add_tenant_membership(tenant_id, user_id)
    role = create_role(tenant_id, _unique_name("role"))
    permission = register_permission(resource, action)
    grant_permission(tenant_id, role.id, permission.id)
    assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, scope=scope)
    return user_id, membership.id


def _grant_manage_role_assignments(
    tenant_id: uuid.UUID, membership_id: uuid.UUID, *, scope: RoleScope = RoleScope.SUBTREE
) -> None:
    """Fixture setup only: grant the actor already holding `membership_id`
    the dedicated "manage role assignments in this tenant" capability
    (`(resource="membership_role", action="create")`) -- bootstrapped the
    same way, never through the path under test."""
    role = create_role(tenant_id, _unique_name("mgmt-role"))
    permission = register_permission("membership_role", "create")
    grant_permission(tenant_id, role.id, permission.id)
    assign_first_role_for_new_tenant(tenant_id, membership_id, role.id, scope=scope)


# --- 1. SELF != SUBTREE ------------------------------------------------------


def test_self_only_actor_cannot_assign_a_subtree_role() -> None:
    """An actor holding only SELF-level authority over a permission
    must not be able to assign a role carrying that same permission at
    SUBTREE scope -- to anyone, including within the actor's own tenant."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        actor, actor_membership = _bootstrap_membership_with_role(
            tenant_id, resource=resource, action=action, scope=RoleScope.SELF
        )
        _grant_manage_role_assignments(tenant_id, actor_membership, scope=RoleScope.SELF)

        target_user = create_user().id
        target_membership = add_tenant_membership(tenant_id, target_user)
        target_role = create_role(tenant_id, _unique_name("target-role"))
        permission = register_permission(_unique_name("res2"), "read")
        grant_permission(tenant_id, target_role.id, permission.id)
        # Re-grant the SAME permission the actor itself only holds at SELF.
        same_permission = register_permission(resource, action)
        grant_permission(tenant_id, target_role.id, same_permission.id)

        with pytest.raises(RoleAssignmentNotAuthorizedError):
            assign_role(
                tenant_id,
                target_membership.id,
                target_role.id,
                scope=RoleScope.SUBTREE,
                actor_user_id=actor,
            )
        assert (
            can(actor_id=target_user, tenant_id=tenant_id, action=action, resource=resource)
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(actor)
        _cleanup_user(target_user)
        _cleanup_permission(resource, action)
        _cleanup_permission("membership_role", "create")
        _cleanup_permission(permission.resource, permission.action)


# --- 2. No broader-than-self reach -------------------------------------------


def test_actor_cannot_assign_a_role_granting_a_permission_it_does_not_itself_hold() -> None:
    """An actor holding the "manage role assignments" capability, but NOT
    the target role's own permission, must not be able to hand that
    permission out via `assign_role()`."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        actor = create_user().id
        actor_membership = add_tenant_membership(tenant_id, actor)
        _grant_manage_role_assignments(tenant_id, actor_membership.id, scope=RoleScope.SUBTREE)
        # actor holds the management capability but never (resource, action).
        register_permission(resource, action)

        target_user = create_user().id
        target_membership = add_tenant_membership(tenant_id, target_user)
        target_role = create_role(tenant_id, _unique_name("target-role"))
        permission = register_permission(resource, action)
        grant_permission(tenant_id, target_role.id, permission.id)

        with pytest.raises(RoleAssignmentNotAuthorizedError):
            assign_role(
                tenant_id,
                target_membership.id,
                target_role.id,
                scope=RoleScope.SELF,
                actor_user_id=actor,
            )
        assert (
            can(actor_id=target_user, tenant_id=tenant_id, action=action, resource=resource)
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(actor)
        _cleanup_user(target_user)
        _cleanup_permission(resource, action)
        _cleanup_permission("membership_role", "create")


# --- 3. No sibling reach ------------------------------------------------------


def test_actor_cannot_assign_a_role_reaching_a_sibling_tenant() -> None:
    """An actor's SUBTREE authority in one tenant must not authorize
    `assign_role()` calls made against a wholly unrelated sibling
    tenant."""
    tenant_a = _new_tenant()
    tenant_b = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        actor, actor_membership = _bootstrap_membership_with_role(
            tenant_a, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        _grant_manage_role_assignments(tenant_a, actor_membership, scope=RoleScope.SUBTREE)

        # actor has no membership at all in tenant_b.
        target_user = create_user().id
        target_membership = add_tenant_membership(tenant_b, target_user)
        target_role = create_role(tenant_b, _unique_name("target-role"))
        permission = register_permission(resource, action)
        grant_permission(tenant_b, target_role.id, permission.id)

        with pytest.raises(RoleAssignmentNotAuthorizedError):
            assign_role(
                tenant_b,
                target_membership.id,
                target_role.id,
                scope=RoleScope.SELF,
                actor_user_id=actor,
            )
        assert (
            can(actor_id=target_user, tenant_id=tenant_b, action=action, resource=resource) is False
        )
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
        _cleanup_user(actor)
        _cleanup_user(target_user)
        _cleanup_permission(resource, action)
        _cleanup_permission("membership_role", "create")


# --- 4. No child -> parent reach ----------------------------------------------


def test_actor_cannot_assign_a_role_reaching_a_parent_tenant() -> None:
    """An actor whose authority is scoped to a child tenant must not be
    able to `assign_role()` against that child's parent -- a hierarchy
    relationship only ever authorizes downward (SUBTREE), never upward."""
    parent_id = _new_tenant()
    child_id = _new_tenant(parent_id=parent_id)
    resource, action = _unique_name("resource"), "read"
    try:
        actor, actor_membership = _bootstrap_membership_with_role(
            child_id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        _grant_manage_role_assignments(child_id, actor_membership, scope=RoleScope.SUBTREE)

        target_user = create_user().id
        target_membership = add_tenant_membership(parent_id, target_user)
        target_role = create_role(parent_id, _unique_name("target-role"))
        permission = register_permission(resource, action)
        grant_permission(parent_id, target_role.id, permission.id)

        with pytest.raises(RoleAssignmentNotAuthorizedError):
            assign_role(
                parent_id,
                target_membership.id,
                target_role.id,
                scope=RoleScope.SELF,
                actor_user_id=actor,
            )
        assert (
            can(actor_id=target_user, tenant_id=parent_id, action=action, resource=resource)
            is False
        )
    finally:
        _cleanup_tenant(child_id)
        _cleanup_tenant(parent_id)
        _cleanup_user(actor)
        _cleanup_user(target_user)
        _cleanup_permission(resource, action)
        _cleanup_permission("membership_role", "create")


# --- 5. Valid parent -> child positive case -----------------------------------


def test_subtree_actor_can_assign_a_subtree_role_to_a_child_tenant_membership() -> None:
    """The positive control for tests 3-4: an actor genuinely holding
    SUBTREE authority over `(resource, action)` from the parent CAN
    assign a role, at SUBTREE, granting that same permission to a
    membership in a child tenant -- `_actor_reaches_tenant_at_scope()`'s
    own ancestor walk only runs for `required_scope=SUBTREE` (its own
    docstring: a SELF-only role AT the target tenant does not qualify,
    only a SUBTREE-capable role does, "whether held directly at
    tenant_id or inherited via SUBTREE from one of its ancestors") -- so
    the new assignment itself must ask for SUBTREE here for the actor's
    parent-level authority to reach it at all (see this file's own
    Anomalies note for the SELF-scope case, which this same ancestor walk
    does not cover)."""
    parent_id = _new_tenant()
    child_id = _new_tenant(parent_id=parent_id)
    resource, action = _unique_name("resource"), "read"
    try:
        actor, actor_membership = _bootstrap_membership_with_role(
            parent_id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        _grant_manage_role_assignments(parent_id, actor_membership, scope=RoleScope.SUBTREE)

        target_user = create_user().id
        target_membership = add_tenant_membership(child_id, target_user)
        target_role = create_role(child_id, _unique_name("target-role"))
        permission = register_permission(resource, action)
        grant_permission(child_id, target_role.id, permission.id)

        assign_role(
            child_id,
            target_membership.id,
            target_role.id,
            scope=RoleScope.SUBTREE,
            actor_user_id=actor,
        )
        assert (
            can(actor_id=target_user, tenant_id=child_id, action=action, resource=resource) is True
        )
    finally:
        _cleanup_tenant(child_id)
        _cleanup_tenant(parent_id)
        _cleanup_user(actor)
        _cleanup_user(target_user)
        _cleanup_permission(resource, action)
        _cleanup_permission("membership_role", "create")


# --- 6. No delegation amplification ------------------------------------------


def test_delegated_authority_cannot_be_used_to_assign_a_role() -> None:
    """`_actor_reaches_tenant_at_scope()` never consults `DelegationGrant`
    rows (its own docstring) -- an actor who can act via delegation alone
    must still be unable to `assign_role()` for that same permission."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        holder, holder_membership = _bootstrap_membership_with_role(
            tenant_id, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        # holder also needs the "manage delegations" capability to call
        # create_delegation() as delegator -- fixture setup only.
        delegation_admin_role = create_role(tenant_id, _unique_name("delegation-admin-role"))
        delegation_admin_permission = register_permission("delegation_grant", "create")
        grant_permission(tenant_id, delegation_admin_role.id, delegation_admin_permission.id)
        assign_first_role_for_new_tenant(
            tenant_id, holder_membership, delegation_admin_role.id, scope=RoleScope.SELF
        )

        delegate_user = create_user().id
        permission = register_permission(resource, action)
        create_delegation(
            delegator_user_id=holder,
            delegate_user_id=delegate_user,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=permission.id,
        )
        # delegate_user can now act via delegation alone...
        assert (
            can(actor_id=delegate_user, tenant_id=tenant_id, action=action, resource=resource)
            is True
        )

        # ...but also needs -- and here is granted -- the "manage role
        # assignments" capability, to attempt using that delegated
        # authority to grant the permission onward via assign_role().
        delegate_membership = add_tenant_membership(tenant_id, delegate_user)
        _grant_manage_role_assignments(tenant_id, delegate_membership.id, scope=RoleScope.SELF)

        target_user = create_user().id
        target_membership = add_tenant_membership(tenant_id, target_user)
        target_role = create_role(tenant_id, _unique_name("target-role"))
        grant_permission(tenant_id, target_role.id, permission.id)

        with pytest.raises(RoleAssignmentNotAuthorizedError):
            assign_role(
                tenant_id,
                target_membership.id,
                target_role.id,
                scope=RoleScope.SELF,
                actor_user_id=delegate_user,
            )
        assert (
            can(actor_id=target_user, tenant_id=tenant_id, action=action, resource=resource)
            is False
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(holder)
        _cleanup_user(delegate_user)
        _cleanup_user(target_user)
        _cleanup_permission(resource, action)
        _cleanup_permission("membership_role", "create")
        _cleanup_permission("delegation_grant", "create")


# --- 7. No actor_type parameter -- the normal path cannot be bypassed --------


def test_assign_role_rejects_an_actor_type_argument_entirely() -> None:
    """Final Hardening's central property: `assign_role()`'s own signature
    accepts no `actor_type` (or equivalent) argument at all -- there is no
    value a caller can supply through the normal role-assignment path
    that reaches an unchecked branch. Both the old bootstrap value
    (`SYSTEM`) and the machine-principal value (`SERVICE_ACCOUNT`) raise
    `TypeError` (an unexpected keyword argument), never a quiet allow and
    never even the checked-but-rejecting `RoleAssignmentNotAuthorizedError`
    path -- the parameter itself does not exist on this function, so
    there is nothing here for a careless or malicious caller to select."""
    tenant_id = _new_tenant()
    try:
        user_id = create_user().id
        membership = add_tenant_membership(tenant_id, user_id)
        role = create_role(tenant_id, _unique_name("role"))

        with pytest.raises(TypeError):
            assign_role(
                tenant_id,
                membership.id,
                role.id,
                actor_user_id=uuid.uuid4(),
                actor_type=PrincipalType.SYSTEM,  # type: ignore[call-arg]
            )
        with pytest.raises(TypeError):
            assign_role(
                tenant_id,
                membership.id,
                role.id,
                actor_user_id=uuid.uuid4(),
                actor_type=PrincipalType.SERVICE_ACCOUNT,  # type: ignore[call-arg]
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(user_id)


# --- 8. Deny still overrides --------------------------------------------------


def test_explicit_deny_on_manage_role_assignments_overrides_allow() -> None:
    """A `DenyGrant` against the "manage role assignments" permission
    must make `assign_role()` reject even an actor who would otherwise
    pass the ordinary `can()` capability check -- `can()`'s own
    deny-first evaluation covers this automatically, since `assign_role()`
    never bypasses `can()`."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        actor, actor_membership = _bootstrap_membership_with_role(
            tenant_id, resource=resource, action=action, scope=RoleScope.SELF
        )
        _grant_manage_role_assignments(tenant_id, actor_membership, scope=RoleScope.SELF)
        assert (
            can(actor_id=actor, tenant_id=tenant_id, action="create", resource="membership_role")
            is True
        )

        deny_permission = register_permission("membership_role", "create")
        grantor, grantor_membership = _bootstrap_membership_with_role(
            tenant_id, resource=_unique_name("deny-admin-res"), action="read", scope=RoleScope.SELF
        )
        _deny_grant_role = create_role(tenant_id, _unique_name("deny-grant-role"))
        deny_create_permission = register_permission("deny_grant", "create")
        grant_permission(tenant_id, _deny_grant_role.id, deny_create_permission.id)
        assign_first_role_for_new_tenant(
            tenant_id, grantor_membership, _deny_grant_role.id, scope=RoleScope.SELF
        )
        create_deny(
            grantor_user_id=grantor,
            principal_user_id=actor,
            tenant_id=tenant_id,
            scope_mode=RoleScope.SELF,
            permission_id=deny_permission.id,
        )
        assert (
            can(actor_id=actor, tenant_id=tenant_id, action="create", resource="membership_role")
            is False
        )

        target_user = create_user().id
        target_membership = add_tenant_membership(tenant_id, target_user)
        target_role = create_role(tenant_id, _unique_name("target-role"))
        same_permission = register_permission(resource, action)
        grant_permission(tenant_id, target_role.id, same_permission.id)

        with pytest.raises(RoleAssignmentNotAuthorizedError):
            assign_role(
                tenant_id,
                target_membership.id,
                target_role.id,
                scope=RoleScope.SELF,
                actor_user_id=actor,
            )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(actor)
        _cleanup_user(grantor)
        _cleanup_user(target_user)
        _cleanup_permission(resource, action)
        _cleanup_permission("membership_role", "create")
        _cleanup_permission("deny_grant", "create")


# --- 9. Bootstrap (separate function) still works ----------------------------


def test_bootstrap_function_still_assigns_the_first_role_in_a_fresh_tenant() -> None:
    """The one legitimate exception: a brand-new tenant's very first role
    assignment, with no pre-existing actor authority to check against,
    still succeeds via the structurally separate
    `assign_first_role_for_new_tenant()` -- exactly
    `api/tenant_bootstrap.py`'s own call shape. This function takes no
    actor at all (there is nothing to check), and is reached only by its
    own distinct name, never through `assign_role()`."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        user_id = create_user().id
        membership = add_tenant_membership(tenant_id, user_id)
        role = create_role(tenant_id, _unique_name("owner-role"))
        permission = register_permission(resource, action)
        grant_permission(tenant_id, role.id, permission.id)

        assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, scope=RoleScope.SELF)

        assert can(actor_id=user_id, tenant_id=tenant_id, action=action, resource=resource) is True
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(user_id)
        _cleanup_permission(resource, action)


# --- 10. Existing role-assignment behavior still works -----------------------


def test_authorized_actor_can_assign_a_self_role_it_already_holds() -> None:
    """An actor holding the "manage role assignments" capability plus the
    target permission at SELF can assign that same permission, at SELF,
    to another membership in its own tenant -- the ordinary, unamplified
    case."""
    tenant_id = _new_tenant()
    resource, action = _unique_name("resource"), "read"
    try:
        actor, actor_membership = _bootstrap_membership_with_role(
            tenant_id, resource=resource, action=action, scope=RoleScope.SELF
        )
        _grant_manage_role_assignments(tenant_id, actor_membership, scope=RoleScope.SELF)

        target_user = create_user().id
        target_membership = add_tenant_membership(tenant_id, target_user)
        target_role = create_role(tenant_id, _unique_name("target-role"))
        same_permission = register_permission(resource, action)
        grant_permission(tenant_id, target_role.id, same_permission.id)

        assign_role(
            tenant_id,
            target_membership.id,
            target_role.id,
            scope=RoleScope.SELF,
            actor_user_id=actor,
        )
        assert (
            can(actor_id=target_user, tenant_id=tenant_id, action=action, resource=resource) is True
        )
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(actor)
        _cleanup_user(target_user)
        _cleanup_permission(resource, action)
        _cleanup_permission("membership_role", "create")


# --- 11. Fail closed with no actor -------------------------------------------


def test_missing_actor_user_id_is_rejected_structurally() -> None:
    """`actor_user_id` is a required keyword argument -- omitting it
    raises `TypeError` before `assign_role()`'s own body (and so its
    authorization check) ever runs, never silently proceeding unchecked
    and never merely relying on a runtime `None` check that a caller
    could route around."""
    tenant_id = _new_tenant()
    try:
        user_id = create_user().id
        membership = add_tenant_membership(tenant_id, user_id)
        role = create_role(tenant_id, _unique_name("role"))

        with pytest.raises(TypeError):
            assign_role(tenant_id, membership.id, role.id)  # type: ignore[call-arg]
    finally:
        _cleanup_tenant(tenant_id)
        _cleanup_user(user_id)


# --- 12. Dynamic hierarchy: live, not snapshotted ----------------------------


def test_moving_tenant_out_of_subtree_removes_assignment_authority_live() -> None:
    """
            a          a       b
            └── b  -->          (b moved to become a new root)

    An actor's SUBTREE authority from `a` authorizes `assign_role()` calls
        (themselves requesting SUBTREE -- see
        `test_subtree_actor_can_assign_a_subtree_role_to_a_child_tenant_membership()`'s
        own docstring for why) against `b` while `b` is a's child; the instant
        `b` is moved out (via `core.tenancy.move_tenant()`, never touching the
        actor's own `MembershipRole` row), the identical `assign_role()` call
        denies -- proving the anti-amplification check reads live ancestry,
        not a value captured when the actor's own role was assigned."""
    a = _new_tenant()
    b = _new_tenant(parent_id=a)
    resource, action = _unique_name("resource"), "read"
    try:
        actor, actor_membership = _bootstrap_membership_with_role(
            a, resource=resource, action=action, scope=RoleScope.SUBTREE
        )
        _grant_manage_role_assignments(a, actor_membership, scope=RoleScope.SUBTREE)

        target_user = create_user().id
        target_membership = add_tenant_membership(b, target_user)
        target_role = create_role(b, _unique_name("target-role"))
        permission = register_permission(resource, action)
        grant_permission(b, target_role.id, permission.id)

        assign_role(
            b, target_membership.id, target_role.id, scope=RoleScope.SUBTREE, actor_user_id=actor
        )
        assert can(actor_id=target_user, tenant_id=b, action=action, resource=resource) is True

        move_tenant(b, None)  # b becomes its own root -- no longer a's descendant

        other_user = create_user().id
        other_membership = add_tenant_membership(b, other_user)

        with pytest.raises(RoleAssignmentNotAuthorizedError):
            assign_role(
                b,
                other_membership.id,
                target_role.id,
                scope=RoleScope.SUBTREE,
                actor_user_id=actor,
            )
        assert can(actor_id=other_user, tenant_id=b, action=action, resource=resource) is False
    finally:
        _cleanup_tenant(b)
        _cleanup_tenant(a)
        _cleanup_user(actor)
        _cleanup_user(target_user)
        _cleanup_user(other_user)
        _cleanup_permission(resource, action)
        _cleanup_permission("membership_role", "create")
