"""The last-administrator invariant across the tenant hierarchy
(docs/ADR/0043-...; `saas_os/core/rbac/administrators.py`), against real
PostgreSQL.

Authority flows down the hierarchy -- a SUBTREE-scoped role, deny or
delegation at a tenant also decides who administers its descendants -- and
lapses with tenant status and with time. Eight ways a tenant could lose
its last administrator from *outside* were demonstrated before the rule
was extended; each is now refused, and each test below is one of them:

- in the parent: removing a role, revoking a permission, suspending a
  membership, revoking a delegation, creating a SUBTREE deny;
- moving the tenant away from its parent;
- suspending the parent tenant;
- a delegation with an expiry (never counted as the administrator a
  tenant may be left with, since nothing runs when it lapses).

Also here: the same operations are allowed while the child keeps another
administrator; a refusal changes and audits nothing; operations racing
from different tenants of one hierarchy leave an administrator and do not
deadlock; and negative controls with the check, and by hand the lock,
removed.

Marked `integration`.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

import saas_os.core.rbac.administrators as administrators
from lifecycle_callers import platform_operator
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import (
    LastTenantAdministratorError,
    MembershipStatus,
    get_membership,
    suspend_membership,
)
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.rbac import RoleScope, can
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_delegation,
    create_deny,
    create_role,
    get_delegation,
    get_role_permission,
    grant_permission,
    list_denies_for_principal,
    list_membership_roles,
    register_permission,
    remove_role,
    revoke_delegation,
    revoke_permission,
)
from saas_os.core.tenancy import (
    TenantStatus,
    create_tenant,
    get_ancestor_ids,
    get_tenant,
    move_tenant,
    transition_tenant_status,
)
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_ASSIGN_ROLES = ("membership_role", "create")
# Authority to perform every mutation used here, including assigning roles.
_ADMIN = [
    _ASSIGN_ROLES,
    ("membership_role", "delete"),
    ("role_permission", "revoke"),
    ("deny_grant", "create"),
    ("delegation_grant", "create"),
    ("delegation_grant", "revoke"),
    ("membership", "suspend"),
]
_OPERATOR = [p for p in _ADMIN if p != _ASSIGN_ROLES]


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.membership_roles LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.membership_roles not reachable: {exc}")
    finally:
        probe.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _Member:
    def __init__(self, user: uuid.UUID, membership: uuid.UUID, role: uuid.UUID | None) -> None:
        self.user, self.membership, self.role = user, membership, role
        self.caller = UserCaller(user)

    @property
    def role_id(self) -> uuid.UUID:
        assert self.role is not None
        return self.role


class _World:
    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    def tenant(self, *, parent: uuid.UUID | None = None) -> uuid.UUID:
        tenant = create_tenant(
            _unique("last-admin-tree"), parent_id=parent, caller=platform_operator()
        )
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def member(
        self,
        tenant_id: uuid.UUID,
        permissions: list[tuple[str, str]],
        *,
        scope: RoleScope = RoleScope.SELF,
        user_id: uuid.UUID | None = None,
    ) -> _Member:
        if user_id is None:
            user_id = create_user().id
            self.user_ids.append(user_id)
        membership = add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
        role_id: uuid.UUID | None = None
        if permissions:
            role = create_role(tenant_id, _unique("role"), caller=_PROVISIONING)
            for resource, action in permissions:
                grant_permission(
                    tenant_id,
                    role.id,
                    register_permission(resource, action).id,
                    caller=_PROVISIONING,
                )
            assign_first_role_for_new_tenant(
                tenant_id, membership.id, role.id, scope=scope, caller=_PROVISIONING
            )
            role_id = role.id
        return _Member(user_id, membership.id, role_id)

    def cleanup(self) -> None:
        tenants = [str(t) for t in self.tenant_ids]
        users = [str(u) for u in self.user_ids]
        engine = build_engine(get_migrations_database_config())
        try:
            factory = build_session_factory(engine)
            with session_scope(session_factory=factory) as session:
                for statement in (
                    "DELETE FROM core.audit_log WHERE tenant_id = ANY(:t) "
                    "OR actor_user_id = ANY(:u)",
                    "DELETE FROM core.deny_grants WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.delegation_grants WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) "
                    "OR ancestor_id = ANY(:t)",
                    "DELETE FROM core.platform_audit_log WHERE target_tenant_id = ANY(:t)",
                    "DELETE FROM core.tenants WHERE id = ANY(:t)",
                    "DELETE FROM core.users WHERE id = ANY(:u)",
                ):
                    session.execute(text(statement), {"t": tenants, "u": users})
        finally:
            engine.dispose()


@pytest.fixture
def world() -> Iterator[_World]:
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


def _administrator(tenant: uuid.UUID) -> uuid.UUID | None:
    """Exactly what the guard asks: one administrator of `tenant`, or None."""
    with tenant_session_scope(tenant) as session:
        return administrators.find_administrator(session, tenant)


def _permission_id(pair: tuple[str, str]) -> uuid.UUID:
    return register_permission(*pair).id


def _audit_actions(tenant: uuid.UUID) -> list[str]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT action FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant)}
            ).all()
        return [row[0] for row in rows]
    finally:
        engine.dispose()


class _Tree:
    """A parent and a child tenant. The parent keeps its own administrator
    (`boss`) throughout, so the parent's own rule is always satisfied.
    `inherited` is a member of both tenants whose only authority is a
    SUBTREE-scoped role held at the parent: the child's sole administrator,
    by inheritance."""

    def __init__(self, world: _World, *, grandparent: bool = False) -> None:
        self.world = world
        self.grandparent = world.tenant() if grandparent else None
        self.parent = world.tenant(parent=self.grandparent)
        self.child = world.tenant(parent=self.parent)
        self.boss = world.member(self.parent, _ADMIN, scope=RoleScope.SUBTREE)
        self.inherited = world.member(self.parent, [_ASSIGN_ROLES], scope=RoleScope.SUBTREE)
        world.member(self.child, [], user_id=self.inherited.user)
        assert _administrator(self.child) == self.inherited.user
        assert _administrator(self.parent) == self.boss.user

    def second_child_administrator(self) -> _Member:
        """An administrator of the child in the child's own right."""
        return self.world.member(self.child, _ADMIN)


def _refused_for(tenant: uuid.UUID, action: Callable[[], object]) -> None:
    with pytest.raises(LastTenantAdministratorError) as raised:
        action()
    assert raised.value.tenant_id == tenant, "the error names the tenant that would be emptied"


# --- 1-5. Mutations in the parent tenant ----------------------------------------------------


def test_a_role_cannot_be_removed_in_the_parent_from_the_childs_last_administrator(
    world: _World,
) -> None:
    tree = _Tree(world)
    _refused_for(
        tree.child,
        lambda: remove_role(
            tree.parent, tree.inherited.membership, tree.inherited.role_id, caller=tree.boss.caller
        ),
    )
    # Nothing changed and nothing was audited, in either tenant.
    roles = list_membership_roles(tree.parent, tree.inherited.membership)
    assert [r.role_id for r in roles] == [tree.inherited.role_id]
    assert "membership_role.delete" not in _audit_actions(tree.parent)
    assert _administrator(tree.child) == tree.inherited.user

    other = tree.second_child_administrator()
    remove_role(
        tree.parent, tree.inherited.membership, tree.inherited.role_id, caller=tree.boss.caller
    )
    assert _administrator(tree.child) == other.user


def test_a_permission_cannot_be_revoked_in_the_parent_from_under_the_childs_last_administrator(
    world: _World,
) -> None:
    tree = _Tree(world)
    assign = _permission_id(_ASSIGN_ROLES)
    _refused_for(
        tree.child,
        lambda: revoke_permission(
            tree.parent, tree.inherited.role_id, assign, caller=tree.boss.caller
        ),
    )
    assert get_role_permission(tree.parent, tree.inherited.role_id, assign) is not None

    tree.second_child_administrator()
    revoke_permission(tree.parent, tree.inherited.role_id, assign, caller=tree.boss.caller)
    assert get_role_permission(tree.parent, tree.inherited.role_id, assign) is None
    assert _administrator(tree.child) is not None


def test_a_parent_membership_cannot_be_suspended_under_the_childs_last_administrator(
    world: _World,
) -> None:
    """The member would stay ACTIVE in the child; the role that makes them
    an administrator there hangs off the parent membership."""
    tree = _Tree(world)
    _refused_for(
        tree.child,
        lambda: suspend_membership(tree.parent, tree.inherited.membership, caller=tree.boss.caller),
    )
    membership = get_membership(tree.parent, tree.inherited.user)
    assert membership is not None and membership.status == MembershipStatus.ACTIVE.value

    tree.second_child_administrator()
    suspend_membership(tree.parent, tree.inherited.membership, caller=tree.boss.caller)
    assert _administrator(tree.child) is not None


def test_a_subtree_deny_in_the_parent_cannot_remove_the_childs_last_administrator(
    world: _World,
) -> None:
    """The strongest case: the child's administrator holds a role granted in
    the child itself, and is not a member of the parent at all."""
    parent = world.tenant()
    child = world.tenant(parent=parent)
    boss = world.member(parent, _ADMIN)
    local = world.member(child, _ADMIN)
    assign = _permission_id(_ASSIGN_ROLES)

    def deny(user: uuid.UUID) -> None:
        create_deny(
            caller=boss.caller,
            principal_user_id=user,
            tenant_id=parent,
            scope_mode=RoleScope.SUBTREE,
            permission_id=assign,
        )

    _refused_for(child, lambda: deny(local.user))
    assert list_denies_for_principal(parent, local.user) == []
    assert _administrator(child) == local.user

    other = world.member(child, _ADMIN)
    deny(local.user)
    assert _administrator(child) == other.user
    _refused_for(child, lambda: deny(other.user))


def test_a_subtree_delegation_in_the_parent_cannot_be_revoked_from_the_childs_last_administrator(
    world: _World,
) -> None:
    parent = world.tenant()
    child = world.tenant(parent=parent)
    boss = world.member(parent, _ADMIN, scope=RoleScope.SUBTREE)
    delegate = world.member(child, [])
    grant = create_delegation(
        caller=boss.caller,
        delegate_user_id=delegate.user,
        tenant_id=parent,
        scope_mode=RoleScope.SUBTREE,
        permission_id=_permission_id(_ASSIGN_ROLES),
    )
    assert _administrator(child) == delegate.user

    _refused_for(
        child,
        lambda: revoke_delegation(
            caller=boss.caller, tenant_id=parent, delegation_grant_id=grant.id
        ),
    )
    assert get_delegation(parent, grant.id).revoked_at is None

    world.member(child, _ADMIN)
    revoke_delegation(caller=boss.caller, tenant_id=parent, delegation_grant_id=grant.id)
    assert get_delegation(parent, grant.id).revoked_at is not None


def test_a_parent_mutation_is_judged_against_every_tenant_it_reaches(world: _World) -> None:
    """Three levels: the role is held at the grandparent, the member it
    makes an administrator sits two levels down. The grandchild is named."""
    top = world.tenant()
    middle = world.tenant(parent=top)
    bottom = world.tenant(parent=middle)
    boss = world.member(top, _ADMIN, scope=RoleScope.SUBTREE)
    inherited = world.member(top, [_ASSIGN_ROLES], scope=RoleScope.SUBTREE)
    world.member(bottom, [], user_id=inherited.user)
    assert _administrator(middle) is None  # not a member there: nothing to protect
    assert _administrator(bottom) == inherited.user

    _refused_for(
        bottom,
        lambda: remove_role(top, inherited.membership, inherited.role_id, caller=boss.caller),
    )


# --- 6-7. Hierarchy and lifecycle changes ---------------------------------------------------


def test_a_tenant_cannot_be_moved_away_from_the_parent_its_last_administrator_depends_on(
    world: _World,
) -> None:
    tree = _Tree(world)
    _refused_for(tree.child, lambda: move_tenant(tree.child, None, caller=platform_operator()))
    assert get_tenant(tree.child).parent_id == tree.parent
    assert tree.parent in get_ancestor_ids(tree.child)  # the ancestry rows were rolled back too

    tree.second_child_administrator()
    move_tenant(tree.child, None, caller=platform_operator())
    assert get_tenant(tree.child).parent_id is None
    assert _administrator(tree.child) is not None


def test_a_tenant_cannot_be_moved_under_a_parent_that_denies_its_last_administrator(
    world: _World,
) -> None:
    """A move can also take authority away by what the *new* ancestors hold."""
    new_parent = world.tenant()
    boss = world.member(new_parent, _ADMIN)
    tenant = world.tenant()
    local = world.member(tenant, _ADMIN)
    create_deny(
        caller=boss.caller,
        principal_user_id=local.user,
        tenant_id=new_parent,
        scope_mode=RoleScope.SUBTREE,
        permission_id=_permission_id(_ASSIGN_ROLES),
    )
    assert _administrator(tenant) == local.user  # the deny does not reach it yet

    _refused_for(tenant, lambda: move_tenant(tenant, new_parent, caller=platform_operator()))
    assert get_tenant(tenant).parent_id is None


def test_moving_a_subtree_is_judged_against_every_tenant_in_it(world: _World) -> None:
    tree = _Tree(world, grandparent=True)
    assert tree.grandparent is not None
    # Moving the parent (and the child with it) keeps the parent->child
    # relationship the child's administrator depends on: allowed.
    move_tenant(tree.parent, None, caller=platform_operator())
    assert _administrator(tree.child) == tree.inherited.user


def test_a_parent_tenant_cannot_be_suspended_under_a_childs_last_administrator(
    world: _World,
) -> None:
    """A role held at a suspended tenant authorizes nothing, in that tenant
    or below it. The suspended tenant itself is exempt."""
    tree = _Tree(world)
    transition_tenant_status(tree.parent, TenantStatus.ACTIVE, caller=platform_operator())
    _refused_for(
        tree.child,
        lambda: transition_tenant_status(
            tree.parent, TenantStatus.SUSPENDED, caller=platform_operator()
        ),
    )
    assert get_tenant(tree.parent).status == TenantStatus.ACTIVE.value

    tree.second_child_administrator()
    transition_tenant_status(tree.parent, TenantStatus.SUSPENDED, caller=platform_operator())
    assert get_tenant(tree.parent).status == TenantStatus.SUSPENDED.value
    assert _administrator(tree.child) is not None
    assert _administrator(tree.parent) is None  # its own principals are locked out, as intended


def test_a_tenant_without_descendants_is_suspended_as_before(world: _World) -> None:
    tenant = world.tenant()
    world.member(tenant, _ADMIN)
    transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=platform_operator())
    transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=platform_operator())
    transition_tenant_status(tenant, TenantStatus.ACTIVE, caller=platform_operator())
    assert _administrator(tenant) is not None


# --- 8. Expiry ------------------------------------------------------------------------------


def test_an_expiring_delegation_does_not_make_the_administrator_a_tenant_can_be_left_with(
    world: _World,
) -> None:
    """Nothing runs when a delegation lapses, so there is nothing to refuse
    then. The refusal happens earlier instead: the delegate can assign
    roles while the delegation is live, but is never the administrator the
    tenant is allowed to be left with."""
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    operator = world.member(tenant, _OPERATOR)
    delegate = world.member(tenant, [])
    create_delegation(
        caller=admin.caller,
        delegate_user_id=delegate.user,
        tenant_id=tenant,
        scope_mode=RoleScope.SELF,
        permission_id=_permission_id(_ASSIGN_ROLES),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    # The delegation is honoured by authorization exactly as before ...
    assert can(
        actor_id=delegate.user, tenant_id=tenant, action="create", resource="membership_role"
    )
    # ... and does not count towards the invariant.
    with tenant_session_scope(tenant) as session:
        assert not administrators.is_administrator(session, tenant, delegate.user)
    _refused_for(
        tenant,
        lambda: remove_role(tenant, admin.membership, admin.role_id, caller=operator.caller),
    )
    assert _administrator(tenant) == admin.user


def test_a_delegation_without_an_expiry_still_makes_an_administrator(world: _World) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    operator = world.member(tenant, _OPERATOR)
    delegate = world.member(tenant, [])
    create_delegation(
        caller=admin.caller,
        delegate_user_id=delegate.user,
        tenant_id=tenant,
        scope_mode=RoleScope.SELF,
        permission_id=_permission_id(_ASSIGN_ROLES),
    )
    remove_role(tenant, admin.membership, admin.role_id, caller=operator.caller)
    assert _administrator(tenant) == delegate.user


# --- What the rule does not do ----------------------------------------------------------------


def test_a_parent_administrator_who_is_not_a_member_of_the_child_does_not_count_there(
    world: _World,
) -> None:
    """An administrator is a *member* of the tenant. Someone who can assign
    roles in the child through a SUBTREE role at the parent, without a
    membership in the child, is not one of its administrators -- so nothing
    in the parent is held back on the child's account."""
    parent = world.tenant()
    child = world.tenant(parent=parent)
    boss = world.member(parent, _ADMIN, scope=RoleScope.SUBTREE)
    other = world.member(parent, [_ASSIGN_ROLES], scope=RoleScope.SUBTREE)
    assert _administrator(child) is None
    remove_role(parent, other.membership, other.role_id, caller=boss.caller)


def test_a_parent_change_that_reaches_no_descendant_searches_none(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only descendants in which the affected user is an active member are
    examined -- not the whole subtree."""
    parent = world.tenant()
    children = [world.tenant(parent=parent) for _ in range(3)]
    for child in children:
        world.member(child, _ADMIN)
    boss = world.member(parent, _ADMIN)
    plain = world.member(parent, [("membership", "read")])
    searched: list[uuid.UUID] = []
    real = administrators.find_administrator

    def counting(session, tenant_id, **kwargs):  # type: ignore[no-untyped-def]
        searched.append(tenant_id)
        return real(session, tenant_id, **kwargs)

    monkeypatch.setattr(administrators, "find_administrator", counting)
    remove_role(parent, plain.membership, plain.role_id, caller=boss.caller)
    assert set(searched) == {parent}


# --- Concurrency across tenants -------------------------------------------------------------


def _race(*actions: Callable[[], object]) -> list[object]:
    barrier = threading.Barrier(len(actions))
    outcomes: list[object] = [None] * len(actions)

    def run(index: int, action: Callable[[], object]) -> None:
        barrier.wait(timeout=10)
        try:
            action()
            outcomes[index] = "done"
        except Exception as exc:  # noqa: BLE001 -- the type is what is asserted
            outcomes[index] = type(exc)

    threads = [
        threading.Thread(target=run, args=(index, action)) for index, action in enumerate(actions)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive(), "a guarded mutation did not finish: deadlock or lock wait"
    return outcomes


# A deadlock would surface as psycopg's DeadlockDetected, which is neither.
_REFUSALS = (LastTenantAdministratorError, AuthorityNotAuthorizedError)


def _exactly_one_went_through(outcomes: list[object]) -> None:
    assert outcomes.count("done") == 1, outcomes
    assert [o for o in outcomes if o != "done"][0] in _REFUSALS, outcomes


@pytest.mark.parametrize("attempt", range(5))
def test_a_parent_mutation_racing_a_child_mutation_leaves_the_child_an_administrator(
    world: _World, attempt: int
) -> None:
    """The child has two administrators: one by inheritance from the
    parent, one in its own right. The parent takes the first away while
    the child takes the second away -- two transactions in two tenants."""
    tree = _Tree(world)
    local = tree.second_child_administrator()
    operator = world.member(tree.child, _OPERATOR)

    outcomes = _race(
        lambda: remove_role(
            tree.parent, tree.inherited.membership, tree.inherited.role_id, caller=tree.boss.caller
        ),
        lambda: remove_role(tree.child, local.membership, local.role_id, caller=operator.caller),
    )

    _exactly_one_went_through(outcomes)
    assert _administrator(tree.child) is not None


@pytest.mark.parametrize("attempt", range(5))
def test_mutations_at_two_ancestor_levels_racing_leave_the_descendant_an_administrator(
    world: _World, attempt: int
) -> None:
    """Grandparent and parent each remove one of the bottom tenant's two
    administrators. Both transactions lock the bottom tenant, each after
    its own -- the order that cannot deadlock."""
    top = world.tenant()
    middle = world.tenant(parent=top)
    bottom = world.tenant(parent=middle)
    top_boss = world.member(top, _ADMIN, scope=RoleScope.SUBTREE)
    middle_boss = world.member(middle, _ADMIN, scope=RoleScope.SUBTREE)
    from_top = world.member(top, [_ASSIGN_ROLES], scope=RoleScope.SUBTREE)
    from_middle = world.member(middle, [_ASSIGN_ROLES], scope=RoleScope.SUBTREE)
    world.member(bottom, [], user_id=from_top.user)
    world.member(bottom, [], user_id=from_middle.user)

    outcomes = _race(
        lambda: remove_role(top, from_top.membership, from_top.role_id, caller=top_boss.caller),
        lambda: suspend_membership(middle, from_middle.membership, caller=middle_boss.caller),
    )

    _exactly_one_went_through(outcomes)
    assert _administrator(bottom) is not None


@pytest.mark.parametrize("attempt", range(5))
def test_a_tenant_move_racing_a_child_mutation_leaves_the_child_an_administrator(
    world: _World, attempt: int
) -> None:
    tree = _Tree(world)
    local = tree.second_child_administrator()
    operator = world.member(tree.child, _OPERATOR)

    outcomes = _race(
        lambda: move_tenant(
            tree.child, None, caller=platform_operator()
        ),  # would end the inherited authority
        lambda: remove_role(tree.child, local.membership, local.role_id, caller=operator.caller),
    )

    _exactly_one_went_through(outcomes)
    assert _administrator(tree.child) is not None


@pytest.mark.parametrize("attempt", range(5))
def test_a_parent_suspension_racing_a_child_mutation_leaves_the_child_an_administrator(
    world: _World, attempt: int
) -> None:
    tree = _Tree(world)
    transition_tenant_status(tree.parent, TenantStatus.ACTIVE, caller=platform_operator())
    local = tree.second_child_administrator()
    operator = world.member(tree.child, _OPERATOR)

    outcomes = _race(
        lambda: transition_tenant_status(
            tree.parent, TenantStatus.SUSPENDED, caller=platform_operator()
        ),
        lambda: remove_role(tree.child, local.membership, local.role_id, caller=operator.caller),
    )

    _exactly_one_went_through(outcomes)
    assert _administrator(tree.child) is not None


@pytest.mark.parametrize("attempt", range(8))
def test_a_parent_deny_racing_a_child_deny_leaves_the_child_an_administrator(
    world: _World, attempt: int
) -> None:
    """Opposing orders. A deny locks the denied user's row exclusively, and
    the guard reads the other administrator's row: the parent denies the
    child's first administrator while the child denies its second, each
    needing the row the other holds. The per-tenant locks are taken before
    either row lock, so one transaction waits for the other instead of the
    two deadlocking."""
    parent = world.tenant()
    child = world.tenant(parent=parent)
    boss = world.member(parent, _ADMIN)
    first, second = world.member(child, _ADMIN), world.member(child, _ADMIN)
    operator = world.member(child, _OPERATOR)
    assign = _permission_id(_ASSIGN_ROLES)

    outcomes = _race(
        lambda: create_deny(
            caller=boss.caller,
            principal_user_id=first.user,
            tenant_id=parent,
            scope_mode=RoleScope.SUBTREE,
            permission_id=assign,
        ),
        lambda: create_deny(
            caller=operator.caller,
            principal_user_id=second.user,
            tenant_id=child,
            scope_mode=RoleScope.SELF,
            permission_id=assign,
        ),
    )

    _exactly_one_went_through(outcomes)
    assert _administrator(child) is not None


def test_a_parent_deny_and_a_child_deny_do_not_deadlock_on_the_denied_users_rows(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The interleaving the race above only sometimes hits, forced: each
    transaction is held for a moment right after it locks the user it is
    denying. If a deny took that row lock before the administrator locks
    of the tenants it reaches, the parent would hold one user's row and
    wait for the child tenant's lock, while the child held that lock and
    waited for the row -- a deadlock, which PostgreSQL breaks by failing
    one of them with a database error. With the administrator locks taken
    first, one transaction simply waits for the other."""
    import time

    import saas_os.core.rbac.service as rbac_service

    parent = world.tenant()
    child = world.tenant(parent=parent)
    boss = world.member(parent, _ADMIN)
    first, second = world.member(child, _ADMIN), world.member(child, _ADMIN)
    operator = world.member(child, _OPERATOR)
    assign = _permission_id(_ASSIGN_ROLES)
    real = rbac_service.lock_user_is_active

    def slow_exclusive_lock(session, user_id, *, exclusive=False):  # type: ignore[no-untyped-def]
        result = real(session, user_id, exclusive=exclusive)
        if exclusive:
            time.sleep(0.75)
        return result

    monkeypatch.setattr(rbac_service, "lock_user_is_active", slow_exclusive_lock)

    outcomes = _race(
        lambda: create_deny(
            caller=boss.caller,
            principal_user_id=first.user,
            tenant_id=parent,
            scope_mode=RoleScope.SUBTREE,
            permission_id=assign,
        ),
        lambda: create_deny(
            caller=operator.caller,
            principal_user_id=second.user,
            tenant_id=child,
            scope_mode=RoleScope.SELF,
            permission_id=assign,
        ),
    )

    _exactly_one_went_through(outcomes)
    assert _administrator(child) is not None


# --- Negative controls ------------------------------------------------------------------


def test_without_the_check_a_parent_mutation_empties_the_child(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _Tree(world)
    monkeypatch.setattr(
        administrators.AdministratorGuard, "verify", lambda self, session, **kwargs: None
    )
    remove_role(
        tree.parent, tree.inherited.membership, tree.inherited.role_id, caller=tree.boss.caller
    )
    assert _administrator(tree.child) is None


def test_without_the_check_a_move_and_a_suspension_empty_the_child(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    moved, suspended = _Tree(world), _Tree(world)
    transition_tenant_status(suspended.parent, TenantStatus.ACTIVE, caller=platform_operator())
    monkeypatch.setattr(
        administrators.AdministratorGuard, "verify", lambda self, session, **kwargs: None
    )
    move_tenant(moved.child, None, caller=platform_operator())
    assert _administrator(moved.child) is None
    transition_tenant_status(suspended.parent, TenantStatus.SUSPENDED, caller=platform_operator())
    assert _administrator(suspended.child) is None


def test_judging_only_the_mutations_own_tenant_misses_the_child(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rule as it was before it followed the hierarchy: with the
    descendant search switched off, the parent's own tenant passes and the
    child is emptied."""
    tree = _Tree(world)
    monkeypatch.setattr(administrators, "descendant_ids_by_depth", lambda session, tenant_id: [])
    remove_role(
        tree.parent, tree.inherited.membership, tree.inherited.role_id, caller=tree.boss.caller
    )
    assert _administrator(tree.child) is None
