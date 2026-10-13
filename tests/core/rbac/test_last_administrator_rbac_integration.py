"""The last-administrator invariant on role, permission, deny and delegation
changes (docs/ADR/0043-...; `saas_os/core/rbac/administrators.py`), against
real PostgreSQL.

`tests/core/identity/test_last_administrator_integration.py` covers
membership suspend and revoke. This module covers the other mutations that
can take the ability to assign roles (`membership_role:create`) away from a
member:

- `remove_role` -- the role is taken off the member;
- `revoke_permission` -- the permission is taken off the role;
- `create_deny` -- an explicit deny is placed on the member;
- `revoke_delegation` -- a delegated authority is withdrawn;
- `delete_role` -- shown to need no guard (the foreign keys refuse it).

One rule for all of them: a tenant that has an administrator still has one
afterwards, or the mutation raises `LastTenantAdministratorError` and
writes nothing. Also: tenants with no administrator are not locked,
tenants are judged separately, mixed concurrent mutations leave one
administrator, and a negative control with the check removed.

Marked `integration`.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Iterator

import pytest
from sqlalchemy import text

import saas_os.core.rbac.administrators as administrators
from lifecycle_callers import PROVISIONING
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import LastTenantAdministratorError, revoke_membership
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.rbac import RoleScope, can
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    assign_role,
    create_delegation,
    create_deny,
    create_role,
    delete_role,
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
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db import IntegrityError
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_ASSIGN_ROLES = ("membership_role", "create")
# Everything an administrator in these tests may do, including the authority
# to perform each guarded mutation -- so a refusal is the invariant, never a
# missing permission.
_ADMIN = [
    _ASSIGN_ROLES,
    ("membership_role", "delete"),
    ("role_permission", "revoke"),
    ("role", "delete"),
    ("deny_grant", "create"),
    ("delegation_grant", "create"),
    ("delegation_grant", "revoke"),
    ("membership", "revoke"),
]
# Can perform every guarded mutation, but cannot assign roles: not an administrator.
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

    def tenant(self) -> uuid.UUID:
        tenant = create_tenant(_unique("last-admin-rbac"), caller=PROVISIONING)
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def member(self, tenant_id: uuid.UUID, permissions: list[tuple[str, str]]) -> _Member:
        user_id = create_user().id
        self.user_ids.append(user_id)
        membership = add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
        role_id = self.role(tenant_id, permissions).id if permissions else None
        if role_id is not None:
            assign_first_role_for_new_tenant(
                tenant_id, membership.id, role_id, caller=_PROVISIONING
            )
        return _Member(user_id, membership.id, role_id)

    def role(self, tenant_id: uuid.UUID, permissions: list[tuple[str, str]]):  # type: ignore[no-untyped-def]
        role = create_role(tenant_id, _unique("role"), caller=_PROVISIONING)
        for resource, action in permissions:
            grant_permission(
                tenant_id, role.id, register_permission(resource, action).id, caller=_PROVISIONING
            )
        return role

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


def _is_admin(tenant: uuid.UUID, member: _Member) -> bool:
    return can(actor_id=member.user, tenant_id=tenant, action="create", resource="membership_role")


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


# --- remove_role ----------------------------------------------------------------------------


def test_the_last_administrators_role_cannot_be_removed(world: _World) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    operator = world.member(tenant, _OPERATOR)
    assert admin.role is not None

    for caller in (admin.caller, operator.caller):  # by themselves, or by someone else
        with pytest.raises(LastTenantAdministratorError) as raised:
            remove_role(tenant, admin.membership, admin.role, caller=caller)
        assert raised.value.tenant_id == tenant

    assert [r.role_id for r in list_membership_roles(tenant, admin.membership)] == [admin.role]
    assert _is_admin(tenant, admin)
    assert "membership_role.delete" not in _audit_actions(tenant)  # refused: nothing audited


def test_a_role_can_be_removed_from_one_of_two_administrators_but_not_from_the_last(
    world: _World,
) -> None:
    tenant = world.tenant()
    first, second = world.member(tenant, _ADMIN), world.member(tenant, _ADMIN)
    assert first.role and second.role

    remove_role(tenant, second.membership, second.role, caller=first.caller)
    assert not _is_admin(tenant, second)
    with pytest.raises(LastTenantAdministratorError):
        remove_role(tenant, first.membership, first.role, caller=first.caller)
    assert _is_admin(tenant, first)


def test_removing_a_role_that_confers_no_administration_is_never_held_back(world: _World) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    reader = world.member(tenant, [("membership", "read")])
    assert reader.role

    remove_role(tenant, reader.membership, reader.role, caller=admin.caller)
    assert list_membership_roles(tenant, reader.membership) == []


def test_an_administrator_with_two_roles_keeps_authority_until_the_second_is_removed(
    world: _World,
) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    spare = world.role(tenant, [_ASSIGN_ROLES])
    assign_role(tenant, admin.membership, spare.id, scope=RoleScope.SELF, caller=admin.caller)
    assert admin.role

    remove_role(tenant, admin.membership, spare.id, caller=admin.caller)  # still an administrator
    with pytest.raises(LastTenantAdministratorError):
        remove_role(tenant, admin.membership, admin.role, caller=admin.caller)


# --- revoke_permission ----------------------------------------------------------------------


def test_the_permission_cannot_be_revoked_from_the_only_role_that_confers_it(
    world: _World,
) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    assert admin.role
    assign = _permission_id(_ASSIGN_ROLES)

    with pytest.raises(LastTenantAdministratorError):
        revoke_permission(tenant, admin.role, assign, caller=admin.caller)
    assert get_role_permission(tenant, admin.role, assign) is not None
    assert "role_permission.revoke" not in _audit_actions(tenant)

    # Any other permission of that role can go.
    other = _permission_id(("deny_grant", "create"))
    revoke_permission(tenant, admin.role, other, caller=admin.caller)
    assert get_role_permission(tenant, admin.role, other) is None


def test_the_permission_can_be_revoked_from_a_role_while_another_administrator_remains(
    world: _World,
) -> None:
    tenant = world.tenant()
    first, second = world.member(tenant, _ADMIN), world.member(tenant, _ADMIN)
    assert first.role and second.role
    assign = _permission_id(_ASSIGN_ROLES)

    revoke_permission(tenant, second.role, assign, caller=first.caller)
    assert not _is_admin(tenant, second)
    with pytest.raises(LastTenantAdministratorError):
        revoke_permission(tenant, first.role, assign, caller=first.caller)


def test_revoking_from_a_shared_role_counts_every_member_who_loses_it(world: _World) -> None:
    """Two administrators through one role: revoking the permission from that
    role removes both at once, so it is refused even though there are two."""
    tenant = world.tenant()
    first = world.member(tenant, _ADMIN)
    second = world.member(tenant, [])
    assert first.role
    assign_role(tenant, second.membership, first.role, scope=RoleScope.SELF, caller=first.caller)
    assert _is_admin(tenant, second)

    with pytest.raises(LastTenantAdministratorError):
        revoke_permission(tenant, first.role, _permission_id(_ASSIGN_ROLES), caller=first.caller)
    assert _is_admin(tenant, first) and _is_admin(tenant, second)


# --- create_deny ----------------------------------------------------------------------------


def test_the_last_administrator_cannot_be_denied_the_authority(world: _World) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    operator = world.member(tenant, _OPERATOR)
    assign = _permission_id(_ASSIGN_ROLES)

    for caller in (admin.caller, operator.caller):
        with pytest.raises(LastTenantAdministratorError):
            create_deny(
                caller=caller,
                principal_user_id=admin.user,
                tenant_id=tenant,
                scope_mode=RoleScope.SELF,
                permission_id=assign,
            )
    assert list_denies_for_principal(tenant, admin.user) == []
    assert _is_admin(tenant, admin)

    # Denying the same administrator something else is not administration.
    create_deny(
        caller=operator.caller,
        principal_user_id=admin.user,
        tenant_id=tenant,
        scope_mode=RoleScope.SELF,
        permission_id=_permission_id(("membership", "revoke")),
    )
    assert _is_admin(tenant, admin)


def test_one_of_two_administrators_can_be_denied_and_then_the_other_cannot(world: _World) -> None:
    tenant = world.tenant()
    first, second = world.member(tenant, _ADMIN), world.member(tenant, _ADMIN)
    assign = _permission_id(_ASSIGN_ROLES)

    create_deny(
        caller=first.caller,
        principal_user_id=second.user,
        tenant_id=tenant,
        scope_mode=RoleScope.SELF,
        permission_id=assign,
    )
    assert not _is_admin(tenant, second)
    with pytest.raises(LastTenantAdministratorError):
        create_deny(
            caller=first.caller,
            principal_user_id=first.user,
            tenant_id=tenant,
            scope_mode=RoleScope.SELF,
            permission_id=assign,
        )


# --- revoke_delegation ----------------------------------------------------------------------


def test_the_delegation_that_makes_someone_the_last_administrator_cannot_be_revoked(
    world: _World,
) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    operator = world.member(tenant, _OPERATOR)
    delegate = world.member(tenant, [])
    assert admin.role

    grant = create_delegation(
        caller=admin.caller,
        delegate_user_id=delegate.user,
        tenant_id=tenant,
        scope_mode=RoleScope.SELF,
        permission_id=_permission_id(_ASSIGN_ROLES),
    )
    assert _is_admin(tenant, delegate), (
        "a delegation of membership_role:create makes an administrator"
    )

    # With the delegate as a second administrator, the first can lose the role.
    remove_role(tenant, admin.membership, admin.role, caller=operator.caller)
    assert not _is_admin(tenant, admin)
    assert _is_admin(tenant, delegate), "the delegated authority outlives the delegator's role"

    # Now the delegation is all that is left: neither the delegator nor an
    # authorized third party can withdraw it.
    for caller in (admin.caller, operator.caller):
        with pytest.raises(LastTenantAdministratorError):
            revoke_delegation(caller=caller, tenant_id=tenant, delegation_grant_id=grant.id)
    assert get_delegation(tenant, grant.id).revoked_at is None
    assert _is_admin(tenant, delegate)


def test_a_delegation_can_be_revoked_while_another_administrator_remains(world: _World) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    delegate = world.member(tenant, [])
    grant = create_delegation(
        caller=admin.caller,
        delegate_user_id=delegate.user,
        tenant_id=tenant,
        scope_mode=RoleScope.SELF,
        permission_id=_permission_id(_ASSIGN_ROLES),
    )
    revoked = revoke_delegation(caller=admin.caller, tenant_id=tenant, delegation_grant_id=grant.id)
    assert revoked.revoked_at is not None
    assert not _is_admin(tenant, delegate) and _is_admin(tenant, admin)


# --- delete_role needs no guard -------------------------------------------------------------


def test_a_role_in_use_cannot_be_deleted_at_all(world: _World) -> None:
    """Why `delete_role` carries no administrator guard: the foreign keys
    refuse to delete a role that is assigned or still grants a permission,
    so deleting a role can never change who is an administrator."""
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    assert admin.role
    with pytest.raises(IntegrityError):
        delete_role(tenant, admin.role, caller=admin.caller)
    assert _is_admin(tenant, admin)

    unused = world.role(tenant, [])
    delete_role(tenant, unused.id, caller=admin.caller)  # an unused role goes
    assert _is_admin(tenant, admin)


# --- What the rule does not do ----------------------------------------------------------------


def test_a_tenant_with_no_administrator_is_not_locked_further(world: _World) -> None:
    tenant = world.tenant()
    operator = world.member(tenant, _OPERATOR)
    reader = world.member(tenant, [("membership", "read")])
    assert operator.role and reader.role

    remove_role(tenant, reader.membership, reader.role, caller=operator.caller)
    revoke_permission(
        tenant, operator.role, _permission_id(("deny_grant", "create")), caller=operator.caller
    )
    remove_role(tenant, operator.membership, operator.role, caller=operator.caller)
    assert list_membership_roles(tenant, operator.membership) == []


def test_tenants_are_judged_separately(world: _World) -> None:
    here, elsewhere = world.tenant(), world.tenant()
    admin = world.member(here, _ADMIN)
    world.member(elsewhere, _ADMIN)
    world.member(elsewhere, _ADMIN)
    assert admin.role

    with pytest.raises(LastTenantAdministratorError):
        remove_role(here, admin.membership, admin.role, caller=admin.caller)


def test_a_caller_without_authority_is_refused_before_the_invariant_is_considered(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    plain = world.member(tenant, [])
    assert admin.role
    searches: list[uuid.UUID] = []
    real = administrators.find_administrator

    def counting(session, tenant_id, **kwargs):  # type: ignore[no-untyped-def]
        searches.append(tenant_id)
        return real(session, tenant_id, **kwargs)

    monkeypatch.setattr(administrators, "find_administrator", counting)
    with pytest.raises(AuthorityNotAuthorizedError):
        remove_role(tenant, admin.membership, admin.role, caller=plain.caller)
    assert searches == []  # no member was examined on behalf of an unauthorized caller


def test_a_no_op_does_not_search_for_administrators(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    searches: list[uuid.UUID] = []
    real = administrators.find_administrator

    def counting(session, tenant_id, **kwargs):  # type: ignore[no-untyped-def]
        searches.append(tenant_id)
        return real(session, tenant_id, **kwargs)

    monkeypatch.setattr(administrators, "find_administrator", counting)
    remove_role(tenant, admin.membership, uuid.uuid4(), caller=admin.caller)  # nothing assigned
    revoke_permission(tenant, uuid.uuid4(), uuid.uuid4(), caller=admin.caller)  # nothing granted
    assert searches == []


# --- Concurrency ------------------------------------------------------------------------


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
        assert not thread.is_alive()
    return outcomes


_REFUSALS = (LastTenantAdministratorError, AuthorityNotAuthorizedError)


@pytest.mark.parametrize("attempt", range(5))
def test_two_administrators_removing_each_others_role_concurrently_leave_one(
    world: _World, attempt: int
) -> None:
    tenant = world.tenant()
    first, second = world.member(tenant, _ADMIN), world.member(tenant, _ADMIN)
    assert first.role and second.role

    outcomes = _race(
        lambda: remove_role(tenant, second.membership, second.role_id, caller=first.caller),
        lambda: remove_role(tenant, first.membership, first.role_id, caller=second.caller),
    )

    assert sorted(map(str, outcomes)).count("done") == 1, outcomes
    assert [o for o in outcomes if o != "done"][0] in _REFUSALS
    assert [_is_admin(tenant, first), _is_admin(tenant, second)].count(True) == 1


@pytest.mark.parametrize("attempt", range(5))
def test_different_mutations_racing_against_the_last_two_administrators_leave_one(
    world: _World, attempt: int
) -> None:
    """One administrator revokes the other's membership while the other
    revokes the permission from the first one's role: different functions,
    the same lock, the same rule."""
    tenant = world.tenant()
    first, second = world.member(tenant, _ADMIN), world.member(tenant, _ADMIN)
    assert first.role and second.role
    assign = _permission_id(_ASSIGN_ROLES)

    outcomes = _race(
        lambda: revoke_membership(tenant, second.membership, caller=first.caller),
        lambda: revoke_permission(tenant, first.role_id, assign, caller=second.caller),
    )

    assert sorted(map(str, outcomes)).count("done") == 1, outcomes
    assert [o for o in outcomes if o != "done"][0] in _REFUSALS
    assert [_is_admin(tenant, first), _is_admin(tenant, second)].count(True) == 1


@pytest.mark.parametrize("attempt", range(5))
def test_a_deny_racing_a_role_removal_leaves_one_administrator(world: _World, attempt: int) -> None:
    tenant = world.tenant()
    first, second = world.member(tenant, _ADMIN), world.member(tenant, _ADMIN)
    assert first.role and second.role
    assign = _permission_id(_ASSIGN_ROLES)

    outcomes = _race(
        lambda: create_deny(
            caller=first.caller,
            principal_user_id=second.user,
            tenant_id=tenant,
            scope_mode=RoleScope.SELF,
            permission_id=assign,
        ),
        lambda: remove_role(tenant, first.membership, first.role_id, caller=second.caller),
    )

    assert "done" in outcomes, outcomes
    assert [_is_admin(tenant, first), _is_admin(tenant, second)].count(True) == 1, outcomes


# --- Negative control ---------------------------------------------------------------------


def test_without_the_check_the_last_administrators_role_is_removed(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = world.tenant()
    admin = world.member(tenant, _ADMIN)
    assert admin.role
    monkeypatch.setattr(
        administrators.AdministratorGuard, "verify", lambda self, session, **kwargs: None
    )

    remove_role(tenant, admin.membership, admin.role, caller=admin.caller)
    assert not _is_admin(tenant, admin)
