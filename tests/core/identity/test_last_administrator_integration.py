"""The last-administrator invariant on membership suspend/revoke
(docs/ADR/0043-last-tenant-administrator-invariant.md), against real
PostgreSQL.

A tenant administrator is an ACTIVE member, an active user, who can assign
roles in the tenant (`membership_role:create`). Suspending or revoking the
last one is refused, inside the transition's own transaction and under a
per-tenant lock.

Covered: self-revocation; revoking another administrator; a suspended or
inactive administrator not counting; a non-administrator never being held
back; a tenant with no administrator at all; tenant isolation; two
administrators revoking each other concurrently; nothing written when the
transition is refused; and a negative control with the guard removed.

Marked `integration`.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import text

import saas_os.core.rbac.administrators as administrators
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import (
    LastTenantAdministratorError,
    MembershipStatus,
    get_membership,
    reactivate_membership,
    revoke_membership,
    suspend_membership,
)
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_ASSIGN_ROLES = ("membership_role", "create")
_MANAGE = [("membership", "suspend"), ("membership", "reactivate"), ("membership", "revoke")]
_ADMIN = [_ASSIGN_ROLES, *_MANAGE]


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


def _as_admin(statement: str, **params: object) -> list[tuple[object, ...]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(statement), params)
            return [tuple(row) for row in result.all()] if result.returns_rows else []
    finally:
        engine.dispose()


class _World:
    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    def tenant(self) -> uuid.UUID:
        tenant = create_tenant(_unique("last-admin"))
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def member(
        self,
        tenant_id: uuid.UUID,
        permissions: list[tuple[str, str]],
        *,
        user_id: uuid.UUID | None = None,
    ) -> tuple[uuid.UUID, uuid.UUID]:
        """(user id, membership id) of an ACTIVE member holding exactly
        `permissions` at `tenant_id`."""
        if user_id is None:
            user_id = create_user().id
            self.user_ids.append(user_id)
        membership = add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
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
                tenant_id, membership.id, role.id, caller=_PROVISIONING
            )
        return user_id, membership.id

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
                    "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) "
                    "OR ancestor_id = ANY(:t)",
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


def _status(tenant_id: uuid.UUID, user_id: uuid.UUID) -> str:
    membership = get_membership(tenant_id, user_id)
    assert membership is not None
    return membership.status


def _transition_audit_rows(tenant_id: uuid.UUID) -> int:
    return int(
        _as_admin(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND action IN ('membership.suspend', 'membership.revoke')",
            t=str(tenant_id),
        )[0][0]  # type: ignore[arg-type]
    )


# --- The sole administrator ---------------------------------------------------------------


@pytest.mark.parametrize("operation", [suspend_membership, revoke_membership])
def test_the_sole_administrator_cannot_suspend_or_revoke_themselves(
    world: _World, operation
) -> None:  # type: ignore[no-untyped-def]
    tenant = world.tenant()
    admin, admin_membership = world.member(tenant, _ADMIN)
    world.member(tenant, [])  # an ordinary member does not make the admin replaceable

    with pytest.raises(LastTenantAdministratorError) as raised:
        operation(tenant, admin_membership, caller=UserCaller(admin))

    assert raised.value.tenant_id == tenant and raised.value.membership_id == admin_membership
    assert _status(tenant, admin) == MembershipStatus.ACTIVE.value
    assert _transition_audit_rows(tenant) == 0  # refused: nothing written, nothing audited


def test_another_member_with_revoke_authority_cannot_remove_the_sole_administrator(
    world: _World,
) -> None:
    """Holding `membership:revoke` is not being an administrator: this member
    can revoke others, but cannot assign roles, so removing the administrator
    would leave nobody who can."""
    tenant = world.tenant()
    admin, admin_membership = world.member(tenant, _ADMIN)
    manager, _ = world.member(tenant, _MANAGE)

    for operation in (suspend_membership, revoke_membership):
        with pytest.raises(LastTenantAdministratorError):
            operation(tenant, admin_membership, caller=UserCaller(manager))
    assert _status(tenant, admin) == MembershipStatus.ACTIVE.value


# --- More than one administrator ----------------------------------------------------------


def test_one_of_two_administrators_can_be_revoked_and_then_the_other_is_the_last(
    world: _World,
) -> None:
    tenant = world.tenant()
    first, first_membership = world.member(tenant, _ADMIN)
    second, second_membership = world.member(tenant, _ADMIN)

    revoked = revoke_membership(tenant, second_membership, caller=UserCaller(first))
    assert revoked.status == MembershipStatus.REVOKED.value

    with pytest.raises(LastTenantAdministratorError):
        revoke_membership(tenant, first_membership, caller=UserCaller(first))
    assert _status(tenant, first) == MembershipStatus.ACTIVE.value
    assert _status(tenant, second) == MembershipStatus.REVOKED.value


def test_an_administrator_may_leave_while_another_remains(world: _World) -> None:
    tenant = world.tenant()
    first, first_membership = world.member(tenant, _ADMIN)
    world.member(tenant, _ADMIN)
    assert (
        revoke_membership(tenant, first_membership, caller=UserCaller(first)).status
        == MembershipStatus.REVOKED.value
    )


# --- Who counts as an administrator ---------------------------------------------------------


def test_a_suspended_administrator_does_not_count(world: _World) -> None:
    tenant = world.tenant()
    first, first_membership = world.member(tenant, _ADMIN)
    second, second_membership = world.member(tenant, _ADMIN)

    suspend_membership(tenant, second_membership, caller=UserCaller(first))
    # The other administrator exists but is suspended: `first` is the last.
    with pytest.raises(LastTenantAdministratorError):
        suspend_membership(tenant, first_membership, caller=UserCaller(first))

    # Revoking the already-suspended one is not a removal of an administrator.
    assert (
        revoke_membership(tenant, second_membership, caller=UserCaller(first)).status
        == MembershipStatus.REVOKED.value
    )


def test_reactivating_the_other_administrator_lifts_the_restriction(world: _World) -> None:
    tenant = world.tenant()
    first, first_membership = world.member(tenant, _ADMIN)
    _, second_membership = world.member(tenant, _ADMIN)

    suspend_membership(tenant, second_membership, caller=UserCaller(first))
    with pytest.raises(LastTenantAdministratorError):
        revoke_membership(tenant, first_membership, caller=UserCaller(first))
    reactivate_membership(tenant, second_membership, caller=UserCaller(first))
    assert (
        revoke_membership(tenant, first_membership, caller=UserCaller(first)).status
        == MembershipStatus.REVOKED.value
    )


def test_an_inactive_user_does_not_count_as_an_administrator(world: _World) -> None:
    tenant = world.tenant()
    first, first_membership = world.member(tenant, _ADMIN)
    second, _ = world.member(tenant, _ADMIN)

    _as_admin("UPDATE core.users SET is_active = false WHERE id = :u", u=str(second))
    # `second` still has an ACTIVE membership and the role, but the user is
    # deactivated: the authorization engine denies them, so they are no
    # administrator.
    with pytest.raises(LastTenantAdministratorError):
        revoke_membership(tenant, first_membership, caller=UserCaller(first))


def test_an_ordinary_member_is_never_held_back(world: _World) -> None:
    tenant = world.tenant()
    admin, _ = world.member(tenant, _ADMIN)
    _, plain_membership = world.member(tenant, [])
    _, other_membership = world.member(tenant, [("membership", "read")])

    assert (
        suspend_membership(tenant, plain_membership, caller=UserCaller(admin)).status
        == MembershipStatus.SUSPENDED.value
    )
    assert (
        revoke_membership(tenant, other_membership, caller=UserCaller(admin)).status
        == MembershipStatus.REVOKED.value
    )


def test_a_tenant_with_no_administrator_is_not_locked_further(world: _World) -> None:
    """The rule protects the last administrator; it does not invent one. A
    tenant nobody can assign roles in keeps working as before."""
    tenant = world.tenant()
    manager, manager_membership = world.member(tenant, _MANAGE)
    _, plain_membership = world.member(tenant, [])

    assert (
        revoke_membership(tenant, plain_membership, caller=UserCaller(manager)).status
        == MembershipStatus.REVOKED.value
    )
    assert (
        revoke_membership(tenant, manager_membership, caller=UserCaller(manager)).status
        == MembershipStatus.REVOKED.value
    )


# --- Tenant isolation -------------------------------------------------------------------


def test_administrators_of_another_tenant_do_not_count(world: _World) -> None:
    here, elsewhere = world.tenant(), world.tenant()
    admin, admin_membership = world.member(here, _ADMIN)
    world.member(elsewhere, _ADMIN)
    world.member(elsewhere, _ADMIN)

    with pytest.raises(LastTenantAdministratorError):
        revoke_membership(here, admin_membership, caller=UserCaller(admin))


def test_the_same_user_is_judged_per_tenant(world: _World) -> None:
    """An administrator of two tenants is the last one in `lonely` and one
    of two in `shared`: only the first removal is refused."""
    lonely, shared = world.tenant(), world.tenant()
    user, lonely_membership = world.member(lonely, _ADMIN)
    _, shared_membership = world.member(shared, _ADMIN, user_id=user)
    world.member(shared, _ADMIN)

    with pytest.raises(LastTenantAdministratorError):
        revoke_membership(lonely, lonely_membership, caller=UserCaller(user))
    assert (
        revoke_membership(shared, shared_membership, caller=UserCaller(user)).status
        == MembershipStatus.REVOKED.value
    )
    assert _status(lonely, user) == MembershipStatus.ACTIVE.value


def test_an_administrator_of_one_tenant_cannot_act_in_another(world: _World) -> None:
    here, elsewhere = world.tenant(), world.tenant()
    outsider, _ = world.member(elsewhere, _ADMIN)
    _, target_membership = world.member(here, _ADMIN)
    world.member(here, _ADMIN)

    with pytest.raises(AuthorityNotAuthorizedError):
        revoke_membership(here, target_membership, caller=UserCaller(outsider))


# --- Concurrency ------------------------------------------------------------------------


@pytest.mark.parametrize("attempt", range(5))
def test_two_administrators_revoking_each_other_concurrently_leave_one(
    world: _World, attempt: int
) -> None:
    """Without the per-tenant lock both transactions would see the other
    administrator still ACTIVE, both would pass the check, and the tenant
    would end with none."""
    tenant = world.tenant()
    first, first_membership = world.member(tenant, _ADMIN)
    second, second_membership = world.member(tenant, _ADMIN)
    barrier = threading.Barrier(2)
    outcomes: dict[str, object] = {}

    def revoke(label: str, caller: uuid.UUID, target: uuid.UUID) -> None:
        barrier.wait(timeout=10)
        try:
            revoke_membership(tenant, target, caller=UserCaller(caller))
            outcomes[label] = "revoked"
        except Exception as exc:  # noqa: BLE001 -- the type is what is asserted
            outcomes[label] = type(exc)

    threads = [
        threading.Thread(target=revoke, args=("first", first, second_membership)),
        threading.Thread(target=revoke, args=("second", second, first_membership)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()

    statuses = sorted([_status(tenant, first), _status(tenant, second)])
    assert statuses == [MembershipStatus.ACTIVE.value, MembershipStatus.REVOKED.value], outcomes
    assert sorted(str(v) for v in outcomes.values()).count("revoked") == 1
    # The loser was refused because, once the winner committed, the loser's
    # own membership no longer authorized anything.
    (loser,) = [v for v in outcomes.values() if v != "revoked"]
    assert loser in (AuthorityNotAuthorizedError, LastTenantAdministratorError)


@pytest.mark.parametrize("attempt", range(5))
def test_two_administrators_leaving_concurrently_leave_one(world: _World, attempt: int) -> None:
    tenant = world.tenant()
    first, first_membership = world.member(tenant, _ADMIN)
    second, second_membership = world.member(tenant, _ADMIN)
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def leave(user: uuid.UUID, membership: uuid.UUID) -> None:
        barrier.wait(timeout=10)
        try:
            revoke_membership(tenant, membership, caller=UserCaller(user))
            outcomes.append("revoked")
        except LastTenantAdministratorError:
            outcomes.append("refused")

    threads = [
        threading.Thread(target=leave, args=(first, first_membership)),
        threading.Thread(target=leave, args=(second, second_membership)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()

    assert sorted(outcomes) == ["refused", "revoked"]  # type: ignore[type-var]
    assert sorted([_status(tenant, first), _status(tenant, second)]) == [
        MembershipStatus.ACTIVE.value,
        MembershipStatus.REVOKED.value,
    ]


# --- Negative controls ------------------------------------------------------------------


def test_without_the_guard_the_sole_administrator_is_removed(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check is what prevents the lockout: with it replaced by a no-op,
    the very call the first test sees refused goes through."""
    tenant = world.tenant()
    admin, admin_membership = world.member(tenant, _ADMIN)
    monkeypatch.setattr(
        administrators.AdministratorGuard, "verify", lambda self, session, **kwargs: None
    )

    revoked = revoke_membership(tenant, admin_membership, caller=UserCaller(admin))
    assert revoked.status == MembershipStatus.REVOKED.value


def test_the_transition_takes_the_tenant_lock_before_it_looks_for_administrators(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Observed in order on a real transition: lock, then the search."""
    tenant = world.tenant()
    admin, _ = world.member(tenant, _ADMIN)
    _, plain_membership = world.member(tenant, [])
    calls: list[str] = []
    real_lock = administrators.lock_tenant_administrators
    real_guard = administrators.guard_last_administrator

    def lock(session, tenant_id):  # type: ignore[no-untyped-def]
        calls.append("lock")
        return real_lock(session, tenant_id)

    def guard(session, tenant_id, **kwargs):  # type: ignore[no-untyped-def]
        calls.append("guard")
        return real_guard(session, tenant_id, **kwargs)

    monkeypatch.setattr(administrators, "lock_tenant_administrators", lock)
    monkeypatch.setattr(administrators, "guard_last_administrator", guard)

    revoke_membership(tenant, plain_membership, caller=UserCaller(admin))
    assert calls == ["lock", "guard"]
