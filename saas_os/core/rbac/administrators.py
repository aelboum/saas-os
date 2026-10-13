"""The last-tenant-administrator invariant (docs/ADR/0043-...).

**One rule.** A tenant that has an administrator must still have one after
any supported mutation that can take administrative authority away from a
member -- whether that mutation happens in the tenant itself or in one of
its ancestors.

**Administrator** is not a role -- roles are a tenant's own, freely named.
It is a capability, in the authorization engine's own terms: an ACTIVE
member of the tenant, an active user, for whom `can()` allows
`membership_role:create` there, i.e. who can assign roles, and who does
not owe that to a delegation with an expiry. Whoever can assign roles can
hand out every other authority, so it is the one a tenant cannot recover
from inside once nobody holds it. Everything `can()` weighs -- membership
status, `User.is_active`, tenant status, role scope, the ancestor chain,
delegation, deny grants -- is weighed here by calling `can()`, never
re-derived.

An expiring delegation is left out because nothing runs when it lapses:
no mutation exists to refuse. A delegate whose only authority expires is
therefore never the administrator a tenant is allowed to be left with.

**One mechanism.** Every guarded mutation does the same things in its own
transaction:

    lock_tenant_administrators(session, tenant_id)         # first statement
    ... authorize the caller, find the row ...
    guard = guard_last_administrator(                      # just before the change
        session, tenant_id, affected_users=[...])
    ... change rows, session.flush() ...
    guard.verify(session)                                  # before commit

`guard_last_administrator` records one current administrator, if there is
one, of every tenant the change can reach. `verify` asks the same question
of the changed rows; if any of those tenants had an administrator and now
has none, it raises `LastTenantAdministratorError` naming that tenant, and
the transaction rolls back -- nothing is written and nothing is audited.

**Which tenants a change can reach.** Authority flows down the hierarchy:
a SUBTREE-scoped role, deny or delegation at a tenant also decides who
administers its descendants. So a change at a tenant is judged against
that tenant and against every descendant in which one of the *affected
users* -- the member losing a role, the holders of the role losing a
permission, the denied user, the delegate, the suspended member -- is an
ACTIVE member. No other descendant can lose an administrator through it:
an administrator is a member, and nobody else's authority changed.

A tenant move and a tenant ceasing to admit its principals (suspension,
closure) change authority for whole subtrees with no user to name;
`saas_os.core.tenancy` guards those with `guard_tenants` over the moved
subtree, respectively the descendants.

Guarded: membership suspend and revoke (`saas_os.core.identity`); removing
a role from a member, revoking a permission from a role, creating a deny
grant and revoking a delegation (`saas_os.core.rbac.service`); moving a
tenant and suspending or closing one (`saas_os.core.tenancy`). Deleting a
role needs no guard: the foreign keys already refuse to delete a role
that is assigned or still grants a permission.

**Locks.** One transaction-scoped PostgreSQL advisory lock per tenant,
shared by every guarded mutation. The mutation's own tenant is locked
first, before the caller is authorized; the descendants it reaches are
locked when they are known, nearest first and then by id
(`saas_os.core.tenancy.descendant_ids_by_depth`). Every transaction
therefore takes the locks it shares with another in the same order --
an ancestor before its descendants -- and two guarded mutations cannot
deadlock on them. Without the lock, two transactions could each remove
one of two administrators, each still seeing the other's.

**Not covered** (docs/ADR/0043-...): the operator-only purge and erasure
paths; and a tenant attached beneath a tenant in the same instant that
tenant is suspended. User deactivation is covered since ADR-0045 Phase C:
`saas_os.core.identity.user_authority.deactivate_user` calls
`guard_tenants` for every tenant the user is an active member of.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from saas_os.core.identity import MembershipStatus, TenantMembership
from saas_os.core.identity.errors import LastTenantAdministratorError
from saas_os.core.rbac.authorization import can
from saas_os.core.tenancy import descendant_ids_by_depth
from saas_os.infra.db import Session, acquire_tenant_advisory_lock, bind_tenant_scope, select

ADMINISTRATOR_RESOURCE = "membership_role"
ADMINISTRATOR_ACTION = "create"
ADMINISTRATOR_LOCK = "tenant.administrators"


def is_administrator(session: Session, tenant_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    return can(
        actor_id=user_id,
        tenant_id=tenant_id,
        action=ADMINISTRATOR_ACTION,
        resource=ADMINISTRATOR_RESOURCE,
        session=session,
        ignore_expiring_delegations=True,
    )


def find_administrator(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    try_first: uuid.UUID | None = None,
    excluding: uuid.UUID | None = None,
) -> uuid.UUID | None:
    """The user id of one administrator of `tenant_id`, or `None`.
    `try_first` is checked before anyone else (the administrator a guard
    saw before the mutation is usually still one). `excluding` leaves one
    user out of the search. Works whatever tenant `session` is scoped to."""
    if try_first is not None and try_first != excluding:
        if _is_active_member(session, tenant_id, [try_first]) and is_administrator(
            session, tenant_id, try_first
        ):
            return try_first
    with bind_tenant_scope(session, tenant_id):
        candidates = (
            session.execute(
                select(TenantMembership.user_id)
                .where(
                    TenantMembership.tenant_id == tenant_id,
                    TenantMembership.status == MembershipStatus.ACTIVE.value,
                )
                .order_by(TenantMembership.created_at, TenantMembership.id)
            )
            .scalars()
            .all()
        )
    for user_id in candidates:
        if user_id in (try_first, excluding):
            continue
        if is_administrator(session, tenant_id, user_id):
            return user_id
    return None


def _is_active_member(
    session: Session, tenant_id: uuid.UUID, user_ids: Sequence[uuid.UUID]
) -> bool:
    """Is any of `user_ids` an ACTIVE member of `tenant_id`?"""
    if not user_ids:
        return False
    with bind_tenant_scope(session, tenant_id):
        return (
            session.execute(
                select(TenantMembership.id)
                .where(
                    TenantMembership.tenant_id == tenant_id,
                    TenantMembership.user_id.in_(user_ids),
                    TenantMembership.status == MembershipStatus.ACTIVE.value,
                )
                .limit(1)
            ).first()
            is not None
        )


@dataclass(frozen=True)
class AdministratorGuard:
    """One administrator (or `None`) of each guarded tenant, as it was
    immediately before the mutation."""

    before: tuple[tuple[uuid.UUID, uuid.UUID | None], ...]

    def verify(self, session: Session, *, membership_id: uuid.UUID | None = None) -> None:
        """Call after the mutation's rows are flushed, before commit."""
        for tenant_id, administrator_before in self.before:
            if administrator_before is None:
                continue  # nothing to preserve: this rule never invents an administrator
            if find_administrator(session, tenant_id, try_first=administrator_before):
                continue
            raise LastTenantAdministratorError(tenant_id, membership_id)


def lock_tenant_administrators(session: Session, tenant_id: uuid.UUID) -> None:
    """Serialize every guarded mutation that can reach this tenant. For the
    mutation's own tenant it must be the first statement of the
    transaction -- before the caller is authorized, so a caller whose own
    authority a concurrent mutation just removed is judged against what
    that mutation committed."""
    acquire_tenant_advisory_lock(session, tenant_id, ADMINISTRATOR_LOCK)


def guard_tenants(session: Session, tenant_ids: Sequence[uuid.UUID]) -> AdministratorGuard:
    """Lock each of `tenant_ids` in the order given and record whether it
    has an administrator now. The caller supplies the order -- nearest the
    root first, then by id -- because it is what keeps two guarded
    transactions from deadlocking (module docstring)."""
    for tenant_id in tenant_ids:
        lock_tenant_administrators(session, tenant_id)
    return AdministratorGuard(
        tuple((tenant_id, find_administrator(session, tenant_id)) for tenant_id in tenant_ids)
    )


def guard_last_administrator(
    session: Session, tenant_id: uuid.UUID, *, affected_users: Iterable[uuid.UUID] = ()
) -> AdministratorGuard:
    """Record who administers `tenant_id`, and every descendant of it in
    which one of `affected_users` is an ACTIVE member. Call under
    `lock_tenant_administrators(session, tenant_id)`, immediately before
    the change; the descendants' locks are taken here."""
    users = list(dict.fromkeys(affected_users))
    reached = [
        descendant_id
        for descendant_id in descendant_ids_by_depth(session, tenant_id)
        if _is_active_member(session, descendant_id, users)
    ]
    for descendant_id in reached:
        lock_tenant_administrators(session, descendant_id)
    return AdministratorGuard(
        tuple((guarded, find_administrator(session, guarded)) for guarded in [tenant_id, *reached])
    )
