"""The last-active-platform-owner invariant
(docs/ADR/0045-installation-scoped-platform-authority.md section 6).

*After every supported change, a deployment that had a platform owner
still has one.*

A platform owner is not a role. It is a definition: an operator with
status `active`, whose user is active, holding an unrevoked
`platform.authority:manage` grant.

The mechanism is ADR-0043's, pointed at the platform: one
transaction-scoped advisory lock, taken as the first statement of every
operation that can change who is an owner; authorization after the lock;
and a recheck on the flushed state, which rolls the whole transaction back
if the owner set was emptied.

Lock order, fixed, and the same in every operation: this lock; then any
ADR-0043 tenant-administrator advisory locks; then row locks. No operation
in this package takes a tenant-administrator lock or a hierarchy lock.

This preserves; it does not create. A fresh deployment has no owner until
bootstrap. It does not bind tier-0 access to the database, where a row can
be changed without the lock.
"""

from __future__ import annotations

import uuid

from saas_os.core.identity.models import User
from saas_os.core.platform_authority.models import (
    OperatorStatus,
    PlatformGrant,
    PlatformOperator,
)
from saas_os.core.platform_authority.permissions import OWNER_PERMISSION
from saas_os.infra.db import Session, acquire_tenant_advisory_lock, select

PLATFORM_OWNERS_LOCK = "platform.owners"

# The nil UUID is not a tenant id (`core.tenants.id` is a random UUID4).
# `(nil, PLATFORM_OWNERS_LOCK)` names one advisory lock for the whole
# deployment -- the sentinel form `saas_os.core.tenancy`'s hierarchy lock
# already uses, under a different key, so the two are different locks.
_SENTINEL = uuid.UUID(int=0)


def lock_platform_owners(session: Session) -> None:
    """Serialize this transaction against every other change to platform
    authority. Must be the transaction's first statement -- before the
    caller is authorized -- so that a caller whose own authority a
    concurrent change just removed is judged against what that change
    committed. Released by PostgreSQL at COMMIT or ROLLBACK."""
    acquire_tenant_advisory_lock(session, _SENTINEL, PLATFORM_OWNERS_LOCK)


def platform_owner_exists(session: Session) -> bool:
    """The owner predicate. All three tables are global; this must run
    with no tenant bound (inside a tenant scope the platform tables are
    hidden and it would report `False`)."""
    row = session.execute(
        select(PlatformOperator.id)
        .join(User, User.id == PlatformOperator.user_id)
        .join(PlatformGrant, PlatformGrant.operator_id == PlatformOperator.id)
        .where(
            PlatformOperator.status == OperatorStatus.ACTIVE.value,
            User.is_active.is_(True),
            PlatformGrant.permission == OWNER_PERMISSION.value,
            PlatformGrant.revoked_at.is_(None),
        )
        .limit(1)
    ).first()
    return row is not None


def unrevoked_operator_exists(session: Session, user_id: uuid.UUID) -> bool:
    """`True` if `user_id` has a platform operator row that is not revoked
    -- active or suspended. The enrollment `erase_user_identity` refuses
    (section 6). Call under `lock_platform_owners()`, so an enrollment or
    a revocation either committed first and is observed, or waits.

    `session` must have no tenant bound."""
    return (
        session.execute(
            select(PlatformOperator.id)
            .where(
                PlatformOperator.user_id == user_id,
                PlatformOperator.status != OperatorStatus.REVOKED.value,
            )
            .limit(1)
        ).first()
        is not None
    )
