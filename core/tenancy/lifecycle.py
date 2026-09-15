"""Tenant lifecycle states (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1,
docs/MULTI-TENANCY.md section 6: "pending -> active -> suspended -> deleted
(soft, retaining audit trail) -> purged (hard delete, compliance-driven,
rare)" -- directional, and explicitly left "to be finalized when
core/tenancy is built"; this module is that finalization).

Transitions are validated against an explicit allowed-transition table --
not any state to any other -- so a lifecycle change can never skip a step
(e.g. `pending` straight to `purged`) or move backward from a terminal
state. This is what "lifecycle transitions are explicit and cannot produce
unauthorized tenant access" (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1)
means at this layer: the state machine itself rejects anything not on the
approved graph, at the point of transition, not by convention.

**Purge lifecycle (PRIV-03 Phase P2 -- approved tombstone-based tenant
erasure architecture).** `PURGING` sits between `DELETED` and `PURGED`:
a tenant must be soft-deleted first, then explicitly enter `PURGING`
(the state under which a later phase's purge orchestration runs and
which fences every new tenant-owned mutation -- `CLOSED_STATUSES` /
`is_closed()` below), and only then reach the terminal `PURGED`. `PURGED`
no longer means "the row is gone": it is the permanent, minimal
*tombstone* state the `core.tenants` row itself keeps forever, so every
retained record that references it (`core.audit_log`,
`core.billing_subscriptions`, `core.support_access_requests`, ...) stays
structurally valid after erasure. The tombstone *minimization* (nulling
`name`, etc.) and the orchestration that empties the tenant's own data
are later phases -- this module only defines the states and the graph.
"""

from __future__ import annotations

import enum

from core.tenancy.errors import InvalidTenantTransitionError


class TenantStatus(enum.StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"
    PURGING = "purging"
    PURGED = "purged"


# PENDING: newly created, not yet usable.
# ACTIVE: normal operating state.
# SUSPENDED: temporarily disabled (reversible), e.g. billing hold.
# DELETED: soft-deleted, retains audit trail (docs/MULTI-TENANCY.md section 6).
#          Closed to new tenant-owned mutations (`is_closed()`); the only
#          way forward is PURGING.
# PURGING: purge in progress (PRIV-03 P2). Closed to new tenant-owned
#          mutations -- this state *is* the lifecycle fence a later phase's
#          purge orchestration relies on: nothing new can be written into a
#          tenant while its data is being wound down. Cannot go back to
#          ACTIVE/SUSPENDED/DELETED; the only way forward is PURGED.
# PURGED:  terminal -- the permanent, minimal tombstone. The `core.tenants`
#          row is retained forever (never hard-deleted) so every retained
#          audit/billing/support record referencing it remains valid. No
#          outgoing transitions, ever.
_ALLOWED_TRANSITIONS: dict[TenantStatus, frozenset[TenantStatus]] = {
    TenantStatus.PENDING: frozenset({TenantStatus.ACTIVE, TenantStatus.DELETED}),
    TenantStatus.ACTIVE: frozenset({TenantStatus.SUSPENDED, TenantStatus.DELETED}),
    TenantStatus.SUSPENDED: frozenset({TenantStatus.ACTIVE, TenantStatus.DELETED}),
    TenantStatus.DELETED: frozenset({TenantStatus.PURGING}),
    TenantStatus.PURGING: frozenset({TenantStatus.PURGED}),
    TenantStatus.PURGED: frozenset(),
}

# The statuses in which a tenant is *closed*: no new tenant-owned row may
# be created and no authority-expanding change may be made
# (`core/tenancy/service.py::require_open_tenant()` is the guard every
# Core mutation entry point calls). Deliberately spelled out as the closed
# set rather than derived as "not PURGED" -- DELETED and PURGING are just
# as closed as PURGED; only PENDING/ACTIVE/SUSPENDED accept new mutations.
# Authority-*reducing* operations on rows that already exist (revoke,
# disable, suspend, remove, cancel, unsubscribe) are deliberately NOT
# fenced, so a closed tenant can still be wound down.
CLOSED_STATUSES: frozenset[TenantStatus] = frozenset(
    {TenantStatus.DELETED, TenantStatus.PURGING, TenantStatus.PURGED}
)


def validate_transition(current: TenantStatus, target: TenantStatus) -> None:
    if target not in _ALLOWED_TRANSITIONS[current]:
        raise InvalidTenantTransitionError(current, target)


def is_closed(status: TenantStatus) -> bool:
    """`True` when `status` is one of `CLOSED_STATUSES` -- the tenant no
    longer accepts new tenant-owned mutations."""
    return status in CLOSED_STATUSES


# The statuses in which the tenant's *own principals* -- members, service
# accounts, API-key holders, delegates -- may not obtain authorization for
# it at all (PRIV-03 Phase P8, privacy re-audit finding RA-04, approved
# policy): every closed status plus SUSPENDED ("temporarily disabled"). A
# distinct, wider set than `CLOSED_STATUSES` on purpose: SUSPENDED stays
# *open* for mutations by platform, purge and support operations, which
# authorize separately (`require_open_tenant()`/`lock_open_tenant()`
# keep treating it as open), but is inaccessible to tenant principals.
# Only PENDING and ACTIVE admit tenant principals.
PRINCIPAL_INACCESSIBLE_STATUSES: frozenset[TenantStatus] = CLOSED_STATUSES | frozenset(
    {TenantStatus.SUSPENDED}
)


def is_accessible_to_principals(status: TenantStatus) -> bool:
    """`True` when a tenant in `status` may still be accessed by its own
    principals (`core/rbac/authorization.py::can()`,
    `core/api_keys/service.py::validate_api_key()`,
    `api/dependencies.py::get_tenant_context()`); `False` for every
    `PRINCIPAL_INACCESSIBLE_STATUSES` member."""
    return status not in PRINCIPAL_INACCESSIBLE_STATUSES
