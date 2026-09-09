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
"""

from __future__ import annotations

import enum

from core.tenancy.errors import InvalidTenantTransitionError


class TenantStatus(enum.StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"
    PURGED = "purged"


# PENDING: newly created, not yet usable.
# ACTIVE: normal operating state.
# SUSPENDED: temporarily disabled (reversible), e.g. billing hold.
# DELETED: soft-deleted, retains audit trail (docs/MULTI-TENANCY.md section 6).
# PURGED: terminal -- the row itself is hard-deleted by `purge_tenant()`,
#         never re-enters this table, so it has no outgoing transitions.
_ALLOWED_TRANSITIONS: dict[TenantStatus, frozenset[TenantStatus]] = {
    TenantStatus.PENDING: frozenset({TenantStatus.ACTIVE, TenantStatus.DELETED}),
    TenantStatus.ACTIVE: frozenset({TenantStatus.SUSPENDED, TenantStatus.DELETED}),
    TenantStatus.SUSPENDED: frozenset({TenantStatus.ACTIVE, TenantStatus.DELETED}),
    TenantStatus.DELETED: frozenset({TenantStatus.PURGED}),
    TenantStatus.PURGED: frozenset(),
}


def validate_transition(current: TenantStatus, target: TenantStatus) -> None:
    if target not in _ALLOWED_TRANSITIONS[current]:
        raise InvalidTenantTransitionError(current, target)
