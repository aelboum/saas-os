"""Typed errors for `core/tenancy` (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1)."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.tenancy.lifecycle import TenantStatus


class TenantNotFoundError(LookupError):
    def __init__(self, tenant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        super().__init__(f"Tenant {tenant_id} not found.")


class InvalidTenantTransitionError(ValueError):
    def __init__(self, current_status: TenantStatus, target_status: TenantStatus) -> None:
        self.current_status = current_status
        self.target_status = target_status
        super().__init__(
            f"Cannot transition tenant from {current_status.value!r} to {target_status.value!r}."
        )


class TenantClosedError(ValueError):
    """Raised when a *new* tenant-owned mutation (a new row, or an
    authority-expanding change) is attempted against a tenant whose
    lifecycle is closed -- `DELETED`, `PURGING`, or `PURGED`
    (`core.tenancy.lifecycle.CLOSED_STATUSES`; PRIV-03 Phase P2). Fails
    closed before any row is written: `core/tenancy/service.py::
    require_open_tenant()` is the guard every Core mutation entry point
    calls. Authority-*reducing* operations (revoke/disable/suspend/remove)
    deliberately never raise this, so a closed tenant can still be wound
    down."""

    def __init__(self, tenant_id: uuid.UUID, status: TenantStatus) -> None:
        self.tenant_id = tenant_id
        self.status = status
        super().__init__(
            f"Tenant {tenant_id} is {status.value!r} and no longer accepts new "
            "tenant-owned mutations."
        )


class TenantNotPurgingError(ValueError):
    """Raised by a module-owned purge operation (`purge_tenant_*()` in
    `core/identity`, `core/rbac`, `core/api_keys`, ...) when called for a
    tenant that is not in the purge phase of its lifecycle (`PURGING`, or
    the terminal `PURGED` where every step is a no-op) -- PRIV-03 Phase P3.
    The per-module purge operations are destructive by design and must
    never run against an open or merely soft-deleted tenant; the
    orchestrator (`core/tenancy/service.py::purge_tenant()`) is the only
    thing that moves a tenant into `PURGING` first."""

    def __init__(self, tenant_id: uuid.UUID, status: TenantStatus) -> None:
        self.tenant_id = tenant_id
        self.status = status
        super().__init__(
            f"Tenant {tenant_id} is {status.value!r}; purge operations require 'purging'."
        )


class TenantHasDescendantsError(ValueError):
    """Raised by `purge_tenant()` when the target tenant still has at
    least one child (`Tenant.parent_id` pointing at it). Purge operates on
    exactly one tenant and never recurses into, reparents, or otherwise
    touches descendants (approved PRIV-03 hierarchy rule) -- so it fails
    closed and names the blocking children instead. Purge or reparent
    every child first, each as its own separately-authorized operation."""

    def __init__(self, tenant_id: uuid.UUID, descendant_ids: frozenset[uuid.UUID]) -> None:
        self.tenant_id = tenant_id
        self.descendant_ids = descendant_ids
        listed = ", ".join(sorted(str(d) for d in descendant_ids))
        super().__init__(f"Tenant {tenant_id} cannot be purged while it has descendants: {listed}.")


class TenantPurgeIncompleteError(RuntimeError):
    """Raised by `purge_tenant()` when, after the maximum number of
    deterministic purge passes, tenant-owned operational rows still remain
    -- the final `PURGED` transition is refused rather than recorded over
    live data. The tenant stays `PURGING`; a retry is safe (every step is
    idempotent). `remaining` names each step that still found rows."""

    def __init__(self, tenant_id: uuid.UUID, remaining: dict[str, int]) -> None:
        self.tenant_id = tenant_id
        self.remaining = dict(remaining)
        super().__init__(
            f"Tenant {tenant_id} purge incomplete; rows remain after the final pass: "
            f"{self.remaining}."
        )


class TenantCycleError(ValueError):
    """Raised when creating or moving a tenant would make it its own
    ancestor -- either directly (`parent_id == id`, also a DB-level CHECK
    constraint, `ck_tenants_parent_not_self`) or transitively (moving a
    tenant beneath one of its own descendants). Fails closed: the move is
    rejected before any row is written, never partially applied."""

    def __init__(self, tenant_id: uuid.UUID, new_parent_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.new_parent_id = new_parent_id
        super().__init__(
            f"Cannot move tenant {tenant_id} beneath {new_parent_id}: "
            f"{new_parent_id} is {tenant_id} itself or one of its own descendants."
        )


class TenantHierarchyDepthExceededError(ValueError):
    """Raised when creating or moving a tenant would place it deeper than
    `core.tenancy.config.TenancyConfig.max_hierarchy_depth` -- an
    operational guardrail, not an architectural limit (the data model
    itself supports arbitrary depth)."""

    def __init__(self, tenant_id: uuid.UUID, resulting_depth: int, max_depth: int) -> None:
        self.tenant_id = tenant_id
        self.resulting_depth = resulting_depth
        self.max_depth = max_depth
        super().__init__(
            f"Placing tenant {tenant_id} at depth {resulting_depth} exceeds the configured "
            f"maximum hierarchy depth of {max_depth} (TENANT_MAX_HIERARCHY_DEPTH)."
        )


class TenancyConfigurationError(ValueError):
    """Raised when a `core/tenancy` environment variable holds an invalid
    value. Never carries a secret -- the hierarchy depth guardrail is a
    plain non-secret tunable."""
