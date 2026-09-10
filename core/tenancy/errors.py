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
