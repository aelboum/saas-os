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
