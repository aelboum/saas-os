"""Derived (never-stored) status for a `SupportAccessRequest` (architecture
research: universal multi-tenant tenancy, Phase F -- "Audit + Support
Access"). Mirrors `core/tenancy/lifecycle.py::TenantStatus`'s own shape --
a plain `enum.StrEnum` -- but, unlike `TenantStatus`, is never itself a
database column: `core/rbac/models.py::SupportAccessRequest`'s own
docstring explains why ("no stored status enum that could drift from the
timestamps that are its real source of truth" -- the same discipline
`core/api_keys/models.py::ApiKey` already applies to expiry/revocation).

`compute_support_access_status()` is a pure, read-only projection of a
request's timestamps -- used for display/reporting/tests, never consulted
by `core/rbac/authorization.py::can()` itself (which queries the
timestamps directly, in SQL, for the one candidate tenant it is currently
evaluating -- see that module's own `_tenant_grants_support_access()`).
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from core.rbac.models import SupportAccessRequest


class SupportAccessStatus(enum.StrEnum):
    REQUESTED = "requested"
    APPROVED = "approved"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    DENIED = "denied"


def compute_support_access_status(
    request: SupportAccessRequest, *, now: datetime | None = None
) -> SupportAccessStatus:
    """Project `request`'s timestamps onto the conceptual lifecycle
    REQUESTED -> APPROVED -> ACTIVE -> EXPIRED/REVOKED/DENIED
    (`SupportAccessRequest`'s own docstring spells out the exact mapping).
    `now` defaults to the current time; tests may pass an explicit value.
    """
    resolved_now = now if now is not None else datetime.now(UTC)

    if request.revoked_at is not None:
        return SupportAccessStatus.REVOKED
    if request.denied_at is not None:
        return SupportAccessStatus.DENIED
    if request.approved_at is None:
        return SupportAccessStatus.REQUESTED
    if request.requested_expires_at <= resolved_now:
        return SupportAccessStatus.EXPIRED
    if request.requested_starts_at <= resolved_now:
        return SupportAccessStatus.ACTIVE
    return SupportAccessStatus.APPROVED
