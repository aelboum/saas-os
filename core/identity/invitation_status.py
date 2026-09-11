"""Derived (never-stored) status for an `Invitation` (architecture
research: universal multi-tenant tenancy, Phase G -- "Invitation /
Membership Lifecycle"). Mirrors `core/rbac/support_status.py`'s own shape
exactly -- a plain `enum.StrEnum`, never itself a database column:
`core/identity/models.py::Invitation`'s own docstring explains why ("no
separate status column that could drift from the timestamps that are its
real source of truth").

`compute_invitation_status()` is a pure, read-only projection of an
invitation's timestamps -- used for display/reporting/tests, never
consulted by `accept_invitation()` itself (which re-checks the timestamps
directly, under a row lock, at acceptance time -- see
`core/identity/service.py`).
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from core.identity.models import Invitation


class InvitationStatus(enum.StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


def compute_invitation_status(
    invitation: Invitation, *, now: datetime | None = None
) -> InvitationStatus:
    """Project `invitation`'s timestamps onto the conceptual lifecycle
    PENDING -> ACCEPTED / EXPIRED / REVOKED (`Invitation`'s own docstring
    spells out the exact mapping). `now` defaults to the current time;
    tests may pass an explicit value."""
    resolved_now = now if now is not None else datetime.now(UTC)

    if invitation.revoked_at is not None:
        return InvitationStatus.REVOKED
    if invitation.accepted_at is not None:
        return InvitationStatus.ACCEPTED
    if invitation.expires_at <= resolved_now:
        return InvitationStatus.EXPIRED
    return InvitationStatus.PENDING
