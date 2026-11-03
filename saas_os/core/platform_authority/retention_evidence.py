"""Read-only evidence the permission grant ledger's approval mechanism needs
from platform and identity storage (owner decisions of 2026-11-02 and
2026-11-03; `docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`).

The platform models are touched only inside this package (ADR-0045), so
`saas_os.core.permission_grants` reads through these functions: who wrote
an audit row and with which session evidence, whether a hold release was
authenticated, whether two operators are linked by enrolment or grant
provenance, whether a user holds a platform permission on any operator that
is not revoked, and the platform-admin session a request presented. They
read rows and nothing else: no operation, no authorization decision, no
write. The platform tables carry the tenant-context exclusion policy, so
`session` must have no tenant bound.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from saas_os.core.identity.models import Session as IdentitySession
from saas_os.core.platform_authority.models import (
    OperatorStatus,
    PlatformActorType,
    PlatformAuditLogEntry,
    PlatformGrant,
    PlatformOperator,
)
from saas_os.core.platform_authority.permissions import PlatformPermission
from saas_os.infra.db import Session, select
from saas_os.infra.db import now as db_now

# The channel label a platform-admin HTTP act records in its audit metadata,
# together with the `session_id` it presented and `session_verified: true`.
PLATFORM_HTTP_CHANNEL = "platform_http"


@dataclass(frozen=True)
class PlatformSessionEvidence:
    """What the platform-admin route hands Core about the request: the id of
    the SaaS OS session the HTTP chain validated, and whether the deployment
    requires a multi-factor login for every operator session
    (`PLATFORM_OPERATOR_REQUIRE_MFA`, ADR-0049). Core does not trust it: it
    reads the session row and checks that it is the caller's, live and, where
    required, multi-factor. Constructed only by the platform-admin router
    (`tests/architecture/test_retention_api_boundary.py`)."""

    session_id: uuid.UUID
    multi_factor_required: bool


@dataclass(frozen=True)
class PlatformSessionRecord:
    """A `core.sessions` row as Core needs it, with `live` and `age_seconds`
    decided by the database clock."""

    session_id: uuid.UUID
    user_id: uuid.UUID
    created_at: datetime
    age_seconds: int
    live: bool
    multi_factor: bool


def platform_session_record(
    session: Session, session_id: uuid.UUID
) -> PlatformSessionRecord | None:
    """The session row `session_id`, or `None` when none exists."""
    row = session.execute(
        select(
            IdentitySession.user_id,
            IdentitySession.created_at,
            IdentitySession.expires_at,
            IdentitySession.revoked_at,
            IdentitySession.multi_factor,
            db_now(),
        ).where(IdentitySession.id == session_id)
    ).one_or_none()
    if row is None:
        return None
    user_id, created_at, expires_at, revoked_at, multi_factor, at = row
    return PlatformSessionRecord(
        session_id=session_id,
        user_id=user_id,
        created_at=created_at,
        age_seconds=max(0, int((at - created_at).total_seconds())),
        live=revoked_at is None and expires_at > at,
        multi_factor=multi_factor is True,
    )


@dataclass(frozen=True)
class AuditActRecord:
    """The fields of one platform audit row that identify an act."""

    id: uuid.UUID
    actor_type: str
    actor_user_id: uuid.UUID | None
    action: str
    outcome: str
    reason: str | None
    metadata: Mapping[str, Any]

    @property
    def authenticated_http_act(self) -> bool:
        """A person's act through the platform-admin HTTP chain whose
        session Core verified in the act's own transaction: the evidence a
        hold release needs to count as authenticated. A holder of the
        application credential can write such a row directly (threat T6)."""
        session_id = self.metadata.get("session_id")
        if not isinstance(session_id, str):
            return False
        try:
            uuid.UUID(session_id)
        except ValueError:
            return False
        return (
            self.actor_type == PlatformActorType.USER.value
            and self.actor_user_id is not None
            and self.metadata.get("channel") == PLATFORM_HTTP_CHANNEL
            and self.metadata.get("session_verified") is True
        )


def platform_audit_acts(
    session: Session, entry_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, AuditActRecord]:
    """The platform audit rows with these ids, by id; a missing id is absent."""
    ids = sorted(set(entry_ids))
    if not ids:
        return {}
    rows = session.execute(
        select(
            PlatformAuditLogEntry.id,
            PlatformAuditLogEntry.actor_type,
            PlatformAuditLogEntry.actor_user_id,
            PlatformAuditLogEntry.action,
            PlatformAuditLogEntry.outcome,
            PlatformAuditLogEntry.reason,
            PlatformAuditLogEntry.entry_metadata,
        ).where(PlatformAuditLogEntry.id.in_(ids))
    ).all()
    return {
        row.id: AuditActRecord(
            id=row.id,
            actor_type=row.actor_type,
            actor_user_id=row.actor_user_id,
            action=row.action,
            outcome=row.outcome,
            reason=row.reason,
            metadata=row.entry_metadata if isinstance(row.entry_metadata, dict) else {},
        )
        for row in rows
    }


def holds_platform_permission(
    session: Session, user_id: uuid.UUID, permission: PlatformPermission
) -> bool:
    """Whether `user_id` has an operator that is not revoked (active **or
    suspended**) holding an unrevoked grant of `permission`. Wider than
    `platform_can` on purpose: the register refuses a subject who could
    regain the permission by a mere reactivation. Not an authorization."""
    return (
        session.execute(
            select(PlatformGrant.id)
            .join(PlatformOperator, PlatformOperator.id == PlatformGrant.operator_id)
            .where(
                PlatformOperator.user_id == user_id,
                PlatformOperator.status != OperatorStatus.REVOKED.value,
                PlatformGrant.permission == permission.value,
                PlatformGrant.revoked_at.is_(None),
            )
            .limit(1)
        ).first()
        is not None
    )


def provenance_linked(session: Session, first: uuid.UUID, second: uuid.UUID) -> bool:
    """Whether either user enrolled the other's operator
    (`enrolled_by_user_id`) or granted the other the retention report
    permission (`granted_by_user_id`), revoked rows included. `NULL`
    provenance (bootstrap, break-glass) links nobody. Defence in depth
    only: the approver eligibility register, not this, decides
    eligibility."""
    for a, b in ((first, second), (second, first)):
        enrolled = session.execute(
            select(PlatformOperator.id)
            .where(PlatformOperator.user_id == b, PlatformOperator.enrolled_by_user_id == a)
            .limit(1)
        ).first()
        if enrolled is not None:
            return True
        granted = session.execute(
            select(PlatformGrant.id)
            .join(PlatformOperator, PlatformOperator.id == PlatformGrant.operator_id)
            .where(
                PlatformOperator.user_id == b,
                PlatformGrant.permission == PlatformPermission.SECURITY_RETENTION_REPORT.value,
                PlatformGrant.granted_by_user_id == a,
            )
            .limit(1)
        ).first()
        if granted is not None:
            return True
    return False
