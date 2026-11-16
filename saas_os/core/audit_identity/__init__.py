"""Audit identity retention, phases P2 and P3c: legal holds on platform and
tenant audit references and the expiry of links and erasure markers
(docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md sections
4.8 to 4.11). Not imported here: the report job
(`saas_os.core.audit_identity.jobs`; registering a job needs `REDIS_URL`)
and the migrations-role expiry command (`saas_os.core.audit_identity.expiry`,
which the runtime may not import). Its `--apply` is disabled (owner decision
O9) until a separate, owner-approved change enables it.
"""

from __future__ import annotations

from saas_os.core.audit_identity.errors import (
    AuditIdentityExpiryConfirmationMismatchError,
    AuditIdentityExpiryDisabledError,
    AuditIdentityHoldAlreadyActiveError,
    AuditIdentityHoldAlreadyReleasedError,
    AuditIdentityHoldNotFoundError,
    AuditIdentityHoldTenantNotFoundError,
    AuditIdentityIndexUnavailableError,
    AuditIdentityRetentionError,
    AuditIdentitySessionEvidenceError,
    InvalidAuditIdentityRequestError,
)
from saas_os.core.audit_identity.holds import (
    AuditIdentityHold,
    AuditIdentityHoldPage,
    AuditIdentityHoldView,
    list_audit_identity_holds,
    place_audit_identity_hold,
    release_audit_identity_hold,
)
from saas_os.core.audit_identity.plan import (
    AuditIdentityExpiryReport,
    audit_identity_expiry_report,
    hold_set_digest,
    reference_set_digest,
)

__all__ = [
    "AuditIdentityExpiryConfirmationMismatchError",
    "AuditIdentityExpiryDisabledError",
    "AuditIdentityExpiryReport",
    "AuditIdentityHold",
    "AuditIdentityHoldAlreadyActiveError",
    "AuditIdentityHoldAlreadyReleasedError",
    "AuditIdentityHoldNotFoundError",
    "AuditIdentityHoldPage",
    "AuditIdentityHoldTenantNotFoundError",
    "AuditIdentityHoldView",
    "AuditIdentityIndexUnavailableError",
    "AuditIdentityRetentionError",
    "AuditIdentitySessionEvidenceError",
    "InvalidAuditIdentityRequestError",
    "audit_identity_expiry_report",
    "hold_set_digest",
    "list_audit_identity_holds",
    "place_audit_identity_hold",
    "reference_set_digest",
    "release_audit_identity_hold",
]
