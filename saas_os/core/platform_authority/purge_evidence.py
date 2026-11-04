"""Read-only access to a tenant's purge evidence in `core.platform_audit_log`
(owner policy of 2026-11-02: the permission grant ledger's retention).

The platform models are touched only inside this package (ADR-0045), so
`saas_os.core.permission_grants.retention` reads the purge time through
this function. It reads rows and nothing else: no operation, no
authorization decision, no write. The table carries the tenant-context
exclusion policy, so `session` must have no tenant bound.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from saas_os.core.platform_authority.models import PlatformAuditLogEntry, PlatformAuditOutcome
from saas_os.core.platform_authority.operations import PLATFORM_OPERATIONS, TENANT_PURGE_TRANSITION
from saas_os.infra.db import Session, select

# The `system_authority` the purge transition's platform row records:
# `SystemAuthority.TENANT_PURGE.value` (asserted by the unit tests). A
# literal, so this module does not import the authority purposes.
TENANT_PURGE_AUTHORITY = "tenant_purge"
_PURGED = "purged"


def tenant_purge_completion_times(session: Session, tenant_id: uuid.UUID) -> list[datetime]:
    """`created_at` of every `success` platform row of `tenant_id`'s
    `PURGING -> PURGED` transition (action `platform.tenant.purge_transition`,
    metadata `to_status = purged`, actor `SystemCaller(TENANT_PURGE)`),
    which `transition_tenant_status()` writes in the same transaction as the
    status change. `DELETED -> PURGING` shares the action; its `to_status`
    differs. Read in `session`'s transaction; never more than the rows of
    that one tenant."""
    rows = session.execute(
        select(PlatformAuditLogEntry.created_at, PlatformAuditLogEntry.entry_metadata).where(
            PlatformAuditLogEntry.action
            == PLATFORM_OPERATIONS[TENANT_PURGE_TRANSITION].audit_action,
            PlatformAuditLogEntry.target_tenant_id == tenant_id,
            PlatformAuditLogEntry.outcome == PlatformAuditOutcome.SUCCESS.value,
            PlatformAuditLogEntry.system_authority == TENANT_PURGE_AUTHORITY,
        )
    ).all()
    return [
        row.created_at
        for row in rows
        if isinstance(row.entry_metadata, dict) and row.entry_metadata.get("to_status") == _PURGED
    ]
