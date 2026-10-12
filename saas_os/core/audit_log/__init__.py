"""`saas_os/core/audit_log` -- the platform-wide, append-only, immutable audit
trail (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4; docs/SECURITY.md section
8; docs/DATA-ARCHITECTURE.md section 7).

The physical directory/package name uses an underscore
(`saas_os/core/audit_log/`), not the hyphen `docs/ARCHITECTURE.md` section 3's
diagram uses (`core/audit-log/`) -- a hyphen is not valid inside a Python
dotted import path, the same reason `control-plane/` maps to the
`control_plane` import name (`pyproject.toml`). Every doc citation in this
module's comments still refers to the concept by the documentation's own
`core/audit-log` spelling.

Owns:
- the `AuditLogEntry` entity (`saas_os.core.audit_log`, `saas_os/core/audit_log/models.py`)
  -- tenant-owned, RLS-protected, no `updated_at` column (the schema
  itself signals immutability, not just the absence of an update
  function); carries optional `acting_as_tenant_id`/`delegation_grant_id`/
  `support_access_id` linkage (architecture research Phase F -- "Audit +
  Support Access") -- pure context, never itself an authorization
  decision;
- the `ActorType`/`AuditOutcome` enums;
- the bounded, safe metadata contract (`saas_os/core/audit_log/metadata.py`);
- exactly three operations: `record()`, `get()`, `list()`
  (`saas_os/core/audit_log/service.py`) -- no `update`/`delete`/`purge`/`edit`.

Does NOT own: authentication (saas_os/core/identity), tenant isolation mechanics
(saas_os/infra/db), authorization (saas_os/core/rbac), any HTTP/API surface (Phase 8), or
a general-purpose event bus / message broker -- this is an audit record
store, not an application event system (docs/IMPLEMENTATION-ROADMAP.md
Phase 3.4 section 3).

`saas_os/core/audit_log` never imports sqlalchemy directly (pyproject.toml's
"Only saas_os/infra/db may import SQLAlchemy or psycopg directly" contract) and
never imports `saas_os.core.identity`, `saas_os.core.tenancy`, or `saas_os.core.rbac` -- the
write path (`record()`) depends only on `saas_os/infra/db` (persistence) and
`saas_os/infra/observability` (optional correlation-id default), so it remains
usable even when another module's own dependency chain is unavailable or
failing (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 6).
"""

from saas_os.core.audit_log.errors import (
    AuditLogEntryNotFoundError,
    ForbiddenMetadataKeyError,
    InvalidActionOrResourceError,
    InvalidActorError,
    InvalidAuditRecordError,
    InvalidOutcomeError,
    MetadataNotJSONSerializableError,
    MetadataTooLargeError,
)
from saas_os.core.audit_log.models import ActorType, AuditLogEntry, AuditOutcome
from saas_os.core.audit_log.service import (
    get,
    list,
    record,
    record_in_transaction,
    referenced_delegation_grant_ids,
    referenced_service_account_ids,
)

__all__ = [
    "referenced_delegation_grant_ids",
    "referenced_service_account_ids",
    "AuditLogEntry",
    "ActorType",
    "AuditOutcome",
    "record",
    "record_in_transaction",
    "get",
    "list",
    "InvalidAuditRecordError",
    "InvalidActorError",
    "InvalidOutcomeError",
    "InvalidActionOrResourceError",
    "MetadataNotJSONSerializableError",
    "MetadataTooLargeError",
    "ForbiddenMetadataKeyError",
    "AuditLogEntryNotFoundError",
]
