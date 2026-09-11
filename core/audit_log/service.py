"""The append-only audit-log write/read interface
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.4).

Exactly three operations: `record()`, `get()`, `list()`
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 7: "Prefer operations
equivalent to record(...), get(...), list(...) only where actually
required"). No `update()`, `delete()`, `purge()`, or `edit()` exists
anywhere in this module -- an audit record, once written, cannot be
changed or removed through this service's published interface.

This is defense in *addition* to, not instead of, the database-level
guarantee: the Phase 3.4 migration `REVOKE`s `UPDATE`/`DELETE` on
`core.audit_log` from the restricted runtime role entirely
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.4's Security Requirement: "verify
no code path can mutate or delete an existing entry, including via direct
database access"). Even a bug that somehow called `session.execute(text("UPDATE
core.audit_log ..."))` directly would fail at the database with a
permission error, not merely be absent from this module's API surface.

Every function here uses `infra.db.tenant_session_scope()`, the restricted
`saas_os_app` runtime role -- never the privileged migrations role, never
a second tenant-context mechanism.

`record()` deliberately does not catch or suppress a write failure: an
audit write that raises propagates the exception to its caller unchanged
(docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 19: "Audit logging must
never turn an authorization/security decision into a fail-open result...
Do not invent fail-open semantics"). No authoritative document defines a
specific alternate failure behavior for this phase, so the only safe
default is the same one every other write in this codebase already
follows: let it raise.
"""

from __future__ import annotations

import builtins
import uuid
from datetime import datetime

from core.audit_log.errors import (
    AuditLogEntryNotFoundError,
    InvalidActionOrResourceError,
    InvalidActorError,
    InvalidOutcomeError,
)
from core.audit_log.metadata import validate_metadata
from core.audit_log.models import ActorType, AuditLogEntry, AuditOutcome
from infra.db import select, tenant_session_scope
from infra.observability import get_correlation_context

_MAX_ACTION_LENGTH = 200
_MAX_RESOURCE_TYPE_LENGTH = 100
_MAX_RESOURCE_ID_LENGTH = 255


def _validate_action_and_resource(action: str, resource_type: str, resource_id: str | None) -> None:
    if not action or not action.strip():
        raise InvalidActionOrResourceError("action must be a non-empty string.")
    if len(action) > _MAX_ACTION_LENGTH:
        raise InvalidActionOrResourceError(f"action exceeds {_MAX_ACTION_LENGTH} characters.")
    if not resource_type or not resource_type.strip():
        raise InvalidActionOrResourceError("resource_type must be a non-empty string.")
    if len(resource_type) > _MAX_RESOURCE_TYPE_LENGTH:
        raise InvalidActionOrResourceError(
            f"resource_type exceeds {_MAX_RESOURCE_TYPE_LENGTH} characters."
        )
    if resource_id is not None and len(resource_id) > _MAX_RESOURCE_ID_LENGTH:
        raise InvalidActionOrResourceError(
            f"resource_id exceeds {_MAX_RESOURCE_ID_LENGTH} characters."
        )


def record(
    *,
    tenant_id: uuid.UUID,
    actor_type: ActorType,
    action: str,
    resource_type: str,
    outcome: AuditOutcome,
    actor_user_id: uuid.UUID | None = None,
    resource_id: str | None = None,
    correlation_id: str | None = None,
    metadata: dict[str, object] | None = None,
    acting_as_tenant_id: uuid.UUID | None = None,
    delegation_grant_id: uuid.UUID | None = None,
    support_access_id: uuid.UUID | None = None,
) -> AuditLogEntry:
    """Append one immutable audit record for `tenant_id`. Fails closed:
    every argument is validated *before* any database write is attempted
    -- an invalid call never produces a partially-written or malformed
    entry (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 8: "The audit
    API should fail closed when supplied metadata violates its contract").

    `actor_type=ActorType.USER` requires `actor_user_id`;
    `actor_type=ActorType.SYSTEM` requires it be omitted -- also enforced
    at the database level (`ck_audit_log_actor_type_user_id_pairing`), so
    this check exists to fail with a clear, typed error before ever
    reaching the database, not because the database check is insufficient.

    `correlation_id` defaults to the ambient
    `infra.observability.get_correlation_context().request_id` when not
    given explicitly -- callers that already have a more specific
    correlation value may pass it directly; callers with no active
    correlation context (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section
    9: "The audit record must remain useful even when no active tracing
    context exists") simply get `None`, same as an explicit omission.

    `acting_as_tenant_id`/`delegation_grant_id`/`support_access_id`
    (architecture research Phase F) are pure linkage/context -- all three
    default to `None`, matching every pre-Phase-F call site exactly, and
    none of the three is validated against `core.rbac`'s own tables here
    (`core/audit_log/models.py`'s own docstring: this module still depends
    on nothing but `infra/db`/`infra/observability`). At most one of
    `delegation_grant_id`/`support_access_id` may be set -- also enforced
    at the database level (`ck_audit_log_single_authorization_linkage`) --
    so this fails closed with a clear, typed error first, for the
    identical reason the actor-pairing check above does.
    """
    if actor_type is ActorType.USER and actor_user_id is None:
        raise InvalidActorError("actor_user_id is required when actor_type is ActorType.USER.")
    if actor_type is ActorType.SYSTEM and actor_user_id is not None:
        raise InvalidActorError(
            "actor_user_id must not be set when actor_type is ActorType.SYSTEM."
        )

    if delegation_grant_id is not None and support_access_id is not None:
        raise InvalidActorError(
            "delegation_grant_id and support_access_id must not both be set -- "
            "an action has exactly one authorization story."
        )

    if outcome not in AuditOutcome:
        raise InvalidOutcomeError(str(outcome))

    _validate_action_and_resource(action, resource_type, resource_id)
    validate_metadata(metadata)

    if correlation_id is None:
        correlation_id = get_correlation_context().request_id

    with tenant_session_scope(tenant_id) as session:
        entry = AuditLogEntry(
            tenant_id=tenant_id,
            actor_type=actor_type.value,
            actor_user_id=actor_user_id,
            acting_as_tenant_id=acting_as_tenant_id,
            delegation_grant_id=delegation_grant_id,
            support_access_id=support_access_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome.value,
            correlation_id=correlation_id,
            entry_metadata=metadata,
        )
        session.add(entry)
        session.flush()
        session.refresh(entry)
        session.expunge(entry)
        return entry


def get(tenant_id: uuid.UUID, entry_id: uuid.UUID) -> AuditLogEntry:
    with tenant_session_scope(tenant_id) as session:
        entry = session.get(AuditLogEntry, entry_id)
        if entry is None or entry.tenant_id != tenant_id:
            raise AuditLogEntryNotFoundError(tenant_id, entry_id)
        session.expunge(entry)
        return entry


def list(  # noqa: A001 -- matches the roadmap's own `list(...)` naming (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section 7); return type below uses `builtins.list` since this name shadows the builtin.
    tenant_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
) -> builtins.list[AuditLogEntry]:
    """List `tenant_id`'s audit entries, most recent first, optionally
    filtered by actor, resource, and/or a time range -- the exact query
    shape docs/SECURITY.md section 8 requires ("queryable by tenant,
    actor, and time range"). `limit` is required (defaulted, not
    optional) so a caller cannot accidentally request an unbounded result
    set from an append-only, ever-growing table.
    """
    if limit <= 0 or limit > 1000:
        raise InvalidActionOrResourceError("limit must be between 1 and 1000.")

    query = select(AuditLogEntry).where(AuditLogEntry.tenant_id == tenant_id)
    if actor_user_id is not None:
        query = query.where(AuditLogEntry.actor_user_id == actor_user_id)
    if resource_type is not None:
        query = query.where(AuditLogEntry.resource_type == resource_type)
    if resource_id is not None:
        query = query.where(AuditLogEntry.resource_id == resource_id)
    if since is not None:
        query = query.where(AuditLogEntry.created_at >= since)
    if until is not None:
        query = query.where(AuditLogEntry.created_at <= until)
    query = query.order_by(AuditLogEntry.created_at.desc()).limit(limit)

    with tenant_session_scope(tenant_id) as session:
        entries = session.execute(query).scalars().all()
        for entry in entries:
            session.expunge(entry)
        return [entry for entry in entries]  # noqa: C416 -- `list(entries)` would recurse into this function, which shadows the builtin by design
