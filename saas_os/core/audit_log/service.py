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

Every function here uses `saas_os.infra.db.tenant_session_scope()`, the restricted
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
import logging
import re
import sys
import uuid
import warnings
from datetime import datetime

from saas_os.core.audit_log.errors import (
    AuditLogEntryNotFoundError,
    InvalidActionOrResourceError,
    InvalidActorError,
    InvalidOutcomeError,
    ReservedMetadataKeyError,
)
from saas_os.core.audit_log.metadata import validate_metadata
from saas_os.core.audit_log.models import ActorType, AuditLogEntry, AuditOutcome
from saas_os.core.authority import (
    INITIATOR_UNAVAILABLE,
    Caller,
    Initiator,
    InitiatorType,
    ServiceAccountCaller,
    SystemActor,
    SystemCaller,
    SystemCorrelation,
    UserCaller,
    require_caller,
)
from saas_os.infra.db import Session, select, tenant_session_scope
from saas_os.infra.observability import get_correlation_context

# PostgreSQL cannot store a NUL in `text`: an action, resource or correlation
# id with a control character is refused as invalid input before the write,
# never as a raw `DataError` from it (2026-10-29 NUL sweep).
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_MAX_ACTION_LENGTH = 200
_MAX_RESOURCE_TYPE_LENGTH = 100
_MAX_RESOURCE_ID_LENGTH = 255
# `saas_os.core.audit_log.correlation_id` is `VARCHAR(100)` (migration
# 2e7cb8c64903). PRIV-03 Phase P11 (privacy re-audit RA-07): enforced here
# too, so a correlation id the column cannot hold is caught before the
# database -- never as a `StringDataRightTruncation` escaping from the
# audit write itself and taking the audited security decision's record
# with it. `saas_os/api/middleware.py`'s accepted `X-Request-ID` shape uses the
# same bound; this check is what protects every other caller.
_MAX_CORRELATION_ID_LENGTH = 100

logger = logging.getLogger(__name__)

# ADR 0061: the metadata key under which a validated `SystemActor` is
# recorded. Written only by this module (from a `SystemActor`), so it is
# refused in caller-supplied metadata: attribution cannot be forged through
# `metadata=`.
SYSTEM_ACTOR_METADATA_KEY = "system_actor"
# Owner decision C (2026-11-01): the initiating actor and the correlation
# identity are recorded beside the executing actor, each under its own key,
# and are reserved the same way.
INITIATED_BY_METADATA_KEY = "initiated_by"
CORRELATION_METADATA_KEY = "correlation"
_RESERVED_METADATA_KEYS = frozenset(
    {SYSTEM_ACTOR_METADATA_KEY, INITIATED_BY_METADATA_KEY, CORRELATION_METADATA_KEY}
)
# The key under which a `SystemCaller`'s purpose is recorded (ADR-0031).
_SYSTEM_AUTHORITY_METADATA_KEY = "system_authority"
# `record_system_action_in_transaction()` authorizes nothing, so a row it
# writes must not look as if a `SystemCaller` purpose authorized it: it
# also refuses `system_authority` from its caller. (`record()` keeps
# accepting it -- existing callers record a purpose that way.)
_SYSTEM_ACTION_RESERVED_METADATA_KEYS = _RESERVED_METADATA_KEYS | {_SYSTEM_AUTHORITY_METADATA_KEY}


def _refuse_reserved_metadata(
    metadata: dict[str, object] | None,
    reserved: frozenset[str] = _RESERVED_METADATA_KEYS,
) -> None:
    """Fail closed, before any write, when caller-supplied metadata carries
    a reserved attribution key -- `system_actor`, `initiated_by` or
    `correlation`, or any other key in `reserved` (top level, any case or
    padding)."""
    if not metadata:
        return
    for key in metadata:
        if isinstance(key, str) and key.strip().lower() in reserved:
            raise ReservedMetadataKeyError(key)


def _attribution(
    actor: SystemActor | None,
    initiated_by: Initiator | None,
    correlation: SystemCorrelation | None,
) -> dict[str, object]:
    """The three attribution roles in their fixed shapes (owner decision C):
    `system_actor` -- the executing component (only when known);
    `initiated_by` -- the initiating actor, or exactly `"unavailable"`;
    `correlation` -- the arq job / outbox event / request ids present
    (possibly `{}`). Each argument must be its exact type or `None`."""
    _require_attribution_types(initiated_by, correlation)
    value: dict[str, object] = {}
    if actor is not None:
        value[SYSTEM_ACTOR_METADATA_KEY] = actor.as_metadata()
    value[INITIATED_BY_METADATA_KEY] = (
        INITIATOR_UNAVAILABLE if initiated_by is None else initiated_by.as_metadata()
    )
    value[CORRELATION_METADATA_KEY] = {} if correlation is None else correlation.as_metadata()
    return value


def _require_attribution_types(initiated_by: object, correlation: object) -> None:
    """Fail closed, before any write, on an attribution argument of the
    wrong type -- and, under owner decision D2 (2026-11-02), on a user
    initiator: a new audit record never stores a raw user id under
    `initiated_by`. Service-account and system initiators, and `None`
    (recorded as `"unavailable"`), are accepted. The refusal names no id."""
    if initiated_by is not None and type(initiated_by) is not Initiator:
        raise InvalidActorError(
            f"initiated_by must be an Initiator, got {type(initiated_by).__name__}."
        )
    if isinstance(initiated_by, Initiator) and initiated_by.type is InitiatorType.USER:
        raise InvalidActorError(
            "initiated_by must not be a user initiator: new audit records do not store "
            "a user id as the initiator (owner decision D2). Pass a service-account or "
            "system initiator, or None to record it as unavailable."
        )
    if correlation is not None and type(correlation) is not SystemCorrelation:
        raise InvalidActorError(
            f"correlation must be a SystemCorrelation, got {type(correlation).__name__}."
        )


def _calling_module() -> str:
    """The module that called `record()` -- the only detail the
    unattributed-row warning logs. Frame 0 is this function, 1 the warning
    helper, 2 `record()`, 3 its caller."""
    try:
        return str(sys._getframe(3).f_globals.get("__name__", "<unknown>"))
    except ValueError:
        return "<unknown>"


def _warn_if_unattributed(
    actor_type: ActorType, outcome: AuditOutcome, metadata: dict[str, object] | None
) -> None:
    """ADR 0061 step 1: a successful `system` row written through
    `record()` with neither a `system_authority` purpose nor a
    `system_actor` is still written -- nothing is refused yet -- but it
    emits a `DeprecationWarning` and one log line naming the calling module
    only. A later, separately approved release refuses such rows."""
    if actor_type is not ActorType.SYSTEM or outcome is not AuditOutcome.SUCCESS:
        return
    if metadata and (
        _SYSTEM_AUTHORITY_METADATA_KEY in metadata or SYSTEM_ACTOR_METADATA_KEY in metadata
    ):
        return
    module = _calling_module()
    logger.warning("audit_system_row_unattributed", extra={"calling_module": module})
    warnings.warn(
        "core.audit_log.record() wrote a successful system row with neither a "
        "system_authority purpose nor a system_actor; use "
        "record_system_action_in_transaction() with a SystemActor (ADR 0061). "
        "Such rows will be refused in a later release.",
        DeprecationWarning,
        stacklevel=3,
    )


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
    for field, value in (
        ("action", action),
        ("resource_type", resource_type),
        ("resource_id", resource_id),
    ):
        if value is not None and _CONTROL_CHARACTERS.search(value):
            raise InvalidActionOrResourceError(f"{field} must not contain control characters.")


def record(
    *,
    tenant_id: uuid.UUID,
    actor_type: ActorType,
    action: str,
    resource_type: str,
    outcome: AuditOutcome,
    actor_user_id: uuid.UUID | None = None,
    actor_service_account_id: uuid.UUID | None = None,
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

    `actor_type=ActorType.USER` requires `actor_user_id` (and forbids
    `actor_service_account_id`); `actor_type=ActorType.SYSTEM` requires
    both be omitted; `actor_type=ActorType.SERVICE_ACCOUNT` (Phase
    J-RBAC-02 -- "Service Account Audit Attribution") requires
    `actor_service_account_id` (and forbids `actor_user_id`) -- also
    enforced at the database level (`ck_audit_log_actor_type_user_id_pairing`),
    so this check exists to fail with a clear, typed error before ever
    reaching the database, not because the database check is insufficient.
    A caller resolving a service-account-authenticated action (e.g. a
    service-account-owned API key) must pass the service account's own id
    here -- the API key is only ever the credential, never the actor
    (`saas_os/core/api_keys/service.py`'s own docstring).

    `correlation_id` defaults to the ambient
    `saas_os.infra.observability.get_correlation_context().request_id` when not
    given explicitly -- callers that already have a more specific
    correlation value may pass it directly; callers with no active
    correlation context (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4 section
    9: "The audit record must remain useful even when no active tracing
    context exists") simply get `None`, same as an explicit omission.

    The stored `correlation_id` is at most `_MAX_CORRELATION_ID_LENGTH`
    (100) characters, the column's own width (PRIV-03 P11 / RA-07). An
    *explicit* value longer than that is a caller error and fails closed
    with `InvalidActionOrResourceError` before any write, exactly like an
    over-long `action`. An *ambient* value longer than that is not this
    caller's doing (it was bound by whatever produced the request or job
    context), so it is treated as absent -- the record is written with
    `correlation_id=None`, the same outcome as having no correlation
    context at all -- rather than letting the database reject the whole
    audit write. `saas_os/api/middleware.py` never binds an over-long id in the
    first place; this is the defense for every other context binder.

    `acting_as_tenant_id`/`delegation_grant_id`/`support_access_id`
    (architecture research Phase F) are pure linkage/context -- all three
    default to `None`, matching every pre-Phase-F call site exactly, and
    none of the three is validated against `saas_os.core.rbac`'s own tables here
    (`saas_os/core/audit_log/models.py`'s own docstring: this module still depends
    on nothing but `saas_os/infra/db`/`saas_os/infra/observability`). At most one of
    `delegation_grant_id`/`support_access_id` may be set -- also enforced
    at the database level (`ck_audit_log_single_authorization_linkage`) --
    so this fails closed with a clear, typed error first, for the
    identical reason the actor-pairing check above does.

    `metadata` must not carry a reserved attribution key -- `system_actor`,
    `initiated_by` or `correlation` (`ReservedMetadataKeyError`, before any
    write): system attribution is written only from validated values,
    through `record_system_action_in_transaction()` or
    `record_in_transaction()` with a `SystemCaller`.
    A successful `ActorType.SYSTEM` row with no `system_authority` purpose
    in its metadata is still written, with a `DeprecationWarning` and an
    `audit_system_row_unattributed` log line naming the calling module
    (ADR 0061 step 1; nothing is refused yet).
    """
    _refuse_reserved_metadata(metadata)
    entry = _validated_entry(
        tenant_id=tenant_id,
        actor_type=actor_type,
        action=action,
        resource_type=resource_type,
        outcome=outcome,
        actor_user_id=actor_user_id,
        actor_service_account_id=actor_service_account_id,
        resource_id=resource_id,
        correlation_id=correlation_id,
        metadata=metadata,
        acting_as_tenant_id=acting_as_tenant_id,
        delegation_grant_id=delegation_grant_id,
        support_access_id=support_access_id,
    )
    _warn_if_unattributed(actor_type, outcome, metadata)
    with tenant_session_scope(tenant_id) as session:
        session.add(entry)
        session.flush()
        session.refresh(entry)
        session.expunge(entry)
        return entry


def record_in_transaction(
    session: Session,
    *,
    caller: Caller,
    tenant_id: uuid.UUID,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    metadata: dict[str, object] | None = None,
    acting_as_tenant_id: uuid.UUID | None = None,
    delegation_grant_id: uuid.UUID | None = None,
    support_access_id: uuid.UUID | None = None,
    initiated_by: Initiator | None = None,
    correlation: SystemCorrelation | None = None,
) -> AuditLogEntry:
    """Append one audit record **inside the caller's own transaction**
    (Foundation Authority & Evidence, ADR-0031): the entry is added to
    `session` and flushed, never committed here. The state change it
    describes and the evidence of that change therefore commit together or
    roll back together -- a rolled-back mutation can never leave behind a
    record claiming it succeeded, and a committed one can never be missing
    its record.

    `session` must be the mutation's own `saas_os.infra.db.tenant_session_scope(
    tenant_id)` session: `saas_os.core.audit_log`'s Row-Level Security policy only
    admits a row whose `tenant_id` matches the session's tenant, so an
    entry for any other tenant fails at the database (fail closed) rather
    than being written outside the mutation's scope.

    The actor columns are derived from `caller` (`saas_os.core.authority`), never
    passed separately, so the evidence cannot name a different actor than
    the one the operation authorized. A `SystemCaller` is recorded as
    `ActorType.SYSTEM` with its purpose under `metadata["system_authority"]`
    and, when it carries one, its `SystemActor` under
    `metadata["system_actor"]` (attribution only, ADR 0061). Validation is
    identical to `record()` (including the refusal of a caller-supplied
    `system_actor`, `initiated_by` or `correlation` key) and happens before
    the insert.

    `initiated_by` and `correlation` (owner decision C, attribution only)
    apply to a `SystemCaller` alone: when it carries an actor, or either is
    given, the row records `initiated_by` (the `Initiator`, or exactly
    `"unavailable"` when `None`) and `correlation` (the ids present) beside
    `system_actor`; a `SystemCaller` with none of the three is recorded
    exactly as before. A `UserCaller` or `ServiceAccountCaller` is its own
    initiator, so passing either for one fails closed
    (`InvalidActorError`) before the insert.

    A user `Initiator` (`InitiatorType.USER`) is refused with
    `InvalidActorError` before the insert, for every caller (owner decision
    D2, 2026-11-02): a new audit record never stores a raw user id under
    `initiated_by`. A user-initiated system action is recorded with
    `initiated_by=None` (`"unavailable"`) until the reference mechanism
    ships. (A `UserCaller`'s own id in `actor_user_id` is unaffected: the
    database requires it for a user row.)
    """
    require_caller("record_in_transaction", caller)
    _refuse_reserved_metadata(metadata)
    _require_attribution_types(initiated_by, correlation)
    if isinstance(caller, SystemCaller):
        if caller.actor is not None or initiated_by is not None or correlation is not None:
            metadata = {**(metadata or {}), **_attribution(caller.actor, initiated_by, correlation)}
    elif initiated_by is not None or correlation is not None:
        raise InvalidActorError(
            "initiated_by and correlation apply only to a SystemCaller; a user or "
            "service-account caller is its own initiator."
        )
    actor_type, actor_user_id, actor_service_account_id, metadata = _caller_actor(caller, metadata)
    entry = _validated_entry(
        tenant_id=tenant_id,
        actor_type=actor_type,
        action=action,
        resource_type=resource_type,
        outcome=outcome,
        actor_user_id=actor_user_id,
        actor_service_account_id=actor_service_account_id,
        resource_id=resource_id,
        correlation_id=None,
        metadata=metadata,
        acting_as_tenant_id=acting_as_tenant_id,
        delegation_grant_id=delegation_grant_id,
        support_access_id=support_access_id,
    )
    session.add(entry)
    session.flush()
    return entry


def _caller_actor(
    caller: Caller, metadata: dict[str, object] | None
) -> tuple[ActorType, uuid.UUID | None, uuid.UUID | None, dict[str, object] | None]:
    if isinstance(caller, UserCaller):
        return ActorType.USER, caller.user_id, None, metadata
    if isinstance(caller, ServiceAccountCaller):
        return ActorType.SERVICE_ACCOUNT, None, caller.service_account_id, metadata
    assert isinstance(caller, SystemCaller)
    system_metadata: dict[str, object] = {
        **(metadata or {}),
        _SYSTEM_AUTHORITY_METADATA_KEY: caller.authority.value,
    }
    return ActorType.SYSTEM, None, None, system_metadata


def record_system_action_in_transaction(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    actor: SystemActor,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    correlation_id: str | None = None,
    metadata: dict[str, object] | None = None,
    initiated_by: Initiator | None = None,
    correlation: SystemCorrelation | None = None,
) -> AuditLogEntry:
    """Append one `ActorType.SYSTEM` audit record attributed to `actor`
    **inside the caller's own transaction** (ADR 0061, option B): the entry
    is added to `session` and flushed, never committed here, exactly like
    `record_in_transaction()` -- the change and its evidence commit or roll
    back together.

    `actor` is attribution only. It is recorded under
    `metadata["system_actor"]` in a fixed shape (`SystemActor.as_metadata()`)
    and confers no authority: this function authorizes nothing, and a
    `SystemActor` is accepted by no Core operation as its `caller`. An
    action that needs Core authority keeps its `SystemCaller` purpose and
    records through `record_in_transaction()` with
    `SystemCaller(authority, actor=...)`.

    `tenant_id` is the tenant whose audit trail receives the row, taken
    from verified context (the job context, the event's own tenant, the
    caller's tenant) -- never from the actor, which carries no tenant.
    `session` must be that tenant's `tenant_session_scope(tenant_id)`
    session: Row-Level Security refuses a row for any other tenant.

    Three roles are recorded distinctly (owner decision C, 2026-11-01):
    `actor` is the **executing** component (`metadata["system_actor"]`);
    `initiated_by` is who or what originally requested the action
    (`metadata["initiated_by"]`: the `Initiator`'s fixed shape, or exactly
    the string `"unavailable"` when `None` -- the executor is never
    substituted for it); `correlation` carries the arq job id, outbox event
    id and request id (`metadata["correlation"]`, only the parts present,
    `{}` when `None`). In a job, `SystemActor.from_job_actor(context.
    system_actor)`, `Initiator.from_job_initiator(context.initiated_by)` and
    `SystemCorrelation.from_job_context(context)` give the three -- except
    that a user initiator is refused (below).

    Fails closed before the insert: `actor` must be a `SystemActor`,
    `initiated_by` a service-account or system `Initiator` or `None`,
    `correlation` a `SystemCorrelation` or `None` (`InvalidActorError`
    otherwise). A user `Initiator` is refused (owner decision D2,
    2026-11-02: a new audit record never stores a raw user id under
    `initiated_by`); in an outbox consumer whose `context.initiated_by` is
    a user, pass `initiated_by=None`, which records `"unavailable"`.
    Further, caller-supplied `metadata` must not carry a reserved key
    (`system_actor`, `initiated_by`, `correlation`, and -- for this
    function, which authorizes nothing -- `system_authority`;
    `ReservedMetadataKeyError`); and every other field is validated as in
    `record()` -- including the metadata size bound, which the attribution
    counts toward. `correlation_id` defaults to the ambient request/job
    correlation id, as in `record()`.
    """
    if type(actor) is not SystemActor:
        raise InvalidActorError(f"actor must be a SystemActor, got {type(actor).__name__}.")
    _refuse_reserved_metadata(metadata, _SYSTEM_ACTION_RESERVED_METADATA_KEYS)
    attribution = _attribution(actor, initiated_by, correlation)
    entry = _validated_entry(
        tenant_id=tenant_id,
        actor_type=ActorType.SYSTEM,
        action=action,
        resource_type=resource_type,
        outcome=outcome,
        actor_user_id=None,
        actor_service_account_id=None,
        resource_id=resource_id,
        correlation_id=correlation_id,
        metadata={**(metadata or {}), **attribution},
        acting_as_tenant_id=None,
        delegation_grant_id=None,
        support_access_id=None,
    )
    session.add(entry)
    session.flush()
    return entry


def _validated_entry(
    *,
    tenant_id: uuid.UUID,
    actor_type: ActorType,
    action: str,
    resource_type: str,
    outcome: AuditOutcome,
    actor_user_id: uuid.UUID | None,
    actor_service_account_id: uuid.UUID | None,
    resource_id: str | None,
    correlation_id: str | None,
    metadata: dict[str, object] | None,
    acting_as_tenant_id: uuid.UUID | None,
    delegation_grant_id: uuid.UUID | None,
    support_access_id: uuid.UUID | None,
) -> AuditLogEntry:
    """Validate every argument (fail closed, before any write) and build
    the unsaved entry -- shared by `record()` and `record_in_transaction()`."""
    if actor_type is ActorType.USER:
        if actor_user_id is None:
            raise InvalidActorError("actor_user_id is required when actor_type is ActorType.USER.")
        if actor_service_account_id is not None:
            raise InvalidActorError(
                "actor_service_account_id must not be set when actor_type is ActorType.USER."
            )
    elif actor_type is ActorType.SYSTEM:
        if actor_user_id is not None:
            raise InvalidActorError(
                "actor_user_id must not be set when actor_type is ActorType.SYSTEM."
            )
        if actor_service_account_id is not None:
            raise InvalidActorError(
                "actor_service_account_id must not be set when actor_type is ActorType.SYSTEM."
            )
    elif actor_type is ActorType.SERVICE_ACCOUNT:
        if actor_service_account_id is None:
            raise InvalidActorError(
                "actor_service_account_id is required when actor_type is ActorType.SERVICE_ACCOUNT."
            )
        if actor_user_id is not None:
            raise InvalidActorError(
                "actor_user_id must not be set when actor_type is ActorType.SERVICE_ACCOUNT."
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

    if correlation_id is not None and len(correlation_id) > _MAX_CORRELATION_ID_LENGTH:
        raise InvalidActionOrResourceError(
            f"correlation_id exceeds {_MAX_CORRELATION_ID_LENGTH} characters."
        )
    if correlation_id is not None and _CONTROL_CHARACTERS.search(correlation_id):
        raise InvalidActionOrResourceError("correlation_id must not contain control characters.")
    if correlation_id is None:
        ambient = get_correlation_context().request_id
        if ambient is not None and len(ambient) <= _MAX_CORRELATION_ID_LENGTH:
            correlation_id = ambient

    return AuditLogEntry(
        tenant_id=tenant_id,
        actor_type=actor_type.value,
        actor_user_id=actor_user_id,
        actor_service_account_id=actor_service_account_id,
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


# --- PRIV-03 Phase P3: retention references ----------------------------------
#
# Two read-only helpers the tenant purge orchestration relies on. Audit rows
# are retained forever and the runtime role cannot delete them, so any
# `core.delegation_grants` / `core.service_accounts` row an audit entry
# references through its own `NO ACTION` foreign keys can never be deleted
# either -- it must be *retained* (revoked/disabled) instead. These return
# exactly that set, from the audit log's own columns, tenant-scoped through
# RLS like every other read here. Still no `update()`/`delete()`/`purge()`.


def referenced_delegation_grant_ids(tenant_id: uuid.UUID) -> frozenset[uuid.UUID]:
    """Every `delegation_grant_id` any of `tenant_id`'s audit entries
    names -- the delegation grants that must survive a tenant purge."""
    with tenant_session_scope(tenant_id) as session:
        rows = session.execute(
            select(AuditLogEntry.delegation_grant_id)
            .where(AuditLogEntry.tenant_id == tenant_id)
            .where(AuditLogEntry.delegation_grant_id.is_not(None))
            .distinct()
        ).scalars()
        return frozenset(grant_id for grant_id in rows if grant_id is not None)


def referenced_service_account_ids(tenant_id: uuid.UUID) -> frozenset[uuid.UUID]:
    """Every `actor_service_account_id` any of `tenant_id`'s audit entries
    names -- the service accounts that must survive a tenant purge."""
    with tenant_session_scope(tenant_id) as session:
        rows = session.execute(
            select(AuditLogEntry.actor_service_account_id)
            .where(AuditLogEntry.tenant_id == tenant_id)
            .where(AuditLogEntry.actor_service_account_id.is_not(None))
            .distinct()
        ).scalars()
        return frozenset(account_id for account_id in rows if account_id is not None)
