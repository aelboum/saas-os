"""Platform audit
(docs/ADR/0045-installation-scoped-platform-authority.md section 8).

Platform evidence lives in its own table, `core.platform_audit_log`. It is
never written to `core.audit_log`, which stays tenant-owned evidence with
`tenant_id NOT NULL` under the tenant policy, unchanged.

Three writers, and no other code constructs a `PlatformAuditLogEntry`:

- `record_platform_event_in_transaction()` adds the row to the mutation's
  own transaction and never commits. The change and its evidence commit
  together or roll back together.
- `record_oversight_attempt()` authorizes an oversight read and commits
  its *attempt* row in a transaction of its own, before anything is read
  (section 9d). It is fail closed: if the row cannot be committed it
  raises, and the read does not happen.
- `record_platform_refusal()` writes one row in a transaction of its own,
  after the refused operation's transaction has rolled back, because
  evidence of a refusal must survive the refusal (ADR-0031 section 3). It
  is best effort: if it cannot be written, the refusal still stands.

The actor columns are derived from the caller, never passed separately, so
evidence cannot name a different actor than the one authorized. A person
is always recorded as a `user`; `system` rows carry the purpose.

What this does and does not guarantee: the runtime role has only `INSERT`
and `SELECT` on the table, so no application code can change or remove a
row. It does not authenticate an insert -- in-process code can still
insert a row describing something that did not happen -- and it does not
bind the migrations role. There is no hash chain.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from saas_os.core.audit_log.metadata import validate_metadata
from saas_os.core.authority import (
    CallerTypeError,
    ServiceAccountCaller,
    SystemCaller,
    UserCaller,
    require_caller,
)
from saas_os.core.platform_authority.authorization import authorize_platform_caller
from saas_os.core.platform_authority.errors import (
    InvalidPlatformRequestError,
    OversightReadTimeoutError,
    PlatformRefusalError,
    UnknownPlatformOperationError,
)
from saas_os.core.platform_authority.models import (
    OperatorStatus,
    PlatformActorType,
    PlatformAuditLogEntry,
    PlatformAuditOutcome,
    PlatformOperator,
)
from saas_os.core.platform_authority.operations import PLATFORM_OPERATIONS
from saas_os.infra.db import (
    OperationalError,
    Session,
    is_statement_timeout,
    select,
    session_scope,
    set_local_statement_timeout,
)
from saas_os.infra.observability import get_correlation_context

logger = logging.getLogger(__name__)

MAX_REASON_LENGTH = 500  # core.platform_audit_log.reason String(500)
_MAX_ACTION_LENGTH = 200
_MAX_TARGET_TYPE_LENGTH = 100
_MAX_TARGET_ID_LENGTH = 255
_MAX_CORRELATION_ID_LENGTH = 100
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_ACTION = re.compile(r"platform\.[a-z_]+(\.[a-z_]+)+")


def validate_reason(reason: object) -> str:
    """A reason is required for every change to platform authority:
    non-empty, at most `MAX_REASON_LENGTH` characters, no control
    characters. Returns the stripped value."""
    if not isinstance(reason, str):
        raise InvalidPlatformRequestError("reason must be a string.")
    value = reason.strip()
    if not value:
        raise InvalidPlatformRequestError("reason must not be empty.")
    if len(value) > MAX_REASON_LENGTH:
        raise InvalidPlatformRequestError(f"reason exceeds {MAX_REASON_LENGTH} characters.")
    if _CONTROL_CHARACTERS.search(value):
        raise InvalidPlatformRequestError("reason must not contain control characters.")
    return value


def _actor(caller: UserCaller | SystemCaller) -> tuple[str, uuid.UUID | None, str | None]:
    if isinstance(caller, UserCaller):
        return PlatformActorType.USER.value, caller.user_id, None
    return PlatformActorType.SYSTEM.value, None, caller.authority.value


def _entry(
    *,
    caller: UserCaller | SystemCaller,
    action: str,
    target_type: str,
    target_id: str | None,
    target_tenant_id: uuid.UUID | None,
    outcome: PlatformAuditOutcome,
    reason: str | None,
    metadata: dict[str, object] | None,
) -> PlatformAuditLogEntry:
    if not isinstance(action, str) or not _ACTION.fullmatch(action):
        raise InvalidPlatformRequestError("action must be a dotted `platform.` action name.")
    if len(action) > _MAX_ACTION_LENGTH:
        raise InvalidPlatformRequestError("action is too long.")
    if not isinstance(target_type, str) or not 0 < len(target_type) <= _MAX_TARGET_TYPE_LENGTH:
        raise InvalidPlatformRequestError("target_type must be a short, non-empty string.")
    if target_id is not None and not 0 < len(target_id) <= _MAX_TARGET_ID_LENGTH:
        raise InvalidPlatformRequestError("target_id is empty or too long.")
    if reason is not None and len(reason) > MAX_REASON_LENGTH:
        raise InvalidPlatformRequestError(f"reason exceeds {MAX_REASON_LENGTH} characters.")
    if not isinstance(outcome, PlatformAuditOutcome):
        raise InvalidPlatformRequestError("outcome must be a PlatformAuditOutcome.")
    validate_metadata(metadata)
    actor_type, actor_user_id, system_authority = _actor(caller)
    correlation_id = get_correlation_context().request_id
    if correlation_id is not None and len(correlation_id) > _MAX_CORRELATION_ID_LENGTH:
        correlation_id = None
    return PlatformAuditLogEntry(
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        system_authority=system_authority,
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_tenant_id=target_tenant_id,
        outcome=outcome.value,
        reason=reason,
        correlation_id=correlation_id,
        entry_metadata=metadata,
    )


def record_platform_event_in_transaction(
    session: Session,
    *,
    caller: object,
    action: str,
    target_type: str,
    target_id: str | None = None,
    target_tenant_id: uuid.UUID | None = None,
    outcome: PlatformAuditOutcome = PlatformAuditOutcome.SUCCESS,
    reason: str | None = None,
    metadata: dict[str, object] | None = None,
) -> PlatformAuditLogEntry:
    """Append one platform audit record **inside the caller's own
    transaction**: added to `session` and flushed, never committed here.

    `session` must have no tenant bound. Inside a tenant scope the
    table's row-level-security policy rejects the insert (fail closed),
    which is the ordering rule of ADR-0045 section 9c.

    `caller` is a `UserCaller` or a `SystemCaller`. A service account is
    never a platform actor (`CallerTypeError`).
    """
    require_caller("record_platform_event_in_transaction", caller, (UserCaller, SystemCaller))
    assert isinstance(caller, (UserCaller, SystemCaller))
    entry = _entry(
        caller=caller,
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_tenant_id=target_tenant_id,
        outcome=outcome,
        reason=reason,
        metadata=metadata,
    )
    session.add(entry)
    session.flush()
    return entry


# An oversight read leaves two rows (ADR-0045 sections 8 and 9d): the
# attempt, under the operation's audit action with this suffix, and the
# completion, under the audit action itself. The actions differ so that a
# reader counting completed reads never counts an attempt.
OVERSIGHT_ATTEMPT_SUFFIX = "_attempt"


def oversight_attempt_action(operation: str) -> str:
    """The audit action of the attempt row of the oversight read
    `operation` (a key of the declared operation table)."""
    spec = PLATFORM_OPERATIONS.get(operation)
    if spec is None:
        raise UnknownPlatformOperationError(operation)
    return spec.audit_action + OVERSIGHT_ATTEMPT_SUFFIX


def record_oversight_attempt(
    *,
    caller: object,
    operation: str,
    target_type: str,
    target_id: str | None = None,
    metadata: dict[str, object] | None = None,
    statement_timeout_ms: int | None = None,
) -> uuid.UUID:
    """Authorize `caller` for the oversight read `operation` and commit
    its attempt row, **in a transaction of its own, before anything is
    read**. Returns the row's id, which the completion row of the same
    read carries as `attempt_id`.

    Fail closed, unlike `record_platform_refusal()`: every error
    propagates. A caller who is not authorized is refused here
    (`PlatformNotAuthorizedError`) and no attempt row exists, because the
    refusal rolls this transaction back; the refusal's own `denied` row is
    the caller's to record. If the row cannot be inserted or the commit
    fails, the error is raised and the caller must not read.

    The row records the request -- the cursor, the page size, a target id
    when one was named -- and never anything read, because nothing has
    been. It carries no `target_tenant_id`: that column references an
    existing tenant, and whether the tenant exists is not yet known.

    Once this returns the row is durable: it survives a read that then
    fails, is refused or never finishes. An attempt with no completion,
    `denied` or `failure` row after it is a read that did not complete.

    `statement_timeout_ms`, when given, bounds every statement of this
    transaction, lock waits included (ADR-0045 section 9d): the
    authorization waits for row locks and the insert for the table, and
    neither may hold the call without limit. A statement PostgreSQL cancels
    is `OversightReadTimeoutError`; like every other failure here it
    leaves no attempt row, and nothing has been read.
    """
    action = oversight_attempt_action(operation)
    try:
        with session_scope() as session:
            if statement_timeout_ms is not None:
                set_local_statement_timeout(session, statement_timeout_ms)
            authorize_platform_caller(caller, session=session, operation=operation)
            entry = record_platform_event_in_transaction(
                session,
                caller=caller,
                action=action,
                target_type=target_type,
                target_id=target_id,
                metadata=metadata,
            )
            attempt_id = entry.id
    except OperationalError as error:
        if statement_timeout_ms is not None and is_statement_timeout(error):
            raise OversightReadTimeoutError(
                operation, statement_timeout_ms, stage=OversightReadTimeoutError.STAGE_ATTEMPT
            ) from error
        raise
    return attempt_id


def record_platform_refusal(
    *,
    caller: object,
    action: str,
    target_type: str,
    target_id: str | None = None,
    code: str,
    outcome: PlatformAuditOutcome = PlatformAuditOutcome.DENIED,
    metadata: dict[str, object] | None = None,
) -> bool:
    """Record that a platform operation was refused, in a transaction of
    its own. `code` is the refusal's fixed code (`not_authorized`,
    `last_platform_owner`, ...) and is stored as the row's reason.

    Best effort, and never raises: the refusal the caller is about to
    receive must not be replaced by an audit error. Returns whether a row
    was written. Nothing is written for a caller that is not a person or a
    system purpose (a service account, a malformed caller), or for a
    `UserCaller` naming a user that does not exist (the foreign key refuses
    it); those are logged.
    """
    try:
        require_caller("record_platform_refusal", caller, (UserCaller, SystemCaller))
    except CallerTypeError:
        kind = "service_account" if isinstance(caller, ServiceAccountCaller) else "invalid"
        logger.warning(
            "platform_refusal_not_recorded",
            extra={"action": action, "code": code, "caller_kind": kind},
        )
        return False
    assert isinstance(caller, (UserCaller, SystemCaller))
    try:
        entry = _entry(
            caller=caller,
            action=action,
            target_type=target_type,
            target_id=target_id,
            target_tenant_id=None,
            outcome=outcome,
            reason=code,
            metadata=metadata,
        )
        with session_scope() as session:
            session.add(entry)
    except Exception:  # noqa: BLE001 -- best effort by contract (docstring)
        logger.warning(
            "platform_refusal_audit_failed",
            extra={"action": action, "code": code},
            exc_info=True,
        )
        return False
    return True


@contextmanager
def recording_platform_refusal(
    *,
    caller: object,
    operation: str,
    target_type: str,
    target_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> Iterator[None]:
    """Wrap one platform operation's whole transaction. If it is refused
    (`PlatformRefusalError`), one `denied` row for the operation's declared
    audit action is recorded after the rollback, and the refusal is
    re-raised. The row is written by `record_platform_refusal()`, so it is
    best effort and never replaces the refusal."""
    spec = PLATFORM_OPERATIONS.get(operation)
    if spec is None:
        raise UnknownPlatformOperationError(operation)
    try:
        yield
    except PlatformRefusalError as refusal:
        record_platform_refusal(
            caller=caller,
            action=spec.audit_action,
            target_type=target_type,
            target_id=target_id,
            code=refusal.code,
            metadata=metadata,
        )
        raise


OPERATOR_SESSION_ISSUED = "platform.operator.session_issued"


def record_operator_session_issued_in_transaction(
    session: Session, *, user_id: uuid.UUID, session_id: uuid.UUID
) -> bool:
    """Record that a session was issued to an enrolled platform operator
    (ADR-0045 sections 8 and 10), inside the issuing transaction. Returns
    whether a row was written; nothing is written for a user who is not an
    operator, or whose operator is revoked.

    This is a login record for the population where it matters most: a
    takeover of an operator's subject at the identity provider produces a
    login the real operator did not make. The event has no operation key
    because nobody is authorized for it. The row names the operator as its
    actor and the session id as its target; never a token or its hash.

    `session` must have no tenant bound."""
    enrolled = session.execute(
        select(PlatformOperator.id)
        .where(
            PlatformOperator.user_id == user_id,
            PlatformOperator.status != OperatorStatus.REVOKED.value,
        )
        .limit(1)
    ).first()
    if enrolled is None:
        return False
    record_platform_event_in_transaction(
        session,
        caller=UserCaller(user_id),
        action=OPERATOR_SESSION_ISSUED,
        target_type="session",
        target_id=str(session_id),
        metadata={"operator_id": str(enrolled.id)},
    )
    return True
