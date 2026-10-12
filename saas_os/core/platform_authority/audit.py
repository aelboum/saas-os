"""Platform audit
(docs/ADR/0045-installation-scoped-platform-authority.md section 8).

Platform evidence lives in its own table, `core.platform_audit_log`. It is
never written to `core.audit_log`, which stays tenant-owned evidence with
`tenant_id NOT NULL` under the tenant policy, unchanged.

Two writers, and no other code constructs a `PlatformAuditLogEntry`:

- `record_platform_event_in_transaction()` adds the row to the mutation's
  own transaction and never commits. The change and its evidence commit
  together or roll back together.
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

from saas_os.core.audit_log.metadata import validate_metadata
from saas_os.core.authority import (
    CallerTypeError,
    ServiceAccountCaller,
    SystemCaller,
    UserCaller,
    require_caller,
)
from saas_os.core.platform_authority.errors import InvalidPlatformRequestError
from saas_os.core.platform_authority.models import (
    PlatformActorType,
    PlatformAuditLogEntry,
    PlatformAuditOutcome,
)
from saas_os.infra.db import Session, session_scope
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
