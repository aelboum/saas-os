"""Operational oversight: the shared path of an oversight read, and the
reads of the platform's own tables
(docs/ADR/0045-installation-scoped-platform-authority.md sections 4, 8 and
9d).

**The path.** Every oversight read runs in two transactions, each opened
with no tenant bound (section 9d, steps 1 to 7):

1. *the attempt*: authorize, insert the attempt row, commit -- before
   anything is read, and fail closed;
2. *the read*: authorize again (the decision holds the caller's rows
   `FOR SHARE` to the end), run the one bounded query, insert the
   completion row carrying the number of entries returned and the
   attempt's id, commit.

The data leaves the function only after the completion row is durable.
Both transactions carry the configured statement timeout.

`run_oversight_read()` is that path, once. `saas_os.core.tenancy.registry`
and `saas_os.core.billing.oversight` predate it and spell the same steps
out; they share `oversight_read_timeout()` and the audit writers with it.

**The reads here** are of global tables this package owns, gated each by
its own permission and returning a fixed projection:

    list_platform_operators   platform.operator:read
    list_platform_grants      platform.operator:read
    list_platform_audit       platform.audit:read

**Request limits (decision D3).** A page size above the maximum is
rejected, never clamped: a silently shortened page looks like a complete
answer. One page per call, by keyset on the primary key -- except the
audit page, which is in time order (`created_at`, then `id`).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

from saas_os.core.authority import ServiceAccountCaller, require_caller
from saas_os.core.platform_authority.audit import (
    record_oversight_attempt,
    record_platform_event_in_transaction,
    record_platform_refusal,
    recording_platform_refusal,
)
from saas_os.core.platform_authority.authorization import (
    authorize_platform_caller,
    platform_operation,
)
from saas_os.core.platform_authority.config import get_oversight_read_config
from saas_os.core.platform_authority.errors import (
    InvalidPlatformRequestError,
    OversightReadTimeoutError,
    PlatformNotAuthorizedError,
    PlatformRefusalError,
)
from saas_os.core.platform_authority.models import (
    PlatformAuditLogEntry,
    PlatformAuditOutcome,
    PlatformGrant,
    PlatformOperator,
)
from saas_os.core.platform_authority.operations import AUDIT_READ, OPERATOR_READ
from saas_os.infra.db import (
    OperationalError,
    Session,
    is_statement_timeout,
    select,
    session_scope,
    set_local_statement_timeout,
)

DEFAULT_OVERSIGHT_PAGE_SIZE = 50
MAX_OVERSIGHT_PAGE_SIZE = 200

_CODE_ERROR = "error"
_CODE_STATEMENT_TIMEOUT = "statement_timeout"
_MAX_ACTION_FILTER_LENGTH = 200


# --- the shared path -----------------------------------------------------------------


@contextmanager
def oversight_read_timeout(operation: str) -> Iterator[Callable[[Session], None]]:
    """Wrap the read transaction of one oversight read (section 9d).
    Yields a function the caller applies to that transaction's session as
    its first statement; it sets the configured statement timeout
    (`PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS`) for that transaction only.
    A statement PostgreSQL cancels inside the block leaves it as
    `OversightReadTimeoutError`, after the transaction has been rolled
    back by its own `session_scope()`.

        with oversight_read_timeout(TENANT_READ) as bound, session_scope() as session:
            bound(session)
            ...

    The attempt transaction carries the same timeout, set by
    `record_oversight_attempt(statement_timeout_ms=...)`."""
    timeout_ms = get_oversight_read_config().statement_timeout_ms

    def bound(session: Session) -> None:
        set_local_statement_timeout(session, timeout_ms)

    try:
        yield bound
    except OperationalError as error:
        if is_statement_timeout(error):
            raise OversightReadTimeoutError(
                operation, timeout_ms, stage=OversightReadTimeoutError.STAGE_READ
            ) from error
        raise


@dataclass(frozen=True)
class OversightOutcome[Value]:
    """What a read hands back to `run_oversight_read()`: the value to
    return, and what the completion row records about it -- how many
    entries, and (when the read resolved one) the target's id and tenant.
    Never the value itself."""

    value: Value
    returned: int
    target_id: str | None = None
    target_tenant_id: uuid.UUID | None = None


def run_oversight_read[Value](
    *,
    caller: object,
    operation: str,
    target_type: str,
    read: Callable[[Session], OversightOutcome[Value]],
    target_id: str | None = None,
    request_metadata: dict[str, object] | None = None,
    records_failure: bool = False,
) -> Value:
    """Run one oversight read by the path of section 9d and return its
    value. `read` receives the read transaction's session, already
    authorized and with no tenant bound, and performs the one bounded
    query; it must not commit.

    `request_metadata` is what the attempt row records of the request (a
    cursor, a page size): never anything read, and never an identity
    provider's issuer or subject.

    Outcomes, as the failure table of section 9d states them:

    - not authorized: nothing read, no attempt row, one `denied` row;
    - the attempt cannot be committed, or times out: error, nothing read,
      no row of any kind;
    - authority revoked between the two transactions: refused, nothing
      returned, the attempt row remains, one `denied` row;
    - the read fails or times out: rolled back, nothing returned, the
      attempt row remains; with `records_failure` (a read that enters a
      tenant scope) a `failure` row is written separately, best effort.

    A service account is refused before any read; a missing or wrongly
    typed caller is `CallerTypeError`."""
    require_oversight_caller(operation, caller)
    action = platform_operation(operation).audit_action
    timeout_ms = get_oversight_read_config().statement_timeout_ms

    with recording_platform_refusal(
        caller=caller, operation=operation, target_type=target_type, target_id=target_id
    ):
        # Committed before anything is read; raises if it cannot be.
        attempt_id = record_oversight_attempt(
            caller=caller,
            operation=operation,
            target_type=target_type,
            target_id=target_id,
            metadata=request_metadata,
            statement_timeout_ms=timeout_ms,
        )
        try:
            with oversight_read_timeout(operation) as bound, session_scope() as session:
                bound(session)  # statement timeout, this transaction only
                # Again: the authority may have been revoked since the attempt.
                authorize_platform_caller(caller, session=session, operation=operation)
                outcome = read(session)
                # With no tenant bound (section 9c).
                record_platform_event_in_transaction(
                    session,
                    caller=caller,
                    action=action,
                    target_type=target_type,
                    target_id=target_id if outcome.target_id is None else outcome.target_id,
                    target_tenant_id=outcome.target_tenant_id,
                    metadata={"attempt_id": str(attempt_id), "returned": outcome.returned},
                )
        except PlatformRefusalError:
            raise  # recorded as `denied` by the block above
        except Exception as error:
            if records_failure:
                timed_out = isinstance(error, OversightReadTimeoutError)
                record_platform_refusal(
                    caller=caller,
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    code=_CODE_STATEMENT_TIMEOUT if timed_out else _CODE_ERROR,
                    outcome=PlatformAuditOutcome.FAILURE,
                )
            raise
    # Committed: the completion row is durable before the value leaves.
    return outcome.value


def require_oversight_caller(operation: str, caller: object) -> None:
    """The first check of every oversight read, before its request is even
    validated: `CallerTypeError` for a missing or wrongly typed caller,
    and a service account refused, so that neither learns from a
    validation error what a well-formed request looks like."""
    require_caller(operation, caller)
    if isinstance(caller, ServiceAccountCaller):
        raise PlatformNotAuthorizedError(operation)


def validate_page_request(cursor: object, limit: object, *, maximum: int) -> None:
    """The request limits of decision D3, for a keyset page: `cursor` is a
    `uuid.UUID` or absent, `limit` a positive integer not above `maximum`.
    Rejected, never clamped."""
    if cursor is not None and not isinstance(cursor, uuid.UUID):
        raise InvalidPlatformRequestError("cursor must be a uuid.UUID.")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise InvalidPlatformRequestError("limit must be a positive integer.")
    if limit > maximum:
        raise InvalidPlatformRequestError(f"limit exceeds the maximum page size of {maximum}.")


def _page_metadata(cursor: uuid.UUID | None, limit: int) -> dict[str, object]:
    return {"cursor": None if cursor is None else str(cursor), "page_size": limit}


# --- operators and grants ------------------------------------------------------------

_TARGET_OPERATOR = "platform_operator"
_TARGET_GRANT = "platform_grant"
_TARGET_AUDIT = "platform_audit"


@dataclass(frozen=True)
class PlatformOperatorView:
    """The complete projection of one operator row, revoked ones included."""

    id: uuid.UUID
    user_id: uuid.UUID
    status: str
    enrolled_by_user_id: uuid.UUID | None
    status_changed_at: datetime
    status_changed_by_user_id: uuid.UUID | None
    created_at: datetime


@dataclass(frozen=True)
class PlatformOperatorPage:
    """`next_cursor` is the id to pass as `cursor` for the following page,
    or `None` when this page was not full."""

    operators: tuple[PlatformOperatorView, ...]
    next_cursor: uuid.UUID | None


@dataclass(frozen=True)
class PlatformGrantView:
    """The complete projection of one grant row, revoked ones included."""

    id: uuid.UUID
    operator_id: uuid.UUID
    permission: str
    granted_by_user_id: uuid.UUID | None
    granted_at: datetime
    revoked_at: datetime | None
    revoked_by_user_id: uuid.UUID | None


@dataclass(frozen=True)
class PlatformGrantPage:
    grants: tuple[PlatformGrantView, ...]
    next_cursor: uuid.UUID | None


def list_platform_operators(
    *, caller: object, cursor: uuid.UUID | None = None, limit: int = DEFAULT_OVERSIGHT_PAGE_SIZE
) -> PlatformOperatorPage:
    """One page of the operators of this deployment, in every status, by
    keyset on the operator id. Authority: `platform.operator:read`."""
    require_oversight_caller(OPERATOR_READ, caller)
    validate_page_request(cursor, limit, maximum=MAX_OVERSIGHT_PAGE_SIZE)

    def read(session: Session) -> OversightOutcome[PlatformOperatorPage]:
        query = select(PlatformOperator)
        if cursor is not None:
            query = query.where(PlatformOperator.id > cursor)
        rows = session.execute(query.order_by(PlatformOperator.id).limit(limit)).scalars().all()
        operators = tuple(
            PlatformOperatorView(
                id=row.id,
                user_id=row.user_id,
                status=row.status,
                enrolled_by_user_id=row.enrolled_by_user_id,
                status_changed_at=row.status_changed_at,
                status_changed_by_user_id=row.status_changed_by_user_id,
                created_at=row.created_at,
            )
            for row in rows
        )
        page = PlatformOperatorPage(
            operators=operators,
            next_cursor=operators[-1].id if len(operators) == limit else None,
        )
        return OversightOutcome(page, len(operators))

    return run_oversight_read(
        caller=caller,
        operation=OPERATOR_READ,
        target_type=_TARGET_OPERATOR,
        request_metadata=_page_metadata(cursor, limit),
        read=read,
    )


def list_platform_grants(
    *,
    caller: object,
    operator_id: uuid.UUID | None = None,
    cursor: uuid.UUID | None = None,
    limit: int = DEFAULT_OVERSIGHT_PAGE_SIZE,
) -> PlatformGrantPage:
    """One page of platform grants, revoked ones included, by keyset on the
    grant id; of one operator when `operator_id` is given, of every
    operator otherwise. Authority: `platform.operator:read`.

    An `operator_id` that names no operator yields an empty page, like one
    that names an operator with no grants."""
    require_oversight_caller(OPERATOR_READ, caller)
    validate_page_request(cursor, limit, maximum=MAX_OVERSIGHT_PAGE_SIZE)
    if operator_id is not None and not isinstance(operator_id, uuid.UUID):
        raise InvalidPlatformRequestError("operator_id must be a uuid.UUID.")

    def read(session: Session) -> OversightOutcome[PlatformGrantPage]:
        query = select(PlatformGrant)
        if operator_id is not None:
            query = query.where(PlatformGrant.operator_id == operator_id)
        if cursor is not None:
            query = query.where(PlatformGrant.id > cursor)
        rows = session.execute(query.order_by(PlatformGrant.id).limit(limit)).scalars().all()
        grants = tuple(
            PlatformGrantView(
                id=row.id,
                operator_id=row.operator_id,
                permission=row.permission,
                granted_by_user_id=row.granted_by_user_id,
                granted_at=row.granted_at,
                revoked_at=row.revoked_at,
                revoked_by_user_id=row.revoked_by_user_id,
            )
            for row in rows
        )
        page = PlatformGrantPage(
            grants=grants, next_cursor=grants[-1].id if len(grants) == limit else None
        )
        return OversightOutcome(page, len(grants))

    return run_oversight_read(
        caller=caller,
        operation=OPERATOR_READ,
        target_type=_TARGET_GRANT,
        target_id=None if operator_id is None else str(operator_id),
        request_metadata=_page_metadata(cursor, limit),
        read=read,
    )


# --- the platform audit table -----------------------------------------------------------


@dataclass(frozen=True)
class PlatformAuditView:
    """One row of `core.platform_audit_log`, as stored."""

    id: uuid.UUID
    created_at: datetime
    actor_type: str
    actor_user_id: uuid.UUID | None
    system_authority: str | None
    action: str
    target_type: str
    target_id: str | None
    target_tenant_id: uuid.UUID | None
    outcome: str
    reason: str | None
    correlation_id: str | None
    metadata: dict[str, object] | None


@dataclass(frozen=True)
class PlatformAuditPage:
    entries: tuple[PlatformAuditView, ...]
    next_cursor: uuid.UUID | None


def list_platform_audit(
    *,
    caller: object,
    since: datetime | None = None,
    until: datetime | None = None,
    actor_user_id: uuid.UUID | None = None,
    action: str | None = None,
    target_tenant_id: uuid.UUID | None = None,
    cursor: uuid.UUID | None = None,
    limit: int = DEFAULT_OVERSIGHT_PAGE_SIZE,
) -> PlatformAuditPage:
    """One page of the platform audit table, oldest first, by keyset on
    (`created_at`, `id`). Authority: `platform.audit:read`.

    **Filters (section 8), each optional, all combined with AND:** `since`
    and `until` bound `created_at` (inclusive and exclusive; both must
    carry a time zone); `actor_user_id`, `action` (exact) and
    `target_tenant_id` match their columns. "What did this operator do in
    the last hour" is one filtered read, not a scan of the table.

    **Order (amended 2026-10-14).** Entries are in time order: by
    `created_at`, and by `id` among entries with the same `created_at`
    (the rows of one transaction share it). The cursor is still the `id`
    of the last entry of the previous page; the next page starts strictly
    after that entry's (`created_at`, `id`). A cursor that names no audit
    row is `InvalidPlatformRequestError` -- raised from the read, so after
    the attempt row was committed, because resolving it needs the table.
    The application role cannot delete audit rows, so a cursor this
    function returned resolves for as long as nothing else removes the row.

    **Rows committed late are not returned by later pages.** `created_at`
    is the time a row's transaction *began*. A transaction that began
    before the cursor's entry and commits after the reader has paged past
    that time writes a row no later page returns -- `until` does not help,
    because the row is inside the bound. Give `until` so that the walk
    ends; a reader who needs every row re-reads the window
    `since = <start of the walk> - <longest platform transaction>`
    afterwards (ADR-0045, amendment of 2026-10-14; deferred ledger).

    Reading the table is itself audited. The attempt row of this call is
    committed before the page is read and may appear on it; its
    completion row is written after the page was read and cannot."""
    require_oversight_caller(AUDIT_READ, caller)
    validate_page_request(cursor, limit, maximum=MAX_OVERSIGHT_PAGE_SIZE)
    for name, moment in (("since", since), ("until", until)):
        if moment is not None and (not isinstance(moment, datetime) or moment.tzinfo is None):
            raise InvalidPlatformRequestError(f"{name} must be a datetime with a time zone.")
    if since is not None and until is not None and since >= until:
        raise InvalidPlatformRequestError("since must be earlier than until.")
    for name, identifier in (
        ("actor_user_id", actor_user_id),
        ("target_tenant_id", target_tenant_id),
    ):
        if identifier is not None and not isinstance(identifier, uuid.UUID):
            raise InvalidPlatformRequestError(f"{name} must be a uuid.UUID.")
    if action is not None and (
        not isinstance(action, str) or not action or len(action) > _MAX_ACTION_FILTER_LENGTH
    ):
        raise InvalidPlatformRequestError("action must be a non-empty platform audit action.")
    request_metadata = _page_metadata(cursor, limit)
    # What was asked for, never what was found.
    request_metadata["filters"] = {
        "since": None if since is None else since.isoformat(),
        "until": None if until is None else until.isoformat(),
        "actor_user_id": None if actor_user_id is None else str(actor_user_id),
        "action": action,
        "target_tenant_id": None if target_tenant_id is None else str(target_tenant_id),
    }

    def read(session: Session) -> OversightOutcome[PlatformAuditPage]:
        query = select(PlatformAuditLogEntry)
        if since is not None:
            query = query.where(PlatformAuditLogEntry.created_at >= since)
        if until is not None:
            query = query.where(PlatformAuditLogEntry.created_at < until)
        if actor_user_id is not None:
            query = query.where(PlatformAuditLogEntry.actor_user_id == actor_user_id)
        if action is not None:
            query = query.where(PlatformAuditLogEntry.action == action)
        if target_tenant_id is not None:
            query = query.where(PlatformAuditLogEntry.target_tenant_id == target_tenant_id)
        if cursor is not None:
            after = session.execute(
                select(PlatformAuditLogEntry.created_at).where(PlatformAuditLogEntry.id == cursor)
            ).scalar_one_or_none()
            if after is None:
                raise InvalidPlatformRequestError("cursor names no platform audit entry.")
            query = query.where(
                (PlatformAuditLogEntry.created_at > after)
                | (
                    (PlatformAuditLogEntry.created_at == after)
                    & (PlatformAuditLogEntry.id > cursor)
                )
            )
        rows = (
            session.execute(
                query.order_by(PlatformAuditLogEntry.created_at, PlatformAuditLogEntry.id).limit(
                    limit
                )
            )
            .scalars()
            .all()
        )
        entries = tuple(
            PlatformAuditView(
                id=row.id,
                created_at=row.created_at,
                actor_type=row.actor_type,
                actor_user_id=row.actor_user_id,
                system_authority=row.system_authority,
                action=row.action,
                target_type=row.target_type,
                target_id=row.target_id,
                target_tenant_id=row.target_tenant_id,
                outcome=row.outcome,
                reason=row.reason,
                correlation_id=row.correlation_id,
                metadata=None if row.entry_metadata is None else dict(row.entry_metadata),
            )
            for row in rows
        )
        page = PlatformAuditPage(
            entries=entries, next_cursor=entries[-1].id if len(entries) == limit else None
        )
        return OversightOutcome(page, len(entries))

    return run_oversight_read(
        caller=caller,
        operation=AUDIT_READ,
        target_type=_TARGET_AUDIT,
        request_metadata=request_metadata,
        read=read,
    )
