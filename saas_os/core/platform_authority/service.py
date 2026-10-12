"""Platform operator and grant lifecycle
(docs/ADR/0045-installation-scoped-platform-authority.md sections 3 and 6).

Six operations change who holds platform authority:

    enroll_operator            reactivate_operator       grant_platform_permission
    suspend_operator           revoke_operator           revoke_platform_permission

Every one runs in exactly one transaction, opened with no tenant bound,
in this order:

1. the platform-owners advisory lock (`owners.lock_platform_owners`);
2. authorization (`authorization.authorize_platform_caller`) -- after the
   lock, so a caller whose own authority a concurrent change just removed
   is judged against what that change committed;
3. record whether a platform owner exists;
4. the change and its platform audit row, flushed;
5. re-run the owner predicate; if an owner existed and none does now,
   raise `LastPlatformOwnerError`.

Any exception leaves the `session_scope()` block and rolls the whole
transaction back: the change and its success audit row disappear together.
A refusal is then recorded separately (`audit.record_platform_refusal`).

Rules for a person changing authority, all enforced here and not at a
route: the caller holds `platform.authority:manage`; no self-service (the
caller may not target their own operator); anti-amplification (the caller
may grant only a permission they hold); the subject user exists and is
active to be enrolled or granted to; a reason is required and recorded.

Rows are never deleted. Revoking an operator is terminal and revokes its
live grants in the same transaction. Granting a permission again after a
revocation inserts a new row, so the rows are the history. Enrolling a
user again after a revocation inserts a new operator row with no grants.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime

from saas_os.core.authority import (
    ServiceAccountCaller,
    SystemCaller,
    UserCaller,
    require_caller,
)
from saas_os.core.identity import lock_user_is_active
from saas_os.core.platform_authority.audit import (
    record_platform_event_in_transaction,
    record_platform_refusal,
    validate_reason,
)
from saas_os.core.platform_authority.authorization import (
    authorize_platform_caller,
    platform_can,
    platform_operation,
)
from saas_os.core.platform_authority.errors import (
    DuplicatePlatformGrantError,
    InactivePlatformSubjectError,
    InvalidPlatformOperatorStateError,
    InvalidPlatformRequestError,
    LastPlatformOwnerError,
    PlatformAmplificationError,
    PlatformGrantNotFoundError,
    PlatformOperatorAlreadyEnrolledError,
    PlatformOperatorNotFoundError,
    PlatformRefusalError,
    PlatformSubjectNotFoundError,
    SelfAuthorityChangeError,
)
from saas_os.core.platform_authority.models import (
    OperatorStatus,
    PlatformGrant,
    PlatformOperator,
)
from saas_os.core.platform_authority.operations import (
    GRANT_CREATE,
    GRANT_REVOKE,
    OPERATOR_ENROLL,
    OPERATOR_REACTIVATE,
    OPERATOR_REVOKE,
    OPERATOR_SUSPEND,
)
from saas_os.core.platform_authority.owners import lock_platform_owners, platform_owner_exists
from saas_os.core.platform_authority.permissions import PlatformPermission
from saas_os.infra.db import Session, select, session_scope, update

_CALLER_TYPES = (UserCaller, ServiceAccountCaller, SystemCaller)
_TARGET_OPERATOR = "platform_operator"
_TARGET_USER = "user"


@contextmanager
def authority_transaction(operations: Sequence[str], caller: object) -> Iterator[Session]:
    """The one transaction shape for every change to platform authority
    (module docstring, steps 1 to 5). `operations` are the declared
    operation keys the transaction performs; the caller is authorized for
    each of them, after the lock.

    The last-owner recheck runs when the block completes. Raising inside
    the block, or failing the recheck, rolls everything back.
    """
    with session_scope() as session:
        lock_platform_owners(session)
        for operation in operations:
            authorize_platform_caller(caller, session=session, operation=operation)
        had_owner = platform_owner_exists(session)
        yield session
        session.flush()
        if had_owner and not platform_owner_exists(session):
            raise LastPlatformOwnerError(operations[-1])


def _run[Result](
    operation: str,
    caller: object,
    *,
    target_type: str,
    target_id: str,
    body: Callable[[Session], Result],
) -> Result:
    """Run `body` inside `authority_transaction`, and record a refusal
    after the rollback if the operation was refused."""
    try:
        with authority_transaction((operation,), caller) as session:
            return body(session)
    except PlatformRefusalError as refusal:
        record_platform_refusal(
            caller=caller,
            action=platform_operation(operation).audit_action,
            target_type=target_type,
            target_id=target_id,
            code=refusal.code,
        )
        raise


def _acting_user_id(caller: object) -> uuid.UUID | None:
    return caller.user_id if isinstance(caller, UserCaller) else None


def _refuse_self(operation: str, caller: object, subject_user_id: uuid.UUID) -> None:
    if _acting_user_id(caller) == subject_user_id:
        raise SelfAuthorityChangeError(operation)


def _require_active_subject(session: Session, user_id: uuid.UUID) -> None:
    """The user to be enrolled or granted to must exist and be active.
    Holds the `core.users` row FOR SHARE until the transaction ends."""
    is_active = lock_user_is_active(session, user_id)
    if is_active is None:
        raise PlatformSubjectNotFoundError(user_id)
    if not is_active:
        raise InactivePlatformSubjectError(user_id)


def _lock_operator(session: Session, operator_id: uuid.UUID) -> PlatformOperator:
    operator = session.execute(
        select(PlatformOperator).where(PlatformOperator.id == operator_id).with_for_update()
    ).scalar_one_or_none()
    if operator is None:
        raise PlatformOperatorNotFoundError(operator_id)
    return operator


def _detach[Row](session: Session, row: Row) -> Row:
    session.flush()
    session.refresh(row)
    session.expunge(row)
    return row


def _require_uuid(name: str, value: object) -> None:
    if not isinstance(value, uuid.UUID):
        raise InvalidPlatformRequestError(f"{name} must be a uuid.UUID.")


def _require_permission(permission: object) -> PlatformPermission:
    if not isinstance(permission, PlatformPermission):
        raise InvalidPlatformRequestError("permission must be a PlatformPermission.")
    return permission


# --- The changes themselves: each runs inside an authority transaction ------
# These take the transaction's session and are shared with the bootstrap and
# recovery composite (`bootstrap.py`). They authorize nothing: the caller of
# each has already been authorized for the operation, in this transaction.


def enroll_in_transaction(
    session: Session, *, caller: object, user_id: uuid.UUID, reason: str
) -> PlatformOperator:
    _refuse_self(OPERATOR_ENROLL, caller, user_id)
    _require_active_subject(session, user_id)
    history = (
        session.execute(
            select(PlatformOperator.id, PlatformOperator.status)
            .where(PlatformOperator.user_id == user_id)
            .order_by(PlatformOperator.created_at.desc(), PlatformOperator.id)
        )
    ).all()
    if any(row.status != OperatorStatus.REVOKED.value for row in history):
        raise PlatformOperatorAlreadyEnrolledError(user_id)
    actor = _acting_user_id(caller)
    operator = PlatformOperator(
        user_id=user_id,
        status=OperatorStatus.ACTIVE.value,
        enrolled_by_user_id=actor,
        status_changed_by_user_id=actor,
    )
    session.add(operator)
    session.flush()
    metadata: dict[str, object] = {"user_id": str(user_id)}
    if history:
        # A re-enrollment: visible as one. Nothing is carried over from the
        # revoked operator, which stays as history.
        metadata["previous_operator_id"] = str(history[0].id)
    record_platform_event_in_transaction(
        session,
        caller=caller,
        action=platform_operation(OPERATOR_ENROLL).audit_action,
        target_type=_TARGET_OPERATOR,
        target_id=str(operator.id),
        reason=reason,
        metadata=metadata,
    )
    return operator


def _set_status(
    session: Session,
    *,
    operation: str,
    caller: object,
    operator_id: uuid.UUID,
    expected: OperatorStatus,
    new: OperatorStatus,
    reason: str,
) -> PlatformOperator:
    operator = _lock_operator(session, operator_id)
    _refuse_self(operation, caller, operator.user_id)
    if operator.status != expected.value:
        raise InvalidPlatformOperatorStateError(operator_id, operator.status, operation)
    operator.status = new.value
    operator.status_changed_at = datetime.now(UTC)
    operator.status_changed_by_user_id = _acting_user_id(caller)
    session.flush()
    record_platform_event_in_transaction(
        session,
        caller=caller,
        action=platform_operation(operation).audit_action,
        target_type=_TARGET_OPERATOR,
        target_id=str(operator.id),
        reason=reason,
        metadata={"user_id": str(operator.user_id), "from": expected.value, "to": new.value},
    )
    return operator


def suspend_in_transaction(
    session: Session, *, caller: object, operator_id: uuid.UUID, reason: str
) -> PlatformOperator:
    return _set_status(
        session,
        operation=OPERATOR_SUSPEND,
        caller=caller,
        operator_id=operator_id,
        expected=OperatorStatus.ACTIVE,
        new=OperatorStatus.SUSPENDED,
        reason=reason,
    )


def grant_in_transaction(
    session: Session,
    *,
    caller: object,
    operator_id: uuid.UUID,
    permission: PlatformPermission,
    reason: str,
) -> PlatformGrant:
    operator = _lock_operator(session, operator_id)
    _refuse_self(GRANT_CREATE, caller, operator.user_id)
    if operator.status == OperatorStatus.REVOKED.value:
        raise InvalidPlatformOperatorStateError(operator_id, operator.status, GRANT_CREATE)
    _require_active_subject(session, operator.user_id)
    acting_user_id = _acting_user_id(caller)
    # Anti-amplification. A system purpose has no grants to compare against
    # and is exempt by definition; it was accepted for this operation only
    # because the operation table lists it.
    if acting_user_id is not None and not platform_can(
        user_id=acting_user_id, permission=permission, session=session
    ):
        raise PlatformAmplificationError(GRANT_CREATE, permission.value)
    live = session.execute(
        select(PlatformGrant.id).where(
            PlatformGrant.operator_id == operator_id,
            PlatformGrant.permission == permission.value,
            PlatformGrant.revoked_at.is_(None),
        )
    ).first()
    if live is not None:
        raise DuplicatePlatformGrantError(operator_id, permission.value)
    grant = PlatformGrant(
        operator_id=operator_id, permission=permission.value, granted_by_user_id=acting_user_id
    )
    session.add(grant)
    session.flush()
    record_platform_event_in_transaction(
        session,
        caller=caller,
        action=platform_operation(GRANT_CREATE).audit_action,
        target_type=_TARGET_OPERATOR,
        target_id=str(operator_id),
        reason=reason,
        metadata={
            "permission": permission.value,
            "grant_id": str(grant.id),
            "user_id": str(operator.user_id),
        },
    )
    return grant


# --- Public operations ------------------------------------------------------


def enroll_operator(user_id: uuid.UUID, *, caller: object, reason: str) -> PlatformOperator:
    """Enroll `user_id` as a platform operator, with no grants.

    Authority: `platform.authority:manage`, or the bootstrap and recovery
    purpose. The user must exist, be active, and not already have an
    operator that is not revoked. Enrolling a user whose earlier operator
    was revoked creates a new row and inherits nothing from the old one.
    """
    require_caller(OPERATOR_ENROLL, caller, _CALLER_TYPES)
    _require_uuid("user_id", user_id)
    reason = validate_reason(reason)

    def body(session: Session) -> PlatformOperator:
        operator = enroll_in_transaction(session, caller=caller, user_id=user_id, reason=reason)
        return _detach(session, operator)

    return _run(
        OPERATOR_ENROLL, caller, target_type=_TARGET_USER, target_id=str(user_id), body=body
    )


def suspend_operator(operator_id: uuid.UUID, *, caller: object, reason: str) -> PlatformOperator:
    """`active -> suspended`. The operator keeps its grant rows and has no
    authority until reactivated. Refused if it would leave no active
    platform owner."""
    require_caller(OPERATOR_SUSPEND, caller, _CALLER_TYPES)
    _require_uuid("operator_id", operator_id)
    reason = validate_reason(reason)

    def body(session: Session) -> PlatformOperator:
        operator = suspend_in_transaction(
            session, caller=caller, operator_id=operator_id, reason=reason
        )
        return _detach(session, operator)

    return _run(
        OPERATOR_SUSPEND,
        caller,
        target_type=_TARGET_OPERATOR,
        target_id=str(operator_id),
        body=body,
    )


def reactivate_operator(operator_id: uuid.UUID, *, caller: object, reason: str) -> PlatformOperator:
    """`suspended -> active`. Requires a person: no system purpose is
    accepted. Reactivating an operator whose user is deactivated is
    permitted and confers nothing until the user is active again."""
    require_caller(OPERATOR_REACTIVATE, caller, _CALLER_TYPES)
    _require_uuid("operator_id", operator_id)
    reason = validate_reason(reason)

    def body(session: Session) -> PlatformOperator:
        operator = _set_status(
            session,
            operation=OPERATOR_REACTIVATE,
            caller=caller,
            operator_id=operator_id,
            expected=OperatorStatus.SUSPENDED,
            new=OperatorStatus.ACTIVE,
            reason=reason,
        )
        return _detach(session, operator)

    return _run(
        OPERATOR_REACTIVATE,
        caller,
        target_type=_TARGET_OPERATOR,
        target_id=str(operator_id),
        body=body,
    )


def revoke_operator(operator_id: uuid.UUID, *, caller: object, reason: str) -> PlatformOperator:
    """Terminal. The operator becomes `revoked` and every live grant it
    holds is revoked in the same transaction; the owner recheck runs once,
    at the end. Requires a person. Refused if it would leave no active
    platform owner."""
    require_caller(OPERATOR_REVOKE, caller, _CALLER_TYPES)
    _require_uuid("operator_id", operator_id)
    reason = validate_reason(reason)

    def body(session: Session) -> PlatformOperator:
        operator = _lock_operator(session, operator_id)
        _refuse_self(OPERATOR_REVOKE, caller, operator.user_id)
        if operator.status == OperatorStatus.REVOKED.value:
            raise InvalidPlatformOperatorStateError(operator_id, operator.status, OPERATOR_REVOKE)
        previous = operator.status
        now = datetime.now(UTC)
        acting_user_id = _acting_user_id(caller)
        revoked_permissions = sorted(
            session.execute(
                select(PlatformGrant.permission)
                .where(PlatformGrant.operator_id == operator_id, PlatformGrant.revoked_at.is_(None))
                .with_for_update()
            ).scalars()
        )
        session.execute(
            update(PlatformGrant)
            .where(PlatformGrant.operator_id == operator_id, PlatformGrant.revoked_at.is_(None))
            .values(revoked_at=now, revoked_by_user_id=acting_user_id)
        )
        operator.status = OperatorStatus.REVOKED.value
        operator.status_changed_at = now
        operator.status_changed_by_user_id = acting_user_id
        session.flush()
        record_platform_event_in_transaction(
            session,
            caller=caller,
            action=platform_operation(OPERATOR_REVOKE).audit_action,
            target_type=_TARGET_OPERATOR,
            target_id=str(operator.id),
            reason=reason,
            metadata={
                "user_id": str(operator.user_id),
                "from": previous,
                "to": OperatorStatus.REVOKED.value,
                "revoked_permissions": revoked_permissions,
            },
        )
        return _detach(session, operator)

    return _run(
        OPERATOR_REVOKE,
        caller,
        target_type=_TARGET_OPERATOR,
        target_id=str(operator_id),
        body=body,
    )


def grant_platform_permission(
    operator_id: uuid.UUID, permission: PlatformPermission, *, caller: object, reason: str
) -> PlatformGrant:
    """Grant exactly one platform permission to an operator.

    Authority: `platform.authority:manage`, or the bootstrap and recovery
    purpose. A person may grant only a permission they hold themselves,
    and never to their own operator. The operator must not be revoked and
    its user must be active. There is no bundle and no copy: every grant
    is one named permission, authorized and audited on its own.
    """
    require_caller(GRANT_CREATE, caller, _CALLER_TYPES)
    _require_uuid("operator_id", operator_id)
    permission = _require_permission(permission)
    reason = validate_reason(reason)

    def body(session: Session) -> PlatformGrant:
        grant = grant_in_transaction(
            session, caller=caller, operator_id=operator_id, permission=permission, reason=reason
        )
        return _detach(session, grant)

    return _run(
        GRANT_CREATE, caller, target_type=_TARGET_OPERATOR, target_id=str(operator_id), body=body
    )


def revoke_platform_permission(
    operator_id: uuid.UUID, permission: PlatformPermission, *, caller: object, reason: str
) -> PlatformGrant:
    """Revoke one live grant. The row is kept, with `revoked_at` set.
    Requires a person, who may not revoke from their own operator. Refused
    if it would leave no active platform owner."""
    require_caller(GRANT_REVOKE, caller, _CALLER_TYPES)
    _require_uuid("operator_id", operator_id)
    permission = _require_permission(permission)
    reason = validate_reason(reason)

    def body(session: Session) -> PlatformGrant:
        operator = _lock_operator(session, operator_id)
        _refuse_self(GRANT_REVOKE, caller, operator.user_id)
        grant = session.execute(
            select(PlatformGrant)
            .where(
                PlatformGrant.operator_id == operator_id,
                PlatformGrant.permission == permission.value,
                PlatformGrant.revoked_at.is_(None),
            )
            .with_for_update()
        ).scalar_one_or_none()
        if grant is None:
            raise PlatformGrantNotFoundError(operator_id, permission.value)
        grant.revoked_at = datetime.now(UTC)
        grant.revoked_by_user_id = _acting_user_id(caller)
        session.flush()
        record_platform_event_in_transaction(
            session,
            caller=caller,
            action=platform_operation(GRANT_REVOKE).audit_action,
            target_type=_TARGET_OPERATOR,
            target_id=str(operator_id),
            reason=reason,
            metadata={
                "permission": permission.value,
                "grant_id": str(grant.id),
                "user_id": str(operator.user_id),
            },
        )
        return _detach(session, grant)

    return _run(
        GRANT_REVOKE, caller, target_type=_TARGET_OPERATOR, target_id=str(operator_id), body=body
    )
