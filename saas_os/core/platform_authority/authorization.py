"""The platform authorization chokepoint
(docs/ADR/0045-installation-scoped-platform-authority.md section 5).

`platform_can()` answers one question from platform grant storage only: is
this user an active operator, of an active user, holding this permission?

It never reads a tenant membership, role, role permission, delegation,
deny, support-access request, a tenant's status, or `PLATFORM_TENANT_ID`.
`saas_os.core.rbac.can()` in turn never reads platform operators or grants.

`authorize_platform_caller()` is the single step a platform operation
calls. The permission and the accepted system purposes come from the
declared operation table (`operations.PLATFORM_OPERATIONS`), never from
the call site.

**This is the authorization.** The row-level-security policy on the
platform tables is defence in depth: it hides them from tenant-scoped
transactions, and it cannot tell an authorized operator from any other
untenanted caller. Nothing in this package treats "the row was visible" as
permission.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from saas_os.core.authority import (
    ServiceAccountCaller,
    SystemCaller,
    UserCaller,
    require_caller,
)
from saas_os.core.identity import lock_user_is_active
from saas_os.core.platform_authority.errors import (
    PlatformNotAuthorizedError,
    UnknownPlatformOperationError,
)
from saas_os.core.platform_authority.models import (
    OperatorStatus,
    PlatformGrant,
    PlatformOperator,
)
from saas_os.core.platform_authority.operations import PLATFORM_OPERATIONS, PlatformOperation
from saas_os.core.platform_authority.permissions import PlatformPermission
from saas_os.infra.db import Session, select, session_scope


def platform_can(
    *, user_id: uuid.UUID, permission: PlatformPermission, session: Session | None = None
) -> bool:
    """`True` only if `user_id` exists and is active, has an operator row
    with status `active`, and that operator holds an unrevoked grant of
    `permission`. Any missing link is `False`; there is no default allow,
    and an argument of the wrong type is `False`, not an error.

    With `session` (a mutation's own transaction) the decision holds the
    user row, the operator row and the grant row `FOR SHARE` until that
    transaction ends: a revocation, suspension or deactivation either
    committed first and is observed, or waits (ADR-0031 section 3a, applied
    to platform authority). Without `session` (a read, a pre-check) it runs
    in one transaction of its own.

    The session must have no tenant bound. Inside a tenant scope the
    platform tables are hidden and this returns `False` -- fail closed.

    A database error propagates; it is never treated as an answer.
    """
    if not isinstance(user_id, uuid.UUID) or not isinstance(permission, PlatformPermission):
        return False
    if session is None:
        with session_scope() as own_session:
            return _decide(own_session, user_id, permission)
    return _decide(session, user_id, permission)


def _decide(session: Session, user_id: uuid.UUID, permission: PlatformPermission) -> bool:
    # `None` (no such user) and `False` (deactivated) both deny. The row
    # stays locked FOR SHARE for the rest of this transaction.
    if not lock_user_is_active(session, user_id):
        return False
    operator = session.execute(
        select(PlatformOperator.id, PlatformOperator.status)
        .where(
            PlatformOperator.user_id == user_id,
            PlatformOperator.status != OperatorStatus.REVOKED.value,
        )
        .with_for_update(read=True)
    ).one_or_none()
    if operator is None or operator.status != OperatorStatus.ACTIVE.value:
        return False
    grant = session.execute(
        select(PlatformGrant.id)
        .where(
            PlatformGrant.operator_id == operator.id,
            PlatformGrant.permission == permission.value,
            PlatformGrant.revoked_at.is_(None),
        )
        .with_for_update(read=True)
    ).first()
    return grant is not None


def is_active_platform_operator(*, user_id: uuid.UUID) -> bool:
    """`True` only if `user_id` exists and is active and has an operator
    row with status `active`, whatever it is granted. Any missing link is
    `False`, and an argument of the wrong type is `False`, not an error.

    Not an authorization: it grants nothing and no operation may rest on
    it. Its one use is the platform HTTP chain (section 7), which answers
    a caller who is not an active operator exactly as it answers an
    unknown path, and only an operator with a refusal. Runs in a
    transaction of its own and holds nothing afterwards."""
    if not isinstance(user_id, uuid.UUID):
        return False
    with session_scope() as session:
        if not lock_user_is_active(session, user_id):
            return False
        status = session.execute(
            select(PlatformOperator.status).where(
                PlatformOperator.user_id == user_id,
                PlatformOperator.status != OperatorStatus.REVOKED.value,
            )
        ).scalar_one_or_none()
    return status == OperatorStatus.ACTIVE.value


def platform_operation(operation: str) -> PlatformOperation:
    """The declared row for `operation`; `UnknownPlatformOperationError`
    (a programming error, never a refusal) if there is none."""
    spec = PLATFORM_OPERATIONS.get(operation)
    if spec is None:
        raise UnknownPlatformOperationError(operation)
    return spec


def authorize_platform_caller(
    caller: object, *, session: Session, operation: str
) -> PlatformOperation:
    """Authorize `caller` for the declared platform `operation`, inside the
    operation's own transaction (`session`, required: there is no
    standalone form). Returns the operation's row; raises otherwise.

    - `UserCaller`: must pass `platform_can()` for the operation's
      permission, in `session`.
    - `ServiceAccountCaller`: always refused. A service account is owned by
      one tenant, and a tenant-owned principal never holds platform
      authority.
    - `SystemCaller`: accepted only if its purpose is in the set the
      operation table declares for this operation. A `SystemCaller` is not
      an operator: it holds no grant and `platform_can()` is never
      evaluated for it.
    - anything else, including `None`: `CallerTypeError`, before any read.

    Raises `PlatformNotAuthorizedError` for every refusal, without saying
    which link was missing.
    """
    spec = platform_operation(operation)
    require_caller(operation, caller)
    if isinstance(caller, SystemCaller):
        if caller.authority not in spec.system_authorities:
            raise PlatformNotAuthorizedError(operation)
        return spec
    if isinstance(caller, ServiceAccountCaller):
        raise PlatformNotAuthorizedError(operation)
    assert isinstance(caller, UserCaller)  # `require_caller` admits exactly these three
    if spec.permission is None:
        raise PlatformNotAuthorizedError(operation)
    if not platform_can(user_id=caller.user_id, permission=spec.permission, session=session):
        raise PlatformNotAuthorizedError(operation)
    return spec


def platform_caller_could_hold_any(caller: object, operations: Sequence[str]) -> bool:
    """A preliminary question, never the decision: could `caller` be
    authorized for at least one of the declared `operations`?

    For a multi-step operation that must read or lock something before it
    knows which operation it is performing, and must not do that for a
    caller with no authority at all (`transition_tenant_status`, ADR-0045
    section 12). The operation still calls `authorize_platform_caller()`
    in its own transaction, under its locks, for the operation it finally
    selects; this function decides nothing and its answer may be stale by
    then.

    - `SystemCaller`: its purpose is accepted by one of the operations.
    - `UserCaller`: `platform_can()` for the permission of one of them,
      each in a transaction of its own, which commits before this returns:
      no lock is held afterwards.
    - a service account, or anything else: `False`.

    An unknown operation key is `UnknownPlatformOperationError`, as
    everywhere."""
    specs = [platform_operation(operation) for operation in operations]
    if isinstance(caller, SystemCaller):
        return any(caller.authority in spec.system_authorities for spec in specs)
    if not isinstance(caller, UserCaller):
        return False
    permissions = sorted(
        {spec.permission for spec in specs if spec.permission is not None},
        key=lambda permission: permission.value,
    )
    return any(
        platform_can(user_id=caller.user_id, permission=permission) for permission in permissions
    )
