"""Platform operations on a user and the user's credentials
(docs/ADR/0045-installation-scoped-platform-authority.md section 11).

    revoke_user_sessions     platform.session:revoke
    revoke_user_api_keys     platform.api_key:revoke
    deactivate_user          platform.user:deactivate
    reactivate_user          platform.user:reactivate

Each takes a required, keyword-only `caller` and `reason`, authorizes the
caller in its own transaction through the platform chokepoint, and writes
its platform audit row in that transaction. No permission implies another:
`platform.user:deactivate` revokes sessions and keys only as part of a
deactivation, `platform.session:revoke` does not touch keys, and
`platform.api_key:revoke` neither touches sessions nor deactivates.

**The contract (replaces ADR-0031 section 5's session sentence for these
operations).** Deactivating a user revokes every live session and every
unrevoked user-owned API key of that user in the same transaction.
Reactivating a user restores neither. A deployment that edits
`core.users.is_active` by SQL gets none of this: the contract belongs to
the operation.

**Deactivation and the two invariants.** `deactivate_user` preserves the
last platform owner (ADR-0045 section 6) and the last administrator of
every tenant the user is an ACTIVE member of (ADR-0043). No query can list
a user's memberships across tenants, so they are discovered by scanning
the tenant registry under the ordinary tenant policy, twice, around an
exclusive lock on the user's row. The transaction, its lock order and the
argument for it are ADR-0045 section 11c; the steps are numbered in
`_deactivate_in_transaction` as they are there.

**Lock order, fixed:** the platform-owners advisory lock; ADR-0043
tenant-administrator advisory locks, nearest the root first, then by id;
row locks. No advisory lock is taken after a row lock.

**Imports of `saas_os.core.platform_authority`, `saas_os.core.rbac` and
`saas_os.core.api_keys` are deferred**: each imports `saas_os.core.identity`
at module scope.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from saas_os.core.authority import ServiceAccountCaller, UserCaller, require_caller
from saas_os.core.identity.config import get_deactivation_scan_config
from saas_os.core.identity.errors import (
    DeactivationRetryError,
    InvalidUserStateError,
    LastTenantAdministratorError,
)
from saas_os.core.identity.models import MembershipStatus, TenantMembership, User
from saas_os.core.identity.models import Session as UserSession
from saas_os.core.identity.service import lock_user_is_active
from saas_os.core.tenancy import count_unpurged_tenants, root_depths, unpurged_tenant_ids_page
from saas_os.infra.db import Session, bind_tenant_scope, select, session_scope, update

logger = logging.getLogger(__name__)

_TARGET_USER = "user"
_SCAN_PAGE_SIZE = 500
# A membership created while the deactivation runs aborts it (step 6); the
# whole transaction is retried this many times before the failure is
# reported.
_MAX_ATTEMPTS = 3

_CODE_USER_NOT_FOUND = "user_not_found"
_CODE_LAST_TENANT_ADMINISTRATOR = "last_tenant_administrator"
_CODE_RETRY_EXHAUSTED = "membership_changed_during_scan"
_CODE_ERROR = "error"


@dataclass(frozen=True)
class UserDeactivationResult:
    """Counts only: never a session id, a key id or a tenant id."""

    user_id: uuid.UUID
    sessions_revoked: int
    api_keys_revoked: int


class _MembershipAppearedError(Exception):
    """Step 6: the second scan found a tenant the first did not. Internal;
    the whole transaction is rolled back and retried."""


# --- shared -------------------------------------------------------------------


def _require_person_or_refuse(operation: str, caller: object) -> None:
    """`CallerTypeError` for a missing or wrongly typed caller; a service
    account is refused before any read."""
    from saas_os.core.platform_authority import PlatformNotAuthorizedError

    require_caller(operation, caller)
    if isinstance(caller, ServiceAccountCaller):
        raise PlatformNotAuthorizedError(operation)


def _validate(user_id: object, reason: object) -> str:
    from saas_os.core.platform_authority import InvalidPlatformRequestError, validate_reason

    if not isinstance(user_id, uuid.UUID):
        raise InvalidPlatformRequestError("user_id must be a uuid.UUID.")
    return validate_reason(reason)


def _record_outcome(
    caller: object,
    operation: str,
    user_id: uuid.UUID,
    code: str,
    *,
    failure: bool = False,
    metadata: dict[str, object] | None = None,
) -> None:
    """One `denied` (or `failure`) platform audit row, in a transaction of
    its own, after the operation's transaction rolled back."""
    from saas_os.core.platform_authority import (
        PlatformAuditOutcome,
        platform_operation,
        record_platform_refusal,
    )

    record_platform_refusal(
        caller=caller,
        action=platform_operation(operation).audit_action,
        target_type=_TARGET_USER,
        target_id=str(user_id),
        code=code,
        outcome=PlatformAuditOutcome.FAILURE if failure else PlatformAuditOutcome.DENIED,
        metadata=metadata,
    )


def _revoke_sessions(session: Session, user_id: uuid.UUID) -> int:
    rows = session.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
        .returning(UserSession.id)
    ).all()
    return len(rows)


def _record_success(
    session: Session,
    *,
    caller: object,
    operation: str,
    user_id: uuid.UUID,
    reason: str,
    metadata: dict[str, object],
) -> None:
    from saas_os.core.platform_authority import (
        platform_operation,
        record_platform_event_in_transaction,
    )

    record_platform_event_in_transaction(
        session,
        caller=caller,
        action=platform_operation(operation).audit_action,
        target_type=_TARGET_USER,
        target_id=str(user_id),
        reason=reason,
        metadata=metadata,
    )


def _run[Result](
    operation: str, caller: object, user_id: uuid.UUID, body: Callable[[], Result]
) -> Result:
    """Run one operation's transaction and record how it ended if it did
    not succeed: a refusal as `denied`, an unknown user as `denied`, any
    other error as `failure`. The original error is always re-raised."""
    from saas_os.core.platform_authority import (
        InvalidPlatformRequestError,
        PlatformRefusalError,
        PlatformSubjectNotFoundError,
    )

    try:
        return body()
    except PlatformRefusalError as refusal:
        metadata: dict[str, object] | None = None
        ceiling = getattr(refusal, "ceiling", None)
        if ceiling is not None:
            metadata = {"ceiling": ceiling}
        _record_outcome(caller, operation, user_id, refusal.code, metadata=metadata)
        raise
    except PlatformSubjectNotFoundError:
        _record_outcome(caller, operation, user_id, _CODE_USER_NOT_FOUND)
        raise
    except LastTenantAdministratorError as last:
        # The refusal names the tenant: the operator needs it to act.
        _record_outcome(
            caller,
            operation,
            user_id,
            _CODE_LAST_TENANT_ADMINISTRATOR,
            metadata={"tenant_id": str(last.tenant_id)},
        )
        raise
    except DeactivationRetryError:
        _record_outcome(caller, operation, user_id, _CODE_RETRY_EXHAUSTED, failure=True)
        raise
    except (InvalidPlatformRequestError, InvalidUserStateError):
        raise
    except Exception:
        _record_outcome(caller, operation, user_id, _CODE_ERROR, failure=True)
        raise


# --- identity erasure ---------------------------------------------------------------

# Identity erasure is not a platform operation -- there is no permission
# for it and it has no row in the operation table (ADR-0045 sections 4 and
# 7). Its one platform safeguard is recorded under the label and action
# declared for it in `operations.NON_OPERATION_REFUSALS`.


def refuse_erasure_of_enrolled_operator(user_id: uuid.UUID, *, actor_user_id: uuid.UUID) -> None:
    """ADR-0045 section 6: identity erasure of a user who has a platform
    operator row that is not revoked is refused outright, until the
    operator is revoked through a guarded path (`revoke_operator`, which
    passes the last-owner invariant). Raises `EnrolledOperatorErasureError`
    and records one `denied` platform audit row naming the acting user;
    returns `None` for every other user.

    `saas_os.core.identity.erasure.erase_user_identity` calls this before
    it erases anything. The read runs under the platform-owners lock in a
    transaction of its own, with no tenant bound. Erasure itself spans
    several transactions, so the lock cannot be held across it: an
    enrollment that commits after this check and before the erasure
    finishes is not seen."""
    from saas_os.core.platform_authority import (
        EnrolledOperatorErasureError,
        lock_platform_owners,
        record_platform_refusal,
    )
    from saas_os.core.platform_authority.operations import (
        NON_OPERATION_REFUSALS,
        USER_ERASE,
    )
    from saas_os.core.platform_authority.owners import unrevoked_operator_exists

    with session_scope() as session:
        lock_platform_owners(session)
        enrolled = unrevoked_operator_exists(session, user_id)
    if not enrolled:
        return
    refusal = EnrolledOperatorErasureError(USER_ERASE)
    audit_action = NON_OPERATION_REFUSALS[USER_ERASE].audit_action
    assert audit_action is not None  # declared with the label
    record_platform_refusal(
        caller=UserCaller(actor_user_id),
        action=audit_action,
        target_type=_TARGET_USER,
        target_id=str(user_id),
        code=refusal.code,
    )
    raise refusal


# --- session and API-key revocation ---------------------------------------------


def revoke_user_sessions(user_id: uuid.UUID, *, caller: object, reason: str) -> int:
    """Revoke every live session of `user_id` and change nothing else.
    Returns the number revoked. Authority: `platform.session:revoke`.

    It removes no authority, so it is refused by neither invariant: it
    succeeds for a last platform owner and for a tenant's last
    administrator. A caller may revoke their own sessions. The user is not
    deactivated and may log in again. Takes effect on the next request
    that presents a revoked session."""
    from saas_os.core.platform_authority import (
        PlatformSubjectNotFoundError,
        authorize_platform_caller,
    )
    from saas_os.core.platform_authority.operations import SESSION_REVOKE

    _require_person_or_refuse(SESSION_REVOKE, caller)
    reason = _validate(user_id, reason)

    def body() -> int:
        with session_scope() as session:
            authorize_platform_caller(caller, session=session, operation=SESSION_REVOKE)
            # Exclusive: an issuance in flight holds this row FOR SHARE, so
            # the session it commits is revoked here too.
            if lock_user_is_active(session, user_id, exclusive=True) is None:
                raise PlatformSubjectNotFoundError(user_id)
            revoked = _revoke_sessions(session, user_id)
            _record_success(
                session,
                caller=caller,
                operation=SESSION_REVOKE,
                user_id=user_id,
                reason=reason,
                metadata={"sessions_revoked": revoked},
            )
            return revoked

    return _run(SESSION_REVOKE, caller, user_id, body)


def revoke_user_api_keys(user_id: uuid.UUID, *, caller: object, reason: str) -> int:
    """Revoke every unrevoked user-owned API key of exactly one user, in
    every tenant, without deactivating the user (ADR-0045 section 11f).
    Returns the number revoked -- never a key id, name or tenant.
    Authority: `platform.api_key:revoke`, and nothing else satisfies it.

    Service-account keys are untouched. The target may be the caller.
    Takes no advisory lock and is refused by neither invariant. In the
    same transaction: one platform audit row (a count of keys and of
    distinct tenants, no identifiers), and one `api_key.revoke` row per key
    in that key's own tenant's audit trail naming the operator. Any failure
    rolls everything back: there is no outcome in which some keys are
    revoked and others are not.

    A point-in-time revocation: the user is still active and can create a
    new key a moment later. An incident response revokes sessions too."""
    from saas_os.core.api_keys.service import (
        record_platform_key_revocations,
        revoke_user_api_keys_in_transaction,
    )
    from saas_os.core.platform_authority import (
        PlatformSubjectNotFoundError,
        authorize_platform_caller,
    )
    from saas_os.core.platform_authority.operations import API_KEY_REVOKE

    _require_person_or_refuse(API_KEY_REVOKE, caller)
    reason = _validate(user_id, reason)

    def body() -> int:
        with session_scope() as session:
            authorize_platform_caller(caller, session=session, operation=API_KEY_REVOKE)
            assert isinstance(caller, UserCaller)  # the operation accepts no system purpose
            # Exclusive: a key creation in flight holds this row FOR SHARE,
            # so the key it commits is revoked here too.
            if lock_user_is_active(session, user_id, exclusive=True) is None:
                raise PlatformSubjectNotFoundError(user_id)
            keys = revoke_user_api_keys_in_transaction(session, user_id)
            _record_success(
                session,
                caller=caller,
                operation=API_KEY_REVOKE,
                user_id=user_id,
                reason=reason,
                metadata={
                    "api_keys_revoked": len(keys),
                    "tenants_affected": len({tenant_id for _, tenant_id in keys}),
                },
            )
            record_platform_key_revocations(session, caller=caller, user_id=user_id, keys=keys)
            return len(keys)

    return _run(API_KEY_REVOKE, caller, user_id, body)


# --- deactivation -------------------------------------------------------------


def _scan_active_memberships(
    session: Session, user_id: uuid.UUID, *, ceiling: int, operation: str
) -> tuple[frozenset[uuid.UUID], int]:
    """One complete pass over the tenant registry: the tenants in which
    `user_id` holds an ACTIVE membership, and how many tenants were
    visited. Each tenant is read under its own row-level-security scope,
    by one indexed existence query, with no row lock. Raises
    `DeactivationScanLimitError` as soon as the pass would visit more
    tenants than `ceiling`; it never returns a partial result."""
    from saas_os.core.platform_authority import DeactivationScanLimitError

    found: set[uuid.UUID] = set()
    visited = 0
    after: uuid.UUID | None = None
    while True:
        page = unpurged_tenant_ids_page(session, after=after, limit=_SCAN_PAGE_SIZE)
        if not page:
            return frozenset(found), visited
        for tenant_id in page:
            visited += 1
            if visited > ceiling:
                raise DeactivationScanLimitError(operation, ceiling)
            with bind_tenant_scope(session, tenant_id):
                member = session.execute(
                    select(TenantMembership.id)
                    .where(
                        TenantMembership.tenant_id == tenant_id,
                        TenantMembership.user_id == user_id,
                        TenantMembership.status == MembershipStatus.ACTIVE.value,
                    )
                    .limit(1)
                ).first()
            if member is not None:
                found.add(tenant_id)
        after = page[-1]


def _deactivate_in_transaction(
    session: Session, *, user_id: uuid.UUID, caller: object, reason: str, ceiling: int
) -> UserDeactivationResult:
    from saas_os.core.api_keys.service import (
        record_platform_key_revocations,
        revoke_user_api_keys_in_transaction,
    )
    from saas_os.core.platform_authority import (
        DeactivationScanLimitError,
        LastPlatformOwnerError,
        PlatformNotAuthorizedError,
        PlatformSelfTargetError,
        PlatformSubjectNotFoundError,
        authorize_platform_caller,
        lock_platform_owners,
        platform_can,
        platform_operation,
        platform_owner_exists,
    )
    from saas_os.core.platform_authority.operations import USER_DEACTIVATE
    from saas_os.core.rbac.administrators import guard_tenants

    # 1. The platform-owners advisory lock, first.
    lock_platform_owners(session)
    #    Preliminary authorization, without row locks and in a transaction
    #    of its own. It is not the decision (step 4 is): it exists so that a
    #    caller with no authority cannot make Core scan the registry.
    permission = platform_operation(USER_DEACTIVATE).permission
    if (
        not isinstance(caller, UserCaller)
        or permission is None
        or not platform_can(user_id=caller.user_id, permission=permission)
    ):
        raise PlatformNotAuthorizedError(USER_DEACTIVATE)
    #    Ceiling check, before any tenant scope is bound.
    if count_unpurged_tenants(session, limit=ceiling + 1) > ceiling:
        raise DeactivationScanLimitError(USER_DEACTIVATE, ceiling)

    # 2. First scan: the tenants the user is an ACTIVE member of.
    first, first_visited = _scan_active_memberships(
        session, user_id, ceiling=ceiling, operation=USER_DEACTIVATE
    )

    # 3. Their ADR-0043 administrator locks, nearest the root first, then
    #    by id; each tenant's administrator is recorded.
    depths = root_depths(session, sorted(first, key=str))
    guard = guard_tenants(session, sorted(first, key=lambda t: (depths[t], str(t))))

    # 4. The decision, after every advisory lock. Its FOR SHARE locks on
    #    the caller's user, operator and grant rows hold to the end.
    authorize_platform_caller(caller, session=session, operation=USER_DEACTIVATE)
    if caller.user_id == user_id:
        raise PlatformSelfTargetError(USER_DEACTIVATE)

    # 5. The user's row, exclusively. This waits for every transaction that
    #    holds it FOR SHARE: a decision that counted the user as an actor
    #    or as an administrator, a session issuance, a key creation or
    #    rotation.
    is_active = lock_user_is_active(session, user_id, exclusive=True)
    if is_active is None:
        raise PlatformSubjectNotFoundError(user_id)
    if not is_active:
        raise InvalidUserStateError(user_id, "inactive")

    # 6. Second scan. From step 5 on nobody can count the user anywhere, so
    #    a membership that exists now and was not seen in step 2 means a
    #    tenant is unguarded: abort, change nothing, retry.
    second, second_visited = _scan_active_memberships(
        session, user_id, ceiling=ceiling, operation=USER_DEACTIVATE
    )
    if second - first:
        raise _MembershipAppearedError

    # 7. The change, with the user's credentials.
    had_owner = platform_owner_exists(session)
    session.execute(update(User).where(User.id == user_id).values(is_active=False))
    sessions_revoked = _revoke_sessions(session, user_id)
    keys = revoke_user_api_keys_in_transaction(session, user_id)
    session.flush()

    # 8. Both invariants, on the flushed state. Neither masks the other;
    #    the first violation found is reported.
    guard.verify(session)
    if had_owner and not platform_owner_exists(session):
        raise LastPlatformOwnerError(USER_DEACTIVATE)

    # 9. Evidence: the platform row while no tenant is bound, then one row
    #    per revoked key in that key's own tenant.
    _record_success(
        session,
        caller=caller,
        operation=USER_DEACTIVATE,
        user_id=user_id,
        reason=reason,
        metadata={
            "sessions_revoked": sessions_revoked,
            "api_keys_revoked": len(keys),
            "tenants_affected": len({tenant_id for _, tenant_id in keys}),
            "tenants_visited_first_pass": first_visited,
            "tenants_visited_second_pass": second_visited,
            "memberships_guarded": len(first),
        },
    )
    record_platform_key_revocations(session, caller=caller, user_id=user_id, keys=keys)
    return UserDeactivationResult(
        user_id=user_id, sessions_revoked=sessions_revoked, api_keys_revoked=len(keys)
    )


def deactivate_user(user_id: uuid.UUID, *, caller: object, reason: str) -> UserDeactivationResult:
    """Set `is_active = false` for `user_id` and revoke, in the same
    transaction, every live session and every unrevoked user-owned API key
    of that user. Authority: `platform.user:deactivate`. A caller may not
    deactivate their own user.

    Refused, with nothing changed, if it would leave the deployment with
    no platform owner (`LastPlatformOwnerError`), or a tenant that has an
    administrator with none (`LastTenantAdministratorError`, naming the
    tenant), or if the tenant registry is larger than
    `PLATFORM_DEACTIVATION_MAX_TENANTS` (`DeactivationScanLimitError`). In
    the last two cases the incident path is `revoke_user_sessions` and
    `revoke_user_api_keys`, which need no scan and are never refused by an
    invariant, together with disabling the subject at the identity
    provider.

    If a membership of the user is created while the operation runs, the
    transaction is rolled back and retried a small fixed number of times;
    `DeactivationRetryError` reports that it never got a stable view. A
    deadlock with a guarded mutation the user is running by inherited
    authority is resolved by PostgreSQL aborting one of the two; nothing is
    left half-done and a retry succeeds.

    Takes effect on the next request: a revoked session or key is refused,
    and any mutation a request already past authentication attempts
    re-evaluates its authorization under lock and is refused."""
    from saas_os.core.platform_authority.operations import USER_DEACTIVATE

    _require_person_or_refuse(USER_DEACTIVATE, caller)
    reason = _validate(user_id, reason)
    ceiling = get_deactivation_scan_config().max_tenants

    def body() -> UserDeactivationResult:
        for _attempt in range(_MAX_ATTEMPTS):
            try:
                with session_scope() as session:
                    return _deactivate_in_transaction(
                        session, user_id=user_id, caller=caller, reason=reason, ceiling=ceiling
                    )
            except _MembershipAppearedError:
                logger.info("user_deactivation_retry", extra={"user_id": str(user_id)})
        raise DeactivationRetryError(user_id)

    return _run(USER_DEACTIVATE, caller, user_id, body)


def reactivate_user(user_id: uuid.UUID, *, caller: object, reason: str) -> UserDeactivationResult:
    """Set `is_active = true` for `user_id`. Authority:
    `platform.user:reactivate`.

    **Restores no credential.** Under the platform-owners lock and an
    exclusive lock on the user's row, every session and every user-owned
    API key of the user that is still unrevoked is revoked *before* the
    user becomes active. That step finds nothing if the deactivation and
    the issuance rules worked; it is kept so that "reactivation restores no
    credential" does not depend on them. The user logs in again and is
    issued new keys. The result reports what this call had to revoke.

    Reactivating a user who is an enrolled operator restores that
    operator's authority without any grant change, and is audited as a user
    reactivation."""
    from saas_os.core.api_keys.service import (
        record_platform_key_revocations,
        revoke_user_api_keys_in_transaction,
    )
    from saas_os.core.platform_authority import (
        PlatformSubjectNotFoundError,
        authorize_platform_caller,
        lock_platform_owners,
    )
    from saas_os.core.platform_authority.operations import USER_REACTIVATE

    _require_person_or_refuse(USER_REACTIVATE, caller)
    reason = _validate(user_id, reason)

    def body() -> UserDeactivationResult:
        with session_scope() as session:
            lock_platform_owners(session)
            authorize_platform_caller(caller, session=session, operation=USER_REACTIVATE)
            assert isinstance(caller, UserCaller)  # the operation accepts no system purpose
            is_active = lock_user_is_active(session, user_id, exclusive=True)
            if is_active is None:
                raise PlatformSubjectNotFoundError(user_id)
            if is_active:
                raise InvalidUserStateError(user_id, "active")
            sessions_revoked = _revoke_sessions(session, user_id)
            keys = revoke_user_api_keys_in_transaction(session, user_id)
            session.execute(update(User).where(User.id == user_id).values(is_active=True))
            session.flush()
            _record_success(
                session,
                caller=caller,
                operation=USER_REACTIVATE,
                user_id=user_id,
                reason=reason,
                metadata={
                    "sessions_revoked": sessions_revoked,
                    "api_keys_revoked": len(keys),
                    "tenants_affected": len({tenant_id for _, tenant_id in keys}),
                },
            )
            record_platform_key_revocations(session, caller=caller, user_id=user_id, keys=keys)
            return UserDeactivationResult(
                user_id=user_id, sessions_revoked=sessions_revoked, api_keys_revoked=len(keys)
            )

    return _run(USER_REACTIVATE, caller, user_id, body)
