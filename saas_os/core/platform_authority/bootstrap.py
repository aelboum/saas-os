"""Platform owner bootstrap and recovery
(docs/ADR/0045-installation-scoped-platform-authority.md section 6).

Two composite operations, each one transaction under the platform-owners
lock, each accepting exactly one caller: `SystemCaller(PLATFORM_BOOTSTRAP)`.
They are reached only from the operator command
(`python -m saas_os.api.platform_bootstrap`); no route, and no Core
function reachable from a route, constructs that purpose.

- `bootstrap_platform_owner()` enrolls the first owner and grants an
  explicit list of permissions. It runs once per deployment: it refuses if
  any platform operator row exists, in any status.
- `recover_platform_authority()` is the break-glass path, for lockout and
  for compromise. It may enroll, grant and suspend. It never revokes and
  never reactivates: suspension is reversible, so a mistaken recovery can
  be undone by an owner, and the evidence stays.

What the purpose reaches is narrow by construction: the declared operation
table accepts it for operator enrollment, grant creation and operator
suspension, and for nothing else. It is not provisioning.

**Neither is a security boundary.** Whoever can run the command holds the
deployment's database credentials and could write the rows directly,
without the lock and without the audit row. These functions make the
legitimate path the audited one. Every change they make is recorded in
`core.platform_audit_log` with actor type `system`, in the same
transaction.

The last-owner invariant applies to recovery like any other change:
suspending the only owner is refused unless the same call enrolls and
grants a replacement that holds `platform.authority:manage`.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from saas_os.core.authority import SystemAuthority, SystemCaller, require_caller
from saas_os.core.identity import (
    find_user_id_for_external_identity_in_transaction,
    get_or_create_user_id_for_external_identity_in_transaction,
)
from saas_os.core.platform_authority.audit import record_platform_refusal, validate_reason
from saas_os.core.platform_authority.authorization import platform_operation
from saas_os.core.platform_authority.errors import (
    InvalidPlatformOperatorStateError,
    InvalidPlatformRequestError,
    PlatformAlreadyBootstrappedError,
    PlatformNotAuthorizedError,
    PlatformRefusalError,
)
from saas_os.core.platform_authority.models import (
    OperatorStatus,
    PlatformGrant,
    PlatformOperator,
)
from saas_os.core.platform_authority.operations import (
    GRANT_CREATE,
    OPERATOR_ENROLL,
    OPERATOR_SUSPEND,
)
from saas_os.core.platform_authority.permissions import OWNER_PERMISSION, PlatformPermission
from saas_os.core.platform_authority.service import (
    authority_transaction,
    enroll_in_transaction,
    grant_in_transaction,
    suspend_in_transaction,
)
from saas_os.infra.db import Session, select

# Names of the two composites, for error messages only. They are not audit
# actions: the platform audit vocabulary is the declared operation table, and
# a refusal row reuses the action of the operation that was refused
# (ADR-0045 section 5b).
_BOOTSTRAP = "platform.bootstrap"
_RECOVER = "platform.recover"


_MAX_ISSUER_LENGTH = 2048  # core.external_identities.issuer String(2048)
_MAX_SUBJECT_LENGTH = 255  # core.external_identities.subject String(255)


@dataclass(frozen=True)
class OperatorIdentity:
    """The OIDC `(issuer, subject)` of a person to enroll, for a caller
    that has not resolved it to a user. The user is resolved -- and, for an
    identity this deployment has never seen, created -- **inside** the
    platform transaction, so a refused or failed operation leaves no user
    and no identity link behind.

    Neither value is a secret. Neither is ever written to the platform
    audit log, which records ids only.
    """

    issuer: str
    subject: str

    def __post_init__(self) -> None:
        for name, value, limit in (
            ("issuer", self.issuer, _MAX_ISSUER_LENGTH),
            ("subject", self.subject, _MAX_SUBJECT_LENGTH),
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > limit:
                raise InvalidPlatformRequestError(
                    f"{name} must be a non-empty string of at most {limit} characters."
                )


def _find_user(session: Session, subject: uuid.UUID | OperatorIdentity) -> uuid.UUID | None:
    """The user a subject names, without creating anything."""
    if isinstance(subject, OperatorIdentity):
        return find_user_id_for_external_identity_in_transaction(
            session, subject.issuer, subject.subject
        )
    return subject


def _resolve_user(session: Session, subject: uuid.UUID | OperatorIdentity) -> uuid.UUID:
    """The user a subject names, created in this transaction if the
    identity has never been seen. Rolled back with the transaction."""
    if isinstance(subject, OperatorIdentity):
        return get_or_create_user_id_for_external_identity_in_transaction(
            session, subject.issuer, subject.subject
        )
    return subject


def _require_subject(name: str, value: object) -> None:
    if not isinstance(value, (uuid.UUID, OperatorIdentity)):
        raise InvalidPlatformRequestError(f"{name} must be a uuid.UUID or an OperatorIdentity.")


@dataclass(frozen=True)
class PlatformBootstrapResult:
    operator_id: uuid.UUID
    user_id: uuid.UUID
    permissions: tuple[str, ...]
    # `False` for an identical second run, which changes nothing.
    created: bool


@dataclass(frozen=True)
class PlatformRecoveryResult:
    enrolled_operator_id: uuid.UUID | None
    enrolled_user_id: uuid.UUID | None
    # Whether the operator named by `enroll_user_id` was created by this
    # call (`False` when an active operator already existed and was reused).
    enrolled: bool
    granted: tuple[str, ...]
    suspended_operator_id: uuid.UUID | None

    @property
    def changed(self) -> bool:
        return self.enrolled or bool(self.granted) or self.suspended_operator_id is not None


def _require_bootstrap_caller(
    composite: str, caller: object, *, refused_operation: str, marker: str
) -> SystemCaller:
    """Only the bootstrap and recovery purpose. A person holding
    `platform.authority:manage` uses the ordinary operations, which apply
    no-self-service and anti-amplification; this path applies neither and
    is therefore closed to everyone else, explicitly.

    A system purpose other than `PLATFORM_BOOTSTRAP` is refused before
    anything is read, and the refusal is recorded: one `denied` row whose
    action is that of `refused_operation` -- the first declared operation
    the composite would have performed -- with `marker` in its metadata
    saying which composite was attempted. The row names the purpose that
    was presented (`system_authority`); it carries no identity, no user id
    and no credential.
    """
    require_caller(composite, caller, (SystemCaller,))
    assert isinstance(caller, SystemCaller)
    if caller.authority is not SystemAuthority.PLATFORM_BOOTSTRAP:
        record_platform_refusal(
            caller=caller,
            action=platform_operation(refused_operation).audit_action,
            target_type="platform_operator",
            code=PlatformNotAuthorizedError.code,
            metadata={marker: True},
        )
        raise PlatformNotAuthorizedError(composite)
    return caller


def _validated_permissions(
    permissions: Sequence[object], *, require_owner: bool
) -> tuple[PlatformPermission, ...]:
    if isinstance(permissions, (str, bytes)):
        raise InvalidPlatformRequestError("permissions must be a sequence of PlatformPermission.")
    values: list[PlatformPermission] = []
    for permission in permissions:
        if not isinstance(permission, PlatformPermission):
            raise InvalidPlatformRequestError(
                "every permission must be a PlatformPermission (no strings, no wildcards)."
            )
        values.append(permission)
    if len(set(values)) != len(values):
        raise InvalidPlatformRequestError("permissions must not contain duplicates.")
    if require_owner and OWNER_PERMISSION not in values:
        raise InvalidPlatformRequestError(
            f"the bootstrap permission list must include {OWNER_PERMISSION.value}: "
            "bootstrap must leave the deployment with a platform owner."
        )
    return tuple(values)


def _live_permissions(session: Session, operator_id: uuid.UUID) -> set[str]:
    return set(
        session.execute(
            select(PlatformGrant.permission).where(
                PlatformGrant.operator_id == operator_id, PlatformGrant.revoked_at.is_(None)
            )
        ).scalars()
    )


def bootstrap_platform_owner(
    owner: uuid.UUID | OperatorIdentity,
    permissions: Sequence[PlatformPermission],
    *,
    caller: object,
    reason: str,
) -> PlatformBootstrapResult:
    """Enroll `owner` as the first platform operator and grant exactly
    `permissions`, in one transaction.

    `owner` is a user id or an `OperatorIdentity`. An identity is resolved
    inside this transaction, after the "already bootstrapped" check, and a
    user is created for it only if the bootstrap is going ahead. Whatever
    happens next, the user, its identity link, the operator, the grants and
    the audit rows commit together or not at all: a refused or failed
    bootstrap creates nothing.

    `permissions` is the caller's explicit list. Nothing is added to it and
    nothing is implied by it; it must include `platform.authority:manage`.

    Refuses (`PlatformAlreadyBootstrappedError`) if any operator row
    exists, in any status -- except that an identical second run, finding
    exactly the operator and the live grants a first run would have
    created, changes nothing and returns `created=False`. The check runs
    under the platform-owners lock, so two concurrent runs cannot both
    enroll.
    """
    system_caller = _require_bootstrap_caller(
        _BOOTSTRAP, caller, refused_operation=OPERATOR_ENROLL, marker="bootstrap"
    )
    _require_subject("owner", owner)
    requested = _validated_permissions(permissions, require_owner=True)
    reason = validate_reason(reason)

    with authority_transaction((OPERATOR_ENROLL, GRANT_CREATE), system_caller) as session:
        existing = session.execute(
            select(PlatformOperator.id, PlatformOperator.user_id, PlatformOperator.status).limit(2)
        ).all()
        if existing:
            only = existing[0]
            # Read only: an identity that was never seen is not created just
            # to be told the deployment is already bootstrapped.
            known_user_id = _find_user(session, owner)
            if (
                len(existing) == 1
                and known_user_id is not None
                and only.user_id == known_user_id
                and only.status == OperatorStatus.ACTIVE.value
                and _live_permissions(session, only.id) == {p.value for p in requested}
            ):
                return PlatformBootstrapResult(
                    operator_id=only.id,
                    user_id=known_user_id,
                    permissions=tuple(p.value for p in requested),
                    created=False,
                )
            raise PlatformAlreadyBootstrappedError()
        user_id = _resolve_user(session, owner)
        operator = enroll_in_transaction(
            session, caller=system_caller, user_id=user_id, reason=reason
        )
        for permission in requested:
            grant_in_transaction(
                session,
                caller=system_caller,
                operator_id=operator.id,
                permission=permission,
                reason=reason,
            )
        return PlatformBootstrapResult(
            operator_id=operator.id,
            user_id=user_id,
            permissions=tuple(p.value for p in requested),
            created=True,
        )


def recover_platform_authority(
    *,
    caller: object,
    reason: str,
    enroll_user_id: uuid.UUID | None = None,
    enroll_identity: OperatorIdentity | None = None,
    grant_permissions: Sequence[PlatformPermission] = (),
    suspend_operator_id: uuid.UUID | None = None,
) -> PlatformRecoveryResult:
    """Break-glass recovery, in one transaction under the platform-owners
    lock, checked once at the end against the last-owner invariant.

    - `enroll_user_id` or `enroll_identity` (one of them): make this
      person an operator. An identity is resolved inside the transaction
      and a user is created for it only as part of that transaction, so a
      refused recovery leaves no user behind. An existing active
      operator for the person is reused; a suspended one is refused (recovery
      cannot reactivate -- an owner does that); a revoked one is history,
      and a new operator row is created.
    - `grant_permissions`: grant each of these to that operator, skipping
      any it already holds. Requires a person to enroll.
    - `suspend_operator_id`: suspend this operator. Already suspended is a
      no-op; revoked is an error.

    Suspending the only owner without, in the same call, enrolling and
    granting a replacement that holds `platform.authority:manage` raises
    `LastPlatformOwnerError`: nothing changes. It never revokes, never
    deletes and never reactivates.
    """
    # The first operation this call asks for, judged from which arguments
    # are present; nothing is validated or read before the caller is.
    if enroll_user_id is not None or enroll_identity is not None:
        first_requested = OPERATOR_ENROLL
    elif suspend_operator_id is not None:
        first_requested = OPERATOR_SUSPEND
    else:
        first_requested = GRANT_CREATE if grant_permissions else OPERATOR_ENROLL
    system_caller = _require_bootstrap_caller(
        _RECOVER, caller, refused_operation=first_requested, marker="recovery"
    )
    reason = validate_reason(reason)
    requested = _validated_permissions(grant_permissions, require_owner=False)
    if enroll_user_id is not None and enroll_identity is not None:
        raise InvalidPlatformRequestError("give enroll_user_id or enroll_identity, not both.")
    for name, value in (
        ("enroll_user_id", enroll_user_id),
        ("suspend_operator_id", suspend_operator_id),
    ):
        if value is not None and not isinstance(value, uuid.UUID):
            raise InvalidPlatformRequestError(f"{name} must be a uuid.UUID.")
    if enroll_identity is not None and not isinstance(enroll_identity, OperatorIdentity):
        raise InvalidPlatformRequestError("enroll_identity must be an OperatorIdentity.")
    enroll: uuid.UUID | OperatorIdentity | None = (
        enroll_user_id if enroll_user_id is not None else enroll_identity
    )
    if enroll is None and suspend_operator_id is None:
        raise InvalidPlatformRequestError(
            "recovery must enroll an operator, suspend an operator, or both."
        )
    if requested and enroll is None:
        raise InvalidPlatformRequestError("grant_permissions requires a person to enroll.")

    operations: list[str] = []
    if enroll is not None:
        operations.append(OPERATOR_ENROLL)
    if requested:
        operations.append(GRANT_CREATE)
    if suspend_operator_id is not None:
        operations.append(OPERATOR_SUSPEND)

    try:
        with authority_transaction(operations, system_caller) as session:
            return _recover(
                session,
                caller=system_caller,
                reason=reason,
                enroll=enroll,
                requested=requested,
                suspend_operator_id=suspend_operator_id,
            )
    except PlatformRefusalError as refusal:
        record_platform_refusal(
            caller=system_caller,
            action=platform_operation(operations[-1]).audit_action,
            target_type="platform_operator",
            target_id=str(suspend_operator_id) if suspend_operator_id is not None else None,
            code=refusal.code,
            metadata={"recovery": True},
        )
        raise


def _recover(
    session: Session,
    *,
    caller: SystemCaller,
    reason: str,
    enroll: uuid.UUID | OperatorIdentity | None,
    requested: tuple[PlatformPermission, ...],
    suspend_operator_id: uuid.UUID | None,
) -> PlatformRecoveryResult:
    enrolled_operator_id: uuid.UUID | None = None
    enroll_user_id: uuid.UUID | None = None
    enrolled = False
    granted: list[str] = []
    if enroll is not None:
        # Created here, in this transaction, if the identity is new: rolled
        # back with everything else if the recovery is refused below.
        enroll_user_id = _resolve_user(session, enroll)
        current = session.execute(
            select(PlatformOperator.id, PlatformOperator.status)
            .where(
                PlatformOperator.user_id == enroll_user_id,
                PlatformOperator.status != OperatorStatus.REVOKED.value,
            )
            .with_for_update()
        ).one_or_none()
        if current is None:
            operator = enroll_in_transaction(
                session, caller=caller, user_id=enroll_user_id, reason=reason
            )
            operator_id: uuid.UUID = operator.id
            enrolled = True
        elif current.status == OperatorStatus.ACTIVE.value:
            operator_id = current.id
        else:
            raise InvalidPlatformOperatorStateError(current.id, current.status, OPERATOR_ENROLL)
        enrolled_operator_id = operator_id
        held = _live_permissions(session, operator_id)
        for permission in requested:
            if permission.value in held:
                continue
            grant_in_transaction(
                session,
                caller=caller,
                operator_id=operator_id,
                permission=permission,
                reason=reason,
            )
            granted.append(permission.value)

    suspended: uuid.UUID | None = None
    if suspend_operator_id is not None:
        status = session.execute(
            select(PlatformOperator.status)
            .where(PlatformOperator.id == suspend_operator_id)
            .with_for_update()
        ).scalar_one_or_none()
        if status != OperatorStatus.SUSPENDED.value:
            # Not found and revoked are reported by the shared helper.
            suspend_in_transaction(
                session, caller=caller, operator_id=suspend_operator_id, reason=reason
            )
            suspended = suspend_operator_id

    return PlatformRecoveryResult(
        enrolled_operator_id=enrolled_operator_id,
        enrolled_user_id=enroll_user_id,
        enrolled=enrolled,
        granted=tuple(granted),
        suspended_operator_id=suspended,
    )
