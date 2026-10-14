"""Typed errors for `saas_os.core.platform_authority`
(docs/ADR/0045-installation-scoped-platform-authority.md).

Two families:

- `PlatformRefusalError` and its subclasses: the operation was refused as
  a matter of authority. Each carries a short, fixed `code` that is what
  the refusal's `denied` platform audit row records. Raised inside the
  operation's own transaction, so everything the operation wrote is rolled
  back.
- State and input errors (`LookupError`/`ValueError` subclasses): the
  caller was authorized, and the request does not fit the current state.

`OversightReadTimeoutError` belongs to neither: an authorized oversight
read that the database did not finish in time.

Messages carry identifiers only: never a credential, never an identity
provider issuer or subject.
"""

from __future__ import annotations

import uuid


class PlatformRefusalError(PermissionError):
    """Base class: a platform operation refused for want of authority, or
    because performing it would break an authority invariant."""

    code = "refused"

    def __init__(self, operation: str, message: str) -> None:
        # `operation` is a declared operation key or one of the closed set
        # of refusal labels that are not operations, and nothing else
        # (`operations.NON_OPERATION_REFUSALS`). Anything else is a
        # programming error and is raised as one, like an unknown key at
        # `platform_operation()`: it is never turned into a refusal.
        from saas_os.core.platform_authority.operations import is_refusal_label

        if not is_refusal_label(operation):
            raise UnknownPlatformOperationError(operation)
        self.operation = operation
        super().__init__(message)


class PlatformNotAuthorizedError(PlatformRefusalError):
    """The caller does not hold the platform permission the operation
    requires, is not an active operator, is an inactive user, is a service
    account, or is a `SystemCaller` whose purpose the operation does not
    accept. The cases are deliberately not distinguished."""

    code = "not_authorized"

    def __init__(self, operation: str) -> None:
        super().__init__(operation, f"Caller is not authorized for platform operation {operation}.")


class SelfAuthorityChangeError(PlatformRefusalError):
    """No self-service: an operator may not enroll, suspend, reactivate or
    revoke their own operator, and may not grant to or revoke from it.
    A second owner or the recovery command does it."""

    code = "self_authority_change"

    def __init__(self, operation: str) -> None:
        super().__init__(
            operation, f"Platform operation {operation} may not target the caller's own authority."
        )


class PlatformAmplificationError(PlatformRefusalError):
    """Anti-amplification: a caller may grant only a platform permission
    they themselves hold."""

    code = "amplification"

    def __init__(self, operation: str, permission: str) -> None:
        self.permission = permission
        super().__init__(
            operation, f"Caller may not grant {permission}: the caller does not hold it."
        )


class LastPlatformOwnerError(PlatformRefusalError):
    """The change would leave the deployment with no active platform owner
    (an active operator, of an active user, holding
    `platform.authority:manage`). Raised after the change was flushed and
    found to have emptied the owner set; the transaction rolls back, so
    nothing changed and nothing is recorded as done."""

    code = "last_platform_owner"

    def __init__(self, operation: str) -> None:
        super().__init__(
            operation,
            f"Platform operation {operation} would remove the last active platform owner.",
        )


class EnrolledOperatorErasureError(PlatformRefusalError):
    """Identity erasure of a user who has a platform operator row that is
    not revoked (ADR-0045 section 6). Erasing the identity would end that
    person's access without passing through the last-owner invariant, so
    it is refused until the operator is revoked through a guarded path.
    Raised before anything is erased."""

    code = "enrolled_operator"

    def __init__(self, operation: str) -> None:
        super().__init__(
            operation,
            f"Platform operation {operation} is refused: the user is an enrolled platform "
            "operator. Revoke the operator first.",
        )


class PlatformSubjectNotLinkedError(PlatformRefusalError):
    """The user to be enrolled as a platform operator is linked to no
    external identity, so nobody could log in as them (ADR-0045 section 6,
    as amended 2026-10-14). An erased user is one: identity erasure removes
    the link and keeps the user. Enrolling such a user would create an
    operator -- possibly an owner -- that exists in every count and that no
    person can use."""

    code = "subject_not_linked"

    def __init__(self, operation: str, user_id: uuid.UUID) -> None:
        self.user_id = user_id
        super().__init__(
            operation,
            f"User {user_id} is linked to no external identity and cannot be enrolled.",
        )


class PlatformSelfTargetError(PlatformRefusalError):
    """A caller may not deactivate their own user (ADR-0045 section 11b).
    Checked in the Core function, so it holds for every entry point."""

    code = "self_target"

    def __init__(self, operation: str) -> None:
        super().__init__(
            operation, f"Platform operation {operation} may not target the caller's own user."
        )


class TenantParentRuleError(PlatformRefusalError):
    """The parent rule for tenant creation (ADR-0045 section 12a): the
    parent's status, read under lock, does not admit a child from this
    caller. `code` is one of `parent_active_requires_operator`,
    `parent_suspended`, `parent_closed`."""

    def __init__(self, operation: str, parent_id: uuid.UUID, status: str, code: str) -> None:
        self.parent_id = parent_id
        self.status = status
        self.code = code
        super().__init__(
            operation, f"Tenant {parent_id} is {status}; this caller may not attach a child to it."
        )


class MoveIntoCallerHierarchyError(PlatformRefusalError):
    """`move_tenant` refuses a caller who is a member of the new parent or
    of any of its ancestors (ADR-0045 section 7): the move would hand the
    caller tenant authority over the moved subtree."""

    code = "caller_in_new_parent_chain"

    def __init__(self, operation: str, new_parent_id: uuid.UUID) -> None:
        self.new_parent_id = new_parent_id
        super().__init__(
            operation,
            f"The caller is a member of tenant {new_parent_id} or of one of its ancestors.",
        )


class DeactivationScanLimitError(PlatformRefusalError):
    """The tenant registry holds more tenants than `deactivate_user` is
    configured to scan (ADR-0045 section 11c, ruling R1). Nothing changed:
    the scan is complete or the operation is refused, never partial."""

    code = "registry_scan_limit"

    def __init__(self, operation: str, ceiling: int) -> None:
        self.ceiling = ceiling
        super().__init__(
            operation,
            f"The tenant registry exceeds the deactivation scan ceiling of {ceiling} tenants.",
        )


class OversightReadTimeoutError(TimeoutError):
    """A transaction of an oversight read was cancelled by PostgreSQL: a
    statement, or its wait for a lock, ran longer than
    `PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS` (ADR-0045 section 9d).
    Nothing was returned and no completion row was written.

    `stage` says which transaction, and so what evidence exists:

    - `"attempt"`: the attempt transaction. No row of any kind was
      written and nothing was read.
    - `"read"`: the read transaction. The attempt row, committed before
      the read, remains, with no completion.

    Not a refusal: nothing was decided against the caller, who may repeat
    the call."""

    STAGE_ATTEMPT = "attempt"
    STAGE_READ = "read"

    def __init__(self, operation: str, timeout_ms: int, *, stage: str) -> None:
        if stage not in (self.STAGE_ATTEMPT, self.STAGE_READ):
            raise ValueError("stage must be 'attempt' or 'read'.")
        self.operation = operation
        self.timeout_ms = timeout_ms
        self.stage = stage
        super().__init__(
            f"Platform operation {operation} did not finish within its statement "
            f"timeout of {timeout_ms} ms ({stage} transaction)."
        )


class UnknownPlatformOperationError(LookupError):
    """A programming error: the operation key is not in the declared
    operation table -- or, where a refusal is being constructed, is
    neither such a key nor one of the declared refusal labels that are not
    operations. Never a refusal, never caught as one."""

    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(f"Unknown platform operation {operation!r}.")


class InvalidPlatformRequestError(ValueError):
    """An argument is malformed (a missing or oversized reason, a value
    that is not a platform permission). Raised before any read."""


class PlatformSubjectNotFoundError(LookupError):
    def __init__(self, user_id: uuid.UUID) -> None:
        self.user_id = user_id
        super().__init__(f"User {user_id} not found.")


class UserNotResolvedError(LookupError):
    """`resolve_user` was asked for an external identity that is linked to
    no user. The message never repeats the issuer or the subject."""

    def __init__(self) -> None:
        super().__init__("No user is linked to the given external identity.")


class InactivePlatformSubjectError(ValueError):
    """The user to be enrolled or granted to is deactivated."""

    def __init__(self, user_id: uuid.UUID) -> None:
        self.user_id = user_id
        super().__init__(f"User {user_id} is inactive and cannot be given platform authority.")


class PlatformOperatorNotFoundError(LookupError):
    def __init__(self, operator_id: uuid.UUID) -> None:
        self.operator_id = operator_id
        super().__init__(f"Platform operator {operator_id} not found.")


class PlatformOperatorAlreadyEnrolledError(ValueError):
    def __init__(self, user_id: uuid.UUID) -> None:
        self.user_id = user_id
        super().__init__(f"User {user_id} already has a platform operator that is not revoked.")


class InvalidPlatformOperatorStateError(ValueError):
    """The operator's current status does not admit the transition."""

    def __init__(self, operator_id: uuid.UUID, status: str, operation: str) -> None:
        self.operator_id = operator_id
        self.status = status
        super().__init__(f"Platform operator {operator_id} is {status}; cannot {operation}.")


class PlatformGrantNotFoundError(LookupError):
    def __init__(self, operator_id: uuid.UUID, permission: str) -> None:
        self.operator_id = operator_id
        self.permission = permission
        super().__init__(f"Platform operator {operator_id} holds no live grant of {permission}.")


class DuplicatePlatformGrantError(ValueError):
    def __init__(self, operator_id: uuid.UUID, permission: str) -> None:
        self.operator_id = operator_id
        self.permission = permission
        super().__init__(f"Platform operator {operator_id} already holds {permission}.")


class PlatformAlreadyBootstrappedError(ValueError):
    """Owner bootstrap runs once per deployment: a platform operator row
    already exists, in whatever status."""

    def __init__(self) -> None:
        super().__init__(
            "This deployment already has a platform operator; owner bootstrap runs only once. "
            "Use the recovery command."
        )
