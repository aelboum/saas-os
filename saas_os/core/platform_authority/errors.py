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


class UnknownPlatformOperationError(LookupError):
    """A programming error: the operation key is not in the declared
    operation table. Never a refusal, never caught as one."""

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
