"""Typed callers (Foundation Authority & Evidence;
docs/ADR/0031-foundation-authority-and-evidence.md).

Each type is a frozen dataclass that validates its own fields at
construction, so a caller can never carry a string, `None` or a bare
boolean where an identity belongs. `require_caller()` is the runtime guard
every authority-changing Core function applies to its `caller` argument
before doing anything else: Python does not enforce annotations, and a
missing or wrongly-typed caller must fail closed with a typed error, never
fall back to some default authority.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass


class CallerTypeError(TypeError):
    """The `caller` argument is missing or is not one of the caller types
    the operation accepts. Raised before any authorization or write."""

    def __init__(self, operation: str, caller: object, allowed: tuple[type, ...]) -> None:
        self.operation = operation
        self.allowed = allowed
        names = ", ".join(cls.__name__ for cls in allowed)
        super().__init__(
            f"{operation} requires an explicit caller of type {names}; got {type(caller).__name__}."
        )


class SystemAuthority(enum.StrEnum):
    """The named purposes for which platform code may act with no human or
    service-account principal. Deliberately few: an operation accepts a
    `SystemCaller` only for the purposes it lists.

    PROVISIONING  creating a tenant's initial authority structure before
                  any principal in it could hold authority (the
                  first-tenant bootstrap command, a consumer's own
                  provisioning/seed code, test fixtures).
    TENANT_PURGE  winding down a tenant that is being purged, when the
                  purge itself has no acting user.
    """

    PROVISIONING = "provisioning"
    TENANT_PURGE = "tenant_purge"


def _require_uuid(field: str, value: object) -> None:
    if not isinstance(value, uuid.UUID):
        raise TypeError(f"{field} must be a uuid.UUID, got {type(value).__name__}.")


@dataclass(frozen=True)
class UserCaller:
    """A `core.identity` User acting as themselves. Whether the user is
    active, and what they may do, is decided by `core.rbac` at call time
    -- this type only names them."""

    user_id: uuid.UUID

    def __post_init__(self) -> None:
        _require_uuid("user_id", self.user_id)


@dataclass(frozen=True)
class ServiceAccountCaller:
    """A `core.identity` ServiceAccount. `tenant_id` is the service
    account's own fixed tenant (what `core.rbac.can()` calls
    `actor_tenant_id`), not the tenant an operation targets."""

    service_account_id: uuid.UUID
    tenant_id: uuid.UUID

    def __post_init__(self) -> None:
        _require_uuid("service_account_id", self.service_account_id)
        _require_uuid("tenant_id", self.tenant_id)


@dataclass(frozen=True)
class SystemCaller:
    """Explicit platform authority for exactly one `SystemAuthority`
    purpose. Recorded in the audit log as `ActorType.SYSTEM` with the
    purpose in the entry's metadata."""

    authority: SystemAuthority

    def __post_init__(self) -> None:
        if not isinstance(self.authority, SystemAuthority):
            raise TypeError(
                f"authority must be a SystemAuthority, got {type(self.authority).__name__}."
            )


PrincipalCaller = UserCaller | ServiceAccountCaller
Caller = UserCaller | ServiceAccountCaller | SystemCaller

_ALL_CALLER_TYPES: tuple[type, ...] = (UserCaller, ServiceAccountCaller, SystemCaller)


def require_caller(
    operation: str, caller: object, allowed: tuple[type, ...] = _ALL_CALLER_TYPES
) -> None:
    """Fail closed with `CallerTypeError` unless `caller` is an instance of
    one of `allowed` (exact caller types; never a subclass of anything
    else, never `None`)."""
    if type(caller) not in allowed:
        raise CallerTypeError(operation, caller, allowed)
