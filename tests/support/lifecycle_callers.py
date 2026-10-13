"""Callers for test setup of the tenant lifecycle and feature flags
(ADR-0045 Phase C).

Since Phase C, `create_tenant`, `move_tenant`, `transition_tenant_status`
and the feature-flag mutations take a required `caller` and authorize it
through the platform chokepoint. A test whose subject is something else
still has to create, suspend, delete or move a tenant to set its scene.
This module gives such a test the caller the operation accepts, and
nothing wider:

- `PROVISIONING` -- for what provisioning may do: create a root tenant or
  a child of a `PENDING` tenant, activate a `PENDING` tenant, define a
  flag;
- `TENANT_PURGE` -- for the `PURGING` and `PURGED` transitions only;
- `platform_operator()` -- an enrolled platform operator, for everything
  that requires a person: suspend, reactivate, delete, move, a child
  beneath an `ACTIVE` tenant, a flag override.

It is on `sys.path` through `pythonpath` in `pyproject.toml`. The tests
*of* these authorization rules do not use `platform_operator()`'s default:
they enroll operators holding exactly the permission under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import create_user
from saas_os.core.platform_authority import (
    PlatformPermission,
    enroll_operator,
    grant_platform_permission,
    platform_can,
)

PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
TENANT_PURGE = SystemCaller(SystemAuthority.TENANT_PURGE)

_BOOTSTRAP = SystemCaller(SystemAuthority.PLATFORM_BOOTSTRAP)
_REASON = "test setup"

# Everything except `platform.authority:manage`: the shared operator is
# never a platform owner, so it cannot disturb a test of the last-owner
# invariant and cannot change who holds platform authority.
_LIFECYCLE_PERMISSIONS: tuple[PlatformPermission, ...] = tuple(
    permission
    for permission in PlatformPermission
    if permission is not PlatformPermission.AUTHORITY_MANAGE
)

_shared: UserCaller | None = None


def enroll_test_operator(permissions: Sequence[PlatformPermission]) -> UserCaller:
    """A new user, enrolled as an active operator holding exactly
    `permissions`, through the ordinary enroll and grant operations acting
    with the bootstrap-and-recovery purpose (which the operation table
    accepts for exactly those two). The operator's rows are never deleted:
    the runtime role cannot delete platform rows, and these tests run
    against disposable databases."""
    user_id = create_user().id
    operator = enroll_operator(user_id, caller=_BOOTSTRAP, reason=_REASON)
    for permission in permissions:
        grant_platform_permission(operator.id, permission, caller=_BOOTSTRAP, reason=_REASON)
    return UserCaller(user_id)


def platform_operator() -> UserCaller:
    """An operator holding every platform permission except
    `platform.authority:manage`, shared by the tests of one process.

    The platform-authority tests start from, and leave behind, empty
    platform tables, so the shared operator can disappear between two
    calls; it is checked on every call and enrolled again when it no
    longer holds authority."""
    global _shared
    if _shared is None or not platform_can(
        user_id=_shared.user_id, permission=PlatformPermission.TENANT_DELETE
    ):
        _shared = enroll_test_operator(_LIFECYCLE_PERMISSIONS)
    return _shared


def platform_operator_id() -> uuid.UUID:
    """The shared operator's user id, for a test that asserts who an
    audit row names."""
    return platform_operator().user_id


def caller_for_transition(target: object) -> SystemCaller | UserCaller:
    """The caller a transition into `target` accepts, for a test that
    walks the lifecycle with a variable target: the purge authority for
    `PURGING` and `PURGED`, the shared operator for everything else (it
    may activate, reactivate, suspend and delete)."""
    if str(getattr(target, "value", target)) in ("purging", "purged"):
        return TENANT_PURGE
    return platform_operator()
