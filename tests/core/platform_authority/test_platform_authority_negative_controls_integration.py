"""Negative controls for platform authority, against a real PostgreSQL
(ADR-0045 Phase B; project protocol "Loop 5").

Each test deliberately removes one protection and shows the outcome the
protection exists to prevent. A security test that passes only while the
mechanism is present is stronger evidence than one that exercises the
happy path; these are the other half of that proof:

- authorization forced to allow ......... a stranger changes authority;
- the last-owner recheck removed ........ the sole owner is suspended;
- the platform-owners lock removed ...... two concurrent removals of the
  last two owners both commit, and the deployment has no owner;
- the lock removed, people as callers ... two owners revoking each other
  deadlock instead of being serialized;
- no-self-service removed ............... an operator revokes themselves;
- anti-amplification removed ............ an operator grants what they
  do not hold.

Nothing here weakens shipped code: every removal is a `monkeypatch` that
lasts for one test. Each test first shows the protection working, then
removes it.

Not covered here, and reported as not run: dropping the `REVOKE`s or the
row-level-security policy would need committed DDL on a shared database.
Those two properties are asserted directly, as the runtime role, in
`tests/infra/db/test_platform_authority_migration.py`.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import threading
import uuid
from typing import Any

import pytest
from platform_helpers import BOOTSTRAP, REASON, PlatformWorld, join, start
from sqlalchemy.exc import OperationalError

import saas_os.core.platform_authority.authorization as authorization_module
import saas_os.core.platform_authority.service as service_module
from saas_os.core.authority import UserCaller
from saas_os.core.platform_authority import (
    LastPlatformOwnerError,
    PlatformAmplificationError,
    PlatformNotAuthorizedError,
    PlatformPermission,
    SelfAuthorityChangeError,
    grant_platform_permission,
    recover_platform_authority,
    revoke_platform_permission,
    suspend_operator,
)

pytestmark = pytest.mark.integration

P = PlatformPermission
MANAGE = P.AUTHORITY_MANAGE


def test_without_authorization_a_stranger_can_change_platform_authority(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    platform.owner()
    _, target = platform.operator([])
    stranger = UserCaller(platform.user())
    with pytest.raises(PlatformNotAuthorizedError):
        suspend_operator(target, caller=stranger, reason=REASON)
    assert platform.operator_status(target) == "active"

    monkeypatch.setattr(authorization_module, "platform_can", lambda **kwargs: True)
    suspend_operator(target, caller=stranger, reason=REASON)
    assert platform.operator_status(target) == "suspended"  # what authorization prevents


def test_without_the_recheck_the_last_owner_can_be_removed(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, sole_owner = platform.owner()
    with pytest.raises(LastPlatformOwnerError):
        recover_platform_authority(caller=BOOTSTRAP, reason=REASON, suspend_operator_id=sole_owner)
    assert platform.owner_count() == 1

    monkeypatch.setattr(service_module, "platform_owner_exists", lambda session: True)
    recover_platform_authority(caller=BOOTSTRAP, reason=REASON, suspend_operator_id=sole_owner)
    assert platform.owner_count() == 0  # what the recheck prevents


def test_without_the_lock_two_concurrent_removals_leave_no_owner(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the lock, the second removal cannot even begin until the first
    has committed, and is then refused (`test_case_03_*`). Without it, both
    transactions run their recheck while the other's change is still
    uncommitted, both see an owner, and both commit."""
    _, operator_x = platform.owner()
    _, operator_y = platform.owner()
    monkeypatch.setattr(service_module, "lock_platform_owners", lambda session: None)

    real = service_module.platform_owner_exists
    both_rechecked = threading.Barrier(2)
    calls: dict[str, int] = {}

    def recheck_together(session: Any) -> bool:
        name = threading.current_thread().name
        calls[name] = calls.get(name, 0) + 1
        result = real(session)
        if calls[name] == 2:  # the recheck: hold the commit until both have run it
            both_rechecked.wait(timeout=30)
        return result

    monkeypatch.setattr(service_module, "platform_owner_exists", recheck_together)

    def suspend(operator_id: uuid.UUID) -> object:
        return recover_platform_authority(
            caller=BOOTSTRAP, reason=REASON, suspend_operator_id=operator_id
        )

    thread_x, outcome_x = start(lambda: suspend(operator_x), "x")
    thread_y, outcome_y = start(lambda: suspend(operator_y), "y")
    join(thread_x)
    join(thread_y)
    assert "result" in outcome_x and "result" in outcome_y, (outcome_x, outcome_y)
    assert platform.owner_count() == 0  # what the lock prevents


def test_without_the_lock_two_owners_revoking_each_other_deadlock(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-0045 predicted that without serialization both would commit. In
    this implementation they do not: each holds its own operator row
    `FOR SHARE` (its authorization) and needs the other's `FOR UPDATE`, so
    PostgreSQL detects a deadlock and aborts one. The invariant survives,
    but a caller receives a database error instead of a clean refusal.
    That is what the lock buys here: orderly serialization, and a refusal
    by authorization."""
    owner_a, operator_a = platform.owner()
    owner_b, operator_b = platform.owner()
    monkeypatch.setattr(service_module, "lock_platform_owners", lambda session: None)

    real = service_module.platform_owner_exists
    both_authorized = threading.Barrier(2)
    calls: dict[str, int] = {}

    def after_authorization(session: Any) -> bool:
        name = threading.current_thread().name
        calls[name] = calls.get(name, 0) + 1
        if calls[name] == 1:  # authorization (and its row locks) has just happened
            both_authorized.wait(timeout=30)
        return real(session)

    monkeypatch.setattr(service_module, "platform_owner_exists", after_authorization)

    thread_a, outcome_a = start(
        lambda: revoke_platform_permission(operator_b, MANAGE, caller=owner_a, reason=REASON), "a"
    )
    thread_b, outcome_b = start(
        lambda: revoke_platform_permission(operator_a, MANAGE, caller=owner_b, reason=REASON), "b"
    )
    join(thread_a)
    join(thread_b)
    errors = [outcome["error"] for outcome in (outcome_a, outcome_b) if "error" in outcome]
    assert len(errors) == 1, (outcome_a, outcome_b)
    assert isinstance(errors[0], OperationalError) and "deadlock detected" in str(errors[0])
    assert platform.owner_count() == 1


def test_without_the_self_service_rule_an_operator_removes_their_own_authority(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    platform.owner()
    owner, operator_id = platform.owner()
    with pytest.raises(SelfAuthorityChangeError):
        revoke_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)
    assert "platform.tenant:read" in platform.live_permissions(operator_id)

    monkeypatch.setattr(service_module, "_refuse_self", lambda *args: None)
    revoke_platform_permission(operator_id, P.TENANT_READ, caller=owner, reason=REASON)
    assert "platform.tenant:read" not in platform.live_permissions(operator_id)


def test_without_anti_amplification_an_operator_grants_what_they_do_not_hold(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    platform.owner()
    manager, _ = platform.operator([MANAGE])
    _, target = platform.operator([])
    with pytest.raises(PlatformAmplificationError):
        grant_platform_permission(target, P.TENANT_DELETE, caller=manager, reason=REASON)
    assert platform.live_permissions(target) == set()

    # `service.platform_can` is the anti-amplification check; authorization
    # itself (in `authorization`) is left intact.
    monkeypatch.setattr(service_module, "platform_can", lambda **kwargs: True)
    grant_platform_permission(target, P.TENANT_DELETE, caller=manager, reason=REASON)
    assert platform.live_permissions(target) == {"platform.tenant:delete"}
