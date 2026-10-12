"""The last-active-platform-owner invariant on the bootstrap and recovery
path, against a real PostgreSQL (ADR-0045 section 6, "Required concurrency
tests", cases 3 and 9 to 12).

Companion to `test_last_owner_concurrency_integration.py`, which holds
cases 1, 2 and 4 to 8 and explains the method: every interleaving is
forced with real PostgreSQL locks, two or three connections and a pause
gate, and the test waits until PostgreSQL itself reports one backend
blocked by the other. No sleeps.

 3. the last two owners removed concurrently ............ `test_case_03_*`
 9. forced `LastPlatformOwnerError` ...................... `test_case_09_*`
10. forced failure of the `denied` write ................. `test_case_10_*`
11. two concurrent bootstraps ............................ `test_case_11_*`
12. recovery suspending the sole owner ................... `test_case_12_*`

These are the cases in which the invariant's recheck itself refuses. With
people as callers it cannot: an actor who holds `platform.authority:manage`
is still an owner after removing somebody else, and self-change is
refused. The recovery path removes an owner without depending on any
owner's authority, so it is where `LastPlatformOwnerError` is reachable.

Nothing here is evidence about `deactivate_user` or `reactivate_user`,
which Phase B does not implement.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable

import pytest
from platform_helpers import (
    ALL_PERMISSIONS,
    BOOTSTRAP,
    REASON,
    Gate,
    PlatformWorld,
    join,
    run_first_then_second,
    start,
)
from sqlalchemy import Engine

import saas_os.core.platform_authority.audit as audit_module
from saas_os.core.authority import UserCaller
from saas_os.core.platform_authority import (
    LastPlatformOwnerError,
    PlatformAlreadyBootstrappedError,
    PlatformNotAuthorizedError,
    PlatformPermission,
    bootstrap_platform_owner,
    platform_can,
    recover_platform_authority,
    revoke_operator,
)

pytestmark = pytest.mark.integration

P = PlatformPermission
MANAGE = P.AUTHORITY_MANAGE


def _first_owner(platform: PlatformWorld) -> tuple[UserCaller, uuid.UUID]:
    """The first owner, through the real bootstrap."""
    user_id = platform.user()
    result = bootstrap_platform_owner(user_id, ALL_PERMISSIONS, caller=BOOTSTRAP, reason=REASON)
    return UserCaller(user_id), result.operator_id


# --- case 3: the last two owners removed concurrently ------------------------


@pytest.mark.parametrize("first_is_x", [True, False])
def test_case_03_two_concurrent_removals_of_the_last_two_owners_keep_one(
    platform: PlatformWorld, admin: Engine, gate: Callable[[str], Gate], first_is_x: bool
) -> None:
    """Two removals that do not depend on the removed owners' own
    authority (the recovery path), each suspending a different one of the
    last two owners. Both orderings. The later one empties the owner set
    and is refused with `LastPlatformOwnerError`."""
    _, operator_x = platform.owner()
    _, operator_y = platform.owner()
    platform.clear_audit()
    order = (operator_x, operator_y) if first_is_x else (operator_y, operator_x)

    def suspend(operator_id: uuid.UUID) -> object:
        return recover_platform_authority(
            caller=BOOTSTRAP, reason=REASON, suspend_operator_id=operator_id
        )

    first, second = run_first_then_second(
        admin, gate("first"), lambda: suspend(order[0]), lambda: suspend(order[1])
    )
    assert "result" in first, first
    assert isinstance(second.get("error"), LastPlatformOwnerError), second
    assert platform.owner_count() == 1
    assert platform.operator_status(order[0]) == "suspended"
    assert platform.operator_status(order[1]) == "active"
    (denied,) = platform.audit(outcome="denied")
    assert denied["reason"] == "last_platform_owner" and denied["actor_type"] == "system"
    assert len(platform.audit("platform.operator.suspend", "success")) == 1


@pytest.mark.parametrize("person_first", [True, False])
def test_case_03_a_person_and_the_recovery_path_removing_the_last_two_owners(
    platform: PlatformWorld, admin: Engine, gate: Callable[[str], Gate], person_first: bool
) -> None:
    """Owners B and C. B revokes C while recovery suspends B. If B goes
    first, recovery would remove the last owner and is refused by the
    invariant. If recovery goes first, B has lost its authority and is
    refused by authorization. One owner remains either way."""
    owner_b, operator_b = platform.owner()
    _, operator_c = platform.owner()
    platform.clear_audit()

    def person() -> object:
        return revoke_operator(operator_c, caller=owner_b, reason=REASON)

    def recovery() -> object:
        return recover_platform_authority(
            caller=BOOTSTRAP, reason=REASON, suspend_operator_id=operator_b
        )

    first, second = run_first_then_second(
        admin,
        gate("first"),
        person if person_first else recovery,
        recovery if person_first else person,
    )
    assert "result" in first, first
    expected = LastPlatformOwnerError if person_first else PlatformNotAuthorizedError
    assert isinstance(second.get("error"), expected), second
    assert platform.owner_count() == 1


# --- cases 9, 10, 12: the invariant refusing, and its evidence --------------------


def test_case_09_a_last_owner_refusal_changes_nothing_and_leaves_exactly_one_denied_row(
    platform: PlatformWorld,
) -> None:
    _, sole_owner = _first_owner(platform)
    platform.clear_audit()
    with pytest.raises(LastPlatformOwnerError):
        recover_platform_authority(caller=BOOTSTRAP, reason=REASON, suspend_operator_id=sole_owner)
    assert platform.operator_status(sole_owner) == "active"
    assert platform.owner_count() == 1
    assert platform.audit(outcome="success") == []  # the success row rolled back with the change
    (denied,) = platform.audit()
    assert denied["outcome"] == "denied" and denied["reason"] == "last_platform_owner"
    assert denied["action"] == "platform.operator.suspend"
    assert denied["actor_type"] == "system" and denied["system_authority"] == "platform_bootstrap"
    assert denied["target_id"] == str(sole_owner)


def test_case_10_a_failing_denied_write_does_not_hide_the_refusal(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, sole_owner = _first_owner(platform)
    platform.clear_audit()

    def broken_scope(*args: object, **kwargs: object) -> None:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(audit_module, "session_scope", broken_scope)
    with pytest.raises(LastPlatformOwnerError):
        recover_platform_authority(caller=BOOTSTRAP, reason=REASON, suspend_operator_id=sole_owner)
    monkeypatch.undo()
    assert platform.operator_status(sole_owner) == "active"
    assert platform.owner_count() == 1
    assert platform.audit_count() == 0


def test_case_12_recovery_cannot_suspend_the_sole_owner_without_a_replacement(
    platform: PlatformWorld,
) -> None:
    """...and can, atomically, with one: enroll, grant and suspend are one
    transaction, checked once at the end, so the deployment is never
    ownerless between two commands."""
    old_owner, old_operator = _first_owner(platform)
    with pytest.raises(LastPlatformOwnerError):
        recover_platform_authority(
            caller=BOOTSTRAP, reason=REASON, suspend_operator_id=old_operator
        )
    # A replacement that does not hold `platform.authority:manage` is not one.
    not_an_owner = platform.user()
    with pytest.raises(LastPlatformOwnerError):
        recover_platform_authority(
            caller=BOOTSTRAP,
            reason=REASON,
            enroll_user_id=not_an_owner,
            grant_permissions=[P.TENANT_READ],
            suspend_operator_id=old_operator,
        )
    assert platform.scalar("SELECT count(*) FROM core.platform_operators") == 1  # rolled back
    assert platform.operator_status(old_operator) == "active"

    replacement = platform.user()
    result = recover_platform_authority(
        caller=BOOTSTRAP,
        reason="owner compromised",
        enroll_user_id=replacement,
        grant_permissions=[MANAGE],
        suspend_operator_id=old_operator,
    )
    assert result.enrolled and result.granted == (MANAGE.value,)
    assert result.suspended_operator_id == old_operator
    assert platform.operator_status(old_operator) == "suspended"
    assert platform.owner_count() == 1
    assert platform_can(user_id=replacement, permission=MANAGE) is True
    assert platform_can(user_id=old_owner.user_id, permission=MANAGE) is False


# --- case 11: two concurrent bootstraps -------------------------------------------


def test_case_11_two_concurrent_bootstraps_of_different_users_enroll_exactly_one(
    platform: PlatformWorld,
) -> None:
    users = [platform.user(), platform.user()]
    barrier = threading.Barrier(2)

    def bootstrap(user_id: uuid.UUID) -> object:
        barrier.wait(timeout=30)
        return bootstrap_platform_owner(user_id, ALL_PERMISSIONS, caller=BOOTSTRAP, reason=REASON)

    threads = [start(lambda u=user: bootstrap(u), f"bootstrap-{i}") for i, user in enumerate(users)]
    for thread, _ in threads:
        join(thread)
    outcomes = [outcome for _, outcome in threads]
    assert sum("result" in outcome for outcome in outcomes) == 1, outcomes
    (refused,) = [outcome["error"] for outcome in outcomes if "error" in outcome]
    assert isinstance(refused, PlatformAlreadyBootstrappedError), refused
    assert platform.scalar("SELECT count(*) FROM core.platform_operators") == 1
    assert platform.scalar("SELECT count(*) FROM core.platform_grants") == len(ALL_PERMISSIONS)
    assert platform.owner_count() == 1


def test_case_11_two_concurrent_identical_bootstraps_create_the_owner_once(
    platform: PlatformWorld,
) -> None:
    user_id = platform.user()
    barrier = threading.Barrier(2)

    def bootstrap() -> object:
        barrier.wait(timeout=30)
        return bootstrap_platform_owner(user_id, ALL_PERMISSIONS, caller=BOOTSTRAP, reason=REASON)

    threads = [start(bootstrap, f"bootstrap-{i}") for i in range(2)]
    for thread, _ in threads:
        join(thread)
    results = [outcome["result"] for _, outcome in threads]
    assert sorted(result.created for result in results) == [False, True]
    assert results[0].operator_id == results[1].operator_id
    assert platform.scalar("SELECT count(*) FROM core.platform_operators") == 1
    assert platform.scalar("SELECT count(*) FROM core.platform_grants") == len(ALL_PERMISSIONS)
    assert len(platform.audit("platform.operator.enroll")) == 1  # the second run wrote nothing
