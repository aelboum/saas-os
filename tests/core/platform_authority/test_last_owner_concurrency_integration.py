"""The last-active-platform-owner invariant under concurrency, against a
real PostgreSQL (ADR-0045 section 6, "Required concurrency tests").

*After every supported change, a deployment that had a platform owner
still has one.*

Every interleaving is forced with real PostgreSQL locks, two or three
connections and thread events -- never a sleep or a timing guess. A pause
gate stops one transaction after its change is flushed and before its
audit row and COMMIT; the test then waits until PostgreSQL itself reports
the other backend blocked by that one (`pg_blocking_pids`).

The twelve cases of the ADR's table, and where each is here:

 1. two owners each removing the other's authority ...... `test_case_01_*`
 2. the same for every pair of removal operations ....... `test_case_02_*`
 3. the last two owners removed concurrently ............ (recovery file)
 4. ordering A: removal commits, then a mutation by the
    removed owner ........................................ `test_case_04_*`
 5. ordering B: a mutation holds its decision locks, then
    removal starts ....................................... `test_case_05_*`
 6. the platform lock composed with ADR-0043 tenant-
    administrator locks, against a guarded removal ....... `test_case_06_*`
 7. a deliberately inverted lock order ................... `test_case_07_*`
 8. forced failure after the mutation, before commit ..... `test_case_08_*`
 9. forced `LastPlatformOwnerError` ...................... (recovery file)
10. forced failure of the `denied` write ................. (recovery file)
11. two concurrent bootstraps ............................ (recovery file)
12. recovery suspending the sole owner ................... (recovery file)

Cases 3 and 9 to 12 remove or create an owner through the bootstrap and
recovery path and live in
`test_last_owner_recovery_concurrency_integration.py`. The seven cases here
use only the ordinary operator and grant operations.

Two honest limits, stated here so nobody reads more into a green run:

- **Case 6 is a lock-order emulation.** ADR-0045's row is about
  `deactivate_user`, which Phase B does not implement. The test runs a
  test-only transaction that takes locks in the order `deactivate_user` is
  specified to take them, against a real ADR-0043-guarded mutation. It
  shows the stated order composes without a deadlock. It is not evidence
  about `deactivate_user`, whose six race tests and the tenant-move case
  remain a Phase C gate.
- **User deactivation as a way to remove an owner is not covered**, because
  no Core function deactivates a user in Phase B. `is_active` changed by
  direct SQL takes no lock and is outside the invariant (tier 0).

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from platform_helpers import (
    ALL_PERMISSIONS,
    REASON,
    Gate,
    PlatformWorld,
    join,
    run_first_then_second,
    start,
    wait_until_blocked_by,
)
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError

import saas_os.core.identity.service as identity_service
import saas_os.core.platform_authority.service as service_module
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import add_tenant_membership, lock_user_is_active, suspend_membership
from saas_os.core.platform_authority import (
    PlatformNotAuthorizedError,
    PlatformPermission,
    grant_platform_permission,
    platform_can,
    revoke_operator,
    revoke_platform_permission,
    suspend_operator,
)
from saas_os.core.platform_authority.owners import lock_platform_owners
from saas_os.core.rbac import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.core.rbac.administrators import guard_tenants
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db import session_scope

pytestmark = pytest.mark.integration

P = PlatformPermission
MANAGE = P.AUTHORITY_MANAGE
PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

Removal = Callable[[uuid.UUID, UserCaller], object]

# The three implemented ways a person can remove another owner.
REMOVALS: dict[str, Removal] = {
    "grant_revoke": lambda operator_id, caller: revoke_platform_permission(
        operator_id, MANAGE, caller=caller, reason=REASON
    ),
    "operator_suspend": lambda operator_id, caller: suspend_operator(
        operator_id, caller=caller, reason=REASON
    ),
    "operator_revoke": lambda operator_id, caller: revoke_operator(
        operator_id, caller=caller, reason=REASON
    ),
}
_REMOVAL_ACTIONS = (
    "platform.grant.revoke",
    "platform.operator.suspend",
    "platform.operator.revoke",
)


def _removal_rows(platform: PlatformWorld, outcome: str) -> list[dict[str, Any]]:
    return [row for row in platform.audit(outcome=outcome) if row["action"] in _REMOVAL_ACTIONS]


# --- case 1: two owners, each removing the other, started together -----------


@pytest.mark.parametrize("removal", sorted(REMOVALS))
def test_case_01_two_owners_removing_each_other_together_leave_exactly_one(
    platform: PlatformWorld, removal: str
) -> None:
    """Started together behind a barrier, no forced order. Exactly one
    commits. The other is refused by authorization -- its own authority is
    gone by the time it holds the lock -- not by a database error."""
    owner_a, operator_a = platform.owner()
    owner_b, operator_b = platform.owner()
    platform.clear_audit()
    barrier = threading.Barrier(2)

    def run(target: uuid.UUID, caller: UserCaller) -> object:
        barrier.wait(timeout=30)
        return REMOVALS[removal](target, caller)

    thread_a, outcome_a = start(lambda: run(operator_b, owner_a), "a")
    thread_b, outcome_b = start(lambda: run(operator_a, owner_b), "b")
    join(thread_a)
    join(thread_b)

    outcomes = [outcome_a, outcome_b]
    assert sum("result" in outcome for outcome in outcomes) == 1, outcomes
    (refused,) = [outcome["error"] for outcome in outcomes if "error" in outcome]
    assert isinstance(refused, PlatformNotAuthorizedError), refused
    assert platform.owner_count() == 1
    assert len(_removal_rows(platform, "success")) == 1
    (denied,) = _removal_rows(platform, "denied")
    assert denied["reason"] == "not_authorized"


# --- case 2: every pair of removal operations, order forced ------------------


@pytest.mark.parametrize("second_removal", sorted(REMOVALS))
@pytest.mark.parametrize("first_removal", sorted(REMOVALS))
def test_case_02_every_pair_of_removals_leaves_exactly_one_owner(
    platform: PlatformWorld,
    admin: Engine,
    gate: Callable[[str], Gate],
    first_removal: str,
    second_removal: str,
) -> None:
    """A removes B while B removes A, for all nine ordered pairs of
    (grant revoke, operator suspend, operator revoke). The first holds the
    platform-owners lock; PostgreSQL reports the second blocked on it; the
    first commits; the second is then judged against what the first
    committed and refused."""
    owner_a, operator_a = platform.owner()
    owner_b, operator_b = platform.owner()
    platform.clear_audit()

    first, second = run_first_then_second(
        admin,
        gate("first"),
        lambda: REMOVALS[first_removal](operator_b, owner_a),
        lambda: REMOVALS[second_removal](operator_a, owner_b),
    )
    assert "result" in first, first
    assert isinstance(second.get("error"), PlatformNotAuthorizedError), second
    assert platform.owner_count() == 1
    assert platform_can(user_id=owner_a.user_id, permission=MANAGE) is True
    assert platform_can(user_id=owner_b.user_id, permission=MANAGE) is False
    assert len(_removal_rows(platform, "success")) == 1
    assert [row["reason"] for row in _removal_rows(platform, "denied")] == ["not_authorized"]


# --- case 4: ordering A -- removal commits, then the removed owner acts ---------


@pytest.mark.parametrize("removal", sorted(REMOVALS))
def test_case_04_a_mutation_by_an_owner_removed_first_is_refused(
    platform: PlatformWorld, admin: Engine, gate: Callable[[str], Gate], removal: str
) -> None:
    owner_a, _ = platform.owner()
    owner_b, operator_b = platform.owner()
    _, target = platform.operator([])
    platform.clear_audit()

    first, second = run_first_then_second(
        admin,
        gate("first"),
        lambda: REMOVALS[removal](operator_b, owner_a),
        lambda: grant_platform_permission(target, P.TENANT_READ, caller=owner_b, reason=REASON),
    )
    assert "result" in first, first
    assert isinstance(second.get("error"), PlatformNotAuthorizedError), second
    assert platform.live_permissions(target) == set()  # nothing was written
    assert platform.audit("platform.grant.create", "success") == []
    assert len(platform.audit("platform.grant.create", "denied")) == 1


def test_case_04_a_decision_waits_for_an_uncommitted_removal_and_then_observes_it(
    platform: PlatformWorld, admin: Engine, gate: Callable[[str], Gate]
) -> None:
    """The same ordering for a transaction that only evaluates
    `platform_can()` -- the shape every later platform mutation has. It
    takes no advisory lock; it waits on the operator row the removal has
    locked, and then reads the committed state."""
    owner_a, _ = platform.owner()
    owner_b, operator_b = platform.owner()

    def decide() -> bool:
        with session_scope() as session:
            return platform_can(user_id=owner_b.user_id, permission=P.TENANT_READ, session=session)

    first, second = run_first_then_second(
        admin,
        gate("first"),
        lambda: suspend_operator(operator_b, caller=owner_a, reason=REASON),
        decide,
    )
    assert "result" in first, first
    assert second.get("result") is False, second


# --- case 5: ordering B -- a mutation holds its decision locks first -------------


@pytest.mark.parametrize("removal", sorted(REMOVALS))
def test_case_05_a_removal_waits_for_a_mutation_in_flight_and_the_mutation_stands(
    platform: PlatformWorld, admin: Engine, gate: Callable[[str], Gate], removal: str
) -> None:
    owner_a, _ = platform.owner()
    owner_b, operator_b = platform.owner()
    _, target = platform.operator([])
    platform.clear_audit()

    first, second = run_first_then_second(
        admin,
        gate("first"),
        lambda: grant_platform_permission(target, P.TENANT_READ, caller=owner_b, reason=REASON),
        lambda: REMOVALS[removal](operator_b, owner_a),
    )
    assert "result" in first and "result" in second, (first, second)
    assert platform.live_permissions(target) == {"platform.tenant:read"}  # the mutation stands
    assert platform_can(user_id=owner_b.user_id, permission=MANAGE) is False  # then removed
    assert platform.owner_count() == 1
    assert len(platform.audit("platform.grant.create", "success")) == 1


@pytest.mark.parametrize("removal", sorted(REMOVALS))
def test_case_05_a_removal_waits_for_a_transaction_holding_only_decision_row_locks(
    platform: PlatformWorld, admin: Engine, removal: str
) -> None:
    """No advisory lock on the first side: only the `FOR SHARE` locks
    `platform_can(session=...)` takes on the user, operator and grant
    rows. The removal must wait for them (ADR-0031 section 3a, applied to
    platform authority) and take effect for the next decision."""
    owner_a, _ = platform.owner()
    owner_b, operator_b = platform.owner()
    with session_scope() as holder:
        assert platform_can(user_id=owner_b.user_id, permission=MANAGE, session=holder) is True
        pid = holder.execute(text("SELECT pg_backend_pid()")).scalar_one()
        thread, outcome = start(lambda: REMOVALS[removal](operator_b, owner_a), "removal")
        wait_until_blocked_by(admin, pid)
        assert "result" not in outcome and "error" not in outcome  # still waiting
        # The decision made inside this transaction is still true here.
        assert platform_can(user_id=owner_b.user_id, permission=MANAGE, session=holder) is True
    join(thread)
    assert "result" in outcome, outcome
    assert platform_can(user_id=owner_b.user_id, permission=MANAGE) is False


# --- case 6: lock order composed with ADR-0043 administrator locks ---------------


@pytest.fixture
def hierarchy(platform: PlatformWorld) -> Iterator[dict[str, Any]]:
    """A root tenant and a child, each with an administrator, and in the
    child one ordinary member whose membership a guarded mutation can
    suspend."""
    root = create_tenant(f"lo-root-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id
    child = create_tenant(
        f"lo-child-{uuid.uuid4().hex[:8]}", parent_id=root, caller=PROVISIONING
    ).id
    permission = register_permission("membership", "suspend")
    assign = register_permission("membership_role", "create")
    world: dict[str, Any] = {"root": root, "child": child}
    for tenant_id in (root, child):
        admin_user = platform.user()
        membership = add_tenant_membership(tenant_id, admin_user, caller=PROVISIONING)
        role = create_role(tenant_id, "admin", caller=PROVISIONING)
        grant_permission(tenant_id, role.id, permission.id, caller=PROVISIONING)
        grant_permission(tenant_id, role.id, assign.id, caller=PROVISIONING)
        assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=PROVISIONING)
        world[f"{'root' if tenant_id == root else 'child'}_admin"] = UserCaller(admin_user)
    member = platform.user()
    world["member_membership"] = add_tenant_membership(child, member, caller=PROVISIONING).id
    world["member"] = member
    try:
        yield world
    finally:
        for tenant_id in (child, root):
            for table in (
                "audit_log",
                "membership_roles",
                "role_permissions",
                "roles",
                "tenant_memberships",
                "tenant_ancestry",
            ):
                platform.execute(
                    f"DELETE FROM core.{table} WHERE tenant_id = :t",  # noqa: S608 -- fixed names
                    {"t": tenant_id},
                )
            platform.execute(
                "DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t", {"t": tenant_id}
            )
            platform.execute("DELETE FROM core.tenants WHERE id = :t", {"t": tenant_id})


def _emulated_deactivation_locks(world: dict[str, Any], reached: threading.Event) -> str:
    """TEST-ONLY. The lock sequence ADR-0045 section 11c specifies for
    `deactivate_user`, with no deactivation: the platform-owners lock, the
    ADR-0043 administrator locks nearest the root first, then an exclusive
    lock on the user's row. Phase B ships no such operation."""
    with session_scope() as session:
        lock_platform_owners(session)
        guard = guard_tenants(session, [world["root"], world["child"]])
        lock_user_is_active(session, world["member"], exclusive=True)
        reached.set()
        guard.verify(session)
    return "done"


@pytest.mark.parametrize("guarded_first", [True, False])
def test_case_06_platform_lock_then_administrator_locks_composes_with_a_guarded_removal(
    platform: PlatformWorld,
    admin: Engine,
    hierarchy: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    guarded_first: bool,
) -> None:
    """Lock-order emulation (module docstring): no deadlock in either
    ordering when the platform-owners lock is taken before the
    administrator locks, and both invariants hold afterwards. Not a test
    of `deactivate_user`."""
    platform.owner()
    pause = Gate("guarded")
    real = identity_service.record_in_transaction

    def gated(session: Any, *args: Any, **kwargs: Any) -> Any:
        pause.checkpoint(session)
        return real(session, *args, **kwargs)

    monkeypatch.setattr(identity_service, "record_in_transaction", gated)
    reached = threading.Event()

    def guarded() -> object:
        return suspend_membership(
            hierarchy["child"], hierarchy["member_membership"], caller=hierarchy["child_admin"]
        )

    def emulation() -> object:
        return _emulated_deactivation_locks(hierarchy, reached)

    if guarded_first:
        guarded_thread, guarded_outcome = start(guarded, "guarded")
        assert pause.paused.wait(timeout=30)
        emulation_thread, emulation_outcome = start(emulation, "emulation")
        wait_until_blocked_by(admin, pause.pid)  # waits on the child's administrator lock
        pause.release.set()
    else:
        pause.release.set()  # the guarded mutation is not paused in this ordering
        with session_scope() as holder:
            lock_platform_owners(holder)
            guard_tenants(holder, [hierarchy["root"], hierarchy["child"]])
            pid = holder.execute(text("SELECT pg_backend_pid()")).scalar_one()
            guarded_thread, guarded_outcome = start(guarded, "guarded")
            wait_until_blocked_by(admin, pid)  # its first statement: the child's lock
        emulation_thread, emulation_outcome = start(emulation, "emulation")
    join(guarded_thread)
    join(emulation_thread)

    assert "result" in guarded_outcome, guarded_outcome  # no deadlock, no error
    assert emulation_outcome.get("result") == "done", emulation_outcome
    assert platform.owner_count() == 1
    for tenant in ("root", "child"):  # each tenant still has its administrator
        assert (
            platform.scalar(
                "SELECT count(*) FROM core.membership_roles WHERE tenant_id = :t",
                {"t": hierarchy[tenant]},
            )
            == 1
        )


# --- case 7: a deliberately inverted lock order ----------------------------------


def test_case_07_an_inverted_lock_order_deadlocks_and_fails_closed(
    platform: PlatformWorld,
) -> None:
    """TEST-ONLY paths: one takes an operator row lock and then the
    platform-owners lock; the other takes them in the specified order.
    PostgreSQL detects the cycle and aborts one transaction. Nothing is
    changed, the invariant holds, and a retry through the real operation
    succeeds -- a deadlock fails closed."""
    owner, _ = platform.owner()
    _, target = platform.operator([])
    has_row_lock = threading.Event()
    has_platform_lock = threading.Event()
    row_lock = text("SELECT id FROM core.platform_operators WHERE id = :i FOR UPDATE")

    def inverted() -> str:
        with session_scope() as session:
            session.execute(row_lock, {"i": target})  # row lock FIRST: the wrong order
            has_row_lock.set()
            assert has_platform_lock.wait(timeout=30)
            lock_platform_owners(session)
            session.execute(
                text("UPDATE core.platform_operators SET status = 'suspended' WHERE id = :i"),
                {"i": target},
            )
        return "inverted committed"

    def specified() -> str:
        with session_scope() as session:
            lock_platform_owners(session)  # the specified order
            has_platform_lock.set()
            assert has_row_lock.wait(timeout=30)
            session.execute(row_lock, {"i": target})
            session.execute(
                text("UPDATE core.platform_operators SET status = 'revoked' WHERE id = :i"),
                {"i": target},
            )
        return "specified committed"

    inverted_thread, inverted_outcome = start(inverted, "inverted")
    specified_thread, specified_outcome = start(specified, "specified")
    join(inverted_thread)
    join(specified_thread)

    outcomes = [inverted_outcome, specified_outcome]
    errors = [outcome["error"] for outcome in outcomes if "error" in outcome]
    assert len(errors) == 1, outcomes  # exactly one transaction was aborted
    assert isinstance(errors[0], OperationalError) and "deadlock detected" in str(errors[0])
    assert sum("result" in outcome for outcome in outcomes) == 1
    assert platform.owner_count() == 1  # the invariant is untouched
    assert platform.operator_status(target) in ("suspended", "revoked")  # one whole change
    # A retry through the real operation works.
    _, another = platform.operator([])
    suspend_operator(another, caller=owner, reason=REASON)
    assert platform.operator_status(another) == "suspended"


# --- case 8: forced failure after the mutation, before commit ---------------------


def test_case_08_a_failure_before_commit_leaves_neither_the_change_nor_its_audit_row(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, _ = platform.owner()
    _, other_owner = platform.owner()
    platform.clear_audit()
    real = service_module.platform_owner_exists
    calls = {"n": 0}

    def fail_on_recheck(session: Any) -> bool:
        calls["n"] += 1
        if calls["n"] == 2:  # the recheck: change and audit row are both written
            raise RuntimeError("failure after the mutation, before commit")
        return real(session)

    monkeypatch.setattr(service_module, "platform_owner_exists", fail_on_recheck)
    with pytest.raises(RuntimeError, match="before commit"):
        revoke_operator(other_owner, caller=owner, reason=REASON)
    monkeypatch.undo()
    assert platform.operator_status(other_owner) == "active"
    assert len(platform.live_permissions(other_owner)) == len(ALL_PERMISSIONS)
    assert platform.audit_count() == 0
    assert platform.owner_count() == 2
