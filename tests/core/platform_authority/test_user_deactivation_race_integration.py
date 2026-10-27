"""The blocking race tests for `deactivate_user` (ADR-0045 Phase C, sections
11c and 11d, and "Open questions for Phase C"), against a real PostgreSQL
with real locks, each interleaving forced with barriers on two or three
connections -- never a sleep or a timing guess.

    (1) the user is made member and administrator of a new tenant, and that
        tenant's other administrator is removed, between the two scans;
    (2) a removal that relies on the user starts after the exclusive lock
        on the user's row;
    (3) a guarded removal holds the user's row FOR SHARE when the
        deactivation reaches step 5;
    (4) the user is the sole administrator of a tenant found by the first
        scan -- sequential, in `test_user_authority_integration.py`;
    (5) the inherited-authority deadlock;
    (6) a login, a key creation, a key rotation and a user revoking their own
        key racing the deactivation, in both orderings;
    (7) a tenant move committing between the depth read and the
        administrator locks.

**How (2) is read.** A membership created between the scans always aborts
the deactivation (that is (1) and (3)), so "the removal is refused" needs a
deactivation that commits: here the user's membership predates the first
scan, and the removal of the tenant's other administrator starts after the
exclusive lock.

**What (5) and (7) establish.** Both interleavings end in a deadlock that
PostgreSQL resolves by aborting one transaction. The tests assert that
exactly one side fails, that nothing is left half-done, that both
invariants hold afterwards and that repeating the aborted operation gives a
correct result. They do not show that the deadlock cannot happen: it can.

`deactivate_user` and `reactivate_user` are exported from Core only while
this module passes (`tests/architecture/test_platform_authority_contract.py`).

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from phase_c_helpers import REASON, P, Pause, Scene, pause_after, pause_before
from platform_helpers import PlatformWorld, join, start, wait_until_blocked_by
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError

import saas_os.core.api_keys.service as api_keys_service
import saas_os.core.identity.service as identity_service
import saas_os.core.identity.user_authority as user_authority
import saas_os.core.platform_authority as platform_authority
import saas_os.core.rbac.administrators as administrators
import saas_os.core.tenancy.authority as lifecycle_authority
from saas_os.core.api_keys import (
    RevokedApiKeyError,
    create_api_key,
    revoke_api_key,
    rotate_api_key,
    validate_api_key,
)
from saas_os.core.authority import UserCaller
from saas_os.core.identity import (
    get_deactivation_scan_config,
    issue_session,
    revoke_membership,
    suspend_membership,
    validate_session,
)
from saas_os.core.identity.errors import (
    InactiveUserError,
    LastTenantAdministratorError,
    SessionRevokedError,
)
from saas_os.core.identity.user_authority import deactivate_user
from saas_os.core.platform_authority import PlatformNotAuthorizedError
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.scope import RoleScope
from saas_os.core.tenancy import move_tenant

pytestmark = pytest.mark.integration

DEACT = "deact"


@pytest.fixture(autouse=True)
def _default_ceiling(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.delenv("PLATFORM_DEACTIVATION_MAX_TENANTS", raising=False)
    get_deactivation_scan_config.cache_clear()
    yield
    get_deactivation_scan_config.cache_clear()


def _deactivation(user_id: uuid.UUID, holder: UserCaller) -> Any:
    return start(lambda: deactivate_user(user_id, caller=holder, reason=REASON), DEACT)


def _paused(pause: Pause) -> None:
    assert pause.paused.wait(timeout=30), f"{pause.thread_name} never reached its barrier"


def _home(scene: Scene) -> uuid.UUID:
    """A tenant with its own administrator, in which the subject is an
    ordinary member."""
    tenant = scene.tenant(active=True)
    scene.admin(tenant)
    return tenant


# --- (1) ------------------------------------------------------------------------


def test_race_1_a_membership_created_between_the_scans_aborts_and_retries(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    user_id = platform.user()
    scene.join(_home(scene), user_id)
    tenant = scene.tenant(active=True)
    other_admin, other_membership = scene.admin(tenant)
    token = scene.session_for(user_id)

    after_first_scan = Pause(DEACT, nth=1)
    pause_after(monkeypatch, user_authority, "_scan_active_memberships", after_first_scan)
    thread, outcome = _deactivation(user_id, holder)
    _paused(after_first_scan)
    # Between the two scans: the user becomes a member and an administrator
    # of a tenant the first scan did not find, and that tenant's other
    # administrator is removed on the strength of it.
    scene.make_admin(tenant, user_id)
    revoke_membership(tenant, other_membership, caller=UserCaller(user_id))
    after_first_scan.release.set()
    join(thread)

    # The first attempt was rolled back by its second scan; the retry found
    # the tenant, guarded it, and refused.
    assert after_first_scan.hits == 4  # two scans per attempt, two attempts
    assert isinstance(outcome["error"], LastTenantAdministratorError)
    assert outcome["error"].tenant_id == tenant
    assert scene.user_is_active(user_id)
    assert scene.has_administrator(tenant)  # the tenant keeps an administrator
    assert validate_session(token).user_id == user_id  # nothing was revoked
    assert other_admin.user_id != user_id
    assert platform.audit(action="platform.user.deactivate", outcome="success") == []


# --- (2) ------------------------------------------------------------------------


def test_race_2_a_removal_started_after_the_exclusive_lock_is_refused(
    scene: Scene, platform: PlatformWorld, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    user_id = platform.user()
    tenant = scene.tenant(active=True)
    other_admin, other_membership = scene.admin(tenant)
    scene.make_admin(tenant, user_id)

    holding_user_row = Pause(DEACT)
    pause_after(monkeypatch, user_authority, "lock_user_is_active", holding_user_row)
    deact_thread, deact = _deactivation(user_id, holder)
    _paused(holding_user_row)
    # The other administrator now removes themselves, relying on the user
    # remaining an administrator. It cannot count the user: it waits.
    removal_thread, removal = start(
        lambda: revoke_membership(tenant, other_membership, caller=other_admin), "removal"
    )
    wait_until_blocked_by(admin, holding_user_row.pid)
    holding_user_row.release.set()
    join(deact_thread)
    join(removal_thread)

    assert "error" not in deact, deact.get("error")
    assert not scene.user_is_active(user_id)
    assert isinstance(removal["error"], LastTenantAdministratorError)
    assert scene.has_administrator(tenant)


# --- (3) ------------------------------------------------------------------------


def test_race_3_the_deactivation_waits_for_a_removal_holding_the_user_row_then_finds_the_tenant(
    scene: Scene, platform: PlatformWorld, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    user_id = platform.user()
    scene.join(_home(scene), user_id)
    tenant = scene.tenant(active=True)
    _, other_membership = scene.admin(tenant)

    after_first_scan = Pause(DEACT, nth=1)
    pause_after(monkeypatch, user_authority, "_scan_active_memberships", after_first_scan)
    removal_in_flight = Pause("removal")
    pause_before(monkeypatch, identity_service, "record_in_transaction", removal_in_flight)

    deact_thread, deact = _deactivation(user_id, holder)
    _paused(after_first_scan)
    scene.make_admin(tenant, user_id)
    # A guarded removal that relied on the user as the tenant's remaining
    # administrator, stopped before its commit: it holds the user's row
    # FOR SHARE.
    removal_thread, removal = start(
        lambda: revoke_membership(tenant, other_membership, caller=UserCaller(user_id)), "removal"
    )
    _paused(removal_in_flight)
    after_first_scan.release.set()
    wait_until_blocked_by(admin, removal_in_flight.pid)  # the deactivation waits at step 5
    removal_in_flight.release.set()
    join(removal_thread)
    join(deact_thread)

    assert "error" not in removal, removal.get("error")
    # Having waited, the second scan found the tenant; the retry guarded it.
    assert isinstance(deact["error"], LastTenantAdministratorError)
    assert deact["error"].tenant_id == tenant
    assert scene.user_is_active(user_id) and scene.has_administrator(tenant)


# --- (5) ------------------------------------------------------------------------


def _assert_one_deadlock_victim(first: dict[str, Any], second: dict[str, Any]) -> str:
    errors = {
        name: o["error"] for name, o in (("first", first), ("second", second)) if "error" in o
    }
    assert len(errors) == 1, errors
    ((victim, error),) = errors.items()
    assert isinstance(error, OperationalError), error
    assert "deadlock" in str(error).lower()
    return victim


def test_race_5_the_inherited_authority_deadlock_fails_closed(
    scene: Scene, platform: PlatformWorld, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    platform.owner()
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    ancestor = scene.tenant()
    middle = scene.tenant(parent=ancestor)
    leaf = scene.tenant(parent=middle)
    scene.activate(ancestor, middle, leaf)
    # The subject administers `middle` only by a SUBTREE role in `ancestor`,
    # and is a plain member of `leaf`. Every tenant has another administrator.
    user_id = platform.user()
    scene.make_admin(ancestor, user_id, scope=RoleScope.SUBTREE)
    scene.join(leaf, user_id)
    other_ancestor_admin, _ = scene.admin(ancestor, scope=RoleScope.SUBTREE)
    scene.admin(leaf)
    affected, affected_membership = scene.member(middle)
    scene.join(leaf, affected)
    token = scene.session_for(user_id)

    after_authorization = Pause("mutation")
    pause_before(monkeypatch, administrators, "guard_last_administrator", after_authorization)
    # The subject's own guarded mutation in `middle`: authorized (it holds
    # the subject's row FOR SHARE), about to lock `leaf`'s administrators.
    mutation_thread, mutation = start(
        lambda: suspend_membership(middle, affected_membership, caller=UserCaller(user_id)),
        "mutation",
    )
    _paused(after_authorization)
    deact_thread, deact = _deactivation(user_id, holder)
    wait_until_blocked_by(admin, after_authorization.pid)  # holds `leaf`'s lock, wants the row
    after_authorization.release.set()
    join(mutation_thread)
    join(deact_thread)

    victim = _assert_one_deadlock_victim(mutation, deact)
    assert platform.owner_count() >= 1
    for tenant in (ancestor, leaf):
        assert scene.has_administrator(tenant)
    if victim == "second":  # the deactivation was aborted: nothing changed
        assert scene.user_is_active(user_id)
        assert validate_session(token).user_id == user_id
        assert platform.audit(action="platform.user.deactivate", outcome="success") == []
        assert len(platform.audit(action="platform.user.deactivate", outcome="failure")) == 1
        deactivate_user(user_id, caller=holder, reason=REASON)  # a retry succeeds
    else:  # the mutation was aborted: the membership is untouched
        status = platform.scalar(
            "SELECT status FROM core.tenant_memberships WHERE id = :m", {"m": affected_membership}
        )
        assert status == "active"
        suspend_membership(middle, affected_membership, caller=other_ancestor_admin)
    assert not scene.user_is_active(user_id)
    with pytest.raises(SessionRevokedError):
        validate_session(token)


# --- (6) ------------------------------------------------------------------------


def test_race_6_a_login_in_flight_is_revoked_by_the_deactivation(
    scene: Scene, platform: PlatformWorld, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    user_id = platform.user()
    scene.join(_home(scene), user_id)

    issuing = Pause("login")
    pause_before(
        monkeypatch, platform_authority, "record_operator_session_issued_in_transaction", issuing
    )
    login_thread, login = start(lambda: issue_session(user_id), "login")
    _paused(issuing)  # the session row is inserted, not committed; the user row is FOR SHARE
    deact_thread, deact = _deactivation(user_id, holder)
    wait_until_blocked_by(admin, issuing.pid)
    issuing.release.set()
    join(login_thread)
    join(deact_thread)

    assert "error" not in deact, deact.get("error")
    _record, token = login["result"]
    with pytest.raises(SessionRevokedError):
        validate_session(token)
    assert scene.live_sessions(user_id) == 0


def test_race_6_a_login_started_after_the_exclusive_lock_is_refused(
    scene: Scene, platform: PlatformWorld, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    user_id = platform.user()
    scene.join(_home(scene), user_id)

    holding_user_row = Pause(DEACT)
    pause_after(monkeypatch, user_authority, "lock_user_is_active", holding_user_row)
    deact_thread, deact = _deactivation(user_id, holder)
    _paused(holding_user_row)
    login_thread, login = start(lambda: issue_session(user_id), "login")
    wait_until_blocked_by(admin, holding_user_row.pid)
    holding_user_row.release.set()
    join(deact_thread)
    join(login_thread)

    assert "error" not in deact, deact.get("error")
    assert isinstance(login["error"], InactiveUserError)
    assert scene.live_sessions(user_id) == 0  # nothing to become usable on reactivation


def test_race_6_a_key_creation_in_flight_is_revoked_by_the_deactivation(
    scene: Scene, platform: PlatformWorld, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    user_id = platform.user()
    tenant = _home(scene)
    scene.join(tenant, user_id)

    creating = Pause("create")
    pause_before(monkeypatch, api_keys_service, "record_in_transaction", creating)
    create_thread, create = start(
        lambda: create_api_key(tenant, "racing", caller=UserCaller(user_id)), "create"
    )
    _paused(creating)
    deact_thread, deact = _deactivation(user_id, holder)
    wait_until_blocked_by(admin, creating.pid)
    creating.release.set()
    join(create_thread)
    join(deact_thread)

    assert "error" not in deact, deact.get("error")
    _key, raw = create["result"]
    with pytest.raises(RevokedApiKeyError):
        validate_api_key(raw)
    assert scene.live_keys(user_id) == 0


def test_race_6_a_key_creation_started_after_the_exclusive_lock_is_refused(
    scene: Scene, platform: PlatformWorld, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    user_id = platform.user()
    tenant = _home(scene)
    scene.join(tenant, user_id)

    holding_user_row = Pause(DEACT)
    pause_after(monkeypatch, user_authority, "lock_user_is_active", holding_user_row)
    deact_thread, deact = _deactivation(user_id, holder)
    _paused(holding_user_row)
    create_thread, create = start(
        lambda: create_api_key(tenant, "racing", caller=UserCaller(user_id)), "create"
    )
    wait_until_blocked_by(admin, holding_user_row.pid)
    holding_user_row.release.set()
    join(deact_thread)
    join(create_thread)

    assert "error" not in deact, deact.get("error")
    assert isinstance(create["error"], AuthorityNotAuthorizedError)
    assert scene.live_keys(user_id) == 0


@pytest.mark.parametrize("rotation_first", [True, False])
def test_race_6_a_rotation_by_an_administrator_never_leaves_a_live_key(
    scene: Scene,
    platform: PlatformWorld,
    admin: Engine,
    monkeypatch: pytest.MonkeyPatch,
    rotation_first: bool,
) -> None:
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    tenant = scene.tenant(active=True)
    administrator, _ = scene.admin(tenant, extra=[("api_key", "rotate")])
    user_id, _ = scene.member(tenant)
    key_id, _ = scene.api_key(tenant, user_id)

    def rotate() -> Any:
        return rotate_api_key(tenant, key_id, caller=administrator)

    if rotation_first:
        rotating = Pause("rotate")
        pause_before(monkeypatch, api_keys_service, "record_in_transaction", rotating)
        rotate_thread, rotation = start(rotate, "rotate")
        _paused(rotating)  # the new key is inserted, not committed
        deact_thread, deact = _deactivation(user_id, holder)
        wait_until_blocked_by(admin, rotating.pid)
        rotating.release.set()
    else:
        holding_user_row = Pause(DEACT)
        pause_after(monkeypatch, user_authority, "lock_user_is_active", holding_user_row)
        deact_thread, deact = _deactivation(user_id, holder)
        _paused(holding_user_row)
        rotate_thread, rotation = start(rotate, "rotate")
        wait_until_blocked_by(admin, holding_user_row.pid)
        holding_user_row.release.set()
    join(rotate_thread)
    join(deact_thread)

    assert "error" not in deact, deact.get("error")
    if rotation_first:
        _new_key, raw = rotation["result"]
        with pytest.raises(RevokedApiKeyError):
            validate_api_key(raw)
    else:
        assert isinstance(rotation["error"], AuthorityNotAuthorizedError)
    assert scene.live_keys(user_id) == 0


@pytest.mark.parametrize("revocation_first", [True, False])
def test_race_6_a_user_revoking_their_own_key_does_not_deadlock_the_deactivation(
    scene: Scene,
    platform: PlatformWorld,
    admin: Engine,
    monkeypatch: pytest.MonkeyPatch,
    revocation_first: bool,
) -> None:
    """`revoke_api_key` locks the key row and only then touches the owner's
    row, through the foreign key of its audit row (`FOR KEY SHARE`), against
    the deactivation's order. That cannot deadlock while the deactivation
    holds the user row `FOR NO KEY UPDATE`, which `FOR KEY SHARE` does not
    conflict with: a revocation in flight makes the deactivation wait for the
    key row, and a revocation that starts during the deactivation does not
    wait at all. If the deactivation took the row `FOR UPDATE`, the first
    ordering would deadlock."""
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    tenant = _home(scene)
    user_id, _ = scene.member(tenant)
    key_id, raw = scene.api_key(tenant, user_id)

    def revoke() -> Any:
        return revoke_api_key(tenant, key_id, caller=UserCaller(user_id))

    if revocation_first:
        revoking = Pause("revoke")
        pause_before(monkeypatch, api_keys_service, "record_in_transaction", revoking)
        revoke_thread, revocation = start(revoke, "revoke")
        _paused(revoking)  # the key is marked revoked, not committed
        deact_thread, deact = _deactivation(user_id, holder)
        wait_until_blocked_by(admin, revoking.pid)  # the deactivation waits for the key row
        revoking.release.set()
    else:
        holding_user_row = Pause(DEACT)
        pause_after(monkeypatch, user_authority, "lock_user_is_active", holding_user_row)
        deact_thread, deact = _deactivation(user_id, holder)
        _paused(holding_user_row)
        revoke_thread, revocation = start(revoke, "revoke")
        join(revoke_thread)  # completes while the deactivation holds the user row
        holding_user_row.release.set()
    join(revoke_thread)
    join(deact_thread)

    assert "error" not in revocation, revocation.get("error")
    assert "error" not in deact, deact.get("error")
    assert not scene.user_is_active(user_id)
    with pytest.raises(RevokedApiKeyError):
        validate_api_key(raw)
    assert scene.live_keys(user_id) == 0


# --- (7) ------------------------------------------------------------------------


def test_race_7_a_move_between_the_depth_read_and_the_administrator_locks_fails_closed(
    scene: Scene, platform: PlatformWorld, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deactivation orders its administrator locks by depths it read
    before taking them. A move that commits in between makes that order
    disagree with the one a guarded mutation in the moved subtree uses. The
    result is a deadlock, which PostgreSQL resolves: one transaction is
    aborted, nothing is left half-done, and neither invariant is violated."""
    platform.owner()
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    mover, _ = platform.operator([P.TENANT_MOVE])
    pair = sorted((scene.tenant(active=True), scene.tenant(active=True)), key=str)
    first, second = pair  # both roots: the deactivation will lock `first`, then `second`
    user_id = platform.user()
    for tenant in pair:
        scene.join(tenant, user_id)
        scene.admin(tenant)
    second_admin, _ = scene.admin(second)
    affected, affected_membership = scene.member(second)
    scene.join(first, affected)
    token = scene.session_for(user_id)

    depths_read = Pause(DEACT)
    pause_after(monkeypatch, user_authority, "root_depths", depths_read)
    holding_first = Pause(DEACT, nth=1)
    pause_after(monkeypatch, administrators, "lock_tenant_administrators", holding_first)

    deact_thread, deact = _deactivation(user_id, holder)
    _paused(depths_read)
    # `first` becomes a child of `second`: the true order is now `second`,
    # then `first`. The deactivation still holds the old one.
    assert move_tenant(first, second, caller=mover).parent_id == second
    depths_read.release.set()
    _paused(holding_first)
    # A guarded mutation at `second` that reaches its descendant `first`:
    # it locks `second`, then waits for `first`.
    mutation_thread, mutation = start(
        lambda: suspend_membership(second, affected_membership, caller=second_admin), "mutation"
    )
    wait_until_blocked_by(admin, holding_first.pid)
    holding_first.release.set()
    join(deact_thread)
    join(mutation_thread)

    victim = _assert_one_deadlock_victim(deact, mutation)
    assert platform.owner_count() >= 1
    assert scene.has_administrator(first) and scene.has_administrator(second)
    if victim == "first":  # the deactivation was aborted: nothing changed
        assert scene.user_is_active(user_id)
        assert validate_session(token).user_id == user_id
        deactivate_user(user_id, caller=holder, reason=REASON)  # a retry succeeds
    else:
        suspend_membership(second, affected_membership, caller=second_admin)
    assert not scene.user_is_active(user_id)
    assert scene.has_administrator(first) and scene.has_administrator(second)


# --- (8) a move by the user who is being deactivated ------------------------------
#
# ADR-0045 section 11c fixes the order: platform lock, administrator locks,
# row locks. `move_tenant` used to authorize its caller (the caller's user
# row FOR SHARE) and only then take the administrator locks of the subtree
# it moves, while a deactivation of that caller holds the administrator
# lock of a tenant in the subtree and then waits for the row. Each then
# held what the other wanted. Since the move takes the subtree's
# administrator locks first, the two queue on one lock and neither holds a
# row the other is waiting for. Both orderings are forced below; in
# neither is a transaction aborted by PostgreSQL.


def _moving_operator(scene: Scene, platform: PlatformWorld) -> tuple[Any, uuid.UUID, uuid.UUID]:
    """An operator who may move tenants and is a member of the tenant to
    be moved; that tenant and the new parent each have an administrator of
    their own. Returns `(mover, tenant, new_parent)`."""
    mover, _ = platform.operator([P.TENANT_MOVE])
    tenant, new_parent = scene.tenant(active=True), scene.tenant(active=True)
    scene.admin(tenant)
    scene.admin(new_parent)
    scene.join(tenant, mover.user_id)
    return mover, tenant, new_parent


def _parent_of(platform: PlatformWorld, tenant: uuid.UUID) -> uuid.UUID | None:
    return platform.scalar("SELECT parent_id FROM core.tenants WHERE id = :t", {"t": tenant})


def test_race_8_a_move_that_starts_during_the_deactivation_waits_and_is_refused(
    scene: Scene, platform: PlatformWorld, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    platform.owner()
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    mover, tenant, new_parent = _moving_operator(scene, platform)

    # The deactivation holds the tenant's administrator lock and has not
    # yet taken the mover's user row.
    holding = Pause(DEACT)
    pause_after(monkeypatch, administrators, "guard_tenants", holding)
    deact_thread, deact = _deactivation(mover.user_id, holder)
    _paused(holding)

    move_thread, move = start(lambda: move_tenant(tenant, new_parent, caller=mover), "move")
    wait_until_blocked_by(admin, holding.pid)  # the move waits for that administrator lock
    # ... and holds no lock on the mover's user row while it waits: the row
    # can be locked exclusively, at once, by a third transaction. Before the
    # correction the move held it FOR SHARE here, and this statement failed.
    with admin.begin() as conn:
        conn.execute(
            text("SELECT id FROM core.users WHERE id = :u FOR NO KEY UPDATE NOWAIT"),
            {"u": mover.user_id},
        )
        conn.rollback()

    holding.release.set()
    join(deact_thread)
    join(move_thread)

    assert "error" not in deact, deact.get("error")  # not a deadlock victim
    assert not scene.user_is_active(mover.user_id)
    # The move was judged after the deactivation committed: a refusal, by
    # the authorization, not a database error.
    assert isinstance(move.get("error"), PlatformNotAuthorizedError), move
    assert _parent_of(platform, tenant) is None
    assert scene.has_administrator(tenant) and scene.has_administrator(new_parent)
    assert platform.audit(action="platform.tenant.move", outcome="success") == []
    assert len(platform.audit(action="platform.tenant.move", outcome="denied")) == 1
    assert len(platform.audit(action="platform.user.deactivate", outcome="success")) == 1
    assert platform.audit(outcome="failure") == []


def test_race_8_a_deactivation_that_starts_during_the_move_waits_and_succeeds(
    scene: Scene, platform: PlatformWorld, admin: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    platform.owner()
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    mover, tenant, new_parent = _moving_operator(scene, platform)

    # The move is authorized: it holds the mover's user row FOR SHARE and,
    # taken before it, the administrator lock of the tenant it moves.
    authorized = Pause("move")
    pause_after(monkeypatch, lifecycle_authority, "authorize", authorized)
    move_thread, move = start(lambda: move_tenant(tenant, new_parent, caller=mover), "move")
    _paused(authorized)

    deact_thread, deact = _deactivation(mover.user_id, holder)
    # The deactivation waits for the administrator lock, before it has
    # taken any row. Before the correction the move did not hold that lock
    # yet: the deactivation took it, waited for the row, and the move then
    # waited for the lock -- the cycle.
    wait_until_blocked_by(admin, authorized.pid)
    authorized.release.set()
    join(move_thread)
    join(deact_thread)

    assert "error" not in move, move.get("error")
    assert "error" not in deact, deact.get("error")
    assert _parent_of(platform, tenant) == new_parent  # the move committed first
    assert not scene.user_is_active(mover.user_id)
    assert scene.has_administrator(tenant) and scene.has_administrator(new_parent)
    assert len(platform.audit(action="platform.tenant.move", outcome="success")) == 1
    assert len(platform.audit(action="platform.user.deactivate", outcome="success")) == 1
    assert platform.audit(outcome="failure") == [] and platform.audit(outcome="denied") == []
