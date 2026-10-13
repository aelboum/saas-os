"""Negative controls for ADR-0045 Phase C, against a real PostgreSQL
(project protocol "Loop 5").

Each test removes one protection for the duration of the test (a
`monkeypatch`; shipped code is never weakened) and shows the outcome the
protection exists to prevent. Each first shows the protection working.

- authorization removed from a lifecycle function ... a stranger suspends
  a tenant;
- the parent rule removed ............................ provisioning attaches
  a child beneath an active tenant;
- the self-service rule forced to allow .............. a plain member
  suspends the tenant;
- the membership rule of `move_tenant` removed ....... an operator moves a
  tenant under a tenant they belong to;
- the second scan removed from `deactivate_user` ..... race (1) leaves a
  tenant with no administrator;
- the scan made to continue past the ceiling ......... a user is
  deactivated in a registry larger than the configured ceiling;
- session revocation removed from `reactivate_user` .. an old session works
  again;
- key revocation removed ............................. a key works after
  deactivation and reactivation;
- the exclusive user lock dropped from
  `revoke_user_api_keys` ............................. a key created
  concurrently stays live;
- the user lock dropped from `issue_session` ......... a login racing the
  deactivation leaves a live session;
- the per-tenant scope binding removed from the
  overview ........................................... the projection is
  empty: the tenant policy, not the query, is what admits the rows;
- the completion insert removed from an oversight
  read ............................................... the read returns
  data and leaves only its attempt row: no record that it completed, or
  of how much it returned. (The three controls of the two-event model are
  in `test_oversight_audit_events_integration.py`.)

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from phase_c_helpers import PROVISIONING, REASON, P, Pause, Scene, pause_after, pause_before
from platform_helpers import PlatformWorld, join, start

import saas_os.core.api_keys.service as api_keys_service
import saas_os.core.billing.oversight as oversight
import saas_os.core.identity.sessions as sessions_module
import saas_os.core.identity.user_authority as user_authority
import saas_os.core.platform_authority as platform_authority
import saas_os.core.tenancy.authority as lifecycle_authority
import saas_os.core.tenancy.service as tenancy_service
from saas_os.core.api_keys import create_api_key, validate_api_key
from saas_os.core.authority import UserCaller
from saas_os.core.billing import commercial_overview
from saas_os.core.billing.provider import FakeBillingProvider
from saas_os.core.billing.service import create_plan, subscribe
from saas_os.core.identity import (
    get_deactivation_scan_config,
    issue_session,
    revoke_membership,
    revoke_user_api_keys,
    validate_session,
)
from saas_os.core.identity.errors import LastTenantAdministratorError
from saas_os.core.identity.user_authority import deactivate_user, reactivate_user
from saas_os.core.platform_authority import (
    DeactivationScanLimitError,
    MoveIntoCallerHierarchyError,
    PlatformNotAuthorizedError,
    TenantParentRuleError,
)
from saas_os.core.tenancy import (
    TenantStatus,
    create_tenant,
    list_tenant_registry,
    move_tenant,
    transition_tenant_status,
)

pytestmark = pytest.mark.integration

DEACT = "deact"


@pytest.fixture(autouse=True)
def _default_ceiling(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.delenv("PLATFORM_DEACTIVATION_MAX_TENANTS", raising=False)
    get_deactivation_scan_config.cache_clear()
    yield
    get_deactivation_scan_config.cache_clear()


def _member_with_another_admin(scene: Scene) -> tuple[uuid.UUID, uuid.UUID]:
    tenant = scene.tenant(active=True)
    scene.admin(tenant)
    user_id, _ = scene.member(tenant)
    return user_id, tenant


# --- tenant lifecycle -------------------------------------------------------------


def test_without_authorization_a_stranger_suspends_a_tenant(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = scene.tenant(active=True)
    stranger = UserCaller(platform.user())
    with pytest.raises(PlatformNotAuthorizedError):
        transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=stranger)
    assert scene.status(tenant) == "active"

    monkeypatch.setattr(lifecycle_authority, "authorize", lambda *args, **kwargs: None)
    transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=stranger)
    assert scene.status(tenant) == "suspended"  # what the authorization call prevents


def test_without_the_parent_rule_provisioning_attaches_a_child_beneath_an_active_tenant(
    scene: Scene, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = scene.tenant(active=True)
    with pytest.raises(TenantParentRuleError):
        create_tenant("pc-refused", parent_id=parent, caller=PROVISIONING)

    monkeypatch.setattr(tenancy_service, "_apply_parent_rule", lambda *args, **kwargs: None)
    child = create_tenant("pc-attached", parent_id=parent, caller=PROVISIONING)
    scene.tenants.append(child.id)
    assert child.parent_id == parent  # what the parent rule prevents


def test_with_the_self_service_rule_forced_a_plain_member_suspends_the_tenant(
    scene: Scene, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = scene.tenant(active=True)
    member = UserCaller(scene.member(tenant)[0])
    with pytest.raises(PlatformNotAuthorizedError):
        transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=member, reason=REASON)
    assert scene.status(tenant) == "active"

    monkeypatch.setattr(lifecycle_authority, "holds_self_suspend", lambda *args, **kwargs: True)
    transition_tenant_status(tenant, TenantStatus.SUSPENDED, caller=member, reason=REASON)
    assert scene.status(tenant) == "suspended"


def test_without_the_membership_rule_an_operator_moves_a_tenant_under_their_own(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    new_parent = scene.tenant()
    tenant = scene.tenant()
    mover, _ = platform.operator([P.TENANT_MOVE])
    scene.make_admin(new_parent, mover.user_id)
    with pytest.raises(MoveIntoCallerHierarchyError):
        move_tenant(tenant, new_parent, caller=mover)

    monkeypatch.setattr(lifecycle_authority, "caller_is_member_of_any", lambda *a, **k: False)
    assert move_tenant(tenant, new_parent, caller=mover).parent_id == new_parent


# --- deactivation -------------------------------------------------------------------


def _race_1(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, *, second_scan: bool
) -> tuple[dict[str, Any], uuid.UUID, uuid.UUID]:
    """Race (1): the user becomes the sole administrator of a new tenant
    between the two scans. Returns the deactivation's outcome, the user
    and the tenant."""
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    user_id, _ = _member_with_another_admin(scene)
    tenant = scene.tenant(active=True)
    _, other_membership = scene.admin(tenant)

    real = user_authority._scan_active_memberships
    remembered: dict[str, Any] = {}

    def scan(*args: Any, **kwargs: Any) -> Any:
        if not second_scan and "first" in remembered:
            return remembered["first"]  # the second scan removed
        remembered["first"] = real(*args, **kwargs)
        return remembered["first"]

    monkeypatch.setattr(user_authority, "_scan_active_memberships", scan)
    after_first_scan = Pause(DEACT, nth=1)
    pause_after(monkeypatch, user_authority, "_scan_active_memberships", after_first_scan)
    thread, outcome = start(lambda: deactivate_user(user_id, caller=holder, reason=REASON), DEACT)
    assert after_first_scan.paused.wait(timeout=30)
    scene.make_admin(tenant, user_id)
    revoke_membership(tenant, other_membership, caller=UserCaller(user_id))
    after_first_scan.release.set()
    join(thread)
    return outcome, user_id, tenant


def test_without_the_second_scan_a_tenant_is_left_with_no_administrator(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcome, user_id, tenant = _race_1(scene, platform, monkeypatch, second_scan=True)
    assert isinstance(outcome["error"], LastTenantAdministratorError)
    assert scene.user_is_active(user_id) and scene.has_administrator(tenant)
    monkeypatch.undo()
    get_deactivation_scan_config.cache_clear()

    outcome, user_id, tenant = _race_1(scene, platform, monkeypatch, second_scan=False)
    assert "error" not in outcome, outcome.get("error")
    assert not scene.user_is_active(user_id)
    assert not scene.has_administrator(tenant)  # what the second scan prevents


def test_a_scan_that_continues_past_the_ceiling_deactivates_a_user(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id, _ = _member_with_another_admin(scene)
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    scene.tenant()  # at least two tenants, so that "one below" is a valid ceiling
    monkeypatch.setenv("PLATFORM_DEACTIVATION_MAX_TENANTS", str(scene.unpurged_tenants() - 1))
    get_deactivation_scan_config.cache_clear()
    with pytest.raises(DeactivationScanLimitError):
        deactivate_user(user_id, caller=holder, reason=REASON)
    assert scene.user_is_active(user_id)

    real = user_authority._scan_active_memberships
    monkeypatch.setattr(user_authority, "count_unpurged_tenants", lambda *args, **kwargs: 0)
    monkeypatch.setattr(
        user_authority,
        "_scan_active_memberships",
        lambda session, subject, *, ceiling, operation: real(
            session, subject, ceiling=10**9, operation=operation
        ),
    )
    deactivate_user(user_id, caller=holder, reason=REASON)
    assert not scene.user_is_active(user_id)  # what the refusal prevents


def test_without_session_revocation_on_reactivation_an_old_session_works_again(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id, _ = _member_with_another_admin(scene)
    operator, _ = platform.operator([P.USER_DEACTIVATE, P.USER_REACTIVATE])
    token = scene.session_for(user_id)
    deactivate_user(user_id, caller=operator, reason=REASON)
    # What a login racing the deactivation would leave behind.
    platform.execute(
        "UPDATE core.sessions SET revoked_at = NULL WHERE user_id = :u", {"u": user_id}
    )

    monkeypatch.setattr(user_authority, "_revoke_sessions", lambda *args, **kwargs: 0)
    reactivate_user(user_id, caller=operator, reason=REASON)
    assert validate_session(token).user_id == user_id  # restored: the step is what prevents it


def test_without_key_revocation_a_key_survives_deactivation_and_reactivation(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id, tenant = _member_with_another_admin(scene)
    operator, _ = platform.operator([P.USER_DEACTIVATE, P.USER_REACTIVATE])
    _, raw = scene.api_key(tenant, user_id)
    monkeypatch.setattr(
        api_keys_service, "revoke_user_api_keys_in_transaction", lambda *args, **kwargs: []
    )
    deactivate_user(user_id, caller=operator, reason=REASON)
    reactivate_user(user_id, caller=operator, reason=REASON)
    assert validate_api_key(raw).user_id == user_id  # a working key: what revocation prevents


def test_without_the_exclusive_user_lock_a_key_created_concurrently_stays_live(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id, tenant = _member_with_another_admin(scene)
    holder, _ = platform.operator([P.API_KEY_REVOKE])
    # With the lock dropped the revocation does not wait for the creation.
    monkeypatch.setattr(user_authority, "lock_user_is_active", lambda *args, **kwargs: True)
    creating = Pause("create")
    pause_before(monkeypatch, api_keys_service, "record_in_transaction", creating)
    thread, create = start(
        lambda: create_api_key(tenant, "racing", caller=UserCaller(user_id)), "create"
    )
    assert creating.paused.wait(timeout=30)  # the key is inserted, not committed
    assert revoke_user_api_keys(user_id, caller=holder, reason=REASON) == 0
    creating.release.set()
    join(thread)
    _key, raw = create["result"]
    assert validate_api_key(raw).user_id == user_id  # a live key the revocation missed


def test_without_the_user_lock_a_login_racing_the_deactivation_leaves_a_live_session(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy import select as plain_select

    user_id, _ = _member_with_another_admin(scene)
    holder, _ = platform.operator([P.USER_DEACTIVATE])

    class _Unlocked:
        """A `select` whose `with_for_update` does nothing: the
        pre-Phase-C unlocked read of the user row."""

        def __init__(self, statement: Any) -> None:
            self.statement = statement

        def where(self, *criteria: Any) -> _Unlocked:
            return _Unlocked(self.statement.where(*criteria))

        def with_for_update(self, **kwargs: Any) -> Any:
            return self.statement

    monkeypatch.setattr(
        sessions_module, "select", lambda *columns: _Unlocked(plain_select(*columns))
    )
    issuing = Pause("login")
    pause_before(
        monkeypatch, platform_authority, "record_operator_session_issued_in_transaction", issuing
    )
    thread, login = start(lambda: issue_session(user_id), "login")
    assert issuing.paused.wait(timeout=30)  # read `is_active = true`; row inserted, uncommitted
    deactivate_user(user_id, caller=holder, reason=REASON)  # does not wait: no lock to wait for
    issuing.release.set()
    join(thread)
    assert "error" not in login, login.get("error")
    assert scene.live_sessions(user_id) == 1  # would become usable on reactivation


# --- oversight ----------------------------------------------------------------------


def test_without_the_scope_binding_the_overview_projection_is_empty(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = scene.tenant(active=True)
    plan_key = f"pc-plan-{uuid.uuid4().hex[:10]}"
    create_plan(plan_key, "Phase C plan", entitlements={"widgets": 1})
    subscribe(tenant, plan_key, provider=FakeBillingProvider())
    reader, _ = platform.operator([P.BILLING_READ])

    def find() -> Any:
        cursor: uuid.UUID | None = None
        while True:
            page = commercial_overview(caller=reader, cursor=cursor, limit=50)
            for entry in page.tenants:
                if entry.tenant_id == tenant:
                    return entry
            assert page.next_cursor is not None
            cursor = page.next_cursor

    assert [s.plan_key for s in find().subscriptions] == [plan_key]

    @contextmanager
    def no_binding(session: Any, tenant_id: uuid.UUID) -> Iterator[None]:
        yield

    monkeypatch.setattr(oversight, "bind_tenant_scope", no_binding)
    # The rows are admitted by the tenant policy, one tenant at a time; an
    # untenanted statement sees none of them, whatever its predicate.
    assert find().subscriptions == ()


def test_without_the_completion_insert_an_oversight_read_leaves_only_its_attempt(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    scene.tenant()
    reader, _ = platform.operator([P.TENANT_READ])
    platform.clear_audit()
    list_tenant_registry(caller=reader, limit=1)
    assert len(platform.audit(action="platform.tenant.read")) == 1

    platform.clear_audit()
    monkeypatch.setattr(
        platform_authority, "record_platform_event_in_transaction", lambda *args, **kwargs: None
    )
    assert len(list_tenant_registry(caller=reader, limit=1).tenants) == 1
    # Read and returned, with no completion: nobody can tell that it
    # finished or how much left. The attempt row, written by its own
    # writer before the read, is all there is.
    assert platform.audit(action="platform.tenant.read") == []
    assert len(platform.audit(action="platform.tenant.read_attempt")) == 1
    assert platform.audit_count() == 1
