"""Feature-flag authority and the oversight reads against a real PostgreSQL
(ADR-0045 Phase C, sections 4, 8, 9d and 13): flag definition and tenant
overrides, the tenant registry read and the commercial overview.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from phase_c_helpers import BILLING, PROVISIONING, REASON, TENANT_PURGE, P, Scene
from platform_helpers import BOOTSTRAP, PlatformWorld
from sqlalchemy import text

import saas_os.core.billing.oversight as oversight
import saas_os.core.feature_flags.service as flags_service
from saas_os.core.authority import CallerTypeError, ServiceAccountCaller, UserCaller
from saas_os.core.billing import commercial_overview
from saas_os.core.billing.oversight import MAX_OVERVIEW_PAGE_SIZE, MAX_SUBSCRIPTIONS_PER_TENANT
from saas_os.core.billing.provider import FakeBillingProvider
from saas_os.core.billing.service import create_plan, subscribe
from saas_os.core.feature_flags import (
    DuplicateFeatureFlagKeyError,
    create_flag,
    evaluate_flag,
    get_tenant_override,
    remove_tenant_override,
    set_tenant_override,
)
from saas_os.core.platform_authority import (
    InvalidPlatformRequestError,
    PlatformNotAuthorizedError,
)
from saas_os.core.tenancy import (
    TenantClosedError,
    TenantNotFoundError,
    TenantStatus,
    list_tenant_registry,
    read_tenant_registry_entry,
)
from saas_os.core.tenancy.registry import MAX_REGISTRY_PAGE_SIZE
from saas_os.infra.db import session_scope

pytestmark = pytest.mark.integration


def _key() -> str:
    return f"pc-flag-{uuid.uuid4().hex[:10]}"


def _everyone_else(
    scene: Scene, platform: PlatformWorld, tenant: uuid.UUID, holds: Any
) -> list[Any]:
    administrator, _ = scene.admin(tenant)
    wrong, _ = platform.operator([p for p in P if p is not holds])
    return [
        ServiceAccountCaller(service_account_id=uuid.uuid4(), tenant_id=tenant),
        UserCaller(platform.user()),
        administrator,
        wrong,
    ]


# --- feature flags ------------------------------------------------------------------


def test_defining_a_flag_needs_the_permission_or_the_provisioning_purpose(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    definer, _ = platform.operator([P.FEATURE_FLAG_DEFINE])
    for bad in (None, "seed"):
        with pytest.raises(CallerTypeError):
            create_flag(_key(), caller=bad)
    for caller in (
        *_everyone_else(scene, platform, tenant, P.FEATURE_FLAG_DEFINE),
        TENANT_PURGE,
        BILLING,
        BOOTSTRAP,
    ):
        with pytest.raises(PlatformNotAuthorizedError):
            create_flag(_key(), caller=caller)
    platform.clear_audit()
    by_operator = create_flag(_key(), enabled_by_default=True, caller=definer)
    by_seed = create_flag(_key(), caller=PROVISIONING)
    rows = platform.audit(action="platform.feature_flag.define", outcome="success")
    assert [(r["actor_type"], r["target_id"]) for r in rows] == [
        ("user", str(by_operator.id)),
        ("system", str(by_seed.id)),
    ]
    assert rows[0]["metadata"] == {"enabled_by_default": True}
    with pytest.raises(DuplicateFeatureFlagKeyError):
        create_flag(by_seed.key, caller=PROVISIONING)


def test_a_tenant_override_needs_a_person_holding_the_permission(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    key = create_flag(_key(), caller=PROVISIONING).key
    for caller in (
        *_everyone_else(scene, platform, tenant, P.FEATURE_FLAG_OVERRIDE),
        PROVISIONING,  # no system purpose: the self-learning kill switch is a flag
        TENANT_PURGE,
        BILLING,
        BOOTSTRAP,
    ):
        with pytest.raises(PlatformNotAuthorizedError):
            set_tenant_override(tenant, key, True, caller=caller)
        with pytest.raises(PlatformNotAuthorizedError):
            remove_tenant_override(tenant, key, caller=caller)
    assert get_tenant_override(tenant, key) is None
    assert evaluate_flag(tenant, key) is False
    assert scene.tenant_audit(tenant, "feature_flag.override_set") == []


def test_an_override_writes_dual_evidence_in_one_transaction(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = scene.tenant(active=True)
    flag = create_flag(_key(), caller=PROVISIONING)
    operator, _ = platform.operator([P.FEATURE_FLAG_OVERRIDE])
    platform.clear_audit()

    set_tenant_override(tenant, flag.key, True, caller=operator, reason=REASON)
    set_tenant_override(tenant, flag.key, False, caller=operator)  # replaced in place
    assert evaluate_flag(tenant, flag.key, default=True) is False
    with session_scope() as session:
        assert (
            session.execute(
                text("SELECT count(*) FROM core.feature_flag_tenant_overrides WHERE flag_id = :f"),
                {"f": flag.id},
            ).scalar_one()
            == 0  # hidden from an untenanted transaction: the row is tenant-owned
        )
    rows = platform.audit(action="platform.feature_flag.override", outcome="success")
    assert [r["metadata"] for r in rows] == [{"enabled": True}, {"enabled": False}]
    assert rows[0]["actor_user_id"] == operator.user_id and rows[0]["target_tenant_id"] == tenant
    assert rows[0]["reason"] == REASON
    own = scene.tenant_audit(tenant, "feature_flag.override_set")
    assert [r["metadata"] for r in own] == [
        {"enabled": True, "platform": True},
        {"enabled": False, "platform": True},
    ]
    assert {r["actor_user_id"] for r in own} == {operator.user_id}

    # A failure in the tenant evidence write rolls the override back.
    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("forced evidence failure")

    monkeypatch.setattr(flags_service, "record_in_transaction", boom)
    with pytest.raises(RuntimeError):
        set_tenant_override(tenant, flag.key, True, caller=operator)
    monkeypatch.undo()
    assert evaluate_flag(tenant, flag.key, default=True) is False
    assert len(platform.audit(action="platform.feature_flag.override", outcome="success")) == 2

    remove_tenant_override(tenant, flag.key, caller=operator)
    assert get_tenant_override(tenant, flag.key) is None
    assert len(scene.tenant_audit(tenant, "feature_flag.override_removed")) == 1
    remove_tenant_override(tenant, flag.key, caller=operator)  # nothing to remove: no evidence
    assert len(platform.audit(action="platform.feature_flag.override", outcome="success")) == 3


def test_a_closed_tenant_receives_no_override(scene: Scene, platform: PlatformWorld) -> None:
    tenant = scene.tenant(active=True)
    key = create_flag(_key(), caller=PROVISIONING).key
    operator, _ = platform.operator([P.FEATURE_FLAG_OVERRIDE])
    scene.set_status(tenant, TenantStatus.DELETED)
    with pytest.raises(TenantClosedError):
        set_tenant_override(tenant, key, True, caller=operator)
    assert platform.audit(action="platform.feature_flag.override", outcome="success") == []


# --- the tenant registry ---------------------------------------------------------------


def test_the_registry_read_needs_the_permission_and_returns_the_fixed_projection(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    suspended = scene.tenant(active=True)
    scene.set_status(suspended, TenantStatus.SUSPENDED)
    for caller in (
        *_everyone_else(scene, platform, tenant, P.TENANT_READ),
        PROVISIONING,
        TENANT_PURGE,
    ):
        with pytest.raises(PlatformNotAuthorizedError):
            list_tenant_registry(caller=caller)
        with pytest.raises(PlatformNotAuthorizedError):
            read_tenant_registry_entry(tenant, caller=caller)
    reader, _ = platform.operator([P.TENANT_READ])
    platform.clear_audit()

    entry = read_tenant_registry_entry(suspended, caller=reader)  # a suspended tenant is readable
    assert entry.status == "suspended"
    assert set(vars(entry)) == {"id", "name", "status", "parent_id", "created_at", "updated_at"}
    rows = platform.audit(action="platform.tenant.read", outcome="success")
    assert len(rows) == 1 and rows[0]["target_tenant_id"] == suspended
    # The completion: the count and the attempt's id, never a returned value.
    assert set(rows[0]["metadata"]) == {"attempt_id", "returned"}
    assert rows[0]["metadata"]["returned"] == 1
    attempts = platform.audit(action="platform.tenant.read_attempt")
    assert len(attempts) == 1 and attempts[0]["target_id"] == str(suspended)
    assert attempts[0]["target_tenant_id"] is None  # written before the tenant was looked up


def test_a_registry_read_of_an_unknown_tenant_is_audited_and_discloses_nothing_unauthorized(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    unknown = uuid.uuid4()
    # Without the permission the answer is the same refusal for a tenant
    # that exists and for one that does not: existence is not disclosed.
    for caller in (*_everyone_else(scene, platform, tenant, P.TENANT_READ), PROVISIONING):
        for target in (tenant, unknown):
            with pytest.raises(PlatformNotAuthorizedError):
                read_tenant_registry_entry(target, caller=caller)
    reader, _ = platform.operator([P.TENANT_READ])
    platform.clear_audit()

    with pytest.raises(TenantNotFoundError):
        read_tenant_registry_entry(unknown, caller=reader)
    # The probe leaves evidence: the attempt and the completion, both
    # naming the id that was asked for.
    rows = platform.audit(action="platform.tenant.read")
    assert len(rows) == 1
    assert rows[0]["outcome"] == "success" and rows[0]["actor_user_id"] == reader.user_id
    assert rows[0]["target_id"] == str(unknown) and rows[0]["target_tenant_id"] is None
    assert rows[0]["metadata"]["returned"] == 0
    attempts = platform.audit(action="platform.tenant.read_attempt")
    assert len(attempts) == 1 and attempts[0]["target_id"] == str(unknown)


def test_a_registry_read_of_an_unknown_tenant_fails_closed_when_it_cannot_be_audited(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    import saas_os.core.platform_authority as platform_package

    reader, _ = platform.operator([P.TENANT_READ])
    platform.clear_audit()

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("forced audit failure")

    monkeypatch.setattr(platform_package, "record_platform_event_in_transaction", refuse)
    # The audit error is what the caller sees, not the answer about existence.
    with pytest.raises(RuntimeError, match="forced audit failure"):
        read_tenant_registry_entry(uuid.uuid4(), caller=reader)


def test_the_registry_is_paged_by_keyset_and_every_page_is_audited(
    scene: Scene, platform: PlatformWorld
) -> None:
    created = {scene.tenant() for _ in range(5)}
    reader, _ = platform.operator([P.TENANT_READ])
    platform.clear_audit()
    seen: list[uuid.UUID] = []
    cursor: uuid.UUID | None = None
    pages = 0
    while True:
        page = list_tenant_registry(caller=reader, cursor=cursor, limit=2)
        pages += 1
        assert len(page.tenants) <= 2
        seen.extend(entry.id for entry in page.tenants)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    assert seen == sorted(seen) and len(set(seen)) == len(seen)
    assert created <= set(seen)
    assert all(entry.status != "purged" for entry in page.tenants)
    rows = platform.audit(action="platform.tenant.read", outcome="success")
    assert len(rows) == pages
    assert rows[0]["metadata"]["returned"] == 2
    # The request -- cursor and page size -- is in each page's attempt row.
    attempts = platform.audit(action="platform.tenant.read_attempt")
    assert len(attempts) == pages
    assert attempts[0]["metadata"] == {"cursor": None, "page_size": 2}
    assert attempts[1]["metadata"]["cursor"] == str(seen[1])


@pytest.mark.parametrize("limit", [MAX_REGISTRY_PAGE_SIZE + 1, 0, -1, True, "10"])
def test_a_registry_request_above_the_maximum_is_rejected_not_clamped(
    platform: PlatformWorld, limit: Any
) -> None:
    reader, _ = platform.operator([P.TENANT_READ])
    platform.clear_audit()
    with pytest.raises(InvalidPlatformRequestError):
        list_tenant_registry(caller=reader, limit=limit)
    assert platform.audit_count() == 0
    assert len(list_tenant_registry(caller=reader, limit=MAX_REGISTRY_PAGE_SIZE).tenants) >= 0


# --- the commercial overview -------------------------------------------------------------


def _subscribed(scene: Scene) -> tuple[uuid.UUID, str]:
    tenant = scene.tenant(active=True)
    plan_key = f"pc-plan-{uuid.uuid4().hex[:10]}"
    create_plan(plan_key, "Phase C plan", entitlements={"widgets": 1})
    subscribe(tenant, plan_key, provider=FakeBillingProvider())
    return tenant, plan_key


def _overview_entry(reader: UserCaller, tenant: uuid.UUID) -> Any:
    cursor: uuid.UUID | None = None
    while True:
        page = commercial_overview(caller=reader, cursor=cursor, limit=MAX_OVERVIEW_PAGE_SIZE)
        for entry in page.tenants:
            if entry.tenant_id == tenant:
                return entry
        assert page.next_cursor is not None, "tenant not found in the overview"
        cursor = page.next_cursor


def test_the_overview_needs_the_permission_and_returns_only_the_projection(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant, plan_key = _subscribed(scene)
    other, other_plan = _subscribed(scene)
    for caller in (
        *_everyone_else(scene, platform, tenant, P.BILLING_READ),
        PROVISIONING,
        BILLING,
    ):
        with pytest.raises(PlatformNotAuthorizedError):
            commercial_overview(caller=caller)
    reader, _ = platform.operator([P.BILLING_READ])
    platform.clear_audit()

    entry = _overview_entry(reader, tenant)
    assert len(entry.subscriptions) == 1
    subscription = entry.subscriptions[0]
    assert set(vars(subscription)) == {"status", "plan_key", "payer_tenant_id", "updated_at"}
    assert subscription.plan_key == plan_key
    # One tenant's rows never appear in another tenant's entry.
    assert [s.plan_key for s in _overview_entry(reader, other).subscriptions] == [other_plan]
    assert len(entry.subscriptions) <= MAX_SUBSCRIPTIONS_PER_TENANT

    rows = platform.audit(action="platform.billing.read", outcome="success")
    assert rows and all(r["actor_user_id"] == reader.user_id for r in rows)
    assert set(rows[0]["metadata"]) == {"attempt_id", "returned"}
    attempts = platform.audit(action="platform.billing.read_attempt")
    assert len(attempts) == len(rows)
    assert set(attempts[0]["metadata"]) == {"cursor", "page_size"}
    flat = str(platform.audit())
    assert plan_key not in flat and str(tenant) not in flat  # no returned value in the evidence


def test_a_suspended_tenant_is_in_the_overview_and_support_access_changes_nothing(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant, plan_key = _subscribed(scene)
    scene.set_status(tenant, TenantStatus.SUSPENDED)
    reader, _ = platform.operator([P.BILLING_READ])
    assert [s.plan_key for s in _overview_entry(reader, tenant).subscriptions] == [plan_key]


@pytest.mark.parametrize("limit", [MAX_OVERVIEW_PAGE_SIZE + 1, 0, True])
def test_an_overview_request_above_the_maximum_is_rejected(
    platform: PlatformWorld, limit: Any
) -> None:
    reader, _ = platform.operator([P.BILLING_READ])
    platform.clear_audit()
    with pytest.raises(InvalidPlatformRequestError):
        commercial_overview(caller=reader, limit=limit)
    assert platform.audit_count() == 0


def test_a_failure_in_the_middle_of_a_page_returns_nothing_and_binds_nothing(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    _subscribed(scene)
    _subscribed(scene)
    reader, _ = platform.operator([P.BILLING_READ])
    platform.clear_audit()
    real = oversight._tenant_subscriptions
    calls = {"n": 0}
    captured: dict[str, Any] = {}

    def fail_on_second(session: Any, tenant_id: uuid.UUID) -> Any:
        calls["n"] += 1
        captured["session"] = session
        if calls["n"] == 2:
            raise RuntimeError("forced failure in the middle of a page")
        return real(session, tenant_id)

    monkeypatch.setattr(oversight, "_tenant_subscriptions", fail_on_second)
    with pytest.raises(RuntimeError):
        commercial_overview(caller=reader, limit=MAX_OVERVIEW_PAGE_SIZE)
    # The completion row was never written and nothing of the read
    # survived; the attempt row, committed before the read, did; a failure
    # row was written separately.
    assert platform.audit(action="platform.billing.read", outcome="success") == []
    assert len(platform.audit(action="platform.billing.read_attempt")) == 1
    assert [
        r["reason"] for r in platform.audit(action="platform.billing.read", outcome="failure")
    ] == ["error"]
    # No tenant is left bound on a pooled connection.
    with session_scope() as session:
        bound = session.execute(text("SELECT current_setting('app.tenant_id', true)")).scalar_one()
    assert bound in (None, "")
