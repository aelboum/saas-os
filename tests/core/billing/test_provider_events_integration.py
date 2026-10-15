"""ADR-0048 -- inbound billing-provider events against real PostgreSQL
with the restricted `saas_os_app` runtime role.

`process_provider_event()` records each event once in the global
`core.billing_provider_events` ledger, resolves its subscription only
through SaaS OS's own reference index and only for an account of a
merchant the platform tenant owns, and reconciles from the provider's
current state as `SystemCaller(BILLING_OPERATIONS)`. These tests cover
activation, duplicates, out-of-order events, every `ignored` reason, a
provider outage and its redelivery, concurrent deliveries, the audit
evidence, a malformed notice and retention pruning.

Marked `integration`; see tests/core/billing/test_commercial_parties_
integration.py's docstring for how to run against a local database.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from lifecycle_callers import PROVISIONING
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.billing import provider_events
from saas_os.core.billing.catalog import create_owned_plan
from saas_os.core.billing.commercial import create_subscription
from saas_os.core.billing.errors import (
    InvalidBillingPartyError,
    LegacyReconciliationError,
    ProviderEventProcessingError,
)
from saas_os.core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_or_create_billing_account,
)
from saas_os.core.billing.provider import (
    FakeBillingProvider,
    ProviderEventNotice,
    ProviderSubscriptionState,
)
from saas_os.core.billing.provider_events import (
    UNKNOWN_SUBSCRIPTION_GRACE,
    ProviderEventOutcome,
    ProviderEventStatus,
    process_provider_event,
    prune_provider_events,
)
from saas_os.core.billing.service import get_subscription
from saas_os.core.tenancy import create_tenant, get_tenancy_config
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

P = ProviderSubscriptionState
_BILLING_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)
_SYSTEM = _BILLING_SYSTEM


@pytest.fixture(autouse=True)
def _require_schema() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT status FROM core.billing_provider_events LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"ADR-0048 schema missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _admin(sql: str, **params: object) -> list[tuple[Any, ...]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(sql), params)
            return [tuple(row) for row in result.all()] if result.returns_rows else []
    finally:
        engine.dispose()


class _CountingProvider(FakeBillingProvider):
    """The "external" provider: counts state reads, so a test can prove a
    duplicate event made no provider call."""

    def __init__(self) -> None:
        super().__init__(initial_state=P.PENDING)
        self.status_reads = 0

    def get_subscription_status(
        self, *, provider_subscription_id: str
    ) -> ProviderSubscriptionState:
        self.status_reads += 1
        return super().get_subscription_status(provider_subscription_id=provider_subscription_id)


class _Env:
    """A platform tenant with an active `fake` merchant, a service tenant
    with one pending subscription, and the ledger rows the test made."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.event_ids: list[str] = []
        self.platform = self.tenant("platform")
        monkeypatch.setenv("PLATFORM_TENANT_ID", str(self.platform))
        get_tenancy_config.cache_clear()
        self.merchant = create_merchant_account(
            _SYSTEM,
            self.platform,
            provider="fake",
            provider_account_ref=_unique("acct"),
            status=MerchantAccountStatus.ACTIVE,
        )
        self.provider = _CountingProvider()

    def tenant(self, label: str) -> uuid.UUID:
        tenant = create_tenant(_unique(label), caller=PROVISIONING)
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def subscription(self) -> tuple[uuid.UUID, uuid.UUID, str]:
        """(service tenant, subscription id, provider subscription ref), pending."""
        service = self.tenant("service")
        account, _ = get_or_create_billing_account(
            _SYSTEM,
            service,
            merchant_tenant_id=self.platform,
            merchant_account_id=self.merchant.id,
        )
        plan = create_owned_plan(
            _BILLING_SYSTEM,
            self.platform,
            merchant_account_id=self.merchant.id,
            key=_unique("adr48-plan"),
            name="Events plan",
            entitlements={"seats": 2},
        )
        _, result = create_subscription(
            _SYSTEM,
            service_tenant_id=service,
            payer_tenant_id=service,
            billing_account_id=account.id,
            plan_id=plan.id,
            idempotency_key=_unique("idem"),
            provider=self.provider,
        )
        assert result.status == "pending"
        return service, result.subscription_id, result.provider_subscription_id

    def notice(
        self,
        subscription_ref: str | None,
        *,
        event_id: str | None = None,
        account: str | None = None,
    ) -> ProviderEventNotice:
        event_id = event_id or _unique("evt")
        self.event_ids.append(event_id)
        return ProviderEventNotice(
            provider="fake",
            event_id=event_id,
            event_type="subscription.updated",
            provider_account_ref=account,
            provider_subscription_ref=subscription_ref,
        )

    def ledger(self, event_id: str) -> tuple[Any, ...] | None:
        rows = _admin(
            "SELECT status, outcome, attempts, last_error_code, processed_at IS NOT NULL "
            "FROM core.billing_provider_events WHERE provider = 'fake' AND event_id = :e",
            e=event_id,
        )
        return rows[0] if rows else None

    def cleanup(self) -> None:
        params = {"t": [str(t) for t in self.tenant_ids], "e": self.event_ids}
        for statement in (
            "DELETE FROM core.billing_provider_events WHERE event_id = ANY(:e)",
            "DELETE FROM core.audit_log WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.outbox_consumptions WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.outbox_events WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.billing_seller_subscriptions WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.billing_payer_subscriptions WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.idempotency_records WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.billing_provider_refs WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.billing_subscriptions WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.billing_accounts WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.billing_plan_offers WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.billing_plans WHERE owner_tenant_id = ANY(:t)",
            "DELETE FROM core.billing_merchant_accounts WHERE tenant_id = ANY(:t)",
            "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) OR ancestor_id = ANY(:t)",
            "DELETE FROM core.platform_audit_log WHERE target_tenant_id = ANY(:t)",
            "DELETE FROM core.tenants WHERE id = ANY(:t)",
        ):
            _admin(statement, **params)


def _backdate(event_id: str, by: timedelta) -> None:
    _admin(
        "UPDATE core.billing_provider_events SET created_at = now() - make_interval(secs => :s) "
        "WHERE event_id = :e",
        s=by.total_seconds(),
        e=event_id,
    )


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Env]:
    environment = _Env(monkeypatch)
    try:
        yield environment
    finally:
        environment.cleanup()
        get_tenancy_config.cache_clear()


# --- processing ------------------------------------------------------------------


def test_an_event_activates_a_paid_subscription_from_the_providers_state(env: _Env) -> None:
    service, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    notice = env.notice(ref)

    result = process_provider_event(notice, provider=env.provider)

    assert (result.status, result.outcome, result.duplicate) == (
        ProviderEventStatus.PROCESSED,
        ProviderEventOutcome.CHANGED,
        False,
    )
    assert get_subscription(service, subscription_id).status == "active"
    assert env.ledger(notice.event_id) == ("processed", "changed", 1, None, True)


def test_the_change_is_audited_as_the_billing_system_authority(env: _Env) -> None:
    service, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    process_provider_event(env.notice(ref), provider=env.provider)
    rows = _admin(
        "SELECT actor_type, actor_user_id FROM core.audit_log "
        "WHERE tenant_id = :t AND resource_id = :s "
        "AND action = 'billing.subscription_status_changed'",
        t=str(service),
        s=str(subscription_id),
    )
    assert rows, "the status change must be audited"
    assert {(r[0], r[1]) for r in rows} == {("system", None)}


def test_a_duplicate_event_does_nothing_and_calls_no_provider(env: _Env) -> None:
    _, _, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    notice = env.notice(ref)
    process_provider_event(notice, provider=env.provider)
    reads = env.provider.status_reads

    again = process_provider_event(notice, provider=env.provider)

    assert (again.status, again.outcome, again.duplicate) == (
        ProviderEventStatus.PROCESSED,
        None,
        True,
    )
    assert env.provider.status_reads == reads
    assert env.ledger(notice.event_id) == ("processed", "changed", 1, None, True)


def test_a_late_event_cannot_move_a_subscription_backwards(env: _Env) -> None:
    """The event body is never applied: an earlier "it became active"
    event delivered after the cancellation leaves it canceled."""
    service, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.CANCELED)
    process_provider_event(env.notice(ref), provider=env.provider)
    assert get_subscription(service, subscription_id).status == "canceled"

    late = process_provider_event(env.notice(ref), provider=env.provider)

    assert (late.status, late.outcome) == (
        ProviderEventStatus.PROCESSED,
        ProviderEventOutcome.UNCHANGED,
    )
    assert get_subscription(service, subscription_id).status == "canceled"


def test_an_event_naming_the_platform_merchants_account_is_processed(env: _Env) -> None:
    service, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.PAST_DUE)
    result = process_provider_event(
        env.notice(ref, account=env.merchant.provider_account_ref), provider=env.provider
    )
    assert result.outcome is ProviderEventOutcome.CHANGED
    assert get_subscription(service, subscription_id).status == "past_due"


# --- ignored ---------------------------------------------------------------------


def test_an_event_about_no_subscription_is_ignored(env: _Env) -> None:
    notice = env.notice(None)
    result = process_provider_event(notice, provider=env.provider)
    assert (result.status, result.outcome) == (
        ProviderEventStatus.IGNORED,
        ProviderEventOutcome.NO_SUBSCRIPTION,
    )
    assert env.ledger(notice.event_id) == ("ignored", "no_subscription", 1, None, True)
    assert env.provider.status_reads == 0


def test_an_unknown_subscription_is_retried_then_ignored_after_the_grace(env: _Env) -> None:
    """Within `UNKNOWN_SUBSCRIPTION_GRACE` of first receipt the event is
    `failed`, so the provider redelivers; after it, `ignored`."""
    notice = env.notice(_unique("sub"))
    with pytest.raises(ProviderEventProcessingError) as raised:
        process_provider_event(notice, provider=env.provider)
    assert raised.value.error_code == "SubscriptionNotYetKnownError"
    assert env.ledger(notice.event_id) == ("failed", None, 1, "SubscriptionNotYetKnownError", False)

    _backdate(notice.event_id, UNKNOWN_SUBSCRIPTION_GRACE + timedelta(minutes=1))
    result = process_provider_event(notice, provider=env.provider)

    assert (result.status, result.outcome) == (
        ProviderEventStatus.IGNORED,
        ProviderEventOutcome.UNKNOWN_SUBSCRIPTION,
    )
    assert env.ledger(notice.event_id) == ("ignored", "unknown_subscription", 2, None, True)
    assert env.provider.status_reads == 0


def test_an_event_that_arrives_before_its_subscription_is_known_is_applied_later(
    env: _Env,
) -> None:
    """The race the grace exists for: the provider creates the
    subscription, and its event arrives before SaaS OS has registered the
    reference. Simulated by removing the reference, then restoring it."""
    service, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    [saved] = _admin(
        "DELETE FROM core.billing_provider_refs WHERE local_object_id = :s "
        "RETURNING id, provider, provider_account_ref, object_type, provider_object_ref, "
        "tenant_id, local_object_type, local_object_id",
        s=str(subscription_id),
    )
    notice = env.notice(ref)
    with pytest.raises(ProviderEventProcessingError):
        process_provider_event(notice, provider=env.provider)
    assert get_subscription(service, subscription_id).status == "pending"

    _admin(
        "INSERT INTO core.billing_provider_refs (id, provider, provider_account_ref, "
        "object_type, provider_object_ref, tenant_id, local_object_type, local_object_id) "
        "VALUES (:id, :p, :a, :o, :r, :t, :lt, :l)",
        id=saved[0],
        p=saved[1],
        a=saved[2],
        o=saved[3],
        r=saved[4],
        t=saved[5],
        lt=saved[6],
        l=saved[7],
    )
    result = process_provider_event(notice, provider=env.provider)

    assert result.outcome is ProviderEventOutcome.CHANGED
    assert get_subscription(service, subscription_id).status == "active"
    assert env.ledger(notice.event_id) == ("processed", "changed", 2, None, True)


def test_an_event_from_an_account_the_platform_does_not_own_is_ignored(env: _Env) -> None:
    """Even for a subscription the index knows: only the platform tenant's
    merchant accounts are processed (Connect is deferred)."""
    service, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    reads = env.provider.status_reads
    result = process_provider_event(env.notice(ref, account=_unique("acct")), provider=env.provider)
    assert result.outcome is ProviderEventOutcome.FOREIGN_ACCOUNT
    assert get_subscription(service, subscription_id).status == "pending"
    assert env.provider.status_reads == reads


def test_a_merchant_of_another_tenant_is_not_the_platforms(env: _Env) -> None:
    other = env.tenant("seller")
    foreign = create_merchant_account(
        _SYSTEM,
        other,
        provider="fake",
        provider_account_ref=_unique("acct"),
        status=MerchantAccountStatus.ACTIVE,
    )
    _, _, ref = env.subscription()
    result = process_provider_event(
        env.notice(ref, account=foreign.provider_account_ref), provider=env.provider
    )
    assert result.outcome is ProviderEventOutcome.FOREIGN_ACCOUNT


def test_a_legacy_subscription_is_ignored(env: _Env, monkeypatch: pytest.MonkeyPatch) -> None:
    """A legacy row leaves that state only through
    `reconcile_legacy_subscription()`; an event does not touch it."""
    _, subscription_id, ref = env.subscription()

    def refuse(*args: object, **kwargs: object) -> None:
        raise LegacyReconciliationError(subscription_id, "legacy")

    monkeypatch.setattr(provider_events, "reconcile_subscription_status", refuse)
    result = process_provider_event(env.notice(ref), provider=env.provider)
    assert (result.status, result.outcome) == (
        ProviderEventStatus.IGNORED,
        ProviderEventOutcome.LEGACY_UNVERIFIED,
    )


# --- failure and redelivery --------------------------------------------------------


def test_a_provider_outage_fails_the_event_and_a_redelivery_processes_it(env: _Env) -> None:
    service, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    env.provider.status_unavailable = True
    notice = env.notice(ref)

    with pytest.raises(ProviderEventProcessingError) as raised:
        process_provider_event(notice, provider=env.provider)
    assert raised.value.error_code == "BillingProviderError"
    assert env.ledger(notice.event_id) == ("failed", None, 1, "BillingProviderError", False)
    assert get_subscription(service, subscription_id).status == "pending"

    env.provider.status_unavailable = False
    result = process_provider_event(notice, provider=env.provider)

    assert result.outcome is ProviderEventOutcome.CHANGED
    assert env.ledger(notice.event_id) == ("processed", "changed", 2, None, True)
    assert get_subscription(service, subscription_id).status == "active"


def test_a_late_failure_does_not_overwrite_a_finished_event(env: _Env) -> None:
    _, _, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    notice = env.notice(ref)
    process_provider_event(notice, provider=env.provider)

    provider_events._mark_failed(notice, "LateError")

    assert env.ledger(notice.event_id) == ("processed", "changed", 1, None, True)


def test_a_late_terminal_mark_does_not_overwrite_a_finished_event(env: _Env) -> None:
    """The first run to finish decides: a slower run that concluded
    `ignored` cannot overwrite `processed`."""
    _, _, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    notice = env.notice(ref)
    process_provider_event(notice, provider=env.provider)

    provider_events._mark(
        notice, ProviderEventStatus.IGNORED, ProviderEventOutcome.UNKNOWN_SUBSCRIPTION
    )

    assert env.ledger(notice.event_id) == ("processed", "changed", 1, None, True)


def test_a_ledger_failure_is_a_processing_error(env: _Env, monkeypatch: pytest.MonkeyPatch) -> None:
    def unreachable(notice: ProviderEventNotice) -> None:
        raise OperationalError("SELECT 1", {}, Exception("down"))

    monkeypatch.setattr(provider_events, "_claim", unreachable)
    with pytest.raises(ProviderEventProcessingError) as raised:
        process_provider_event(env.notice(None), provider=env.provider)
    assert raised.value.error_code == "OperationalError"


def test_concurrent_deliveries_of_one_event_record_it_once(env: _Env) -> None:
    service, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    notice = env.notice(ref)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(lambda _: process_provider_event(notice, provider=env.provider), range(4))
        )

    assert all(r.status is ProviderEventStatus.PROCESSED for r in results)
    rows = _admin(
        "SELECT count(*) FROM core.billing_provider_events WHERE event_id = :e",
        e=notice.event_id,
    )
    assert rows == [(1,)]
    assert get_subscription(service, subscription_id).status == "active"


def test_a_malformed_notice_is_refused_before_anything_is_recorded(env: _Env) -> None:
    event_id = "e" * 256
    env.event_ids.append(event_id)
    with pytest.raises(InvalidBillingPartyError):
        process_provider_event(
            ProviderEventNotice(provider="fake", event_id=event_id, event_type="x"),
            provider=env.provider,
        )
    assert env.ledger(event_id) is None


def test_an_unbounded_event_type_is_truncated_not_refused(env: _Env) -> None:
    notice = env.notice(None)
    long = ProviderEventNotice(provider="fake", event_id=notice.event_id, event_type="t" * 400)
    process_provider_event(long, provider=env.provider)
    rows = _admin(
        "SELECT length(event_type) FROM core.billing_provider_events WHERE event_id = :e",
        e=notice.event_id,
    )
    assert rows == [(255,)]


# --- retention -------------------------------------------------------------------


def test_pruning_removes_only_rows_past_the_retention_period(env: _Env) -> None:
    old, recent = env.notice(None), env.notice(None)
    process_provider_event(old, provider=env.provider)
    process_provider_event(recent, provider=env.provider)
    _admin(
        "UPDATE core.billing_provider_events SET created_at = now() - interval '91 days' "
        "WHERE event_id = :e",
        e=old.event_id,
    )

    deleted = prune_provider_events(batch_size=1)

    assert deleted >= 1
    assert env.ledger(old.event_id) is None
    assert env.ledger(recent.event_id) is not None


def test_pruning_refuses_a_non_positive_retention() -> None:
    with pytest.raises(ValueError, match="retention"):
        prune_provider_events(retention=timedelta(0))
    with pytest.raises(ValueError, match="batch_size"):
        prune_provider_events(batch_size=0)


def test_pruning_with_a_cutoff_in_the_past_keeps_everything(env: _Env) -> None:
    notice = env.notice(None)
    process_provider_event(notice, provider=env.provider)
    prune_provider_events(current_time=datetime.now(UTC) - timedelta(days=365))
    assert env.ledger(notice.event_id) is not None
