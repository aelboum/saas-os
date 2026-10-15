"""Subscription lifecycle integration tests against Stripe's real
sandbox/test mode (docs/IMPLEMENTATION-ROADMAP.md Phase 5.1's own Tests
requirement, quoted verbatim: "subscription lifecycle integration test
against Stripe's sandbox/test mode, run through the abstraction
interface (not the Stripe SDK directly, in test assertions)").

Every assertion about a subscription is against SaaS OS's own return
values and reads (`saas_os.core.billing` results, `get_entitlements()`,
`list_subscriptions()`, `BillingProviderError`) -- never against a raw
`stripe.Subscription`'s status. The Stripe SDK sets up what happens
outside SaaS OS: prices, Stripe's test cards, paying an invoice as a
payment page would, and test clocks that move a customer's time forward.
Where a test must show *why* Stripe acted (which card was declined), it
checks that cause through the SDK too.

Marked `integration` and excluded from the default `pytest` run. Skips
cleanly (mirrors `tests/infra/test_db_integration.py`'s own unreachable-
dependency convention) when `STRIPE_API_KEY` is not configured for the
local/CI environment -- this environment has no real Stripe test-mode
account, so this test is expected to skip here, not fail. A maintainer
with a real Stripe test-mode secret key can run it locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        STRIPE_API_KEY=sk_test_... \\
        pytest -m integration tests/core/billing/test_billing_stripe_integration.py
"""

from __future__ import annotations

import time
import uuid

import pytest
import stripe
from sqlalchemy import text

# Registers core.users on the shared declarative Base.metadata -- see
# tests/core/billing/test_billing_isolation_integration.py's identical
# import for the full rationale.
import saas_os.core.identity.models  # noqa: F401
from lifecycle_callers import PROVISIONING
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.billing.catalog import create_owned_plan
from saas_os.core.billing.commercial import (
    cancel_commercial_subscription,
    create_subscription,
    reconcile_subscription_status,
)
from saas_os.core.billing.errors import BillingProviderError, LiveSubscriptionExistsError
from saas_os.core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_or_create_billing_account,
)
from saas_os.core.billing.provider import ProviderCommerceContext
from saas_os.core.billing.service import (
    SubscribeResult,
    create_plan,
    get_entitlements,
    list_subscriptions,
    subscribe,
)
from saas_os.core.billing.stripe_provider import StripeBillingProvider
from saas_os.core.tenancy import create_tenant, get_tenancy_config
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.secrets import get_secrets_provider

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.billing_subscriptions LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.billing_subscriptions not reachable: {exc}. "
            "Run `docker compose up -d db` and `alembic upgrade head` first."
        )
    finally:
        probe_engine.dispose()


@pytest.fixture
def stripe_api_key() -> str:
    try:
        api_key = get_secrets_provider().get_required("STRIPE_API_KEY")
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"STRIPE_API_KEY not configured for the integration test: {exc}")
    if not api_key.startswith("sk_test_"):
        pytest.skip(
            "STRIPE_API_KEY is not a test-mode key (must start with 'sk_test_') -- "
            "refusing to run against a live account."
        )
    return api_key


_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)


def _price(client: stripe.StripeClient, amount: int) -> str:
    return client.v1.prices.create(
        params={
            "currency": "usd",
            "unit_amount": amount,
            "recurring": {"interval": "month"},
            "product_data": {"name": f"Test {uuid.uuid4().hex[:8]}"},
        }
    ).id


def _admin(sql: str, **params: object) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(text(sql), params)
    finally:
        engine.dispose()


def _cleanup(tenant_ids: list[uuid.UUID]) -> None:
    params = {"t": [str(t) for t in tenant_ids]}
    for statement in (
        "DELETE FROM core.audit_log WHERE tenant_id = ANY(:t) OR acting_as_tenant_id = ANY(:t)",
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


def test_stripe_commercial_subscription_is_pending_until_paid_then_cancels(
    stripe_api_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Create through the commercial path and the real adapter: `pending`
    with no entitlements until the payer pays the first invoice (here with
    Stripe's test card, as a payment page would), `active` with them after
    reconciliation, and `canceled` with none after cancellation."""
    client = stripe.StripeClient(api_key=stripe_api_key)
    provider = StripeBillingProvider(api_key=stripe_api_key)
    tenant_ids: list[uuid.UUID] = []
    try:
        platform = create_tenant(f"stripe-platform-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        tenant_ids.append(platform.id)
        monkeypatch.setenv("PLATFORM_TENANT_ID", str(platform.id))
        get_tenancy_config.cache_clear()
        merchant = create_merchant_account(
            _SYSTEM,
            platform.id,
            provider="stripe",
            provider_account_ref=f"acct_live_test_{uuid.uuid4().hex[:12]}",
            status=MerchantAccountStatus.ACTIVE,
        )
        service = create_tenant(f"stripe-live-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        tenant_ids.append(service.id)
        account, _ = get_or_create_billing_account(
            _SYSTEM,
            service.id,
            merchant_tenant_id=platform.id,
            merchant_account_id=merchant.id,
        )
        plan = create_owned_plan(
            _SYSTEM,
            platform.id,
            merchant_account_id=merchant.id,
            key=f"stripe-starter-{uuid.uuid4().hex[:8]}",
            name="Starter",
            entitlements={"max_users": 5},
            provider_price_id=_price(client, 1000),
        )

        _, created = create_subscription(
            _SYSTEM,
            service_tenant_id=service.id,
            payer_tenant_id=service.id,
            billing_account_id=account.id,
            plan_id=plan.id,
            idempotency_key=f"live-{uuid.uuid4().hex}",
            provider=provider,
        )
        assert created.status == "pending"
        assert get_entitlements(service.id) == {}

        stripe_subscription = client.v1.subscriptions.retrieve(created.provider_subscription_id)
        card = client.v1.payment_methods.attach(
            "pm_card_visa", params={"customer": str(stripe_subscription.customer)}
        )
        client.v1.invoices.pay(
            str(stripe_subscription.latest_invoice), params={"payment_method": card.id}
        )
        # Stripe settles the invoice synchronously in test mode; a few
        # reads guard against a brief lag before the status is visible.
        for _ in range(5):
            reconciled = reconcile_subscription_status(
                _SYSTEM,
                service_tenant_id=service.id,
                subscription_id=created.subscription_id,
                provider=provider,
            )
            if reconciled.status != "pending":
                break
            time.sleep(1)
        assert reconciled.status == "active"
        assert get_entitlements(service.id) == {"max_users": 5}

        canceled = cancel_commercial_subscription(
            _SYSTEM,
            service_tenant_id=service.id,
            subscription_id=created.subscription_id,
            provider=provider,
        )
        assert canceled.status == "canceled"
        assert get_entitlements(service.id) == {}
    finally:
        get_tenancy_config.cache_clear()
        _cleanup(tenant_ids)


def test_stripe_legacy_subscribe_without_a_payment_method_fails_closed(
    stripe_api_key: str,
) -> None:
    """The legacy `subscribe()` writes `active` as soon as the provider
    creates the subscription, so it must not obtain an unpaid one: Stripe
    refuses a customer with no payment method, and no row is written."""
    client = stripe.StripeClient(api_key=stripe_api_key)
    tenant = create_tenant(f"stripe-legacy-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
    key = f"stripe-legacy-{uuid.uuid4().hex[:8]}"
    try:
        create_plan(
            key, "Legacy", entitlements={"max_users": 5}, provider_price_id=_price(client, 1000)
        )
        with pytest.raises(BillingProviderError) as refused:
            subscribe(tenant.id, key, provider=StripeBillingProvider(api_key=stripe_api_key))
        # Refused for the missing payment, not for anything else (a bad key,
        # a bad price, the network).
        cause = refused.value.__cause__
        assert isinstance(cause, stripe.InvalidRequestError)
        assert "payment method" in str(cause.user_message or cause).lower()
        assert list_subscriptions(tenant.id) == []
        assert get_entitlements(tenant.id) == {}
    finally:
        # Also removes a subscription row, should one have been written.
        _cleanup([tenant.id])
        _admin("DELETE FROM core.billing_plans WHERE key = :k", k=key)


class _ClockedStripeProvider(StripeBillingProvider):
    """The real adapter, except that the payer's Stripe customer is created
    on a Stripe test clock, so a test can move that customer's time
    forward (renewals, expiry). Everything else is the adapter's own."""

    def __init__(self, api_key: str, *, test_clock: str) -> None:
        super().__init__(api_key)
        self._test_clock = test_clock

    def ensure_customer(self, *, context: ProviderCommerceContext, idempotency_key: str) -> str:
        # The adapter's own call, with `test_clock` added.
        try:
            customer = self._client.v1.customers.create(
                params={
                    "test_clock": self._test_clock,
                    "metadata": {"billing_account_id": str(context.payer_billing_account_id)},
                },
                options={"idempotency_key": idempotency_key},
            )
        except stripe.StripeError as exc:
            raise BillingProviderError("ensure_customer", type(exc).__name__) from exc
        return str(customer.id)


class _Commerce:
    """One platform merchant, one service tenant paying for itself, and a
    plan priced in Stripe; created through Core, removed by `cleanup()`."""

    def __init__(
        self,
        client: stripe.StripeClient,
        monkeypatch: pytest.MonkeyPatch,
        tenant_ids: list[uuid.UUID],
    ) -> None:
        platform = create_tenant(f"stripe-platform-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        tenant_ids.append(platform.id)
        monkeypatch.setenv("PLATFORM_TENANT_ID", str(platform.id))
        get_tenancy_config.cache_clear()
        merchant = create_merchant_account(
            _SYSTEM,
            platform.id,
            provider="stripe",
            provider_account_ref=f"acct_live_test_{uuid.uuid4().hex[:12]}",
            status=MerchantAccountStatus.ACTIVE,
        )
        service = create_tenant(f"stripe-live-{uuid.uuid4().hex[:8]}", caller=PROVISIONING)
        tenant_ids.append(service.id)
        self.service_id = service.id
        self.account, _ = get_or_create_billing_account(
            _SYSTEM, service.id, merchant_tenant_id=platform.id, merchant_account_id=merchant.id
        )
        self.plan = create_owned_plan(
            _SYSTEM,
            platform.id,
            merchant_account_id=merchant.id,
            key=f"stripe-starter-{uuid.uuid4().hex[:8]}",
            name="Starter",
            entitlements={"max_users": 5},
            provider_price_id=_price(client, 1000),
        )

    def subscribe(self, provider: StripeBillingProvider) -> SubscribeResult:
        _, created = create_subscription(
            _SYSTEM,
            service_tenant_id=self.service_id,
            payer_tenant_id=self.service_id,
            billing_account_id=self.account.id,
            plan_id=self.plan.id,
            idempotency_key=f"live-{uuid.uuid4().hex}",
            provider=provider,
        )
        return created

    def reconcile_until(
        self,
        subscription_id: uuid.UUID,
        provider: StripeBillingProvider,
        want: str,
        *,
        seconds: int = 30,
    ) -> str:
        """Reconcile until the status is `want` or `seconds` pass; returns
        the last status. Stripe applies a test clock's effects (renewal
        attempts, expiry) shortly after the clock is ready."""
        status = ""
        for _ in range(seconds):
            try:
                status = reconcile_subscription_status(
                    _SYSTEM,
                    service_tenant_id=self.service_id,
                    subscription_id=subscription_id,
                    provider=provider,
                ).status
            except BillingProviderError:
                # A transient provider error is one more poll, not a
                # failure: the loop exists to wait.
                status = "provider_error"
            if status == want:
                break
            time.sleep(1)
        return status


def _card(client: stripe.StripeClient, customer: str, test_card: str) -> str:
    return client.v1.payment_methods.attach(test_card, params={"customer": customer}).id


def _clock(client: stripe.StripeClient) -> tuple[str, int]:
    now = int(time.time())
    clock = client.v1.test_helpers.test_clocks.create(params={"frozen_time": now})
    return clock.id, now


def _advance(client: stripe.StripeClient, clock: str, to: int) -> None:
    client.v1.test_helpers.test_clocks.advance(clock, params={"frozen_time": to})
    for _ in range(120):
        state = client.v1.test_helpers.test_clocks.retrieve(clock).status
        if state == "ready":
            return
        if state == "internal_failure":
            raise AssertionError("the Stripe test clock failed to advance")
        time.sleep(1)
    raise AssertionError("the Stripe test clock did not finish advancing")


def test_stripe_declined_first_payment_stays_pending(
    stripe_api_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A card that is declined when charged: the first invoice stays
    unpaid, Stripe keeps the subscription `incomplete`, and SaaS OS keeps
    it `pending` with no entitlements."""
    client = stripe.StripeClient(api_key=stripe_api_key)
    clock, _ = _clock(client)
    provider = _ClockedStripeProvider(stripe_api_key, test_clock=clock)
    tenant_ids: list[uuid.UUID] = []
    try:
        commerce = _Commerce(client, monkeypatch, tenant_ids)
        created = commerce.subscribe(provider)
        stripe_subscription = client.v1.subscriptions.retrieve(created.provider_subscription_id)
        declining = _card(client, str(stripe_subscription.customer), "pm_card_chargeCustomerFail")
        with pytest.raises(stripe.CardError) as declined:
            client.v1.invoices.pay(
                str(stripe_subscription.latest_invoice), params={"payment_method": declining}
            )
        assert declined.value.code == "card_declined"
        reconciled = reconcile_subscription_status(
            _SYSTEM,
            service_tenant_id=commerce.service_id,
            subscription_id=created.subscription_id,
            provider=provider,
        )
        assert reconciled.status == "pending"
        assert get_entitlements(commerce.service_id) == {}
    finally:
        try:
            get_tenancy_config.cache_clear()
            _cleanup(tenant_ids)
        finally:
            client.v1.test_helpers.test_clocks.delete(clock)


def test_stripe_failed_renewal_is_past_due_without_entitlements(
    stripe_api_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Paid for the first month, then the renewal is charged to a card that
    is declined (a Stripe test clock moves the customer past the period
    end): Stripe makes the subscription `past_due`, and SaaS OS follows
    with no entitlements."""
    client = stripe.StripeClient(api_key=stripe_api_key)
    clock, now = _clock(client)
    provider = _ClockedStripeProvider(stripe_api_key, test_clock=clock)
    tenant_ids: list[uuid.UUID] = []
    try:
        commerce = _Commerce(client, monkeypatch, tenant_ids)
        created = commerce.subscribe(provider)
        stripe_subscription = client.v1.subscriptions.retrieve(created.provider_subscription_id)
        customer = str(stripe_subscription.customer)
        good = _card(client, customer, "pm_card_visa")
        client.v1.invoices.pay(
            str(stripe_subscription.latest_invoice), params={"payment_method": good}
        )
        assert commerce.reconcile_until(created.subscription_id, provider, "active") == "active"
        assert get_entitlements(commerce.service_id) == {"max_users": 5}

        declining = _card(client, customer, "pm_card_chargeCustomerFail")
        client.v1.subscriptions.update(
            created.provider_subscription_id, params={"default_payment_method": declining}
        )
        _advance(client, clock, now + 35 * 24 * 3600)
        status = commerce.reconcile_until(created.subscription_id, provider, "past_due", seconds=60)
        assert status == "past_due"
        assert get_entitlements(commerce.service_id) == {}
        # The cause is the declining card: it is what the renewal charged.
        renewed = client.v1.subscriptions.retrieve(created.provider_subscription_id)
        assert renewed.default_payment_method == declining
        renewal = client.v1.invoices.retrieve(str(renewed.latest_invoice))
        assert renewal.status == "open"
        assert renewal.attempt_count >= 1
    finally:
        try:
            get_tenancy_config.cache_clear()
            _cleanup(tenant_ids)
        finally:
            client.v1.test_helpers.test_clocks.delete(clock)


def test_stripe_unpaid_first_invoice_expires_to_canceled(
    stripe_api_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A first invoice nobody pays: after 23 hours Stripe expires the
    subscription (`incomplete_expired`), SaaS OS reconciles it to `canceled`
    with no entitlements, and it no longer stops the payer from
    subscribing again."""
    client = stripe.StripeClient(api_key=stripe_api_key)
    clock, now = _clock(client)
    provider = _ClockedStripeProvider(stripe_api_key, test_clock=clock)
    tenant_ids: list[uuid.UUID] = []
    try:
        commerce = _Commerce(client, monkeypatch, tenant_ids)
        created = commerce.subscribe(provider)
        with pytest.raises(LiveSubscriptionExistsError):
            commerce.subscribe(provider)

        _advance(client, clock, now + 2 * 24 * 3600)
        status = commerce.reconcile_until(created.subscription_id, provider, "canceled", seconds=60)
        assert status == "canceled"
        assert get_entitlements(commerce.service_id) == {}
        assert commerce.subscribe(provider).status == "pending"
    finally:
        try:
            get_tenancy_config.cache_clear()
            _cleanup(tenant_ids)
        finally:
            client.v1.test_helpers.test_clocks.delete(clock)
