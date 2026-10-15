"""ADR-0048 -- `POST /v1/billing/providers/stripe/events` end to end:
a signed Stripe delivery through `build_platform_app()`, the router, the
ledger and reconciliation, against real PostgreSQL and Redis.

The provider is an in-memory adapter named `stripe` (a
`FakeBillingProvider` subclass), so reconciliation reads a state the test
controls; deliveries are signed exactly as Stripe signs them, so the
SDK's own verification runs unmodified. Each test uses a rate-limit key
of its own.

Marked `integration`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from lifecycle_callers import PROVISIONING
from saas_os.api.platform import build_platform_app
from saas_os.api.route_policy import RoutePolicyKind, assert_route_policies
from saas_os.api.v1 import billing_events
from saas_os.api.v1.billing_events import (
    MAX_EVENT_BODY_BYTES,
    STRIPE_EVENTS_PATH,
    build_stripe_billing_events_router,
)
from saas_os.core.authority import SystemAuthority, SystemCaller
from saas_os.core.billing.catalog import create_owned_plan
from saas_os.core.billing.commercial import create_subscription
from saas_os.core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_or_create_billing_account,
)
from saas_os.core.billing.provider import FakeBillingProvider, ProviderSubscriptionState
from saas_os.core.billing.service import get_subscription
from saas_os.core.tenancy import create_tenant, get_tenancy_config
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.ratelimit import get_ratelimit_config
from saas_os.infra.secrets.provider import SecretNotFoundError

pytestmark = pytest.mark.integration

P = ProviderSubscriptionState
_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)
_SECRET = "whsec_router_integration_only"  # pragma: allowlist secret


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
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _admin(sql: str, **params: object) -> list[tuple[Any, ...]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(sql), params)
            return [tuple(row) for row in result.all()] if result.returns_rows else []
    finally:
        engine.dispose()


class _StripeShapedProvider(FakeBillingProvider):
    """An in-memory adapter that answers to the name `stripe`."""

    name = "stripe"


class _Env:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.event_ids: list[str] = []
        self.platform = self.tenant("platform")
        monkeypatch.setenv("PLATFORM_TENANT_ID", str(self.platform))
        get_tenancy_config.cache_clear()
        self.merchant = create_merchant_account(
            _SYSTEM,
            self.platform,
            provider="stripe",
            provider_account_ref=_unique("acct"),
            status=MerchantAccountStatus.ACTIVE,
        )
        self.provider = _StripeShapedProvider(initial_state=P.PENDING)

    def tenant(self, label: str) -> uuid.UUID:
        tenant = create_tenant(_unique(label), caller=PROVISIONING)
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def subscription(self) -> tuple[uuid.UUID, uuid.UUID, str]:
        service = self.tenant("service")
        account, _ = get_or_create_billing_account(
            _SYSTEM,
            service,
            merchant_tenant_id=self.platform,
            merchant_account_id=self.merchant.id,
        )
        plan = create_owned_plan(
            _SYSTEM,
            self.platform,
            merchant_account_id=self.merchant.id,
            key=_unique("adr48-http"),
            name="Events plan",
            entitlements={"seats": 1},
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
        return service, result.subscription_id, result.provider_subscription_id

    def event(self, subscription_ref: str | None, *, event_id: str | None = None) -> bytes:
        event_id = event_id or _unique("evt")
        self.event_ids.append(event_id)
        obj: dict[str, Any] = (
            {"object": "subscription", "id": subscription_ref}
            if subscription_ref
            else {"object": "customer", "id": "cus_1"}
        )
        return json.dumps(
            {
                "id": event_id,
                "object": "event",
                "type": "customer.subscription.updated",
                "data": {"object": obj},
            }
        ).encode()

    def ledger(self, body: bytes) -> tuple[Any, ...] | None:
        rows = _admin(
            "SELECT status, outcome, attempts FROM core.billing_provider_events "
            "WHERE provider = 'stripe' AND event_id = :e",
            e=json.loads(body)["id"],
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


def _signed(body: bytes, *, secret: str = _SECRET, at: int | None = None) -> str:
    timestamp = int(time.time()) if at is None else at
    signature = hmac.new(
        secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256
    ).hexdigest()
    return f"t={timestamp},v1={signature}"


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Env]:
    # A rate-limit key of this test's own: the route's key is fixed.
    monkeypatch.setattr(billing_events, "_RATE_LIMIT_KEY", _unique("billing-events-test"))
    environment = _Env(monkeypatch)
    try:
        yield environment
    finally:
        environment.cleanup()
        get_tenancy_config.cache_clear()


@pytest.fixture
def client(env: _Env) -> Iterator[TestClient]:
    app: FastAPI = build_platform_app(title="billing events", version="test")
    app.include_router(
        build_stripe_billing_events_router(provider=env.provider, webhook_secret=_SECRET)
    )
    with TestClient(app) as test_client:  # runs the lifespan: route policies, DB role guard
        yield test_client


def _deliver(client: TestClient, body: bytes, header: str | None = None, **headers: str):
    if header is None:
        header = _signed(body)
    if header:
        headers["Stripe-Signature"] = header
    headers.setdefault("Content-Type", "application/json")
    return client.post(STRIPE_EVENTS_PATH, content=body, headers=headers)


# --- accepted deliveries ---------------------------------------------------------


def test_a_signed_event_reconciles_the_subscription(env: _Env, client: TestClient) -> None:
    service, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    body = env.event(ref)

    response = _deliver(client, body)

    assert (response.status_code, response.json()) == (200, {"status": "processed"})
    assert get_subscription(service, subscription_id).status == "active"
    assert env.ledger(body) == ("processed", "changed", 1)


def test_a_redelivery_is_answered_without_processing_again(env: _Env, client: TestClient) -> None:
    _, _, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    body = env.event(ref)
    assert _deliver(client, body).status_code == 200

    again = _deliver(client, body)

    assert (again.status_code, again.json()) == (200, {"status": "processed"})
    assert env.ledger(body) == ("processed", "changed", 1)


def test_an_unknown_subscription_is_retried_then_accepted_as_ignored(
    env: _Env, client: TestClient
) -> None:
    body = env.event(_unique("sub"))
    first = _deliver(client, body)
    assert first.status_code == 503
    assert env.ledger(body) == ("failed", None, 1)

    _admin(
        "UPDATE core.billing_provider_events SET created_at = now() - interval '2 hours' "
        "WHERE event_id = :e",
        e=json.loads(body)["id"],
    )
    later = _deliver(client, body)
    assert (later.status_code, later.json()) == (200, {"status": "ignored"})
    assert env.ledger(body) == ("ignored", "unknown_subscription", 2)


def test_a_verified_event_core_cannot_record_is_400(env: _Env, client: TestClient) -> None:
    body = env.event(None, event_id="e" * 300)
    response = _deliver(client, body)
    assert (response.status_code, response.json()) == (400, {"detail": "invalid_event"})
    assert env.ledger(body) is None


def test_a_failed_processing_is_503_and_the_redelivery_succeeds(
    env: _Env, client: TestClient
) -> None:
    service, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    env.provider.status_unavailable = True
    body = env.event(ref)

    failed = _deliver(client, body)

    assert failed.status_code == 503
    assert failed.headers["Retry-After"].isdigit()
    assert "BillingProviderError" not in failed.text
    assert env.ledger(body) == ("failed", None, 1)

    env.provider.status_unavailable = False
    assert _deliver(client, body).status_code == 200
    assert env.ledger(body) == ("processed", "changed", 2)
    assert get_subscription(service, subscription_id).status == "active"


# --- refused deliveries: nothing is recorded ---------------------------------------


@pytest.mark.parametrize(
    "header",
    ["", "t=1,v1=00", "garbage"],
    ids=["missing", "wrong", "malformed"],
)
def test_an_unverified_delivery_is_400_and_records_nothing(
    env: _Env, client: TestClient, header: str
) -> None:
    _, subscription_id, ref = env.subscription()
    env.provider.set_state(ref, P.ACTIVE)
    body = env.event(ref)
    response = _deliver(client, body, header)
    assert (response.status_code, response.json()) == (400, {"detail": "invalid_signature"})
    assert env.ledger(body) is None


def test_a_delivery_signed_with_another_secret_is_refused(env: _Env, client: TestClient) -> None:
    body = env.event(_unique("sub"))
    other = "whsec_someone_else"  # pragma: allowlist secret
    response = _deliver(client, body, _signed(body, secret=other))
    assert response.status_code == 400
    assert env.ledger(body) is None


def test_a_stale_delivery_is_refused(env: _Env, client: TestClient) -> None:
    body = env.event(_unique("sub"))
    response = _deliver(client, body, _signed(body, at=int(time.time()) - 3600))
    assert response.status_code == 400
    assert env.ledger(body) is None


def test_an_oversized_body_is_413_before_verification(env: _Env, client: TestClient) -> None:
    body = env.event(_unique("sub"))
    padded = body[:-1] + b',"pad":"' + b"x" * MAX_EVENT_BODY_BYTES + b'"}'
    response = _deliver(client, padded, _signed(padded))
    assert response.status_code == 413
    assert env.ledger(body) is None


def test_a_session_or_cookie_grants_nothing(env: _Env, client: TestClient) -> None:
    """The route has no credential: a cookie or bearer token neither
    replaces the signature nor is required."""
    body = env.event(None)
    refused = _deliver(
        client, body, "t=1,v1=00", Authorization="Bearer anything", Cookie="saas_os_session=x"
    )
    assert refused.status_code == 400
    accepted = _deliver(client, body, Cookie="saas_os_session=x")
    assert accepted.status_code == 200


def test_the_route_is_rate_limited_per_source(
    env: _Env, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unsigned requests from one source use up only that source's
    allowance: the provider's own delivery, from another, still passes."""
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", "1")
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    get_ratelimit_config.cache_clear()
    attacker = {"X-Forwarded-For": "198.51.100.66"}
    provider = {"X-Forwarded-For": "203.0.113.10"}
    try:
        unsigned = _deliver(client, env.event(None), "t=1,v1=00", **attacker)
        flooded = _deliver(client, env.event(None), "t=1,v1=00", **attacker)
        delivered = _deliver(client, env.event(None), **provider)
        again = _deliver(client, env.event(None), **provider)
    finally:
        get_ratelimit_config.cache_clear()
    assert (unsigned.status_code, flooded.status_code) == (400, 429)
    assert delivered.status_code == 200
    assert again.status_code == 429


@pytest.mark.parametrize("declared", ["abc", "-"])
def test_an_unreadable_content_length_is_400(declared: str) -> None:
    import asyncio

    from starlette.requests import Request

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    request = Request(
        {"type": "http", "method": "POST", "headers": [(b"content-length", declared.encode())]},
        receive,
    )
    with pytest.raises(HTTPException) as raised:
        asyncio.run(billing_events._read_capped(request))
    assert (raised.value.status_code, raised.value.detail) == (400, "invalid_content_length")


# --- building the router ---------------------------------------------------------


def test_building_without_a_secret_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    with pytest.raises(SecretNotFoundError):
        build_stripe_billing_events_router()


def test_building_with_an_empty_secret_fails() -> None:
    with pytest.raises(ValueError, match="secret"):
        build_stripe_billing_events_router(webhook_secret=" ")


def test_the_route_is_public_with_a_stated_reason() -> None:
    app = FastAPI()
    app.include_router(build_stripe_billing_events_router(webhook_secret=_SECRET))
    policies = assert_route_policies(app, production=False)
    [policy] = [p for label, p in policies.items() if STRIPE_EVENTS_PATH in label]
    assert policy.kind is RoutePolicyKind.PUBLIC
    assert "signature" in policy.detail
