"""Billing Foundation v2 Phase 3 -- lifecycle safety against real
PostgreSQL (`41e8273a685d` migrated) with the restricted `saas_os_app`
runtime role:

- provider-confirmed activation: a commercial subscription is `active`
  only when the provider confirms it; pending/past-due/not-found/unknown/
  outage never activate;
- the synchronous refresh boundary, its authorization and its refusal of
  forbidden transitions;
- the one-live-subscription partial unique index, including races;
- legacy-unverified rows and their authorized, auditable reconciliation;
- provider idempotency across retries, concurrency and an abandoned
  (crashed) attempt;
- cross-tenant isolation of every new operation.

Marked `integration`; see tests/core/billing/test_commercial_parties_
integration.py's docstring for how to run against a local database.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import core.identity.models  # noqa: F401  (registers core.users for audit FKs)
import pytest
from core.authority import SystemAuthority, SystemCaller
from core.billing.authorization import BillingActor, trusted_system
from core.billing.catalog import create_owned_plan
from core.billing.commercial import (
    cancel_commercial_subscription,
    create_subscription,
    get_subscription_by_provider_ref,
    reconcile_legacy_subscription,
    reconcile_subscription_status,
)
from core.billing.errors import (
    BillingAccountNotFoundError,
    BillingActorRequiredError,
    BillingNotAuthorizedError,
    BillingProviderContractError,
    BillingProviderError,
    LegacyReconciliationError,
    LiveSubscriptionExistsError,
    ProviderReferenceMismatchError,
    SubscriptionNotFoundError,
)
from core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_or_create_billing_account,
)
from core.billing.provider import FakeBillingProvider, ProviderSubscriptionState
from core.billing.provider_refs import ProviderObjectType
from core.billing.service import (
    cancel_subscription,
    create_plan,
    get_entitlements,
    get_subscription,
    subscribe,
)
from core.idempotency.config import get_idempotency_config
from core.identity.service import add_tenant_membership, create_user
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_role,
    grant_permission,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from core.billing import commercial
from core.idempotency import IdempotencyInProgressError, IdempotencyKeyReusedError
from core.identity import get_membership
from core.tenancy import create_tenant, get_tenancy_config

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

pytestmark = pytest.mark.integration

P = ProviderSubscriptionState


@pytest.fixture(autouse=True)
def _require_lifecycle_schema() -> None:
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
            conn.execute(text("SELECT verification FROM core.billing_subscriptions LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"Phase 3 schema missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _World:
    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        self.plan_keys: list[str] = []

    def tenant(self, label: str) -> uuid.UUID:
        tenant = create_tenant(_unique(label))
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def user(self) -> uuid.UUID:
        user = create_user()
        self.user_ids.append(user.id)
        return user.id

    def plan(self, entitlements: dict[str, object]) -> str:
        key = _unique("p3-plan")
        create_plan(key, "Phase 3 plan", entitlements=entitlements)
        self.plan_keys.append(key)
        return key

    def grant(self, tenant_id: uuid.UUID, user_id: uuid.UUID, perms: list[tuple[str, str]]) -> None:
        membership = get_membership(tenant_id, user_id) or add_tenant_membership(
            tenant_id, user_id, caller=_PROVISIONING
        )
        role = create_role(tenant_id, _unique("role"), caller=_PROVISIONING)
        for resource, action in perms:
            grant_permission(
                tenant_id, role.id, register_permission(resource, action).id, caller=_PROVISIONING
            )
        assign_first_role_for_new_tenant(tenant_id, membership.id, role.id, caller=_PROVISIONING)

    def cleanup(self) -> None:
        params = {
            "t": [str(t) for t in self.tenant_ids],
            "u": [str(u) for u in self.user_ids],
            "k": self.plan_keys,
        }
        engine = build_engine(get_migrations_database_config())
        try:
            factory = build_session_factory(engine)
            with session_scope(session_factory=factory) as session:
                for statement in (
                    "DELETE FROM core.audit_log WHERE tenant_id = ANY(:t) "
                    "OR actor_user_id = ANY(:u)",
                    "DELETE FROM core.outbox_consumptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.outbox_events WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_seller_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_payer_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.idempotency_records WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.usage_events WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_provider_refs WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_accounts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plan_offers WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plans WHERE owner_tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_merchant_accounts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) "
                    "OR ancestor_id = ANY(:t)",
                    "DELETE FROM core.tenants WHERE id = ANY(:t)",
                    "DELETE FROM core.billing_plans WHERE key = ANY(:k)",
                    "DELETE FROM core.users WHERE id = ANY(:u)",
                ):
                    session.execute(text(statement), params)
        finally:
            engine.dispose()


_SYSTEM = trusted_system("phase 3 integration test")
_BILLING_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)


class _Env:
    """A platform tenant with an active `fake` merchant, a fake provider
    (the "external" provider: its memory outlives SaaS-OS calls), and
    helpers."""

    def __init__(self, world: _World, monkeypatch: pytest.MonkeyPatch) -> None:
        self.world = world
        self.platform = world.tenant("platform")
        monkeypatch.setenv("PLATFORM_TENANT_ID", str(self.platform))
        get_tenancy_config.cache_clear()
        self.merchant = self.new_merchant()
        self.provider = _CountingProvider()

    def new_merchant(self):
        return create_merchant_account(
            _SYSTEM,
            self.platform,
            provider="fake",
            provider_account_ref=_unique("acct"),
            status=MerchantAccountStatus.ACTIVE,
        )

    def plan(self, entitlements: dict[str, object], merchant=None) -> uuid.UUID:  # type: ignore[no-untyped-def]
        """A Catalog v2 plan sold by `merchant` (default: the platform
        merchant) -- the commercial path takes owned plans by id."""
        return create_owned_plan(
            _BILLING_SYSTEM,
            self.platform,
            merchant_account_id=(merchant or self.merchant).id,
            key=_unique("p3-plan"),
            name="Commercial plan",
            entitlements=entitlements,
        ).id

    def account(self, payer: uuid.UUID, merchant=None) -> uuid.UUID:
        merchant = merchant or self.merchant
        account, _ = get_or_create_billing_account(
            _SYSTEM, payer, merchant_tenant_id=self.platform, merchant_account_id=merchant.id
        )
        return account.id

    def create(
        self, service: uuid.UUID, *, payer=None, merchant=None, key=None, caller=None, plan=None
    ):
        payer = payer or service
        return create_subscription(
            caller or _SYSTEM,
            service_tenant_id=service,
            payer_tenant_id=payer,
            billing_account_id=self.account(payer, merchant),
            plan_id=plan or self.plan({"seats": 3}, merchant),
            idempotency_key=key or _unique("idem"),
            provider=self.provider,
        )


class _CountingProvider(FakeBillingProvider):
    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(**kwargs)
        self.create_calls = 0

    def create_subscription(self, *, tenant_id, plan, idempotency_key=None, context=None):  # type: ignore[no-untyped-def]
        self.create_calls += 1
        return super().create_subscription(
            tenant_id=tenant_id, plan=plan, idempotency_key=idempotency_key, context=context
        )


@pytest.fixture
def world() -> Iterator[_World]:
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


@pytest.fixture
def env(world: _World, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Env]:
    yield _Env(world, monkeypatch)
    get_tenancy_config.cache_clear()


def _row(tenant_id: uuid.UUID, subscription_id: uuid.UUID):
    return get_subscription(tenant_id, subscription_id)


def _live_count(tenant_id: uuid.UUID) -> int:
    with tenant_session_scope(tenant_id) as session:
        return session.execute(
            text(
                "SELECT count(*) FROM core.billing_subscriptions "
                "WHERE status IN ('pending', 'active', 'past_due')"
            )
        ).scalar_one()


# --- Provider-confirmed activation -------------------------------------------


def test_provider_confirmed_active_becomes_active_and_entitled(world: _World, env: _Env) -> None:
    service = world.tenant("service")
    _, result = env.create(service)
    row = _row(service, result.subscription_id)
    assert (row.status, row.verification) == ("active", "verified")
    assert row.merchant_account_id == env.merchant.id
    assert get_entitlements(service) == {"seats": 3}


@pytest.mark.parametrize(
    ("initial", "expected"),
    [(P.PENDING, "pending"), (P.PAST_DUE, "past_due"), (P.UNKNOWN, "pending")],
)
def test_unconfirmed_provider_states_never_activate(
    world: _World, env: _Env, initial: ProviderSubscriptionState, expected: str
) -> None:
    env.provider.initial_state = initial
    service = world.tenant("service")
    _, result = env.create(service)
    assert result.status == expected
    assert get_entitlements(service) == {}


def test_provider_outage_during_confirmation_leaves_the_row_pending(
    world: _World, env: _Env
) -> None:
    env.provider.status_unavailable = True
    service = world.tenant("service")
    _, result = env.create(service)
    assert result.status == "pending"
    assert get_entitlements(service) == {}
    with pytest.raises(BillingProviderError):
        reconcile_subscription_status(
            _SYSTEM,
            service_tenant_id=service,
            subscription_id=result.subscription_id,
            provider=env.provider,
        )
    assert _row(service, result.subscription_id).status == "pending"

    env.provider.status_unavailable = False
    refreshed = reconcile_subscription_status(
        _SYSTEM,
        service_tenant_id=service,
        subscription_id=result.subscription_id,
        provider=env.provider,
    )
    assert (refreshed.previous_status, refreshed.status, refreshed.changed) == (
        "pending",
        "active",
        True,
    )
    assert get_entitlements(service) == {"seats": 3}


def test_provider_not_found_never_activates(world: _World, env: _Env) -> None:
    env.provider.initial_state = P.PENDING
    service = world.tenant("service")
    _, result = env.create(service)
    env.provider.set_state(result.provider_subscription_id, P.NOT_FOUND)
    refreshed = reconcile_subscription_status(
        _SYSTEM,
        service_tenant_id=service,
        subscription_id=result.subscription_id,
        provider=env.provider,
    )
    assert (refreshed.status, refreshed.changed, refreshed.provider_state) == (
        "pending",
        False,
        P.NOT_FOUND,
    )


def test_refresh_follows_the_provider_through_allowed_transitions_only(
    world: _World, env: _Env
) -> None:
    service = world.tenant("service")
    _, result = env.create(service)
    sub = result.subscription_id

    def refresh() -> str:
        return reconcile_subscription_status(
            _SYSTEM, service_tenant_id=service, subscription_id=sub, provider=env.provider
        ).status

    env.provider.set_state(result.provider_subscription_id, P.PAST_DUE)
    assert refresh() == "past_due" and get_entitlements(service) == {}
    env.provider.set_state(result.provider_subscription_id, P.ACTIVE)
    assert refresh() == "active"
    env.provider.set_state(result.provider_subscription_id, P.CANCELED)
    assert refresh() == "canceled"
    # A canceled subscription is never resurrected by a provider answer.
    env.provider.set_state(result.provider_subscription_id, P.ACTIVE)
    assert refresh() == "canceled"
    assert get_entitlements(service) == {}


def test_status_changes_are_audited(world: _World, env: _Env) -> None:
    env.provider.initial_state = P.PENDING
    service = world.tenant("service")
    _, result = env.create(service)
    env.provider.set_state(result.provider_subscription_id, P.ACTIVE)
    reconcile_subscription_status(
        _SYSTEM,
        service_tenant_id=service,
        subscription_id=result.subscription_id,
        provider=env.provider,
    )
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            actions = [
                row[0]
                for row in conn.execute(
                    text(
                        "SELECT action FROM core.audit_log WHERE resource_id = :r "
                        "ORDER BY created_at"
                    ),
                    {"r": str(result.subscription_id)},
                ).all()
            ]
    finally:
        engine.dispose()
    assert actions == ["billing.subscription_created", "billing.subscription_status_changed"]


def test_refresh_requires_an_explicit_authorized_caller(world: _World, env: _Env) -> None:
    service, outsider = world.tenant("service"), world.user()
    _, result = env.create(service)
    with pytest.raises(BillingActorRequiredError):
        reconcile_subscription_status(
            None, service_tenant_id=service, subscription_id=result.subscription_id
        )
    with pytest.raises(BillingNotAuthorizedError):
        reconcile_subscription_status(
            BillingActor.user(outsider),
            service_tenant_id=service,
            subscription_id=result.subscription_id,
            provider=env.provider,
        )
    world.grant(service, outsider, [("billing.subscription", "read")])
    assert (
        reconcile_subscription_status(
            BillingActor.user(outsider),
            service_tenant_id=service,
            subscription_id=result.subscription_id,
            provider=env.provider,
        ).status
        == "active"
    )


def test_refresh_is_tenant_isolated(world: _World, env: _Env) -> None:
    service, other = world.tenant("service"), world.tenant("other")
    _, result = env.create(service)
    with pytest.raises(SubscriptionNotFoundError):
        reconcile_subscription_status(
            _SYSTEM,
            service_tenant_id=other,
            subscription_id=result.subscription_id,
            provider=env.provider,
        )
    user = world.user()
    world.grant(other, user, [("billing.subscription", "read")])
    with pytest.raises(BillingNotAuthorizedError):
        reconcile_subscription_status(
            BillingActor.user(user),
            service_tenant_id=service,
            subscription_id=result.subscription_id,
            provider=env.provider,
        )


def test_refresh_refuses_legacy_rows(world: _World, env: _Env) -> None:
    tenant = world.tenant("legacy")
    legacy = subscribe(tenant, world.plan({}), provider=env.provider)
    with pytest.raises(LegacyReconciliationError):
        reconcile_subscription_status(
            _SYSTEM, service_tenant_id=tenant, subscription_id=legacy.id, provider=env.provider
        )


def test_status_cannot_be_written_outside_the_lifecycle_even_by_the_app_role(
    world: _World, env: _Env
) -> None:
    """There is no public setter; the database itself still accepts the
    app role's own UPDATE on its own tenant (RLS scope, not lifecycle) --
    which is why no consumer-reachable code path performs one (static
    test in test_lifecycle_unit.py). This pins the database half: the
    verified-row invariant cannot be broken by stripping the payer."""
    service = world.tenant("service")
    _, result = env.create(service)
    with pytest.raises(IntegrityError), tenant_session_scope(service) as session:
        session.execute(
            text(
                "UPDATE core.billing_subscriptions SET payer_tenant_id = NULL, "
                "billing_account_id = NULL, merchant_account_id = NULL WHERE id = :id"
            ),
            {"id": str(result.subscription_id)},
        )


# --- One live subscription per (service tenant, merchant) --------------------


def test_second_live_subscription_at_the_same_merchant_is_rejected(
    world: _World, env: _Env
) -> None:
    service = world.tenant("service")
    env.create(service)
    calls = env.provider.create_calls
    with pytest.raises(LiveSubscriptionExistsError):
        env.create(service)
    assert env.provider.create_calls == calls  # rejected before the provider
    assert _live_count(service) == 1


def test_other_merchant_and_other_service_tenant_are_independent(world: _World, env: _Env) -> None:
    service, other_service = world.tenant("service"), world.tenant("other-service")
    env.create(service)
    env.create(service, merchant=env.new_merchant())
    env.create(other_service)
    assert _live_count(service) == 2 and _live_count(other_service) == 1


def test_a_canceled_subscription_frees_the_slot(world: _World, env: _Env) -> None:
    service = world.tenant("service")
    _, first = env.create(service)
    # Commercial rows are canceled through the commercial API (Phase 5.3 step 7).
    _cancel(env, service, first.subscription_id)
    _, second = env.create(service)
    assert second.status == "active" and _live_count(service) == 1


def test_the_database_index_not_the_precheck_enforces_the_invariant(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = world.tenant("service")
    env.create(service)
    monkeypatch.setattr(commercial, "_live_subscription_exists", lambda *_: False)
    with pytest.raises(LiveSubscriptionExistsError):
        env.create(service)
    assert _live_count(service) == 1


def test_concurrent_different_requests_yield_exactly_one_live_subscription(
    world: _World, env: _Env
) -> None:
    service = world.tenant("service")
    plan = env.plan({})
    env.account(service)

    def attempt(i: int) -> str:
        try:
            env.create(service, key=f"race-{i}", plan=plan)
            return "created"
        except LiveSubscriptionExistsError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(attempt, range(6)))
    assert outcomes.count("created") == 1
    assert outcomes.count("rejected") == 5
    assert _live_count(service) == 1


def test_raw_second_live_row_is_rejected_by_the_database(world: _World, env: _Env) -> None:
    service = world.tenant("service")
    _, result = env.create(service)
    with pytest.raises(IntegrityError) as excinfo, tenant_session_scope(service) as session:
        session.execute(
            text(
                "INSERT INTO core.billing_subscriptions (id, tenant_id, plan_id, status, "
                "provider_subscription_id, payer_tenant_id, billing_account_id, "
                "merchant_account_id, provider, verification) "
                "SELECT :id, tenant_id, plan_id, 'pending', 'other', payer_tenant_id, "
                "billing_account_id, merchant_account_id, provider, 'verified' "
                "FROM core.billing_subscriptions WHERE id = :src"
            ),
            {"id": str(uuid.uuid4()), "src": str(result.subscription_id)},
        )
    assert "uq_billing_subscriptions_one_live_per_merchant" in str(excinfo.value)


# --- Legacy-unverified rows and reconciliation -------------------------------


def test_legacy_rows_are_explicitly_unverified_and_keep_compatibility(
    world: _World, env: _Env
) -> None:
    tenant = world.tenant("legacy")
    legacy = subscribe(tenant, world.plan({"seats": 1}), provider=env.provider)
    row = _row(tenant, legacy.id)
    assert (row.status, row.verification) == ("active", "legacy_unverified")
    assert row.payer_tenant_id is None and row.merchant_account_id is None
    # Compatibility (documented): a legacy row keeps its pre-Phase-3 effect.
    assert get_entitlements(tenant) == {"seats": 1}
    # It is outside the one-live invariant until reconciled.
    env.create(tenant)
    assert _live_count(tenant) == 2


def test_reconciliation_requires_dual_authorization(world: _World, env: _Env) -> None:
    tenant, user = world.tenant("legacy"), world.user()
    legacy = subscribe(tenant, world.plan({}), provider=env.provider)
    account = env.account(tenant)

    def reconcile(caller: object):  # type: ignore[no-untyped-def]
        return reconcile_legacy_subscription(
            caller,
            service_tenant_id=tenant,
            subscription_id=legacy.id,
            payer_tenant_id=tenant,
            billing_account_id=account,
            provider=env.provider,
        )

    with pytest.raises(BillingActorRequiredError):
        reconcile(None)
    world.grant(tenant, user, [("billing.subscription", "create")])
    with pytest.raises(BillingNotAuthorizedError):
        reconcile(BillingActor.user(user))
    assert _row(tenant, legacy.id).verification == "legacy_unverified"
    world.grant(tenant, user, [("billing.account", "charge")])
    result = reconcile(BillingActor.user(user))
    assert result.status == "active"


def test_successful_reconciliation_records_authoritative_facts_and_is_audited(
    world: _World, env: _Env
) -> None:
    tenant = world.tenant("legacy")
    legacy = subscribe(tenant, world.plan({}), provider=env.provider)
    account = env.account(tenant)
    env.provider.set_state(legacy.provider_subscription_id, P.PAST_DUE)
    result = reconcile_legacy_subscription(
        _SYSTEM,
        service_tenant_id=tenant,
        subscription_id=legacy.id,
        payer_tenant_id=tenant,
        billing_account_id=account,
        provider=env.provider,
    )
    row = _row(tenant, legacy.id)
    assert (row.verification, row.status) == ("verified", "past_due")
    assert (row.payer_tenant_id, row.billing_account_id, row.merchant_account_id, row.provider) == (
        tenant,
        account,
        env.merchant.id,
        "fake",
    )
    assert result.subscription_id == legacy.id
    assert (
        get_subscription_by_provider_ref(
            provider="fake",
            provider_account_ref=env.merchant.provider_account_ref,
            provider_subscription_ref=legacy.provider_subscription_id,
        ).id
        == legacy.id
    )
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM core.audit_log WHERE resource_id = :r "
                        "AND action = 'billing.subscription_reconciled'"
                    ),
                    {"r": str(legacy.id)},
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize("failure", ["not_found", "unknown", "outage"])
def test_failed_reconciliation_leaves_the_row_unverified(
    world: _World, env: _Env, failure: str
) -> None:
    tenant = world.tenant("legacy")
    legacy = subscribe(tenant, world.plan({}), provider=env.provider)
    account = env.account(tenant)
    if failure == "not_found":
        env.provider.set_state(legacy.provider_subscription_id, P.NOT_FOUND)
        expected: type[Exception] = LegacyReconciliationError
    elif failure == "unknown":
        env.provider.set_state(legacy.provider_subscription_id, P.UNKNOWN)
        expected = LegacyReconciliationError
    else:
        env.provider.status_unavailable = True
        expected = BillingProviderError
    with pytest.raises(expected):
        reconcile_legacy_subscription(
            _SYSTEM,
            service_tenant_id=tenant,
            subscription_id=legacy.id,
            payer_tenant_id=tenant,
            billing_account_id=account,
            provider=env.provider,
        )
    row = _row(tenant, legacy.id)
    assert (row.verification, row.status, row.billing_account_id) == (
        "legacy_unverified",
        "active",
        None,
    )


def test_reconciliation_never_revives_a_canceled_legacy_row(world: _World, env: _Env) -> None:
    tenant = world.tenant("legacy")
    legacy = subscribe(tenant, world.plan({}), provider=env.provider)
    with tenant_session_scope(tenant) as session:
        session.execute(
            text("UPDATE core.billing_subscriptions SET status = 'canceled' WHERE id = :id"),
            {"id": str(legacy.id)},
        )
    with pytest.raises(LegacyReconciliationError):
        reconcile_legacy_subscription(
            _SYSTEM,
            service_tenant_id=tenant,
            subscription_id=legacy.id,
            payer_tenant_id=tenant,
            billing_account_id=env.account(tenant),
            provider=env.provider,
        )


def test_reconciliation_cannot_create_a_second_live_subscription(world: _World, env: _Env) -> None:
    tenant = world.tenant("legacy")
    legacy = subscribe(tenant, world.plan({}), provider=env.provider)
    env.create(tenant)
    with pytest.raises(LiveSubscriptionExistsError):
        reconcile_legacy_subscription(
            _SYSTEM,
            service_tenant_id=tenant,
            subscription_id=legacy.id,
            payer_tenant_id=tenant,
            billing_account_id=env.account(tenant),
            provider=env.provider,
        )
    assert _row(tenant, legacy.id).verification == "legacy_unverified"


def test_reconciliation_is_refused_for_verified_rows(world: _World, env: _Env) -> None:
    tenant = world.tenant("service")
    _, result = env.create(tenant)
    with pytest.raises(LegacyReconciliationError):
        reconcile_legacy_subscription(
            _SYSTEM,
            service_tenant_id=tenant,
            subscription_id=result.subscription_id,
            payer_tenant_id=tenant,
            billing_account_id=env.account(tenant),
            provider=env.provider,
        )


def test_cross_tenant_reconciliation_is_rejected(world: _World, env: _Env) -> None:
    tenant, other = world.tenant("legacy"), world.tenant("other")
    legacy = subscribe(tenant, world.plan({}), provider=env.provider)
    # The row is invisible under another service tenant's RLS scope ...
    with pytest.raises(SubscriptionNotFoundError):
        reconcile_legacy_subscription(
            _SYSTEM,
            service_tenant_id=other,
            subscription_id=legacy.id,
            payer_tenant_id=other,
            billing_account_id=env.account(other),
            provider=env.provider,
        )
    # ... and another payer's billing account cannot be claimed.
    with pytest.raises(BillingAccountNotFoundError):
        reconcile_legacy_subscription(
            _SYSTEM,
            service_tenant_id=tenant,
            subscription_id=legacy.id,
            payer_tenant_id=tenant,
            billing_account_id=env.account(other),
            provider=env.provider,
        )
    assert _row(tenant, legacy.id).verification == "legacy_unverified"


def test_reconciliation_must_agree_with_a_payer_the_row_already_records(
    world: _World, env: _Env
) -> None:
    """A Phase-2 commercial row (payer recorded, still legacy-unverified)
    can only be reconciled with that same payer."""
    tenant, other_payer = world.tenant("service"), world.tenant("payer")
    _, result = env.create(tenant)
    with tenant_session_scope(tenant) as session:
        session.execute(
            text(
                "UPDATE core.billing_subscriptions SET verification = 'legacy_unverified' "
                "WHERE id = :id"
            ),
            {"id": str(result.subscription_id)},
        )
    with pytest.raises(LegacyReconciliationError):
        reconcile_legacy_subscription(
            _SYSTEM,
            service_tenant_id=tenant,
            subscription_id=result.subscription_id,
            payer_tenant_id=other_payer,
            billing_account_id=env.account(other_payer),
            provider=env.provider,
        )


# --- Provider idempotency ------------------------------------------------------


def test_retry_with_the_same_key_reaches_the_provider_once_and_replays_current_state(
    world: _World, env: _Env
) -> None:
    env.provider.initial_state = P.PENDING
    service = world.tenant("service")
    plan = env.plan({})
    first_replay, first = env.create(service, key="same", plan=plan)
    env.provider.set_state(first.provider_subscription_id, P.ACTIVE)
    reconcile_subscription_status(
        _SYSTEM,
        service_tenant_id=service,
        subscription_id=first.subscription_id,
        provider=env.provider,
    )
    second_replay, second = env.create(service, key="same", plan=plan)
    assert (first_replay, second_replay) == (False, True)
    assert second.subscription_id == first.subscription_id
    assert second.status == "active"  # current state, not the stale stored one
    assert env.provider.create_calls == 1


def test_concurrent_identical_requests_reach_the_provider_once(world: _World, env: _Env) -> None:
    service = world.tenant("service")
    plan = env.plan({})
    env.account(service)

    def attempt(_: int) -> str:
        try:
            is_replay, _r = env.create(service, key="concurrent", plan=plan)
            return "replayed" if is_replay else "executed"
        except IdempotencyInProgressError:
            return "in_progress"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))
    assert outcomes.count("executed") == 1
    assert env.provider.create_calls == 1
    assert _live_count(service) == 1


def test_abandoned_attempt_is_completed_without_a_second_provider_subscription(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash after the provider call and the local insert, before the
    idempotency record is finalized (simulated by the finalize step
    failing), leaves the reservation pending. After the pending TTL a
    retry -- as from a restarted process, with nothing in memory --
    reuses the same provider idempotency key and the same local id: the
    provider returns the same subscription and no second row appears."""
    monkeypatch.setenv("IDEMPOTENCY_PENDING_TTL_SECONDS", "1")
    get_idempotency_config.cache_clear()
    service = world.tenant("service")
    plan = env.plan({})
    env.account(service)

    real_finalize = commercial.finalize_idempotent_operation

    def crash_on_success(*args, **kwargs):  # type: ignore[no-untyped-def]
        if kwargs.get("status") is not None and kwargs["status"].value == "succeeded":
            raise RuntimeError("simulated crash before finalize")
        return real_finalize(*args, **kwargs)

    monkeypatch.setattr(commercial, "finalize_idempotent_operation", crash_on_success)
    with pytest.raises(RuntimeError):
        env.create(service, key="crashy", plan=plan)
    monkeypatch.setattr(commercial, "finalize_idempotent_operation", real_finalize)

    time.sleep(1.5)
    # Even if the provider has since forgotten the idempotency key (its own
    # retention window passed), recovery uses the durably recorded row.
    env.provider._by_idempotency_key.clear()
    is_replay, result = env.create(service, key="crashy", plan=plan)
    assert is_replay is False
    assert env.provider.create_calls == 1  # the provider is not asked again
    assert len(env.provider._subscriptions) == 1
    assert _live_count(service) == 1
    assert result.status == "active"
    get_idempotency_config.cache_clear()


def test_reusing_a_key_for_a_different_request_fails(world: _World, env: _Env) -> None:
    service = world.tenant("service")
    env.create(service, key="reused")
    with pytest.raises(IdempotencyKeyReusedError):
        env.create(service, key="reused", plan=env.plan({"other": True}))


def test_provider_creation_failure_leaves_no_row_and_allows_retry(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = world.tenant("service")
    plan = env.plan({})
    env.account(service)
    real_create = env.provider.create_subscription

    def failing(**kwargs):  # type: ignore[no-untyped-def]
        raise BillingProviderError("create_subscription", "declined")

    monkeypatch.setattr(env.provider, "create_subscription", failing)
    with pytest.raises(BillingProviderError):
        env.create(service, key="retry-after-failure", plan=plan)
    assert _live_count(service) == 0
    monkeypatch.setattr(env.provider, "create_subscription", real_create)
    _, result = env.create(service, key="retry-after-failure", plan=plan)
    assert result.status == "active"


def test_local_failure_after_provider_success_is_recovered_without_a_duplicate(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """provider creates -> local write fails -> client retries: the retry
    reuses the same provider idempotency key (the reservation is FAILED and
    reset, same record id), the provider returns the same subscription, and
    exactly one local row results."""
    service = world.tenant("service")
    plan = env.plan({})
    env.account(service)
    real_insert = commercial._insert_pending

    def failing_insert(**kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("simulated database failure after provider success")

    monkeypatch.setattr(commercial, "_insert_pending", failing_insert)
    with pytest.raises(RuntimeError):
        env.create(service, key="local-failure", plan=plan)
    assert _live_count(service) == 0
    assert len(env.provider._subscriptions) == 1

    monkeypatch.setattr(commercial, "_insert_pending", real_insert)
    env.provider._by_idempotency_key.clear()  # provider key window expired
    _, result = env.create(service, key="local-failure", plan=plan)
    assert result.status == "active"
    assert env.provider.create_calls == 1  # recovered from the provider reference
    assert len(env.provider._subscriptions) == 1  # no second provider subscription
    assert _live_count(service) == 1


# --- Cancellation safety ---------------------------------------------------------


def _cancel(env: _Env, service: uuid.UUID, subscription_id: uuid.UUID, caller: object = None):
    return cancel_commercial_subscription(
        caller or _SYSTEM,
        service_tenant_id=service,
        subscription_id=subscription_id,
        provider=env.provider,
    )


def _cancel_raises(env: _Env, monkeypatch: pytest.MonkeyPatch) -> None:
    def raising(**kwargs):  # type: ignore[no-untyped-def]
        raise BillingProviderError("cancel_subscription", "provider rejected the cancel")

    monkeypatch.setattr(env.provider, "cancel_subscription", raising)


def test_normal_cancellation_cancels_at_provider_and_locally(world: _World, env: _Env) -> None:
    service = world.tenant("service")
    _, result = env.create(service)
    canceled = _cancel(env, service, result.subscription_id)
    assert canceled.status == "canceled"
    assert (
        env.provider.get_subscription_status(
            provider_subscription_id=result.provider_subscription_id
        )
        is P.CANCELED
    )
    assert get_entitlements(service) == {}
    # Idempotent: a second cancel is a local no-op (no provider call needed).
    assert _cancel(env, service, result.subscription_id).status == "canceled"


def test_provider_already_canceled_is_tolerated_and_corrects_local_state(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = world.tenant("service")
    _, result = env.create(service)
    env.provider.set_state(result.provider_subscription_id, P.CANCELED)  # canceled out of band
    _cancel_raises(env, monkeypatch)  # the provider now refuses a second cancel
    assert _cancel(env, service, result.subscription_id).status == "canceled"


@pytest.mark.parametrize("provider_answer", ["unavailable", "not_found", "active"])
def test_uncertain_provider_never_yields_a_local_cancellation(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch, provider_answer: str
) -> None:
    service = world.tenant("service")
    _, result = env.create(service)
    _cancel_raises(env, monkeypatch)
    if provider_answer == "unavailable":
        env.provider.status_unavailable = True
    elif provider_answer == "not_found":
        env.provider.set_state(result.provider_subscription_id, P.NOT_FOUND)
    with pytest.raises(BillingProviderError):
        _cancel(env, service, result.subscription_id)
    assert _row(service, result.subscription_id).status == "active"


def test_provider_cancel_succeeded_but_local_write_failed_converges(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = world.tenant("service")
    _, result = env.create(service)

    def failing_transition(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("simulated database failure after provider cancel")

    real_transition = commercial.set_subscription_status
    monkeypatch.setattr(commercial, "set_subscription_status", failing_transition)
    with pytest.raises(RuntimeError):
        _cancel(env, service, result.subscription_id)
    assert _row(service, result.subscription_id).status == "active"  # local still says active
    monkeypatch.setattr(commercial, "set_subscription_status", real_transition)

    # Reconciliation corrects it from the provider's authoritative state ...
    reconciled = reconcile_subscription_status(
        _SYSTEM,
        service_tenant_id=service,
        subscription_id=result.subscription_id,
        provider=env.provider,
    )
    assert (reconciled.status, reconciled.changed) == ("canceled", True)


def test_retrying_the_cancel_after_a_failed_local_write_also_converges(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = world.tenant("service")
    _, result = env.create(service)
    env.provider.set_state(result.provider_subscription_id, P.CANCELED)  # provider already did it
    _cancel_raises(env, monkeypatch)
    assert _cancel(env, service, result.subscription_id).status == "canceled"


def test_legacy_cancel_tolerates_an_already_canceled_provider(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = world.tenant("legacy")
    legacy = subscribe(tenant, world.plan({}), provider=env.provider)
    env.provider.set_state(legacy.provider_subscription_id, P.CANCELED)
    _cancel_raises(env, monkeypatch)
    assert cancel_subscription(tenant, legacy.id, provider=env.provider).status == "canceled"


def test_commercial_cancel_requires_authorization_and_a_verified_row(
    world: _World, env: _Env
) -> None:
    service, user = world.tenant("service"), world.user()
    _, result = env.create(service)
    with pytest.raises(BillingActorRequiredError):
        cancel_commercial_subscription(
            None, service_tenant_id=service, subscription_id=result.subscription_id
        )
    with pytest.raises(BillingNotAuthorizedError):
        _cancel(env, service, result.subscription_id, BillingActor.user(user))
    world.grant(service, user, [("billing.subscription", "cancel")])
    assert _cancel(env, service, result.subscription_id, BillingActor.user(user)).status == (
        "canceled"
    )
    legacy_tenant = world.tenant("legacy")
    legacy = subscribe(legacy_tenant, world.plan({}), provider=env.provider)
    with pytest.raises(LegacyReconciliationError):
        _cancel(env, legacy_tenant, legacy.id)
    other = world.tenant("other")
    with pytest.raises(SubscriptionNotFoundError):
        _cancel(env, other, result.subscription_id)


# --- Reconciliation safety -----------------------------------------------------------


def test_repeated_reconciliation_is_idempotent(world: _World, env: _Env) -> None:
    env.provider.initial_state = P.PENDING
    service = world.tenant("service")
    _, result = env.create(service)
    env.provider.set_state(result.provider_subscription_id, P.ACTIVE)

    def reconcile():  # type: ignore[no-untyped-def]
        return reconcile_subscription_status(
            _SYSTEM,
            service_tenant_id=service,
            subscription_id=result.subscription_id,
            provider=env.provider,
        )

    first, second = reconcile(), reconcile()
    assert (first.status, first.changed) == ("active", True)
    assert (second.status, second.changed) == ("active", False)


def test_reconciliation_fails_closed_on_a_missing_provider_reference(
    world: _World, env: _Env
) -> None:
    service = world.tenant("service")
    _, result = env.create(service)
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM core.billing_provider_refs WHERE local_object_id = :id"),
                {"id": str(result.subscription_id)},
            )
    finally:
        engine.dispose()
    env.provider.set_state(result.provider_subscription_id, P.CANCELED)
    with pytest.raises(ProviderReferenceMismatchError):
        reconcile_subscription_status(
            _SYSTEM,
            service_tenant_id=service,
            subscription_id=result.subscription_id,
            provider=env.provider,
        )
    with pytest.raises(ProviderReferenceMismatchError):
        _cancel(env, service, result.subscription_id)
    assert _row(service, result.subscription_id).status == "active"


def test_reconciliation_fails_closed_when_the_row_and_reference_disagree(
    world: _World, env: _Env
) -> None:
    service = world.tenant("service")
    _, result = env.create(service)
    with tenant_session_scope(service) as session:
        session.execute(
            text(
                "UPDATE core.billing_subscriptions "
                "SET provider_subscription_id = 'fake_sub_forged' "
                "WHERE id = :id"
            ),
            {"id": str(result.subscription_id)},
        )
    with pytest.raises(ProviderReferenceMismatchError):
        reconcile_subscription_status(
            _SYSTEM,
            service_tenant_id=service,
            subscription_id=result.subscription_id,
            provider=env.provider,
        )


def test_the_retry_reuses_the_same_reservation_key_and_local_id(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The only window with nothing durable: the provider created the
    subscription but the reference was never registered. The retry reuses
    the same durable reservation, so it sends the exact same provider
    idempotency key and targets the same local id; the provider's own key
    deduplication returns the first subscription."""
    service = world.tenant("service")
    plan = env.plan({})
    env.account(service)
    seen_keys: list[str | None] = []
    real_create = env.provider.create_subscription

    def recording_create(**kwargs):  # type: ignore[no-untyped-def]
        seen_keys.append(kwargs.get("idempotency_key"))
        return real_create(**kwargs)

    real_register = commercial.register_provider_ref

    def failing_register(**kwargs):  # type: ignore[no-untyped-def]
        # Only the subscription's own reference: the (payer, merchant)
        # customer is set up before the provider subscription exists.
        if kwargs["object_type"] is ProviderObjectType.SUBSCRIPTION:
            raise RuntimeError("simulated crash before the provider reference is registered")
        return real_register(**kwargs)

    monkeypatch.setattr(env.provider, "create_subscription", recording_create)
    monkeypatch.setattr(commercial, "register_provider_ref", failing_register)
    with pytest.raises(RuntimeError):
        env.create(service, key="window", plan=plan)
    monkeypatch.setattr(commercial, "register_provider_ref", real_register)
    _, result = env.create(service, key="window", plan=plan)

    assert len(seen_keys) == 2 and seen_keys[0] == seen_keys[1] is not None
    assert len(env.provider._subscriptions) == 1
    assert _live_count(service) == 1
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            reservations = conn.execute(
                text(
                    "SELECT id FROM core.idempotency_records WHERE tenant_id = :t "
                    "AND operation = 'billing.subscription.create' AND idempotency_key = 'window'"
                ),
                {"t": str(service)},
            ).all()
    finally:
        engine.dispose()
    assert len(reservations) == 1
    assert seen_keys[0] == f"saas-os:billing.subscription.create:{reservations[0][0]}"
    assert result.subscription_id == uuid.uuid5(
        commercial._SUBSCRIPTION_ID_NAMESPACE, str(reservations[0][0])
    )


def test_an_adapter_not_declaring_idempotency_support_is_refused(world: _World, env: _Env) -> None:
    class _UndeclaredProvider(FakeBillingProvider):
        honors_idempotency_keys = False  # type: ignore[assignment]

    service = world.tenant("service")
    with pytest.raises(BillingProviderContractError):
        create_subscription(
            _SYSTEM,
            service_tenant_id=service,
            payer_tenant_id=service,
            billing_account_id=env.account(service),
            plan_id=env.plan({}),
            idempotency_key="undeclared",
            provider=_UndeclaredProvider(),
        )
    assert _live_count(service) == 0


def test_a_reconciliation_during_a_legacy_upgrade_refuses_the_upgrade(
    world: _World, env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Phase 5.3 step 7: a legacy row verified by `reconcile_legacy_subscription()`
    while a legacy upgrade waits on the provider is a commercial row by the
    time the upgrade writes; the locked re-check refuses it."""
    from core.billing.errors import LegacyBillingPathError
    from core.billing.service import upgrade_subscription

    tenant = world.tenant("legacy")
    legacy = subscribe(tenant, world.plan({"api_calls": 1}), provider=env.provider)
    account = env.account(tenant)
    target_key = world.plan({"api_calls": 999999})
    real = env.provider.change_plan

    def change_then_reconcile(**kwargs):  # type: ignore[no-untyped-def]
        real(**kwargs)
        reconcile_legacy_subscription(
            _SYSTEM,
            service_tenant_id=tenant,
            subscription_id=legacy.id,
            payer_tenant_id=tenant,
            billing_account_id=account,
            provider=env.provider,
        )

    monkeypatch.setattr(env.provider, "change_plan", change_then_reconcile)
    with pytest.raises(LegacyBillingPathError):
        upgrade_subscription(tenant, legacy.id, target_key, provider=env.provider)
    row = _row(tenant, legacy.id)
    assert row.verification == "verified" and row.plan_id == legacy.plan_id
