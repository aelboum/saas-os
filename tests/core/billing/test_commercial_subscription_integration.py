"""Phase 5.3 step 3 -- the commercial subscription path on Catalog v2,
against a real PostgreSQL instance (docs/ADR/0029-..., "Amendment
(2026-10-02)").

The B2B2C shape used throughout -- generic tenants, nothing product-named:

    Agency A (merchant mA)              Agency B (merchant mB)
      +-- Client B (pays itself, at mA)
      +-- Client C (Agency A pays)

Pins: the explicit parties (service tenant, payer, merchant), payer
authority and billing-account ownership, the single Catalog v2 predicate
on the create path, the final transaction re-running every check after the
provider call (withdrawal, offer revocation, merchant and billing-account
deactivation, revoked authority), provider context and per-(payer,
merchant) customer reuse, and audit evidence.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from lifecycle_callers import platform_operator
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.billing import commercial
from saas_os.core.billing.catalog import (
    PlanVisibility,
    create_owned_plan,
    create_plan_offer,
    revoke_plan_offer,
    withdraw_plan,
)
from saas_os.core.billing.commercial import create_subscription
from saas_os.core.billing.errors import (
    BillingAccountNotFoundError,
    BillingNotAuthorizedError,
    BillingProviderError,
    CommercialPartyNotActiveError,
    PlanNotEligibleError,
)
from saas_os.core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_billing_account,
    get_or_create_billing_account,
    set_merchant_account_status,
)
from saas_os.core.billing.provider import FakeBillingProvider
from saas_os.core.billing.provider_refs import (
    LocalObjectType,
    ProviderObjectType,
    resolve_provider_ref,
)
from saas_os.core.billing.service import create_plan, get_entitlements, get_subscription
from saas_os.core.identity import get_membership
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.rbac import RoleScope
from saas_os.core.rbac.service import (
    approve_support_access,
    assign_first_role_for_new_tenant,
    create_deny,
    create_role,
    create_support_access_request,
    grant_permission,
    register_permission,
)
from saas_os.core.tenancy import TenantStatus, create_tenant, transition_tenant_status
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_BILLING_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)
_CHARGE = ("billing.account", "charge")
_CREATE = ("billing.subscription", "create")


@pytest.fixture(autouse=True)
def _require_reachable_database_with_catalog_v2() -> None:
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
            conn.execute(text("SELECT 1 FROM core.billing_plan_offers LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"Catalog v2 tables missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe_engine.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _admin(sql: str, **params: object) -> list:  # type: ignore[type-arg]
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(sql), params)
            return list(result.all()) if result.returns_rows else []
    finally:
        engine.dispose()


class _World:
    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        self.legacy_keys: list[str] = []

    def tenant(self, label: str, *, parent_id: uuid.UUID | None = None) -> uuid.UUID:
        tenant = create_tenant(_unique(label), parent_id=parent_id, caller=platform_operator())
        transition_tenant_status(tenant.id, TenantStatus.ACTIVE, caller=platform_operator())
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def user(self) -> uuid.UUID:
        user = create_user()
        self.user_ids.append(user.id)
        return user.id

    def grant(
        self,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        *permissions: tuple[str, str],
        scope: RoleScope = RoleScope.SELF,
    ) -> None:
        membership = get_membership(tenant_id, user_id)
        if membership is None:
            membership = add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
        role = create_role(tenant_id, _unique("role"), caller=_PROVISIONING)
        for permission in permissions:
            grant_permission(
                tenant_id, role.id, register_permission(*permission).id, caller=_PROVISIONING
            )
        assign_first_role_for_new_tenant(
            tenant_id, membership.id, role.id, scope=scope, caller=_PROVISIONING
        )

    def merchant(self, owner: uuid.UUID) -> uuid.UUID:
        return create_merchant_account(
            _BILLING_SYSTEM,
            owner,
            provider="fake",
            provider_account_ref=_unique("acct"),
            status=MerchantAccountStatus.ACTIVE,
        ).id

    def plan(
        self,
        owner: uuid.UUID,
        merchant: uuid.UUID,
        *,
        visibility: PlanVisibility = PlanVisibility.PUBLIC,
        entitlements: dict[str, object] | None = None,
    ) -> uuid.UUID:
        return create_owned_plan(
            _BILLING_SYSTEM,
            owner,
            merchant_account_id=merchant,
            key=_unique("plan"),
            name="Commercial plan",
            entitlements=entitlements or {"seats": 5},
            visibility=visibility,
        ).id

    def account(
        self, payer: uuid.UUID, merchant_owner: uuid.UUID, merchant: uuid.UUID
    ) -> uuid.UUID:
        account, _ = get_or_create_billing_account(
            _BILLING_SYSTEM, payer, merchant_tenant_id=merchant_owner, merchant_account_id=merchant
        )
        return account.id

    def support_engineer(self, tenant_id: uuid.UUID) -> uuid.UUID:
        approver, engineer = self.user(), self.user()
        self.grant(tenant_id, approver, ("support_access_request", "approve"))
        request = create_support_access_request(
            caller=UserCaller(engineer),
            tenant_id=tenant_id,
            reason="step 3 boundary",
            requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        approve_support_access(
            caller=UserCaller(approver), tenant_id=tenant_id, request_id=request.id
        )
        return engineer

    def cleanup(self) -> None:
        tenants = [str(t) for t in self.tenant_ids]
        users = [str(u) for u in self.user_ids]
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
                    "DELETE FROM core.billing_provider_refs WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plan_offers WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plans WHERE owner_tenant_id = ANY(:t) "
                    "OR key = ANY(:k)",
                    "DELETE FROM core.billing_accounts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_merchant_accounts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.support_access_requests WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.deny_grants WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) "
                    "OR ancestor_id = ANY(:t)",
                    "DELETE FROM core.platform_audit_log WHERE target_tenant_id = ANY(:t)",
                    "DELETE FROM core.tenants WHERE id = ANY(:t)",
                    "DELETE FROM core.users WHERE id = ANY(:u)",
                ):
                    session.execute(
                        text(statement), {"t": tenants, "u": users, "k": self.legacy_keys}
                    )
        finally:
            engine.dispose()


@pytest.fixture
def world() -> Iterator[_World]:
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


class _Market:
    def __init__(self, world: _World) -> None:
        self.world = world
        self.agency_a = world.tenant("agency-a")
        self.agency_b = world.tenant("agency-b")
        self.client_b = world.tenant("client-b", parent_id=self.agency_a)
        self.client_c = world.tenant("client-c", parent_id=self.agency_a)
        self.m_a = world.merchant(self.agency_a)
        self.m_b = world.merchant(self.agency_b)
        self.plan_x = world.plan(self.agency_a, self.m_a, visibility=PlanVisibility.DESCENDANTS)
        # Billing accounts at Agency A's merchant: the agency's own, and
        # Client B's.
        self.acct_agency = world.account(self.agency_a, self.agency_a, self.m_a)
        self.acct_client_b = world.account(self.client_b, self.agency_a, self.m_a)
        self.provider = FakeBillingProvider()

    def create(
        self,
        caller: object,
        *,
        service: uuid.UUID,
        payer: uuid.UUID,
        account: uuid.UUID,
        plan: uuid.UUID | None = None,
        provider: FakeBillingProvider | None = None,
    ):  # type: ignore[no-untyped-def]
        return create_subscription(
            caller,
            service_tenant_id=service,
            payer_tenant_id=payer,
            billing_account_id=account,
            plan_id=plan or self.plan_x,
            idempotency_key=_unique("idem"),
            provider=provider or self.provider,
        )


@pytest.fixture
def market(world: _World) -> _Market:
    return _Market(world)


def _subscriptions(tenant_id: uuid.UUID) -> int:
    with tenant_session_scope(tenant_id) as session:
        return session.execute(text("SELECT count(*) FROM core.billing_subscriptions")).scalar_one()


def _audit(tenant_id: uuid.UUID, action: str) -> list:  # type: ignore[type-arg]
    return _admin(
        "SELECT actor_type, actor_user_id, resource_id, outcome, metadata AS meta "
        "FROM core.audit_log WHERE tenant_id = :t AND action = :a",
        t=str(tenant_id),
        a=action,
    )


# --- Happy paths: the three B2B2C relationships ------------------------------------


def test_client_pays_itself_for_the_agencys_plan(market: _Market) -> None:
    _, result = market.create(
        _BILLING_SYSTEM,
        service=market.client_b,
        payer=market.client_b,
        account=market.acct_client_b,
    )
    row = get_subscription(market.client_b, result.subscription_id)
    assert (row.tenant_id, row.payer_tenant_id, row.billing_account_id) == (
        market.client_b,
        market.client_b,
        market.acct_client_b,
    )
    assert (row.merchant_account_id, row.plan_id, row.status) == (
        market.m_a,
        market.plan_x,
        "active",
    )
    assert get_entitlements(market.client_b) == {"seats": 5}
    assert get_entitlements(market.agency_a) == {}  # the merchant gains nothing


def test_agency_pays_for_its_client(world: _World, market: _Market) -> None:
    admin = world.user()
    world.grant(market.agency_a, admin, _CHARGE, _CREATE, scope=RoleScope.SUBTREE)
    _, result = market.create(
        UserCaller(admin),
        service=market.client_c,
        payer=market.agency_a,
        account=market.acct_agency,
    )
    row = get_subscription(market.client_c, result.subscription_id)
    assert (row.tenant_id, row.payer_tenant_id, row.merchant_account_id) == (
        market.client_c,
        market.agency_a,
        market.m_a,
    )
    # Entitlements follow the service tenant; the paying agency gets nothing.
    assert get_entitlements(market.client_c) == {"seats": 5}
    assert get_entitlements(market.agency_a) == {}
    # The payer cannot read the row: it is the service tenant's.
    assert _subscriptions(market.agency_a) == 0


def test_a_tenant_pays_itself_at_another_merchant(world: _World, market: _Market) -> None:
    public_b = world.plan(market.agency_b, market.m_b, entitlements={"reports": True})
    account = world.account(market.agency_a, market.agency_b, market.m_b)
    _, result = market.create(
        _BILLING_SYSTEM,
        service=market.agency_a,
        payer=market.agency_a,
        account=account,
        plan=public_b,
    )
    row = get_subscription(market.agency_a, result.subscription_id)
    assert (row.payer_tenant_id, row.merchant_account_id) == (market.agency_a, market.m_b)


# --- Authorization and payer ownership ----------------------------------------------


def test_creating_needs_create_on_the_service_and_charge_on_the_payer(
    world: _World, market: _Market
) -> None:
    only_charge, only_create = world.user(), world.user()
    world.grant(market.client_b, only_charge, _CHARGE)
    world.grant(market.client_b, only_create, _CREATE)
    for caller in (UserCaller(only_charge), UserCaller(only_create)):
        with pytest.raises(BillingNotAuthorizedError):
            market.create(
                caller, service=market.client_b, payer=market.client_b, account=market.acct_client_b
            )
    assert _subscriptions(market.client_b) == 0


def test_a_caller_cannot_name_a_payer_it_has_no_charge_authority_over(
    world: _World, market: _Market
) -> None:
    """Client C's own admin may subscribe Client C, but cannot make Agency A
    pay by naming the agency's billing account."""
    client_admin = world.user()
    world.grant(market.client_c, client_admin, _CHARGE, _CREATE)
    with pytest.raises(BillingNotAuthorizedError):
        market.create(
            UserCaller(client_admin),
            service=market.client_c,
            payer=market.agency_a,
            account=market.acct_agency,
        )
    assert _subscriptions(market.client_c) == 0
    assert market.provider.contexts == {}  # refused before the provider


def test_the_billing_account_must_belong_to_the_named_payer(market: _Market) -> None:
    for payer, account in (
        (market.client_b, market.acct_agency),  # B naming A's account
        (market.agency_a, market.acct_client_b),  # A naming B's account
    ):
        with pytest.raises(BillingAccountNotFoundError):
            market.create(_BILLING_SYSTEM, service=market.client_b, payer=payer, account=account)
    assert _subscriptions(market.client_b) == 0


def test_support_access_cannot_create_a_subscription(world: _World, market: _Market) -> None:
    engineer = world.support_engineer(market.client_b)
    with pytest.raises(BillingNotAuthorizedError):
        market.create(
            UserCaller(engineer),
            service=market.client_b,
            payer=market.client_b,
            account=market.acct_client_b,
        )


@pytest.mark.parametrize("purpose", [SystemAuthority.PROVISIONING, SystemAuthority.TENANT_PURGE])
def test_only_the_billing_system_purpose_may_create(
    market: _Market, purpose: SystemAuthority
) -> None:
    with pytest.raises(BillingNotAuthorizedError):
        market.create(
            SystemCaller(purpose),
            service=market.client_b,
            payer=market.client_b,
            account=market.acct_client_b,
        )


# --- Catalog v2 eligibility on the create path --------------------------------------


def _refused(market: _Market, **kwargs: object) -> str:  # type: ignore[no-untyped-def]
    arguments = {
        "service": market.client_b,
        "payer": market.client_b,
        "account": market.acct_client_b,
    }
    arguments.update(kwargs)  # type: ignore[arg-type]
    with pytest.raises(PlanNotEligibleError) as excinfo:
        market.create(_BILLING_SYSTEM, **arguments)  # type: ignore[arg-type]
    return excinfo.value.reason


def test_descendants_plans_are_refused_outside_the_owners_subtree(
    world: _World, market: _Market
) -> None:
    outsider = world.tenant("outsider")
    account = world.account(outsider, market.agency_a, market.m_a)
    assert _refused(market, service=outsider, payer=outsider, account=account) == "not_a_descendant"


def test_private_plans_need_catalog_read_on_the_owner(world: _World, market: _Market) -> None:
    private = world.plan(market.agency_a, market.m_a, visibility=PlanVisibility.PRIVATE)
    buyer = world.user()
    world.grant(market.client_b, buyer, _CHARGE, _CREATE)
    with pytest.raises(PlanNotEligibleError):
        market.create(
            UserCaller(buyer),
            service=market.client_b,
            payer=market.client_b,
            account=market.acct_client_b,
            plan=private,
        )
    world.grant(market.agency_a, buyer, ("billing.catalog", "read"))
    market.create(
        UserCaller(buyer),
        service=market.client_b,
        payer=market.client_b,
        account=market.acct_client_b,
        plan=private,
    )


def test_unlisted_plans_need_an_active_offer(world: _World, market: _Market) -> None:
    unlisted = world.plan(market.agency_a, market.m_a, visibility=PlanVisibility.UNLISTED)
    assert _refused(market, plan=unlisted) == "no_offer"  # knowing the id is not enough
    offer = create_plan_offer(
        _BILLING_SYSTEM, market.agency_a, unlisted, service_tenant_id=market.client_c
    )
    assert _refused(market, plan=unlisted) == "no_offer"  # offered to C, not B
    revoke_plan_offer(_BILLING_SYSTEM, market.agency_a, offer.id)
    create_plan_offer(_BILLING_SYSTEM, market.agency_a, unlisted, service_tenant_id=market.client_b)
    market.create(
        _BILLING_SYSTEM,
        service=market.client_b,
        payer=market.client_b,
        account=market.acct_client_b,
        plan=unlisted,
    )


def test_withdrawn_plans_and_inactive_merchants_are_refused(world: _World, market: _Market) -> None:
    withdrawn = world.plan(market.agency_a, market.m_a)
    withdraw_plan(_BILLING_SYSTEM, market.agency_a, withdrawn)
    assert _refused(market, plan=withdrawn) == "withdrawn"
    set_merchant_account_status(
        _BILLING_SYSTEM, market.agency_a, market.m_a, MerchantAccountStatus.RESTRICTED
    )
    assert _refused(market) == "merchant_inactive"


def test_a_plan_from_another_merchant_is_refused(world: _World, market: _Market) -> None:
    """Agency A's client cannot buy Agency B's plan through an account at
    Agency A's merchant, nor use Agency B's merchant for Agency A's plan."""
    public_b = world.plan(market.agency_b, market.m_b)
    assert _refused(market, plan=public_b) == "merchant_mismatch"
    account_at_b = world.account(market.client_b, market.agency_b, market.m_b)
    assert _refused(market, account=account_at_b) == "merchant_mismatch"


def test_unknown_and_unadopted_plans_look_the_same(world: _World, market: _Market) -> None:
    legacy_key = _unique("legacy")
    world.legacy_keys.append(legacy_key)
    legacy = create_plan(legacy_key, "Legacy")
    assert _refused(market, plan=legacy.id) == "not_adopted"
    with pytest.raises(PlanNotEligibleError) as unknown:
        market.create(
            _BILLING_SYSTEM,
            service=market.client_b,
            payer=market.client_b,
            account=market.acct_client_b,
            plan=uuid.uuid4(),
        )
    with pytest.raises(PlanNotEligibleError) as unadopted:
        market.create(
            _BILLING_SYSTEM,
            service=market.client_b,
            payer=market.client_b,
            account=market.acct_client_b,
            plan=legacy.id,
        )
    assert str(unknown.value).split(" is ")[1] == str(unadopted.value).split(" is ")[1]
    assert _subscriptions(market.client_b) == 0


# --- Provider context and customer reuse -------------------------------------------


def test_the_provider_receives_the_merchant_and_payer_context(
    world: _World, market: _Market
) -> None:
    _, result = market.create(
        _BILLING_SYSTEM, service=market.client_c, payer=market.agency_a, account=market.acct_agency
    )
    context = market.provider.contexts[result.provider_subscription_id]
    assert context is not None
    merchant_ref = _admin(
        "SELECT provider_account_ref FROM core.billing_merchant_accounts WHERE id = :m",
        m=str(market.m_a),
    )[0][0]
    assert (
        context.merchant_account_id,
        context.merchant_provider_account_ref,
        context.payer_tenant_id,
        context.payer_billing_account_id,
    ) == (market.m_a, merchant_ref, market.agency_a, market.acct_agency)
    stored = get_billing_account(market.agency_a, market.acct_agency).provider_customer_ref
    assert stored is not None and context.provider_customer_ref == stored
    resolution = resolve_provider_ref(
        provider="fake",
        provider_account_ref=merchant_ref,
        object_type=ProviderObjectType.CUSTOMER,
        provider_object_ref=stored,
    )
    assert (resolution.tenant_id, resolution.local_object_type, resolution.local_object_id) == (
        market.agency_a,
        LocalObjectType.BILLING_ACCOUNT,
        market.acct_agency,
    )


def test_a_customer_is_reused_per_payer_and_merchant_only(world: _World, market: _Market) -> None:
    other = world.plan(market.agency_a, market.m_a)
    _, first = market.create(
        _BILLING_SYSTEM, service=market.client_c, payer=market.agency_a, account=market.acct_agency
    )
    _, second = market.create(
        _BILLING_SYSTEM,
        service=market.client_b,
        payer=market.agency_a,
        account=market.acct_agency,
        plan=other,
    )
    first_ctx = market.provider.contexts[first.provider_subscription_id]
    second_ctx = market.provider.contexts[second.provider_subscription_id]
    assert first_ctx is not None and second_ctx is not None
    assert first_ctx.provider_customer_ref == second_ctx.provider_customer_ref
    assert len(market.provider.customers) == 1
    # The same payer at another merchant gets a different customer.
    public_b = world.plan(market.agency_b, market.m_b)
    account_at_b = world.account(market.agency_a, market.agency_b, market.m_b)
    _, third = market.create(
        _BILLING_SYSTEM,
        service=market.agency_a,
        payer=market.agency_a,
        account=account_at_b,
        plan=public_b,
    )
    third_ctx = market.provider.contexts[third.provider_subscription_id]
    assert (
        third_ctx is not None and third_ctx.provider_customer_ref != first_ctx.provider_customer_ref
    )


def test_a_provider_failure_creates_nothing_locally(
    market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(**_: object) -> str:
        raise BillingProviderError("create_subscription", "declined")

    monkeypatch.setattr(market.provider, "create_subscription", failing)
    with pytest.raises(BillingProviderError):
        market.create(
            _BILLING_SYSTEM,
            service=market.client_b,
            payer=market.client_b,
            account=market.acct_client_b,
        )
    assert _subscriptions(market.client_b) == 0
    assert _audit(market.client_b, "billing.subscription_created") == []


# --- The final transaction re-checks everything after the provider call -----------


def _during_provider_call(market: _Market, monkeypatch: pytest.MonkeyPatch, change) -> None:  # type: ignore[no-untyped-def]
    real = market.provider.create_subscription

    def create_then_change(**kwargs):  # type: ignore[no-untyped-def]
        provider_subscription_id = real(**kwargs)
        change()
        return provider_subscription_id

    monkeypatch.setattr(market.provider, "create_subscription", create_then_change)


def _assert_refused_after_provider(market: _Market, service: uuid.UUID, refusal: type) -> None:
    """No local row, no success audit, a failure audit naming the provider
    object, and the provider reference still resolving to the local id that
    was never written -- reconcilable, not lost."""
    assert _subscriptions(service) == 0
    assert _audit(service, "billing.subscription_created") == []
    [refused] = _audit(service, "billing.subscription_create_refused")
    assert refused.outcome == "failure"
    assert refused.meta["refusal"] == refusal.__name__
    provider_subscription_id = refused.meta["provider_subscription_id"]
    assert provider_subscription_id in market.provider.contexts
    merchant_ref = _admin(
        "SELECT provider_account_ref FROM core.billing_merchant_accounts WHERE id = :m",
        m=str(market.m_a),
    )[0][0]
    resolution = resolve_provider_ref(
        provider="fake",
        provider_account_ref=merchant_ref,
        object_type=ProviderObjectType.SUBSCRIPTION,
        provider_object_ref=provider_subscription_id,
    )
    assert str(resolution.local_object_id) == refused.resource_id


@pytest.mark.parametrize("change", ["withdraw", "revoke_offer", "merchant", "account", "authority"])
def test_a_change_during_the_provider_call_refuses_the_final_transaction(
    world: _World, market: _Market, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    unlisted = world.plan(market.agency_a, market.m_a, visibility=PlanVisibility.UNLISTED)
    offer = create_plan_offer(
        _BILLING_SYSTEM, market.agency_a, unlisted, service_tenant_id=market.client_b
    )
    buyer, grantor = world.user(), world.user()
    world.grant(market.client_b, buyer, _CHARGE, _CREATE)
    world.grant(market.client_b, grantor, ("deny_grant", "create"))
    changes = {
        "withdraw": (
            lambda: withdraw_plan(_BILLING_SYSTEM, market.agency_a, unlisted),
            PlanNotEligibleError,
        ),
        "revoke_offer": (
            lambda: revoke_plan_offer(_BILLING_SYSTEM, market.agency_a, offer.id),
            PlanNotEligibleError,
        ),
        "merchant": (
            lambda: set_merchant_account_status(
                _BILLING_SYSTEM, market.agency_a, market.m_a, MerchantAccountStatus.RESTRICTED
            ),
            PlanNotEligibleError,
        ),
        "account": (
            lambda: _admin(
                "UPDATE core.billing_accounts SET status = 'disabled' WHERE id = :a",
                a=str(market.acct_client_b),
            ),
            CommercialPartyNotActiveError,
        ),
        "authority": (
            lambda: create_deny(
                caller=UserCaller(grantor),
                principal_user_id=buyer,
                tenant_id=market.client_b,
                scope_mode=RoleScope.SELF,
                permission_id=register_permission(*_CREATE).id,
            ),
            BillingNotAuthorizedError,
        ),
    }
    action, refusal = changes[change]
    _during_provider_call(market, monkeypatch, action)
    with pytest.raises(refusal):
        market.create(
            UserCaller(buyer),
            service=market.client_b,
            payer=market.client_b,
            account=market.acct_client_b,
            plan=unlisted,
        )
    _assert_refused_after_provider(market, market.client_b, refusal)


def test_a_withdrawal_waits_for_a_creation_that_relies_on_the_plan(
    world: _World, market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The final transaction holds the plan row `FOR SHARE`: a withdrawal
    cannot commit between its eligibility decision and its insert, so the
    subscription is created against a plan that was active throughout, and
    the withdrawal then applies to new subscriptions only."""
    holding, release = threading.Event(), threading.Event()
    pid: dict[str, int] = {}
    errors: list[BaseException] = []
    real_audit = commercial.record_billing_audit

    def pause_in_final_transaction(session, *args, **kwargs):  # type: ignore[no-untyped-def]
        if kwargs.get("action") == "billing.subscription_created":
            pid["final"] = session.execute(text("SELECT pg_backend_pid()")).scalar_one()
            holding.set()
            assert release.wait(30)
        return real_audit(session, *args, **kwargs)

    monkeypatch.setattr(commercial, "record_billing_audit", pause_in_final_transaction)
    result: dict[str, object] = {}

    def _create() -> None:
        try:
            result["value"] = market.create(
                _BILLING_SYSTEM,
                service=market.client_b,
                payer=market.client_b,
                account=market.acct_client_b,
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
            holding.set()

    withdrawn = threading.Event()

    def _withdraw() -> None:
        try:
            withdraw_plan(_BILLING_SYSTEM, market.agency_a, market.plan_x)
            withdrawn.set()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    creator = threading.Thread(target=_create)
    creator.start()
    assert holding.wait(30) and not errors
    withdrawer = threading.Thread(target=_withdraw)
    withdrawer.start()
    engine = build_engine(get_migrations_database_config())
    try:
        deadline = time.monotonic() + 30
        while True:
            with engine.connect() as conn:
                blocked = conn.execute(
                    text("SELECT 1 FROM pg_stat_activity WHERE :p = ANY(pg_blocking_pids(pid))"),
                    {"p": pid["final"]},
                ).first()
            if blocked:
                break
            assert time.monotonic() < deadline, "the withdrawal never waited for the creation"
            threading.Event().wait(0.02)
        assert not withdrawn.is_set()
    finally:
        engine.dispose()
        release.set()
        creator.join(30)
        withdrawer.join(30)
    assert not errors and withdrawn.is_set()
    _, created = result["value"]  # type: ignore[misc]
    assert get_subscription(market.client_b, created.subscription_id).status == "active"
    assert _refused(market, service=market.client_b) == "withdrawn"


# --- Audit evidence -----------------------------------------------------------------


def test_creation_audit_names_every_party(world: _World, market: _Market) -> None:
    admin = world.user()
    world.grant(market.agency_a, admin, _CHARGE, _CREATE, scope=RoleScope.SUBTREE)
    _, result = market.create(
        UserCaller(admin),
        service=market.client_c,
        payer=market.agency_a,
        account=market.acct_agency,
    )
    [created] = _audit(market.client_c, "billing.subscription_created")
    assert (created.actor_type, created.actor_user_id, created.outcome) == (
        "user",
        admin,
        "success",
    )
    assert created.resource_id == str(result.subscription_id)
    meta = created.meta
    assert (
        meta["service_tenant_id"],
        meta["payer_tenant_id"],
        meta["billing_account_id"],
        meta["merchant_account_id"],
        meta["merchant_tenant_id"],
        meta["plan_id"],
        meta["plan_owner_tenant_id"],
        meta["status"],
    ) == (
        str(market.client_c),
        str(market.agency_a),
        str(market.acct_agency),
        str(market.m_a),
        str(market.agency_a),
        str(market.plan_x),
        str(market.agency_a),
        "pending",
    )
    assert "provider_customer_ref" not in meta and "provider_subscription_id" not in meta
    [charged] = _audit(market.agency_a, "billing.subscription_charged_to_account")
    assert charged.meta["subscription_id"] == str(result.subscription_id)


def test_a_refusal_before_the_provider_writes_no_success_evidence(
    world: _World, market: _Market
) -> None:
    """A cross-tenant payer attempt is refused before any provider object
    or local row exists: following the existing audit policy (refused
    authority checks are not audited), nothing is written -- in particular
    no success record and no provider object to reconcile."""
    client_admin = world.user()
    world.grant(market.client_c, client_admin, _CHARGE, _CREATE)
    with pytest.raises(BillingNotAuthorizedError):
        market.create(
            UserCaller(client_admin),
            service=market.client_c,
            payer=market.agency_a,
            account=market.acct_agency,
        )
    for tenant in (market.client_c, market.agency_a):
        for action in (
            "billing.subscription_created",
            "billing.subscription_create_refused",
            "billing.subscription_charged_to_account",
        ):
            assert _audit(tenant, action) == []
    assert market.provider.contexts == {} and market.provider.customers == {}
