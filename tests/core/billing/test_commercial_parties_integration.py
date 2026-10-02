"""Billing Foundation v2 Phase 2 -- commercial party model against a real
PostgreSQL instance with the `6e99825a629c` tables migrated and the real
restricted `saas_os_app` runtime role (RLS enforced).

Covers docs/ADR/0029-commercial-parties-and-billing-relationships.md:

- merchant (payee) and billing account (payer) isolation under RLS;
- `(provider, provider_account_ref)` and `(payer, merchant)` uniqueness;
- the payee recorded on a billing account is the merchant's real owner
  (composite foreign key);
- `Subscription.tenant_id` is the service tenant, the payer is recorded
  separately, and entitlements follow the service tenant only;
- dual authorization through `core.rbac.can()` -- payer `charge` AND
  service-tenant `create`, SUBTREE roles, delegation, explicit deny;
- the explicit trusted-system path and the rejection of a missing actor;
- `inherits_billing` is never used to decide a payer;
- the global-by-design provider-reference index and its bounded lookup.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/billing/test_commercial_parties_integration.py
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import core.identity.models  # noqa: F401  (registers core.users for audit FKs)
import pytest
from core.authority import SystemAuthority, SystemCaller, UserCaller
from core.billing.authorization import BillingActor, trusted_system
from core.billing.commercial import create_subscription, get_subscription_by_provider_ref
from core.billing.errors import (
    BillingAccountNotFoundError,
    BillingActorRequiredError,
    BillingNotAuthorizedError,
    BillingProviderMismatchError,
    CommercialPartyNotActiveError,
    DuplicateMerchantAccountError,
    InheritedBillingSubscriptionError,
    MerchantAccountNotFoundError,
    MerchantNotEligibleForPlanError,
    ProviderRefConflictError,
    ProviderRefNotFoundError,
    SubscriptionNotFoundError,
)
from core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_billing_account,
    get_merchant_account,
    get_or_create_billing_account,
    list_billing_accounts,
    list_merchant_accounts,
    set_merchant_account_status,
)
from core.billing.provider import FakeBillingProvider
from core.billing.provider_refs import (
    LocalObjectType,
    ProviderObjectType,
    register_provider_ref,
    resolve_provider_ref,
)
from core.billing.service import create_plan, get_entitlements, get_subscription, subscribe
from core.identity.service import add_tenant_membership, create_user
from core.rbac.service import (
    assign_first_role_for_new_tenant,
    create_delegation,
    create_deny,
    create_role,
    grant_permission,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from core.identity import get_membership
from core.rbac import RoleScope
from core.tenancy import (
    PlatformTenantNotConfiguredError,
    create_tenant,
    get_tenancy_config,
    set_tenant_billing_inheritance,
)

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_party_tables() -> None:
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
            conn.execute(text("SELECT 1 FROM core.billing_merchant_accounts LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"Commercial party tables missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe_engine.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _World:
    """Tracks everything a test creates, and tears it down with the
    privileged migration role (FK order, RLS-independent)."""

    def __init__(self) -> None:
        self.tenant_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        self.plan_keys: list[str] = []

    def tenant(self, label: str, *, parent_id: uuid.UUID | None = None) -> uuid.UUID:
        tenant = create_tenant(_unique(label), parent_id=parent_id)
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def user(self) -> uuid.UUID:
        user = create_user()
        self.user_ids.append(user.id)
        return user.id

    def plan(self, entitlements: dict[str, object]) -> str:
        key = _unique("p2-plan")
        create_plan(key, "Phase 2 plan", entitlements=entitlements)
        self.plan_keys.append(key)
        return key

    def grant(
        self,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        permissions: list[tuple[str, str]],
        *,
        scope: RoleScope = RoleScope.SELF,
    ) -> None:
        membership = get_membership(tenant_id, user_id)
        if membership is None:
            membership = add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
        role = create_role(tenant_id, _unique("role"), caller=_PROVISIONING)
        for resource, action in permissions:
            grant_permission(
                tenant_id, role.id, register_permission(resource, action).id, caller=_PROVISIONING
            )
        assign_first_role_for_new_tenant(
            tenant_id, membership.id, role.id, scope=scope, caller=_PROVISIONING
        )

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
                    "DELETE FROM core.idempotency_records WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_provider_refs WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_accounts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_merchant_accounts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.deny_grants WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.delegation_grants WHERE tenant_id = ANY(:t)",
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
                    session.execute(
                        text(statement),
                        {"t": tenants, "u": users, "k": self.plan_keys},
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


_SYSTEM = trusted_system("integration test fixture")


class _Platform:
    """A designated platform tenant with an active `fake` merchant."""

    def __init__(self, world: _World, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tenant_id = world.tenant("platform")
        monkeypatch.setenv("PLATFORM_TENANT_ID", str(self.tenant_id))
        get_tenancy_config.cache_clear()
        self.merchant = create_merchant_account(
            _SYSTEM,
            self.tenant_id,
            provider="fake",
            provider_account_ref=_unique("acct"),
            status=MerchantAccountStatus.ACTIVE,
        )

    def account_for(self, payer_tenant_id: uuid.UUID) -> uuid.UUID:
        account, _ = get_or_create_billing_account(
            _SYSTEM,
            payer_tenant_id,
            merchant_tenant_id=self.tenant_id,
            merchant_account_id=self.merchant.id,
        )
        return account.id


@pytest.fixture
def platform(world: _World, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Platform]:
    yield _Platform(world, monkeypatch)
    get_tenancy_config.cache_clear()


class _CountingProvider(FakeBillingProvider):
    def __init__(self) -> None:
        super().__init__()
        self.create_calls = 0

    def create_subscription(self, *, tenant_id, plan, idempotency_key=None):  # type: ignore[no-untyped-def]
        self.create_calls += 1
        return super().create_subscription(
            tenant_id=tenant_id, plan=plan, idempotency_key=idempotency_key
        )


def _create(
    caller: object,
    *,
    service: uuid.UUID,
    payer: uuid.UUID,
    account: uuid.UUID,
    plan_key: str,
    provider: FakeBillingProvider | None = None,
    key: str | None = None,
):
    return create_subscription(
        caller,
        service_tenant_id=service,
        payer_tenant_id=payer,
        billing_account_id=account,
        plan_key=plan_key,
        idempotency_key=key or _unique("idem"),
        provider=provider or FakeBillingProvider(),
    )


def _count(tenant_id: uuid.UUID, table: str) -> int:
    with tenant_session_scope(tenant_id) as session:
        return session.execute(text(f"SELECT count(*) FROM core.{table}")).scalar_one()


# --- MerchantAccount (payee) isolation and uniqueness -----------------------


def test_owner_can_read_its_merchant_and_another_tenant_cannot(
    world: _World, platform: _Platform
) -> None:
    other = world.tenant("other")
    assert get_merchant_account(platform.tenant_id, platform.merchant.id).id == platform.merchant.id
    assert [m.id for m in list_merchant_accounts(platform.tenant_id)] == [platform.merchant.id]

    with pytest.raises(MerchantAccountNotFoundError):
        get_merchant_account(other, platform.merchant.id)
    assert list_merchant_accounts(other) == []
    assert _count(other, "billing_merchant_accounts") == 0
    with tenant_session_scope(other) as session:
        updated = session.execute(
            text(
                "UPDATE core.billing_merchant_accounts SET status = 'disabled' "
                "WHERE id = :id RETURNING id"
            ),
            {"id": str(platform.merchant.id)},
        ).all()
    assert updated == []
    assert get_merchant_account(platform.tenant_id, platform.merchant.id).status == "active"


def test_merchant_provider_account_is_unique_across_the_deployment(
    world: _World, platform: _Platform
) -> None:
    other = world.tenant("other")
    with pytest.raises(DuplicateMerchantAccountError) as excinfo:
        create_merchant_account(
            _SYSTEM,
            other,
            provider="fake",
            provider_account_ref=platform.merchant.provider_account_ref,
        )
    assert str(platform.tenant_id) not in str(excinfo.value)
    # The same opaque reference at a different provider is a different merchant.
    create_merchant_account(
        _SYSTEM,
        other,
        provider="other",
        provider_account_ref=platform.merchant.provider_account_ref,
    )


def test_merchant_management_requires_billing_merchant_manage(world: _World) -> None:
    tenant, user = world.tenant("payee"), world.user()
    with pytest.raises(BillingNotAuthorizedError):
        create_merchant_account(
            BillingActor.user(user), tenant, provider="fake", provider_account_ref=_unique("acct")
        )
    world.grant(tenant, user, [("billing.merchant", "manage")])
    merchant = create_merchant_account(
        BillingActor.user(user), tenant, provider="fake", provider_account_ref=_unique("acct")
    )
    assert merchant.status == "onboarding"
    updated = set_merchant_account_status(
        BillingActor.user(user), tenant, merchant.id, MerchantAccountStatus.ACTIVE
    )
    assert updated.status == "active"


# --- BillingAccount (payer) --------------------------------------------------


def test_same_payer_and_merchant_resolve_to_one_billing_account(
    world: _World, platform: _Platform
) -> None:
    payer = world.tenant("payer")
    first, created = get_or_create_billing_account(
        _SYSTEM,
        payer,
        merchant_tenant_id=platform.tenant_id,
        merchant_account_id=platform.merchant.id,
    )
    second, created_again = get_or_create_billing_account(
        _SYSTEM,
        payer,
        merchant_tenant_id=platform.tenant_id,
        merchant_account_id=platform.merchant.id,
    )
    assert created is True and created_again is False
    assert first.id == second.id
    assert first.tenant_id == payer
    assert first.merchant_tenant_id == platform.tenant_id
    # No provider customer is invented.
    assert first.provider_customer_ref is None


def test_same_payer_has_distinct_billing_accounts_at_distinct_merchants(
    world: _World, platform: _Platform
) -> None:
    payer = world.tenant("payer")
    seller = world.tenant("seller")
    second_merchant = create_merchant_account(
        _SYSTEM,
        seller,
        provider="fake",
        provider_account_ref=_unique("acct"),
        status=MerchantAccountStatus.ACTIVE,
    )
    a = platform.account_for(payer)
    b, _ = get_or_create_billing_account(
        _SYSTEM, payer, merchant_tenant_id=seller, merchant_account_id=second_merchant.id
    )
    assert a != b.id
    assert {acc.id for acc in list_billing_accounts(payer)} == {a, b.id}


def test_billing_account_is_isolated_to_its_payer(world: _World, platform: _Platform) -> None:
    payer_a, payer_b = world.tenant("payer-a"), world.tenant("payer-b")
    account_a = platform.account_for(payer_a)
    with pytest.raises(BillingAccountNotFoundError):
        get_billing_account(payer_b, account_a)
    assert list_billing_accounts(payer_b) == []
    assert _count(payer_b, "billing_accounts") == 0
    # The payee cannot read its customers' billing accounts either.
    assert _count(platform.tenant_id, "billing_accounts") == 0


def test_billing_account_payee_must_be_the_merchants_real_owner(
    world: _World, platform: _Platform
) -> None:
    """The composite FK makes a forged payee tenant impossible."""
    payer, impostor = world.tenant("payer"), world.tenant("impostor")
    with pytest.raises(IntegrityError), tenant_session_scope(payer) as session:
        session.execute(
            text(
                "INSERT INTO core.billing_accounts (id, tenant_id, merchant_tenant_id, "
                "merchant_account_id, status) VALUES (:id, :t, :mt, :m, 'active')"
            ),
            {
                "id": str(uuid.uuid4()),
                "t": str(payer),
                "mt": str(impostor),
                "m": str(platform.merchant.id),
            },
        )


def test_billing_account_requires_an_active_merchant(world: _World, platform: _Platform) -> None:
    payer = world.tenant("payer")
    set_merchant_account_status(
        _SYSTEM, platform.tenant_id, platform.merchant.id, MerchantAccountStatus.RESTRICTED
    )
    with pytest.raises(CommercialPartyNotActiveError):
        get_or_create_billing_account(
            _SYSTEM,
            payer,
            merchant_tenant_id=platform.tenant_id,
            merchant_account_id=platform.merchant.id,
        )


def test_billing_account_management_requires_billing_account_manage(
    world: _World, platform: _Platform
) -> None:
    payer, user = world.tenant("payer"), world.user()
    with pytest.raises(BillingNotAuthorizedError):
        get_or_create_billing_account(
            BillingActor.user(user),
            payer,
            merchant_tenant_id=platform.tenant_id,
            merchant_account_id=platform.merchant.id,
        )


# --- Subscription semantics: service tenant vs payer ------------------------


def test_subscription_tenant_is_the_service_tenant_and_payer_is_recorded_separately(
    world: _World, platform: _Platform
) -> None:
    service, payer = world.tenant("service"), world.tenant("payer")
    account = platform.account_for(payer)
    plan_key = world.plan({"seats": 7, "reports": True})

    is_replay, result = _create(
        _SYSTEM, service=service, payer=payer, account=account, plan_key=plan_key
    )

    assert is_replay is False
    subscription = get_subscription(service, result.subscription_id)
    assert subscription.tenant_id == service
    assert subscription.payer_tenant_id == payer
    assert subscription.billing_account_id == account
    assert get_billing_account(payer, account).tenant_id == payer
    assert subscription.provider == "fake"
    # Entitlements follow the service tenant; the payer gains nothing.
    assert get_entitlements(service) == {"seats": 7, "reports": True}
    assert get_entitlements(payer) == {}
    # RLS owner is the service tenant: the payer cannot read the row.
    assert _count(payer, "billing_subscriptions") == 0
    with pytest.raises(SubscriptionNotFoundError):
        get_subscription(payer, result.subscription_id)


def test_a_different_payer_does_not_move_entitlement_ownership(
    world: _World, platform: _Platform
) -> None:
    service, payer_one, payer_two = (
        world.tenant("service"),
        world.tenant("payer-1"),
        world.tenant("payer-2"),
    )
    plan_key = world.plan({"seats": 3})
    _, first = _create(
        _SYSTEM,
        service=service,
        payer=payer_one,
        account=platform.account_for(payer_one),
        plan_key=plan_key,
    )
    with tenant_session_scope(service) as session:
        session.execute(
            text("UPDATE core.billing_subscriptions SET status = 'canceled' WHERE id = :id"),
            {"id": str(first.subscription_id)},
        )
    _, second = _create(
        _SYSTEM,
        service=service,
        payer=payer_two,
        account=platform.account_for(payer_two),
        plan_key=plan_key,
    )
    assert second.payer_tenant_id == payer_two
    assert get_entitlements(service) == {"seats": 3}
    assert get_entitlements(payer_one) == {} and get_entitlements(payer_two) == {}


def test_self_paid_subscription_records_the_service_tenant_as_payer(
    world: _World, platform: _Platform
) -> None:
    tenant = world.tenant("self")
    _, result = _create(
        _SYSTEM,
        service=tenant,
        payer=tenant,
        account=platform.account_for(tenant),
        plan_key=world.plan({"seats": 1}),
    )
    assert result.payer_tenant_id == tenant
    assert get_entitlements(tenant) == {"seats": 1}


def test_create_subscription_replays_without_a_second_provider_call(
    world: _World, platform: _Platform
) -> None:
    service = world.tenant("service")
    account = platform.account_for(service)
    plan_key = world.plan({})
    provider = _CountingProvider()
    first = _create(
        _SYSTEM,
        service=service,
        payer=service,
        account=account,
        plan_key=plan_key,
        provider=provider,
        key="same-key",
    )
    second = _create(
        _SYSTEM,
        service=service,
        payer=service,
        account=account,
        plan_key=plan_key,
        provider=provider,
        key="same-key",
    )
    assert first[0] is False and second[0] is True
    assert first[1] == second[1]
    assert provider.create_calls == 1


# --- Dual authorization ------------------------------------------------------

_CHARGE = ("billing.account", "charge")
_CREATE = ("billing.subscription", "create")


@pytest.fixture
def parties(world: _World, platform: _Platform):
    service, payer = world.tenant("service"), world.tenant("payer")
    return service, payer, platform.account_for(payer), world.plan({"seats": 2}), world.user()


def test_authorized_payer_and_authorized_service_tenant_is_allowed(world: _World, parties) -> None:
    service, payer, account, plan_key, user = parties
    world.grant(payer, user, [_CHARGE])
    world.grant(service, user, [_CREATE])
    _, result = _create(
        BillingActor.user(user), service=service, payer=payer, account=account, plan_key=plan_key
    )
    assert result.payer_tenant_id == payer


@pytest.mark.parametrize("granted", ["payer_only", "service_only", "neither", "swapped"])
def test_missing_either_authorization_is_denied_with_no_side_effect(
    world: _World, parties, granted: str
) -> None:
    service, payer, account, plan_key, user = parties
    if granted == "payer_only":
        world.grant(payer, user, [_CHARGE])
    elif granted == "service_only":
        world.grant(service, user, [_CREATE])
    elif granted == "swapped":
        # Each permission held, but on the wrong side of the relationship.
        world.grant(payer, user, [_CREATE])
        world.grant(service, user, [_CHARGE])
    provider = _CountingProvider()
    with pytest.raises(BillingNotAuthorizedError):
        _create(
            BillingActor.user(user),
            service=service,
            payer=payer,
            account=account,
            plan_key=plan_key,
            provider=provider,
        )
    assert provider.create_calls == 0
    assert _count(service, "billing_subscriptions") == 0


def test_payer_cannot_be_substituted_by_naming_another_payers_account(
    world: _World, platform: _Platform, parties
) -> None:
    """Authority over one payer never lets an actor charge another payer's
    billing account by supplying its id."""
    service, payer, account_of_payer, plan_key, user = parties
    own = world.tenant("own")
    world.grant(own, user, [_CHARGE])
    world.grant(service, user, [_CREATE])
    # Claiming the victim as payer: no `charge` on the victim.
    with pytest.raises(BillingNotAuthorizedError):
        _create(
            BillingActor.user(user),
            service=service,
            payer=payer,
            account=account_of_payer,
            plan_key=plan_key,
        )
    # Claiming the actor's own tenant as payer with the victim's account id:
    # the account is read under the claimed payer's RLS scope and is not there.
    with pytest.raises(BillingAccountNotFoundError):
        _create(
            BillingActor.user(user),
            service=service,
            payer=own,
            account=account_of_payer,
            plan_key=plan_key,
        )


def test_subtree_role_on_a_common_ancestor_authorizes_both_sides(
    world: _World, platform: _Platform
) -> None:
    parent = world.tenant("parent")
    service = world.tenant("child-service", parent_id=parent)
    payer = world.tenant("child-payer", parent_id=parent)
    user = world.user()
    world.grant(parent, user, [_CHARGE, _CREATE], scope=RoleScope.SUBTREE)
    _, result = _create(
        BillingActor.user(user),
        service=service,
        payer=payer,
        account=platform.account_for(payer),
        plan_key=world.plan({}),
    )
    assert result.payer_tenant_id == payer


def test_delegated_charge_authority_is_honoured(world: _World, parties) -> None:
    service, payer, account, plan_key, user = parties
    delegator = world.user()
    world.grant(payer, delegator, [_CHARGE, ("delegation_grant", "create")])
    world.grant(service, user, [_CREATE])
    with pytest.raises(BillingNotAuthorizedError):
        _create(
            BillingActor.user(user),
            service=service,
            payer=payer,
            account=account,
            plan_key=plan_key,
        )
    create_delegation(
        delegate_user_id=user,
        tenant_id=payer,
        scope_mode=RoleScope.SELF,
        permission_id=register_permission(*_CHARGE).id,
        caller=UserCaller(delegator),
    )
    _, result = _create(
        BillingActor.user(user), service=service, payer=payer, account=account, plan_key=plan_key
    )
    assert result.payer_tenant_id == payer


def test_explicit_deny_on_the_payer_wins(world: _World, parties) -> None:
    service, payer, account, plan_key, user = parties
    grantor = world.user()
    world.grant(payer, user, [_CHARGE])
    world.grant(service, user, [_CREATE])
    world.grant(payer, grantor, [("deny_grant", "create")])
    create_deny(
        principal_user_id=user,
        tenant_id=payer,
        scope_mode=RoleScope.SELF,
        permission_id=register_permission(*_CHARGE).id,
        caller=UserCaller(grantor),
    )
    with pytest.raises(BillingNotAuthorizedError):
        _create(
            BillingActor.user(user),
            service=service,
            payer=payer,
            account=account,
            plan_key=plan_key,
        )


# --- Actor-less compatibility ------------------------------------------------


def test_missing_actor_is_rejected_on_the_commercial_path(world: _World, parties) -> None:
    service, payer, account, plan_key, _ = parties
    with pytest.raises(BillingActorRequiredError):
        _create(None, service=service, payer=payer, account=account, plan_key=plan_key)
    assert _count(service, "billing_subscriptions") == 0


def test_trusted_system_path_is_audited_as_system_with_its_reason(world: _World, parties) -> None:
    service, payer, account, plan_key, _ = parties
    _, result = _create(
        trusted_system("operator backfill"),
        service=service,
        payer=payer,
        account=account,
        plan_key=plan_key,
    )
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT tenant_id, actor_type, actor_user_id, metadata AS meta "
                    "FROM core.audit_log WHERE resource_id = :sid "
                    "OR (tenant_id = :payer "
                    "AND action = 'billing.subscription_charged_to_account')"
                ),
                {"sid": str(result.subscription_id), "payer": str(payer)},
            ).all()
    finally:
        engine.dispose()
    assert {row.tenant_id for row in rows} == {service, payer}
    for row in rows:
        assert row.actor_type == "system"
        assert row.actor_user_id is None
        assert row.meta["trusted_system_reason"] == "operator backfill"


def test_legacy_subscribe_remains_compatible_and_records_no_payer(
    world: _World, platform: _Platform
) -> None:
    """The legacy trusted path is unchanged: no actor needed, the service
    tenant is implicitly its own payer and no payer is fabricated."""
    tenant = world.tenant("legacy")
    plan_key = world.plan({"seats": 4})
    subscription = subscribe(tenant, plan_key, provider=FakeBillingProvider())
    assert subscription.tenant_id == tenant
    assert subscription.payer_tenant_id is None
    assert subscription.billing_account_id is None
    assert subscription.provider == "fake"
    assert get_entitlements(tenant) == {"seats": 4}


def test_payer_and_billing_account_must_be_recorded_together(world: _World) -> None:
    tenant = world.tenant("pair")
    plan_key = world.plan({})
    with pytest.raises(IntegrityError), tenant_session_scope(tenant) as session:
        session.execute(
            text(
                "INSERT INTO core.billing_subscriptions (id, tenant_id, plan_id, status, "
                "provider_subscription_id, payer_tenant_id) SELECT :id, :t, id, 'active', "
                "'x', :t FROM core.billing_plans WHERE key = :k"
            ),
            {"id": str(uuid.uuid4()), "t": str(tenant), "k": plan_key},
        )


# --- inherits_billing is never used to decide a payer ------------------------


def test_payer_is_never_inferred_from_the_hierarchy_or_inherits_billing(
    world: _World, platform: _Platform
) -> None:
    parent = world.tenant("parent")
    child = world.tenant("child", parent_id=parent)
    platform.account_for(parent)  # the parent has an account; it is never picked
    _, result = _create(
        _SYSTEM,
        service=child,
        payer=child,
        account=platform.account_for(child),
        plan_key=world.plan({"seats": 1}),
    )
    assert result.payer_tenant_id == child


def test_inheriting_service_tenant_is_refused_rather_than_redirected(
    world: _World, platform: _Platform
) -> None:
    parent = world.tenant("parent")
    child = world.tenant("child", parent_id=parent)
    set_tenant_billing_inheritance(child, True)
    with pytest.raises(InheritedBillingSubscriptionError):
        _create(
            _SYSTEM,
            service=child,
            payer=parent,
            account=platform.account_for(parent),
            plan_key=world.plan({}),
        )
    assert _count(parent, "billing_subscriptions") == 0
    assert _count(child, "billing_subscriptions") == 0


# --- Merchant / provider boundaries ------------------------------------------


def test_only_the_platform_merchant_sells_plans_before_catalog_v2(
    world: _World, platform: _Platform
) -> None:
    seller, payer = world.tenant("seller"), world.tenant("payer")
    merchant = create_merchant_account(
        _SYSTEM,
        seller,
        provider="fake",
        provider_account_ref=_unique("acct"),
        status=MerchantAccountStatus.ACTIVE,
    )
    account, _ = get_or_create_billing_account(
        _SYSTEM, payer, merchant_tenant_id=seller, merchant_account_id=merchant.id
    )
    with pytest.raises(MerchantNotEligibleForPlanError):
        _create(_SYSTEM, service=payer, payer=payer, account=account.id, plan_key=world.plan({}))


def test_provider_adapter_must_match_the_merchant(world: _World, platform: _Platform) -> None:
    payer = world.tenant("payer")
    account = platform.account_for(payer)

    class _OtherProvider(FakeBillingProvider):
        name = "other"

    with pytest.raises(BillingProviderMismatchError):
        _create(
            _SYSTEM,
            service=payer,
            payer=payer,
            account=account,
            plan_key=world.plan({}),
            provider=_OtherProvider(),
        )


def test_inactive_merchant_cannot_be_charged_through(world: _World, platform: _Platform) -> None:
    payer = world.tenant("payer")
    account = platform.account_for(payer)
    set_merchant_account_status(
        _SYSTEM, platform.tenant_id, platform.merchant.id, MerchantAccountStatus.DISABLED
    )
    with pytest.raises(CommercialPartyNotActiveError):
        _create(_SYSTEM, service=payer, payer=payer, account=account, plan_key=world.plan({}))


def test_unconfigured_platform_tenant_fails_closed(
    world: _World, platform: _Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    payer = world.tenant("payer")
    account = platform.account_for(payer)
    monkeypatch.delenv("PLATFORM_TENANT_ID")
    get_tenancy_config.cache_clear()
    with pytest.raises(PlatformTenantNotConfiguredError):
        _create(_SYSTEM, service=payer, payer=payer, account=account, plan_key=world.plan({}))


# --- ProviderRef: global-by-design, bounded lookup ---------------------------


def test_provider_ref_resolves_deterministically_to_the_service_tenant_row(
    world: _World, platform: _Platform
) -> None:
    service, payer = world.tenant("service"), world.tenant("payer")
    _, result = _create(
        _SYSTEM,
        service=service,
        payer=payer,
        account=platform.account_for(payer),
        plan_key=world.plan({}),
    )
    for _ in range(2):
        resolution = resolve_provider_ref(
            provider="fake",
            provider_account_ref=platform.merchant.provider_account_ref,
            object_type=ProviderObjectType.SUBSCRIPTION,
            provider_object_ref=result.provider_subscription_id,
        )
        assert resolution.tenant_id == service
        assert resolution.local_object_type is LocalObjectType.BILLING_SUBSCRIPTION
        assert resolution.local_object_id == result.subscription_id

    found = get_subscription_by_provider_ref(
        provider="fake",
        provider_account_ref=platform.merchant.provider_account_ref,
        provider_subscription_ref=result.provider_subscription_id,
    )
    assert found.id == result.subscription_id and found.tenant_id == service


def test_provider_ref_is_unique_and_cannot_be_repointed(world: _World) -> None:
    tenant_a, tenant_b = world.tenant("a"), world.tenant("b")
    ref = {
        "provider": "fake",
        "provider_account_ref": _unique("acct"),
        "object_type": ProviderObjectType.SUBSCRIPTION,
        "provider_object_ref": _unique("sub"),
    }
    local_id = uuid.uuid4()
    first = register_provider_ref(
        **ref,
        tenant_id=tenant_a,
        local_object_type=LocalObjectType.BILLING_SUBSCRIPTION,
        local_object_id=local_id,
    )
    # The identical mapping is idempotent ...
    assert (
        register_provider_ref(
            **ref,
            tenant_id=tenant_a,
            local_object_type=LocalObjectType.BILLING_SUBSCRIPTION,
            local_object_id=local_id,
        )
        == first
    )
    # ... any other mapping of the same provider reference is refused.
    with pytest.raises(ProviderRefConflictError) as excinfo:
        register_provider_ref(
            **ref,
            tenant_id=tenant_b,
            local_object_type=LocalObjectType.BILLING_SUBSCRIPTION,
            local_object_id=uuid.uuid4(),
        )
    assert str(tenant_a) not in str(excinfo.value)
    assert resolve_provider_ref(**ref).tenant_id == tenant_a


def test_unknown_and_dangling_provider_refs_fail_closed(world: _World) -> None:
    tenant = world.tenant("t")
    account_ref, sub_ref = _unique("acct"), _unique("sub")
    with pytest.raises(ProviderRefNotFoundError):
        get_subscription_by_provider_ref(
            provider="fake", provider_account_ref=account_ref, provider_subscription_ref=sub_ref
        )
    register_provider_ref(
        provider="fake",
        provider_account_ref=account_ref,
        object_type=ProviderObjectType.SUBSCRIPTION,
        provider_object_ref=sub_ref,
        tenant_id=tenant,
        local_object_type=LocalObjectType.BILLING_SUBSCRIPTION,
        local_object_id=uuid.uuid4(),
    )
    with pytest.raises(SubscriptionNotFoundError):
        get_subscription_by_provider_ref(
            provider="fake", provider_account_ref=account_ref, provider_subscription_ref=sub_ref
        )


def test_provider_ref_index_is_global_while_party_tables_stay_tenant_scoped(
    world: _World, platform: _Platform
) -> None:
    """Without any tenant context the app role reads the global index (by
    design) but zero rows of every tenant-owned billing table."""
    payer = world.tenant("payer")
    _create(
        _SYSTEM,
        service=payer,
        payer=payer,
        account=platform.account_for(payer),
        plan_key=world.plan({}),
    )
    with session_scope() as session:
        assert (
            session.execute(
                text("SELECT count(*) FROM core.billing_provider_refs WHERE tenant_id = :t"),
                {"t": str(payer)},
            ).scalar_one()
            == 1
        )
        for table in ("billing_merchant_accounts", "billing_accounts", "billing_subscriptions"):
            assert session.execute(text(f"SELECT count(*) FROM core.{table}")).scalar_one() == 0
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            flags = {
                row[0]: row[1]
                for row in conn.execute(
                    text(
                        "SELECT relname, relforcerowsecurity FROM pg_class WHERE relname IN "
                        "('billing_merchant_accounts', 'billing_accounts', "
                        "'billing_subscriptions', 'billing_provider_refs')"
                    )
                ).all()
            }
    finally:
        engine.dispose()
    assert flags == {
        "billing_merchant_accounts": True,
        "billing_accounts": True,
        "billing_subscriptions": True,
        "billing_provider_refs": False,
    }
