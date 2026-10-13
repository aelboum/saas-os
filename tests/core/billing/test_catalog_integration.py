"""Phase 5.3 step 2 -- Catalog v2 against a real PostgreSQL instance
(docs/ADR/0029-commercial-parties-and-billing-relationships.md and
docs/ADR/0022-..., both 2026-10-02).

Pins: explicit plan ownership and merchant; owner-scoped keys; the four
visibilities; offers for unlisted plans; withdrawal; the single eligibility
predicate behind `list_plans()`; operator-only legacy adoption; catalog
mutation authority (no support elevation) with same-transaction audit; and
that an eligibility decision holds the offer it relied on until its
transaction ends.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from lifecycle_callers import platform_operator
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.billing import catalog
from saas_os.core.billing.catalog import (
    EligibilityReason,
    PlanVisibility,
    adopt_legacy_plan,
    create_owned_plan,
    create_plan_offer,
    evaluate_plan_eligibility,
    list_plans,
    revoke_plan_offer,
    set_plan_visibility,
    withdraw_plan,
)
from saas_os.core.billing.errors import (
    BillingNotAuthorizedError,
    CatalogPlanNotFoundError,
    DuplicateOwnedPlanKeyError,
    LegacyPlanAdoptionError,
    MerchantAccountNotFoundError,
    PlanWithdrawnError,
)
from saas_os.core.billing.models import Plan
from saas_os.core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    set_merchant_account_status,
)
from saas_os.core.billing.provider import FakeBillingProvider
from saas_os.core.billing.service import (
    create_plan,
    get_entitlements,
    get_plan,
    get_subscription,
    subscribe,
)
from saas_os.core.identity import get_membership
from saas_os.core.identity.service import add_tenant_membership, create_user
from saas_os.core.rbac import RoleScope
from saas_os.core.rbac.service import (
    approve_support_access,
    assign_first_role_for_new_tenant,
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
_MANAGE = ("billing.catalog", "manage")
_CREATE_SUBSCRIPTION = ("billing.subscription", "create")


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

    def user(self, *grants: tuple[uuid.UUID, tuple[str, str]]) -> uuid.UUID:
        user = create_user()
        self.user_ids.append(user.id)
        for tenant_id, permission in grants:
            self.grant(tenant_id, user.id, permission)
        return user.id

    def grant(self, tenant_id: uuid.UUID, user_id: uuid.UUID, permission: tuple[str, str]) -> None:
        membership = get_membership(tenant_id, user_id)
        if membership is None:
            membership = add_tenant_membership(tenant_id, user_id, caller=_PROVISIONING)
        role = create_role(tenant_id, _unique("role"), caller=_PROVISIONING)
        grant_permission(
            tenant_id, role.id, register_permission(*permission).id, caller=_PROVISIONING
        )
        assign_first_role_for_new_tenant(
            tenant_id, membership.id, role.id, scope=RoleScope.SELF, caller=_PROVISIONING
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
        key: str | None = None,
        visibility: PlanVisibility = PlanVisibility.PUBLIC,
        entitlements: dict[str, object] | None = None,
    ) -> Plan:
        return create_owned_plan(
            _BILLING_SYSTEM,
            owner,
            merchant_account_id=merchant,
            key=key or _unique("plan"),
            name="Catalog v2 plan",
            entitlements=entitlements or {"seats": 1},
            visibility=visibility,
        )

    def legacy_plan(self, entitlements: dict[str, object] | None = None) -> Plan:
        key = _unique("legacy")
        self.legacy_keys.append(key)
        return create_plan(key, "Legacy plan", entitlements=entitlements or {"seats": 2})

    def support_engineer(self, tenant_id: uuid.UUID) -> uuid.UUID:
        approver = self.user((tenant_id, ("support_access_request", "approve")))
        engineer = self.user()
        from datetime import UTC, datetime, timedelta

        request = create_support_access_request(
            caller=UserCaller(engineer),
            tenant_id=tenant_id,
            reason="catalog v2 boundary",
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
                    "DELETE FROM core.billing_provider_refs WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plan_offers WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plans WHERE owner_tenant_id = ANY(:t) "
                    "OR key = ANY(:k)",
                    "DELETE FROM core.billing_accounts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_merchant_accounts WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.support_access_requests WHERE tenant_id = ANY(:t)",
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


def _eligibility(caller: object, service: uuid.UUID, plan: Plan, **kwargs: object):  # type: ignore[no-untyped-def]
    with tenant_session_scope(service) as session:
        return catalog.evaluate_plan_eligibility(caller, service, plan, session=session, **kwargs)  # type: ignore[arg-type]


def _listed(caller: object, service: uuid.UUID, plans: list[Plan]) -> set[uuid.UUID]:
    ours = {p.id for p in plans}
    return {p.id for p in list_plans(caller, service_tenant_id=service)} & ours


def _audit(tenant_id: uuid.UUID, action: str) -> list:  # type: ignore[type-arg]
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            return list(
                conn.execute(
                    text(
                        "SELECT actor_type, actor_user_id, resource_id, metadata AS meta "
                        "FROM core.audit_log WHERE tenant_id = :t AND action = :a"
                    ),
                    {"t": str(tenant_id), "a": action},
                ).all()
            )
    finally:
        engine.dispose()


# --- Ownership and owner-scoped keys --------------------------------------------------


def test_a_plan_records_its_owner_and_merchant_explicitly(world: _World) -> None:
    agency = world.tenant("agency")
    merchant = world.merchant(agency)
    plan = world.plan(agency, merchant)
    assert (plan.owner_tenant_id, plan.merchant_account_id) == (agency, merchant)
    assert (plan.legacy, plan.visibility, plan.status) == (False, "public", "active")
    [row] = _audit(agency, "billing.plan_created")
    assert row.resource_id == str(plan.id) and row.meta["system_authority"] == "billing_operations"


def test_keys_are_unique_per_owner_not_per_deployment(world: _World) -> None:
    agency_a, agency_b = world.tenant("agency-a"), world.tenant("agency-b")
    merchant_a, merchant_b = world.merchant(agency_a), world.merchant(agency_b)
    key = _unique("starter")
    first = world.plan(agency_a, merchant_a, key=key)
    second = world.plan(agency_b, merchant_b, key=key)
    assert first.key == second.key and first.id != second.id
    with pytest.raises(DuplicateOwnedPlanKeyError) as excinfo:
        world.plan(agency_a, merchant_a, key=key)
    assert excinfo.value.owner_tenant_id == agency_a  # names only the caller's own catalog
    # A legacy plan with the same key lives in its own namespace.
    world.legacy_keys.append(key)
    assert create_plan(key, "Legacy twin").owner_tenant_id is None


def test_a_plan_can_only_be_sold_by_a_merchant_its_owner_owns(world: _World) -> None:
    agency_a, agency_b = world.tenant("agency-a"), world.tenant("agency-b")
    merchant_a = world.merchant(agency_a)
    with pytest.raises(MerchantAccountNotFoundError):
        world.plan(agency_b, merchant_a)
    # The database refuses it too, whatever the application does.
    with pytest.raises(IntegrityError), tenant_session_scope(agency_b) as session:
        session.execute(
            text(
                "INSERT INTO core.billing_plans (id, key, name, entitlements, owner_tenant_id, "
                "merchant_account_id, legacy) VALUES (:id, :k, 'x', '{}', :o, :m, false)"
            ),
            {
                "id": str(uuid.uuid4()),
                "k": _unique("raw"),
                "o": str(agency_b),
                "m": str(merchant_a),
            },
        )


def test_another_owner_cannot_mutate_a_plan(world: _World) -> None:
    agency_a, agency_b = world.tenant("agency-a"), world.tenant("agency-b")
    plan = world.plan(agency_a, world.merchant(agency_a), visibility=PlanVisibility.UNLISTED)
    other = UserCaller(world.user((agency_b, _MANAGE)))
    # Naming its own tenant: the plan is simply not among its plans.
    with pytest.raises(CatalogPlanNotFoundError):
        set_plan_visibility(other, agency_b, plan.id, PlanVisibility.PUBLIC)
    with pytest.raises(CatalogPlanNotFoundError):
        withdraw_plan(other, agency_b, plan.id)
    with pytest.raises(CatalogPlanNotFoundError):
        create_plan_offer(other, agency_b, plan.id, service_tenant_id=agency_b)
    # Naming the real owner: no authority there.
    with pytest.raises(BillingNotAuthorizedError):
        set_plan_visibility(other, agency_a, plan.id, PlanVisibility.PUBLIC)
    with pytest.raises(BillingNotAuthorizedError):
        withdraw_plan(other, agency_a, plan.id)
    assert get_plan_row(plan.id).visibility == "unlisted"
    assert get_plan_row(plan.id).status == "active"


def get_plan_row(plan_id: uuid.UUID) -> Plan:
    with session_scope() as session:
        plan = session.get(Plan, plan_id)
        assert plan is not None
        session.expunge(plan)
        return plan


# --- Catalog mutation authority -----------------------------------------------------


@pytest.mark.parametrize("who", ["no-permission", "support"])
def test_catalog_mutations_need_catalog_manage_on_the_owner(world: _World, who: str) -> None:
    agency, client = world.tenant("agency"), world.tenant("client")
    merchant = world.merchant(agency)
    plan = world.plan(agency, merchant, visibility=PlanVisibility.UNLISTED)
    offer = create_plan_offer(_BILLING_SYSTEM, agency, plan.id, service_tenant_id=client)
    if who == "support":
        caller = UserCaller(world.support_engineer(agency))
    else:
        caller = UserCaller(world.user((agency, ("billing.catalog", "read"))))
    attempts = [
        lambda: create_owned_plan(
            caller, agency, merchant_account_id=merchant, key=_unique("k"), name="n"
        ),
        lambda: set_plan_visibility(caller, agency, plan.id, PlanVisibility.PUBLIC),
        lambda: withdraw_plan(caller, agency, plan.id),
        lambda: create_plan_offer(caller, agency, plan.id, service_tenant_id=agency),
        lambda: revoke_plan_offer(caller, agency, offer.id),
        lambda: adopt_legacy_plan(
            caller, world.legacy_plan().id, owner_tenant_id=agency, merchant_account_id=merchant
        ),
    ]
    for attempt in attempts:
        with pytest.raises(BillingNotAuthorizedError):
            attempt()
    row = get_plan_row(plan.id)
    assert (row.visibility, row.status) == ("unlisted", "active")
    assert _eligibility(_BILLING_SYSTEM, client, plan).eligible  # the offer was not revoked


def test_a_catalog_manager_performs_every_mutation_audited_as_itself(world: _World) -> None:
    agency, client = world.tenant("agency"), world.tenant("client")
    merchant = world.merchant(agency)
    manager = world.user((agency, _MANAGE))
    caller = UserCaller(manager)
    plan = create_owned_plan(
        caller, agency, merchant_account_id=merchant, key=_unique("k"), name="n"
    )
    set_plan_visibility(caller, agency, plan.id, PlanVisibility.UNLISTED)
    offer = create_plan_offer(caller, agency, plan.id, service_tenant_id=client)
    revoke_plan_offer(caller, agency, offer.id)
    withdraw_plan(caller, agency, plan.id)
    for action in (
        "billing.plan_created",
        "billing.plan_visibility_changed",
        "billing.plan_offer_created",
        "billing.plan_offer_revoked",
        "billing.plan_withdrawn",
    ):
        [row] = _audit(agency, action)
        assert (row.actor_type, row.actor_user_id) == ("user", manager), action


def test_a_rolled_back_catalog_mutation_leaves_no_audit_entry(
    world: _World, monkeypatch: pytest.MonkeyPatch
) -> None:
    agency = world.tenant("agency")
    plan = world.plan(agency, world.merchant(agency))
    real = catalog.record_billing_audit

    def audit_then_fail(*args, **kwargs):  # type: ignore[no-untyped-def]
        real(*args, **kwargs)
        raise RuntimeError("simulated failure after the audit entry")

    monkeypatch.setattr(catalog, "record_billing_audit", audit_then_fail)
    with pytest.raises(RuntimeError):
        withdraw_plan(_BILLING_SYSTEM, agency, plan.id)
    assert get_plan_row(plan.id).status == "active"
    assert _audit(agency, "billing.plan_withdrawn") == []


# --- Visibility ---------------------------------------------------------------------


class _Market:
    """Platform-agnostic B2B2C shape: an agency with a merchant, a child
    client and a grandchild client below it, an unrelated tenant, and a
    buyer who may create subscriptions at every one of those tenants."""

    def __init__(self, world: _World) -> None:
        self.agency = world.tenant("agency")
        self.merchant = world.merchant(self.agency)
        self.client = world.tenant("client", parent_id=self.agency)
        self.grandchild = world.tenant("grandchild", parent_id=self.client)
        self.unrelated = world.tenant("unrelated")
        services = (self.agency, self.client, self.grandchild, self.unrelated)
        self.buyer = UserCaller(world.user(*((t, _CREATE_SUBSCRIPTION) for t in services)))


@pytest.fixture
def market(world: _World) -> _Market:
    return _Market(world)


def test_public_plans_are_eligible_anywhere_the_caller_may_subscribe(
    world: _World, market: _Market
) -> None:
    plan = world.plan(market.agency, market.merchant, visibility=PlanVisibility.PUBLIC)
    for tenant in (market.client, market.unrelated, market.agency):
        assert _eligibility(market.buyer, tenant, plan).eligible


def test_descendants_plans_reach_strict_descendants_only(world: _World, market: _Market) -> None:
    plan = world.plan(market.agency, market.merchant, visibility=PlanVisibility.DESCENDANTS)
    assert _eligibility(market.buyer, market.client, plan).eligible
    assert _eligibility(market.buyer, market.grandchild, plan).eligible
    for tenant in (market.agency, market.unrelated):
        decision = _eligibility(market.buyer, tenant, plan)
        assert decision.reason is EligibilityReason.NOT_A_DESCENDANT


def test_private_plans_need_catalog_read_on_the_owner(world: _World, market: _Market) -> None:
    plan = world.plan(market.agency, market.merchant, visibility=PlanVisibility.PRIVATE)
    assert _eligibility(market.buyer, market.client, plan).reason is EligibilityReason.PRIVATE
    reader = world.user(
        (market.client, _CREATE_SUBSCRIPTION), (market.agency, ("billing.catalog", "read"))
    )
    assert _eligibility(UserCaller(reader), market.client, plan).eligible


def test_unlisted_plans_need_an_active_offer_to_that_tenant(world: _World, market: _Market) -> None:
    plan = world.plan(market.agency, market.merchant, visibility=PlanVisibility.UNLISTED)
    # Knowing the plan id grants nothing.
    assert _eligibility(market.buyer, market.client, plan).reason is EligibilityReason.NO_OFFER
    offer = create_plan_offer(
        _BILLING_SYSTEM, market.agency, plan.id, service_tenant_id=market.client
    )
    assert _eligibility(market.buyer, market.client, plan).eligible
    # The offer is to one tenant only -- not its descendant, not anyone else.
    for tenant in (market.grandchild, market.unrelated):
        assert _eligibility(market.buyer, tenant, plan).reason is EligibilityReason.NO_OFFER
    revoke_plan_offer(_BILLING_SYSTEM, market.agency, offer.id)
    assert _eligibility(market.buyer, market.client, plan).reason is EligibilityReason.NO_OFFER


def test_offers_are_invisible_to_the_offered_tenant(world: _World, market: _Market) -> None:
    plan = world.plan(market.agency, market.merchant, visibility=PlanVisibility.UNLISTED)
    create_plan_offer(_BILLING_SYSTEM, market.agency, plan.id, service_tenant_id=market.client)
    for tenant, expected in ((market.client, 0), (market.unrelated, 0), (market.agency, 1)):
        with tenant_session_scope(tenant) as session:
            count = session.execute(
                text("SELECT count(*) FROM core.billing_plan_offers WHERE plan_id = :p"),
                {"p": str(plan.id)},
            ).scalar_one()
        assert count == expected, tenant


def test_without_subscription_authority_nothing_is_eligible(world: _World, market: _Market) -> None:
    plan = world.plan(market.agency, market.merchant)
    stranger = UserCaller(world.user((market.client, ("billing.subscription", "read"))))
    support = UserCaller(world.support_engineer(market.client))
    for caller in (stranger, support):
        assert _eligibility(caller, market.client, plan).reason is EligibilityReason.NOT_AUTHORIZED
        assert _listed(caller, market.client, [plan]) == set()


# --- Status, merchant, adoption -----------------------------------------------------


def test_withdrawn_plans_are_not_eligible_and_cannot_be_offered(
    world: _World, market: _Market
) -> None:
    plan = world.plan(market.agency, market.merchant)
    withdraw_plan(_BILLING_SYSTEM, market.agency, plan.id)
    withdrawn = get_plan_row(plan.id)
    assert (
        _eligibility(market.buyer, market.client, withdrawn).reason is EligibilityReason.WITHDRAWN
    )
    with pytest.raises(PlanWithdrawnError):
        create_plan_offer(_BILLING_SYSTEM, market.agency, plan.id, service_tenant_id=market.client)
    # Terminal and idempotent.
    withdraw_plan(_BILLING_SYSTEM, market.agency, plan.id)
    assert len(_audit(market.agency, "billing.plan_withdrawn")) == 1


def test_withdrawal_does_not_touch_an_existing_subscription(world: _World, market: _Market) -> None:
    legacy = world.legacy_plan({"seats": 9})
    subscription = subscribe(market.client, legacy.key, provider=FakeBillingProvider())
    adopt_legacy_plan(
        _BILLING_SYSTEM,
        legacy.id,
        owner_tenant_id=market.agency,
        merchant_account_id=market.merchant,
    )
    withdraw_plan(_BILLING_SYSTEM, market.agency, legacy.id)
    after = get_subscription(market.client, subscription.id)
    assert (after.status, after.plan_id) == (subscription.status, legacy.id)
    assert get_entitlements(market.client) == {"seats": 9}


def test_merchant_compatibility_and_merchant_status(world: _World, market: _Market) -> None:
    plan = world.plan(market.agency, market.merchant)
    other_merchant = world.merchant(market.agency)
    assert _eligibility(
        market.buyer, market.client, plan, merchant_account_id=market.merchant
    ).eligible
    decision = _eligibility(market.buyer, market.client, plan, merchant_account_id=other_merchant)
    assert decision.reason is EligibilityReason.MERCHANT_MISMATCH
    set_merchant_account_status(
        _BILLING_SYSTEM, market.agency, market.merchant, MerchantAccountStatus.RESTRICTED
    )
    assert _eligibility(market.buyer, market.client, plan).reason is (
        EligibilityReason.MERCHANT_INACTIVE
    )


def test_a_legacy_plan_is_never_silently_owned_or_eligible(world: _World, market: _Market) -> None:
    legacy = world.legacy_plan()
    assert (legacy.owner_tenant_id, legacy.merchant_account_id, legacy.legacy) == (None, None, True)
    assert _eligibility(_BILLING_SYSTEM, market.client, legacy).reason is (
        EligibilityReason.NOT_ADOPTED
    )
    assert _listed(market.buyer, market.client, [legacy]) == set()


def test_operator_adoption_records_the_owner_and_keeps_legacy_paths(
    world: _World, market: _Market
) -> None:
    legacy = world.legacy_plan()
    adopted = adopt_legacy_plan(
        _BILLING_SYSTEM,
        legacy.id,
        owner_tenant_id=market.agency,
        merchant_account_id=market.merchant,
        visibility=PlanVisibility.DESCENDANTS,
    )
    assert (adopted.owner_tenant_id, adopted.merchant_account_id) == (
        market.agency,
        market.merchant,
    )
    assert get_plan_row(legacy.id).owner_tenant_id == market.agency
    assert get_plan(legacy.key).id == legacy.id  # the legacy key still resolves
    assert _eligibility(market.buyer, market.client, adopted).eligible
    [row] = _audit(market.agency, "billing.plan_adopted")
    assert row.meta["system_authority"] == "billing_operations"
    with pytest.raises(LegacyPlanAdoptionError):
        adopt_legacy_plan(
            _BILLING_SYSTEM,
            legacy.id,
            owner_tenant_id=market.agency,
            merchant_account_id=market.merchant,
        )


def test_adoption_is_an_operator_action_only(world: _World, market: _Market) -> None:
    legacy = world.legacy_plan()
    manager = UserCaller(world.user((market.agency, _MANAGE)))
    for caller in (manager, _PROVISIONING, SystemCaller(SystemAuthority.TENANT_PURGE)):
        with pytest.raises(BillingNotAuthorizedError):
            adopt_legacy_plan(
                caller,
                legacy.id,
                owner_tenant_id=market.agency,
                merchant_account_id=market.merchant,
            )
    owned = world.plan(market.agency, market.merchant)
    with pytest.raises(LegacyPlanAdoptionError):
        adopt_legacy_plan(
            _BILLING_SYSTEM,
            owned.id,
            owner_tenant_id=market.agency,
            merchant_account_id=market.merchant,
        )
    stranger_merchant = world.merchant(market.unrelated)
    with pytest.raises(MerchantAccountNotFoundError):
        adopt_legacy_plan(
            _BILLING_SYSTEM,
            legacy.id,
            owner_tenant_id=market.agency,
            merchant_account_id=stranger_merchant,
        )
    assert get_plan_row(legacy.id).owner_tenant_id is None


# --- list_plans() is the predicate --------------------------------------------------


def test_list_plans_returns_exactly_what_the_predicate_admits(
    world: _World, market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    public = world.plan(market.agency, market.merchant, visibility=PlanVisibility.PUBLIC)
    descendants = world.plan(market.agency, market.merchant, visibility=PlanVisibility.DESCENDANTS)
    private = world.plan(market.agency, market.merchant, visibility=PlanVisibility.PRIVATE)
    unlisted = world.plan(market.agency, market.merchant, visibility=PlanVisibility.UNLISTED)
    withdrawn = world.plan(market.agency, market.merchant)
    withdraw_plan(_BILLING_SYSTEM, market.agency, withdrawn.id)
    create_plan_offer(_BILLING_SYSTEM, market.agency, unlisted.id, service_tenant_id=market.client)
    ours = [public, descendants, private, unlisted, withdrawn]

    evaluated: list[tuple[uuid.UUID, bool]] = []
    real = catalog.evaluate_plan_eligibility

    def spying(caller, service, plan, **kwargs):  # type: ignore[no-untyped-def]
        decision = real(caller, service, plan, **kwargs)
        evaluated.append((plan.id, decision.eligible))
        return decision

    monkeypatch.setattr(catalog, "evaluate_plan_eligibility", spying)
    assert _listed(market.buyer, market.client, ours) == {public.id, descendants.id, unlisted.id}
    # Every one of our active candidates went through the predicate, and the
    # listing is exactly its verdict (the withdrawn plan is not a candidate).
    verdicts = {plan_id: ok for plan_id, ok in evaluated}
    assert {
        plan_id: verdicts[plan_id]
        for plan_id in (public.id, descendants.id, private.id, unlisted.id)
    } == {
        public.id: True,
        descendants.id: True,
        private.id: False,
        unlisted.id: True,
    }
    assert withdrawn.id not in verdicts
    evaluated.clear()
    assert _listed(market.buyer, market.unrelated, ours) == {public.id}


# --- Concurrency: a decision holds the offer it relied on --------------------------


def test_offer_revocation_waits_for_a_transaction_relying_on_the_offer(
    world: _World, market: _Market
) -> None:
    """The step 3 commit-time re-check depends on this: an eligibility
    decision reads the offer `FOR SHARE`, so a revocation cannot commit
    between the decision and the end of the transaction that relies on it."""
    plan = world.plan(market.agency, market.merchant, visibility=PlanVisibility.UNLISTED)
    offer = create_plan_offer(
        _BILLING_SYSTEM, market.agency, plan.id, service_tenant_id=market.client
    )
    decided, release, revoked = threading.Event(), threading.Event(), threading.Event()
    pid: dict[str, int] = {}
    errors: list[BaseException] = []

    def _decide_and_hold() -> None:
        try:
            with tenant_session_scope(market.client) as session:
                pid["decision"] = session.execute(text("SELECT pg_backend_pid()")).scalar_one()
                assert evaluate_plan_eligibility(
                    market.buyer, market.client, plan, session=session
                ).eligible
                decided.set()
                assert release.wait(30)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
            decided.set()

    def _revoke() -> None:
        try:
            revoke_plan_offer(_BILLING_SYSTEM, market.agency, offer.id)
            revoked.set()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    holder = threading.Thread(target=_decide_and_hold)
    holder.start()
    assert decided.wait(30) and not errors
    revoker = threading.Thread(target=_revoke)
    revoker.start()
    engine = build_engine(get_migrations_database_config())
    try:
        deadline = time.monotonic() + 30
        while True:
            with engine.connect() as conn:
                blocked = conn.execute(
                    text("SELECT 1 FROM pg_stat_activity WHERE :p = ANY(pg_blocking_pids(pid))"),
                    {"p": pid["decision"]},
                ).first()
            if blocked:
                break
            assert time.monotonic() < deadline, "the revocation never waited for the decision"
            threading.Event().wait(0.02)
        assert not revoked.is_set()
    finally:
        engine.dispose()
        release.set()
        holder.join(30)
        revoker.join(30)
    assert not errors and revoked.is_set()
    assert _eligibility(market.buyer, market.client, plan).reason is EligibilityReason.NO_OFFER
