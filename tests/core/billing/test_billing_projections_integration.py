"""Phase 5.3 step 4 -- seller and payer projections against a real
PostgreSQL instance (docs/ADR/0029-..., "Seller and payer projections").

Shape (generic tenants):

    Agency A (merchant mA)                  Agency B (merchant mB)
      +-- Client B  pays itself, at mA        +-- Client D pays itself, at mB
      +-- Client C  Agency A pays, at mA

Pins: the subscription stays the source of truth; every canonical change
and its projection event commit (or roll back) together; the consumer
projects the current canonical row into the merchant's and the payer's
RLS-owned read models, version-fenced and idempotent under duplicate,
reordered, retried and concurrent delivery; malformed and cross-tenant
events are refused; reads are authorized and owner-scoped; the service
tenant and support see only what policy grants.
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import core.identity.models  # noqa: F401  (registers core.users for audit FKs)
import pytest
from core.authority import SystemAuthority, SystemCaller, UserCaller
from core.billing.catalog import create_owned_plan
from core.billing.commercial import (
    cancel_commercial_subscription,
    create_subscription,
    reconcile_subscription_status,
)
from core.billing.errors import (
    BillingNotAuthorizedError,
    MalformedProjectionEventError,
    ProjectionNotReadyError,
    SubscriptionProjectionNotFoundError,
)
from core.billing.models import PayerSubscription, SellerSubscription
from core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_or_create_billing_account,
)
from core.billing.projections import (
    SUBSCRIPTION_CHANGED_EVENT_TYPE,
    get_payer_subscription,
    get_seller_subscription,
    list_payer_subscriptions,
    list_seller_subscriptions,
    project_subscription,
)
from core.billing.provider import FakeBillingProvider, ProviderSubscriptionState
from core.billing.service import cancel_subscription, create_plan, get_subscription, subscribe
from core.identity.service import add_tenant_membership, create_user
from core.rbac.service import (
    approve_support_access,
    assign_first_role_for_new_tenant,
    create_role,
    create_support_access_request,
    grant_permission,
    register_permission,
)
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from api import outbox_dispatcher
from core.billing import commercial, projections
from core.identity import get_membership
from core.outbox import (
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_PUBLISHED,
    OutboxDispatchConfig,
    PermanentEventError,
    append_event,
    claim_due_events,
)
from core.outbox import dispatch as outbox_dispatch
from core.rbac import RoleScope
from core.tenancy import TenantStatus, create_tenant, transition_tenant_status
from infra.jobs import TenantJobContext, TenantJobPayload

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_BILLING_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)
_MERCHANT_MANAGE = ("billing.merchant", "manage")
_ACCOUNT_READ = ("billing.account", "read")
_CONFIG = OutboxDispatchConfig(
    max_attempts=3, retry_jitter_ratio=0, lease_seconds=300, retry_base_seconds=60
)


@pytest.fixture(autouse=True)
def _require_reachable_database_with_projections() -> None:
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
            conn.execute(text("SELECT 1 FROM core.billing_seller_subscriptions LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"Projection tables missing -- run `alembic upgrade head`: {exc}")
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
        tenant = create_tenant(_unique(label), parent_id=parent_id)
        transition_tenant_status(tenant.id, TenantStatus.ACTIVE)
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def user(self, *grants: tuple[uuid.UUID, tuple[str, str]]) -> uuid.UUID:
        user = create_user()
        self.user_ids.append(user.id)
        for tenant_id, permission in grants:
            membership = get_membership(tenant_id, user.id)
            if membership is None:
                membership = add_tenant_membership(tenant_id, user.id, caller=_PROVISIONING)
            role = create_role(tenant_id, _unique("role"), caller=_PROVISIONING)
            grant_permission(
                tenant_id, role.id, register_permission(*permission).id, caller=_PROVISIONING
            )
            assign_first_role_for_new_tenant(
                tenant_id, membership.id, role.id, scope=RoleScope.SELF, caller=_PROVISIONING
            )
        return user.id

    def support_engineer(self, tenant_id: uuid.UUID) -> uuid.UUID:
        approver = self.user((tenant_id, ("support_access_request", "approve")))
        engineer = self.user()
        request = create_support_access_request(
            caller=UserCaller(engineer),
            tenant_id=tenant_id,
            reason="step 4 boundary",
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
                    "DELETE FROM core.membership_roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.role_permissions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_memberships WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.roles WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) "
                    "OR ancestor_id = ANY(:t)",
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
        self.provider = FakeBillingProvider()
        self.agency_a, self.agency_b = world.tenant("agency-a"), world.tenant("agency-b")
        self.client_b = world.tenant("client-b", parent_id=self.agency_a)
        self.client_c = world.tenant("client-c", parent_id=self.agency_a)
        self.client_d = world.tenant("client-d", parent_id=self.agency_b)
        self.m_a, self.m_b = self._merchant(self.agency_a), self._merchant(self.agency_b)
        self.plan_a = self._plan(self.agency_a, self.m_a)
        self.plan_b = self._plan(self.agency_b, self.m_b)
        self.acct_client_b = self._account(self.client_b, self.agency_a, self.m_a)
        self.acct_agency_a = self._account(self.agency_a, self.agency_a, self.m_a)
        self.acct_client_d = self._account(self.client_d, self.agency_b, self.m_b)
        self.sub_b = self.create(self.client_b, self.client_b, self.acct_client_b, self.plan_a)
        self.sub_c = self.create(self.client_c, self.agency_a, self.acct_agency_a, self.plan_a)
        self.sub_d = self.create(self.client_d, self.client_d, self.acct_client_d, self.plan_b)

    def _merchant(self, owner: uuid.UUID) -> uuid.UUID:
        return create_merchant_account(
            _BILLING_SYSTEM,
            owner,
            provider="fake",
            provider_account_ref=_unique("acct"),
            status=MerchantAccountStatus.ACTIVE,
        ).id

    def _plan(self, owner: uuid.UUID, merchant: uuid.UUID) -> uuid.UUID:
        return create_owned_plan(
            _BILLING_SYSTEM,
            owner,
            merchant_account_id=merchant,
            key=_unique("plan"),
            name="Projected plan",
            entitlements={"seats": 3},
        ).id

    def _account(self, payer: uuid.UUID, owner: uuid.UUID, merchant: uuid.UUID) -> uuid.UUID:
        account, _ = get_or_create_billing_account(
            _BILLING_SYSTEM, payer, merchant_tenant_id=owner, merchant_account_id=merchant
        )
        return account.id

    def create(
        self, service: uuid.UUID, payer: uuid.UUID, account: uuid.UUID, plan: uuid.UUID
    ) -> uuid.UUID:
        _, result = create_subscription(
            _BILLING_SYSTEM,
            service_tenant_id=service,
            payer_tenant_id=payer,
            billing_account_id=account,
            plan_id=plan,
            idempotency_key=_unique("idem"),
            provider=self.provider,
        )
        return result.subscription_id

    @property
    def tenants(self) -> list[uuid.UUID]:
        return [self.agency_a, self.agency_b, self.client_b, self.client_c, self.client_d]


@pytest.fixture
def market(world: _World) -> _Market:
    return _Market(world)


# --- Delivery helpers -----------------------------------------------------------------


def _events(tenant_id: uuid.UUID, status: str | None = None) -> list:  # type: ignore[type-arg]
    sql = (
        "SELECT id, payload, status FROM core.outbox_events WHERE tenant_id = :t "
        "AND event_type = :e"
    )
    if status is not None:
        sql += " AND status = :s"
    return _admin(
        sql + " ORDER BY created_at, id",
        t=str(tenant_id),
        e=SUBSCRIPTION_CHANGED_EVENT_TYPE,
        s=status,
    )


def _run(tenant_id: uuid.UUID, event_id: uuid.UUID | None, payload: dict[str, object]) -> None:
    asyncio.run(
        projections._project_subscription_job(
            TenantJobContext(tenant_id=tenant_id, event_id=event_id),
            TenantJobPayload(tenant_id=str(tenant_id), data=dict(payload)),
        )
    )


def _deliver(market: _Market) -> None:
    """Run every pending projection event of the market's tenants through
    the consumer, oldest first, as the dispatcher would."""
    for tenant in market.tenants:
        for event_id, payload, _ in _events(tenant, OUTBOX_STATUS_PENDING):
            _run(tenant, event_id, payload)


def _seller(owner: uuid.UUID) -> dict[uuid.UUID, tuple]:  # type: ignore[type-arg]
    with tenant_session_scope(owner) as session:
        return {
            row.subscription_id: (row.status, row.source_version, row.projected_at)
            for row in session.query(SellerSubscription).all()
        }


def _payer(owner: uuid.UUID) -> dict[uuid.UUID, tuple]:  # type: ignore[type-arg]
    with tenant_session_scope(owner) as session:
        return {
            row.subscription_id: (row.status, row.source_version, row.projected_at)
            for row in session.query(PayerSubscription).all()
        }


# --- The transactional outbox --------------------------------------------------------


def test_each_canonical_change_commits_one_event_with_its_version(market: _Market) -> None:
    # Creation inserts version 1 (pending) and the provider confirmation moves
    # it to version 2 (active): two events, each naming its own version.
    payloads = [payload for _, payload, _ in _events(market.client_b)]
    assert payloads == [
        {"subscription_id": str(market.sub_b), "version": 1},
        {"subscription_id": str(market.sub_b), "version": 2},
    ]
    row = get_subscription(market.client_b, market.sub_b)
    assert (row.version, row.status) == (2, "active")
    # The payer-paid subscription's events live in the SERVICE tenant.
    assert len(_events(market.client_c)) == 2 and _events(market.agency_a) == []


def test_a_rolled_back_change_leaves_neither_row_nor_event(
    market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_after_announce(*_: object, **__: object) -> None:
        raise RuntimeError("simulated failure after the event was appended")

    monkeypatch.setattr(commercial, "record_billing_audit", fail_after_announce)
    before = len(_events(market.client_b))
    with pytest.raises(RuntimeError):
        cancel_commercial_subscription(
            _BILLING_SYSTEM,
            service_tenant_id=market.client_b,
            subscription_id=market.sub_b,
            provider=market.provider,
        )
    row = get_subscription(market.client_b, market.sub_b)
    assert (row.status, row.version) == ("active", 2)
    assert len(_events(market.client_b)) == before


def test_a_legacy_subscription_without_a_payer_announces_nothing(world: _World) -> None:
    tenant = world.tenant("legacy")
    key = _unique("legacy")
    world.legacy_keys.append(key)
    create_plan(key, "Legacy")
    subscription = subscribe(tenant, key, provider=FakeBillingProvider())
    assert _events(tenant) == []
    cancel_subscription(tenant, subscription.id, provider=FakeBillingProvider())
    assert get_subscription(tenant, subscription.id).version == 2  # versioned, not projected
    assert _events(tenant) == []


def test_the_real_dispatcher_runs_the_projection_consumer(
    market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert SUBSCRIPTION_CHANGED_EVENT_TYPE in outbox_dispatcher.outbox_event_handlers()
    monkeypatch.setattr(outbox_dispatch, "list_open_tenant_ids", lambda: market.tenants)
    for _ in range(3):  # per-tenant claim limits: drain in rounds
        for claim in claim_due_events(config=_CONFIG):
            asyncio.run(
                outbox_dispatcher._run_outbox_event(
                    TenantJobContext(tenant_id=claim.tenant_id),
                    TenantJobPayload(
                        tenant_id=str(claim.tenant_id),
                        data={
                            "outbox_event_id": str(claim.id),
                            "claim_token": str(claim.claim_token),
                        },
                    ),
                )
            )
    for tenant in market.tenants:
        assert {status for _, _, status in _events(tenant)} <= {OUTBOX_STATUS_PUBLISHED}
    assert set(_seller(market.agency_a)) == {market.sub_b, market.sub_c}
    assert set(_payer(market.agency_a)) == {market.sub_c}


# --- Seller / payer / service-tenant isolation --------------------------------------


def test_each_side_sees_exactly_its_own_relationships(world: _World, market: _Market) -> None:
    _deliver(market)
    seller_a = UserCaller(world.user((market.agency_a, _MERCHANT_MANAGE)))
    seller_b = UserCaller(world.user((market.agency_b, _MERCHANT_MANAGE)))
    payer_a = UserCaller(world.user((market.agency_a, _ACCOUNT_READ)))
    payer_b = UserCaller(world.user((market.client_b, _ACCOUNT_READ)))

    sold_by_a = list_seller_subscriptions(seller_a, market.agency_a)
    assert {v.subscription_id for v in sold_by_a} == {market.sub_b, market.sub_c}
    assert {v.subscription_id for v in list_seller_subscriptions(seller_b, market.agency_b)} == {
        market.sub_d
    }
    assert {v.subscription_id for v in list_payer_subscriptions(payer_a, market.agency_a)} == {
        market.sub_c
    }
    assert {v.subscription_id for v in list_payer_subscriptions(payer_b, market.client_b)} == {
        market.sub_b
    }
    # A merchant cannot reach another merchant's sale, or a payer another
    # payer's, by naming its id: not found in its own view.
    with pytest.raises(SubscriptionProjectionNotFoundError):
        get_seller_subscription(seller_a, market.agency_a, market.sub_d)
    with pytest.raises(SubscriptionProjectionNotFoundError):
        get_payer_subscription(payer_a, market.agency_a, market.sub_b)
    # Nor by naming the other tenant: no authority there.
    with pytest.raises(BillingNotAuthorizedError):
        list_seller_subscriptions(seller_a, market.agency_b)
    with pytest.raises(BillingNotAuthorizedError):
        list_payer_subscriptions(payer_a, market.client_b)


def test_views_carry_the_canonical_parties_and_no_provider_data(
    world: _World, market: _Market
) -> None:
    _deliver(market)
    seller = list_seller_subscriptions(
        UserCaller(world.user((market.agency_a, _MERCHANT_MANAGE))),
        market.agency_a,
        merchant_account_id=market.m_a,
        status="active",
    )
    view = next(v for v in seller if v.subscription_id == market.sub_c)
    canonical = get_subscription(market.client_c, market.sub_c)
    assert (
        view.merchant_tenant_id,
        view.merchant_account_id,
        view.service_tenant_id,
        view.payer_tenant_id,
        view.plan_id,
        view.status,
        view.source_version,
    ) == (
        market.agency_a,
        market.m_a,
        market.client_c,
        market.agency_a,
        market.plan_a,
        canonical.status,
        canonical.version,
    )
    payer = get_payer_subscription(
        UserCaller(world.user((market.agency_a, _ACCOUNT_READ))), market.agency_a, market.sub_c
    )
    assert (payer.billing_account_id, payer.merchant_tenant_id) == (
        market.acct_agency_a,
        market.agency_a,
    )
    for model in (SellerSubscription, PayerSubscription):
        columns = {c.name for c in model.__table__.columns}
        assert not {c for c in columns if "provider" in c or "customer" in c}


def test_the_service_tenant_gains_no_projection_access(world: _World, market: _Market) -> None:
    _deliver(market)
    # Client C is the service tenant of a subscription Agency A sells and pays
    # for: its own views are empty, and it has no authority in Agency A's.
    client_admin = UserCaller(
        world.user((market.client_c, _MERCHANT_MANAGE), (market.client_c, _ACCOUNT_READ))
    )
    assert list_seller_subscriptions(client_admin, market.client_c) == []
    assert list_payer_subscriptions(client_admin, market.client_c) == []
    for read in (list_seller_subscriptions, list_payer_subscriptions):
        with pytest.raises(BillingNotAuthorizedError):
            read(client_admin, market.agency_a)


def test_rls_alone_confines_projection_rows_to_their_owner(market: _Market) -> None:
    """The app role sees only the owner's rows, with no application filter;
    the privileged role shows the rows exist (the negative control)."""
    _deliver(market)
    for owner, seller_rows, payer_rows in (
        (market.agency_a, 2, 1),
        (market.client_b, 0, 1),
        (market.client_c, 0, 0),
        (market.agency_b, 1, 0),
    ):
        with tenant_session_scope(owner) as session:
            assert (
                session.execute(
                    text("SELECT count(*) FROM core.billing_seller_subscriptions")
                ).scalar_one(),
                session.execute(
                    text("SELECT count(*) FROM core.billing_payer_subscriptions")
                ).scalar_one(),
            ) == (seller_rows, payer_rows), owner
    total = _admin(
        "SELECT count(*) FROM core.billing_seller_subscriptions WHERE subscription_id = ANY(:s)",
        s=[str(market.sub_b), str(market.sub_c), str(market.sub_d)],
    )[0][0]
    assert total == 3


def test_support_reads_the_payer_view_but_never_the_seller_view(
    world: _World, market: _Market
) -> None:
    _deliver(market)
    engineer = UserCaller(world.support_engineer(market.agency_a))
    assert {v.subscription_id for v in list_payer_subscriptions(engineer, market.agency_a)} == {
        market.sub_c
    }
    with pytest.raises(BillingNotAuthorizedError):
        list_seller_subscriptions(engineer, market.agency_a)
    with pytest.raises(BillingNotAuthorizedError):
        cancel_commercial_subscription(
            engineer,
            service_tenant_id=market.client_c,
            subscription_id=market.sub_c,
            provider=market.provider,
        )


# --- Idempotency, versions, ordering --------------------------------------------------


def test_a_duplicate_delivery_is_suppressed(market: _Market) -> None:
    event_id, payload, _ = _events(market.client_b)[-1]
    _run(market.client_b, event_id, payload)
    first = _seller(market.agency_a)[market.sub_b]
    _run(market.client_b, event_id, payload)  # the same event again
    assert _seller(market.agency_a)[market.sub_b] == first
    assert (
        _admin(
            "SELECT count(*) FROM core.outbox_consumptions WHERE tenant_id = :t AND event_id = :e",
            t=str(market.client_b),
            e=str(event_id),
        )[0][0]
        == 1
    )


def test_an_older_event_after_a_newer_one_changes_nothing(market: _Market) -> None:
    (old_id, old_payload, _), (new_id, new_payload, _) = _events(market.client_b)
    _run(market.client_b, new_id, new_payload)
    newest = _seller(market.agency_a)[market.sub_b]
    assert newest[:2] == ("active", 2)
    _run(market.client_b, old_id, old_payload)  # late, older delivery
    assert _seller(market.agency_a)[market.sub_b] == newest
    assert _payer(market.client_b)[market.sub_b][:2] == ("active", 2)


def test_the_version_fence_applies_only_newer_canonical_versions(market: _Market) -> None:
    project_subscription(market.client_b, market.sub_b)
    snapshot = projections._canonical_snapshot(market.client_b, market.sub_b)
    assert snapshot is not None
    owner = snapshot.merchant_tenant_id
    values: dict[str, object] = {"payer_tenant_id": snapshot.payer_tenant_id}
    from dataclasses import replace

    for version, expected in ((snapshot.version, "stale"), (snapshot.version - 1, "stale")):
        outcome = projections._apply_projection(
            SellerSubscription, owner, replace(snapshot, version=version, status="canceled"), values
        )
        assert outcome == expected
    assert _seller(owner)[market.sub_b][:2] == ("active", 2)
    outcome = projections._apply_projection(
        SellerSubscription, owner, replace(snapshot, version=snapshot.version + 1), values
    )
    assert outcome == "updated" and _seller(owner)[market.sub_b][1] == snapshot.version + 1


def test_a_crash_between_the_two_projections_converges_on_retry(
    market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_id, payload, _ = _events(market.client_c)[-1]
    real = projections._apply_projection
    calls = {"payer": 0}

    def crash_on_payer(model, *args, **kwargs):  # type: ignore[no-untyped-def]
        if model is PayerSubscription and calls["payer"] == 0:
            calls["payer"] += 1
            raise RuntimeError("simulated crash after the seller projection")
        return real(model, *args, **kwargs)

    monkeypatch.setattr(projections, "_apply_projection", crash_on_payer)
    with pytest.raises(RuntimeError):
        _run(market.client_c, event_id, payload)
    assert market.sub_c in _seller(market.agency_a)
    assert market.sub_c not in _payer(market.agency_a)
    _run(market.client_c, event_id, payload)  # not recorded: it runs again
    assert _payer(market.agency_a)[market.sub_c][:2] == ("active", 2)
    assert _seller(market.agency_a)[market.sub_c][:2] == ("active", 2)


def test_concurrent_processing_yields_one_row_per_side(market: _Market) -> None:
    errors: list[BaseException] = []
    barrier = threading.Barrier(4)

    def _project() -> None:
        try:
            barrier.wait(10)
            project_subscription(market.client_c, market.sub_c)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_project) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert errors == []
    rows = _admin(
        "SELECT 'seller', count(*) FROM core.billing_seller_subscriptions "
        "WHERE subscription_id = :s "
        "UNION ALL SELECT 'payer', count(*) FROM core.billing_payer_subscriptions "
        "WHERE subscription_id = :s",
        s=str(market.sub_c),
    )
    assert {kind: count for kind, count in rows} == {"seller": 1, "payer": 1}


# --- Malformed and cross-tenant events ----------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"version": 1},
        {"subscription_id": "not-a-uuid", "version": 1},
        {"subscription_id": str(uuid.uuid4()), "version": 0},
        {"subscription_id": str(uuid.uuid4()), "version": "1"},
        {"subscription_id": str(uuid.uuid4()), "version": True},
    ],
)
def test_malformed_events_are_permanent_failures(market: _Market, payload: dict) -> None:  # type: ignore[type-arg]
    with pytest.raises(MalformedProjectionEventError) as excinfo:
        _run(market.client_b, uuid.uuid4(), payload)
    assert isinstance(excinfo.value, PermanentEventError)


def test_an_event_cannot_project_another_tenants_subscription(market: _Market) -> None:
    """An event recorded in Client B's outbox naming Client D's subscription
    (a forged or misrouted event) is refused: the consumer looks the
    subscription up only under the event's own tenant."""
    with tenant_session_scope(market.client_b) as session:
        forged = append_event(
            session,
            tenant_id=market.client_b,
            event_type=SUBSCRIPTION_CHANGED_EVENT_TYPE,
            aggregate_type="billing_subscription",
            aggregate_id=str(market.sub_d),
            payload={"subscription_id": str(market.sub_d), "version": 2},
        )
    with pytest.raises(MalformedProjectionEventError):
        _run(market.client_b, forged, {"subscription_id": str(market.sub_d), "version": 2})
    assert market.sub_d not in _seller(market.agency_b)
    assert market.sub_d not in _seller(market.agency_a)


def test_an_event_ahead_of_its_canonical_row_is_retried(market: _Market) -> None:
    with pytest.raises(ProjectionNotReadyError):
        _run(market.client_b, uuid.uuid4(), {"subscription_id": str(market.sub_b), "version": 99})
    assert market.sub_b not in _seller(market.agency_a)


# --- Lifecycle changes reach the projections ----------------------------------------


def test_cancellation_and_reconciliation_are_projected(world: _World, market: _Market) -> None:
    _deliver(market)
    cancel_commercial_subscription(
        _BILLING_SYSTEM,
        service_tenant_id=market.client_c,
        subscription_id=market.sub_c,
        provider=market.provider,
    )
    _deliver(market)
    assert _seller(market.agency_a)[market.sub_c][:2] == ("canceled", 3)
    assert _payer(market.agency_a)[market.sub_c][:2] == ("canceled", 3)

    market.provider.initial_state = ProviderSubscriptionState.PENDING
    account_at_b = market._account(market.client_b, market.agency_b, market.m_b)
    pending = market.create(market.client_b, market.client_b, account_at_b, market.plan_b)
    _deliver(market)
    assert _seller(market.agency_b)[pending][:2] == ("pending", 1)
    row = get_subscription(market.client_b, pending)
    market.provider.set_state(row.provider_subscription_id, ProviderSubscriptionState.ACTIVE)
    reconcile_subscription_status(
        _BILLING_SYSTEM,
        service_tenant_id=market.client_b,
        subscription_id=pending,
        provider=market.provider,
    )
    _deliver(market)
    assert _seller(market.agency_b)[pending][:2] == ("active", 2)


def test_a_legacy_cancel_cannot_touch_a_commercial_subscription_or_its_projection(
    market: _Market,
) -> None:
    """Phase 5.3 step 7: the unauthorized legacy cancel refuses a commercial
    row, so it can neither change the subscription nor its projections."""
    from core.billing.errors import LegacyBillingPathError

    _deliver(market)
    before = _seller(market.agency_a)[market.sub_b]
    with pytest.raises(LegacyBillingPathError):
        cancel_subscription(market.client_b, market.sub_b, provider=market.provider)
    _deliver(market)
    assert _seller(market.agency_a)[market.sub_b] == before
    assert get_subscription(market.client_b, market.sub_b).status == "active"


def test_a_failed_projection_leaves_the_subscription_and_the_event_intact(
    market: _Market, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(outbox_dispatch, "list_open_tenant_ids", lambda: [market.client_b])

    def broken(*_: object, **__: object) -> bool:
        raise RuntimeError("projection store unavailable")

    monkeypatch.setattr(projections, "project_subscription", broken)
    for claim in claim_due_events(config=_CONFIG):
        asyncio.run(
            outbox_dispatcher._run_outbox_event(
                TenantJobContext(tenant_id=claim.tenant_id),
                TenantJobPayload(
                    tenant_id=str(claim.tenant_id),
                    data={"outbox_event_id": str(claim.id), "claim_token": str(claim.claim_token)},
                ),
            )
        )
    assert {status for _, _, status in _events(market.client_b)} == {OUTBOX_STATUS_PENDING}
    row = get_subscription(market.client_b, market.sub_b)
    assert (row.status, row.version) == ("active", 2)
    assert market.sub_b not in _seller(market.agency_a)
