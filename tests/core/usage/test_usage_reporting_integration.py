"""Phase 5.3 step 6 -- usage reporting against a real PostgreSQL instance.

Shape (generic tenants):

    Agency A (merchant mA; plan X: api_calls 100, reports)
      +-- Client C   two live subscriptions: X (Agency A pays) and Y (C pays)
      |     +-- Grandchild G
      +-- Client B   X, paying itself
    Agency B (merchant mB; plan Y: api_calls 250, exports)

Pins: usage is reported for the tenant that owns it and nothing else; the
`[since, until)` window and exact Decimal sums; descendant-inclusive
totals are reports, never pools; several live subscriptions are all shown,
none chosen, and the enforced limit is their combination (MAX, never a
sum); payer and merchant views follow the canonical relationship and the
plan's metrics only; every view is authorized; reporting writes nothing.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from lifecycle_callers import platform_operator
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.billing.catalog import PlanVisibility, create_owned_plan
from saas_os.core.billing.commercial import create_subscription
from saas_os.core.billing.errors import BillingNotAuthorizedError
from saas_os.core.billing.parties import (
    MerchantAccountStatus,
    create_merchant_account,
    get_or_create_billing_account,
)
from saas_os.core.billing.provider import FakeBillingProvider
from saas_os.core.billing.service import get_entitlements
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
from saas_os.core.usage.errors import InvalidUsageEventError
from saas_os.core.usage.models import UsageEvent
from saas_os.core.usage.reporting import (
    merchant_subscription_usage,
    payer_subscription_usage,
    service_tenant_usage_report,
)
from saas_os.core.usage.service import check_quota
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import build_session_factory, session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

_PROVISIONING = SystemCaller(SystemAuthority.PROVISIONING)
_BILLING_SYSTEM = SystemCaller(SystemAuthority.BILLING_OPERATIONS)
_READ = ("billing.subscription", "read")
_ACCOUNT_READ = ("billing.account", "read")
_MERCHANT = ("billing.merchant", "manage")
_SINCE = datetime(2026, 6, 1, tzinfo=UTC)
_UNTIL = datetime(2026, 7, 1, tzinfo=UTC)


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
            conn.execute(text("SELECT 1 FROM core.billing_plan_offers LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable or not at head: {exc}")
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

    def tenant(self, label: str, *, parent_id: uuid.UUID | None = None) -> uuid.UUID:
        tenant = create_tenant(_unique(label), parent_id=parent_id, caller=platform_operator())
        transition_tenant_status(tenant.id, TenantStatus.ACTIVE, caller=platform_operator())
        self.tenant_ids.append(tenant.id)
        return tenant.id

    def user(
        self, *grants: tuple[uuid.UUID, tuple[str, str]], scope: RoleScope = RoleScope.SELF
    ) -> UserCaller:
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
                tenant_id, membership.id, role.id, scope=scope, caller=_PROVISIONING
            )
        return UserCaller(user.id)

    def support_engineer(self, tenant_id: uuid.UUID) -> UserCaller:
        engineer = create_user()
        self.user_ids.append(engineer.id)
        approver = self.user((tenant_id, ("support_access_request", "approve")))
        request = create_support_access_request(
            caller=UserCaller(engineer.id),
            tenant_id=tenant_id,
            reason="step 6 boundary",
            requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        approve_support_access(caller=approver, tenant_id=tenant_id, request_id=request.id)
        return UserCaller(engineer.id)

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
                    "DELETE FROM core.usage_events WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.outbox_consumptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.outbox_events WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_seller_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_payer_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.idempotency_records WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_provider_refs WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_subscriptions WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plan_offers WHERE tenant_id = ANY(:t)",
                    "DELETE FROM core.billing_plans WHERE owner_tenant_id = ANY(:t)",
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
                    session.execute(text(statement), {"t": tenants, "u": users})
        finally:
            engine.dispose()


@pytest.fixture
def world() -> Iterator[_World]:
    w = _World()
    try:
        yield w
    finally:
        w.cleanup()


def _usage(tenant_id: uuid.UUID, metric: str, quantity: str, at: datetime) -> None:
    with tenant_session_scope(tenant_id) as session:
        session.add(
            UsageEvent(
                tenant_id=tenant_id, metric=metric, quantity=Decimal(quantity), occurred_at=at
            )
        )


class _Market:
    def __init__(self, world: _World) -> None:
        self.provider = FakeBillingProvider()
        self.agency_a, self.agency_b = world.tenant("agency-a"), world.tenant("agency-b")
        self.client_c = world.tenant("client-c", parent_id=self.agency_a)
        self.client_b = world.tenant("client-b", parent_id=self.agency_a)
        self.grandchild = world.tenant("grandchild", parent_id=self.client_c)
        self.m_a = self._merchant(self.agency_a)
        self.m_b = self._merchant(self.agency_b)
        self.plan_x = self._plan(
            self.agency_a, self.m_a, {"api_calls": 100, "reports": True}, PlanVisibility.DESCENDANTS
        )
        self.plan_y = self._plan(
            self.agency_b, self.m_b, {"api_calls": 250, "exports": True}, PlanVisibility.PUBLIC
        )
        acct_a = self._account(self.agency_a, self.agency_a, self.m_a)
        acct_c_at_b = self._account(self.client_c, self.agency_b, self.m_b)
        acct_b = self._account(self.client_b, self.agency_a, self.m_a)
        self.sub_cx = self._create(self.client_c, self.agency_a, acct_a, self.plan_x)
        self.sub_cy = self._create(self.client_c, self.client_c, acct_c_at_b, self.plan_y)
        self.sub_bx = self._create(self.client_b, self.client_b, acct_b, self.plan_x)

    def _merchant(self, owner: uuid.UUID) -> uuid.UUID:
        return create_merchant_account(
            _BILLING_SYSTEM,
            owner,
            provider="fake",
            provider_account_ref=_unique("acct"),
            status=MerchantAccountStatus.ACTIVE,
        ).id

    def _plan(self, owner, merchant, entitlements, visibility):  # type: ignore[no-untyped-def]
        return create_owned_plan(
            _BILLING_SYSTEM,
            owner,
            merchant_account_id=merchant,
            key=_unique("plan"),
            name="Reported plan",
            entitlements=entitlements,
            visibility=visibility,
        ).id

    def _account(self, payer, owner, merchant):  # type: ignore[no-untyped-def]
        account, _ = get_or_create_billing_account(
            _BILLING_SYSTEM, payer, merchant_tenant_id=owner, merchant_account_id=merchant
        )
        return account.id

    def _create(self, service, payer, account, plan):  # type: ignore[no-untyped-def]
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


@pytest.fixture
def market(world: _World) -> _Market:
    m = _Market(world)
    for tenant, metric, quantity in (
        (m.client_c, "api_calls", "40.1"),
        (m.client_c, "api_calls", "19.9"),
        (m.client_c, "storage_gb", "0.000000000000000001"),
        (m.client_c, "exports_run", "3"),
        (m.agency_a, "api_calls", "1000"),
        (m.grandchild, "api_calls", "7"),
        (m.client_b, "api_calls", "11"),
    ):
        _usage(tenant, metric, quantity, _SINCE + timedelta(days=3))
    return m


def _report(caller: object, tenant: uuid.UUID, **kwargs: object):  # type: ignore[no-untyped-def]
    return service_tenant_usage_report(caller, tenant, since=_SINCE, until=_UNTIL, **kwargs)  # type: ignore[arg-type]


def _line(report, metric: str):  # type: ignore[no-untyped-def]
    return next(line for line in report.metrics if line.metric == metric)


# --- Direct service-tenant usage -------------------------------------------------------


def test_a_tenant_report_reads_only_its_own_usage_exactly(world: _World, market: _Market) -> None:
    report = _report(world.user((market.client_c, _READ)), market.client_c)
    assert report.scope == "direct"
    assert set(report.per_tenant) == {market.client_c}
    used = {line.metric: line.used for line in report.metrics}
    # Exact Decimal sums; the parent's 1000, the grandchild's 7 and the
    # sibling's 11 are not here.
    assert used["api_calls"] == Decimal("60.0")
    assert used["storage_gb"] == Decimal("0.000000000000000001")
    assert used["exports_run"] == Decimal("3")
    assert all(isinstance(line.used, Decimal) for line in report.metrics)


def test_the_window_is_half_open_and_utc(world: _World, market: _Market) -> None:
    caller = world.user((market.client_c, _READ))
    since = datetime(2026, 8, 1, tzinfo=UTC)
    until = datetime(2026, 8, 2, tzinfo=UTC)
    _usage(market.client_c, "edge", "1", since)  # at `since`: included
    _usage(market.client_c, "edge", "10", until)  # at `until`: excluded
    report = service_tenant_usage_report(caller, market.client_c, since=since, until=until)
    assert _line(report, "edge").used == Decimal("1")
    empty = service_tenant_usage_report(
        caller, market.client_c, since=until + timedelta(hours=1), until=until + timedelta(hours=2)
    )
    assert "edge" not in {line.metric for line in empty.metrics}
    assert _line(empty, "api_calls").used == Decimal("0")  # limit metrics still shown
    for bad in (
        {"since": datetime(2026, 8, 1), "until": datetime(2026, 8, 2)},
        {"since": until, "until": since},
        {"since": since, "until": None},
    ):
        with pytest.raises(InvalidUsageEventError):
            service_tenant_usage_report(caller, market.client_c, **bad)  # type: ignore[arg-type]


# --- Hierarchy reporting --------------------------------------------------------------


def test_descendant_inclusive_totals_are_reports_not_pools(world: _World, market: _Market) -> None:
    caller = world.user((market.client_c, _READ), scope=RoleScope.SUBTREE)
    report = _report(caller, market.client_c, include_descendants=True)
    assert report.scope == "descendants"
    assert set(report.per_tenant) == {market.client_c, market.grandchild}
    assert report.per_tenant[market.grandchild] == {"api_calls": Decimal("7")}
    line = _line(report, "api_calls")
    assert line.used == Decimal("67.0")  # C's 60 + G's 7; never the parent's 1000
    assert (line.limit, line.remaining, line.over_limit) == (None, None, False)
    # Ownership and enforcement are untouched: C's quota counts only C.
    assert check_quota(market.client_c, "api_calls", since=_SINCE, until=_UNTIL).used == Decimal(
        "60.0"
    )
    owners = _admin(
        "SELECT DISTINCT tenant_id FROM core.usage_events "
        "WHERE tenant_id = ANY(:t) AND metric = 'api_calls'",
        t=[str(market.client_c), str(market.grandchild)],
    )
    assert {row[0] for row in owners} == {market.client_c, market.grandchild}


def test_descendant_reporting_needs_authority_over_every_included_tenant(
    world: _World, market: _Market
) -> None:
    only_c = world.user((market.client_c, _READ))  # SELF scope: not the grandchild
    assert _report(only_c, market.client_c).scope == "direct"
    with pytest.raises(BillingNotAuthorizedError):
        _report(only_c, market.client_c, include_descendants=True)


# --- Several live subscriptions -------------------------------------------------------


def test_every_live_subscription_is_shown_and_limits_combine_by_max(
    world: _World, market: _Market
) -> None:
    report = _report(world.user((market.client_c, _READ)), market.client_c)
    assert {s.subscription_id for s in report.subscriptions} == {market.sub_cx, market.sub_cy}
    assert {s.plan_id for s in report.subscriptions} == {market.plan_x, market.plan_y}
    assert report.effective_entitlements == {"api_calls": 250, "reports": True, "exports": True}
    assert report.effective_entitlements == get_entitlements(market.client_c)
    line = _line(report, "api_calls")
    assert line.limit == Decimal("250")  # MAX(100, 250) -- never 350
    assert line.remaining == Decimal("190.0")
    assert check_quota(market.client_c, "api_calls", since=_SINCE, until=_UNTIL).limit == Decimal(
        "250"
    )


@pytest.mark.parametrize(
    ("extra", "remaining", "over"),
    [("0", "190.0", False), ("190.0", "0.0", False), ("191", "-1.0", True)],
)
def test_usage_below_at_and_above_the_limit(
    world: _World, market: _Market, extra: str, remaining: str, over: bool
) -> None:
    if extra != "0":
        _usage(market.client_c, "api_calls", extra, _SINCE + timedelta(days=5))
    caller = world.user((market.client_c, _READ))
    before = _admin(
        "SELECT count(*) FROM core.usage_events WHERE tenant_id = :t", t=str(market.client_c)
    )
    line = _line(_report(caller, market.client_c), "api_calls")
    assert (line.remaining, line.over_limit) == (Decimal(remaining), over)
    unlimited = _line(_report(caller, market.client_c), "storage_gb")
    assert (unlimited.limit, unlimited.remaining, unlimited.over_limit) == (None, None, False)
    after = _admin(
        "SELECT count(*) FROM core.usage_events WHERE tenant_id = :t", t=str(market.client_c)
    )
    assert before == after  # reading consumed nothing


# --- Payer and merchant views ---------------------------------------------------------


def test_the_payer_sees_only_the_subscription_it_pays_for(world: _World, market: _Market) -> None:
    payer_a = world.user((market.agency_a, _ACCOUNT_READ))
    report = payer_subscription_usage(
        payer_a,
        market.agency_a,
        service_tenant_id=market.client_c,
        subscription_id=market.sub_cx,
        since=_SINCE,
        until=_UNTIL,
    )
    # C still owns the usage; only plan X's metrics are visible.
    assert report.service_tenant_id == market.client_c
    assert report.usage == {"api_calls": Decimal("60.0"), "reports": Decimal("0")}
    for service, sub in (
        (market.client_c, market.sub_cy),  # C pays for Y itself
        (market.client_b, market.sub_bx),  # B pays for X itself
        (market.client_c, uuid.uuid4()),  # no such subscription: same refusal
    ):
        with pytest.raises(BillingNotAuthorizedError):
            payer_subscription_usage(
                payer_a,
                market.agency_a,
                service_tenant_id=service,
                subscription_id=sub,
                since=_SINCE,
                until=_UNTIL,
            )


def test_the_merchant_sees_only_what_it_sold(world: _World, market: _Market) -> None:
    seller_a = world.user((market.agency_a, _MERCHANT))
    seller_b = world.user((market.agency_b, _MERCHANT))
    sold_a = merchant_subscription_usage(
        seller_a,
        market.agency_a,
        service_tenant_id=market.client_c,
        subscription_id=market.sub_cx,
        since=_SINCE,
        until=_UNTIL,
    )
    assert set(sold_a.usage) == {"api_calls", "reports"}
    sold_b = merchant_subscription_usage(
        seller_b,
        market.agency_b,
        service_tenant_id=market.client_c,
        subscription_id=market.sub_cy,
        since=_SINCE,
        until=_UNTIL,
    )
    assert set(sold_b.usage) == {"api_calls", "exports"}
    for caller, merchant, sub in (
        (seller_a, market.agency_a, market.sub_cy),  # sold by B
        (seller_b, market.agency_b, market.sub_cx),  # sold by A
    ):
        with pytest.raises(BillingNotAuthorizedError):
            merchant_subscription_usage(
                caller,
                merchant,
                service_tenant_id=market.client_c,
                subscription_id=sub,
                since=_SINCE,
                until=_UNTIL,
            )


def test_hierarchy_never_substitutes_for_the_relationship(world: _World, market: _Market) -> None:
    """Agency A is Client C's ancestor and holds subtree-wide account-read
    and merchant authority -- still only the subscription it pays for and
    the one it sold are visible, never C's subscription at Agency B."""
    ancestor = world.user(
        (market.agency_a, _ACCOUNT_READ), (market.agency_a, _MERCHANT), scope=RoleScope.SUBTREE
    )
    for view in (payer_subscription_usage, merchant_subscription_usage):
        with pytest.raises(BillingNotAuthorizedError):
            view(
                ancestor,
                market.agency_a,
                service_tenant_id=market.client_c,
                subscription_id=market.sub_cy,
                since=_SINCE,
                until=_UNTIL,
            )


# --- Isolation and authority ------------------------------------------------------------


def test_unrelated_sibling_and_ancestor_readers_are_refused(world: _World, market: _Market) -> None:
    for caller in (
        world.user((market.agency_b, _READ)),  # unrelated tenant
        world.user((market.client_b, _READ)),  # sibling
        world.user((market.agency_a, _READ)),  # ancestor, SELF scope: no inferred authority
        _PROVISIONING,  # a system purpose other than billing operations
        world.user((market.client_c, ("billing.account", "read"))),  # wrong capability
    ):
        with pytest.raises(BillingNotAuthorizedError):
            _report(caller, market.client_c)
    assert _report(_BILLING_SYSTEM, market.client_c).tenant_id == market.client_c


def test_support_reads_follow_the_read_policy_and_stop_at_mutation_actions(
    world: _World, market: _Market
) -> None:
    engineer = world.support_engineer(market.client_c)
    # `billing.subscription:read` is a read: support access satisfies it.
    assert _report(engineer, market.client_c).tenant_id == market.client_c
    seller_engineer = world.support_engineer(market.agency_a)
    # `billing.merchant:manage` is a mutation action: never via support.
    with pytest.raises(BillingNotAuthorizedError):
        merchant_subscription_usage(
            seller_engineer,
            market.agency_a,
            service_tenant_id=market.client_c,
            subscription_id=market.sub_cx,
            since=_SINCE,
            until=_UNTIL,
        )


def test_reporting_writes_nothing(world: _World, market: _Market) -> None:
    caller = world.user((market.client_c, _READ), (market.agency_a, _ACCOUNT_READ))
    counts = (
        "SELECT (SELECT count(*) FROM core.audit_log WHERE tenant_id = ANY(:t)), "
        "(SELECT count(*) FROM core.outbox_events WHERE tenant_id = ANY(:t)), "
        "(SELECT count(*) FROM core.usage_events WHERE tenant_id = ANY(:t)), "
        "(SELECT coalesce(sum(version), 0) FROM core.billing_subscriptions "
        "WHERE tenant_id = ANY(:t))"
    )
    tenants = [str(market.client_c), str(market.agency_a)]
    before = _admin(counts, t=tenants)
    _report(caller, market.client_c)
    payer_subscription_usage(
        caller,
        market.agency_a,
        service_tenant_id=market.client_c,
        subscription_id=market.sub_cx,
        since=_SINCE,
        until=_UNTIL,
    )
    assert _admin(counts, t=tenants) == before
