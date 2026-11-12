"""The monthly AI usage rollup and the limits read against a real PostgreSQL
(ADR-0054 amendment of 2026-11-11; Gap 22b, stage 7).

Pinned: the governed path's own settlements land in the rollup, once each,
also under parallel requests; for a month with no attempt still `started`,
the monthly read equals the attempt-based report for that month, for every
grouping; it keeps counting after the attempt rows are deleted (the simulated
retention purge of Gap 22 criterion 11); months are whole UTC months, at
most 24, the default is the current month and the eleven before it, and
every month of the window is listed; the limits read returns the quota and
budget blocks alone. Both reads take the same authority as the attempt
report (`ai.usage:read`, a user only, not support access) and write one
`ai.usage.read` row naming the view; a refusal writes a `denied` row. Rows
are seeded directly or written by the governed path with FakeAdapter: no
provider, no network.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import AIWorld, Scene, admin_scalar, runtime
from lifecycle_callers import PROVISIONING
from saas_os.control_plane.inference import service
from saas_os.control_plane.inference.adapters import AdapterResult, AdapterUsage
from saas_os.control_plane.inference.tenant_usage import (
    AIMonthlyGroupBy,
    AIUsageGroupBy,
    AIUsageReadError,
    read_tenant_ai_limits,
    read_tenant_ai_monthly_usage,
    read_tenant_ai_usage,
)
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.core.authority import ServiceAccountCaller, UserCaller
from saas_os.core.identity.service import create_service_account
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import (
    assign_service_account_role,
    create_role,
    grant_permission,
    register_permission,
)
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

USAGE = ("ai.usage", "read")
OCT = datetime(2026, 10, 1, tzinfo=UTC)
NOV = datetime(2026, 11, 1, tzinfo=UTC)
DEC = datetime(2026, 12, 1, tzinfo=UTC)
_NO_LIMIT: Callable[[uuid.UUID], dict[str, object]] = lambda _t: {}  # noqa: E731


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


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
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM control_plane.ai_usage_monthly LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"AI tables missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch, platform_config_database: None) -> None:
    from saas_os.control_plane.inference.config import service as ai_config

    class _Secrets:
        def get(self, name: str) -> str | None:
            return "placeholder" if name.startswith("AI_TEST_") else None

    monkeypatch.setattr(ai_config, "get_secrets_provider", lambda: _Secrets())
    monkeypatch.setenv("AI_PROVIDER_CREDENTIALS", "AI_TEST_PROVIDER_KEY,AI_TEST_ROTATED")


@pytest.fixture
def world() -> Iterator[AIWorld]:
    w = AIWorld()
    try:
        yield w
    finally:
        w.cleanup()


def _admin(sql: str, **params: object) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(text(sql), params)
    finally:
        engine.dispose()


def _insert(
    tenant_id: uuid.UUID,
    *,
    at: datetime,
    provider: str = "p1",
    model: str = "m1",
    use_case: str = "uc-a",
    state: str = "succeeded",
    provenance: str = "provider_reported",
    tokens: tuple[int | None, int | None, int | None] = (10, 5, 1),
    cost: Decimal | None = Decimal("0.00100000"),
    currency: str | None = "USD",
) -> None:
    _admin(
        "INSERT INTO control_plane.ai_inference_attempts (id, tenant_id, request_id, "
        "attempt_number, actor_type, use_case, alias, provider_key, model_id, "
        "provider_config_version, model_config_version, effective_classification, decision, "
        "state, started_at, finished_at, input_tokens, output_tokens, cached_input_tokens, "
        "usage_provenance, estimated_cost, currency) VALUES (:i, :t, :r, 1, 'service_account', "
        ":uc, 'alias', :p, :m, 1, 1, 'tenant_data', CAST(:d AS json), CAST(:s AS varchar), "
        ":at, :fin, :in, :out, :c, :prov, :cost, :cur)",
        i=str(uuid.uuid4()),
        t=str(tenant_id),
        r=str(uuid.uuid4()),
        uc=use_case,
        p=provider,
        m=model,
        d=json.dumps({"sentinel": "DECISION-SENTINEL"}),
        s=state,
        at=at,
        fin=None if state == "started" else at,
        **{"in": tokens[0]},
        out=tokens[1],
        c=tokens[2],
        prov=provenance,
        cost=cost,
        cur=currency,
    )


def _seed_month(tenant_id: uuid.UUID, month: datetime) -> None:
    """Two providers, two models, two use cases, three states, every
    provenance, two currencies and unpriced attempts, across the month."""
    last = month.replace(day=28, hour=23, minute=59, second=59)
    _insert(tenant_id, at=month)
    _insert(tenant_id, at=month.replace(day=2), provenance="estimated", tokens=(3, 2, None))
    _insert(tenant_id, at=last, provider="p2", currency="EUR", cost=Decimal("0.5"))
    _insert(tenant_id, at=month.replace(day=5), model="m2", use_case="uc-b", state="failed",
            provenance="unknown", tokens=(None, None, None), cost=None, currency=None)  # fmt: skip
    _insert(tenant_id, at=month.replace(day=6), state="interrupted", cost=None, currency=None)


def _audit(tenant_id: uuid.UUID, outcome: str) -> list[dict[str, Any]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT metadata FROM core.audit_log WHERE tenant_id = :t "
                    "AND action = 'ai.usage.read' AND outcome = :o ORDER BY created_at"
                ),
                {"t": str(tenant_id), "o": outcome},
            ).scalars()
            return [dict(r) if isinstance(r, dict) else json.loads(r) for r in rows]
    finally:
        engine.dispose()


# --- the rollup equals the attempts --------------------------------------------------------


@pytest.mark.parametrize(
    "grouping", [g for g in AIMonthlyGroupBy if g is not AIMonthlyGroupBy.MONTH]
)
def test_a_month_of_the_rollup_equals_the_attempt_report_for_that_month(
    world: AIWorld, grouping: AIMonthlyGroupBy
) -> None:
    tenant_id = world.tenant()
    reader = world.member(tenant_id, USAGE)
    _seed_month(tenant_id, OCT)
    _seed_month(tenant_id, NOV)
    monthly = read_tenant_ai_monthly_usage(
        tenant_id, caller=reader, since=OCT, until=NOV, group_by=grouping
    )
    attempts = read_tenant_ai_usage(
        tenant_id,
        caller=reader,
        since=OCT,
        until=NOV,
        group_by=AIUsageGroupBy(grouping.value),
        entitlements=_NO_LIMIT,
    )
    assert monthly.totals == attempts.totals
    assert monthly.groups == attempts.groups
    assert monthly.totals.attempts == 5
    assert {c.currency: c.estimated for c in monthly.totals.cost} == {
        "USD": Decimal("0.002"),
        "EUR": Decimal("0.5"),
    }
    assert monthly.totals.cost_unknown_attempts == 2
    assert monthly.totals.usage_unknown_attempts == 1


def test_by_month_every_month_of_the_window_is_listed(world: AIWorld) -> None:
    tenant_id = world.tenant()
    reader = world.member(tenant_id, USAGE)
    _seed_month(tenant_id, OCT)
    report = read_tenant_ai_monthly_usage(
        tenant_id, caller=reader, since=datetime(2026, 9, 1, tzinfo=UTC), until=DEC
    )
    assert [g.key for g in report.groups] == ["2026-09", "2026-10", "2026-11"]
    assert [g.amounts.attempts for g in report.groups] == [0, 5, 0]
    assert report.basis == "monthly_rollup_of_finished_attempts"


def test_a_started_attempt_is_not_in_the_rollup_until_it_finishes(world: AIWorld) -> None:
    tenant_id = world.tenant()
    reader = world.member(tenant_id, USAGE)
    _insert(tenant_id, at=OCT, state="started", tokens=(None, None, None), cost=None,
            currency=None)  # fmt: skip
    assert (
        read_tenant_ai_monthly_usage(tenant_id, caller=reader, since=OCT, until=NOV).totals.attempts
        == 0
    )
    report = read_tenant_ai_usage(
        tenant_id, caller=reader, since=OCT, until=NOV, entitlements=_NO_LIMIT
    )
    assert report.totals.attempts == 1  # the attempt report counts it


def test_the_rollup_survives_the_deletion_of_the_attempts(world: AIWorld) -> None:
    tenant_id = world.tenant()
    reader = world.member(tenant_id, USAGE)
    _seed_month(tenant_id, OCT)
    before = read_tenant_ai_monthly_usage(tenant_id, caller=reader, since=OCT, until=NOV)
    _admin("DELETE FROM control_plane.ai_inference_attempts WHERE tenant_id = :t", t=str(tenant_id))
    after = read_tenant_ai_monthly_usage(tenant_id, caller=reader, since=OCT, until=NOV)
    assert after.totals == before.totals and after.totals.attempts == 5
    gone = read_tenant_ai_usage(
        tenant_id, caller=reader, since=OCT, until=NOV, entitlements=_NO_LIMIT
    )
    assert gone.totals.attempts == 0


def test_another_tenants_rollup_is_never_read(world: AIWorld) -> None:
    mine, theirs = world.tenant(), world.tenant()
    _seed_month(theirs, OCT)
    reader = world.member(mine, USAGE)
    own = read_tenant_ai_monthly_usage(mine, caller=reader, since=OCT, until=NOV)
    assert own.totals.attempts == 0
    with pytest.raises(AuthorityNotAuthorizedError):
        read_tenant_ai_monthly_usage(theirs, caller=reader, since=OCT, until=NOV)


# --- the governed path ---------------------------------------------------------------------


def _request(scene: Scene) -> InferenceRequest:
    return InferenceRequest(
        alias=scene.alias,
        use_case=scene.use_case.name,
        messages=(Message("user", (ContentPart("text", "tenant_data", text="hello"),)),),
        max_output_tokens=50,
    )


def _ok() -> AdapterResult:
    return AdapterResult(
        text="ok",
        finish_reason="stop",
        usage=AdapterUsage(input_tokens=5, output_tokens=7),
        model="model-1",
        provider_request_id="req-ok",
    )


async def test_the_governed_paths_settlements_land_once_each_also_in_parallel(
    world: AIWorld,
) -> None:
    scene = world.scene()
    reader = world.member(scene.tenant_id, USAGE)
    rt, _, _ = runtime([_ok() for _ in range(8)])
    await asyncio.gather(
        *(
            service.run_inference(
                scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
            )
            for _ in range(8)
        )
    )
    monthly = read_tenant_ai_monthly_usage(scene.tenant_id, caller=reader)
    attempts = read_tenant_ai_usage(scene.tenant_id, caller=reader, entitlements=_NO_LIMIT)
    assert monthly.totals.attempts == 8
    assert (monthly.totals.input_tokens, monthly.totals.output_tokens) == (40, 56)
    assert monthly.totals == attempts.totals
    rows = admin_scalar(
        "SELECT count(*) FROM control_plane.ai_usage_monthly WHERE tenant_id = :t",
        t=str(scene.tenant_id),
    )
    assert rows == 1  # one grain: one row, eight additions


# --- windows ---------------------------------------------------------------------------------


def test_windows_are_whole_utc_months_at_most_24_and_default_to_twelve(world: AIWorld) -> None:
    tenant_id = world.tenant()
    reader = world.member(tenant_id, USAGE)
    for kwargs in (
        {"since": OCT},
        {"until": NOV},
        {"since": OCT, "until": OCT},
        {"since": NOV, "until": OCT},
        {"since": OCT.replace(day=2), "until": NOV},
        {"since": OCT, "until": NOV.replace(hour=1)},
        {"since": datetime(2024, 10, 1, tzinfo=UTC), "until": datetime(2026, 10, 2, tzinfo=UTC)},
        {"since": datetime(2024, 9, 1, tzinfo=UTC), "until": OCT},  # 25 months
        {"since": datetime(2026, 10, 1), "until": NOV},  # noqa: DTZ001 -- naive
    ):
        with pytest.raises(AIUsageReadError) as caught:
            read_tenant_ai_monthly_usage(tenant_id, caller=reader, **kwargs)  # type: ignore[arg-type]
        assert caught.value.reason == "invalid_window"
    for bad in ("day", "tenant", "", None):
        with pytest.raises(AIUsageReadError) as caught:
            read_tenant_ai_monthly_usage(tenant_id, caller=reader, group_by=bad)  # type: ignore[arg-type]
        assert caught.value.reason == "invalid_group_by"
    widest = read_tenant_ai_monthly_usage(
        tenant_id, caller=reader, since=datetime(2024, 10, 1, tzinfo=UTC), until=OCT
    )
    assert len(widest.groups) == 24
    default = read_tenant_ai_monthly_usage(tenant_id, caller=reader)
    assert len(default.groups) == 12
    now = datetime.now(UTC)
    assert default.groups[-1].key == now.strftime("%Y-%m")
    assert default.until.day == 1 and default.until > now


# --- authority and evidence -----------------------------------------------------------------


def test_both_reads_take_the_same_authority_and_write_one_row_naming_the_view(
    world: AIWorld,
) -> None:
    tenant_id = world.tenant()
    reader = world.member(tenant_id, USAGE)
    billing = world.member(tenant_id, ("billing.subscription", "read"))
    for read in (
        lambda caller: read_tenant_ai_monthly_usage(tenant_id, caller=caller),
        lambda caller: read_tenant_ai_limits(tenant_id, caller=caller, entitlements=_NO_LIMIT),
    ):
        with pytest.raises(AuthorityNotAuthorizedError):
            read(billing)
        with pytest.raises(AuthorityNotAuthorizedError):
            read(ServiceAccountCaller(uuid.uuid4(), tenant_id))
        with pytest.raises(AuthorityNotAuthorizedError):
            read(UserCaller(world.user()))  # not a member
    assert len(_audit(tenant_id, "denied")) == 4  # each refusal that has a tenant row to attach to
    read_tenant_ai_monthly_usage(tenant_id, caller=reader, since=OCT, until=NOV)
    limits = read_tenant_ai_limits(tenant_id, caller=reader, entitlements=_NO_LIMIT)
    assert _audit(tenant_id, "success") == [
        {
            "view": "monthly",
            "since": OCT.isoformat(),
            "until": NOV.isoformat(),
            "group_by": "month",
        },
        {"view": "limits"},
    ]
    assert limits.quota.state == "unlimited"
    assert limits.budget.state == "unconfigured"
    assert limits.tenant_id == tenant_id


def test_a_service_account_holding_the_permission_is_still_refused(world: AIWorld) -> None:
    """Users only (owner decision 4): the check holds even where RBAC would
    allow the account."""
    tenant_id = world.tenant()
    admin = world.member(tenant_id, ("service_account_role", "create"), USAGE)
    account = create_service_account(tenant_id, f"svc-{uuid.uuid4().hex[:6]}", caller=PROVISIONING)
    role = create_role(tenant_id, f"svc-{uuid.uuid4().hex[:6]}", caller=PROVISIONING)
    grant_permission(tenant_id, role.id, register_permission(*USAGE).id, caller=PROVISIONING)
    assign_service_account_role(
        caller=admin, tenant_id=tenant_id, service_account_id=account.id, role_id=role.id
    )
    caller = ServiceAccountCaller(account.id, tenant_id)
    try:
        for read in (
            lambda: read_tenant_ai_usage(tenant_id, caller=caller, entitlements=_NO_LIMIT),
            lambda: read_tenant_ai_monthly_usage(tenant_id, caller=caller),
            lambda: read_tenant_ai_limits(tenant_id, caller=caller, entitlements=_NO_LIMIT),
        ):
            with pytest.raises(AuthorityNotAuthorizedError):
                read()
        assert _audit(tenant_id, "success") == []
    finally:
        params = {"a": str(account.id)}
        _admin("DELETE FROM core.audit_log WHERE actor_service_account_id = :a", **params)
        _admin("DELETE FROM core.service_account_roles WHERE service_account_id = :a", **params)
        _admin("DELETE FROM core.service_accounts WHERE id = :a", **params)
