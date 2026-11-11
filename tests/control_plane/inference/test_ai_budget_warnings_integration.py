"""Monetary AI budget warnings against a real PostgreSQL (ADR-0054 amendment
of 2026-11-11; Gap 21c, stage 6; Gap 21 acceptance criterion 11).

Pinned: each warning threshold is notified once per tenant and month, with
one webhook event per subscription and one audit row, in the transaction
that reaches it, without any amount; several thresholds reached at once are
each notified; a release and a second reach do not notify again; a
settlement above the reservation notifies; parallel admissions notify a
threshold once; the tenant's list replaces the plan's and an empty list turns
warnings off; a failed notification never fails the request and is retried;
a new month starts with nothing notified; the status reads `warning`;
malformed stored thresholds refuse like other unreadable budget data.
FakeAdapter only: no provider, no network, no cost.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import REASON, AIWorld, P, Scene, runtime
from saas_os.control_plane.inference import budget, budget_admin, service
from saas_os.control_plane.inference.adapters import (
    AdapterError,
    AdapterResult,
    AdapterUsage,
    ErrorCategory,
    FakeAdapter,
)
from saas_os.control_plane.inference.budget_admin import AIBudgetError
from saas_os.control_plane.inference.config import service as ai_config
from saas_os.control_plane.inference.errors import (
    InferenceInvalidRequestError,
    InferenceQuotaExceededError,
)
from saas_os.control_plane.inference.tenant_usage import read_tenant_ai_usage
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.core.authority import UserCaller
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_TEXT = "hello"  # 5 bytes
_MAX_OUTPUT = 100
# 5 x 3 + 100 x 15 per million: the worst case, and the cost of a reply of
# exactly `_MAX_OUTPUT` tokens.
_WORST = Decimal("0.00151500")
_EVENT = "ai.budget.threshold_crossed"


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
            conn.execute(text("SELECT 1 FROM control_plane.ai_budget_periods LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"budget tables missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch, platform_config_database: None) -> None:
    class _Secrets:
        def get(self, name: str) -> str | None:
            return "placeholder" if name.startswith("AI_TEST_") else None

    monkeypatch.setattr(ai_config, "get_secrets_provider", lambda: _Secrets())
    monkeypatch.setenv("AI_PROVIDER_CREDENTIALS", "AI_TEST_PROVIDER_KEY,AI_TEST_ROTATED")
    monkeypatch.delenv("AI_INFERENCE_BUDGET_REQUIRED", raising=False)
    monkeypatch.delenv("AI_PRICE_MAX_AGE_SECONDS", raising=False)


@pytest.fixture
def world() -> Iterator[AIWorld]:
    w = AIWorld()
    try:
        yield w
    finally:
        w.cleanup()


# --- helpers ------------------------------------------------------------------------------


def _warned(
    world: AIWorld, *, amount: Decimal, warn: list[int] | None, subscriptions: int = 1
) -> tuple[Scene, uuid.UUID]:
    """A scene with a fresh price, a plan budget of `amount` with the warning
    thresholds `warn`, and `subscriptions` webhook subscriptions."""
    scene = world.scene()
    target = scene.destinations[0]
    ai_config.set_model_price(
        provider_key=target.provider_key,
        model_id=target.model_id,
        pricing_version="v1",
        currency="USD",
        input_per_million=Decimal("3"),
        output_per_million=Decimal("15"),
        effective_from=datetime.now(UTC) - timedelta(days=40),
        caller=scene.operator,
        reason=REASON,
    )
    plan_id = world.plan()
    budget_admin.set_plan_budget(
        plan_id,
        budget_version="b1",
        currency="USD",
        monthly_amount=amount,
        effective_from=datetime.now(UTC) - timedelta(days=1),
        caller=world.operator(P.AI_BUDGET_MANAGE),
        reason=REASON,
        warn_thresholds=warn,
    )
    for index in range(subscriptions):
        _admin(
            "INSERT INTO core.webhook_subscriptions "
            "(id, tenant_id, url, signing_secret, created_at, updated_at) "
            "VALUES (:id, :t, :url, 'not-a-secret', now(), now())",
            id=str(uuid.uuid4()),
            t=str(scene.tenant_id),
            url=f"https://hooks.example.com/{index}",
        )
    return scene, plan_id


def _runtime(plan_id: uuid.UUID, script: list[Any] | None = None, **kwargs: Any) -> Any:
    rt, fake, gate = runtime(script, **kwargs)
    rt.budget_plans = lambda tenant_id: [plan_id]
    return rt, fake, gate


def _request(scene: Scene) -> InferenceRequest:
    return InferenceRequest(
        alias=scene.alias,
        use_case=scene.use_case.name,
        messages=(Message("user", (ContentPart("text", "tenant_data", text=_TEXT),)),),
        max_output_tokens=_MAX_OUTPUT,
    )


def _ok(output_tokens: int = _MAX_OUTPUT) -> AdapterResult:
    return AdapterResult(
        text="ok",
        finish_reason="stop",
        usage=AdapterUsage(input_tokens=5, output_tokens=output_tokens),
        model="model-1",
        provider_request_id="req-ok",
    )


def _rows(sql: str, **params: object) -> list[dict[str, Any]]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            return [dict(r) for r in conn.execute(text(sql), params).mappings()]
    finally:
        engine.dispose()


def _admin(sql: str, **params: object) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(text(sql), params)
    finally:
        engine.dispose()


def _events(tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    """The webhook deliveries of threshold warnings, oldest first."""
    return [
        r["payload"]
        for r in _rows(
            "SELECT payload FROM core.outbox_events WHERE tenant_id = :t "
            "AND event_type = 'webhook.delivery' AND payload->>'event_type' = :e "
            "ORDER BY created_at, (payload->'event_data'->>'threshold_percent')::int, "
            "aggregate_id",
            t=str(tenant_id),
            e=_EVENT,
        )
    ]


def _audits(tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    return _rows(
        "SELECT actor_user_id, outcome, metadata FROM core.audit_log WHERE tenant_id = :t "
        "AND action = :e ORDER BY created_at, (metadata->>'threshold_percent')::int",
        t=str(tenant_id),
        e=_EVENT,
    )


def _notified(tenant_id: uuid.UUID) -> list[int | None]:
    return [
        r["last_threshold_notified"]
        for r in _rows(
            "SELECT last_threshold_notified FROM control_plane.ai_budget_periods "
            "WHERE tenant_id = :t ORDER BY period_start",
            t=str(tenant_id),
        )
    ]


async def _run(scene: Scene, rt: Any) -> None:
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )


def _thresholds_of(rows: list[dict[str, Any]]) -> list[int]:
    return [int(r["event_data"]["threshold_percent"]) for r in rows]


# --- notification -------------------------------------------------------------------------


async def test_a_threshold_is_notified_once_per_subscription_with_an_audit_row_and_no_amount(
    world: AIWorld,
) -> None:
    scene, plan_id = _warned(world, amount=_WORST * 2, warn=[50, 90], subscriptions=2)
    rt, _, _ = _runtime(plan_id, [_ok(), _ok()])
    await _run(scene, rt)  # reserves 50 %: notifies 50
    events = _events(scene.tenant_id)
    assert _thresholds_of(events) == [50, 50]
    assert len({e["subscription_id"] for e in events}) == 2
    assert len({e["event_id"] for e in events}) == 1  # one occurrence, fanned out
    data = events[0]["event_data"]
    assert data == {
        "threshold_percent": 50,
        "period_start": data["period_start"],
        "currency": "USD",
        "basis": "estimated_platform_spend",
    }
    assert datetime.fromisoformat(data["period_start"]).day == 1
    (audit,) = _audits(scene.tenant_id)
    assert audit["actor_user_id"] == scene.member.user_id
    assert audit["outcome"] == "success"
    assert audit["metadata"]["threshold_percent"] == 50
    assert audit["metadata"]["trigger"] == "admission"
    for text_ in (str(events), str(audit["metadata"])):
        assert "0.0015" not in text_ and "0.0030" not in text_  # no amount anywhere

    await _run(scene, rt)  # reaches 100 %: notifies 90 only
    assert _thresholds_of(_events(scene.tenant_id)) == [50, 50, 90, 90]
    assert [a["metadata"]["threshold_percent"] for a in _audits(scene.tenant_id)] == [50, 90]
    assert _notified(scene.tenant_id) == [90]
    with pytest.raises(InferenceQuotaExceededError):
        await _run(scene, rt)
    assert len(_events(scene.tenant_id)) == 4


async def test_several_thresholds_reached_at_once_are_each_notified(world: AIWorld) -> None:
    scene, plan_id = _warned(world, amount=_WORST * 2, warn=[10, 20, 30, 60])
    rt, _, _ = _runtime(plan_id, [_ok()])
    await _run(scene, rt)
    assert _thresholds_of(_events(scene.tenant_id)) == [10, 20, 30]
    assert len(_audits(scene.tenant_id)) == 3
    assert _notified(scene.tenant_id) == [30]


async def test_a_release_and_a_second_reach_do_not_notify_again(world: AIWorld) -> None:
    scene, plan_id = _warned(world, amount=_WORST * 2, warn=[50])
    rt, _, _ = _runtime(
        plan_id, [AdapterError(ErrorCategory.INVALID_REQUEST, possibly_accepted=False)]
    )
    with pytest.raises(InferenceInvalidRequestError):
        await _run(scene, rt)
    # The reservation reached 50 % and was released afterwards.
    assert _thresholds_of(_events(scene.tenant_id)) == [50]
    rt, _, _ = _runtime(plan_id, [_ok()])
    await _run(scene, rt)
    assert _thresholds_of(_events(scene.tenant_id)) == [50]
    assert len(_audits(scene.tenant_id)) == 1


async def test_a_settlement_above_the_reservation_notifies(world: AIWorld) -> None:
    scene, plan_id = _warned(world, amount=_WORST * 4, warn=[100])
    rt, _, _ = _runtime(plan_id, [_ok(output_tokens=1000)])  # ten times the worst output
    await _run(scene, rt)
    assert _thresholds_of(_events(scene.tenant_id)) == [100]
    (audit,) = _audits(scene.tenant_id)
    assert audit["metadata"]["trigger"] == "settlement"
    assert _notified(scene.tenant_id) == [100]


@pytest.mark.parametrize("round_", range(3))
async def test_parallel_admissions_notify_a_threshold_once(world: AIWorld, round_: int) -> None:
    del round_
    scene, plan_id = _warned(world, amount=_WORST * 8, warn=[25, 50])
    release = asyncio.Event()

    class Slow(FakeAdapter):
        async def complete(self, request: Any, **kwargs: Any) -> AdapterResult:
            await release.wait()
            return _ok()

    rt, _, _ = _runtime(plan_id, adapter=Slow())
    tasks = [asyncio.create_task(_run(scene, rt)) for _ in range(6)]
    for _ in range(200):
        await asyncio.sleep(0.05)
        reserved = _rows(
            "SELECT count(*) AS n FROM control_plane.ai_budget_reservations WHERE tenant_id = :t",
            t=str(scene.tenant_id),
        )[0]["n"]
        if reserved >= len(tasks):
            break
    release.set()
    await asyncio.gather(*tasks)
    # `created_at` is each transaction's start, so concurrent admissions can
    # list out of order: each threshold once is what is pinned.
    assert sorted(_thresholds_of(_events(scene.tenant_id))) == [25, 50]
    assert sorted(a["metadata"]["threshold_percent"] for a in _audits(scene.tenant_id)) == [
        25,
        50,
    ]
    assert _notified(scene.tenant_id) == [50]


# --- configuration ------------------------------------------------------------------------


async def test_the_tenant_list_replaces_the_plan_list_and_an_empty_one_turns_warnings_off(
    world: AIWorld,
) -> None:
    scene, plan_id = _warned(world, amount=_WORST * 10, warn=[5])
    manager = world.member(scene.tenant_id, ("ai.budget", "manage"))
    view = budget_admin.set_tenant_budget_cap(
        scene.tenant_id, currency="USD", amount=None, caller=manager, warn_thresholds=[]
    )
    assert view.warn_thresholds == ()
    rt, _, _ = _runtime(plan_id, [_ok(), _ok()])
    await _run(scene, rt)  # 10 %, but warnings are off
    assert _events(scene.tenant_id) == []
    budget_admin.set_tenant_budget_cap(
        scene.tenant_id, currency="USD", amount=None, caller=manager, warn_thresholds=[15]
    )
    await _run(scene, rt)  # 20 %: the tenant's 15
    assert _thresholds_of(_events(scene.tenant_id)) == [15]
    with pytest.raises(AIBudgetError) as raised:
        budget_admin.set_tenant_budget_cap(
            scene.tenant_id, currency="USD", amount=None, caller=manager, warn_thresholds=[90, 80]
        )
    assert raised.value.reason == "invalid_thresholds"


async def test_malformed_stored_thresholds_refuse_like_unreadable_budget_data(
    world: AIWorld,
) -> None:
    scene, plan_id = _warned(world, amount=_WORST * 10, warn=[50])
    _admin(
        "UPDATE control_plane.ai_plan_budgets SET warn_thresholds = '[0, \"x\"]' "
        "WHERE plan_id = :p",
        p=str(plan_id),
    )
    rt, fake, _ = _runtime(plan_id, [_ok()])
    with pytest.raises(InferenceQuotaExceededError) as raised:
        await _run(scene, rt)
    assert raised.value.reason == "budget_unavailable"
    assert fake.calls == []
    reader = world.member(scene.tenant_id, ("ai.usage", "read"))
    status = budget_admin.read_tenant_budget(
        scene.tenant_id, caller=reader, plans=lambda tenant_id: [plan_id]
    )
    assert status.state == "unavailable"


# --- failure, months and status -----------------------------------------------------------


async def test_a_failed_notification_never_fails_the_request_and_is_retried(
    world: AIWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    scene, plan_id = _warned(world, amount=_WORST * 4, warn=[25])
    real = budget.trigger_event
    calls: list[int] = []

    def flaky(*args: Any, **kwargs: Any) -> Any:
        # The first call fails after its events are written: the savepoint
        # must take them back.
        calls.append(1)
        written = real(*args, **kwargs)
        if len(calls) == 1:
            raise RuntimeError("outbox unavailable")
        return written

    monkeypatch.setattr(budget, "trigger_event", flaky)
    rt, fake, _ = _runtime(plan_id, [_ok(), _ok()])
    await _run(scene, rt)
    assert len(fake.calls) == 1
    assert _events(scene.tenant_id) == [] and _audits(scene.tenant_id) == []
    assert _notified(scene.tenant_id) == [None]
    await _run(scene, rt)
    assert _thresholds_of(_events(scene.tenant_id)) == [25]
    assert len(_audits(scene.tenant_id)) == 1


async def test_a_new_month_starts_with_nothing_notified(world: AIWorld) -> None:
    scene, plan_id = _warned(world, amount=_WORST * 2, warn=[50])
    rt, _, _ = _runtime(plan_id, [_ok(), _ok()])
    await _run(scene, rt)
    # Move this month's row back one month; the next request opens a new one.
    _admin(
        "UPDATE control_plane.ai_budget_periods "
        "SET period_start = period_start - interval '1 month' WHERE tenant_id = :t",
        t=str(scene.tenant_id),
    )
    await _run(scene, rt)
    assert _thresholds_of(_events(scene.tenant_id)) == [50, 50]
    assert _notified(scene.tenant_id) == [50, 50]


async def test_the_status_reads_warning_with_the_threshold_reached(world: AIWorld) -> None:
    scene, plan_id = _warned(world, amount=_WORST * 4, warn=[25, 75])
    rt, _, _ = _runtime(plan_id, [_ok()])
    await _run(scene, rt)
    reader: UserCaller = world.member(scene.tenant_id, ("ai.usage", "read"))
    status = budget_admin.read_tenant_budget(
        scene.tenant_id, caller=reader, plans=lambda tenant_id: [plan_id]
    )
    assert (status.state, status.warn_thresholds, status.threshold_reached) == (
        "warning",
        (25, 75),
        25,
    )
    report = read_tenant_ai_usage(
        scene.tenant_id, caller=reader, budget_plans=lambda tenant_id: [plan_id]
    )
    assert (report.budget.state, report.budget.threshold_reached) == ("warning", 25)
