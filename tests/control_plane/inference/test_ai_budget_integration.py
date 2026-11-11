"""The monetary AI budget against a real PostgreSQL (ADR-0054 amendment of
2026-11-10; Gap 21b, stage 5; acceptance criteria of Gap 21 section 10).

Pinned: a tenant with no budget runs exactly as before and writes no budget
row; `AI_INFERENCE_BUDGET_REQUIRED` refuses it; an admitted attempt reserves
its worst case and settles its estimated cost with the price version it was
reserved with; exhaustion, a stale, missing or foreign-currency price, and
parts in two currencies each refuse before any attempt row is written and
before the provider is called; parallel requests never admit more than fits;
a definite provider refusal releases the reservation, a possibly accepted one
and an abandoned attempt keep the worst case charged until an audited
operator release; a tenant cap only lowers the limit and needs
`ai.budget:manage`; an override raises it and lapses at its expiry; the
status read is audited; the tenant tables are isolated by row-level security
and the application role cannot write the platform budget tables.
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
from ai_inference_world import (
    REASON,
    AIWorld,
    P,
    Scene,
    admin_scalar,
    attempts,
    runtime,
)
from saas_os.control_plane.inference import budget_admin, service
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
    InferenceOutcomeUnknownError,
    InferenceQuotaExceededError,
)
from saas_os.control_plane.inference.tenant_usage import read_tenant_ai_usage
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.core.authority import ServiceAccountCaller, UserCaller
from saas_os.core.platform_authority import PlatformNotAuthorizedError
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import session_scope, tenant_session_scope

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_INPUT = Decimal("3")
_OUTPUT = Decimal("15")
_TEXT = "hello"  # 5 bytes: the worst case reserves 5 input tokens
_MAX_OUTPUT = 100
# 5 x 3 + 100 x 15 per million = 0.001515
_WORST = Decimal("0.00151500")


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


def _price(
    scene: Scene,
    version: str = "v1",
    *,
    currency: str = "USD",
    input_per_million: Decimal = _INPUT,
    output_per_million: Decimal = _OUTPUT,
    index: int = 0,
) -> None:
    target = scene.destinations[index]
    ai_config.set_model_price(
        provider_key=target.provider_key,
        model_id=target.model_id,
        pricing_version=version,
        currency=currency,
        input_per_million=input_per_million,
        output_per_million=output_per_million,
        effective_from=datetime.now(UTC) - timedelta(days=40),
        caller=scene.operator,
        reason=REASON,
    )


def _budgeted(
    world: AIWorld,
    *,
    amount: Decimal | None,
    currency: str = "USD",
    destinations: int = 1,
    price: bool = True,
) -> tuple[Scene, UserCaller, uuid.UUID]:
    """A scene with a fresh price and, with `amount`, a plan budget."""
    scene = world.scene(destinations=destinations)
    if price:
        for index in range(destinations):
            _price(scene, index=index)
    budgeter = world.operator(P.AI_BUDGET_MANAGE)
    plan_id = world.plan()
    if amount is not None:
        budget_admin.set_plan_budget(
            plan_id,
            budget_version="b1",
            currency=currency,
            monthly_amount=amount,
            effective_from=datetime.now(UTC) - timedelta(days=1),
            caller=budgeter,
            reason=REASON,
        )
    return scene, budgeter, plan_id


def _runtime(plan_id: uuid.UUID | None, script: list[Any] | None = None, **kwargs: Any) -> Any:
    rt, fake, gate = runtime(script, **kwargs)
    rt.budget_plans = lambda tenant_id: [plan_id] if plan_id else []
    return rt, fake, gate


def _request(scene: Scene, *, max_output_tokens: int = _MAX_OUTPUT) -> InferenceRequest:
    return InferenceRequest(
        alias=scene.alias,
        use_case=scene.use_case.name,
        messages=(Message("user", (ContentPart("text", "tenant_data", text=_TEXT),)),),
        max_output_tokens=max_output_tokens,
    )


def _ok(input_tokens: int = 5, output_tokens: int = 10) -> AdapterResult:
    return AdapterResult(
        text="ok",
        finish_reason="stop",
        usage=AdapterUsage(input_tokens=input_tokens, output_tokens=output_tokens),
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


def _period(tenant_id: uuid.UUID) -> dict[str, Any] | None:
    rows = _rows(
        "SELECT * FROM control_plane.ai_budget_periods WHERE tenant_id = :t", t=str(tenant_id)
    )
    assert len(rows) <= 1
    return rows[0] if rows else None


def _reservations(tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    return _rows(
        "SELECT * FROM control_plane.ai_budget_reservations WHERE tenant_id = :t "
        "ORDER BY created_at, attempt_number",
        t=str(tenant_id),
    )


def _admin(sql: str, **params: object) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(text(sql), params)
    finally:
        engine.dispose()


async def _refused(scene: Scene, rt: Any, **kwargs: Any) -> str | None:
    with pytest.raises(InferenceQuotaExceededError) as raised:
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene, **kwargs), runtime=rt
        )
    return raised.value.reason


# --- compatibility ------------------------------------------------------------------------


async def test_a_tenant_without_a_budget_runs_as_before_and_writes_no_budget_row(
    world: AIWorld,
) -> None:
    scene, _, _ = _budgeted(world, amount=None)
    rt, fake, _ = _runtime(None, [_ok()])
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.usage.estimated_cost == Decimal("0.00016500")  # 5x3 + 10x15 per million
    assert len(fake.calls) == 1
    assert _period(scene.tenant_id) is None
    assert _reservations(scene.tenant_id) == []


async def test_a_required_budget_refuses_a_tenant_without_one(
    world: AIWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    scene, _, _ = _budgeted(world, amount=None)
    monkeypatch.setenv("AI_INFERENCE_BUDGET_REQUIRED", "true")
    rt, fake, _ = _runtime(None, [_ok()])
    assert await _refused(scene, rt) == "budget_not_configured"
    assert fake.calls == []
    assert attempts(scene.tenant_id) == []


# --- reserve and settle -------------------------------------------------------------------


async def test_an_admitted_attempt_reserves_its_worst_case_and_settles_its_cost(
    world: AIWorld,
) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    seen: dict[str, Any] = {}

    class Observing(FakeAdapter):
        async def complete(self, request: Any, **kwargs: Any) -> AdapterResult:
            # While the provider call is in flight the worst case is reserved.
            seen["period"] = _period(scene.tenant_id)
            seen["reservations"] = _reservations(scene.tenant_id)
            return await super().complete(request, **kwargs)

    rt, _, _ = _runtime(plan_id, adapter=Observing([_ok()]))
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert seen["period"]["reserved"] == _WORST
    assert [r["state"] for r in seen["reservations"]] == ["held"]
    cost = Decimal("0.00016500")
    assert result.usage.estimated_cost == cost
    period = _period(scene.tenant_id)
    assert period is not None
    assert (period["reserved"], period["retained"], period["settled"]) == (0, 0, cost)
    assert period["plan_limit"] == Decimal("1")
    assert period["period_start"].day == 1 and period["period_start"].hour == 0
    (reservation,) = _reservations(scene.tenant_id)
    assert reservation["state"] == "settled"
    assert reservation["amount"] == _WORST
    assert reservation["settled_amount"] == cost
    assert reservation["attempt_id"] == attempts(scene.tenant_id)[0]["id"]


async def test_the_reserved_price_version_prices_the_attempt_even_if_a_new_one_arrives(
    world: AIWorld,
) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))

    class Repricing(FakeAdapter):
        async def complete(self, request: Any, **kwargs: Any) -> AdapterResult:
            # A new, dearer version takes effect while the call is in flight.
            target = scene.destinations[0]
            ai_config.set_model_price(
                provider_key=target.provider_key,
                model_id=target.model_id,
                pricing_version="v2",
                currency="USD",
                input_per_million=Decimal("300"),
                output_per_million=Decimal("1500"),
                effective_from=datetime.now(UTC) - timedelta(seconds=1),
                caller=scene.operator,
                reason=REASON,
            )
            return await super().complete(request, **kwargs)

    rt, _, _ = _runtime(plan_id, adapter=Repricing([_ok()]))
    first = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert (first.usage.estimated_cost, first.usage.pricing_version) == (
        Decimal("0.00016500"),
        "v1",
    )
    # The next attempt reserves and settles with the new version.
    rt2, _, _ = _runtime(plan_id, [_ok()])
    second = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt2
    )
    assert second.usage.pricing_version == "v2"
    assert second.usage.estimated_cost == Decimal("0.01650000")


async def test_usage_without_a_provider_report_settles_the_worst_case(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    unreported = AdapterResult(
        text="ok",
        finish_reason="stop",
        usage=AdapterUsage(),
        model="model-1",
        provider_request_id="r",
    )
    rt, _, _ = _runtime(plan_id, [unreported])
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    period = _period(scene.tenant_id)
    assert period is not None and period["settled"] == _WORST


async def test_a_provider_report_above_the_worst_case_is_recorded_not_hidden(
    world: AIWorld,
) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    rt, _, _ = _runtime(plan_id, [_ok(input_tokens=5, output_tokens=1000)])
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.usage.estimated_cost is not None and result.usage.estimated_cost > _WORST
    period = _period(scene.tenant_id)
    assert period is not None and period["settled"] == result.usage.estimated_cost


# --- refusals before anything is sent -----------------------------------------------------


async def test_exhaustion_refuses_before_any_attempt_row_or_provider_call(world: AIWorld) -> None:
    # Room for exactly one worst case.
    scene, _, plan_id = _budgeted(world, amount=_WORST)
    rt, fake, _ = _runtime(plan_id, [_ok(output_tokens=_MAX_OUTPUT), _ok()])
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    calls_before = len(fake.calls)
    rows_before = len(attempts(scene.tenant_id))
    assert await _refused(scene, rt) == "monthly_budget_exhausted"
    assert len(fake.calls) == calls_before
    assert len(attempts(scene.tenant_id)) == rows_before
    assert len(_reservations(scene.tenant_id)) == 1


async def test_a_zero_budget_refuses_everything(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("0"))
    rt, fake, _ = _runtime(plan_id, [_ok()])
    assert await _refused(scene, rt) == "monthly_budget_exhausted"
    assert fake.calls == [] and attempts(scene.tenant_id) == []


async def test_a_stale_price_refuses_a_budgeted_request(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    _admin(
        "UPDATE control_plane.ai_model_prices SET reviewed_at = now() - interval '25 hours' "
        "WHERE model_ref = :m",
        m=str(scene.destinations[0].model_ref),
    )
    rt, fake, _ = _runtime(plan_id, [_ok()])
    assert await _refused(scene, rt) == "budget_pricing_unavailable"
    assert fake.calls == [] and attempts(scene.tenant_id) == []


async def test_a_never_confirmed_price_refuses_a_budgeted_request(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    _admin(
        "UPDATE control_plane.ai_model_prices SET reviewed_at = NULL WHERE model_ref = :m",
        m=str(scene.destinations[0].model_ref),
    )
    rt, _, _ = _runtime(plan_id, [_ok()])
    assert await _refused(scene, rt) == "budget_pricing_unavailable"


async def test_a_missing_price_refuses_a_budgeted_request(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"), price=False)
    rt, fake, _ = _runtime(plan_id, [_ok()])
    assert await _refused(scene, rt) == "budget_pricing_unavailable"
    assert fake.calls == []


async def test_a_price_in_another_currency_refuses(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"), currency="EUR")
    rt, _, _ = _runtime(plan_id, [_ok()])
    assert await _refused(scene, rt) == "budget_pricing_unavailable"


async def test_parts_in_two_currencies_refuse(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    budgeter = world.member(scene.tenant_id, ("ai.budget", "manage"))
    budget_admin.set_tenant_budget_cap(
        scene.tenant_id, currency="EUR", amount=Decimal("1"), caller=budgeter
    )
    rt, fake, _ = _runtime(plan_id, [_ok()])
    assert await _refused(scene, rt) == "budget_currency_conflict"
    assert fake.calls == []


async def test_two_plans_in_two_currencies_refuse(world: AIWorld) -> None:
    scene, budgeter, plan_id = _budgeted(world, amount=Decimal("1"))
    other = world.plan()
    budget_admin.set_plan_budget(
        other,
        budget_version="b1",
        currency="EUR",
        monthly_amount=Decimal("5"),
        effective_from=datetime.now(UTC) - timedelta(days=1),
        caller=budgeter,
        reason=REASON,
    )
    rt, _, _ = _runtime(plan_id, [_ok()])
    rt.budget_plans = lambda tenant_id: [plan_id, other]
    assert await _refused(scene, rt) == "budget_currency_conflict"


async def test_unreadable_billing_data_refuses(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    rt, fake, _ = _runtime(plan_id, [_ok()])

    def broken(tenant_id: uuid.UUID) -> list[uuid.UUID]:
        raise RuntimeError("billing down")

    rt.budget_plans = broken
    assert await _refused(scene, rt) == "budget_unavailable"
    assert fake.calls == []


async def test_several_plans_in_one_currency_take_the_largest(world: AIWorld) -> None:
    scene, budgeter, small = _budgeted(world, amount=Decimal("0.0001"))
    large = world.plan()
    budget_admin.set_plan_budget(
        large,
        budget_version="b1",
        currency="USD",
        monthly_amount=Decimal("1"),
        effective_from=datetime.now(UTC) - timedelta(days=1),
        caller=budgeter,
        reason=REASON,
    )
    rt, _, _ = _runtime(small, [_ok()])
    rt.budget_plans = lambda tenant_id: [small, large]
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    period = _period(scene.tenant_id)
    assert period is not None and period["plan_limit"] == Decimal("1")


# --- concurrency --------------------------------------------------------------------------


@pytest.mark.parametrize("round_", range(3))
async def test_parallel_requests_never_admit_more_than_fits(world: AIWorld, round_: int) -> None:
    del round_
    fits = 3
    scene, _, plan_id = _budgeted(world, amount=_WORST * fits)
    release = asyncio.Event()

    class Slow(FakeAdapter):
        async def complete(self, request: Any, **kwargs: Any) -> AdapterResult:
            await release.wait()
            return _ok(output_tokens=_MAX_OUTPUT)

    adapter = Slow()
    rt, _, _ = _runtime(plan_id, adapter=adapter)

    async def one() -> str:
        try:
            await service.run_inference(
                scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
            )
        except InferenceQuotaExceededError as exc:
            return exc.reason or "refused"
        return "ok"

    tasks = [asyncio.create_task(one()) for _ in range(8)]
    # Every admission decision is taken before any provider call returns.
    for _ in range(200):
        await asyncio.sleep(0.05)
        decided = len(_reservations(scene.tenant_id)) + sum(t.done() for t in tasks)
        if decided >= len(tasks):
            break
    period = _period(scene.tenant_id)
    assert period is not None
    assert period["reserved"] + period["settled"] + period["retained"] <= _WORST * fits
    release.set()
    outcomes = await asyncio.gather(*tasks)
    assert outcomes.count("ok") == fits
    assert outcomes.count("monthly_budget_exhausted") == len(tasks) - fits
    period = _period(scene.tenant_id)
    assert period is not None and period["settled"] == _WORST * fits
    assert len(attempts(scene.tenant_id)) == fits


# --- failures and unknown outcomes --------------------------------------------------------


async def test_a_definite_provider_refusal_releases_the_reservation(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    rt, _, _ = _runtime(
        plan_id, [AdapterError(ErrorCategory.INVALID_REQUEST, possibly_accepted=False)]
    )
    with pytest.raises(InferenceInvalidRequestError):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    (reservation,) = _reservations(scene.tenant_id)
    assert reservation["state"] == "released"
    period = _period(scene.tenant_id)
    assert period is not None
    assert (period["reserved"], period["retained"], period["settled"]) == (0, 0, 0)


async def test_a_retried_attempt_reserves_again_after_its_release(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    rt, _, _ = _runtime(
        plan_id,
        [AdapterError(ErrorCategory.PROVIDER_OVERLOADED, possibly_accepted=False), _ok()],
    )
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert [r["state"] for r in _reservations(scene.tenant_id)] == ["released", "settled"]


async def test_a_possibly_accepted_outcome_keeps_the_worst_case_charged(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    rt, _, _ = _runtime(
        plan_id, [AdapterError(ErrorCategory.PROVIDER_ERROR, possibly_accepted=True)]
    )
    with pytest.raises(InferenceOutcomeUnknownError):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    (reservation,) = _reservations(scene.tenant_id)
    assert reservation["state"] == "expired_unknown"
    period = _period(scene.tenant_id)
    assert period is not None
    assert (period["reserved"], period["retained"], period["settled"]) == (0, _WORST, 0)


async def test_an_abandoned_attempt_keeps_the_worst_case_charged(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    rt, _, _ = _runtime(plan_id, [_ok()])
    validated = service.validate_request(_request(scene))
    candidates = service._resolve(  # pyright: ignore[reportPrivateUsage]
        scene.member,
        scene.tenant_id,
        validated,
        _request(scene),
        rt,
        abandon_before=datetime.now(UTC) - timedelta(hours=1),
    )
    # A process admitted an attempt and died before settling it.
    service._begin_attempt(  # pyright: ignore[reportPrivateUsage]
        scene.member,
        scene.tenant_id,
        validated,
        _request(scene),
        rt,
        candidates[0],
        request_id=uuid.uuid4(),
        attempt_number=1,
        budget=service._BudgetContext(plan_ids=(plan_id,), required=False),  # pyright: ignore[reportPrivateUsage]
    )
    assert [r["state"] for r in _reservations(scene.tenant_id)] == ["held"]
    # The next request's sweep abandons it.
    service._resolve(  # pyright: ignore[reportPrivateUsage]
        scene.member,
        scene.tenant_id,
        validated,
        _request(scene),
        rt,
        abandon_before=datetime.now(UTC) + timedelta(hours=1),
    )
    assert [r["state"] for r in _reservations(scene.tenant_id)] == ["expired_unknown"]
    period = _period(scene.tenant_id)
    assert period is not None
    assert (period["reserved"], period["retained"]) == (0, _WORST)


async def test_only_a_budget_operator_releases_an_unknown_outcome_with_both_audit_rows(
    world: AIWorld,
) -> None:
    scene, budgeter, plan_id = _budgeted(world, amount=Decimal("1"))
    rt, _, _ = _runtime(
        plan_id, [AdapterError(ErrorCategory.PROVIDER_ERROR, possibly_accepted=True)]
    )
    with pytest.raises(InferenceOutcomeUnknownError):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    (reservation,) = _reservations(scene.tenant_id)
    outsider = world.operator(P.AI_POLICY_MANAGE)
    with pytest.raises(PlatformNotAuthorizedError):
        budget_admin.release_budget_reservation(
            scene.tenant_id, reservation["id"], caller=outsider, reason=REASON
        )
    with pytest.raises(AIBudgetError) as wrong_tenant:
        budget_admin.release_budget_reservation(
            world.tenant(), reservation["id"], caller=budgeter, reason=REASON
        )
    assert wrong_tenant.value.reason == "reservation_unavailable"
    released = budget_admin.release_budget_reservation(
        scene.tenant_id, reservation["id"], caller=budgeter, reason=REASON
    )
    assert released.amount == _WORST
    (after,) = _reservations(scene.tenant_id)
    assert after["state"] == "operator_released"
    period = _period(scene.tenant_id)
    assert period is not None and period["retained"] == 0
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND action = 'ai.budget.reservation_release' AND outcome = 'success'",
            t=str(scene.tenant_id),
        )
        == 1
    )
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.platform_audit_log WHERE target_tenant_id = :t "
            "AND action = 'platform.ai_budget_reservation.release' AND outcome = 'success'",
            t=str(scene.tenant_id),
        )
        == 1
    )
    with pytest.raises(AIBudgetError) as twice:
        budget_admin.release_budget_reservation(
            scene.tenant_id, reservation["id"], caller=budgeter, reason=REASON
        )
    assert twice.value.reason == "reservation_unavailable"


# --- the tenant cap and the operator override ----------------------------------------------


async def test_a_tenant_cap_lowers_the_limit_and_one_above_the_plan_changes_nothing(
    world: AIWorld,
) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    budgeter = world.member(scene.tenant_id, ("ai.budget", "manage"))
    budget_admin.set_tenant_budget_cap(
        scene.tenant_id, currency="USD", amount=Decimal("1000"), caller=budgeter
    )
    rt, _, _ = _runtime(plan_id, [_ok(), _ok()])
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    view = budget_admin.set_tenant_budget_cap(
        scene.tenant_id, currency="USD", amount=Decimal("0.0001"), caller=budgeter
    )
    assert view.version == 2
    assert await _refused(scene, rt) == "monthly_budget_exhausted"
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND action = 'ai.budget.set_cap'"
            " AND outcome = 'success'",
            t=str(scene.tenant_id),
        )
        == 2
    )


async def test_the_cap_needs_ai_budget_manage_and_a_user(world: AIWorld) -> None:
    scene, _, _ = _budgeted(world, amount=Decimal("1"))
    # Neither managing the AI policy nor reading usage and cost implies it.
    for other in (
        scene.manager,
        world.member(scene.tenant_id, ("ai.usage", "read"), ("ai.policy", "read")),
    ):
        with pytest.raises(AuthorityNotAuthorizedError):
            budget_admin.set_tenant_budget_cap(
                scene.tenant_id, currency="USD", amount=Decimal("1"), caller=other
            )
    service_account = ServiceAccountCaller(uuid.uuid4(), scene.tenant_id)
    with pytest.raises(AuthorityNotAuthorizedError):
        budget_admin.set_tenant_budget_cap(
            scene.tenant_id, currency="USD", amount=Decimal("1"), caller=service_account
        )
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND action = 'ai.budget.set_cap'"
            " AND outcome = 'denied'",
            t=str(scene.tenant_id),
        )
        >= 1
    )
    assert (
        admin_scalar(
            "SELECT count(*) FROM control_plane.ai_tenant_budgets WHERE tenant_id = :t",
            t=str(scene.tenant_id),
        )
        == 0
    )
    # The permission alone is enough.
    holder = world.member(scene.tenant_id, ("ai.budget", "manage"))
    view = budget_admin.set_tenant_budget_cap(
        scene.tenant_id, currency="USD", amount=Decimal("1"), caller=holder
    )
    assert (view.cap_amount, view.version) == (Decimal("1"), 1)


async def test_an_override_raises_the_budget_and_lapses_at_its_expiry(world: AIWorld) -> None:
    scene, budgeter, plan_id = _budgeted(world, amount=Decimal("0"))
    rt, _, _ = _runtime(plan_id, [_ok(), _ok()])
    assert await _refused(scene, rt) == "monthly_budget_exhausted"
    view = budget_admin.set_tenant_budget_override(
        scene.tenant_id,
        currency="USD",
        amount=Decimal("1"),
        reason="support",
        expires_at=datetime.now(UTC) + timedelta(days=2),
        caller=budgeter,
    )
    assert view.active and view.amount == Decimal("1")
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND action = 'ai.budget.override_set'",
            t=str(scene.tenant_id),
        )
        == 1
    )
    # Expired: the plan budget (zero) applies again.
    _admin(
        "UPDATE control_plane.ai_budget_overrides SET set_at = now() - interval '3 days', "
        "expires_at = now() - interval '1 second' WHERE target_tenant_id = :t",
        t=str(scene.tenant_id),
    )
    assert await _refused(scene, rt) == "monthly_budget_exhausted"


async def test_an_override_needs_the_budget_permission_and_a_bounded_expiry(
    world: AIWorld,
) -> None:
    scene, budgeter, _ = _budgeted(world, amount=Decimal("1"))
    with pytest.raises(PlatformNotAuthorizedError):
        budget_admin.set_tenant_budget_override(
            scene.tenant_id,
            currency="USD",
            amount=Decimal("5"),
            reason="support",
            expires_at=datetime.now(UTC) + timedelta(days=1),
            caller=world.operator(P.AI_POLICY_MANAGE, P.AI_TENANT_HOLD_MANAGE),
        )
    for expiry in (
        datetime.now(UTC) - timedelta(minutes=1),
        datetime.now(UTC) + timedelta(days=400),
    ):
        with pytest.raises(AIBudgetError) as raised:
            budget_admin.set_tenant_budget_override(
                scene.tenant_id,
                currency="USD",
                amount=Decimal("5"),
                reason="support",
                expires_at=expiry,
                caller=budgeter,
            )
        assert raised.value.reason == "invalid_expiry"
    with pytest.raises(AIBudgetError) as bad_reason:
        budget_admin.set_tenant_budget_override(
            scene.tenant_id,
            currency="USD",
            amount=Decimal("5"),
            reason="because",
            expires_at=datetime.now(UTC) + timedelta(days=1),
            caller=budgeter,
        )
    assert bad_reason.value.reason == "invalid_reason"
    with pytest.raises(AIBudgetError) as nothing:
        budget_admin.clear_tenant_budget_override(scene.tenant_id, caller=budgeter)
    assert nothing.value.reason == "not_overridden"


async def test_a_lower_plan_budget_mid_month_applies_and_a_higher_one_waits(
    world: AIWorld,
) -> None:
    scene, budgeter, plan_id = _budgeted(world, amount=_WORST * 2)
    rt, _, _ = _runtime(plan_id, [_ok(output_tokens=_MAX_OUTPUT)] * 3)
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    # A higher version mid-month does not raise this month's limit.
    budget_admin.set_plan_budget(
        plan_id,
        budget_version="b2",
        currency="USD",
        monthly_amount=Decimal("1"),
        caller=budgeter,
        reason=REASON,
    )
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert await _refused(scene, rt) == "monthly_budget_exhausted"
    period = _period(scene.tenant_id)
    assert period is not None and period["plan_limit"] == _WORST * 2
    # A lower one applies at once.
    budget_admin.set_plan_budget(
        plan_id,
        budget_version="b3",
        currency="USD",
        monthly_amount=_WORST,
        caller=budgeter,
        reason=REASON,
    )
    assert await _refused(scene, rt) == "monthly_budget_exhausted"
    reader = world.member(scene.tenant_id, ("ai.usage", "read"))
    status = budget_admin.read_tenant_budget(
        scene.tenant_id, caller=reader, plans=lambda tenant_id: [plan_id]
    )
    assert (status.limit, status.state) == (_WORST, "exhausted")


async def test_plan_budget_versions_are_immutable_and_need_a_known_plan(world: AIWorld) -> None:
    _, budgeter, plan_id = _budgeted(world, amount=Decimal("1"))
    with pytest.raises(AIBudgetError) as again:
        budget_admin.set_plan_budget(
            plan_id,
            budget_version="b1",
            currency="USD",
            monthly_amount=Decimal("2"),
            caller=budgeter,
            reason=REASON,
        )
    assert again.value.reason == "version_exists"
    with pytest.raises(AIBudgetError) as unknown:
        budget_admin.set_plan_budget(
            uuid.uuid4(),
            budget_version="b1",
            currency="USD",
            monthly_amount=Decimal("2"),
            caller=budgeter,
            reason=REASON,
        )
    assert unknown.value.reason == "plan_unavailable"


# --- reads, isolation and grants -----------------------------------------------------------


async def test_the_status_read_is_audited_and_the_usage_report_carries_it(world: AIWorld) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    rt, _, _ = _runtime(plan_id, [_ok()])
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    reader = world.member(scene.tenant_id, ("ai.usage", "read"))
    status = budget_admin.read_tenant_budget(
        scene.tenant_id, caller=reader, plans=lambda tenant_id: [plan_id]
    )
    assert (status.state, status.currency, status.limit, status.source) == (
        "ok",
        "USD",
        Decimal("1"),
        "plan",
    )
    assert status.settled == Decimal("0.00016500")
    assert status.remaining == Decimal("1") - Decimal("0.00016500")
    assert status.basis == "estimated_platform_spend"
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND action = 'ai.budget.read'",
            t=str(scene.tenant_id),
        )
        == 1
    )
    report = read_tenant_ai_usage(
        scene.tenant_id, caller=reader, budget_plans=lambda tenant_id: [plan_id]
    )
    assert report.budget.state == "ok" and report.budget.settled == status.settled
    with pytest.raises(AuthorityNotAuthorizedError):
        budget_admin.read_tenant_budget(scene.tenant_id, caller=scene.member)


async def test_the_tenant_budget_tables_are_isolated_by_row_level_security(
    world: AIWorld,
) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    rt, _, _ = _runtime(plan_id, [_ok()])
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    other = world.tenant()
    with tenant_session_scope(other) as session:
        for table in ("ai_budget_periods", "ai_budget_reservations", "ai_tenant_budgets"):
            assert (
                session.execute(
                    text(f"SELECT count(*) FROM control_plane.{table}")  # noqa: S608 -- fixed names
                ).scalar_one()
                == 0
            )
    with tenant_session_scope(scene.tenant_id) as session:
        assert (
            session.execute(
                text("SELECT count(*) FROM control_plane.ai_budget_periods")
            ).scalar_one()
            == 1
        )


async def test_the_application_role_cannot_write_the_platform_budget_tables(
    world: AIWorld,
) -> None:
    scene, _, plan_id = _budgeted(world, amount=Decimal("1"))
    for statement in (
        "UPDATE control_plane.ai_plan_budgets SET monthly_amount = 1000 WHERE plan_id = :p",
        "INSERT INTO control_plane.ai_budget_overrides (id, target_tenant_id, currency, amount, "
        "reason, active, expires_at, set_at) VALUES (gen_random_uuid(), :t, 'USD', 1000, "
        "'support', true, now() + interval '1 day', now())",
    ):
        with pytest.raises(ProgrammingError), session_scope() as session:
            session.execute(text(statement), {"p": str(plan_id), "t": str(scene.tenant_id)})
    for table in ("ai_budget_periods", "ai_budget_reservations"):
        with pytest.raises(ProgrammingError), tenant_session_scope(scene.tenant_id) as session:
            session.execute(text(f"DELETE FROM control_plane.{table}"))  # noqa: S608 -- fixed names
