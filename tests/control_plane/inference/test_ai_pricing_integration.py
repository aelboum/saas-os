"""The extended model price and its confirmation against a real PostgreSQL
(ADR-0054 amendment of 2026-11-09; Gap 21a).

Pinned: `set_model_price` stores the cache-write rate, the per-request amount
and the other unit rates and records the version as reviewed now;
`confirm_model_price` moves only the review time, needs
`platform.ai_provider:manage`, writes its platform audit row in the same
transaction and records a refusal as denied; a price nobody confirmed reads as
stale or unverifiable; the application role cannot write the price table, with
or without a tenant; the oversight read shows the new fields; an attempt that
wrote to a provider cache is priced at the cache-write rate and has no cost
(never a zero one) under a price without that rate; and a stale price refuses
nothing in this stage. FakeAdapter only: no provider, no network.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import (
    REASON,
    AIWorld,
    Destination,
    P,
    Scene,
    admin_scalar,
    attempts,
    runtime,
)
from saas_os.control_plane.inference import service
from saas_os.control_plane.inference.accounting import PriceStatus, price_in_effect, price_status
from saas_os.control_plane.inference.adapters import AdapterResult, AdapterUsage
from saas_os.control_plane.inference.config import service as ai_config
from saas_os.control_plane.inference.config.errors import AIConfigurationNotFoundError
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.core.authority import UserCaller
from saas_os.core.platform_authority import PlatformNotAuthorizedError
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import session_scope, tenant_session_scope

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_INPUT = Decimal("3")
_OUTPUT = Decimal("15")
_CACHE_WRITE = Decimal("3.75")
_PER_REQUEST = Decimal("0.002")


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
            conn.execute(text("SELECT reviewed_at FROM control_plane.ai_model_prices LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"reviewed_at column missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch, platform_config_database: None) -> None:
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


def _set_price(
    scene: Scene,
    version: str = "v1",
    *,
    effective_from: datetime | None = None,
    cached_input_per_million: Decimal | None = None,
    cache_write_per_million: Decimal | None = None,
    per_request: Decimal | None = None,
    unit_rates: dict[str, Decimal] | None = None,
) -> ai_config.ModelPriceView:
    target = scene.destinations[0]
    return ai_config.set_model_price(
        provider_key=target.provider_key,
        model_id=target.model_id,
        pricing_version=version,
        currency="USD",
        input_per_million=_INPUT,
        output_per_million=_OUTPUT,
        cached_input_per_million=cached_input_per_million,
        cache_write_per_million=cache_write_per_million,
        per_request=per_request,
        unit_rates=unit_rates,
        effective_from=effective_from or datetime.now(UTC) - timedelta(days=40),
        caller=scene.operator,
        reason=REASON,
    )


def _confirm(
    scene: Scene,
    version: str = "v1",
    *,
    caller: UserCaller | None = None,
    provider_key: str | None = None,
    model_id: str | None = None,
) -> ai_config.ModelPriceView:
    target = scene.destinations[0]
    return ai_config.confirm_model_price(
        provider_key=provider_key or target.provider_key,
        model_id=model_id or target.model_id,
        pricing_version=version,
        caller=caller or scene.operator,
        reason=REASON,
    )


def _stored(target: Destination, version: str = "v1") -> dict[str, object]:
    """The stored price row, read with the migrations role."""
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            row = (
                conn.execute(
                    text(
                        "SELECT currency, input_per_million, output_per_million, "
                        "cached_input_per_million, cache_write_per_million, per_request, "
                        "unit_rates::text AS unit_rates, effective_from, reviewed_at "
                        "FROM control_plane.ai_model_prices "
                        "WHERE model_ref = :m AND pricing_version = :v"
                    ),
                    {"m": str(target.model_ref), "v": version},
                )
                .mappings()
                .one()
            )
            return dict(row)
    finally:
        engine.dispose()


def _set_reviewed_at(target: Destination, at: datetime | None, version: str = "v1") -> None:
    """Put the review time of a stored price where a test needs it (the
    migrations role; no code path of SaaS OS can move it backwards)."""
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE control_plane.ai_model_prices SET reviewed_at = :at "
                    "WHERE model_ref = :m AND pricing_version = :v"
                ),
                {"at": at, "m": str(target.model_ref), "v": version},
            )
    finally:
        engine.dispose()


def _status(target: Destination) -> PriceStatus:
    """The status of the price in effect now, read as the application reads it."""
    now = datetime.now(UTC)
    with session_scope() as session:
        return price_status(price_in_effect(session, target.model_ref, now), at=now)


def _platform_rows(user_id: uuid.UUID) -> list[tuple[str, str, dict | None]]:
    with session_scope() as session:
        return [
            (row[0], row[1], row[2])
            for row in session.execute(
                text(
                    "SELECT action, outcome, metadata FROM core.platform_audit_log "
                    "WHERE actor_user_id = :u ORDER BY created_at, id"
                ),
                {"u": str(user_id)},
            )
        ]


def _request(scene: Scene) -> InferenceRequest:
    return InferenceRequest(
        alias=scene.alias,
        use_case=scene.use_case.name,
        messages=(Message("user", (ContentPart("text", "tenant_data", text="hello"),)),),
        max_output_tokens=64,
    )


def _result(usage: AdapterUsage) -> AdapterResult:
    return AdapterResult(
        text="ok", finish_reason="stop", usage=usage, model="model-1", provider_request_id="req-ok"
    )


# --- the stored price ---------------------------------------------------------------


def test_a_price_stores_every_rate_and_is_recorded_as_reviewed(world: AIWorld) -> None:
    scene = world.scene()
    target = scene.destinations[0]
    before = datetime.now(UTC)
    view = _set_price(
        scene,
        cached_input_per_million=Decimal("0.3"),
        cache_write_per_million=_CACHE_WRITE,
        per_request=_PER_REQUEST,
        unit_rates={"web_search_requests": Decimal("0.01"), "audio_seconds": Decimal("0.00006")},
    )
    after = datetime.now(UTC)

    assert (view.cache_write_per_million, view.per_request) == (_CACHE_WRITE, _PER_REQUEST)
    assert view.unit_rates == (
        ("audio_seconds", Decimal("0.00006")),
        ("web_search_requests", Decimal("0.01")),
    )
    assert view.reviewed_at is not None and before <= view.reviewed_at <= after

    stored = _stored(target)
    assert stored["cached_input_per_million"] == Decimal("0.3")
    assert stored["cache_write_per_million"] == _CACHE_WRITE
    assert stored["per_request"] == _PER_REQUEST
    # JSON has no decimal type: a rate is stored as its decimal string, never a float
    assert json.loads(str(stored["unit_rates"])) == {
        "audio_seconds": "0.00006",
        "web_search_requests": "0.01",
    }
    assert stored["reviewed_at"] == view.reviewed_at
    assert _status(target) is PriceStatus.FRESH


def test_a_price_without_the_new_rates_stores_none_of_them(world: AIWorld) -> None:
    scene = world.scene()
    view = _set_price(scene)
    assert (view.cache_write_per_million, view.per_request, view.unit_rates) == (None, None, ())
    stored = _stored(scene.destinations[0])
    assert stored["cache_write_per_million"] is None and stored["per_request"] is None
    # an absent rate is NULL, never an empty object or a zero
    assert stored["unit_rates"] is None
    assert stored["reviewed_at"] is not None


# --- confirmation -------------------------------------------------------------------


def test_confirming_a_price_moves_only_its_review_time(world: AIWorld) -> None:
    scene = world.scene()
    target = scene.destinations[0]
    _set_price(
        scene,
        cache_write_per_million=_CACHE_WRITE,
        per_request=_PER_REQUEST,
        unit_rates={"web_search_requests": Decimal("0.01")},
    )
    _set_reviewed_at(target, datetime.now(UTC) - timedelta(days=2))
    assert _status(target) is PriceStatus.STALE
    stale = _stored(target)

    before = datetime.now(UTC)
    view = _confirm(scene)
    after = datetime.now(UTC)

    assert view.reviewed_at is not None and before <= view.reviewed_at <= after
    confirmed = _stored(target)
    assert confirmed["reviewed_at"] == view.reviewed_at
    # the version is immutable: nothing but the review time changed
    assert {k: v for k, v in confirmed.items() if k != "reviewed_at"} == {
        k: v for k, v in stale.items() if k != "reviewed_at"
    }
    assert _status(target) is PriceStatus.FRESH

    action, outcome, metadata = _platform_rows(scene.operator.user_id)[-1]
    assert (action, outcome) == ("platform.ai_provider.configure", "success")
    assert metadata is not None
    assert metadata["change"] == "confirm_model_price"
    assert (metadata["provider"], metadata["model"], metadata["pricing_version"]) == (
        target.provider_key,
        target.model_id,
        "v1",
    )


def test_a_price_nobody_confirmed_reads_as_unverifiable(world: AIWorld) -> None:
    """The state of every price that existed before the upgrade: no review time."""
    scene = world.scene()
    target = scene.destinations[0]
    _set_price(scene)
    _set_reviewed_at(target, None)
    assert _status(target) is PriceStatus.UNVERIFIABLE
    _confirm(scene)
    assert _status(target) is PriceStatus.FRESH


def test_a_model_without_a_price_reads_as_missing(world: AIWorld) -> None:
    scene = world.scene()
    assert _status(scene.destinations[0]) is PriceStatus.MISSING


def test_confirming_one_version_leaves_the_others_alone(world: AIWorld) -> None:
    scene = world.scene()
    target = scene.destinations[0]
    _set_price(scene, "v1")
    _set_price(scene, "v2", effective_from=datetime.now(UTC) - timedelta(days=10))
    old = datetime.now(UTC).replace(microsecond=0) - timedelta(days=3)
    _set_reviewed_at(target, old, "v1")
    _set_reviewed_at(target, old, "v2")

    _confirm(scene, "v1")

    assert _stored(target, "v1")["reviewed_at"] != old
    assert _stored(target, "v2")["reviewed_at"] == old
    # v2 is the price in effect, and it was not confirmed
    assert _status(target) is PriceStatus.STALE


def test_confirming_without_the_permission_is_refused_and_recorded(world: AIWorld) -> None:
    scene = world.scene()
    target = scene.destinations[0]
    _set_price(scene)
    old = datetime.now(UTC).replace(microsecond=0) - timedelta(days=2)
    _set_reviewed_at(target, old)
    without = world.operator(P.AI_CONFIG_READ, P.AI_POLICY_MANAGE)

    with pytest.raises(PlatformNotAuthorizedError):
        _confirm(scene, caller=without)

    assert _stored(target)["reviewed_at"] == old
    assert [(a, o) for a, o, _ in _platform_rows(without.user_id)] == [
        ("platform.ai_provider.configure", "denied")
    ]


def test_a_tenant_member_cannot_confirm_a_price(world: AIWorld) -> None:
    scene = world.scene()
    target = scene.destinations[0]
    _set_price(scene)
    old = datetime.now(UTC).replace(microsecond=0) - timedelta(days=2)
    _set_reviewed_at(target, old)
    for caller in (scene.manager, scene.member):
        with pytest.raises(PlatformNotAuthorizedError):
            _confirm(scene, caller=caller)
    assert _stored(target)["reviewed_at"] == old


@pytest.mark.parametrize(
    ("version", "model_id", "provider_key", "kind"),
    [
        ("v9", None, None, "price"),
        ("v1", "no-such-model", None, "model"),
        ("v1", None, "no-such-provider", "provider"),
    ],
)
def test_confirming_an_unknown_price_changes_nothing(
    world: AIWorld, version: str, model_id: str | None, provider_key: str | None, kind: str
) -> None:
    scene = world.scene()
    target = scene.destinations[0]
    _set_price(scene)
    old = datetime.now(UTC).replace(microsecond=0) - timedelta(days=2)
    _set_reviewed_at(target, old)
    before = _platform_rows(scene.operator.user_id)
    with pytest.raises(AIConfigurationNotFoundError) as caught:
        _confirm(scene, version, model_id=model_id, provider_key=provider_key)
    assert caught.value.kind == kind
    assert _stored(target)["reviewed_at"] == old
    # An input refusal is not an authorization refusal: it leaves no audit row.
    assert _platform_rows(scene.operator.user_id) == before


# --- the database boundary (ADR-0056) ---------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE control_plane.ai_model_prices SET reviewed_at = now() WHERE model_ref = :m",
        "UPDATE control_plane.ai_model_prices SET cache_write_per_million = 0, per_request = 0, "
        "unit_rates = '{}' WHERE model_ref = :m",
        "DELETE FROM control_plane.ai_model_prices WHERE model_ref = :m",
    ],
)
def test_the_application_role_cannot_write_a_price(world: AIWorld, statement: str) -> None:
    scene = world.scene()
    target = scene.destinations[0]
    _set_price(scene, cache_write_per_million=_CACHE_WRITE)
    stored = _stored(target)
    parameters = {"m": str(target.model_ref)}

    with pytest.raises(ProgrammingError, match="permission denied"), session_scope() as session:
        session.execute(text(statement), parameters)
    with (
        pytest.raises(ProgrammingError, match="permission denied"),
        tenant_session_scope(scene.tenant_id) as session,
    ):
        session.execute(text(statement), parameters)

    assert _stored(target) == stored


# --- the oversight read -----------------------------------------------------------------


def test_the_oversight_read_shows_the_new_fields(world: AIWorld) -> None:
    scene = world.scene()
    target = scene.destinations[0]
    written = _set_price(
        scene,
        cache_write_per_million=_CACHE_WRITE,
        per_request=_PER_REQUEST,
        unit_rates={"web_search_requests": Decimal("0.01")},
    )
    reader = world.operator(P.AI_CONFIG_READ)
    (price,) = [
        p
        for p in ai_config.read_ai_configuration(caller=reader).prices
        if p.provider_key == target.provider_key
    ]
    assert price == written
    assert price.unit_rates == (("web_search_requests", Decimal("0.01")),)
    assert price.reviewed_at is not None

    _set_reviewed_at(target, None)
    (price,) = [
        p
        for p in ai_config.read_ai_configuration(caller=reader).prices
        if p.provider_key == target.provider_key
    ]
    assert price.reviewed_at is None


# --- settlement ---------------------------------------------------------------------------


async def test_cache_write_tokens_and_the_request_amount_are_priced(world: AIWorld) -> None:
    scene = world.scene()
    _set_price(scene, cache_write_per_million=_CACHE_WRITE, per_request=_PER_REQUEST)
    usage = AdapterUsage(input_tokens=11, output_tokens=7, cache_write_tokens=1000)
    rt, _, _ = runtime([_result(usage)])

    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )

    # (11 * 3 + 7 * 15 + 1000 * 3.75) / 1 000 000 + 0.002
    expected = Decimal("0.00588800")
    assert (result.usage.estimated_cost, result.usage.currency) == (expected, "USD")
    assert result.usage.cache_write_tokens == 1000
    (row,) = attempts(scene.tenant_id)
    assert (row["estimated_cost"], row["pricing_version"], row["currency"]) == (
        expected,
        "v1",
        "USD",
    )
    assert row["cache_write_tokens"] == 1000


async def test_cache_write_tokens_without_a_rate_record_no_cost(world: AIWorld) -> None:
    """An attempt that used a unit the price has no rate for has an unknown
    cost. It is never recorded as zero and never as the cost of the other
    units alone (an underestimate)."""
    scene = world.scene()
    _set_price(scene, per_request=_PER_REQUEST)
    usage = AdapterUsage(input_tokens=11, output_tokens=7, cache_write_tokens=1000)
    rt, _, _ = runtime([_result(usage)])

    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )

    assert result.usage.estimated_cost is None
    assert (result.usage.currency, result.usage.pricing_version) == (None, None)
    (row,) = attempts(scene.tenant_id)
    assert (row["estimated_cost"], row["pricing_version"], row["currency"]) == (None, None, None)
    # the usage itself is still recorded
    assert (row["input_tokens"], row["output_tokens"], row["cache_write_tokens"]) == (11, 7, 1000)
    zero_cost_rows = admin_scalar(
        "SELECT count(*) FROM control_plane.ai_inference_attempts "
        "WHERE tenant_id = :t AND estimated_cost = 0",
        t=str(scene.tenant_id),
    )
    assert zero_cost_rows == 0


async def test_an_attempt_that_wrote_no_cache_needs_no_cache_write_rate(world: AIWorld) -> None:
    scene = world.scene()
    _set_price(scene)
    usage = AdapterUsage(input_tokens=11, output_tokens=7, cache_write_tokens=0)
    rt, _, _ = runtime([_result(usage)])
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.usage.estimated_cost == Decimal("0.00013800")  # (11 * 3 + 7 * 15) / 1 000 000


async def test_a_stale_price_refuses_nothing_in_this_stage(world: AIWorld) -> None:
    """Gap 21a adds the staleness evaluation only. The refusal on a stale,
    missing or unverifiable price belongs to the budget stage (Gap 21b) and
    applies to spend-controlled requests; until then a request is served and
    its cost is estimated from the price in effect, whatever its age."""
    scene = world.scene()
    target = scene.destinations[0]
    _set_price(scene)
    for reviewed_at in (datetime.now(UTC) - timedelta(days=3), None):
        _set_reviewed_at(target, reviewed_at)
        assert _status(target) is not PriceStatus.FRESH
        rt, _, _ = runtime([_result(AdapterUsage(input_tokens=11, output_tokens=7))])
        result = await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
        assert result.usage.estimated_cost == Decimal("0.00013800")
    assert len(attempts(scene.tenant_id)) == 2
