"""The reference consumer's governed inference, end to end (ADR-0054 Phase
AI-H; roadmap AI-D acceptance: "reference consumer exercises one inference
call against a fake endpoint through the Q11 interface").

`reference_consumer.inference` calls `saas_os.inference` only. Everything is
real except the provider: the default runtime keeps its real admission
(Redis concurrency lease) and the real entitlement check against the
tenant's plan; the provider adapter is replaced by the scripted fake, so no
network and no provider credential is used. Also pinned: without the plan's
`ai.inference` entitlement the same call is refused before anything is sent.
"""

from __future__ import annotations

import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

_REFERENCE_CONSUMER_ROOT = Path(__file__).resolve().parents[1] / "examples" / "reference-consumer"
if str(_REFERENCE_CONSUMER_ROOT) not in sys.path:
    sys.path.insert(0, str(_REFERENCE_CONSUMER_ROOT))

from reference_consumer import inference as consumer  # noqa: E402

import saas_os.core.identity.models  # noqa: E402, F401  (registers core.users for audit FKs)
from ai_inference_world import AIWorld, attempts  # noqa: E402
from saas_os.control_plane.inference import service  # noqa: E402
from saas_os.control_plane.inference.adapters import FakeAdapter, OpaqueCredential  # noqa: E402
from saas_os.control_plane.inference.config import service as ai_config  # noqa: E402
from saas_os.control_plane.inference.config import tenant_policy  # noqa: E402
from saas_os.core.billing.provider import FakeBillingProvider  # noqa: E402
from saas_os.core.billing.service import create_plan, subscribe  # noqa: E402
from saas_os.inference import InferenceEntitlementDeniedError  # noqa: E402
from saas_os.infra.db.config import get_database_config, get_migrations_database_config  # noqa: E402
from saas_os.infra.db.engine import build_engine, get_engine  # noqa: E402

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


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
            conn.execute(text("SELECT 1 FROM control_plane.ai_inference_attempts LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    finally:
        probe.dispose()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch, platform_config_database: None) -> None:
    class _Secrets:
        def get(self, name: str) -> str | None:
            return "placeholder" if name.startswith("AI_TEST_") else None

    monkeypatch.setattr(ai_config, "get_secrets_provider", lambda: _Secrets())
    # Only these names are provisioned for AI provider use (credentials.py).
    monkeypatch.setenv("AI_PROVIDER_CREDENTIALS", "AI_TEST_PROVIDER_KEY,AI_TEST_ROTATED")


@pytest.fixture
def plans() -> Iterator[list[str]]:
    keys: list[str] = []
    yield keys
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM core.billing_plans WHERE key = ANY(:k)"), {"k": keys})
    finally:
        engine.dispose()


@pytest.fixture
def world(plans: list[str]) -> Iterator[AIWorld]:
    w = AIWorld()
    try:
        yield w
    finally:
        engine = build_engine(get_migrations_database_config())
        try:
            with engine.begin() as conn:
                for table in (
                    "billing_provider_refs",
                    "billing_subscriptions",
                    "idempotency_records",
                ):
                    conn.execute(
                        text(f"DELETE FROM core.{table} WHERE tenant_id = ANY(:t)"),
                        {"t": [str(t) for t in w.tenant_ids]},
                    )
        finally:
            engine.dispose()
        w.cleanup()


@pytest.fixture
def fake_provider(monkeypatch: pytest.MonkeyPatch) -> FakeAdapter:
    """The default runtime -- real admission, real entitlement -- with the
    provider replaced by the scripted fake."""
    fake = FakeAdapter()
    runtime = service.default_runtime()
    monkeypatch.setattr(runtime, "adapters", {"openai_chat_completions": fake})
    monkeypatch.setattr(runtime, "egress", lambda eligible: None)
    monkeypatch.setattr(runtime, "credential", lambda name: OpaqueCredential("test-credential"))
    return fake


def _entitle(plans: list[str], tenant_id: uuid.UUID, *, entitled: bool) -> None:
    key = f"ai-plan-{uuid.uuid4().hex[:8]}"
    create_plan(key, "AI plan", entitlements={"ai.inference": entitled})
    plans.append(key)
    subscribe(tenant_id, key, provider=FakeBillingProvider())


def _grant_consumer_use_case(world: AIWorld, *, destination: bool) -> object:
    consumer.register_inference_use_cases()
    scene = world.scene()
    tenant_policy.grant_use_case(
        scene.tenant_id,
        use_case=consumer.SUMMARIZE_NOTE.name,
        classifications=["none", "tenant_data"],
        caller=scene.manager,
    )
    if destination:
        target = scene.destinations[0]
        tenant_policy.grant_destination(
            scene.tenant_id,
            use_case=consumer.SUMMARIZE_NOTE.name,
            provider_key=target.provider_key,
            model_id=target.model_id,
            classifications=["none", "tenant_data"],
            caller=scene.manager,
        )
    return scene


async def test_the_reference_consumer_runs_one_governed_call(
    world: AIWorld, plans: list[str], fake_provider: FakeAdapter
) -> None:
    scene = _grant_consumer_use_case(world, destination=True)
    _entitle(plans, scene.tenant_id, entitled=True)  # type: ignore[attr-defined]
    result = await consumer.summarize_note(
        scene.member,  # type: ignore[attr-defined]
        tenant_id=scene.tenant_id,  # type: ignore[attr-defined]
        alias=scene.alias,  # type: ignore[attr-defined]
        note="the invoice is wrong",
    )
    assert result.output[0].text == "the invoice is wrong"  # the fake echoes the last turn
    assert result.output[0].classification == "tenant_data"
    assert result.client_request_id == f"note-summary-{scene.tenant_id}"  # type: ignore[attr-defined]
    (call,) = fake_provider.calls
    assert call.request.system == "Summarize in one line."
    (row,) = attempts(scene.tenant_id)  # type: ignore[attr-defined]
    assert row["state"] == "succeeded" and row["use_case"] == consumer.SUMMARIZE_NOTE.name


async def test_without_the_entitlement_nothing_is_sent(
    world: AIWorld, plans: list[str], fake_provider: FakeAdapter
) -> None:
    scene = _grant_consumer_use_case(world, destination=True)
    _entitle(plans, scene.tenant_id, entitled=False)  # type: ignore[attr-defined]
    with pytest.raises(InferenceEntitlementDeniedError):
        await consumer.summarize_note(
            scene.member,  # type: ignore[attr-defined]
            tenant_id=scene.tenant_id,  # type: ignore[attr-defined]
            alias=scene.alias,  # type: ignore[attr-defined]
            note="x",
        )
    assert fake_provider.calls == [] and attempts(scene.tenant_id) == []  # type: ignore[attr-defined]
