"""Governed inference against a real PostgreSQL (ADR-0054 Phase AI-D;
ADR-0055; AI-INFERENCE-CONTRACTS sections 4, 5 and 7).

The provider is a scripted adapter (no network); everything else is real:
authorization, tenant RLS, policy, the attempt ledger, settlement and the
usage outbox. Pinned:

- **Pre-send evidence.** The `started` attempt row, with its decision, is
  committed before the adapter is called; if it cannot be written nothing is
  sent.
- **Authority.** Only a member holding `ai.inference:run` may send; support
  access never may; a service account of another tenant may not; a refusal
  writes a `denied` tenant audit row and no attempt.
- **Policy.** Each tenant and installation decision denies on its own, before
  anything is sent, and is never turned into a fallback.
- **Admission.** Entitlement and capacity refusals send nothing; a slot is
  released on every exit path, including cancellation.
- **Retry and fallback** within one deadline, each attempt its own row; never
  after a possibly-accepted outcome or an authentication failure.
- **Settlement.** Provider-reported usage is mirrored to the usage outbox in
  the attempt's settlement transaction; estimated usage is not.
- **Usage oversight** (`platform.ai_usage:read`): aggregates of one tenant,
  audited.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import (
    AIWorld,
    MemoryAdmission,
    P,
    Scene,
    admin_scalar,
    attempts,
    runtime,
)
from saas_os.control_plane.inference import service
from saas_os.control_plane.inference.adapters import (
    AdapterError,
    AdapterResult,
    AdapterUsage,
    ErrorCategory,
)
from saas_os.control_plane.inference.config import service as ai_config
from saas_os.control_plane.inference.config import tenant_policy
from saas_os.control_plane.inference.errors import (
    InferenceCapacityExhaustedError,
    InferenceEntitlementDeniedError,
    InferenceInternalError,
    InferenceNotAuthorizedError,
    InferenceOutcomeUnknownError,
    InferencePolicyDeniedError,
    InferenceProviderAuthError,
    InferenceTimeoutError,
)
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.control_plane.inference.usage import read_ai_usage_totals
from saas_os.core.authority import ServiceAccountCaller, UserCaller
from saas_os.core.platform_authority import PlatformNotAuthorizedError
from saas_os.core.rbac.service import approve_support_access, create_support_access_request
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_SECRET_VALUE = "placeholder-credential-value-for-tests"  # pragma: allowlist secret
_PROMPT = "customer ticket 4711: the invoice is wrong"


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
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"AI tables missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Secrets:
        def get(self, name: str) -> str | None:
            return _SECRET_VALUE if name.startswith("AI_TEST_") else None

    monkeypatch.setattr(ai_config, "get_secrets_provider", lambda: _Secrets())


@pytest.fixture
def world() -> Iterator[AIWorld]:
    w = AIWorld()
    try:
        yield w
    finally:
        w.cleanup()


def _request(scene: Scene, classification: str = "tenant_data", **kw: object) -> InferenceRequest:
    return InferenceRequest(
        alias=scene.alias,
        use_case=scene.use_case.name,
        messages=(Message("user", (ContentPart("text", classification, text=_PROMPT),)),),  # type: ignore[arg-type]
        max_output_tokens=256,
        **kw,  # type: ignore[arg-type]
    )


def _ok(text_out: str = "summary", *, usage: AdapterUsage | None = None) -> AdapterResult:
    return AdapterResult(
        text=text_out,
        finish_reason="stop",
        usage=usage or AdapterUsage(input_tokens=11, output_tokens=7),
        model="model-1",
        provider_request_id="req-ok",
    )


def _usage_events(tenant_id: uuid.UUID) -> list[str]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.connect() as conn:
            return sorted(
                conn.execute(
                    text(
                        "SELECT payload->>'metric' FROM core.outbox_events "
                        "WHERE tenant_id = :t AND event_type = 'usage.ingestion'"
                    ),
                    {"t": str(tenant_id)},
                ).scalars()
            )
    finally:
        engine.dispose()


def _denials(tenant_id: uuid.UUID) -> list[str]:
    return [
        row
        for row in [
            admin_scalar(
                "SELECT string_agg(metadata->>'reason', ',' ORDER BY created_at) "
                "FROM core.audit_log WHERE tenant_id = :t AND action = 'ai.inference.run' "
                "AND outcome = 'denied'",
                t=str(tenant_id),
            )
        ]
        if row
    ]


# --- the governed path ---------------------------------------------------------------


async def test_a_governed_call_returns_output_after_its_evidence(world: AIWorld) -> None:
    scene = world.scene()
    seen_rows: list[list[dict]] = []

    class _Observing:
        protocol = "openai_chat_completions"
        protocol_capabilities = (
            service.default_runtime().adapters["openai_chat_completions"].protocol_capabilities
        )

        async def complete(self, request, *, target, credential, egress, deadline):  # type: ignore[no-untyped-def]
            # Pre-send evidence: the row is committed and visible to another
            # connection before anything is sent.
            seen_rows.append(await asyncio.to_thread(attempts, scene.tenant_id))
            assert credential.reveal() == "test-credential"
            return _ok()

    rt, _, gate = runtime(adapter=_Observing())
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.output[0].text == "summary"
    assert result.output[0].classification == "tenant_data"
    assert result.usage.provenance == "provider_reported" and result.attempts == 1
    assert not result.fell_back and result.provider_key == scene.destinations[0].provider_key

    (before,) = seen_rows
    assert [(r["state"], r["attempt_number"]) for r in before] == [("started", 1)]
    decision = before[0]["decision"]
    assert decision["classification"] == "tenant_data"
    assert decision["use_case"] == scene.use_case.name

    (row,) = attempts(scene.tenant_id)
    assert row["state"] == "succeeded" and row["usage_provenance"] == "provider_reported"
    assert (row["input_tokens"], row["output_tokens"]) == (11, 7)
    assert row["provider_request_id"] == "req-ok" and row["actor_user_id"] == scene.member.user_id
    # The ledger holds no content.
    assert _PROMPT not in repr(row) and "summary" not in repr(row)
    # Provider-reported usage is mirrored, in the settlement transaction.
    assert _usage_events(scene.tenant_id) == ["ai.input_tokens", "ai.output_tokens"]
    assert gate.admitted == gate.released == 1


async def test_estimated_usage_is_recorded_but_never_mirrored(world: AIWorld) -> None:
    scene = world.scene()
    rt, _, _ = runtime([_ok(usage=AdapterUsage())])
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.usage.provenance == "estimated" and result.usage.input_tokens
    assert attempts(scene.tenant_id)[0]["usage_provenance"] == "estimated"
    assert _usage_events(scene.tenant_id) == []


async def test_if_the_evidence_cannot_be_written_nothing_is_sent(
    world: AIWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    scene = world.scene()
    rt, fake, gate = runtime()

    def broken(*args: object, **kwargs: object) -> uuid.UUID:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(service, "_begin_attempt", broken)
    with pytest.raises(InferenceInternalError, match="attempt_not_recorded"):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == [] and attempts(scene.tenant_id) == []
    assert gate.released == gate.admitted == 1


# --- authority ---------------------------------------------------------------------------


async def test_a_member_without_the_permission_is_refused_and_recorded(world: AIWorld) -> None:
    scene = world.scene()
    reader = world.member(scene.tenant_id, ("ai.policy", "read"))
    rt, fake, gate = runtime()
    with pytest.raises(InferenceNotAuthorizedError):
        await service.run_inference(
            reader, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == [] and attempts(scene.tenant_id) == [] and gate.admitted == 0
    assert _denials(scene.tenant_id) == ["not_authorized"]


async def test_authority_is_checked_before_the_request_is_examined(world: AIWorld) -> None:
    """Contracts section 5, step 1: an unauthorized caller gets
    `caller_not_authorized` even for an invalid request, and leaves no
    policy row."""
    scene = world.scene()
    outsider = world.member(scene.tenant_id, ("ai.policy", "read"))
    rt, fake, _ = runtime()
    invalid = InferenceRequest(
        alias=scene.alias,
        use_case="not.registered",
        messages=(Message("user", (ContentPart("text", "secret", text="x"),)),),  # type: ignore[arg-type]
        max_output_tokens=10,
    )
    with pytest.raises(InferenceNotAuthorizedError):
        await service.run_inference(
            outsider, tenant_id=scene.tenant_id, request=invalid, runtime=rt
        )
    assert _denials(scene.tenant_id) == ["not_authorized"]
    assert fake.calls == []


async def test_support_access_can_never_send_tenant_data(world: AIWorld) -> None:
    scene = world.scene()
    approver = world.member(scene.tenant_id, ("support_access_request", "approve"))
    engineer = world.user()
    request = create_support_access_request(
        caller=UserCaller(engineer),
        tenant_id=scene.tenant_id,
        reason="AI-D support boundary",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    approve_support_access(caller=approver, tenant_id=scene.tenant_id, request_id=request.id)
    rt, fake, _ = runtime()
    with pytest.raises(InferenceNotAuthorizedError):
        await service.run_inference(
            UserCaller(engineer), tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == []


async def test_a_service_account_of_another_tenant_is_refused(world: AIWorld) -> None:
    scene = world.scene()
    other = world.tenant()
    rt, fake, _ = runtime()
    with pytest.raises(InferenceNotAuthorizedError):
        await service.run_inference(
            ServiceAccountCaller(uuid.uuid4(), other),
            tenant_id=scene.tenant_id,
            request=_request(scene),
            runtime=rt,
        )
    assert fake.calls == []


async def test_a_member_of_one_tenant_cannot_send_as_another(world: AIWorld) -> None:
    scene = world.scene()
    stranger_scene = world.scene()
    rt, fake, _ = runtime()
    with pytest.raises(InferenceNotAuthorizedError):
        await service.run_inference(
            stranger_scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == []


# --- policy -------------------------------------------------------------------------------


async def test_a_classification_above_the_tenant_grant_is_denied(world: AIWorld) -> None:
    scene = world.scene(max_classification="sensitive", grant=("none", "tenant_data"))
    rt, fake, gate = runtime()
    with pytest.raises(InferencePolicyDeniedError) as caught:
        await service.run_inference(
            scene.member,
            tenant_id=scene.tenant_id,
            request=_request(scene, "sensitive"),
            runtime=rt,
        )
    assert caught.value.reason == "classification_not_granted_for_use_case"
    assert fake.calls == [] and gate.admitted == 0 and attempts(scene.tenant_id) == []
    assert _denials(scene.tenant_id) == ["classification_not_granted_for_use_case"]


async def test_a_disabled_tenant_policy_denies(world: AIWorld) -> None:
    scene = world.scene()
    tenant_policy.set_tenant_ai_policy(scene.tenant_id, enabled=False, caller=scene.manager)
    rt, fake, _ = runtime()
    with pytest.raises(InferencePolicyDeniedError, match="tenant_policy_absent_or_disabled"):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == []


async def test_installation_policy_withdrawn_denies_without_fallback(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    for target in scene.destinations:
        ai_config.set_destination_policy(
            provider_key=target.provider_key,
            classification="tenant_data",
            allowed=False,
            caller=scene.operator,
            reason="withdrawn",
        )
    rt, fake, _ = runtime()
    with pytest.raises(InferencePolicyDeniedError, match="no_eligible_destination"):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == []


async def test_an_unbound_credential_makes_the_destination_ineligible(world: AIWorld) -> None:
    scene = world.scene()
    ai_config.update_provider_endpoint(
        key=scene.destinations[0].provider_key,
        base_url="https://moved.example.net/v1",
        caller=scene.operator,
        reason="moved",
    )
    rt, fake, _ = runtime()
    with pytest.raises(InferencePolicyDeniedError, match="no_eligible_destination"):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == []


# --- admission ----------------------------------------------------------------------------


async def test_entitlement_denial_sends_nothing(world: AIWorld) -> None:
    scene = world.scene()
    rt, fake, gate = runtime(entitled=False)
    with pytest.raises(InferenceEntitlementDeniedError):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == [] and gate.admitted == 0 and attempts(scene.tenant_id) == []


async def test_capacity_exhaustion_sends_nothing(world: AIWorld) -> None:
    scene = world.scene()
    rt, fake, _ = runtime(admission=MemoryAdmission(limit=0))
    with pytest.raises(InferenceCapacityExhaustedError):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == [] and attempts(scene.tenant_id) == []


async def test_cancellation_interrupts_the_attempt_and_releases_the_slot(world: AIWorld) -> None:
    scene = world.scene()
    entered = asyncio.Event()

    class _Hanging:
        protocol = "openai_chat_completions"
        protocol_capabilities = (
            service.default_runtime().adapters["openai_chat_completions"].protocol_capabilities
        )

        async def complete(self, request, *, target, credential, egress, deadline):  # type: ignore[no-untyped-def]
            entered.set()
            await asyncio.sleep(3600)

    rt, _, gate = runtime(adapter=_Hanging())
    task = asyncio.create_task(
        service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    )
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    (row,) = attempts(scene.tenant_id)
    assert row["state"] == "interrupted" and row["possibly_accepted"] is True
    assert gate.admitted == gate.released == 1


# --- retry and fallback -------------------------------------------------------------------


async def test_a_not_processed_error_is_retried_as_a_new_attempt(world: AIWorld) -> None:
    scene = world.scene()
    rt, fake, _ = runtime(
        [
            AdapterError(
                ErrorCategory.RATE_LIMITED, possibly_accepted=False, retry_after_seconds=0.1
            ),
            _ok(),
        ]
    )
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.attempts == 2 and not result.fell_back and len(fake.calls) == 2
    assert [(r["state"], r["error_category"]) for r in attempts(scene.tenant_id)] == [
        ("failed", "rate_limited"),
        ("succeeded", None),
    ]


async def test_exhausted_retries_fall_back_to_the_next_destination(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    overloaded = AdapterError(ErrorCategory.PROVIDER_OVERLOADED, possibly_accepted=False)
    rt, fake, _ = runtime([overloaded, overloaded, overloaded, _ok()])
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.fell_back and result.attempts == 4
    assert result.provider_key == scene.destinations[1].provider_key
    rows = attempts(scene.tenant_id)
    assert [r["provider_key"] for r in rows] == [scene.destinations[0].provider_key] * 3 + [
        scene.destinations[1].provider_key
    ]
    assert len({r["request_id"] for r in rows}) == 1


async def test_an_authentication_failure_is_never_hidden_by_a_fallback(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    rt, fake, _ = runtime(
        [AdapterError(ErrorCategory.PROVIDER_AUTH, possibly_accepted=False, status_code=401), _ok()]
    )
    with pytest.raises(InferenceProviderAuthError):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert len(fake.calls) == 1 and len(attempts(scene.tenant_id)) == 1


@pytest.mark.parametrize(
    ("category", "error"),
    [
        (ErrorCategory.TIMEOUT, InferenceTimeoutError),
        (ErrorCategory.PROVIDER_ERROR, InferenceOutcomeUnknownError),
    ],
)
async def test_a_possibly_accepted_outcome_is_never_retried(
    world: AIWorld, category: ErrorCategory, error: type
) -> None:
    scene = world.scene(destinations=2)
    rt, fake, _ = runtime([AdapterError(category, possibly_accepted=True), _ok()])
    with pytest.raises(error):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    (row,) = attempts(scene.tenant_id)
    assert row["possibly_accepted"] is True and row["usage_provenance"] == "unknown"
    assert len(fake.calls) == 1


# --- abandoned attempts and usage oversight -------------------------------------------------


async def test_a_stale_started_attempt_is_marked_abandoned(world: AIWorld) -> None:
    scene = world.scene()
    stale = uuid.uuid4()
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO control_plane.ai_inference_attempts (id, tenant_id, request_id, "
                    "attempt_number, actor_type, actor_user_id, use_case, alias, provider_key, "
                    "model_id, provider_config_version, model_config_version, "
                    "effective_classification, decision, state, started_at, usage_provenance) "
                    "VALUES (:id, :t, :r, 1, 'user', :u, 'x', 'x', 'x', 'x', 1, 1, 'none', '{}', "
                    "'started', now() - interval '1 day', 'unknown')"
                ),
                {
                    "id": stale,
                    "t": str(scene.tenant_id),
                    "r": uuid.uuid4(),
                    "u": scene.member.user_id,
                },
            )
    finally:
        engine.dispose()
    rt, _, _ = runtime()
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    states = {r["id"]: (r["state"], r["possibly_accepted"]) for r in attempts(scene.tenant_id)}
    assert states[stale] == ("abandoned", True)


async def test_usage_totals_are_aggregates_of_one_tenant_and_audited(world: AIWorld) -> None:
    scene = world.scene()
    other = world.scene()
    rt, _, _ = runtime([_ok(), _ok()])
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    await service.run_inference(
        other.member, tenant_id=other.tenant_id, request=_request(other), runtime=rt
    )
    reader = world.operator(P.AI_USAGE_READ)
    now = datetime.now(UTC)
    totals = await asyncio.to_thread(
        lambda: read_ai_usage_totals(
            caller=reader,
            tenant_id=scene.tenant_id,
            since=now - timedelta(hours=1),
            until=now + timedelta(minutes=1),
        )
    )
    assert [(line.provider_key, line.attempts, line.input_tokens) for line in totals.lines] == [
        (scene.destinations[0].provider_key, 1, 11)
    ]
    # The attempt row (committed before the read) and the completion row;
    # the completion row names the tenant.
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.platform_audit_log WHERE actor_user_id = :u "
            "AND action LIKE 'platform.ai_usage.read%' AND target_id = :t",
            u=str(reader.user_id),
            t=str(scene.tenant_id),
        )
        == 2
    )
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.platform_audit_log WHERE actor_user_id = :u "
            "AND action = 'platform.ai_usage.read' AND target_tenant_id = :t",
            u=str(reader.user_id),
            t=str(scene.tenant_id),
        )
        == 1
    )
    without = world.operator(P.AI_CONFIG_READ)
    with pytest.raises(PlatformNotAuthorizedError):
        read_ai_usage_totals(
            caller=without, tenant_id=scene.tenant_id, since=now - timedelta(hours=1), until=now
        )


# --- accounting (AI-F) ----------------------------------------------------------------------


async def test_a_priced_model_records_a_cost_estimate_with_its_version(world: AIWorld) -> None:
    from decimal import Decimal

    from saas_os.control_plane.inference.config.errors import AIConfigurationError

    scene = world.scene()
    target = scene.destinations[0]
    past = datetime.now(UTC) - timedelta(days=1)
    for version, rate, effective in (
        ("v1", Decimal("1000"), past - timedelta(days=30)),
        ("v2", Decimal("2000"), past),
        ("v3", Decimal("9999"), datetime.now(UTC) + timedelta(days=30)),  # not yet in effect
    ):
        ai_config.set_model_price(
            provider_key=target.provider_key,
            model_id=target.model_id,
            pricing_version=version,
            currency="EUR",
            input_per_million=rate,
            output_per_million=rate,
            effective_from=effective,
            caller=scene.operator,
            reason="prices",
        )
    with pytest.raises(AIConfigurationError, match="pricing_version_exists"):
        ai_config.set_model_price(
            provider_key=target.provider_key,
            model_id=target.model_id,
            pricing_version="v2",
            currency="EUR",
            input_per_million=Decimal("1"),
            output_per_million=Decimal("1"),
            effective_from=past,
            caller=scene.operator,
            reason="rewrite",
        )
    rt, _, _ = runtime([_ok()])  # 11 input + 7 output tokens, provider-reported
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    expected = Decimal("0.03600000")  # 18 tokens at 2000 per million
    assert (result.usage.estimated_cost, result.usage.currency) == (expected, "EUR")
    assert result.usage.pricing_version == "v2"
    (row,) = attempts(scene.tenant_id)
    assert (row["estimated_cost"], row["pricing_version"], row["currency"]) == (
        expected,
        "v2",
        "EUR",
    )


async def test_an_unpriced_model_records_no_cost(world: AIWorld) -> None:
    scene = world.scene()
    rt, _, _ = runtime([_ok()])
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.usage.estimated_cost is None and result.usage.pricing_version is None


async def test_the_soft_token_quota_refuses_before_anything_is_sent(world: AIWorld) -> None:
    import functools

    from saas_os.control_plane.inference.accounting import check_soft_token_quota
    from saas_os.control_plane.inference.errors import InferenceQuotaExceededError

    scene = world.scene()
    rt, fake, gate = runtime([_ok(), _ok()])
    # The real ledger read; a monthly limit of 300 tokens from the plan.
    rt.token_quota = functools.partial(
        check_soft_token_quota, entitlements=lambda t: {"ai.tokens": 300}
    )
    request = InferenceRequest(
        alias=scene.alias,
        use_case=scene.use_case.name,
        messages=(Message("user", (ContentPart("text", "tenant_data", text="hi"),)),),
        max_output_tokens=200,
    )
    await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=request, runtime=rt
    )
    # The first call projected 0 + 1 + 200 <= 300 and recorded 18 tokens. A
    # request projecting 18 + 1 + 290 = 309 > 300 is now refused.
    big = InferenceRequest(
        alias=scene.alias,
        use_case=scene.use_case.name,
        messages=request.messages,
        max_output_tokens=290,
    )
    with pytest.raises(InferenceQuotaExceededError, match="monthly_token_quota"):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=big, runtime=rt
        )
    assert len(fake.calls) == 1 and len(attempts(scene.tenant_id)) == 1
    assert gate.admitted == 1  # refused before admission


async def test_a_required_quota_that_is_not_configured_refuses(world: AIWorld) -> None:
    import functools

    from saas_os.control_plane.inference.accounting import check_soft_token_quota
    from saas_os.control_plane.inference.errors import InferenceQuotaExceededError

    scene = world.scene()
    rt, fake, _ = runtime()
    rt.token_quota = functools.partial(check_soft_token_quota, required=True)
    with pytest.raises(InferenceQuotaExceededError, match="quota_not_configured"):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == []
