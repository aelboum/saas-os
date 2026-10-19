"""AI-D governance -- hermetic checks (ADR-0054 Phase AI-D; ADR-0055).

- Request validation and classification against a registered use case.
- Destination eligibility from a configuration snapshot: every independent
  check denies on its own, a denial is never turned into a fallback, and the
  decision recorded for an eligible destination names what allowed it.
- The use-case registry (Q5): immutable, conflicting re-registration refused,
  registration authorizes nothing.
- Admission: the entitlement gate and the lease-based concurrency gate fail
  closed.
- Error mapping, retry and fallback eligibility; the circuit breaker.
"""

from __future__ import annotations

import dataclasses
import uuid
from typing import Any

import pytest

from saas_os.control_plane.inference import admission, service
from saas_os.control_plane.inference.adapters import AdapterError, ErrorCategory
from saas_os.control_plane.inference.capabilities import Capability
from saas_os.control_plane.inference.errors import (
    InferenceCapacityExhaustedError,
    InferenceEntitlementDeniedError,
    InferenceInternalError,
    InferenceInvalidRequestError,
    InferenceOutcomeUnknownError,
    InferencePolicyDeniedError,
    InferenceProviderAuthError,
    InferenceProviderUnavailableError,
    InferenceRateLimitedError,
    InferenceTimeoutError,
    InferenceUnsupportedCapabilityError,
    UseCaseRegistrationError,
)
from saas_os.control_plane.inference.resolution import (
    Candidate,
    Snapshot,
    evaluate,
    validate_request,
)
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.control_plane.inference.use_cases import (
    UseCase,
    register_use_case,
    registered_use_case,
)
from saas_os.infra.ratelimit import Lease, LeaseRefusal, RateLimitBackendError

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _name() -> str:
    return f"uc.{uuid.uuid4().hex[:10]}"


def _use_case(**overrides: Any) -> UseCase:
    values: dict[str, Any] = {"name": _name(), "max_classification": "tenant_data"}
    values.update(overrides)
    return register_use_case(UseCase(**values))


def _text(text: str, classification: str = "tenant_data", role: str = "user") -> Message:
    return Message(role, (ContentPart("text", classification, text=text),))  # type: ignore[arg-type]


def _request(use_case: UseCase, *messages: Message, **overrides: Any) -> InferenceRequest:
    values: dict[str, Any] = {
        "alias": "chat",
        "use_case": use_case.name,
        "messages": messages or (_text("hello"),),
        "max_output_tokens": 100,
    }
    values.update(overrides)
    return InferenceRequest(**values)


# --- registry ----------------------------------------------------------------------------


def test_registration_is_idempotent_and_refuses_a_conflicting_definition() -> None:
    use_case = _use_case()
    assert register_use_case(UseCase(name=use_case.name, max_classification="tenant_data"))
    with pytest.raises(UseCaseRegistrationError):
        register_use_case(UseCase(name=use_case.name, max_classification="sensitive"))
    assert registered_use_case(use_case.name) == use_case


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": "Bad Name"},
        {"max_classification": "secret"},
        {"part_kinds": frozenset({"audio"})},
        {"max_parts": 0},
        {"max_input_bytes": 10**9},
        {"required_capabilities": frozenset({"text_input"})},
    ],
)
def test_a_malformed_use_case_is_refused(overrides: dict[str, Any]) -> None:
    values: dict[str, Any] = {"name": _name(), "max_classification": "none", **overrides}
    with pytest.raises(UseCaseRegistrationError):
        UseCase(**values)


# --- validation and classification ------------------------------------------------------


def test_effective_classification_is_the_highest_part_and_capabilities_are_implied() -> None:
    use_case = _use_case(max_classification="sensitive")
    validated = validate_request(
        _request(
            use_case,
            _text("be brief", "none", role="system"),
            _text("public", "none"),
            Message(
                "user",
                (
                    ContentPart("text", "tenant_data", text="a"),
                    ContentPart("text", "sensitive", text="b"),
                ),
            ),
            temperature=0.2,
            stop=("END",),
        )
    )
    assert validated.effective_classification == "sensitive"
    assert validated.required_capabilities == {
        Capability.TEXT_INPUT,
        Capability.TEXT_OUTPUT,
        Capability.SYSTEM_INSTRUCTIONS,
        Capability.TEMPERATURE,
        Capability.STOP_SEQUENCES,
    }
    assert validated.system == "be brief"


@pytest.mark.parametrize(
    ("messages", "reason"),
    [
        ((_text("x", "secret"),), "invalid_classification"),
        ((_text("x", ""),), "invalid_classification"),
        ((_text("x", "sensitive"),), "classification_above_use_case_ceiling"),
    ],
)
def test_classification_failures_are_policy_denials(messages: tuple, reason: str) -> None:
    use_case = _use_case(max_classification="tenant_data")
    with pytest.raises(InferencePolicyDeniedError) as caught:
        validate_request(_request(use_case, *messages))
    assert caught.value.reason == reason


def test_an_unregistered_use_case_is_denied() -> None:
    request = InferenceRequest(
        alias="chat", use_case="never.registered", messages=(_text("x"),), max_output_tokens=1
    )
    with pytest.raises(InferencePolicyDeniedError) as caught:
        validate_request(request)
    assert caught.value.reason == "use_case_not_registered"


def test_size_and_part_bounds_of_the_use_case() -> None:
    use_case = _use_case(max_parts=2, max_input_bytes=10)
    with pytest.raises(InferencePolicyDeniedError, match="input_too_large"):
        validate_request(_request(use_case, _text("x" * 11)))
    with pytest.raises(InferencePolicyDeniedError, match="too_many_parts"):
        validate_request(_request(use_case, _text("a"), _text("b", role="assistant"), _text("c")))


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"tools": ("t",)}, InferenceUnsupportedCapabilityError),
        ({"response_format": "json"}, InferenceUnsupportedCapabilityError),
        ({"max_output_tokens": 0}, InferenceInvalidRequestError),
        ({"max_output_tokens": True}, InferenceInvalidRequestError),
        ({"temperature": 3.0}, InferenceInvalidRequestError),
        # Not a number: the typed refusal, never a raw ValueError or TypeError.
        ({"temperature": "warm"}, InferenceInvalidRequestError),
        ({"temperature": object()}, InferenceInvalidRequestError),
        ({"temperature": float("nan")}, InferenceInvalidRequestError),
        ({"stop": ("a", "b", "c", "d", "e")}, InferenceInvalidRequestError),
        ({"client_request_id": "x" * 129}, InferenceInvalidRequestError),
        ({"messages": ()}, InferenceInvalidRequestError),
        (
            {"messages": (Message("tool", (ContentPart("text", "none", text="r"),)),)},
            InferenceUnsupportedCapabilityError,
        ),
        (
            {"messages": (Message("user", (ContentPart("image", "none", image=b""),)),)},
            InferencePolicyDeniedError,  # not an accepted part kind of the use case
        ),
        ({"messages": (_text("a"), _text("b", role="assistant"))}, InferenceInvalidRequestError),
        (
            {"messages": (_text("a"), _text("s", "none", role="system"))},
            InferenceInvalidRequestError,
        ),
    ],
)
def test_unsupported_or_invalid_requests_are_refused(overrides: dict, error: type) -> None:
    use_case = _use_case()
    with pytest.raises(error):
        validate_request(_request(use_case, **overrides))


def test_an_image_part_is_unsupported_even_when_the_use_case_accepts_images() -> None:
    use_case = _use_case(part_kinds=frozenset({"text", "image"}))
    message = Message("user", (ContentPart("image", "none", image=b"\x89PNG"),))
    with pytest.raises(InferenceUnsupportedCapabilityError):
        validate_request(_request(use_case, message))


# --- eligibility ------------------------------------------------------------------------

_ALL_CAPS = frozenset(c.value for c in Capability)
_ADAPTERS = {"openai_chat_completions": frozenset(Capability)}


def _candidate(**overrides: Any) -> Candidate:
    values: dict[str, Any] = {
        "model_ref": uuid.uuid4(),
        "provider_key": "p",
        "protocol": "openai_chat_completions",
        "base_url": "https://api.example.com/v1",
        "credential_ref": "KEY",
        "credential_bound": True,
        "provider_active": True,
        "provider_version": 1,
        "model_id": "m",
        "capabilities": _ALL_CAPS,
        "max_output_tokens": 1000,
        "model_usable": True,
        "model_version": 1,
        "installation_allows": True,
        "tenant_grant": frozenset({"none", "tenant_data"}),
    }
    values.update(overrides)
    return Candidate(**values)


def _snapshot(*candidates: Candidate, **overrides: Any) -> Snapshot:
    values: dict[str, Any] = {
        "tenant_policy_exists": True,
        "tenant_policy_enabled": True,
        "tenant_policy_version": 3,
        "use_case_grant": frozenset({"none", "tenant_data"}),
        "alias_active": True,
        "alias_version": 2,
        "candidates": candidates or (_candidate(),),
    }
    values.update(overrides)
    return Snapshot(**values)


def _evaluate(snapshot: Snapshot, max_output_tokens: int = 100):
    validated = validate_request(_request(_use_case()))
    return evaluate(
        snapshot,
        validated,
        max_output_tokens=max_output_tokens,
        adapter_capabilities=_ADAPTERS,  # type: ignore[arg-type]
    )


def test_an_eligible_destination_carries_its_decision() -> None:
    (eligible,) = _evaluate(_snapshot())
    decision = eligible.decision
    assert decision["classification"] == "tenant_data"
    assert decision["tenant_policy_version"] == 3 and decision["alias_version"] == 2
    assert decision["installation_policy"] is True
    assert "text_input" in decision["capabilities"]  # type: ignore[operator]


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"tenant_policy_exists": False}, "tenant_policy_absent_or_disabled"),
        ({"tenant_policy_enabled": False}, "tenant_policy_absent_or_disabled"),
        ({"use_case_grant": None}, "use_case_not_granted"),
        ({"use_case_grant": frozenset({"none"})}, "classification_not_granted_for_use_case"),
        ({"alias_active": False}, "alias_unavailable"),
    ],
)
def test_each_tenant_level_check_denies_on_its_own(overrides: dict, reason: str) -> None:
    with pytest.raises(InferencePolicyDeniedError) as caught:
        _evaluate(_snapshot(**overrides))
    assert caught.value.reason == reason


@pytest.mark.parametrize(
    "overrides",
    [
        {"provider_active": False},
        {"credential_bound": False},
        {"model_usable": False},
        {"installation_allows": False},
        {"tenant_grant": None},
        {"tenant_grant": frozenset({"none"})},
    ],
)
def test_each_destination_check_makes_it_ineligible(overrides: dict) -> None:
    with pytest.raises(InferencePolicyDeniedError, match="no_eligible_destination"):
        _evaluate(_snapshot(_candidate(**overrides)))
    # ... and only that destination: a valid one after it is still eligible.
    good = _candidate(model_id="good")
    eligible = _evaluate(_snapshot(_candidate(**overrides), good))
    assert [e.candidate.model_id for e in eligible] == ["good"]


def test_capability_or_output_limit_shortfall_is_unsupported_not_denied() -> None:
    with pytest.raises(InferenceUnsupportedCapabilityError):
        _evaluate(_snapshot(_candidate(capabilities=frozenset({"text_input"}))))
    with pytest.raises(InferenceUnsupportedCapabilityError):
        _evaluate(_snapshot(_candidate(max_output_tokens=50)), max_output_tokens=100)
    with pytest.raises(InferenceUnsupportedCapabilityError):
        _evaluate(_snapshot(_candidate(protocol="anthropic_messages")))


def test_alias_order_is_kept() -> None:
    first, second = _candidate(model_id="first"), _candidate(model_id="second")
    assert [e.candidate.model_id for e in _evaluate(_snapshot(first, second))] == [
        "first",
        "second",
    ]


# --- admission --------------------------------------------------------------------------


@pytest.mark.parametrize("value", [False, None, 1, "true"])
def test_entitlement_is_granted_only_by_a_literal_true(value: object) -> None:
    with pytest.raises(InferenceEntitlementDeniedError):
        admission.check_entitlement(uuid.uuid4(), check=lambda t, k: value)  # type: ignore[arg-type,return-value]
    admission.check_entitlement(uuid.uuid4(), check=lambda t, k: k == "ai.inference")


def test_an_unreadable_entitlement_denies() -> None:
    def broken(tenant_id: uuid.UUID, key: str) -> bool:
        raise RuntimeError("database down")

    with pytest.raises(InferenceEntitlementDeniedError, match="entitlement_unavailable"):
        admission.check_entitlement(uuid.uuid4(), check=broken)


class _Leases:
    def __init__(self, outcome: object) -> None:
        self.outcome = outcome
        self.requests: list[tuple[tuple[Any, ...], float]] = []
        self.released: list[Lease] = []

    async def acquire(self, scopes: Any, *, ttl_seconds: float) -> object:
        self.requests.append((tuple(scopes), ttl_seconds))
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome

    async def release(self, lease: Lease) -> None:
        self.released.append(lease)


async def test_admission_takes_a_tenant_and_an_installation_slot_with_a_margin() -> None:
    lease = Lease("id", ("a", "b"))
    leases = _Leases(lease)
    gate = admission.RedisAdmission(
        leases=leases,  # type: ignore[arg-type]
        limits=admission.ConcurrencyLimits(tenant=2, installation=9),
    )
    tenant = uuid.uuid4()
    assert await gate.admit(tenant, ttl_seconds=120) is lease
    ((scopes, ttl),) = leases.requests
    assert [(s.name, s.limit) for s in scopes] == [
        (f"ai_inference:tenant:{tenant}", 2),
        ("ai_inference:global", 9),
    ]
    assert ttl == 120 + admission.LEASE_MARGIN_SECONDS
    await gate.release(lease)
    assert leases.released == [lease]


@pytest.mark.parametrize(
    ("scope", "reason"),
    [
        ("ai_inference:global", "installation_concurrency"),
        ("ai_inference:tenant:x", "tenant_concurrency"),
    ],
)
async def test_a_full_scope_is_capacity_exhausted(scope: str, reason: str) -> None:
    gate = admission.RedisAdmission(
        leases=_Leases(LeaseRefusal(scope)),  # type: ignore[arg-type]
        limits=admission.ConcurrencyLimits(1, 1),
    )
    with pytest.raises(InferenceCapacityExhaustedError) as caught:
        await gate.admit(uuid.uuid4(), ttl_seconds=1)
    assert caught.value.reason == reason


async def test_redis_unavailable_fails_closed() -> None:
    gate = admission.RedisAdmission(
        leases=_Leases(RateLimitBackendError("lease")),  # type: ignore[arg-type]
        limits=admission.ConcurrencyLimits(1, 1),
    )
    with pytest.raises(InferenceInternalError, match="admission_unavailable"):
        await gate.admit(uuid.uuid4(), ttl_seconds=1)


@pytest.mark.parametrize("raw", ["0", "-1", "x", "100001"])
def test_invalid_concurrency_limits_fail_closed(raw: str) -> None:
    with pytest.raises(InferenceInternalError):
        admission.ConcurrencyLimits.from_env({"AI_INFERENCE_TENANT_CONCURRENCY": raw})


def test_concurrency_limit_defaults_are_the_provisional_values() -> None:
    limits = admission.ConcurrencyLimits.from_env({})
    assert (limits.tenant, limits.installation) == (4, 64)


# --- error mapping, retry and fallback --------------------------------------------------


@pytest.mark.parametrize(
    ("category", "accepted", "expected"),
    [
        (ErrorCategory.RATE_LIMITED, False, InferenceRateLimitedError),
        (ErrorCategory.PROVIDER_QUOTA_EXHAUSTED, False, InferenceProviderUnavailableError),
        (ErrorCategory.PROVIDER_AUTH, False, InferenceProviderAuthError),
        (ErrorCategory.TIMEOUT, True, InferenceTimeoutError),
        (ErrorCategory.PROVIDER_ERROR, True, InferenceOutcomeUnknownError),
        (ErrorCategory.MALFORMED_RESPONSE, True, InferenceOutcomeUnknownError),
    ],
)
def test_adapter_errors_map_to_consumer_categories(
    category: ErrorCategory, accepted: bool, expected: type
) -> None:
    error = service._consumer_error(  # pyright: ignore[reportPrivateUsage]
        AdapterError(category, possibly_accepted=accepted, provider_request_id="req-1"),
        request_id=uuid.uuid4(),
    )
    assert type(error) is expected and error.provider_request_id == "req-1"


def test_retry_and_fallback_sets() -> None:
    never = service._NEVER_FALLBACK  # pyright: ignore[reportPrivateUsage]
    assert ErrorCategory.PROVIDER_AUTH in never and ErrorCategory.ENDPOINT_SECURITY in never
    retryable = service._RETRYABLE  # pyright: ignore[reportPrivateUsage]
    assert not retryable & never
    assert (
        ErrorCategory.RATE_LIMITED in retryable and ErrorCategory.PROVIDER_OVERLOADED in retryable
    )
    # An exhausted provider account is not retried, but may fall back.
    assert ErrorCategory.PROVIDER_QUOTA_EXHAUSTED not in retryable | never


async def test_the_circuit_opens_after_the_threshold_and_closes_on_success() -> None:
    breaker = service.CircuitBreaker(threshold=2, open_seconds=60)
    assert await breaker.failure("p") is False
    assert not await breaker.is_open("p")
    assert await breaker.failure("p") is True
    assert await breaker.is_open("p") and not await breaker.is_open("q")
    await breaker.success("p")
    assert not await breaker.is_open("p")


async def test_streaming_is_refused_for_every_request() -> None:
    with pytest.raises(InferenceUnsupportedCapabilityError, match="streaming_not_enabled"):
        await service.stream_inference(object(), tenant_id=uuid.uuid4(), request=None)  # type: ignore[arg-type]


def test_the_request_types_never_show_content() -> None:
    part = ContentPart("text", "sensitive", text="secret customer text")
    request = InferenceRequest(
        alias="a", use_case="u", messages=(Message("user", (part,)),), max_output_tokens=1
    )
    assert "secret customer text" not in repr(request)
    assert "secret customer text" not in repr(dataclasses.replace(part))


# --- tenant preferences (AI-E) ----------------------------------------------------------


@pytest.mark.parametrize(
    ("handling", "preferences", "eligible"),
    [
        ({}, {}, True),  # no requirement: nothing to meet
        ({}, {"allowed_residency": ("eu",)}, False),  # undeclared fails
        ({"residency": ["eu"]}, {"allowed_residency": ("eu", "ch")}, True),
        ({"residency": ["eu", "us"]}, {"allowed_residency": ("eu",)}, False),
        ({"residency": []}, {"allowed_residency": ("eu",)}, False),
        ({"retention_days": 30}, {"max_retention_days": 30}, True),
        ({"retention_days": 31}, {"max_retention_days": 30}, False),
        ({"retention_days": None}, {"max_retention_days": 30}, False),
        ({"retention_days": True}, {"max_retention_days": 30}, False),
        ({"training_use": False}, {"exclude_training_use": True}, True),
        ({"training_use": True}, {"exclude_training_use": True}, False),
        ({}, {"exclude_training_use": True}, False),
    ],
)
def test_preferences_are_met_only_by_declared_handling(
    handling: dict, preferences: dict, eligible: bool
) -> None:
    from saas_os.control_plane.inference.config.tenant_policy import TenantAIPreferencesView
    from saas_os.control_plane.inference.resolution import meets_preferences

    assert meets_preferences(handling, TenantAIPreferencesView(**preferences)) is eligible


def test_preferences_only_narrow_eligibility() -> None:
    from saas_os.control_plane.inference.config.tenant_policy import TenantAIPreferencesView

    strict = TenantAIPreferencesView(allowed_residency=("eu",), version=4)
    eu = _candidate(model_id="eu", data_handling={"residency": ["eu"]})
    us = _candidate(model_id="us", data_handling={"residency": ["us"]})
    eligible = _evaluate(_snapshot(us, eu, preferences=strict))
    assert [e.candidate.model_id for e in eligible] == ["eu"]
    assert eligible[0].decision["preferences_version"] == 4
    with pytest.raises(InferencePolicyDeniedError, match="no_eligible_destination"):
        _evaluate(_snapshot(us, preferences=strict))
    # A preference never revives a destination that policy excluded.
    excluded = _candidate(installation_allows=False, data_handling={"residency": ["eu"]})
    with pytest.raises(InferencePolicyDeniedError):
        _evaluate(_snapshot(excluded, preferences=strict))


def test_the_adr_0013_gate_is_consulted_and_can_veto(monkeypatch: pytest.MonkeyPatch) -> None:
    """ADR-0054 D1 / ADR-0055 section 3: the data authorization evaluator is
    called for every candidate; its denial alone makes a destination
    ineligible, even when routing found nothing wrong."""
    from saas_os.control_plane.data_authorization import DataAuthorizationOutcome, DataDenialReason
    from saas_os.control_plane.inference import resolution

    seen: list[tuple[str, str, str]] = []
    real = resolution.evaluate_data_authorization

    def recording(request, **kwargs):  # type: ignore[no-untyped-def]
        seen.append((request.provider, request.purpose, request.data_classification))
        decision = real(request, **kwargs)
        assert decision.outcome is DataAuthorizationOutcome.ALLOW
        return decision

    monkeypatch.setattr(resolution, "evaluate_data_authorization", recording)
    (eligible,) = _evaluate(_snapshot())
    assert eligible.decision["data_authorization"] == "allow"
    assert seen and seen[0][0] == "p" and seen[0][2] == "tenant_data"

    def deny(request, **kwargs):  # type: ignore[no-untyped-def]
        decision = real(request, **kwargs)
        return dataclasses.replace(
            decision,
            outcome=DataAuthorizationOutcome.DENY,
            reason=DataDenialReason.PROVIDER_NOT_PERMITTED,
        )

    monkeypatch.setattr(resolution, "evaluate_data_authorization", deny)
    with pytest.raises(InferencePolicyDeniedError, match="no_eligible_destination"):
        _evaluate(_snapshot())
