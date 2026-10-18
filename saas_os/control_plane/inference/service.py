"""Governed inference: `run_inference` (ADR-0054 sections 4, 7, 8, 8a; ADR-0055;
AI-INFERENCE-CONTRACTS sections 4, 5, 7). Products reach it only through
`saas_os.inference`.

Order of a call -- nothing is sent before every step before egress succeeded:

1. **Authority** -- a `UserCaller` or a `ServiceAccountCaller` of the tenant
   (anything else: `CallerTypeError` / not authorized); the tenant is open;
   the caller holds `ai.inference:run` at the tenant (`can()`; never support
   access). A refusal writes a `denied` row to the tenant's audit log.
2. **Validation and classification** -- against the registered use case.
3. **Resolution and eligibility** -- tenant policy, grants, installation
   policy, binding, lifecycle, capabilities (`resolution.evaluate`). A policy
   denial writes a `denied` tenant audit row with its reason code.
4. **Admission** -- entitlement, then the soft token quota, then one
   concurrency slot (`admission`). An entitlement refusal writes a `denied`
   tenant audit row with its reason code; quota and capacity refusals do not.

Denial rows are written in their own transaction after the refusal is
decided (`_record_denied`). The refusal is enforced whether or not its row is
written: if the write fails, `ai_inference_denial_unrecorded` is logged with
the exception type only, and the caller still gets the refusal. Their
metadata is the reason code only.
5. **Attempt** -- one tenant transaction: re-authorize the caller, re-evaluate
   this destination against fresh configuration, insert the `started`
   attempt row with its decision; commit. Only then is the credential handed
   to the adapter and the request sent (pre-send evidence, Q10).
6. **Settlement** -- one tenant transaction: finalize the attempt row; for
   provider-reported usage, append `ai.input_tokens` / `ai.output_tokens`
   usage events (outbox) in the same transaction. The output is returned only
   after this commits.
7. **Retry and fallback** -- within one total deadline computed once: at most
   `MAX_RETRIES` retries of the same destination for errors the provider
   declared *not processed*; then the next eligible candidate, each tried at
   most once more and re-authorized. Never after a possibly-accepted outcome,
   never after an authentication or endpoint-security failure, never after a
   policy denial.

Logs carry identifiers, categories and durations only -- never content,
credentials or provider bodies. Streaming is not available (contracts
section 6.6): `stream_inference` refuses every request.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import math
import random
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Protocol
from urllib.parse import urlsplit

from saas_os.control_plane.inference.accounting import (
    CostEstimate,
    check_soft_token_quota,
    estimate_cost,
    price_in_effect,
)
from saas_os.control_plane.inference.adapters import (
    AdapterError,
    AdapterMessage,
    AdapterRequest,
    AdapterResult,
    AnthropicMessagesAdapter,
    Capability,
    EgressClient,
    ErrorCategory,
    GeminiGenerateContentAdapter,
    OpaqueCredential,
    OpenAICompatibleAdapter,
    ProviderAdapter,
    ResolvedTarget,
    error_from_egress,
)
from saas_os.control_plane.inference.admission import Admission, RedisAdmission, check_entitlement
from saas_os.control_plane.inference.attempts import AIInferenceAttempt, AttemptState
from saas_os.control_plane.inference.credentials import resolve_ai_credential
from saas_os.control_plane.inference.egress_config import ai_egress_settings
from saas_os.control_plane.inference.errors import (
    InferenceConnectionError,
    InferenceEndpointSecurityError,
    InferenceEntitlementDeniedError,
    InferenceError,
    InferenceInternalError,
    InferenceInvalidRequestError,
    InferenceNotAuthorizedError,
    InferenceOutcomeUnknownError,
    InferencePolicyDeniedError,
    InferenceProviderAuthError,
    InferenceProviderUnavailableError,
    InferenceRateLimitedError,
    InferenceResponseLimitError,
    InferenceTimeoutError,
    InferenceUnsupportedCapabilityError,
)
from saas_os.control_plane.inference.permissions import AI_INFERENCE
from saas_os.control_plane.inference.resolution import (
    EligibleCandidate,
    ValidatedRequest,
    evaluate,
    load_snapshot,
    validate_request,
)
from saas_os.control_plane.inference.types import (
    ContentPart,
    InferenceRequest,
    InferenceResult,
    UsageReport,
)
from saas_os.core.audit_log import ActorType, AuditOutcome, record
from saas_os.core.authority import ServiceAccountCaller, UserCaller, require_caller
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import authorize_caller
from saas_os.core.tenancy import lock_open_tenant, require_open_tenant
from saas_os.core.usage import ingest_event
from saas_os.infra.db import Session, select, tenant_session_scope, update
from saas_os.infra.egress import (
    Deadline,
    EgressConfigurationError,
    EgressError,
    StrictEgressClient,
)
from saas_os.infra.ratelimit import SharedCircuitBreaker, get_ratelimit_config

logger = logging.getLogger(__name__)

OPERATION = "ai_inference.run"
MAX_RETRIES = 2
_BACKOFF_BASE_SECONDS = 0.5
_BACKOFF_CAP_SECONDS = 8.0
ABANDON_MARGIN_SECONDS = 300.0
INPUT_TOKENS_METRIC = "ai.input_tokens"
OUTPUT_TOKENS_METRIC = "ai.output_tokens"
_AUDIT_RESOURCE = "ai_inference"

_RETRYABLE = {
    ErrorCategory.RATE_LIMITED,
    ErrorCategory.PROVIDER_OVERLOADED,
    ErrorCategory.TRANSIENT_PRE_ACCEPTANCE,
    ErrorCategory.PROVIDER_ERROR,
}
_NEVER_FALLBACK = {
    ErrorCategory.PROVIDER_AUTH,
    ErrorCategory.ENDPOINT_SECURITY,
    ErrorCategory.INVALID_REQUEST,
    ErrorCategory.RESPONSE_TOO_LARGE,
    ErrorCategory.MALFORMED_RESPONSE,
    ErrorCategory.TIMEOUT,
}


# --- runtime (adapters, egress, admission) ------------------------------------------


class Circuit(Protocol):
    """Provider circuit breaking (ADR-0054 section 8): skipped while open."""

    async def is_open(self, name: str) -> bool: ...

    async def failure(self, name: str) -> bool: ...

    async def success(self, name: str) -> None: ...


@dataclass
class CircuitBreaker:
    """An in-process circuit, for tests and single-instance use: after
    `threshold` consecutive overloaded or pre-acceptance failures the
    provider is skipped for `open_seconds`; a success closes it. The default
    runtime uses `SharedCircuitBreaker` (Redis), shared by all instances."""

    threshold: int = 5
    open_seconds: float = 30.0
    _failures: dict[str, int] = field(default_factory=dict)
    _open_until: dict[str, float] = field(default_factory=dict)

    async def is_open(self, name: str) -> bool:
        return self._open_until.get(name, 0.0) > time.monotonic()

    async def failure(self, name: str) -> bool:
        count = self._failures.get(name, 0) + 1
        self._failures[name] = count
        if count >= self.threshold:
            self._open_until[name] = time.monotonic() + self.open_seconds
            self._failures[name] = 0
            return True
        return False

    async def success(self, name: str) -> None:
        self._failures.pop(name, None)
        self._open_until.pop(name, None)


def _shared_circuit() -> Circuit:
    config = get_ratelimit_config()
    return SharedCircuitBreaker(
        redis_url=config.redis_url,
        timeout_seconds=config.redis_timeout_seconds,
        key_prefix=f"{config.key_prefix}:circuit:ai_provider",
    )


EgressFactory = Callable[[EligibleCandidate], EgressClient]


def _default_egress(eligible: EligibleCandidate) -> EgressClient:
    settings = ai_egress_settings()
    parts = urlsplit(eligible.candidate.base_url)
    port = parts.port if parts.port is not None else 443
    policy = dataclasses.replace(
        settings.policy,
        allowed_ports=frozenset({port}),
        trusted_endpoints=eligible.candidate.trusted_endpoints,
    )
    return StrictEgressClient(policy)


def _default_credential(name: str) -> OpaqueCredential | None:
    # Only a credential provisioned for AI use resolves; anything else is
    # unavailable, and the call fails closed before any content is sent.
    value = resolve_ai_credential(name)
    return OpaqueCredential(value) if value else None


@dataclass
class InferenceRuntime:
    adapters: Mapping[str, ProviderAdapter]
    egress: EgressFactory = _default_egress
    admission: Admission = field(default_factory=RedisAdmission)
    entitlement: Callable[[uuid.UUID, str], bool] | None = None
    token_quota: Callable[..., None] = check_soft_token_quota
    credential: Callable[[str], OpaqueCredential | None] = _default_credential
    circuit: Circuit = field(default_factory=CircuitBreaker)
    total_deadline_seconds: float | None = None
    sleep: Callable[[float], object] = asyncio.sleep

    def adapter_capabilities(self) -> dict[str, frozenset[Capability]]:
        return {name: a.protocol_capabilities for name, a in self.adapters.items()}


_default: InferenceRuntime | None = None


def default_runtime() -> InferenceRuntime:
    global _default
    if _default is None:
        _default = InferenceRuntime(
            adapters={
                OpenAICompatibleAdapter.protocol: OpenAICompatibleAdapter(),
                AnthropicMessagesAdapter.protocol: AnthropicMessagesAdapter(),
                GeminiGenerateContentAdapter.protocol: GeminiGenerateContentAdapter(),
            },
            circuit=_shared_circuit(),
        )
    return _default


def register_adapter(adapter: ProviderAdapter) -> None:
    """Add a protocol adapter to the default runtime (AI-G)."""
    default_runtime().adapters = {**default_runtime().adapters, adapter.protocol: adapter}


# --- steps ---------------------------------------------------------------------------


def _actor(
    caller: UserCaller | ServiceAccountCaller,
) -> tuple[str, uuid.UUID | None, uuid.UUID | None]:
    if isinstance(caller, UserCaller):
        return "user", caller.user_id, None
    return "service_account", None, caller.service_account_id


def _record_denied(
    tenant_id: uuid.UUID,
    caller: UserCaller | ServiceAccountCaller,
    *,
    reason: str,
    request_id: uuid.UUID,
) -> None:
    """Best effort: called only after a refusal is decided, and never turns it
    into an allow. A failed write is logged (`ai_inference_denial_unrecorded`,
    exception type only) and swallowed so the caller still gets the refusal."""
    actor_type, user_id, sa_id = _actor(caller)
    try:
        record(
            tenant_id=tenant_id,
            actor_type=ActorType.USER if actor_type == "user" else ActorType.SERVICE_ACCOUNT,
            actor_user_id=user_id,
            actor_service_account_id=sa_id,
            action="ai.inference.run",
            resource_type=_AUDIT_RESOURCE,
            resource_id=str(request_id),
            outcome=AuditOutcome.DENIED,
            metadata={"reason": reason},
        )
    except Exception as exc:  # noqa: BLE001 -- the refusal stands without its row
        logger.warning("ai_inference_denial_unrecorded", extra={"error_type": type(exc).__name__})


def _authorize(
    session: Session, caller: UserCaller | ServiceAccountCaller, tenant_id: uuid.UUID
) -> None:
    lock_open_tenant(session, tenant_id)
    authorize_caller(
        caller,
        session=session,
        operation=OPERATION,
        tenant_id=tenant_id,
        resource=AI_INFERENCE,
        action="run",
    )


def _authorize_in_tenant(caller: UserCaller | ServiceAccountCaller, tenant_id: uuid.UUID) -> None:
    with tenant_session_scope(tenant_id) as session:
        _authorize(session, caller, tenant_id)


def _abandon_stale(session: Session, tenant_id: uuid.UUID, older_than: datetime) -> None:
    """Attempts left `started` by a process that died: `abandoned`,
    possibly accepted, usage unknown (reconciled in AI-F)."""
    now = datetime.now(UTC)
    session.execute(
        update(AIInferenceAttempt)
        .where(
            AIInferenceAttempt.tenant_id == tenant_id,
            AIInferenceAttempt.state == AttemptState.STARTED.value,
            AIInferenceAttempt.started_at < older_than,
        )
        .values(
            state=AttemptState.ABANDONED.value,
            finished_at=now,
            error_category="abandoned",
            possibly_accepted=True,
            usage_provenance="unknown",
        )
    )


def _resolve(
    caller: UserCaller | ServiceAccountCaller,
    tenant_id: uuid.UUID,
    validated: ValidatedRequest,
    request: InferenceRequest,
    runtime: InferenceRuntime,
    *,
    abandon_before: datetime,
) -> tuple[EligibleCandidate, ...]:
    with tenant_session_scope(tenant_id) as session:
        _authorize(session, caller, tenant_id)
        _abandon_stale(session, tenant_id, abandon_before)
        snapshot = load_snapshot(
            session,
            tenant_id,
            alias=request.alias,
            use_case=request.use_case,
            classification=validated.effective_classification,
        )
    return evaluate(
        snapshot,
        validated,
        max_output_tokens=request.max_output_tokens,
        adapter_capabilities=runtime.adapter_capabilities(),
    )


def _begin_attempt(
    caller: UserCaller | ServiceAccountCaller,
    tenant_id: uuid.UUID,
    validated: ValidatedRequest,
    request: InferenceRequest,
    runtime: InferenceRuntime,
    eligible: EligibleCandidate,
    *,
    request_id: uuid.UUID,
    attempt_number: int,
) -> uuid.UUID:
    """Re-authorize, re-evaluate this destination on fresh configuration,
    and commit the `started` row. Raises if anything changed so that the
    destination is no longer allowed."""
    actor_type, user_id, sa_id = _actor(caller)
    with tenant_session_scope(tenant_id) as session:
        _authorize(session, caller, tenant_id)
        snapshot = load_snapshot(
            session,
            tenant_id,
            alias=request.alias,
            use_case=request.use_case,
            classification=validated.effective_classification,
        )
        fresh = evaluate(
            snapshot,
            validated,
            max_output_tokens=request.max_output_tokens,
            adapter_capabilities=runtime.adapter_capabilities(),
        )
        current = next(
            (e for e in fresh if e.candidate.model_ref == eligible.candidate.model_ref), None
        )
        if current is None:
            raise InferencePolicyDeniedError("destination_no_longer_eligible")
        candidate = current.candidate
        if (
            candidate.provider_version != eligible.candidate.provider_version
            or candidate.base_url != eligible.candidate.base_url
            or candidate.credential_ref != eligible.candidate.credential_ref
        ):
            raise InferencePolicyDeniedError("destination_changed")
        attempt = AIInferenceAttempt(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            request_id=request_id,
            attempt_number=attempt_number,
            actor_type=actor_type,
            actor_user_id=user_id,
            actor_service_account_id=sa_id,
            use_case=validated.use_case.name,
            alias=request.alias,
            provider_key=candidate.provider_key,
            model_id=candidate.model_id,
            provider_config_version=candidate.provider_version,
            model_config_version=candidate.model_version,
            effective_classification=validated.effective_classification,
            decision=current.decision,
            state=AttemptState.STARTED.value,
            started_at=datetime.now(UTC),
            usage_provenance="unknown",
        )
        session.add(attempt)
        session.flush()
        return attempt.id


@dataclass(frozen=True)
class _Settlement:
    state: AttemptState
    error_category: str | None = None
    possibly_accepted: bool = False
    output_delivered: bool = False
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_input_tokens: int | None = None
    cache_write_tokens: int | None = None
    provenance: str = "unknown"
    provider_request_id: str | None = None
    model_ref: uuid.UUID | None = None


def _settle(
    tenant_id: uuid.UUID, attempt_id: uuid.UUID, outcome: _Settlement
) -> CostEstimate | None:
    now = datetime.now(UTC)
    with tenant_session_scope(tenant_id) as session:
        row = session.execute(
            select(AIInferenceAttempt).where(AIInferenceAttempt.id == attempt_id).with_for_update()
        ).scalar_one()
        if row.state != AttemptState.STARTED.value:
            return None  # already settled or abandoned
        cost: CostEstimate | None = None
        row.state = outcome.state.value
        row.error_category = outcome.error_category
        row.possibly_accepted = outcome.possibly_accepted
        row.output_delivered = outcome.output_delivered
        row.finished_at = now
        row.duration_ms = int((now - row.started_at).total_seconds() * 1000)
        row.input_tokens = outcome.input_tokens
        row.output_tokens = outcome.output_tokens
        row.cached_input_tokens = outcome.cached_input_tokens
        row.cache_write_tokens = outcome.cache_write_tokens
        row.usage_provenance = outcome.provenance
        if outcome.model_ref is not None and outcome.provenance != "unknown":
            cost = estimate_cost(
                price_in_effect(session, outcome.model_ref, now),
                input_tokens=outcome.input_tokens,
                output_tokens=outcome.output_tokens,
                cached_input_tokens=outcome.cached_input_tokens,
            )
            if cost is not None:
                row.estimated_cost = cost.amount
                row.currency = cost.currency
                row.pricing_version = cost.pricing_version
        row.provider_request_id = (
            outcome.provider_request_id or None
        ) and outcome.provider_request_id[:255]
        session.flush()
        if outcome.provenance == "provider_reported":
            # Mirrored to the usage ledger in this same transaction (outbox);
            # unknown or estimated usage is never mirrored as a number.
            if outcome.input_tokens is not None:
                ingest_event(session, tenant_id, INPUT_TOKENS_METRIC, Decimal(outcome.input_tokens))
            if outcome.output_tokens is not None:
                ingest_event(
                    session, tenant_id, OUTPUT_TOKENS_METRIC, Decimal(outcome.output_tokens)
                )
    return cost


def _settle_failure(tenant_id: uuid.UUID, attempt_id: uuid.UUID, outcome: _Settlement) -> bool:
    """`_settle()` for an attempt that did not succeed. A database error is
    logged and reported as `False`, never raised: the caller then raises the
    error it was already handling (a provider error, `CancelledError`, an
    internal error) instead of a raw database exception. The attempt stays
    `started` and is marked abandoned at the tenant's next request."""
    try:
        _settle(tenant_id, attempt_id, outcome)
    except Exception as exc:  # noqa: BLE001 -- the original outcome must reach the caller
        logger.warning("ai_inference_settlement_failed", extra={"error_type": type(exc).__name__})
        return False
    return True


def _estimate(byte_count: int) -> int:
    return max(1, math.ceil(byte_count / 4))


def _usage_settlement(
    result: AdapterResult, validated: ValidatedRequest, model_ref: uuid.UUID
) -> _Settlement:
    usage = result.usage
    if usage.input_tokens is not None or usage.output_tokens is not None:
        return _Settlement(
            AttemptState.SUCCEEDED,
            output_delivered=True,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cached_input_tokens=usage.cached_input_tokens,
            cache_write_tokens=usage.cache_write_tokens,
            provenance="provider_reported",
            provider_request_id=result.provider_request_id,
            model_ref=model_ref,
        )
    return _Settlement(
        AttemptState.SUCCEEDED,
        output_delivered=True,
        input_tokens=_estimate(validated.input_bytes),
        output_tokens=_estimate(len(result.text.encode("utf-8"))),
        provenance="estimated",
        provider_request_id=result.provider_request_id,
        model_ref=model_ref,
    )


def _consumer_error(err: AdapterError, **ids: object) -> InferenceError:
    kwargs = {
        "request_id": ids.get("request_id"),
        "attempt_id": ids.get("attempt_id"),
        "provider_request_id": err.provider_request_id,
    }
    if err.possibly_accepted and err.category is not ErrorCategory.RESPONSE_TOO_LARGE:
        if err.category is ErrorCategory.TIMEOUT:
            return InferenceTimeoutError("possibly_accepted", **kwargs)  # type: ignore[arg-type]
        return InferenceOutcomeUnknownError(err.category.value, **kwargs)  # type: ignore[arg-type]
    mapping: dict[ErrorCategory, type[InferenceError]] = {
        ErrorCategory.INVALID_REQUEST: InferenceInvalidRequestError,
        ErrorCategory.UNSUPPORTED_CAPABILITY: InferenceUnsupportedCapabilityError,
        ErrorCategory.PROVIDER_AUTH: InferenceProviderAuthError,
        ErrorCategory.RATE_LIMITED: InferenceRateLimitedError,
        ErrorCategory.PROVIDER_OVERLOADED: InferenceProviderUnavailableError,
        ErrorCategory.PROVIDER_ERROR: InferenceProviderUnavailableError,
        ErrorCategory.TRANSIENT_PRE_ACCEPTANCE: InferenceConnectionError,
        ErrorCategory.TIMEOUT: InferenceTimeoutError,
        ErrorCategory.ENDPOINT_SECURITY: InferenceEndpointSecurityError,
        ErrorCategory.RESPONSE_TOO_LARGE: InferenceResponseLimitError,
        ErrorCategory.MALFORMED_RESPONSE: InferenceOutcomeUnknownError,
    }
    error = mapping[err.category](err.category.value, **kwargs)  # type: ignore[arg-type]
    error.retry_after = err.retry_after_seconds
    return error


def _adapter_request(validated: ValidatedRequest, request: InferenceRequest) -> AdapterRequest:
    return AdapterRequest(
        messages=tuple(AdapterMessage(role=role, text=text) for role, text in validated.turns),  # type: ignore[arg-type]
        max_output_tokens=request.max_output_tokens,
        system=validated.system,
        temperature=request.temperature,
        stop=tuple(request.stop),
    )


def _configured_deadline(runtime: InferenceRuntime) -> float:
    configured = runtime.total_deadline_seconds
    if not configured:
        # An invalid `AI_EGRESS_*` setting is a deployment misconfiguration:
        # a typed internal error, as for an invalid concurrency limit
        # (admission.py), never the egress layer's own exception. Nothing has
        # been read, authorized, recorded or sent yet.
        try:
            configured = ai_egress_settings().total_deadline_seconds
        except EgressConfigurationError as exc:
            raise InferenceInternalError(exc.reason) from exc
    return configured


def _total_deadline(request: InferenceRequest, runtime: InferenceRuntime) -> float:
    configured = _configured_deadline(runtime)
    if request.deadline_seconds is None:
        return configured
    if isinstance(request.deadline_seconds, bool) or not request.deadline_seconds > 0:
        raise InferenceInvalidRequestError("deadline_seconds")
    return min(float(request.deadline_seconds), configured)


def _log(event: str, **fields: object) -> None:
    logger.info(event, extra={f"ai_{k}": v for k, v in fields.items()})


async def run_inference(
    caller: object,
    *,
    tenant_id: uuid.UUID,
    request: InferenceRequest,
    runtime: InferenceRuntime | None = None,
) -> InferenceResult:
    """See the module docstring. `runtime` is an internal seam for tests and
    for registering adapters; the public interface does not expose it."""
    require_caller(OPERATION, caller, (UserCaller, ServiceAccountCaller))
    assert isinstance(caller, UserCaller | ServiceAccountCaller)
    if not isinstance(tenant_id, uuid.UUID):
        raise InferenceInvalidRequestError("tenant_id")
    rt = runtime or default_runtime()
    request_id = uuid.uuid4()
    total = _total_deadline(request, rt)
    deadline = Deadline.after(total)

    if isinstance(caller, ServiceAccountCaller) and caller.tenant_id != tenant_id:
        _record_denied(
            tenant_id, caller, reason="service_account_of_another_tenant", request_id=request_id
        )
        raise InferenceNotAuthorizedError("not_authorized", request_id=request_id)
    # An unknown or closed tenant is refused exactly like a tenant the caller
    # does not belong to (same error and reason), so the refusal does not
    # reveal whether a tenant id exists. No audit row: there is no open
    # tenant to record it in. Not chained either: the cause's type
    # (`TenantNotFoundError`, `TenantClosedError`) would tell them apart.
    try:
        await asyncio.to_thread(require_open_tenant, tenant_id)
    except Exception:  # noqa: BLE001 -- unknown or closed tenant: not authorized
        raise InferenceNotAuthorizedError("not_authorized", request_id=request_id) from None

    # 1. Authority, before anything about the request is examined: an
    # unauthorized caller learns nothing from validation and leaves no
    # policy row in the tenant's audit log.
    try:
        await asyncio.to_thread(_authorize_in_tenant, caller, tenant_id)
    except AuthorityNotAuthorizedError:
        await asyncio.to_thread(
            _record_denied, tenant_id, caller, reason="not_authorized", request_id=request_id
        )
        raise InferenceNotAuthorizedError("not_authorized", request_id=request_id) from None

    # 2. Validation and classification.
    try:
        validated = validate_request(request)
    except InferencePolicyDeniedError as exc:
        await asyncio.to_thread(
            _record_denied, tenant_id, caller, reason=exc.reason or "policy", request_id=request_id
        )
        exc.request_id = request_id
        raise
    except InferenceError as exc:
        exc.request_id = request_id
        raise

    # Measured from the installation's configured deadline, never from this
    # request's own (possibly shorter) one: another request's attempt may run
    # for the full configured deadline and must not be abandoned under it.
    abandon_before = datetime.now(UTC) - timedelta(
        seconds=_configured_deadline(rt) + ABANDON_MARGIN_SECONDS
    )
    try:
        candidates = await asyncio.to_thread(
            _resolve, caller, tenant_id, validated, request, rt, abandon_before=abandon_before
        )
    except AuthorityNotAuthorizedError as exc:
        await asyncio.to_thread(
            _record_denied, tenant_id, caller, reason="not_authorized", request_id=request_id
        )
        raise InferenceNotAuthorizedError("not_authorized", request_id=request_id) from exc
    except InferencePolicyDeniedError as exc:
        await asyncio.to_thread(
            _record_denied, tenant_id, caller, reason=exc.reason or "policy", request_id=request_id
        )
        exc.request_id = request_id
        raise
    except InferenceError as exc:
        exc.request_id = request_id
        raise

    # Admission: entitlement, then a concurrency slot. An entitlement refusal
    # is recorded in the tenant's audit log (ADR-0055 section 6); the caller
    # is already authorized at this tenant, so only the tenant's own members
    # and service accounts can add such a row. The refusal stands whether or
    # not the row is written (`_record_denied`). Quota and capacity refusals
    # write no audit row: capacity exhaustion is logged
    # (`ai_inference_capacity_exhausted`, admission.py); a quota refusal is
    # the typed error only.
    entitlement = rt.entitlement
    try:
        await asyncio.to_thread(
            check_entitlement, tenant_id, **({"check": entitlement} if entitlement else {})
        )
    except InferenceEntitlementDeniedError as exc:
        await asyncio.to_thread(
            _record_denied,
            tenant_id,
            caller,
            reason=exc.reason or "entitlement",
            request_id=request_id,
        )
        exc.request_id = request_id
        raise
    try:
        await asyncio.to_thread(
            rt.token_quota,
            tenant_id,
            input_bytes=validated.input_bytes,
            max_output_tokens=request.max_output_tokens,
        )
        slot = await rt.admission.admit(tenant_id, ttl_seconds=total)
    except InferenceError as exc:
        exc.request_id = request_id
        raise
    try:
        return await _attempt_all(
            caller,
            tenant_id,
            validated,
            request,
            rt,
            candidates,
            request_id=request_id,
            deadline=deadline,
        )
    finally:
        await asyncio.shield(rt.admission.release(slot))


async def _attempt_all(
    caller: UserCaller | ServiceAccountCaller,
    tenant_id: uuid.UUID,
    validated: ValidatedRequest,
    request: InferenceRequest,
    rt: InferenceRuntime,
    candidates: tuple[EligibleCandidate, ...],
    *,
    request_id: uuid.UUID,
    deadline: Deadline,
) -> InferenceResult:
    attempt_number = 0
    last_error: InferenceError | None = None
    adapter_request = _adapter_request(validated, request)
    for index, eligible in enumerate(candidates):
        candidate = eligible.candidate
        if await rt.circuit.is_open(candidate.provider_key):
            last_error = InferenceProviderUnavailableError("circuit_open", request_id=request_id)
            continue
        adapter = rt.adapters.get(candidate.protocol)
        if adapter is None:
            last_error = InferenceUnsupportedCapabilityError("protocol", request_id=request_id)
            continue
        try:
            credential = rt.credential(candidate.credential_ref)
        except Exception as exc:  # noqa: BLE001 -- an unreadable secrets backend: unavailable
            # Never the backend's own exception: its message may name the secret.
            logger.warning(
                "ai_provider_credential_unavailable",
                extra={"ai_provider": candidate.provider_key, "error_type": type(exc).__name__},
            )
            raise InferenceProviderAuthError(
                "credential_unavailable", request_id=request_id
            ) from None
        if credential is None:
            # A missing or unprovisioned credential is never hidden by a
            # fallback. The log names the provider, never the secret.
            logger.warning(
                "ai_provider_credential_unavailable",
                extra={"ai_provider": candidate.provider_key},
            )
            raise InferenceProviderAuthError("credential_unavailable", request_id=request_id)
        target = ResolvedTarget(
            base_url=candidate.base_url,
            model_id=candidate.model_id,
            capabilities=frozenset(Capability(c) for c in candidate.capabilities),
        )
        for retry in range(MAX_RETRIES + 1):
            if deadline.expired:
                raise last_error or InferenceTimeoutError("deadline", request_id=request_id)
            attempt_number += 1
            try:
                attempt_id = await asyncio.to_thread(
                    _begin_attempt,
                    caller,
                    tenant_id,
                    validated,
                    request,
                    rt,
                    eligible,
                    request_id=request_id,
                    attempt_number=attempt_number,
                )
            except AuthorityNotAuthorizedError as exc:
                await asyncio.to_thread(
                    _record_denied,
                    tenant_id,
                    caller,
                    reason="not_authorized",
                    request_id=request_id,
                )
                raise InferenceNotAuthorizedError("not_authorized", request_id=request_id) from exc
            except InferenceError as exc:
                exc.request_id = request_id
                raise
            except Exception as exc:  # noqa: BLE001 -- no evidence, nothing is sent
                logger.warning(
                    "ai_inference_attempt_unrecorded", extra={"error_type": type(exc).__name__}
                )
                raise InferenceInternalError("attempt_not_recorded", request_id=request_id) from exc

            started = time.monotonic()
            try:
                egress = rt.egress(eligible)
                result = await adapter.complete(
                    adapter_request,
                    target=target,
                    credential=credential,
                    egress=egress,
                    deadline=deadline,
                )
            except asyncio.CancelledError:
                # Cancellation must propagate as itself: a settlement failure
                # is logged by `_settle_failure`, never raised in its place.
                _settle_failure(
                    tenant_id,
                    attempt_id,
                    _Settlement(
                        AttemptState.INTERRUPTED, error_category="cancelled", possibly_accepted=True
                    ),
                )
                raise
            except EgressConfigurationError as raw:
                # The client could not be built with its guarantees (an
                # unsupported HTTP stack, an invalid policy): nothing was
                # sent, and it is a deployment fault, not a provider failure
                # to retry or fall back from.
                await asyncio.to_thread(
                    _settle_failure,
                    tenant_id,
                    attempt_id,
                    _Settlement(AttemptState.FAILED, error_category="internal"),
                )
                raise InferenceInternalError(
                    raw.reason, request_id=request_id, attempt_id=attempt_id
                ) from None
            except (AdapterError, EgressError) as raw:
                err = raw if isinstance(raw, AdapterError) else error_from_egress(raw)
                settled = await asyncio.to_thread(
                    _settle_failure,
                    tenant_id,
                    attempt_id,
                    _Settlement(
                        AttemptState.FAILED,
                        error_category=err.category.value,
                        possibly_accepted=err.possibly_accepted,
                        provenance="unknown",
                        provider_request_id=err.provider_request_id,
                    ),
                )
                if not settled:
                    # The attempt's evidence could not be closed: no further
                    # attempt is started, and the caller gets a typed error.
                    raise InferenceInternalError(
                        "settlement_failed", request_id=request_id, attempt_id=attempt_id
                    ) from None
                _log(
                    "ai_inference_attempt",
                    request_id=str(request_id),
                    attempt=attempt_number,
                    provider=candidate.provider_key,
                    model=candidate.model_id,
                    outcome="failed",
                    category=err.category.value,
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
                error = _consumer_error(err, request_id=request_id, attempt_id=attempt_id)
                last_error = error
                if err.category in (
                    ErrorCategory.PROVIDER_OVERLOADED,
                    ErrorCategory.TRANSIENT_PRE_ACCEPTANCE,
                ):
                    if await rt.circuit.failure(candidate.provider_key):
                        logger.warning(
                            "ai_provider_circuit_open",
                            extra={"ai_provider": candidate.provider_key},
                        )
                if err.possibly_accepted or err.category in _NEVER_FALLBACK:
                    # Not chained: the provider-side cause (an httpx error
                    # holding the request and its credential header, and the
                    # frames that built it) must not travel with the error.
                    raise error from None
                if err.category not in _RETRYABLE:
                    break  # e.g. unsupported capability: next candidate
                if retry < MAX_RETRIES:
                    delay = min(
                        _BACKOFF_CAP_SECONDS,
                        _BACKOFF_BASE_SECONDS * (2**retry) * (0.5 + random.random()),
                    )
                    if err.retry_after_seconds is not None:
                        delay = max(delay, err.retry_after_seconds)
                    if delay >= deadline.remaining():
                        break  # no time left to retry here: try the next candidate
                    await rt.sleep(delay)  # type: ignore[misc]
                continue
            except Exception as exc:  # noqa: BLE001 -- an adapter bug: evidence, then internal
                await asyncio.to_thread(
                    _settle_failure,
                    tenant_id,
                    attempt_id,
                    _Settlement(
                        AttemptState.FAILED, error_category="internal", possibly_accepted=True
                    ),
                )
                logger.warning(
                    "ai_inference_adapter_failure", extra={"error_type": type(exc).__name__}
                )
                raise InferenceInternalError(
                    "adapter_failure", request_id=request_id, attempt_id=attempt_id
                ) from None

            await rt.circuit.success(candidate.provider_key)
            settlement = _usage_settlement(result, validated, candidate.model_ref)
            try:
                cost = await asyncio.to_thread(_settle, tenant_id, attempt_id, settlement)
            except Exception as exc:  # noqa: BLE001 -- never return output before settlement commits
                logger.warning(
                    "ai_inference_settlement_failed", extra={"error_type": type(exc).__name__}
                )
                raise InferenceInternalError(
                    "settlement_failed", request_id=request_id, attempt_id=attempt_id
                ) from exc
            _log(
                "ai_inference_attempt",
                request_id=str(request_id),
                attempt=attempt_number,
                provider=candidate.provider_key,
                model=candidate.model_id,
                outcome="succeeded",
                provenance=settlement.provenance,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            return InferenceResult(
                request_id=request_id,
                client_request_id=request.client_request_id,
                alias=request.alias,
                provider_key=candidate.provider_key,
                model_id=candidate.model_id,
                output=(
                    ContentPart(
                        kind="text",
                        classification=validated.effective_classification,  # type: ignore[arg-type]
                        text=result.text,
                    ),
                ),
                tool_calls=(),
                finish_reason=result.finish_reason,
                usage=UsageReport(
                    input_tokens=settlement.input_tokens,
                    output_tokens=settlement.output_tokens,
                    cached_input_tokens=settlement.cached_input_tokens,
                    cache_write_tokens=settlement.cache_write_tokens,
                    provenance=settlement.provenance,  # type: ignore[arg-type]
                    estimated_cost=cost.amount if cost else None,
                    currency=cost.currency if cost else None,
                    pricing_version=cost.pricing_version if cost else None,
                ),
                attempts=attempt_number,
                fell_back=index > 0,
            )
    raise last_error or InferenceProviderUnavailableError(
        "no_destination_succeeded", request_id=request_id
    )


async def stream_inference(
    caller: object, *, tenant_id: uuid.UUID, request: InferenceRequest
) -> None:
    """Streaming is not enabled: its six release criteria (contracts section
    6.6) are not met in AI-D. Every request is refused before anything is
    read or sent."""
    del caller, tenant_id, request
    raise InferenceUnsupportedCapabilityError("streaming_not_enabled")
