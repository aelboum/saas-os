# AI inference — provider and consumer contracts

Status: written as Proposed (2026-10-16), Phase AI-A; companion of ADR-0054 and ADR-0055, Accepted 2026-10-18; reconciled four times with owner decisions on 2026-10-16 (status labels: ADR-0054 section 12). Companion to [ADR-0054](../ADR/0054-governed-ai-inference-subsystem.md) and [ADR-0055](../ADR/0055-ai-data-governance-and-destination-authorization.md). **Implementation status (2026-10-18): implemented and merged (pull request #53), as section 9 records; streaming is not enabled.** The text below was written on 2026-10-16, when nothing in it existed in code and the public interface and its dependency direction were open (ADR-0054 Q11, settled on 2026-10-17 in ADR-0054 section 3a: `saas_os.inference`, invoked by products only). The owner approved in principle the boundaries it relies on: a supported public interface, the five platform permissions and the classification trust model. Approved owner decisions cover permission registration timing (Q9), pre-send attempt evidence (Q10), entitlement and concurrency (Q12) and audit granularity (Q7); the use-case registry is in-process (Q5). Section 9 states where the implementation is a subset or differs. Since 2026-10-18 ADR-0054 and ADR-0055 are Accepted (Q6): the implemented contract this document describes, as section 9 states it, is part of ADR-0054's accepted scope (section 12c); proposals not implemented here (streaming, section 6, and its release criteria; tool calls; images) are not accepted as implemented and stay subject to their own decisions. The Python illustrates shape, not final source.

## 1. Conventions

- **Import surface (blocked on Q11).**
  - Products use only a supported public interface and never import the internal implementation (provisionally `saas_os.control_plane.inference`) or its adapters.
  - Where the public types and entry points live, and in which dependency direction, is **not decided**. `saas_os.inference` re-exporting the internal package (F1) is only a provisional internal design. It cannot serve callers that are forbidden from reaching the Control Plane indirectly (ADR-0054 section 3).
  - Module paths below, such as `saas_os.inference`, are placeholders for that undecided interface.
- All public types are frozen dataclasses or enums. No provider type, `httpx` type or SQLAlchemy type appears in the public API.
- Times are timezone-aware UTC. Durations are `float` seconds. Token counts are `int`. Money is `Decimal` with an ISO 4217 currency.
- Every public function takes keyword-only arguments after `caller`.
- Failure is an exception from one hierarchy rooted at `InferenceError`. Nothing returns a partial result without saying so.

## 2. Provider adapter contract

### 2.1 Adapter interface

**Implemented in AI-B (internal, 2026-10-16):** `saas_os.control_plane.inference.adapters`. The implemented interface is the non-streaming subset of the sketch below: `complete()` only, with an `EgressClient` whose single method is `post(url, *, headers, content, deadline) -> EgressResponse`. `stream()` is not implemented (streaming deferred). Implemented capabilities: `text_input`, `text_output`, `system_instructions`, `temperature`, `stop_sequences`. Implemented error categories add two adapter-level ones to section 4: `provider_error` (an undeclared 5xx, possibly accepted) and `malformed_response` (a 2xx that cannot be interpreted, possibly accepted).

```python
class ProviderAdapter(Protocol):
    protocol: ClassVar[str]  # "openai_chat_completions" | "anthropic_messages"
    protocol_capabilities: ClassVar[frozenset[Capability]]

    async def complete(
        self,
        request: AdapterRequest,
        *,
        target: ResolvedTarget,
        credential: OpaqueCredential,
        egress: EgressClient,
        deadline: Deadline,
    ) -> AdapterResult: ...

    def stream(
        self,
        request: AdapterRequest,
        *,
        target: ResolvedTarget,
        credential: OpaqueCredential,
        egress: EgressClient,
        deadline: Deadline,
        limits: StreamLimits,
    ) -> AsyncIterator[AdapterEvent]: ...
```

- `AdapterRequest` is the normalized, already-authorized request (messages, parts, parameters). It carries no tenant id, no classification and no policy; classification has already been enforced and the adapter cannot weaken it.
- `ResolvedTarget` carries the base URL, model id and declared model capabilities from configuration.
- `OpaqueCredential` exposes the secret only to the adapter's header builder; its `repr` and `str` never show it.
- `EgressClient` is the only way an adapter performs I/O. It enforces destination validation, pinning, no redirects, no environment proxies, deadlines and body caps (threat model section 3).
- An adapter must: never retry; never follow a redirect; map every failure to an `ErrorCategory` (section 4) with `possibly_accepted` set correctly; report usage only from the provider's own fields; set `provider_request_id` when the provider returns one; close the response on every path.

### 2.2 Initial protocols

| Protocol | Endpoint | Auth header | Usage source | Notes |
|---|---|---|---|---|
| `openai_chat_completions` | `POST {base_url}/chat/completions` | `Authorization: Bearer` (header name configurable for gateways) | `usage.prompt_tokens`, `usage.completion_tokens`, cached-token details when present; streaming usage only if the server honours `stream_options.include_usage` | Serves OpenAI, OpenRouter, a LiteLLM server, vLLM, Ollama's OpenAI-compatible endpoint, Groq, internal gateways. **Compatible is not capable**: each provider and model declares what it supports; an undeclared parameter is refused before sending, never sent and hoped for |
| `anthropic_messages` | `POST {base_url}/v1/messages` | `x-api-key`, `anthropic-version` | `usage.input_tokens`, `usage.output_tokens`, cache read/creation fields; streaming: `message_start` and `message_delta` events | System instructions are a separate field, not a message; `max_tokens` is required |

Later candidates (Phase AI-G, not designed here): Gemini-native, AWS Bedrock (SigV4 request signing needs its own credential model), Google Vertex AI (service-account OAuth tokens). Each needs its own adapter and conformance suite; none changes the consumer API.

### 2.3 Capability declarations

Capabilities are declared at three levels and intersected: protocol (what the adapter can express), provider (what the endpoint implements), model (what the model supports).

| Capability | Meaning |
|---|---|
| `text_input`, `text_output` | Baseline |
| `system_instructions` | Separate system/developer instruction part |
| `streaming` | Incremental output |
| `streaming_usage` | Usage reported at the end of a stream |
| `tool_calls` | Model may return structured tool-call requests (returned as data, never executed by SaaS OS) |
| `json_output` | Constrained JSON output mode |
| `image_input` | Image content parts |
| `stop_sequences`, `temperature`, `top_p`, `seed` | Parameters the endpoint accepts |
| `prompt_caching` | Provider-side caching with reported cached tokens |

Model metadata (configuration, ADR-0054 section 5): `model_id`, capabilities, `context_window_tokens`, `max_output_tokens`, `lifecycle` and `retire_after`, optional `pricing_ref` (as implemented: no `pricing_ref` column; `control_plane.ai_model_prices` rows reference the model), and its provider's declared `data_handling`. A request requiring a capability outside the intersection is refused with `unsupported_capability` before any egress.

### 2.4 Conformance suite (Phase AI-B)

Every adapter passes the same suite against a local fake server: request shape; header construction; no credential in any exception, log record or `repr`; each status code mapped to the expected category and `possibly_accepted`; redirect refused; oversized body refused; a slow server hits each deadline; streaming parse including malformed events, missing final usage, a mid-stream error event and an abrupt close; cancellation closes the connection. A deterministic `FakeAdapter` implements the interface for governance and consumer tests.

## 3. Consumer request types

```python
@dataclass(frozen=True)
class ContentPart:
    kind: Literal["text", "image"]
    classification: Literal["none", "tenant_data", "sensitive"]  # required, no default
    text: str | None = None
    image: ImageRef | None = None  # bytes + media type; size-capped


@dataclass(frozen=True)
class Message:
    role: Literal["system", "user", "assistant", "tool"]
    parts: tuple[ContentPart, ...]
    tool_call_id: str | None = None


@dataclass(frozen=True)
class InferenceRequest:
    alias: str  # configured alias, never a provider model id
    use_case: str  # registered use case (ADR-0055 section 4)
    messages: tuple[Message, ...]
    max_output_tokens: int  # required: bounds cost and quota admission
    required_capabilities: frozenset[Capability] = frozenset()
    temperature: float | None = None
    stop: tuple[str, ...] = ()
    tools: tuple[ToolSpec, ...] = ()  # each ToolSpec carries a classification
    response_format: Literal["text", "json"] = "text"
    deadline_seconds: float | None = None  # capped by configuration
    client_request_id: str | None = None  # caller's correlation id, <= 128 chars, echoed
```

Rules: no free-form provider parameters ("extra body"); a parameter the resolved model does not declare is refused, not dropped. A product names an alias, never a provider or a model; an alias's candidates are platform configuration.

Use-case registration is an in-process registry of immutable, application-defined use cases (approved owner decision Q5; ADR-0055 section 4). Registration alone authorizes nothing. The sketch shows the shape; the module path is a placeholder until Q11 decides the public interface: The tenant's grant names the use case and the classifications it allows, so a registered ceiling alone authorizes nothing (ADR-0055 section 4):

```python
from saas_os.inference import UseCase, register_use_case  # placeholder path (Q11)

register_use_case(
    UseCase(
        name="support.summarize_ticket",
        max_classification="tenant_data",
        part_kinds=frozenset({"text"}),
        max_parts=64,
        max_input_bytes=200_000,
        required_capabilities=frozenset(),
    )
)
```

## 4. Normalized errors, retry and fallback eligibility

All exceptions derive from `InferenceError(category, request_id, attempt_id | None, provider_request_id | None, retry_after | None)`. Messages never contain content, credentials or provider error bodies. Since 2026-10-18 an error raised after a provider-side failure is not chained to that failure (`raise ... from None`): the provider-side exception held the outgoing request, its credential header and the frames that built it, so it does not travel with the error to the caller or an error tracker. A secrets-backend failure while reading a credential is `InferenceProviderAuthError("credential_unavailable")`, never the backend's own exception; an egress client that cannot be built with its guarantees is `InferenceInternalError`, recorded as a failed attempt and never retried or fallen back from. Every refusal, quota and capacity included, carries the `request_id`.

`caller_not_authorized` has the reason `not_authorized` for a caller who does not hold `ai.inference:run` at the tenant and equally for an unknown or closed tenant, with no chained cause, so the refusal does not reveal whether a tenant id exists (2026-10-18; before, an unknown or closed tenant had the reason `tenant_not_open`).

| Category | Exception | Raised when | Same-destination retry | Fallback | Usage recorded |
|---|---|---|---|---|---|
| `caller_not_authorized` | `InferenceNotAuthorizedError` | Caller lacks `ai.inference:run` at the tenant, wrong caller type, tenant not open | No | No | None |
| `policy_denied` | `InferencePolicyDeniedError(reason)` | Missing, invalid or unsupported classification on any part, unregistered use case, ceiling exceeded, tenant policy absent or disabled, use case not granted, classification not allowed for the use case, no eligible destination | No | No — a denial is never a reason to try another destination | None |
| `invalid_request` | `InferenceInvalidRequestError` | Shape, size, undeclared parameter; provider 400/404/413/422 | No | No | Provider-reported if any |
| `unsupported_capability` | `InferenceUnsupportedCapabilityError` | No candidate supports a requirement (before sending) | No | Yes, to a candidate that supports it, before sending only | None |
| `entitlement_denied` | `InferenceEntitlementDeniedError` | The tenant lacks the inference entitlement, or entitlement information is missing or ambiguous (AI-D, Q12) | No | No | None |
| `capacity_exhausted` | `InferenceCapacityExhaustedError` | The tenant's bounded concurrency, or the installation-wide ceiling, is exhausted (AI-D, Q12); observable through metric and log | No (the caller may retry later) | No | None |
| `quota_exceeded` | `InferenceQuotaExceededError` | (AI-F) soft token limit. A soft limit can be overshot under concurrency; it is not a hard ceiling (ADR-0054 section 7) | No | No | None |
| `rate_limited` | `InferenceRateLimitedError(retry_after)` | Provider 429 | Yes, bounded, if the adapter declares 429 "not processed" | Yes | None |
| `provider_overloaded` | `InferenceProviderUnavailableError` | Declared not-processed statuses (e.g. Anthropic 529), open circuit | Yes, bounded | Yes | None |
| `provider_auth` | `InferenceProviderAuthError` | Provider 401/403 | No | **No** — a fallback must not hide a revoked or misbound credential | None |
| `transient_pre_acceptance` | `InferenceConnectionError` | DNS failure, connection refused, TLS handshake failure | Yes, bounded | Yes | None |
| `possibly_accepted` | `InferenceOutcomeUnknownError` | Write completed then read timeout, reset, or an undeclared 5xx | **No** | **No** | `unknown` or `estimated` |
| `timeout` | `InferenceTimeoutError` | Caller or configured deadline expired | No | No | As `possibly_accepted` if bytes were sent |
| `cancelled` | `InferenceCancelledError` | Caller cancelled | No | No | As above |
| `endpoint_security` | `InferenceEndpointSecurityError` | Egress refused (non-public, untrusted, port, scheme), redirect received, binding mismatch, TLS verification failure | No | **No** | None |
| `response_too_large` | `InferenceResponseLimitError` | Body or stream cap exceeded | No | No | Estimated from bytes received |
| `stream_interrupted` | `InferenceStreamInterruptedError(partial=True)` | Error after streamed output reached the caller | No | **No** | Last reported, else estimated |
| `internal` | `InferenceInternalError` | SaaS OS fault, for example the ledger or audit write failing before sending | No | No | None — nothing was sent |

Retry bounds: at most 2 retries per destination (proposed bound), backoff with jitter, `Retry-After` honoured only up to the remaining time of the original deadline; retries and fallback share that deadline. Each retry is a new attempt row. Fallback: the next candidate in alias order, each at most once, each re-authorized (ADR-0055 section 6).

## 5. `run_inference`

```python
async def run_inference(
    caller: UserCaller | ServiceAccountCaller, *, tenant_id: UUID, request: InferenceRequest
) -> InferenceResult: ...


@dataclass(frozen=True)
class InferenceResult:
    request_id: UUID
    client_request_id: str | None
    alias: str
    provider_key: str  # configuration key, not a credential
    model_id: str
    output: tuple[ContentPart, ...]  # classified with the request's effective classification
    tool_calls: tuple[ToolCall, ...]  # data only; never executed by SaaS OS
    finish_reason: Literal["stop", "length", "tool_calls", "content_filter", "other"]
    usage: UsageReport
    attempts: int
    fell_back: bool
```

Semantics, in order (ADR-0054 section 4):

Products call `run_inference` through the supported public interface (placeholder path `saas_os.inference`, Q11). The interface adds no parameter that skips any step below.

1. **Authority.** `caller` must be a `UserCaller` or `ServiceAccountCaller`; anything else raises `CallerTypeError` before any read (the ADR-0045 convention). `tenant_id` is a claim; it establishes no authority until the caller is authorized there. A `ServiceAccountCaller` must belong to `tenant_id`. The caller is authorized for the tenant permission `ai.inference:run` at `tenant_id` the way Core authorizes (`can()`; support access never satisfies it). Products build the caller from their own request context — `UserCaller(context.actor_id)` or `ServiceAccountCaller(context.actor_id, context.tenant_id)`, as SaaS OS's own `saas_os/api/v1/_common.py` does today. Background jobs use a service account of the tenant; no system purpose is added.
2. **Validation and classification** (ADR-0055 sections 2, 4).
3. **Resolution and eligibility** (ADR-0055 section 3).
4. **Admission** (ADR-0054 section 7).
5. **Attempt.** One transaction: re-check authority, insert the `started` attempt row, record the data authorization decision; commit. Then egress.
6. **Settlement.** One transaction: finalize the attempt row; append the usage outbox event.
7. **Return or raise.** On fallback, steps 3–6 repeat for the next candidate.

Deadlines follow ADR-0054 section 8a. `deadline_seconds` defaults to, and is capped by, the configured total non-streaming deadline (candidate value 120 s, not approved). It is computed once and covers the whole call: resolution, connection, retries, fallback, provider processing and response read. Retries and fallback never receive a fresh full deadline. Cancellation (`asyncio.CancelledError`) closes the HTTP response, finalizes the attempt as `interrupted`, and re-raises.

Admission (required in AI-D, Q12): entitlement gate first, then acquisition of a per-tenant concurrency slot enforced across application instances. Either rejection raises before any provider content is sent (`entitlement_denied`, `capacity_exhausted`). The slot is released on every exit path and expires if the process dies.

## 6. `stream_inference`

```python
def stream_inference(
    caller, *, tenant_id: UUID, request: InferenceRequest
) -> AsyncContextManager[InferenceStream]: ...


class InferenceStream(AsyncIterator[StreamEvent]):
    request_id: UUID
    final: InferenceResult | None  # set after StreamCompleted


StreamEvent = TextDelta | ToolCallDelta | UsageUpdate | StreamCompleted
```

### 6.1 Lifecycle guarantees

1. Authorization, validation, eligibility, admission and the attempt transaction (section 5 steps 1–5) all complete **before** the provider is contacted. Entering the context manager performs them; a failure raises before any event.
2. Only `async with` is supported, so the response is always closed: on normal end, caller break, exception, cancellation and deadline.
3. Deadlines (ADR-0054 section 8a): streaming idle timeout and maximum streaming lifetime (candidates 60 s and 10 min, not approved), plus the connection and read-inactivity timeouts. Any per-use-case first-event limit (for example for voice) is open (Q3).
4. Backpressure: the adapter reads from the network only when the consumer awaits the next event; SaaS OS buffers at most one parsed event plus the HTTP read buffer. A consumer that stops reading holds one connection until the idle deadline closes it.
5. Limits: per-event bytes, total bytes, maximum events, maximum output tokens (the stream is cut with `finish_reason="length"` if a provider overruns).

### 6.2 Partial output

- Every delivered delta is final from the caller's point of view; SaaS OS never retracts it.
- After the first delta, any failure raises `InferenceStreamInterruptedError(partial=True)` with the attempt id and the usage known so far. **No retry and no fallback after the first delta**, ever.
- Before the first delta, section 4's retry and fallback rules apply unchanged (nothing has reached the caller).

### 6.3 Disconnect

A product that loses its own client (a browser disconnect) must exit the `async with`; SaaS OS then closes the provider stream and finalizes the attempt `interrupted`. SaaS OS cannot detect the product's client disconnect itself.

### 6.4 Usage for streams

- `UsageUpdate` events forward provider-reported usage when it arrives mid-stream.
- At completion: provider-reported final usage if present (`provider_reported`); otherwise input estimated locally and output counted from delivered text (`estimated`).
- On interruption: the last provider-reported values, completed with estimates for delivered output (`estimated`). Never zero unless nothing was sent.

### 6.5 Logging

As for non-streaming: no deltas, no content; event counts, bytes, time to first event, finish reason.

### 6.6 Release criteria (all required before `stream_inference` is enabled)

1. The conformance suite passes for both adapters, including abrupt close, malformed event, mid-stream provider error and missing final usage.
2. Tests prove the connection is closed on caller break, exception, cancellation and each deadline (connection-count assertion against the fake server).
3. Tests prove no retry or fallback after the first delta, with a negative control (allowing it must fail the test).
4. Interrupted and abandoned attempts produce ledger rows with correct provenance; usage mirrors to `core.usage_events` exactly once.
5. The per-tenant concurrency limit counts open streams.
6. The canary-credential test covers streaming error paths.

Until all six pass, `stream_inference` raises `InferenceUnsupportedCapabilityError` for every request. Recommended: a separate authorization gate inside Phase AI-D (roadmap).

## 7. Attempt evidence and usage reporting

Phase split (approved owner decision Q10):
- **AI-D** records pre-send attempt evidence and correlates provider outcomes. Nothing is sent before the required decision and evidence records are written; a failed write sends nothing.
- **AI-F** adds durable usage reconciliation, quotas and pricing. It is not the first phase to record an attempt.

Audit granularity (approved owner decision Q7): one durable decision record per attempt, plus destination-level evidence where needed (ADR-0054 section 7a).

The fields below are a proposed structure, to be designed and validated in AI-D. Cost fields are AI-F.

```python
@dataclass(frozen=True)
class UsageReport:
    input_tokens: int | None
    output_tokens: int | None
    cached_input_tokens: int | None
    cache_write_tokens: int | None
    provenance: Literal["provider_reported", "estimated", "unknown"]
    estimated_cost: Decimal | None  # never a billed amount
    currency: str | None
    pricing_version: str | None
```

Attempt record, proposed as table `control_plane.ai_inference_attempts` (tenant-owned, RLS), one row per actual provider attempt. Durability and atomicity hold only if this PostgreSQL mechanism is chosen and tested:

| Field | Notes |
|---|---|
| `id`, `tenant_id`, `request_id`, `attempt_number` | `request_id` groups retries and fallbacks |
| `actor_type`, `actor_user_id` / `actor_service_account_id` | From the typed caller |
| `use_case`, `alias`, `provider_key`, `model_id`, `provider_config_version` | Configuration snapshot identifiers |
| `effective_classification`, `data_authorization_decision_id` | ADR-0055 |
| `state` | `started`, `succeeded`, `failed`, `interrupted`, `abandoned` |
| `error_category`, `possibly_accepted` | Section 4 |
| `streamed`, `output_delivered` | Whether any output reached the caller |
| `started_at`, `finished_at`, `duration_ms`, `time_to_first_token_ms` | |
| `input_tokens`, `output_tokens`, `cached_input_tokens`, `cache_write_tokens` | Nullable |
| `other_usage` | Bounded JSON of provider-specific dimensions, allow-listed keys only |
| `usage_provenance` | `provider_reported`, `estimated`, `unknown` |
| `provider_request_id` | For reconciliation and support; at most 255 characters |
| `estimated_cost`, `currency`, `pricing_version` | Phase AI-F |

Mirroring: on finalization, `ingest_event(session, tenant_id, "ai.input_tokens", n)` and `"ai.output_tokens"` in the same transaction (outbox; idempotent per ADR-0036). Unknown usage is not mirrored as zero; the ledger reports it and reconciliation resolves it if the provider later reports it.

Retention: the ledger holds no content. Its retention class is decided in AI-F (`core.usage_events` is `DEFERRED_POLICY` today).

## 8. Platform administration operations (Phase AI-C)

The permissions are approved in principle and are implemented only in an authorized phase (four in AI-C; `platform.ai_usage:read` with its read operation once the AI-D read path exists, ADR-0054 section 9 and Q9), through the full ADR-0045 registration process (ADR-0054 section 9). **Implementation status (2026-10-17):** all five permissions exist, implemented on branch `feat/ai-inference` and merged into `main` by pull request #53 (`0598a9a`). The implemented operation and CLI names differ from the proposed names in the table below; section 9 lists the implemented names. These operations are not exported by the public facade; they are reached through `saas-os-operator` and in-process operator tooling.

Python operations in `saas_os.control_plane.inference.config`. Each takes a `UserCaller`, is authorized through `authorize_platform_caller` with a declared operation key, requires a `reason`, and is audited with `record_platform_event_in_transaction` in the same transaction:

| Operation | Permission |
|---|---|
| `create_provider`, `update_provider`, `disable_provider` | `platform.ai_provider:manage` |
| `rebind_provider_credential` (clears), `confirm_provider_binding` | `platform.ai_provider:manage` |
| `create_model`, `update_model`, `deprecate_model`, `disable_model` | `platform.ai_provider:manage` |
| `create_alias`, `update_alias`, `disable_alias` | `platform.ai_provider:manage` |
| `create_trust_entry`, `expire_trust_entry` | `platform.ai_endpoint_trust:manage` |
| `set_platform_destination_policy` | `platform.ai_policy:manage` |
| `read_configuration` | `platform.ai_config:read` |
| `read_usage_totals` | `platform.ai_usage:read` |

CLI: `saas-os-operator ai-provider|ai-model|ai-alias|ai-trust|ai-policy <verb>`, following ADR-0050 (`--operator <user id>`, `--reason`, `--confirm-production`, application-role validation, one JSON object on stdout). No HTTP route.

**Tenant AI policy (AI-C minimum, AI-E expansion).** These are tenant operations, not platform operations. They are authorized by the proposed tenant permission `ai.policy:manage` through `can()`, audited in the tenant's own audit log in the same transaction, and never writable by a platform permission (ADR-0055 section 7). Their exact contract is designed in the AI-C implementation phase.

Rules: no operation returns a credential value; a credential name must be provisioned for AI use in `AI_PROVIDER_CREDENTIALS` and must resolve (implemented 2026-10-17; ADR-0054 section 6, implementation status); changing a provider's origin, or its credential name, always clears its binding; disabling takes effect for new requests immediately and does not cut streams in progress (bounded by their deadlines); every change increments the row's `version`, which attempts record.

## 9. Implementation status (2026-10-17; implemented on branch `feat/ai-inference`; merged by pull request #53)

| Section | Status |
|---|---|
| 2 Adapter contract | Implemented: OpenAI-compatible Chat Completions, Anthropic Messages, Gemini `generateContent` (AI-G), and the scripted fake. One conformance suite runs for all three |
| 3 Request types | Implemented in `saas_os.inference` (module path settled by Q11). Subset: text parts only (`image` is `unsupported_capability`), roles `system`, `user`, `assistant`; `tool` messages, `tools` and `response_format="json"` are refused, never dropped |
| 4 Errors | Implemented as listed. `possibly_accepted` maps to `InferenceOutcomeUnknownError` (or `InferenceTimeoutError` for a read timeout after sending). Retry bound: two retries per destination |
| 5 `run_inference` | Implemented, in the order stated, with the AI-F soft quota inside admission |
| 6 `stream_inference` | **Not enabled**: raises `InferenceUnsupportedCapabilityError` for every request; none of the six release criteria is claimed |
| 7 Evidence and usage | Implemented: `control_plane.ai_inference_attempts` with the fields listed (no content); provider-reported usage mirrored as `ai.input_tokens` / `ai.output_tokens` in the settlement transaction; estimated usage recorded but not mirrored; cost estimates with currency and pricing version (AI-F). Refusals for authority, policy and (since 2026-10-18) entitlement write a `denied` tenant audit row with the reason code only, best effort after the refusal (`ai_inference_denial_unrecorded` if the write fails; the refusal stands); quota and capacity refusals write none (ADR-0055 section 6) |
| 8 Administration | Implemented with the names in `saas_os.control_plane.inference.config.service` (`create_provider`, `update_provider_endpoint`, `confirm_provider_binding`, `set_provider_credential_ref`, `set_provider_status`, `set_provider_data_handling`, `create_model`, `set_model_lifecycle`, `set_alias`, `create_trust_entry`, `revoke_trust_entry`, `set_destination_policy`, `set_model_price`, `read_ai_configuration`) and `…inference.usage.read_ai_usage_totals`. CLI: `saas-os-operator ai-show`, `ai-provider-create`, `ai-provider-endpoint`, `ai-provider-confirm-binding`, `ai-provider-credential`, `ai-provider-status`, `ai-provider-data-handling`, `ai-model-create`, `ai-model-lifecycle`, `ai-alias-set`, `ai-trust-create`, `ai-trust-revoke`, `ai-destination-policy`. Tenant policy: `set_tenant_ai_policy`, `grant_use_case`, `grant_destination`, `set_tenant_ai_preferences`, `read_tenant_ai_policy` |

Tenant permissions: `ai.inference:run`, `ai.policy:read`, `ai.policy:manage`
(`ai.credential:manage` is reserved for tenant-owned credentials, not
implemented). Support access never satisfies `ai.inference:run`,
`ai.policy:manage` or `ai.credential:manage`.
