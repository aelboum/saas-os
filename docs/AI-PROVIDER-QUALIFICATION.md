# AI inference: provider and deployment qualification

Status: **procedure.** Section 2 has been run against OpenAI `gpt-4o-mini` (`docs/RELEASE-READINESS.md` 8.4: a first run on 2026-10-18 was incomplete for lack of account credit, and the rerun the same day passed 6 of 6), and section 3 has been rehearsed locally (sections 9 to 11 there); nothing on this page has been executed against a deployment. It says how a product qualifies one AI provider and its own deployment of governed inference (ADR-0054, ADR-0055), and what evidence each step must leave. Results go in `docs/RELEASE-READINESS.md` (section 8; the local rehearsals of section 3 are sections 9 to 11); open findings go in the `docs/P-ROADMAP.md` ledger.

SaaS OS is a library (ADR-0015). Qualifying a deployment is the product's act, done in the product's own non-production environment. ADR-0054 section 12c, conditions 1, 2 and 8, applies: the shipped timeout, response-size and concurrency values are provisional defaults, every production deployment validates its own settings before enabling real-provider traffic, and no real-provider conformance has been claimed.

## 1. Two kinds of provider evidence

| Kind | What it proves | Where | Runs |
|---|---|---|---|
| Deterministic conformance (fakes) | The mapping SaaS OS applies to every response shape and status a provider is documented to return: success and usage, 401/403, 400/404/413/422, 429 with and without a usable `Retry-After`, declared not-processed statuses (Anthropic 529, Gemini 503), other 5xx as possibly accepted, malformed and non-JSON bodies, oversized bodies, connect and read timeouts, redirects, private addresses, credential and content hygiene, cancellation | `tests/control_plane/inference/test_provider_adapters_unit.py` (all three adapters through one `case` fixture), `test_gemini_adapter_unit.py`, `tests/infra/egress/` (real TLS on loopback, redirects, timeouts, byte caps) | Every pull request (CI `backend checks`) |
| Real-provider conformance | That the provider actually behaves as the fakes assume, for one protocol, model and account | `tests/control_plane/inference/test_ai_provider_live_integration.py` | By hand only, with a non-production key; excluded from CI |

A fake-provider pass is never reported as real-provider conformance.

## 2. Real-provider conformance procedure

**Prerequisites (all required; otherwise do not run):**

1. A non-production account or project at the provider, with a hard spending limit set at the provider, and a key for it alone.
2. One protocol (`openai_chat_completions`, `anthropic_messages` or `gemini_generate_content`), its base URL and one model id, decided in advance.
3. No customer data: the test sends one fixed prompt.
4. The key injected as `AI_LIVE_PROVIDER_KEY` through the environment or a local `.env` (read only with `ENVIRONMENT=development`; the suite defaults to `test`, which reads the process environment), never on a command line that is logged, never committed.
5. Credit on the account: an account without credit refuses every generating request (OpenAI: HTTP 429 `insufficient_quota`), and the two generating cases then fail.

**Budget.** At most six requests, each asking for at most 16 output tokens; two of them (invalid credential, unknown model) are refused by the provider before generation. Rate limiting is not provoked: that would need a burst of billed requests, and its mapping is covered deterministically.

**Run:**

```
AI_LIVE_PROTOCOL=<protocol> AI_LIVE_BASE_URL=<base url> AI_LIVE_MODEL=<model> \
AI_LIVE_NON_PRODUCTION=yes AI_LIVE_REPORT=ai-live-report.jsonl \
pytest -m integration tests/control_plane/inference/test_ai_provider_live_integration.py -rs
```

**Cases:** success with provider-reported input and output token counts and a provider request id; the output bound sent and honoured (`max_output_tokens=1` ends with `finish_reason="length"`); an invalid credential is `provider_auth`, not possibly accepted; an unknown model is `invalid_request` and no error rendering contains the key; a 64-byte response limit is `response_too_large`; a 50 ms deadline is a timeout, before or after the request was written, without the key in any rendering.

**Record** (in `docs/RELEASE-READINESS.md` section 8): date, protocol, base URL host, model id, the six outcomes from `ai-live-report.jsonl` (sanitized by construction: no prompt, output, credential or provider error body), the pytest totals, and every limitation observed (for example a provider that reports usage differently). A case that was not run is recorded as not run.

**What a pass does not prove:** behaviour under load, latency percentiles, behaviour of other models or regions, streaming (disabled), tool calls (refused), and the cost accuracy of a configured price.

## 3. Deployment qualification checklist

Run in the product's non-production environment, with the deployment's real topology (instances, PostgreSQL, Redis, network egress) and a non-production provider key. Each row says what evidence qualifies it. A generic CI pass is not deployment evidence.

| # | Item | How to qualify | Evidence to record |
|---|---|---|---|
| D1 | Migrations and roles | `saas-os-migrate upgrade` with the migration role; the platform-configuration role exists (ADR-0056, `docs/RUNBOOKS.md` "AI configuration role"); the application starts and `/readyz` is 200 | Migration head revision; readiness result |
| D2 | Provider configuration | `saas-os-operator ai-provider-create`, `ai-model-create`, `ai-alias-set` and `ai-destination-policy` (`docs/RUNBOOKS.md`), each with `--reason`; prices through `set_model_price` (`saas_os.control_plane.inference.config`); platform audit rows written | The configuration as read back with `platform.ai_config:read`; audit row ids |
| D3 | Credentials | The key's secret name listed in `AI_PROVIDER_CREDENTIALS` and injected as a secret; a request succeeds; removing the name from the list makes the next request fail `credential_unavailable` with nothing sent | Request outcomes; the `ai_provider_credential_unavailable` log event |
| D4 | Credential rotation | Rotate by injecting the new value under the same name (takes effect for new requests once the process sees the new environment), or by binding a new name (`ai-provider-credential`) and confirming it (`ai-provider-confirm-binding`); the old key revoked at the provider afterwards produces `provider_auth`, never a silent fallback | The steps taken and the outcome before and after |
| D5 | Egress | AI egress ignores proxy environment variables (`trust_env=False`): the network must allow direct HTTPS to the provider host on its configured port, and nothing else is needed. A private or internal endpoint needs an explicit `ai-trust-create` entry | A successful request through the production network path; a refused request to a non-allowed host |
| D6 | Timeouts and response size | Measure, for the deployment's use cases and model, the time to a complete response at the largest `max_output_tokens` used, and the largest response size. Set `AI_EGRESS_TOTAL_DEADLINE_SECONDS` above the observed maximum with margin, `AI_EGRESS_READ_TIMEOUT_SECONDS` above the longest gap before the first byte, and `AI_EGRESS_MAX_RESPONSE_BYTES` above the largest response | The measurements (count, maximum, p95), the chosen values and the reasoning |
| D7 | Concurrency | Choose `AI_INFERENCE_TENANT_CONCURRENCY` and `AI_INFERENCE_GLOBAL_CONCURRENCY` from the provider's rate limits for the account and the worker capacity; run concurrent requests above the tenant limit and confirm `InferenceCapacityExhaustedError` and the `ai_inference_capacity_exhausted` log event | The chosen values; the over-limit test outcome |
| D8 | Redis | Stop Redis in the non-production environment: inference refuses with `InferenceInternalError("admission_unavailable")` and nothing is sent; on restart, requests succeed again | Outcomes and log events |
| D9 | Token quota | Set `AI_INFERENCE_TOKEN_QUOTA_REQUIRED=true` unless unlimited AI spend for a tenant is acceptable; give each plan an `ai.tokens` limit; confirm a tenant over its limit is refused and a tenant without one is refused (`quota_not_configured`). The quota is soft: overshoot is bounded by concurrency times the largest per-request bound | Plan entitlements; outcomes |
| D10 | Cost visibility | Configure prices (`set_model_price`); confirm settled attempts carry `estimated_cost` with currency and pricing version; read totals with `platform.ai_usage:read`. Estimates are not billed amounts | A usage read-back for the test tenant |
| D11 | Monitoring | Route the structured log events to the deployment's log system and alert on them (section 4). SaaS OS has no metrics pipeline for AI admission (ADR-0054 section 12c, condition 6) | The alert rules |
| D12 | Database limits | Each request uses short transactions (authorization, attempt start, settlement) on the application pool; size the pool for the concurrency limits, and keep statement and idle-in-transaction timeouts as the deployment already sets them | Pool size and timeouts |
| D13 | Backup and recovery | The attempt ledger (`control_plane.ai_inference_attempts`), the AI configuration tables and the usage outbox are in the main database backup (`docs/BACKUP-RESTORE.md`); attempts left `started` by a crash are swept to `abandoned` (usage unknown) at the tenant's next request | The backup includes the schema `control_plane` |
| D14 | Rollback | A rollback of the product to an earlier SaaS OS pin keeps the AI tables (migrations are additive). A pin whose migration history does not contain the database's head cannot run its own `saas-os-migrate upgrade` (it exits 1, `Can't locate revision`, and changes nothing): skip that pin's migration step. Downgrading the database is a separate decision, not part of a rollback. Disable inference by removing the `ai.inference` entitlement from plans or withdrawing the installation destination policy (`ai-destination-policy`), which refuses before anything is sent | The chosen switch and its tested effect |

## 4. Operational signals and runbook pointers

Structured log events (logger `saas_os.control_plane.inference.*`; fields never carry content, credentials or tenant data beyond ids):

| Event | Meaning | First response |
|---|---|---|
| `ai_inference_attempt` | One provider attempt, with provider, model, outcome, category and duration | Baseline for latency and error rates per provider and model |
| `ai_provider_circuit_open` | A (provider, model) failed repeatedly before acceptance (fields `ai_provider`, `ai_model`); requests skip that model until the circuit closes | Provider outage: check the provider's status; requests fall back to other alias candidates if configured |
| `ai_inference_capacity_exhausted` | A tenant or the installation hit its concurrency limit | Quota exhaustion or a burst: compare with D7; raise the limit only within the provider's rate limit |
| `ai_inference_admission_unavailable` | Redis unreachable: every request is refused | Restore Redis |
| `ai_provider_credential_unavailable` | A configured credential is not provisioned or the secrets backend failed | Credential rotation or provisioning error: D3, D4 |
| `ai_token_quota_invalid` | A plan's `ai.tokens` is malformed (treated as no limit unless required) | Fix the plan entitlement |
| `ai_inference_settlement_failed`, `ai_inference_attempt_unrecorded`, `ai_inference_denial_unrecorded` | The database rejected an evidence write; for settlement after a provider success the caller got an error and the usage of that attempt is unknown | Database health; the attempts are swept to `abandoned` |
| `ai_inference_adapter_failure` | An unexpected exception inside an adapter | A defect: report it |

Provider-side rate limits appear as `rate_limited` attempt outcomes; repeated ones mean the account's limits are lower than the configured concurrency. An OpenAI-compatible account without credit or past its own usage limit appears as `provider_quota_exhausted` (not retried; the request falls back if another destination is configured): top up or raise the limit at the provider.

## 5. What remains outside this procedure

Streaming, tool calls, tenant-owned credentials, provider-report reconciliation, hard token caps, Bedrock and Vertex AI are not implemented (`docs/RELEASE-READINESS.md` section 6). No SLA, RPO, RTO or certification is implied.
