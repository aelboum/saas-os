# Observability Architecture

Status: ACCEPTED (boundary rules, correlation scheme, and instrumentation standard — OpenTelemetry). Backend vendor remains open — see §5 and `docs/ADR/0009-observability-backend.md`.

**Implementation status** (`docs/IMPLEMENTATION-ROADMAP.md` Phase 2.2): `infra/observability` implements the §2 correlation scheme (logs + traces, via `bind_correlation_context()`/`configure_logging()`/`configure_tracing()`) with a local/console exporter, matching §5's "OTel can emit to a local/console exporter during early development." Metrics (§3) are not yet implemented — deferred to a later phase, not part of Phase 2.2's scope.

**P1.4 (API request-lifecycle wiring)**: `api.middleware.CorrelationIdMiddleware` establishes `request_id` for every inbound `/v1` request — reusing an incoming `X-Request-ID` header when present and well-formed, otherwise generating one — and returns it under that same header. `X-Request-ID` is this platform's one canonical correlation header (no other convention existed prior to this). Job-level (`infra/jobs`) correlation propagation is not yet implemented — deferred, no current call site requires it.

## 1. Ownership

- `infra/observability` owns the instrumentation SDK/conventions and the pipeline to a backend (logs/metrics/traces storage and query).
- Each module (Core, Control Plane, each Product) owns *what* it instruments — its own log statements, custom metrics, and span names — but must do so through the shared SDK/conventions rather than inventing its own logging format or metrics client.

## 2. Correlation Scheme (Required, Platform-Wide)

Every log line, metric, and trace span emitted anywhere in the platform must carry, where applicable:

- `tenant_id` — which tenant this activity belongs to (absent only for genuinely tenant-agnostic platform-internal activity)
- `user_id` — the human actor, if any
- `request_id` — correlates all activity within one inbound request/job execution
- `agent_id` / `action_id` — present whenever an AI Control Plane agent is the actor, correlating the specific tool invocation to its logs/traces/audit entry (`docs/SECURITY.md` §8)
- `deployment_id` / `version` — present on all signals, correlating activity to the specific deployment/release that produced it, enabling deployment-scoped tracing (e.g., "show all errors since release X") and feeding the rollback decision process (`docs/DEPLOYMENT-ARCHITECTURE.md` §6)

This scheme is treated as a platform-wide contract enforced by the shared SDK (e.g., context propagation baked into the `infra/observability` client), not left to each module to remember to attach manually.

## 3. Signal Types and Ownership Split

| Signal | Owned by (mechanism) | Owned by (content) |
|---|---|---|
| Logs | `infra/observability` (structured logging conventions, transport) | Each module (what it logs) |
| Metrics | `infra/observability` (collection, dashboards infra) | Each module (business-relevant metrics it exposes) |
| Traces | `infra/observability` (tracing SDK, span propagation) | Each module (span boundaries within its own code) |
| Health signals | `infra/health` (aggregation) | Each module (its own health definition) — see `docs/DEPLOYMENT-ARCHITECTURE.md` §7 |
| Alerts | `infra/observability` (alerting mechanism) | Each module/team (alert thresholds relevant to its own domain) |

## 4. AI Control Plane Observability

Distinct from application observability: every agent action must be traceable end-to-end — which agent, which tool, what input, what approval state, what output — correlated via `agent_id`/`action_id` (§2) and cross-linked to the corresponding `core/audit-log` entry (`docs/SECURITY.md` §8). This is what answers "what did the AI do and why" without a separate investigation process, and is a prerequisite (not an optional nicety) for raising any capability's autonomy level (`docs/SECURITY.md` §7).

## 5. Standard (Accepted) and Backend (Open)

**OpenTelemetry is the Accepted instrumentation standard** (`docs/ADR/0009-observability-backend.md`) — every module instruments through the OTel SDK/conventions, never a vendor-proprietary SDK directly, so the backend can be chosen or changed independently of instrumentation code.

**The backend (where telemetry is stored/queried) remains an open decision** — a managed service (Grafana Cloud, Honeycomb, Datadog) and a self-hosted stack (Prometheus/Loki/Tempo/Grafana, which pairs naturally with the Docker Compose + VPS deployment target, `docs/ADR/0010-deployment-target.md`) are both live options. This does not block Phase 1–2 work: OTel can emit to a local/console exporter during early development regardless of the eventual production backend.

## 6. Product Observability via the Contract

A Product declares its health checks (`docs/ARCHITECTURE.md` §9, `healthChecks`) through its contract; this is the mechanism by which the platform (and eventually the AI Control Plane's incident-resolution capability) discovers what "healthy" means for a product it did not build, without reading that product's source.

## 7. What Is Hard to Change Later

The correlation ID scheme (§2) is not catastrophic to retrofit but is tedious once a large amount of code exists without it — every log/span call site would need updating. Establishing it as a non-optional part of the shared SDK from Phase 1 avoids that cost entirely.
