# ADR-0009: Observability standard and backend

Status: Accepted (instrumentation standard) — Backend vendor remains a separate, unresolved decision (see below)
Date: 2026-09-06
Supersedes / Superseded by: —

## Context

`infra/observability` needs an instrumentation standard and a storage/query backend for logs, metrics, and traces, satisfying the correlation scheme in `docs/OBSERVABILITY.md` §2.

## Options Considered

### Option A — OpenTelemetry (instrumentation) + a managed backend (Grafana Cloud, Honeycomb, Datadog, etc.)
- Advantages: vendor-neutral instrumentation standard avoids locking the SDK choice to a backend vendor; managed backend avoids operating observability infra at this stage
- Disadvantages: managed-backend cost scales with volume; still a vendor dependency for the backend even if the instrumentation layer is portable

### Option B — Vendor-specific SDK + matching backend (e.g., Datadog SDK + Datadog)
- Advantages: potentially tighter integration/features with that vendor
- Disadvantages: instrumentation code becomes vendor-coupled, not just the backend; harder to switch backends later

### Option C — Self-hosted stack (e.g., Prometheus + Loki + Tempo + Grafana)
- Advantages: no per-volume vendor cost; full control; pairs naturally with the Docker Compose + VPS deployment target (ADR-0010) since it requires no external managed service
- Disadvantages: operational burden of running and scaling observability infra

## Recommendation

OpenTelemetry as the instrumentation standard (part of Option A/B/C alike). Backend selection remains open — a self-hosted stack (Option C) is worth weighing more seriously than the original recommendation given ADR-0010's VPS-based deployment target, but this is not decided here.

## Decision

**Accepted — instrumentation standard only.** OpenTelemetry is the platform's standard for logs, metrics, and traces across every layer (Core, Infra, AI Control Plane, Product). Every module instruments through the OTel SDK/conventions, never a vendor-proprietary SDK directly, so the backend can be chosen or changed independently of instrumentation code.

**Not yet decided**: which backend receives and stores this telemetry (managed service vs. self-hosted). This is tracked as a residual open decision (see `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md`) and does not block Phase 1–2 work, since `infra/observability`'s OTel instrumentation can emit to a local/console exporter during early development regardless of the eventual production backend.

The correlation-ID scheme (`docs/OBSERVABILITY.md` §2) is extended per this decision to explicitly include a **deployment/version dimension**, so telemetry can be correlated to a specific deployment or release in addition to tenant, user, request, and agent action — necessary given the platform's rollback and autonomous-DevOps ambitions (`docs/DEPLOYMENT-ARCHITECTURE.md` §6, `docs/AI-CONTROL-PLANE.md`).

## Rejected Alternatives

- **Vendor-specific SDK (Option B)**: rejected — instrumentation-layer vendor lock-in is unnecessary when OpenTelemetry provides the same capability without it.

Self-hosted (Option C) and managed-backend (Option A) are **not** rejected — the choice between them is the open residual decision noted above.

## Future Migration / Extension Path

Because instrumentation is OTel-standard regardless of backend, changing or adding a backend later (e.g., starting self-hosted and moving to a managed service as volume grows, or vice versa) requires only an exporter/collector configuration change — no application code touching logging/metrics/tracing needs to change.

## What Would Be Difficult to Change Later

The correlation ID scheme (`docs/OBSERVABILITY.md` §2) is independent of the backend choice and must be baked into the shared SDK from Phase 1 regardless — retrofitting it after significant code exists without it is tedious (every call site needs updating), even though it isn't catastrophic.

## Related

`docs/OBSERVABILITY.md`; `docs/ARCHITECTURE-DISCOVERY.md` §15; ADR-0010; `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md`.
