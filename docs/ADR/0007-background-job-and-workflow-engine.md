# ADR-0007: Background job execution vs. durable workflow engine

Status: Accepted
Date: 2026-09-06 (refined 2026-09-06 with concrete library per `docs/ADR/0011-backend-language-and-toolchain.md`)
Supersedes / Superseded by: —

## Context

The platform needs background execution for webhook delivery, usage aggregation, billing sync, notifications, and — critically — AI Control Plane multi-step autonomous workflows (`docs/AI-CONTROL-PLANE.md` §7), which benefit from durable, resumable, compensable execution far more than simple fire-and-forget jobs do.

## Options Considered

### Option A — Redis-backed job/queue framework for everything
- Advantages: simplest to operate; Redis is likely already present for caching, so no new infrastructure dependency; sufficient for core plumbing (notifications, webhook retries, usage aggregation)
- Disadvantages: no native support for durable multi-step orchestration with compensation/resumption semantics — a poor fit, on its own, for autonomous incident-response or DevOps workflows that span multiple systems and need reliable resumption after failure

### Option B — Managed queue service only (SQS, Cloud Tasks)
- Advantages: offloads operational burden of running queue infrastructure
- Disadvantages: same orchestration-semantics gap as Option A; adds cloud-provider coupling not otherwise required by the Docker Compose + VPS deployment target (ADR-0010)

### Option C — Redis-backed queue for core plumbing now + a durable workflow engine (e.g., Temporal) introduced later specifically for AI Control Plane multi-step workflows
- Advantages: matches tool to job — cheap/simple where sufficient, durable/resumable where the AI Control Plane's blast-radius and reliability needs actually require it later; defers the operational cost of a second piece of infrastructure until it is actually needed
- Disadvantages: requires deliberate interface design now so the later addition doesn't force a rewrite (see below)

## Recommendation

Option C, starting with Redis only.

## Decision

**Accepted.** `infra/jobs` is implemented as a Redis-backed background worker queue (retry/backoff, dead-letter handling per `docs/DATA-ARCHITECTURE.md` §5), concretely using **ARQ** (an asyncio-native Redis job library, matching the Python/FastAPI runtime fixed by `docs/ADR/0011-backend-language-and-toolchain.md`). **A distributed workflow engine is explicitly not introduced at this stage.**

To keep this reversible, `infra/jobs` exposes a minimal, deliberately narrow interface — enqueue, execute, retry-on-failure, dead-letter — and is used only for tasks that are genuinely single-step-retryable (a webhook delivery, a usage-aggregation run, a notification dispatch). Multi-step, stateful, or compensating logic (the kind the AI Control Plane's incident-resolution and DevOps agents will eventually need, per `docs/AI-CONTROL-PLANE.md` §4, §7) must **not** be built by chaining `infra/jobs` calls with hand-rolled state tracking — that would recreate workflow-engine semantics on top of a primitive that doesn't support them safely, which is precisely the one-way door this ADR exists to avoid. Any Control Plane capability that needs multi-step durability is a signal to introduce the workflow engine, not to work around its absence.

## Rejected Alternatives

- **Managed cloud queue (SQS/Cloud Tasks, Option B)**: rejected — adds cloud-provider coupling that doesn't match the Docker Compose + VPS deployment target (ADR-0010), and offers no orchestration-semantics advantage over Redis for the jobs it would actually run today.
- **Adopting a workflow engine now**: rejected as premature — no capability yet exists that needs it (Phase 7+ in `docs/IMPLEMENTATION-ROADMAP.md` is still ahead), and introducing it now would be operational overhead without a consumer to justify it.

## Future Migration / Extension Path

When the AI Control Plane's multi-step autonomous workflows are built (`docs/IMPLEMENTATION-ROADMAP.md` Phase 7+), evaluate and introduce a durable workflow engine (Temporal or equivalent) as a second execution substrate used specifically for those workflows, alongside — not replacing — `infra/jobs` for simple single-step tasks. Because `infra/jobs`'s interface was kept narrow (per the Decision above), this addition is additive rather than a migration of existing job producers.

## What Would Be Difficult to Change Later

If multi-step autonomous agent workflows are built by layering ad hoc state-tracking on top of simple Redis jobs (violating the constraint above), migrating them to a durable workflow engine later means rewriting their control flow entirely, since durable-execution semantics change how a workflow's steps are expressed. This constraint exists specifically to prevent that outcome.

## Related

`docs/AI-CONTROL-PLANE.md` §7; `docs/DATA-ARCHITECTURE.md` §5; `docs/ARCHITECTURE-DISCOVERY.md` §13; ADR-0010; ADR-0011 (concrete library: ARQ).
