# Phase 0.1 — Architecture Review

Status: COMPLETE — including the language/runtime gap this review originally flagged as blocking (§6.1), now resolved by `docs/ADR/0011-backend-language-and-toolchain.md` (see §6 Addendum). This document is the decision record and documentation-consistency review for Phase 0.1. It supersedes the "PROPOSED" status previously carried by ADR-0002, ADR-0005–0010, and records the addition of ADR-0011. **The secrets-backend item this review left open (§2, §6 item 2) is now resolved by `docs/ADR/0012-secrets-management.md` — see `docs/PHASE-0.3-SECRETS-DECISION.md` for that decision record and the current Phase 0 closure status.**

Date: 2026-09-06 (updated same day with ADR-0011; secrets item closed same day via ADR-0012 / PHASE-0.3)

## 1. Approved Decisions

All seven decisions submitted for Phase 0.1 review are **Accepted**, with reasoning, rejected alternatives, and migration paths recorded in their respective ADRs.

| # | Area | Decision | ADR |
|---|---|---|---|
| 1 | Multi-tenancy | PostgreSQL, shared database, shared schema, row-level tenancy. Canonical column `tenant_id` (== `organization_id` — one entity, one ID, see §3 below). Centralized enforcement at the `infra/db` chokepoint; PostgreSQL RLS as defense in depth. Dedicated-database escape hatch reserved for later via storage-location indirection. | `docs/ADR/0002-multi-tenancy-isolation-model.md` |
| 2 | Identity | ZITADEL as external Identity Provider via OIDC. `core/identity` is the OIDC relying party and owns session issuance, user↔org mapping, and machine identity — it does not store credentials. `core/rbac` owns all application authorization/permissions, entirely independent of the IdP. | `docs/ADR/0005-identity-build-vs-buy.md` |
| 3 | API | REST, documented with OpenAPI as the source of truth. External API versioned from the first release via URL path segment (`/v1/...`). Internal API versioned per-module interface. | `docs/ADR/0006-api-style-and-versioning.md` |
| 4 | Background jobs | Redis-backed `infra/jobs` for single-step, retryable tasks. No distributed workflow engine introduced now. `infra/jobs`'s interface is deliberately kept narrow so a durable workflow engine (e.g., Temporal) can be added later, specifically for AI Control Plane multi-step workflows, without a rewrite. | `docs/ADR/0007-background-job-and-workflow-engine.md` |
| 5 | Billing | Provider-abstraction interface in `core/billing`, Stripe as the first (and initially only) adapter. Plans, Subscriptions, Entitlements, Usage, Invoices, and Payments modeled as distinct, provider-agnostic concepts. | `docs/ADR/0008-billing-provider.md` |
| 6 | Observability | OpenTelemetry as the platform-wide instrumentation standard. Correlation scheme extended to five dimensions: `tenant_id`, `user_id`, `request_id`, `agent_id`/`action_id`, `deployment_id`/`version`. | `docs/ADR/0009-observability-backend.md` |
| 7 | Deployment | Docker + Docker Compose + a single VPS as the initial deployment target. Kubernetes explicitly not implemented now. `infra/deploy` defines a deployment-target interface (build/push/deploy/health-check/rollback) so Kubernetes or a managed platform can be added later behind the same interface. | `docs/ADR/0010-deployment-target.md` |
| 8 | Backend language/toolchain + frontend | Python 3.13+, FastAPI, SQLAlchemy 2.x, Alembic, Redis+ARQ (concrete implementation of decision 4), pytest, Ruff, Pyright (switched from mypy in Phase 1.1). Frontend: TypeScript + Next.js. | `docs/ADR/0011-backend-language-and-toolchain.md` |

Cross-references updated as part of accepting these decisions: `docs/ARCHITECTURE.md` (§4 module ownership, new §10 technology-decisions summary), `docs/SECURITY.md` (§2 authentication boundary rewritten for the ZITADEL/OIDC split, §3 authorization boundary clarified as IdP-independent, §11 open-decisions list), `docs/MULTI-TENANCY.md` (§1 tenant/organization terminology, §2 isolation model), `docs/DATA-ARCHITECTURE.md` (§9 PostgreSQL accepted), `docs/API-ARCHITECTURE.md` (§3–§5 REST/OpenAPI/versioning accepted), `docs/DEPLOYMENT-ARCHITECTURE.md` (§5, §8 deployment-target interface), `docs/OBSERVABILITY.md` (§2 correlation scheme, §5 standard accepted/backend open), `docs/AI-CONTROL-PLANE.md` (§7 agent identity via machine-identity path, execution-substrate constraint), and `docs/IMPLEMENTATION-ROADMAP.md` (Phases 0.1, 1.4, 2.1, 2.2, 2.4, 3.2, 5.1, 8.2).

## 2. Remaining Unresolved Decisions

These do not block Phase 1 (repository scaffolding, boundary enforcement, CI skeleton) but must be resolved before the phase that depends on them, as noted:

| Decision | Status | Blocks |
|---|---|---|
| Observability backend vendor (managed service vs. self-hosted stack) | Open, tracked in `docs/ADR/0009-...` | Nothing before Phase 2.2 ships a production exporter; local/console exporter suffices until then |
| Secrets management backend (cloud secrets manager, Vault, or a simpler mechanism compatible with the VPS target) | Open | Phase 2.3 (`infra/secrets`) needs at least a placeholder decision to start; a full production-grade choice can follow |
| Compliance target (SOC2/GDPR/etc., if any, and its timeline) | Open, no urgency at zero-customer stage | Formal data-classification/retention policy (`docs/SECURITY.md` §9); does not block early phases |
| AI Control Plane model/provider abstraction (commit to Claude/Claude Agent SDK only, vs. build a provider-agnostic layer) | Open | Phase 7 (AI Control Plane v0) |
| ~~Primary application language/runtime~~ | **Resolved** — Python 3.13+/FastAPI/SQLAlchemy 2.x/Alembic/Redis+ARQ/pytest/Ruff/Pyright backend, TypeScript+Next.js frontend (`docs/ADR/0011-...`) | See §6 Addendum |
| Python package manager (`uv`/`poetry`/plain `pip`) and Node package manager (`npm`/`pnpm`/`yarn`) | Resolved for Phase 1.1: plain `pip`+`setuptools` used as the neutral default (no lock-in decision made); `npm` used for the frontend. `uv`/`poetry` remain open if a future phase wants to revisit. | Not blocking |
| mypy vs. pyright | **Resolved during Phase 1.1: Pyright** (Phase 1.1 instructions specified it directly; ADR-0011 pre-authorized this exact substitution as a tooling note, not a new ADR — see ADR-0011's "Tooling note") | Not blocking |
| ~~Secrets backend~~ | **Resolved** — provider-agnostic `SecretsProvider`; dev = `.env`; initial prod = Docker/host runtime injection; Vault/cloud/Docker Secrets deferred (`docs/ADR/0012-...`) | See `docs/PHASE-0.3-SECRETS-DECISION.md` |

## 3. Documentation Consistency Review

A structured check was performed against the categories requested. Findings and their resolution status:

### 3.1 Contradictory technology choices
- **Found and resolved**: `docs/ARCHITECTURE-DISCOVERY.md` §21 (an exploratory, non-binding table from the discovery phase) lists TypeScript/Go/Python as candidate languages and Fly.io/Render/Cloud Run/ECS as candidate deploy targets — both superseded for deployment by ADR-0010 (Docker Compose + VPS). This is **not** a live contradiction: the discovery document is explicitly historical/exploratory (its own status line says so), and all currently-authoritative documents (`ARCHITECTURE.md`, `DEPLOYMENT-ARCHITECTURE.md`, the ADRs) now agree. No edit was made to the discovery doc itself, since rewriting historical exploration would destroy the record of what was considered — but this review makes explicit that `docs/ARCHITECTURE-DISCOVERY.md` §21 is superseded by `docs/ARCHITECTURE.md` §10 and the ADRs for anything it conflicts with.
- **No other contradictions found**: multi-tenancy (Postgres row-level), identity (ZITADEL/OIDC), API (REST/OpenAPI), jobs (Redis), billing (Stripe-adapter), observability (OTel), and deployment (Compose/VPS) are now stated consistently across every document that references them.

### 3.2 Undefined ownership
- **Found and resolved**: prior to this pass, `core/identity`'s ownership boundary was ambiguous about which parts of "authentication" it owned once an external IdP entered the picture. Resolved in `docs/SECURITY.md` §2 and `docs/ADR/0005-...`: ZITADEL owns credential verification; `core/identity` owns everything on the platform side (OIDC integration, session issuance, user↔org mapping, machine identity).
- **Found and resolved**: `core/billing`'s prior "Plans, subscriptions, invoices, entitlements" ownership line did not mention Payments or the provider-abstraction boundary. Resolved in `docs/ARCHITECTURE.md` §4 and `docs/ADR/0008-...`: Payments added explicitly; the provider-abstraction interface is now the stated ownership boundary between Core-owned concepts and the Stripe adapter.
- **No other undefined ownership found**: the module ownership table in `docs/ARCHITECTURE.md` §4 and the schema ownership rules in `docs/DATA-ARCHITECTURE.md` §1 remain internally consistent with the accepted decisions.

### 3.3 Circular dependencies
- **None found.** The dependency rule (`docs/ARCHITECTURE.md` §2) — Product → Core → Infra, AI Control Plane → Core/Infra via tools only, Core never → Product — is unaffected by any of the seven decisions. ZITADEL is an external system `core/identity` depends on, not a platform module, so it does not introduce an internal cycle. Stripe is similarly external, behind `core/billing`'s abstraction. Redis is an external dependency of `infra/jobs` only.

### 3.4 Unclear tenant boundaries
- **Found and resolved**: the user's instruction referred to "`tenant_id` / `organization_id`" as if they might be two related-but-distinct identifiers, which — left unaddressed — would have been exactly the kind of ambiguity `docs/ARCHITECTURE-DISCOVERY.md` §23 warned against. Resolved explicitly in `docs/MULTI-TENANCY.md` §1 and `docs/ADR/0002-...`: **tenant and organization are the same entity**, one canonical ID (`tenant_id` internally; may be surfaced as `organization_id` in APIs/UI for end-user familiarity), one table (`core.tenants`). This is now stated as a binding rule, not left implicit.

### 3.5 Unclear identity boundaries
- **Found and resolved**: without explicit treatment, "ZITADEL as IdP" could have been misread as ZITADEL also owning authorization/permissions (some IdPs offer this). Resolved explicitly in `docs/SECURITY.md` §2–§3 and `docs/ADR/0005-...`: authorization is 100% `core/rbac`'s responsibility, independent of and never delegated to ZITADEL — matching the user's explicit instruction ("SaaS OS owns application authorization and permissions, not authentication infrastructure").
- **Found and resolved**: AI agent identity's relationship to the human OIDC flow was previously unstated. Resolved in `docs/AI-CONTROL-PLANE.md` §7: agents are authenticated through a separate machine-identity mechanism inside `core/identity`, never through ZITADEL's human login flow, while still resolving to the same identity-context shape for `core/rbac`.

### 3.6 Unclear API ownership
- **None found.** `docs/API-ARCHITECTURE.md` §2's ownership table was already unambiguous and required no changes beyond confirming REST/OpenAPI/versioning as Accepted (§3–§5).

### 3.7 Unclear deployment ownership
- **Found and resolved**: the original `docs/DEPLOYMENT-ARCHITECTURE.md` §8 described the deployment target as an open, directional default without a concrete interface obligation. Resolved: §8 now states the binding `infra/deploy` deployment-target interface (build/push/deploy/health-check/rollback) as a design constraint, not an aspiration, directly addressing the instruction to "design deployment interfaces so Kubernetes/cloud providers can be added later."

### 3.8 Unclear AI permissions
- **None found beyond §3.5's identity-boundary fix.** The tool-mediated-access rule (`docs/ADR/0004-...`, unaffected by this round of decisions) and the autonomy-tier framework (`docs/SECURITY.md` §7, `docs/AI-CONTROL-PLANE.md` §5) remain internally consistent. The one addition made here is the explicit constraint in `docs/AI-CONTROL-PLANE.md` §7 that multi-step agent workflows must not be built on top of simple Redis jobs (see §3.9 below) — this is a permissions-adjacent boundary (what an agent tool is allowed to be built on) worth flagging even though it isn't a human/agent permission per se.

### 3.9 Future migration blockers
- **Identified and mitigated, not eliminated**: the Redis-jobs-now / workflow-engine-later decision (ADR-0007) carries a real risk — if a future AI Control Plane capability is built by hand-rolling multi-step state tracking on top of `infra/jobs` because introducing Temporal feels like overhead at the time, that becomes the exact "one-way door" the ADR was written to prevent. This is not a documentation inconsistency; it is a process risk. Mitigation recorded in `docs/AI-CONTROL-PLANE.md` §7 and `docs/ADR/0007-...`: any Control Plane capability needing multi-step durability is explicitly defined as the trigger to introduce the workflow engine, not a signal to work around its absence. This constraint should be treated as a review checklist item when Phase 7 begins.
- **Identified and mitigated**: the Docker Compose + VPS deployment target (ADR-0010) risks the same class of blocker if Compose/VPS-specific assumptions leak into CI stages 1–4 or application code. Mitigated by making the `infra/deploy` interface boundary explicit and binding (`docs/DEPLOYMENT-ARCHITECTURE.md` §8) rather than a soft convention.
- **Identified, not yet mitigated (flagged for Phase 1)**: the primary application language/runtime was never formally decided via ADR (see §2 above) — `docs/ARCHITECTURE-DISCOVERY.md` §21 only lists it as a directional candidate. Phase 1.2 (toolchain baseline) cannot proceed without this decision, and retroactively changing language after Phase 1–2 code exists would be a substantial migration. **This is the most consequential gap surfaced by this review.**

## 4. Architectural Risks (Carried Forward and New)

In addition to the risks already catalogued in `docs/ARCHITECTURE-DISCOVERY.md` §23 (which remain valid and are not repeated in full here), this review surfaces:

1. **Language/runtime decision gap** (§2, §3.9) — the single highest-priority item before Phase 1.2.
2. **ZITADEL operational dependency**: whether self-hosted (adds an operational component to the Docker Compose stack) or managed (adds an external dependency and cost), ZITADEL is now a hard dependency for every authenticated request path. Its own availability/backup story should be planned before Phase 3.2, not discovered during an incident.
3. **Redis as a hard dependency for two concerns**: if Redis is used for both caching and `infra/jobs`, a Redis outage now affects both — this coupling should be evaluated (separate instances/databases vs. shared) when Phase 2.4 is implemented, not assumed away.
4. **Single-VPS deployment has no built-in redundancy** (ADR-0010, honestly stated in its own disadvantages list) — acceptable for the current stage per explicit non-goals (`docs/ARCHITECTURE-DISCOVERY.md` §4), but should not be forgotten as tenant count grows; the `infra/deploy` interface abstraction exists specifically so this is a future infrastructure change, not a future rewrite.
5. **Stripe adapter must not leak**, per the discipline in ADR-0008 — this requires active code-review discipline in Phase 5.1, not just the documented interface, since the temptation to reach for a Stripe type directly "just this once" is the realistic failure mode.

## 5. Decisions Intentionally Deferred

Restated for clarity — these are deliberate, not oversights:

- Distributed workflow engine adoption (ADR-0007) — deferred until an AI Control Plane capability actually needs it (Phase 7+).
- Kubernetes / managed cloud deployment (ADR-0010) — deferred until scale or reliability needs demand it, behind the `infra/deploy` interface.
- Observability backend vendor (ADR-0009) — deferred; instrumentation standard (OpenTelemetry) is enough to unblock early phases.
- Hybrid dedicated-database-per-tenant escape hatch (ADR-0002) — deferred until an enterprise/compliance tenant actually requires it, behind the `infra/db` storage-location indirection.
- Formal compliance program (SOC2/GDPR/etc.) — deferred until a concrete customer or regulatory driver exists, per `docs/ARCHITECTURE-DISCOVERY.md` §17.
- AI Control Plane model-provider abstraction — deferred; Claude/Claude Agent SDK is the working assumption until Phase 7 revisits it.

## 6. Preconditions for Phase 1

Phase 1 (`docs/IMPLEMENTATION-ROADMAP.md`, repository scaffolding and boundary enforcement) may begin once:

1. ~~The language/runtime and toolchain decision is made and recorded as an ADR.~~ **RESOLVED** — see §6 Addendum below.
2. ~~A decision exists for the secrets backend sufficient to unblock `infra/secrets` (Phase 2.3).~~ **RESOLVED** — `docs/ADR/0012-secrets-management.md`; full record in `docs/PHASE-0.3-SECRETS-DECISION.md`.
3. This document, `docs/PHASE-0.3-SECRETS-DECISION.md`, and all twelve ADRs (0001–0012) are reviewed and confirmed by the human owner as accurately reflecting their intent.

No precondition blocks any part of Phase 1 (1.1–1.4) from starting. See `docs/PHASE-0.3-SECRETS-DECISION.md` for the authoritative statement that Phase 0 is now fully unblocked.

## 6 Addendum — Language/Runtime Gap Resolved

The blocking gap identified in the original version of this review (§3.9, §6.1) — no ratified primary application language — is resolved. The human decision-maker supplied the full backend and frontend stack directly: **Python 3.13+, FastAPI, PostgreSQL (already Accepted, ADR-0002), SQLAlchemy 2.x, Alembic, Redis + ARQ (concrete implementation of ADR-0007), ZITADEL/OIDC (already Accepted, ADR-0005), OpenAPI (already Accepted, ADR-0006), OpenTelemetry (already Accepted, ADR-0009), TypeScript + Next.js frontend, Docker + Docker Compose (already Accepted, ADR-0010), pytest, Ruff, and mypy** (chosen over pyright as the default — recorded as low-cost to reverse). Recorded as `docs/ADR/0011-backend-language-and-toolchain.md`.

**Consistency check performed on this addition**: every element of the supplied stack was checked against the seven previously Accepted ADRs for conflict. None found — FastAPI's native OpenAPI generation directly implements ADR-0006; SQLAlchemy 2.x becomes the concrete implementation of the `infra/db` tenant-scoping chokepoint required by ADR-0002; ARQ is a Redis-based library, consistent with (and now the concrete fulfillment of) ADR-0007's "Redis-backed, no workflow engine yet" decision; Docker Compose already covers both the Python backend and Next.js frontend as services. Two small residual items were newly surfaced and are non-blocking: the Python and Node package managers (`docs/ADR/0011-...` explicitly scopes these below ADR-level, deferred to Phase 1.2 directly) and the choice of a Python import-boundary tool for Phase 1.3 (directionally `import-linter`, not formally pinned).

## 7. Next Step

Per the governing instructions for this phase: **stop here.** No `core/`, `infra/`, `control-plane/`, `products/`, or `frontend/` directories have been created; no dependencies have been installed; no application code has been written. Both gaps this review tracked (language/toolchain, §6 Addendum; secrets backend, resolved via `docs/ADR/0012-...`) are now closed. See `docs/PHASE-0.3-SECRETS-DECISION.md` for the authoritative, current statement of Phase 0 closure.
