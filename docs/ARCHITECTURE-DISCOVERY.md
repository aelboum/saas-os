# SaaS OS — Architecture Discovery

Status: DRAFT — awaiting human decisions. No implementation has started.

## 1. Executive Summary

`saas-os` is intended to become a reusable SaaS platform ("SaaS Operating System") that provides common capabilities — multi-tenancy, identity, billing, background jobs, observability, AI agents, and more — as a foundation that multiple products (starting with Dograh) can be built on top of, without any product-specific logic leaking into the core.

As of this discovery, the repository is **completely empty**: it contains only a `.git` directory with zero commits, zero files, and zero history. There is nothing to reverse-engineer, no prior architectural decisions to respect, and no legacy constraints to work around. This is a greenfield decision point — which is both the best possible starting condition (no debt) and the highest-risk moment (every early decision compounds).

This document does not propose file layouts filled with code. It maps the problem space, draws provisional boundaries between SaaS Core / Infrastructure / AI Control Plane / Product layers, flags the decisions that are expensive to reverse, and proposes a phased roadmap. **No implementation should begin until the "Human Decisions Required" section is resolved.**

## 2. Current Repository State

- Git: initialized, branch `main`, **0 commits**.
- Filesystem: **0 files** outside `.git/`.
- No package manifests, no `Dograh` reference code, no CI config, no docs, no license.
- No existing technology commitments of any kind (no language, framework, database, or cloud provider has been chosen).

**Implication:** every "identify what's already implemented" instruction in the task yields the same answer — nothing. This discovery is therefore purely forward-looking: it defines the decision space, not an audit of existing code.

## 3. Architectural Goals

- **Reusability first**: every capability in SaaS Core must be usable by a hypothetical "Product B" that has nothing to do with Dograh's domain (voice AI agents), without modification.
- **Product-agnostic core**: the core must not encode any assumptions about what a tenant's product *does* — only that tenants, users, permissions, subscriptions, usage, etc. exist.
- **Composable, not monolithic**: capabilities (billing, RBAC, notifications, …) should be independently understandable, testable, and — ideally — independently deployable/upgradable, even if they ship in one repo/one binary initially.
- **Boring core, adventurous edges**: multi-tenancy, auth, and billing should use proven, unglamorous patterns. The AI/autonomous-operations layer is where genuine R&D happens.
- **Human-in-the-loop autonomy by default**: "autonomous DevOps / incident resolution / customer support" agents should default to propose-and-approve, with a documented path to increasing autonomy — not the reverse.
- **Single source of truth for tenancy and identity**: every other capability (billing, audit logs, feature flags, usage metering) depends on tenant/user identity being modeled once, correctly, and consistently referenced.

## 4. Non-Goals

- Building Dograh's actual product features (voice agents, call flows, whatever is domain-specific to Dograh) inside this repo.
- Picking a single "one true way" to do autonomous AI agents platform-wide before any product has exercised it — the AI Control Plane should start narrow and proven, not speculative and broad.
- Supporting every possible billing model, auth provider, or cloud target from day one. Breadth should follow demonstrated need, not anticipated need.
- Multi-region / multi-cloud portability as a v1 requirement (unless a human decision states otherwise) — premature abstraction here is a classic monolith-in-disguise risk.
- Building a general-purpose PaaS/orchestrator. This is a product platform, not a Kubernetes competitor.

## 5. SaaS Core Responsibilities

Domain-agnostic, product-agnostic business primitives. If a capability requires knowing what the product *does*, it does not belong here.

- **Organizations & Tenancy**: tenant entity, tenant lifecycle (create/suspend/delete), tenant settings.
- **Users & Membership**: user identity records, org-membership, invitations.
- **Authentication / Identity**: login, session/token issuance, SSO/OAuth federation, MFA — the *mechanism*, not product-specific login UX.
- **RBAC / Permissions**: roles, permissions, policy evaluation, scoping (org-level, resource-level).
- **Billing & Subscriptions**: plans, entitlements, invoices, payment provider integration, dunning.
- **Usage Metering**: event ingestion, aggregation, quota enforcement hooks.
- **API Keys**: issuance, rotation, scoping, revocation for programmatic tenant access.
- **Webhooks (outbound)**: subscription management, delivery, retry, signing — as a generic dispatch capability.
- **Notifications**: generic dispatch abstraction (email/SMS/push/in-app) — templates and triggers are product-specific, the delivery pipe is core.
- **Audit Logs**: generic event-sourcing/append-only log capability with a stable event schema.
- **Feature Flags**: flag definitions, targeting rules, evaluation SDK.

## 6. Infrastructure Responsibilities

Cross-cutting technical concerns that every capability (core or product) relies on, but which are not themselves business logic.

- **Data storage primitives**: primary DB, object/file storage, cache.
- **Background jobs / queues**: generic job execution, scheduling, retry/backoff, dead-letter handling.
- **Observability**: logging, metrics, tracing, error reporting — instrumentation conventions, not product dashboards.
- **Health checks**: liveness/readiness endpoints, dependency health aggregation.
- **Deployment**: build/release pipeline, environment promotion, config/secrets management.
- **Migrations**: schema migration tooling and conventions (core-owned tables vs. product-owned tables must be migratable independently).
- **Backups & Rollback**: data backup policy, restore procedure, release rollback mechanism.
- **CI/CD**: test/build/deploy automation, environment gating.
- **Security**: secret management, dependency scanning, network/infra hardening — the platform-level half of "Security Architecture" (§17 covers the full picture including core-level security like authz).

## 7. AI Control Plane Responsibilities

The layer that lets AI agents *operate* the platform and *operate within* products, kept distinct from both core business logic and product features.

- **Agent orchestration substrate**: how agents are invoked, sandboxed, given tools, and audited — a runtime, not a specific agent.
- **Autonomous DevOps**: agents that can propose/apply infra changes, roll back bad deploys, respond to alerts.
- **Autonomous incident resolution**: agents that triage, diagnose, and (with approval gates) remediate incidents.
- **Autonomous customer support**: agents that answer tenant support requests, escalate, and act on tenant data within RBAC scope.
- **Autonomous development**: agents that write/review/ship code against this platform (e.g., "Claude Code as a citizen of the platform").
- **Guardrails**: approval workflows, blast-radius limits, audit trail integration (every AI action is an audit-logged action), kill switches.

**Boundary rule**: the Control Plane consumes SaaS Core capabilities (identity, RBAC, audit log, notifications) the same way a product would — it should not get a private backdoor into core data models. This is the single biggest lever against the platform quietly becoming "a bunch of AI agents with ambient god-mode access."

## 8. Product Layer Responsibilities

Everything that makes Dograh *Dograh* (or any future product *itself*):

- Domain models specific to the product (e.g., voice-agent call flows, conversation scripts).
- Product-specific UI/UX.
- Product-specific business rules layered on top of core entitlements (e.g., "what does a Dograh 'Pro' plan unlock" — the *plan concept* is core, the *unlock semantics* are product).
- Product-specific integrations (third-party APIs the product needs that aren't platform-wide concerns).
- Product-specific extensions to notification templates, webhook payload shapes, audit event types (using core-provided extension points, not forking core).

**Test for "is this core or product?"**: *Would a second, unrelated SaaS product need this exact capability, with only configuration differing?* If yes → Core. If the answer requires knowing what the product does → Product.

## 9. Multi-Tenancy Strategy

Options (not yet decided):

| Option | Advantages | Disadvantages | Difficulty to change later |
|---|---|---|---|
| **Shared DB, shared schema, tenant_id column** (row-level tenancy) | Cheapest to operate; simplest migrations; easiest cross-tenant admin queries | Requires airtight row-level filtering everywhere (RLS or app-layer discipline); noisy-neighbor risk; a single query bug leaks data across tenants | Hard — retrofitting isolation into every query later is a large, security-sensitive migration |
| **Shared DB, schema-per-tenant** | Stronger isolation than row-level; per-tenant migration flexibility | Migration fan-out cost grows with tenant count; connection/schema management complexity | Medium-hard |
| **DB-per-tenant** | Strongest isolation; simplest "delete a tenant" story; easiest per-tenant compliance/residency story | Expensive at scale; operationally heavy (migrations × N tenants); cross-tenant analytics is hard | Very hard to consolidate later if scale demands it |
| **Hybrid** (row-level by default, dedicated DB for enterprise/compliance tenants) | Matches cost to tenant value; common in mature SaaS platforms | More code paths to test and reason about | N/A if designed in from the start; hard to bolt on later |

Recommendation (non-binding, human must confirm): start with **row-level tenancy + enforced tenant_id scoping at the data-access layer (and DB-level RLS if the chosen database supports it)**, with the data-access layer designed so a tenant *could* be moved to a dedicated store later without changing calling code. This is the industry-default starting point and defers the DB-per-tenant cost until it's actually needed.

**What is hard to change later**: whether tenant scoping is enforced centrally (one chokepoint every query passes through) vs. ad hoc (every query author remembers to filter). Choosing "ad hoc" is effectively irreversible without a full data-access rewrite, and is the single most common source of catastrophic multi-tenant data leaks. This decision should be made deliberately, not by default.

## 10. Identity Strategy

Options:

- **Build vs. buy authentication** (roll your own vs. Auth0/Clerk/WorkOS/Ory/Keycloak/Supabase Auth, etc.).
  - Build: full control, no per-MAU cost, but real security burden (password storage, session mgmt, MFA, SSO/SAML protocol compliance) and ongoing maintenance.
  - Buy: fast to ship, offloads security-critical code to a specialist, but introduces vendor cost/lock-in and a dependency on the vendor's roadmap for enterprise features (SSO, SCIM).
- **User identity vs. org membership modeling**: a user should be modeled as global (one identity, many org memberships) rather than scoped per-org, so a person can belong to multiple tenants — this generalizes across almost every real SaaS.
- **Machine identity**: API keys and service-to-service auth (including AI agents acting on a tenant's behalf) need their own identity model distinct from human users, with clear attribution in audit logs ("agent X acting for user Y").

**What is hard to change later**: the user↔org relationship cardinality (1:1 vs 1:many) and the canonical user ID scheme. Every other capability (billing seats, RBAC, audit logs) references user/org IDs; changing the identity model after data exists is a platform-wide migration.

## 11. Data Architecture

Key open questions:

- **Relational vs. polyglot persistence**: a single relational database (Postgres being the default assumption for this kind of platform) is almost certainly right for core entities (tenants, users, billing, RBAC) given their transactional/relational nature. Usage metering and audit logs may warrant append-only/event-store or time-series storage as a secondary store.
- **Core/product schema separation**: core tables and product tables should be clearly namespaced (schema or naming convention) and migrated independently, so a product team doesn't need core-team sign-off for its own migrations, and vice versa.
- **Event-driven vs. synchronous integration between core and product**: e.g., does "subscription upgraded" propagate to product code via a domain event (core emits, product subscribes) or direct synchronous calls? Event-driven scales better for decoupling but adds eventual-consistency and debugging complexity.

**What is hard to change later**: the core/product schema boundary. If product code reaches directly into core tables (or vice versa) early on, un-tangling that later is a major refactor. This argues for enforcing the boundary via API/interface even if everything lives in one database initially.

## 12. API Architecture

- **REST vs. GraphQL vs. RPC (e.g., gRPC/tRPC)**: REST remains the safest default for a platform meant to be consumed by many future products and possibly external tenants (widest tooling support, simplest auth story). GraphQL adds flexibility but a bigger upfront investment (schema federation across core/product boundaries is itself a hard problem). RPC frameworks (tRPC) are attractive if the whole stack is one TypeScript codebase but couple client/server tightly.
- **Internal API (core→product, product→core) vs. external API (tenant-facing, third-party integrations)**: these have different versioning, auth, and stability requirements and should likely be architected as genuinely separate surfaces from day one, even if they share implementation code.
- **Versioning strategy**: must be decided before the first external consumer exists — retrofitting versioning onto an unversioned API is painful and typically requires a breaking migration for early adopters.

**What is hard to change later**: the public API's versioning scheme and auth model, once external tenants or Dograh itself depend on it.

## 13. Background Jobs

- Needed for: webhook delivery/retry, usage aggregation, billing sync, notification dispatch, AI agent async work (long-running autonomous tasks), scheduled maintenance (backups, cleanup).
- Options: language/framework-native queue (e.g., BullMQ/Sidekiq-equivalent) vs. managed queue service (SQS, Cloud Tasks) vs. a workflow engine (Temporal) for anything requiring durable multi-step orchestration (this matters a lot for autonomous agents that take actions across several systems and need reliable resumption/compensation).
- **Recommendation direction**: simple job queue for core plumbing (notifications, webhooks); seriously evaluate a durable workflow engine (e.g., Temporal) specifically for the AI Control Plane, since autonomous multi-step operations (incident resolution, DevOps actions) benefit enormously from durable execution, retries, and human-approval-as-a-workflow-step semantics.

**What is hard to change later**: if long-running autonomous agent workflows are first built on a simple fire-and-forget job queue, migrating them to a durable workflow engine later means rewriting their control flow, not just swapping infrastructure.

## 14. Billing / Usage Architecture

- **Build vs. buy**: Stripe Billing (or similar) for payment processing and subscription lifecycle is close to a default choice for a startup-stage SaaS platform — reimplementing payment processing/PCI concerns in-house is rarely justified. Usage metering/aggregation logic, however, is platform-specific enough that it likely needs custom code that *feeds into* Stripe (or whatever billing provider) rather than being replaced by it.
- **Entitlements model**: plan → features/limits mapping should be a core, product-agnostic data model (a generic "entitlement key + value" scheme) so each product defines its own entitlement keys without core code changes.
- **Usage metering pipeline**: needs an ingestion path that is cheap enough to call from hot paths (product code emitting usage events) without becoming a bottleneck — likely async (write to queue/log, aggregate later) rather than synchronous updates on every event.

**What is hard to change later**: the entitlement key schema and the usage-event schema, once products depend on them for gating features.

## 15. Observability Architecture

- Structured logging, metrics, and tracing conventions should be defined once at the platform level (e.g., every request/job carries tenant_id, user_id, request_id, and — critically for the AI Control Plane — agent_id/action_id for anything an AI agent does).
- **Recommendation direction**: adopt OpenTelemetry as the instrumentation standard from the start (vendor-neutral), pairing it with a managed backend (e.g., Grafana Cloud, Datadog, Honeycomb) rather than self-hosting observability infra initially.
- AI Control Plane observability is a distinct concern from application observability: agent actions need their own trace/audit correlation so a human can answer "what did the AI do, why, and was it approved."

**What is hard to change later**: the correlation ID scheme (tenant/request/agent-action IDs) — retrofitting trace correlation into an already-large system is tedious but not catastrophic; worth getting right early to avoid the tedium.

## 16. Deployment Architecture

- **Monorepo vs. polyrepo** for core/infra/product: a monorepo (single repo, clear internal package boundaries) is the more common and lower-friction choice at this stage, and doesn't preclude splitting into separate deployable services later — the internal boundary discipline matters more than the repo-count decision.
- **Single deployable vs. services**: starting as a modular monolith (one deployable, internally organized into core/infra/AI/product modules with enforced boundaries) is very likely the right early choice — it avoids premature distributed-systems tax while the org is small, provided module boundaries are real (enforced via code structure/lint rules, not just convention).
- **Target infra**: containerized deployment to a managed platform (e.g., Fly.io, Render, ECS, Cloud Run) is a reasonable default that avoids a full Kubernetes commitment until scale demands it.

**What is hard to change later**: nothing here is truly irreversible if module boundaries were enforced from the start — that enforcement is the actual load-bearing decision, not the specific deploy target.

## 17. Security Architecture

- **Authn/authz**: covered in §10/§5; RBAC must be checked at a single enforced layer (e.g., a policy-check middleware/decorator), not reimplemented ad hoc per endpoint.
- **Secrets management**: platform-level (infra) concern — dedicated secrets manager, not environment-variable sprawl, from day one.
- **AI agent authorization**: agents must operate under the same RBAC/audit system as human users, scoped to explicit tool permissions — never given raw DB/infra credentials directly. This is the most consequential security decision in this document given the "autonomous DevOps/incident resolution" goals: an over-privileged agent is a standing risk of platform-wide blast radius.
- **Tenant data isolation**: see §9 — the multi-tenancy strategy *is* the primary security boundary for customer data.
- **Compliance posture** (SOC2, GDPR, etc.): not urgent at zero-customer stage, but audit logging (§5) and data-deletion capability should be designed with eventual compliance needs in mind, since retrofitting "can we prove who accessed what" is much harder than building it in from the start.

## 18. AI Agent Architecture

- Distinguish **agents that build the platform** (autonomous development, e.g., Claude Code sessions like this one) from **agents that operate the platform at runtime** (DevOps/incident/support agents embedded in the AI Control Plane, §7) — different trust levels, different guardrails, likely different tooling.
- **Tool-use model**: runtime agents should be given a curated, scoped tool set (through the Control Plane) rather than raw system access — mirrors the RBAC principle in §17.
- **Approval/autonomy spectrum**: every autonomous capability should be designed with an explicit autonomy level (propose-only → propose-with-approval → auto-execute-with-audit → fully autonomous), and start at the least autonomous level that's still useful, moving up only with demonstrated reliability.
- **Model/provider abstraction**: whether the platform hard-codes a single LLM provider or builds a provider-agnostic interface is an open decision — an abstraction layer costs some complexity now but avoids lock-in; given this is Anthropic tooling building the platform, using Claude/the Claude Agent SDK as the primary runtime is a reasonable default, with the abstraction question revisited if/when multi-provider need actually appears.

## 19. Autonomous Operations Strategy

- **Autonomous DevOps**: agent-proposed infra/deploy changes, gated behind human approval initially; audit-logged regardless of autonomy level.
- **Autonomous incident resolution**: agent triages using observability data (§15), proposes remediation, executes only pre-approved "safe" remediation classes (e.g., restart a service) autonomously, escalates anything else.
- **Autonomous customer support**: agent answers using product knowledge + tenant data (scoped via RBAC), escalates to human for anything outside a defined confidence/scope boundary.
- **Autonomous development**: this repository itself is a candidate testbed — using Claude Code (or similar) against the platform's own codebase, governed by normal code review, is a lower-risk starting point than autonomous *production* operations.

**Sequencing recommendation**: build autonomous development workflows first (lowest blast radius, fastest feedback loop), then customer support (bounded by RBAC and mostly read-heavy), then incident response and DevOps last (highest blast radius, needs the most mature guardrails and audit trail).

## 20. Dograh Integration Strategy

Dograh is a consumer of this platform, not part of it. Integration questions to resolve when Dograh onboarding begins (not now):

- Does Dograh's existing codebase (if one exists elsewhere) get migrated onto SaaS Core's identity/billing/tenancy, or does it start fresh against the platform?
- Which core capabilities does Dograh need first (informs which core modules get built/hardened first)?
- Where do Dograh-specific entitlement keys, notification templates, and audit event types live (per §8's extension-point pattern)?

This discovery task explicitly excludes designing that integration — flagged here only so it isn't forgotten once core work starts.

## 21. Recommended Technology Stack

**No technology has been chosen. The items below are directional starting points for human evaluation, not decisions.**

| Layer | Candidate(s) | Notes |
|---|---|---|
| Language/runtime | TypeScript (Node) or a typed backend language (Go, Python w/ types) | TypeScript enables sharing types between core/product and, if desired, frontend; Go offers stronger runtime guarantees for infra-heavy code |
| Primary DB | PostgreSQL | De facto default for relational + RLS support for tenancy |
| Cache/queue | Redis | Cache + simple job queue backing |
| Durable workflow (AI Control Plane) | Temporal (evaluate) | For multi-step autonomous operations needing durability/compensation |
| Auth | Buy (Clerk/WorkOS/Auth0) vs. build | See §10 tradeoffs |
| Billing | Stripe | Near-default for SaaS billing |
| Observability | OpenTelemetry + managed backend (Grafana Cloud/Honeycomb/Datadog) | Vendor-neutral instrumentation |
| Deployment | Containers on a managed platform (Fly.io/Render/Cloud Run/ECS) | Avoids premature Kubernetes |
| AI runtime | Claude Agent SDK / Claude API | Aligns with tooling already in use for platform development |

## 22. Repository Structure Proposal

Directional only — not to be created until approved.

```
/core/            # SaaS Core: tenancy, users, auth, RBAC, billing, usage, api-keys,
                   # webhooks, notifications, audit-log, feature-flags
/infra/            # Infrastructure: db access layer, job runner, observability,
                   # health checks, deploy config, migrations tooling
/control-plane/    # AI Control Plane: agent orchestration, tool registry,
                   # autonomous-devops, autonomous-incident, autonomous-support
/products/
  /dograh/         # Product-specific code (eventually — not built now)
/docs/             # Architecture docs (this file lives here)
```

Enforcement of the `core` → cannot import from `products/*` rule (and similar boundary rules) via lint/dependency-graph tooling is the mechanism that actually prevents monolith drift — the directory layout alone is not sufficient.

## 23. Major Risks

1. **Core absorbs product logic by convenience.** The first product (Dograh) will always tempt "just add this one Dograh-specific field to the core tenant table." Every such shortcut is how platforms become single-product monoliths wearing a platform costume. Mitigate with the extension-point pattern (§8) and code-review discipline, enforced structurally where possible.
2. **Multi-tenancy isolation implemented ad hoc.** If tenant scoping isn't centrally enforced (§9), a data leak is a matter of when, not if.
3. **AI Control Plane granted excessive privilege for expedience.** "Just give the agent the DB credentials, it's faster" is the single most dangerous shortcut available given this platform's stated ambitions (§7, §17).
4. **Premature distributed-systems complexity.** Splitting into many services/repos before there's a second product or a scaling need adds coordination overhead with no present benefit.
5. **Premature abstraction for hypothetical products.** Building flexibility for imagined "Product B/C" use cases that never materialize, before Dograh (the only real product) has exercised the platform, risks generic-but-useless abstractions. Reusability should be extracted from Dograh's real needs, not designed in the abstract.
6. **No enforced module boundaries.** Without lint/dependency-graph enforcement, "core/infra/control-plane/product" is just a naming convention that erodes under deadline pressure.
7. **Autonomous operations outrunning audit/approval infrastructure.** Shipping autonomous DevOps/incident-response capability before the audit-log and approval-workflow foundation (§5, §18) is solid enough to trust.

## 24. Decisions Required From Human

(Consolidated in §25 below — see "HUMAN DECISIONS REQUIRED".)

## 25. Phased Implementation Roadmap

Proposed only — sequencing depends on decisions in §HUMAN DECISIONS REQUIRED.

- **Phase 0 — Decisions** (this phase): resolve the open questions below. No code.
- **Phase 1 — Foundations**: repo scaffolding with enforced module boundaries; tenancy + user + auth data model; migration tooling; CI skeleton (lint/test/build); observability instrumentation conventions.
- **Phase 2 — Core capabilities, minimal**: RBAC, API keys, audit log, feature flags — the capabilities every product needs on day one, built narrow (not maximally general) against Dograh's actual first needs.
- **Phase 3 — Monetization**: billing/subscription integration, entitlements, usage metering pipeline.
- **Phase 4 — Operational maturity**: background job infra, notifications, webhooks, backups/rollback, health checks, deployment automation.
- **Phase 5 — AI Control Plane v0**: agent orchestration substrate + guardrails, starting with autonomous *development* workflows (lowest blast radius) per §19.
- **Phase 6 — AI Control Plane v1**: autonomous customer support (bounded, read-heavy), then incident resolution and DevOps, only after audit/approval infra is proven.
- **Phase 7 — Dograh onboarding**: Dograh built as the first true product-layer consumer, exercising and hardening the extension points designed in §8.

Each phase should end with an explicit re-check: "did anything built this phase leak into a lower layer or violate a boundary in §5–§8?"

---

## HUMAN DECISIONS REQUIRED

These decisions are foundational and expensive to reverse. They should be made explicitly by a human before any implementation begins.

1. **Multi-tenancy isolation model** (§9): row-level, schema-per-tenant, DB-per-tenant, or hybrid?
2. **Identity build-vs-buy** (§10): roll our own auth, or adopt a third-party identity provider (and which one)?
3. **User↔org cardinality** (§10): confirm users can belong to multiple orgs (recommended), or constrain to one org per user?
4. **Primary language/runtime and monorepo structure** (§21/§22): confirm TypeScript-first (or alternative), and confirm monorepo with enforced module boundaries.
5. **API style and versioning** (§12): REST vs. GraphQL vs. RPC, and versioning scheme, before any external/Dograh consumer exists.
6. **Background job vs. durable workflow engine** (§13): plain job queue only, or introduce a durable workflow engine (e.g., Temporal) specifically for AI Control Plane workflows?
7. **Billing provider** (§14): confirm Stripe (or alternative) as payment processor.
8. **Observability backend** (§15): confirm OpenTelemetry + which managed backend, or self-hosted.
9. **Deployment target** (§16): confirm modular-monolith-first approach and target infra platform.
10. **AI agent autonomy defaults** (§18/§19): confirm the proposed "propose-only → approval → audit-execute → autonomous" sequencing and where each autonomous capability starts on that spectrum.
11. **Model/provider abstraction** (§18): commit to Claude/Claude Agent SDK as the sole AI runtime, or build a provider-agnostic abstraction from the start?
12. **Compliance target** (§17): is there a near-term compliance requirement (SOC2, HIPAA, GDPR) that should shape audit-log/data-deletion design now rather than later?
13. **Boundary enforcement mechanism** (§6/§22): how will "core cannot import from product" actually be enforced — lint rule, dependency-graph CI check, separate packages/repos — and who owns that enforcement?

No implementation should begin until these are answered.
