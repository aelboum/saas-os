# SaaS OS — Architecture Specification

Status: ACCEPTED — governance/boundary rules, and the seven foundational technology decisions (Phase 0.1, `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md`) summarized in §10. A small number of secondary technology choices remain open — see §10.

This document is the formal architecture for `saas-os`, following on from `docs/ARCHITECTURE-DISCOVERY.md` (approved). It defines binding rules for how the platform is structured. Where the discovery doc explored options, this document settles the structural/boundary questions; the foundational technology choices are now settled per the ADRs in `docs/ADR/` and summarized in §11.

This is a documentation and repository-architecture artifact only. No application functionality, SaaS Core, or AI agents exist yet.

## 1. The Four Layers

The platform is divided into exactly four layers. Every file, module, and package in this repository must belong to one of them.

1. **SaaS Core** — domain-agnostic business primitives reusable by any SaaS product: tenancy, users, auth, RBAC, billing, subscriptions, usage metering, API keys, webhooks, notifications, audit logs, feature flags.
2. **Infrastructure** — technical plumbing with no business semantics: database access primitives, job/queue runner, observability instrumentation, health checks, deployment tooling, migration tooling, backup/restore, secrets access.
3. **AI Control Plane** — the substrate that lets AI agents operate the platform and act within products: agent orchestration, tool registry, autonomous DevOps/incident/support/development capabilities, approval workflows.
4. **Product** — everything specific to one SaaS product (Dograh, eventually others): domain models, product UI, product business rules, product integrations.

## 2. The Dependency Rule

This is the single most important rule in this document. It is not a guideline — it is enforced structurally (see §8).

```
Product  ──depends on──>  SaaS Core  ──depends on──>  Infrastructure
Product  ──depends on──>  Infrastructure (directly, for cross-cutting concerns)
AI Control Plane  ──depends on──>  SaaS Core (abstractions)
AI Control Plane  ──depends on──>  Infrastructure
AI Control Plane  ──interacts with──>  Product   (ONLY through explicitly declared tools/interfaces)
```

Binding rules:

- **SaaS Core must never import from, reference, or encode knowledge of any Product module.** Core code that needs product-specific behavior must expose an extension point (interface, hook, plugin registry, or event) that Product code implements or subscribes to — never the reverse.
- **Product code depends on SaaS Core through its published abstractions (interfaces/SDK), never on Core's internals.** Product code does not reach into Core's database tables, internal services, or private modules.
- **Infrastructure has zero knowledge of business concepts.** It does not know what a "tenant" or a "subscription" is — it knows about connections, queues, spans, and files. Core and Product both depend on Infrastructure; Infrastructure depends on nothing above it.
- **AI Control Plane never gets ambient access to Core internals or Product internals.** All action the Control Plane takes against Core or Product happens through explicitly declared "tools" (see `docs/AI-CONTROL-PLANE.md`) that are themselves implemented using Core's public abstractions and Product's declared contract (see §9). This makes every AI action auditable, scopable, and revocable by construction.
- **Product modules must never depend on each other directly.** If Product A needs something from Product B, that capability either belongs in Core (if it's generic) or is exposed through an explicit, versioned interface.

A dependency in the wrong direction is treated as a defect, not a style preference. See §8 for enforcement.

## 3. Proposed Repository Structure

```
saas-os/
├── core/                      # SaaS Core — see docs/ARCHITECTURE-DISCOVERY.md §5
│   ├── tenancy/
│   ├── identity/              # users, auth, sessions
│   ├── rbac/
│   ├── billing/
│   ├── usage/
│   ├── api-keys/
│   ├── webhooks/
│   ├── notifications/
│   ├── audit-log/
│   └── feature-flags/
│
├── infra/                     # Infrastructure — see docs/ARCHITECTURE-DISCOVERY.md §6
│   ├── db/                    # connection mgmt, query primitives, RLS helpers
│   ├── jobs/                  # queue/worker runner
│   ├── observability/         # logging, metrics, tracing conventions (docs/OBSERVABILITY.md)
│   ├── health/
│   ├── migrations/            # migration tooling (not the migrations themselves — see docs/DATA-ARCHITECTURE.md)
│   ├── secrets/                # secrets access abstraction (docs/SECURITY.md)
│   └── deploy/                 # deployment tooling/config (docs/DEPLOYMENT-ARCHITECTURE.md)
│
├── control-plane/             # AI Control Plane — see docs/AI-CONTROL-PLANE.md
│   ├── orchestration/         # agent runtime, tool registry
│   ├── tools/                 # explicit tool definitions (each tool = one bounded capability)
│   ├── approvals/             # human approval gate workflows
│   ├── devops/
│   ├── incident/
│   ├── support/
│   └── development/
│
├── products/
│   └── dograh/                # NOT built yet — placeholder for future product
│
├── contracts/                 # SaaS Product Contract schema + validated product contracts (see §9)
│
├── frontend/                  # Next.js frontend(s) — platform admin console (if built) and/or product UI shells,
│                               # per docs/ADR/0011-backend-language-and-toolchain.md; a distinct toolchain
│                               # (TypeScript/npm-or-pnpm) from the Python backend above, same monorepo
│
├── docs/
│   ├── ARCHITECTURE-DISCOVERY.md
│   ├── ARCHITECTURE.md               (this file)
│   ├── SECURITY.md
│   ├── MULTI-TENANCY.md
│   ├── DATA-ARCHITECTURE.md
│   ├── API-ARCHITECTURE.md
│   ├── DEPLOYMENT-ARCHITECTURE.md
│   ├── OBSERVABILITY.md
│   ├── AI-CONTROL-PLANE.md
│   ├── IMPLEMENTATION-ROADMAP.md
│   └── ADR/
│
└── (repo-root config: CI, lint, dependency-boundary rules — introduced in Phase 1 of the roadmap)
```

None of the above directories exist yet except `docs/` and `docs/ADR/`. Creating them is Phase 1 work (see `docs/IMPLEMENTATION-ROADMAP.md`), not part of this documentation pass.

## 4. Module Ownership

Ownership means: this module is the single writer of its own data and the single source of truth for its own logic. Other modules read/act on it only through its published interface.

| Module | Layer | Owns |
|---|---|---|
| `core/tenancy` | Core | Tenant entity, tenant lifecycle, tenant settings |
| `core/identity` | Core | User entity, sessions, OIDC relying-party integration (ZITADEL), machine identity, org membership — not credential storage (delegated to ZITADEL, `docs/ADR/0005-...`) |
| `core/rbac` | Core | Roles, permissions, policy evaluation — all application authorization, independent of the IdP |
| `core/billing` | Core | Plans, subscriptions, invoices, payments, entitlements, behind a provider-abstraction interface (Stripe first adapter, `docs/ADR/0008-...`) |
| `core/usage` | Core | Usage event ingestion, aggregation, quota state |
| `core/api-keys` | Core | API key issuance, scoping, rotation, revocation |
| `core/webhooks` | Core | Outbound webhook subscriptions, delivery, retry |
| `core/notifications` | Core | Notification dispatch pipeline (templates are Product-supplied via the contract) |
| `core/audit-log` | Core | Append-only audit event store and query interface |
| `core/feature-flags` | Core | Flag definitions, targeting rules, evaluation |
| `infra/db` | Infra | Connection pooling, query primitives, tenant-scoping enforcement chokepoint |
| `infra/jobs` | Infra | Job/queue execution, retry/backoff, dead-letter handling |
| `infra/observability` | Infra | Logging/metrics/tracing conventions and SDK |
| `infra/health` | Infra | Liveness/readiness endpoints, dependency health aggregation |
| `infra/secrets` | Infra | `SecretsProvider` interface and its dev/production implementations (`docs/ADR/0012-...`) |
| `infra/deploy` | Infra | Deployment pipeline configuration |
| `control-plane/orchestration` | AI Control Plane | Agent invocation, tool registry, execution sandboxing |
| `control-plane/tools/*` | AI Control Plane | One bounded, explicitly scoped capability per tool |
| `control-plane/approvals` | AI Control Plane | Human approval workflow state |
| `products/<name>/*` | Product | Everything specific to that product |
| `contracts/*` | Cross-cutting (owned by Core governance) | The Product Contract schema (§9) and each product's declared contract instance |

Rule: **exactly one module owns each piece of state.** No two modules write the same table, cache key, or queue. Cross-module reads happen through the owning module's interface, never direct storage access — this is what makes §2's dependency rule enforceable in practice, not just in import graphs.

## 5. Database Ownership

Detailed in `docs/DATA-ARCHITECTURE.md`. Summary rule: each layer/module owns a distinct schema (or clearly namespaced table set). Core owns `core.*`. Infra owns operational tables it needs (job queue state, migration history) under `infra.*`, if not delegated entirely to managed services. Each Product owns `product_<name>.*`. Cross-schema foreign keys from Product into Core are permitted for referential integrity (e.g., `product_dograh.calls.tenant_id → core.tenants.id`) but Product code must never write to `core.*` tables directly — only through Core's API/interface.

## 6. API Ownership

Detailed in `docs/API-ARCHITECTURE.md`. Summary: Core exposes an internal API surface consumed by Product and the Control Plane. Each Product owns its own external-facing API routes for product-specific functionality, but all cross-cutting concerns (auth, tenant resolution, rate limiting) are enforced by Core/Infra middleware that every route passes through — a product cannot opt out of the platform's auth chokepoint.

## 7. Event, Background Job, and Configuration Ownership

- **Events**: the module that owns the underlying state owns the event schema for changes to that state (e.g., `core/billing` owns and emits `subscription.upgraded`). Consumers (Product, Control Plane) subscribe; they never emit events on behalf of another module's domain.
- **Background jobs**: each job is owned by the module whose state it mutates or whose action it performs. `infra/jobs` owns only the generic execution/retry mechanism, not any job's business logic. A Product's background workers are declared in that product's contract (§9) and owned by the product.
- **Configuration**: `infra/secrets` and `infra/deploy` own the mechanism for supplying configuration; each module (Core, Control Plane, or Product) owns the *schema* of the configuration/environment variables it requires, and must declare them explicitly (Product does so via the contract, §9) rather than reading ambient environment state implicitly.

## 8. Boundary Enforcement Mechanism

The dependency rule in §2 is enforced, not just documented, starting in Phase 1 of the roadmap:

- A dependency-graph lint rule runs in CI and fails the build on any disallowed import (Core → Product, Product → Product, Control Plane → Core/Product internals instead of tools). Per `docs/ADR/0011-backend-language-and-toolchain.md`, the backend (Python) uses an import-boundary tool such as `import-linter`; the frontend (TypeScript/Next.js), if it grows internal boundaries worth enforcing, uses the equivalent ESLint import-boundary rules. Same rule, enforced per toolchain in this polyglot monorepo. Frontend boundary enforcement is not yet needed — as of Phase 1.3 the frontend is a single placeholder page with no internal modules to bound — and will be introduced when a meaningful frontend module structure actually exists, not preemptively.
- Module boundaries are physical (separate top-level directories/packages per §3), not just conventional, so the rule has a clear graph to check.
- **Implementation (`pyproject.toml` `[tool.importlinter]`, since Phase 1.3)**: three contracts enforce §2's rules — Core forbidden from Products/Control Plane, Infrastructure forbidden from Products/Control Plane, and Core forbidden from a set of mainstream AI/LLM/agent framework packages (rule 5). The third contract uses import-linter's `include_external_packages` option, which lets it detect a forbidden third-party import (e.g. `import openai`) inside Core even when that package isn't installed — the same mechanism that enforces internal-package boundaries also enforces the AI-framework boundary, rather than a second, separately-maintained checker. `tests/architecture/test_layer_boundaries.py` wraps all three contracts as pytest assertions (run by `scripts/check-backend.sh` and CI) and includes positive tests proving the permitted direction (Products/Control Plane → Core) still resolves. Every one of the five forbidden edges has been individually, manually verified to fail with a clear violation message before being reverted — see `docs/IMPLEMENTATION-ROADMAP.md` Phase 1.3 for the record.
- Any exception must be recorded as an ADR explaining why, with an explicit expiry/follow-up — silent exceptions are not permitted.

## 9. The SaaS Product Contract (Specification Only — Not Implemented)

This section documents the future contract every SaaS product will declare so the AI Control Plane and platform tooling can understand and operate it. **No parser, validator, or runtime for this contract exists yet.** This is a specification for future implementation, tracked in the roadmap.

A product's contract is a declarative manifest (final serialization format — e.g., YAML/JSON/TS-typed config — is an open decision, not fixed here) stating:

| Field | Purpose |
|---|---|
| `productName` | Unique identifier for the product across the platform |
| `productVersion` | Semantic version of the product's contract/deployment |
| `requiredCoreModules` | Which Core modules (tenancy, billing, rbac, …) this product depends on, and any module-specific configuration |
| `requiredInfrastructureServices` | Which Infra services (db, jobs, observability, storage) and any capacity/tier requirements |
| `databaseMigrations` | Pointer to this product's migration set and the schema namespace it owns |
| `environmentVariables` | The full declared set of config/secrets this product needs, with types and required/optional status |
| `healthChecks` | Endpoints or checks the platform should poll to determine this product's health |
| `backgroundWorkers` | The jobs/workers this product registers, their triggers, and their owning module |
| `apiRoutes` | The external API surface this product exposes, for gateway registration and documentation generation |
| `frontendModules` | Which UI modules/entry points this product contributes, for host-app composition |
| `billingMetrics` | Which usage-metering events this product emits and how they map to Core billing entitlements |
| `featureFlags` | The flags this product defines, their default state, and targeting needs |
| `deploymentRequirements` | Resource/runtime requirements (compute, region, scaling) for this product's deployable units |
| `aiTools` | The explicit set of Control-Plane tools this product exposes for AI agents to act on it (see `docs/AI-CONTROL-PLANE.md` §"Tool Registry") — nothing beyond this declared set is reachable by an agent |
| `supportKnowledge` | Pointer to this product's knowledge base/documentation for the autonomous customer-support capability |

**Purpose**: once implemented, this contract is what lets the platform (and its AI Control Plane) treat "add a new SaaS product" as registering a contract rather than writing bespoke platform-integration code per product — and what lets an autonomous agent discover *what a product is and what it's allowed to do* without being given ambient access to its code.

**Explicitly out of scope for this document**: contract file format, parser/validator implementation, schema versioning mechanism. These are implementation decisions for the phase that builds this contract (see `docs/IMPLEMENTATION-ROADMAP.md`).

## 10. Technology Decisions (Accepted — Phase 0.1)

The following are settled, binding decisions as of Phase 0.1 (`docs/PHASE-0.1-ARCHITECTURE-REVIEW.md`). Full reasoning, rejected alternatives, and migration paths live in the linked ADRs; this table is a summary, not a substitute.

| Area | Decision | ADR |
|---|---|---|
| Multi-tenancy | PostgreSQL, shared schema, row-level tenancy (`tenant_id`/`organization_id`), centralized enforcement at `infra/db`, RLS as defense in depth | `docs/ADR/0002-...` |
| Identity | ZITADEL as external IdP via OIDC (authentication only); `core/identity` + `core/rbac` own all authorization/permissions | `docs/ADR/0005-...` |
| API | REST + OpenAPI; versioned from the first release (`/v1/...`) | `docs/ADR/0006-...` |
| Background jobs | Redis-backed `infra/jobs`; no distributed workflow engine yet; interfaces reserved for one later | `docs/ADR/0007-...` |
| Billing | Provider-abstraction interface in `core/billing`; Stripe as first adapter; Plans/Subscriptions/Entitlements/Usage/Invoices/Payments modeled as distinct concepts | `docs/ADR/0008-...` |
| Observability | OpenTelemetry as the instrumentation standard; backend vendor still open | `docs/ADR/0009-...` |
| Deployment | Docker + Docker Compose + VPS; Kubernetes/cloud deferred behind an `infra/deploy` target interface | `docs/ADR/0010-...` |
| Backend language/runtime | Python 3.13+, FastAPI, SQLAlchemy 2.x, Alembic, Redis + ARQ (implements ADR-0007), pytest, Ruff, Pyright (switched from mypy in Phase 1.1, see ADR-0011) | `docs/ADR/0011-...` |
| Frontend | TypeScript + Next.js (platform default; individual products may justify an alternative via their own ADR) | `docs/ADR/0011-...` |
| Secrets | Provider-agnostic `SecretsProvider` interface; dev = `.env` (gitignored, never committed); initial production = Docker/host runtime injection (Docker Compose `secrets:` or host-supplied env, never baked into images or committed); Vault/cloud secret managers/Docker Secrets deferred as future adapters, not installed now | `docs/ADR/0012-...` |

Still open (do not block Phase 1, tracked in `docs/PHASE-0.3-SECRETS-DECISION.md` and `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md`): observability backend vendor, compliance target, agent runtime/model-provider abstraction, Python/Node package manager choice.

## 11. Related Documents

- `docs/SECURITY.md` — authz boundaries, secrets, AI permission boundaries, approval gates
- `docs/MULTI-TENANCY.md` — tenant isolation model and enforcement
- `docs/DATA-ARCHITECTURE.md` — schema ownership, migrations, event ownership detail
- `docs/API-ARCHITECTURE.md` — API surfaces, versioning, ownership
- `docs/DEPLOYMENT-ARCHITECTURE.md` — deployment units, environments, rollback
- `docs/OBSERVABILITY.md` — logging/metrics/tracing conventions and ownership
- `docs/AI-CONTROL-PLANE.md` — tool registry, agent categories, approval workflow detail
- `docs/IMPLEMENTATION-ROADMAP.md` — phased build plan
- `docs/ADR/` — individual architecture decisions and their status
- `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` — Phase 0.1 decision record and consistency review
- `docs/PHASE-0.3-SECRETS-DECISION.md` — secrets management decision record and Phase 0 closure status
