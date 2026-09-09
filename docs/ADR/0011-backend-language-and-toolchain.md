# ADR-0011: Backend language/runtime and toolchain; frontend stack

Status: Accepted
Date: 2026-09-06 (tooling note added during Phase 1.1: type checker switched to Pyright)
Supersedes / Superseded by: —

## Context

`docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` §2/§3.9/§6 identified the primary application language/runtime as the one decision blocking Phase 1.2 (toolchain baseline) and, by extension, Phase 1.3 (dependency-boundary lint tooling, which is language-dependent). No language had been formally ratified — `docs/ARCHITECTURE-DISCOVERY.md` §21 only listed candidates directionally. This ADR resolves that gap and, since the human decision arrived as a full stack rather than a language alone, records the complete backend and frontend toolchain in one place.

## Options Considered

Given as a settled human decision rather than a set of options to weigh — recorded here per the ADR process, with the reasoning that makes each choice coherent with prior ADRs rather than a full options/tradeoffs analysis (that analysis was implicitly done by the human decision-maker; this ADR's job is to make the choice binding and check it against the platform's existing constraints).

## Decision

**Accepted**, effective immediately — this is the toolchain Phase 1 scaffolding (`docs/IMPLEMENTATION-ROADMAP.md` Phase 1.2) is built against.

| Concern | Choice | Fit with prior decisions |
|---|---|---|
| Backend language/runtime | **Python 3.13+** | — |
| API framework | **FastAPI** | Native OpenAPI generation satisfies `docs/ADR/0006-api-style-and-versioning.md` (REST + OpenAPI as source of truth) with no separate spec-authoring step |
| Database | **PostgreSQL** | Already Accepted in `docs/ADR/0002-multi-tenancy-isolation-model.md` — no conflict |
| ORM / DB access | **SQLAlchemy 2.x** | Becomes the concrete implementation of the `infra/db` tenant-scoping chokepoint (`docs/MULTI-TENANCY.md` §3) — session-scoped `tenant_id` binding for RLS (`docs/ADR/0002-...`) is implemented via SQLAlchemy session/engine hooks |
| Migrations | **Alembic** | Implements the migration tooling described in `docs/DATA-ARCHITECTURE.md` §2 (`infra/migrations`) |
| Background jobs | **Redis + ARQ** | Refines `docs/ADR/0007-background-job-and-workflow-engine.md`: ARQ is the concrete asyncio-native Redis job library implementing `infra/jobs`. The narrow-interface constraint from ADR-0007 (no multi-step/compensating logic built on top of it) still applies — ARQ does not change that constraint, it only fixes the library |
| Identity | **ZITADEL / OIDC** | Already Accepted in `docs/ADR/0005-identity-build-vs-buy.md` — `core/identity` is implemented as an OIDC relying party in FastAPI (e.g., via an OIDC client library), not a proprietary ZITADEL SDK, preserving ADR-0005's provider-portability discipline |
| API contract | **OpenAPI** | Already Accepted in `docs/ADR/0006-...`; FastAPI generates this directly from route/type definitions rather than requiring hand-maintained spec files |
| Observability | **OpenTelemetry** | Already Accepted in `docs/ADR/0009-observability-backend.md`; implemented via the OTel Python SDK with FastAPI/SQLAlchemy/ARQ auto-instrumentation where available |
| Frontend | **TypeScript + Next.js** | New decision — see §"Frontend" below |
| Infrastructure | **Docker + Docker Compose** | Already Accepted in `docs/ADR/0010-deployment-target.md` — no conflict; both the Python backend and the Next.js frontend ship as Docker services in the Compose stack |
| Testing | **pytest** | Backend test runner for all unit/integration tests specified throughout `docs/IMPLEMENTATION-ROADMAP.md` |
| Lint/formatting | **Ruff** | Backend lint/format tooling |
| Type checking | **Pyright** (switched from the original mypy default during Phase 1.1 — see §"Type Checker" below) | See §"Type Checker" below |

### Frontend: TypeScript + Next.js

This is the platform's first frontend technology decision. It applies to any UI the platform itself ships (e.g., an admin console, if one is built) and is the expected default for Product frontend modules (`docs/ARCHITECTURE.md` §9, `frontendModules`), though **individual products are not compelled to use Next.js specifically** — the Product Contract's `frontendModules` field describes what a product contributes, not a mandated framework, and this ADR only fixes the platform's own default. Product teams may justify a different frontend stack via their own ADR if warranted; absent one, Next.js is the default.

### Type Checker: mypy vs. pyright

The instruction named both ("mypy of pyright"). **mypy was adopted as the default** at the time of this ADR, since it has the more mature integration story with SQLAlchemy 2.x's typing plugin and is the more common pairing with Ruff in the Python ecosystem this stack otherwise follows. This was recorded as a low-cost-to-reverse choice (both are dev-time-only tools with no runtime or data-model impact) — if pyright's editor-integration speed proves worth it in practice, switching is a tooling change, not an architecture change, and does not require a superseding ADR, just a note in this one.

**Tooling note (Phase 1.1, `docs/IMPLEMENTATION-ROADMAP.md`)**: the Phase 1.1 repository-foundation instructions specified Pyright directly. Per the reversibility judgment above, this is accepted as exercising that already-anticipated switch, not a new architectural decision: **Pyright is the type checker actually configured and run** (`pyproject.toml` `[tool.pyright]`), mypy is not installed. This paragraph is the "note in this one" the original decision called for — no superseding ADR was created.

### Package Management (Residual, Not Blocking)

Python package manager (e.g., `uv`, `poetry`, plain `pip` + `requirements.txt`) and the Node package manager for the Next.js frontend (`npm`, `pnpm`, `yarn`) are not specified by this decision and remain open, low-stakes implementation details for Phase 1.2 to settle directly (no ADR needed — this is exactly the class of decision `docs/ADR/README.md` scopes ADRs above).

## Rejected Alternatives

Not applicable in the usual sense — this ADR records a direct human decision rather than an options analysis performed by prior ADRs in this set. No alternative languages/frameworks were evaluated in documentation; if a future need arises to reconsider (e.g., a performance-critical service warranting a different runtime), that is a new ADR, not a revision of this one.

## Future Migration / Extension Path

- **Boundary enforcement tooling** (`docs/ARCHITECTURE.md` §8): the dependency-graph lint rule is implemented for Python using an import-boundary tool (e.g., `import-linter`, contracts-based) enforcing the Core/Infra/Control-Plane/Product layering from `docs/ARCHITECTURE.md` §2. The Next.js frontend, if it grows internal module boundaries worth enforcing, uses the TypeScript-ecosystem equivalent (e.g., ESLint import-boundary rules) — the same rule, two toolchains, since the repository is polyglot (Python backend, TypeScript frontend) under one monorepo (`docs/ADR/0003-...`).
- Should the platform later need a different runtime for a specific high-throughput or latency-critical component (unlikely at this stage, and explicitly not anticipated by `docs/ARCHITECTURE-DISCOVERY.md`'s non-goals), that component would be introduced as its own deployable behind the module-boundary discipline already established — the modular-monolith approach (`docs/ADR/0003-...`) does not require every future service to share this language, only that boundaries stay real.

## What Would Be Difficult to Change Later

A language change after Phase 2+ (Core modules implemented) would be a full rewrite, not a migration — this is the standard cost of any language decision and is why this ADR was treated as the blocking precondition for Phase 1 (`docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` §6). The ORM choice (SQLAlchemy 2.x) is similarly load-bearing once `core/tenancy`'s RLS-binding session logic (`docs/MULTI-TENANCY.md` §3) is implemented against it — swapping ORMs later means reimplementing the tenant-scoping chokepoint, the platform's primary security boundary.

## Related

`docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` §2, §3.9, §6; `docs/ARCHITECTURE.md` §8, §10; `docs/ADR/0002-...`, `0005-...`, `0006-...`, `0007-...`, `0009-...`, `0010-...`; `docs/IMPLEMENTATION-ROADMAP.md` Phase 1.2–1.3.
