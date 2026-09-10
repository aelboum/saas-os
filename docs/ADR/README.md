# Architecture Decision Records

This directory records individual architecture decisions for `saas-os`. Each ADR captures one decision: the context, the options considered, the choice (if made), and its status.

## Status values

- **Proposed** — options laid out, a direction may be recommended, but the decision has not been confirmed by a human. Do not build against a Proposed ADR's recommendation as if it were final.
- **Accepted** — confirmed and binding. Implementation may proceed against it.
- **Superseded** — replaced by a later ADR (linked).
- **Deprecated** — no longer applicable; kept for history.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-layered-architecture-and-dependency-rule.md) | Layered architecture and the core dependency rule | Accepted |
| [0002](0002-multi-tenancy-isolation-model.md) | Multi-tenancy isolation model | Accepted — PostgreSQL, shared-schema row-level (`tenant_id`/`organization_id`), centralized enforcement |
| [0003](0003-monorepo-with-enforced-module-boundaries.md) | Monorepo with enforced module boundaries | Accepted |
| [0004](0004-ai-control-plane-tool-mediated-access.md) | AI Control Plane: tool-mediated access only | Accepted |
| [0005](0005-identity-build-vs-buy.md) | Identity: build vs. buy | Accepted — ZITADEL via OIDC (authentication); Core owns authorization |
| [0006](0006-api-style-and-versioning.md) | API style and versioning | Accepted — REST + OpenAPI, versioned from the start |
| [0007](0007-background-job-and-workflow-engine.md) | Background job execution vs. durable workflow engine | Accepted — Redis + ARQ now; workflow engine deferred, interface reserved |
| [0008](0008-billing-provider.md) | Billing provider | Accepted — provider-abstraction interface, Stripe as first adapter |
| [0009](0009-observability-backend.md) | Observability standard and backend | Accepted (standard: OpenTelemetry) — backend vendor still open |
| [0010](0010-deployment-target.md) | Deployment target platform | Accepted — Docker + Docker Compose + VPS; K8s/cloud deferred behind an interface |
| [0011](0011-backend-language-and-toolchain.md) | Backend language/runtime and toolchain; frontend stack | Accepted — Python 3.13+/FastAPI/SQLAlchemy 2.x/Alembic/pytest/Ruff/Pyright (switched from mypy in Phase 1.1); TypeScript + Next.js frontend |
| [0012](0012-secrets-management.md) | Secrets management | Accepted — provider-agnostic `SecretsProvider`; dev = `.env`; initial prod = Docker/host runtime injection; Vault/cloud/Docker Secrets deferred |
| [0013](0013-ai-data-privacy-and-external-model-boundary.md) | AI data privacy and external-model boundary | Accepted — mandatory data-authorization boundary between tenant/user data and any external AI provider, complementary to ADR-0004's tool-authorization boundary; implementation deferred to Phase 7+ |
| [0014](0014-learning-authorization-and-continuous-improvement-boundary.md) | Learning authorization and the Self-Learning data boundary | Accepted — a third, independent gate (retention/reuse) alongside Tool Authorization (ADR-0004) and Data Authorization (ADR-0013); default-deny; implementation deferred to Phase 9+ |
| [0015](0015-saas-os-distribution-and-consumer-boundary.md) | SaaS OS distribution and independent-consumer boundary | Accepted — SaaS OS is a versioned package consumed by independent, separately-repo'd/deployed/databased SaaS projects; initial consumption via a pinned Git/VCS dependency, not a private index; `products/` is not the consumer model |
| [0016](0016-independent-database-migration-histories.md) | Independent database migration histories for SaaS OS and consuming projects | Accepted — two independent Alembic environments (SaaS-OS-owned `core.*`, project-owned `<project>.*`) applied to one shared physical database per project, in place of a single branched multi-root history |
| [0017](0017-saas-os-api-application-boundary.md) | SaaS OS API / application boundary | Accepted — a consuming project owns its own application entrypoint/composition; SaaS OS exposes reusable ingress/auth/tenant-resolution components only; exact `api/` restructuring left as open follow-up |
| [0018](0018-reference-consumer-validation-fixture.md) | Reference consumer as an architecture validation fixture | Accepted and implemented (`examples/reference-consumer/`) — a minimal, non-shipped internal consumer proving ADR-0015/0016/0017 end-to-end against a real installed package and a real disposable database |

New ADRs should use the next sequential number and follow `0000-template.md`.
