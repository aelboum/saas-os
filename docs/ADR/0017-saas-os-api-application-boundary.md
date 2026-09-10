# ADR-0017: SaaS OS API / application boundary

Status: Accepted
Date: 2026-09-10
Supersedes / Superseded by: —

## Context

ADR-0015 establishes that a consuming SaaS project owns its own deployment and its own application entirely. `api/__init__.py`'s own module docstring already states the intended internal split, written before this ADR and before the distribution question was settled: `api/dependencies.py` owns "the enforced ingress chain (authentication → tenant resolution → rate limiting → RBAC authorization), reusing `core.identity`/`core.rbac`/`infra.ratelimit` entirely"; `api/context.py` owns the verified `RequestContext`; `api/errors.py` owns "stable, non-leaking HTTP error responses"; `api/main.py` is described as "the FastAPI application composition root"; `api/server.py` is "the production ASGI entrypoint... for `api.main.app`" — in its own words, "the one real ASGI application this repository runs" (`api/main.py` docstring).

That existing split already distinguishes two different kinds of thing inside `api/`, but it was written for a world where this repository is the only application that will ever run. `docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` §9 investigated what changes once independent consuming projects exist: a consuming project needs its own application entrypoint (its own routes, its own composition, its own deployment), and must not be forced to import a complete SaaS OS server as if it were the consumer's own application. This ADR records the architectural principle that follows from combining these two facts. It does not restructure `api/`, because the current implementation (three route groups: health, OIDC auth, tenant-status; no product route exists) does not yet give enough evidence to fix an exact, final file-level package boundary — see "What Is Deliberately Not Decided Here."

## Options Considered

### Option A — A consuming project imports and runs `api.main:app` directly as its own application, adding its own routes to the same FastAPI instance
- Advantages: no new packaging split required; matches how this repository runs today
- Disadvantages: forces every consuming project onto one specific application-composition choice made by SaaS OS (route ordering, middleware stack shape, lifespan behavior) rather than letting the project own its own composition; directly contradicts the principle this ADR exists to record

### Option B — SaaS OS exposes reusable ingress/middleware components as library code; each consuming project builds and owns its own FastAPI (or other framework) application object, mounting SaaS OS's reusable pieces into it
- Advantages: matches the "own deployment, own application entrypoint" requirement in ADR-0015 directly; consistent with `api/__init__.py`'s own existing internal split (ingress-chain components already described as reusable, composition root already described as this repository's own application); a project remains free to choose its own framework version, its own route layout, its own lifespan/startup behavior, importing only the ingress/auth/tenant-resolution/RBAC pieces it needs
- Disadvantages: the current `api/` package has never been built or tested as an importable library surface separate from being "the application this repository runs" — some restructuring will eventually be needed, and its exact shape is not yet proven

### Option C — SaaS OS exposes no HTTP-layer code at all; every consuming project reimplements its own authentication/tenant-resolution/RBAC ingress chain against `core.identity`/`core.rbac` directly
- Advantages: avoids any question of what belongs in a shared API library
- Disadvantages: `core.identity`/`core.rbac`'s enforcement value depends on being applied consistently and correctly at every ingress point; reimplementing that chain per project recreates exactly the "ad hoc, per-team discipline" failure mode this codebase's other boundary ADRs (0004, 0013, 0014) were each written to avoid one layer up; discards real, working, already-built code (`api/dependencies.py`) for no benefit

## Recommendation

Option B, recorded as a principle now; the precise package-level restructuring is left as open follow-up work rather than invented ahead of evidence.

## Decision

**Accepted.** The following principle is binding:

> A consuming SaaS project owns its own application entrypoint and its own application composition. SaaS OS may expose reusable API infrastructure/components (an authentication/tenant-resolution/RBAC-authorization ingress chain, standard error-response shaping, health/readiness endpoints), but a consumer must never be forced to import a complete SaaS OS application or server as if it were the consumer's own application.

Based on direct inspection of `api/`'s current contents and its own existing internal documentation, the following classification currently holds and is recorded as evidence supporting this principle, **not** as a restructuring performed by this ADR:

| Component | Current role | Classification under this principle |
|---|---|---|
| `api/dependencies.py` | Ingress chain (auth → tenant resolution → rate limit → RBAC), reusing `core.identity`/`core.rbac`/`infra.ratelimit` | Reusable library surface — a consuming project imports and mounts this |
| `api/context.py` | Verified `RequestContext` passed to route handlers | Reusable library surface |
| `api/errors.py` | Stable, non-leaking HTTP error responses | Reusable library surface |
| `api/middleware.py` | Correlation-ID / observability middleware | Reusable library surface |
| `api/health.py` | Liveness/readiness routes, outside the versioned `/v1` surface | Reusable library surface (generic, business-domain-agnostic) |
| `api/auth/*` | OIDC login routes | Reusable library surface (identity is a Core concern, ADR-0005) |
| `api/main.py` | "The FastAPI application composition root" (its own docstring) | Application-specific composition root — a consuming project builds its own, importing the reusable pieces above into it; a project must not import this module as its own app |
| `api/server.py` | "The production ASGI entrypoint... for `api.main.app`" (its own docstring) | Application-specific entrypoint — likewise not something a consuming project imports as its own |
| `api/v1/tenant_status.py` | The one existing external route | Not yet classified either way — no product route exists to generalize from; see open follow-up below |

This table records current evidence; it is not a commitment that `api/`'s physical file/package layout will be reorganized to match it. Whether that reorganization happens, and exactly how, is explicitly deferred (see "What Is Deliberately Not Decided Here").

## Rejected Alternatives

- **A consuming project runs `api.main:app` directly (Option A)**: rejected — forces one specific application-composition choice onto every consumer, contradicting ADR-0015's "own deployment" requirement.
- **No shared API library at all (Option C)**: rejected — discards already-built, already-correct ingress-chain code, and reintroduces the per-project ad hoc security discipline this codebase's boundary ADRs consistently avoid.

## What Would Be Difficult to Change Later

If a consuming project is built against `api.main:app` as its own application (Option A) before this principle is enforced, unwinding that coupling once the project has its own routes mixed into the same FastAPI instance is a real, non-trivial refactor for that project — not merely a documentation fix. Recording the principle now, before any real consuming project exists, avoids that outcome for the first (and every subsequent) consumer.

## What Is Deliberately Not Decided Here

Per the explicit instruction this ADR is based on, the following are recorded as open rather than invented:

- The exact physical restructuring of `api/` (whether it is split into two packages, whether `api/main.py`/`api/server.py` move to become an explicitly-labeled example/reference application rather than "the" application, or whether the split remains logical/documentation-only for now) is not performed or finalized by this ADR.
- Whether `api/v1/tenant_status.py` (the one existing external route) represents a reusable Core-capability route or a placeholder with no generalizable shape is not decided — no second route exists yet to compare it against.
- No file in `api/` is moved, renamed, or restructured by this ADR.

## Related

`docs/architecture/SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` §9 (repository boundary analysis, evidence base); `api/__init__.py` (the existing module-ownership docstring this ADR's classification table is drawn from); `docs/API-ARCHITECTURE.md` (existing API ownership rules this ADR extends across a repository boundary); ADR-0006 (API style and versioning); ADR-0015 (distribution and consumer boundary — the "own deployment" requirement this ADR's principle exists to satisfy); ADR-0018 (reference consumer validation fixture — the first real test of whether this classification actually holds up in practice, now implemented).

## Implementation Note (packaging implementation phase)

Resolves the minimal, bounded slice of "What Is Deliberately Not Decided Here" this phase needed; does not change the Decision or its classification table above, and performs no broader restructuring of `api/`.

- **`api/platform.py::build_platform_app(*, title, version)` added** — the minimal reusable builder Option B's Decision called for. It owns exactly the rows this ADR's own table already marked "Reusable library surface": `FastAPI` construction (`debug=False`, fixed), `lifespan` (logging/tracing configuration, the `validate_application_role()` fail-closed RLS/database-role guard — moved here unchanged from `api/main.py`), `CorrelationIdMiddleware`, and two of the reusable default routers (`api/health.py`, `api/auth`). `api/v1/tenant_status.py` is deliberately NOT mounted by the builder — this ADR's table leaves it unclassified, and that remains true; a consumer (or this repository's own `api/main.py`) mounts it explicitly if wanted.
- **This repository's own `api/main.py` is now the builder's first consumer** — `create_app()` calls `build_platform_app(title="saas-os external API", version="v1")` and mounts `tenant_status_router` on top, exactly the shape ADR-0017's worked example (`build_platform_app(title="Recharge", ...)`) describes. This directly demonstrates Option A ("run `api.main:app` directly") is no longer how even this repository's own server is built — it goes through the same reusable builder any consumer would.
- **`examples/reference-consumer/` (ADR-0018) is the second, independent consumer** of `build_platform_app()` — its own `reference_consumer/app.py` calls it and mounts its own route, proving the builder works for a project that is not this repository's own server.
- Still not decided: any physical split of `api/` into two packages, or moving `api/main.py`/`api/server.py` to an explicitly-labeled example — both remain open, exactly as this ADR originally left them.
