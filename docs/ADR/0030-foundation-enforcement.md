# ADR-0030: Foundation enforcement — route policy, table isolation, RLS proof, typed jobs

Status: Accepted and implemented
Date: 2026-10-01
Supersedes / Superseded by: — (refines [ADR-0022](0022-tenant-session-boundary-enforcement.md) with a table-level classification and a schema-wide RLS proof; corrects the "enforced ingress middleware" claims in `docs/API-ARCHITECTURE.md`, `docs/ARCHITECTURE.md` and `docs/SECURITY.md`)

## Context

A read-only foundation audit (baseline `51a6022`) confirmed four gaps.

**1. Routes are not guarded by default.**
- Authentication, tenant resolution, rate limiting and RBAC are a per-route FastAPI dependency chain in `api/dependencies.py`.
- A route that forgets `Depends(require_permission(...))` is silently public. No middleware, no router-level dependency and no test prevents it.
- The roadmap's Phase 8.1 outcome already recorded this as "structural-by-convention (per-route opt-in)". The reference consumer once shipped exactly such a route.
- `docs/API-ARCHITECTURE.md`, `docs/ARCHITECTURE.md` and `docs/SECURITY.md` nevertheless described universal, opt-out-proof middleware.
- FastAPI's generated documentation (`/openapi.json`, `/docs`, `/redoc`) was reachable on the backend's port in every environment, by default rather than by decision.

**2. Tables carry no explicit isolation classification.**
- All 24 tenant-owned tables had correct RLS (ENABLE + FORCE, one canonical policy), and the 11 global tables and 1 system table had none.
- Nothing declared which table is which. The retention map classifies tables by retention, not isolation, and ADR-0022's inventory is prose.
- A new tenant table that forgot `tenant_rls_statements()` would only be caught if its author also wrote an isolation test.

**3. No schema-wide RLS proof.**
- Coverage rested on ~30 per-module isolation tests.
- `core.webhook_replay_records` had no RLS assertion at all.

**4. Background jobs are untyped.**
- Every handler had the same signature, `handler(payload: TenantJobPayload | None)`; nothing distinguished a tenant job from a system job.
- Handlers parsed raw `str` tenant ids themselves, and the worker never validated payloads.
- A malformed or missing tenant payload was retried with backoff before being dead-lettered, as if it were a transient failure.
- No job read its tenant from ambient state; that was already correct and stays so.

## Decision

**Accepted (2026-10-01).** All four gaps are closed by reusing existing mechanisms. No second authentication system, authorization engine, tenant-context system or RLS implementation is introduced.

### 1. Secure-by-default route policy (`api/route_policy.py`)

Every HTTP route declares exactly one policy:

| Policy | How a route declares it |
|---|---|
| permission | `Depends(require_permission(resource, action))`, directly or through a wrapper such as `require_entitlement_and_quota` |
| authenticated | `Depends(get_current_actor)` or `Depends(get_current_session)` |
| public | `Depends(public_route("why no credential is needed"))`, a new no-op marker |

How it works:
- The exact dependency objects that already enforce authentication and RBAC (and each `public_route()` closure) are recorded in a private identity registry in `api/route_policy.py`; their behaviour is unchanged. The registry is keyed by object identity, not by a function attribute, so a wrapper of an enforcing dependency (for example one built with `functools.wraps`) never inherits its policy. Only `api/route_policy.py` and `api/dependencies.py` may register a dependency; an architecture test pins that.
- `assert_route_policies(app, production=...)` reads each route's resolved dependency graph using FastAPI's own route resolution (`fastapi.routing.iter_route_contexts`), so included routers, prefixes and router-level dependencies are seen exactly as they are served. It never looks at path strings.

Resolution rules:
- A permission implies authentication, so authentication markers collapse into it.
- `public` combined with anything else is a conflict.
- Two different permissions on one route is a conflict.
- No marker means the policy is missing.
- A public marker must have a non-empty reason.
- Any route that isn't a FastAPI API route (a mount, a bare Starlette route) has no policy and fails.

**Fail closed.** `api/platform.py::_platform_lifespan` runs the check first, before logging, tracing or the database role guard. It therefore sees the final application, including every router a consumer mounted after `build_platform_app()` returned. An application with an undeclared route does not start. `tests/architecture/test_route_policy.py` runs the same check on `api.main` and on the reference consumer app, plus synthetic violations.

The current routes:
- `/healthz`, `/readyz`, `/auth/login` and `/auth/callback` are explicitly public, with reasons.
- `/auth/logout` and `/auth/me` are authenticated-only.
- `/v1/tenants/{tenant_id}/status` requires `tenant:read_status`.
- The reference consumer's `/widgets/...` requires `reference_consumer.widgets:read`. It stays outside the edge routing contract, as before.

**D1 — API documentation.** `build_platform_app()` disables `openapi_url`, `docs_url` and `redoc_url` when `ENVIRONMENT=production`; outside production they remain. The route check accepts the documentation routes only outside production, and only at exactly the configured URLs.

### 2. Table isolation classification (`core/tenancy/isolation.py`)

- **The registry:** `ISOLATION_CLASSIFICATION` classifies every table SaaS OS's migrations produce, plus `public.alembic_version_saas_os`, as `TENANT_OWNED`, `GLOBAL` or `SYSTEM`. Every GLOBAL and SYSTEM entry carries its reason.
- **D3 — location:** it sits next to, and separate from, the retention classification. Retention and isolation are different axes.
- **The static audit:** `audit_isolation_classification()` checks the registry against `schema_at_head()`, a database-free replay of every migration. It rejects:
  - missing tables;
  - stale entries;
  - duplicate entries;
  - GLOBAL/SYSTEM entries without a reason;
  - TENANT_OWNED entries with a reason or without a `tenant_id` column;
  - a `tenant_id`-carrying table that isn't TENANT_OWNED and has no reason. The reason *is* the declared exception; today only `core.api_keys`, `core.billing_provider_refs` and `core.tenant_ancestry` have one.
- **Consumer tables:** consumer-owned tables are never in this registry.

### 3. Schema-wide RLS proof (`tests/infra/db/test_rls_coverage_sweep_integration.py`)

Against a real database migrated to head, the sweep checks:
- **Coverage:** the live SaaS-OS table set equals the registry.
- **Tenant-owned tables:** every one has RLS enabled and forced, and exactly one policy, `<table>_tenant_isolation`, PERMISSIVE, `public`, `ALL`. Its expression must equal what PostgreSQL stores for `tenant_rls_statements()`' own `USING` clause.
- **Global and system tables:** none has RLS or a policy.
- **Privileged functions:** no `SECURITY DEFINER` function exists in a SaaS-OS schema.
- **Runtime role:** it passes `validate_application_role()` and is neither superuser nor `BYPASSRLS`.
- **Self-check:** a probe proves the catalog queries detect a table that is missing its policy.

This covers `core.webhook_replay_records`. A consuming project's own version table (`public.alembic_version`, ADR-0016) is consumer-owned and excluded.

### 4. Typed tenant/system jobs (`infra/jobs/context.py`, `infra/jobs/queue.py`)

- **Registration declares the kind.**
  - `register_tenant_job(handler)` — handler is `handler(TenantJobContext, TenantJobPayload)`.
  - `register_system_job(handler)` — handler is `handler(SystemJobContext)`.
  - The bare `register_job` is removed. Re-registering a name with a different kind is refused.
- **Contexts:** `TenantJobContext` carries `tenant_id: uuid.UUID` and `correlation_id`; `SystemJobContext` carries `correlation_id`. Both live in `infra/jobs`, which never imports Core.
- **D4 — system payloads:** system jobs keep the `None` payload, and the kind decides whether `None` is valid.
- **Worker-side validation:** before the handler runs, the wrapper checks the payload against the kind.
  - A tenant job needs a `TenantJobPayload` whose `tenant_id` is a UUID in canonical `str(uuid)` form (lower-case, hyphenated), so the raw string the dead-letter entry and tenant purge match on is always the canonical one.
  - A system job needs `None`.
  - A mismatch is a permanent `JobContractViolationError`. It is dead-lettered on the attempt it occurs, never retried, and the handler never executes.
  - Genuine handler failures keep the existing retry-then-dead-letter policy unchanged.
- **Enqueue-side validation:** `enqueue_job()` checks a job registered in the producing process against its declared kind before anything reaches Redis.
- **Compatibility:** arq function names are unchanged (the handlers' own names), so already-queued jobs keep resolving. All five jobs are migrated: session cleanup is a system job; usage, notifications, webhooks and the continuous-learning loop are tenant jobs.
- **D5 — lifecycle fences unchanged:**
  - The webhook job keeps `tenant_job_session()`.
  - Usage and notifications keep their manual two-phase fences.
  - Notifications deliberately keeps its send-before-lock order.
  - Tests pin all three.

## Consequences

- **Consumers:** any application built on `build_platform_app()` must declare a policy on every route, or it refuses to start. A consumer upgrading SaaS OS adds `public_route(reason)` to its intentionally public routes. Its permission and authenticated routes already comply through the existing dependencies.
- **Custom job handlers** must use the typed registration functions and signatures.
- **New tables:** a new SaaS-OS table must be classified in `core/tenancy/isolation.py`, or the static audit fails. A tenant-owned table without the canonical policy fails the RLS sweep.

## Explicitly not part of this decision

These remain later work:
- Typed Core mutation callers.
- Completeness of privileged auditing.
- Support-access redesign.
- `User.is_active` enforcement.
- Transactional outbox; retry and dead-letter redesign; atomic rate limiter; webhook retry changes.
- Purge lifecycle changes; billing cancellation on tenant deletion; tenant export.
- Billing provider webhooks and the event ledger; orphaned-provider reconciliation.
- Quota fail-closed rollout; entitlement policy changes.
- Catalog, checkout, trials, plans, seats.
- Marketstack.
- A consumer-side isolation registry.
- Permission fields on `contracts.ApiRouteDeclaration`.
- The standalone `tests/control_plane` path-shadowing issue.

## What Would Be Difficult to Change Later

- **The route-policy markers and startup check:** once consumers depend on fail-closed startup, relaxing it would silently re-open the original gap.
- **The three isolation classes:** the classes, and the rule that a tenant-keyed exception needs a reason, become the vocabulary every future table is reviewed against.
- **The typed job handler signatures:** these are a public `infra.jobs` contract for every job a consumer registers.

## Related

[ADR-0002](0002-multi-tenancy-isolation-model.md); [ADR-0007](0007-background-job-and-workflow-engine.md); [ADR-0016](0016-independent-database-migration-histories.md); [ADR-0017](0017-saas-os-api-application-boundary.md); [ADR-0022](0022-tenant-session-boundary-enforcement.md); [ADR-0024](0024-single-origin-application-runtime.md); `api/dependencies.py`; `api/route_policy.py`; `api/platform.py`; `core/tenancy/isolation.py`; `core/tenancy/retention.py`; `infra/db/rls.py`; `infra/jobs/`.
