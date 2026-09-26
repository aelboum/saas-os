# ADR-0021: PostgreSQL/Redis transport encryption enforcement

Status: Accepted
Date: 2026-09-18
Supersedes / Superseded by: —

## Context

BANK-SEC-01 (the Open Banking security readiness audit) identified finding S-05 (MED): future PSD2/Open Banking integration raises the value of a compromise of the PostgreSQL/Redis transport, and this codebase's own database/cache connection configuration (`infra/db/config.py`, `infra/jobs/config.py`, `infra/ratelimit/config.py`) had no enforcement layer of any kind — a production deployment could silently connect to either backend in plaintext, purely by omission, with no error and no warning. This ADR is BANK-SEC-05: the remediation for S-05 only.

Verifying the actual connection behavior rather than assuming it from the URL scheme alone (this phase's own directive):

- **PostgreSQL**: `psycopg`'s own default `sslmode` is `prefer` — it attempts TLS but silently falls back to plaintext if the server does not offer it. A `DATABASE_URL`/`MIGRATIONS_DATABASE_URL` with no `sslmode` parameter at all inherits this weak default with zero indication in application logs.
- **Redis**: confirmed by reading `arq.connections.RedisSettings.from_dsn()`'s actual source — it sets `ssl=(scheme == "rediss")` directly from the URL scheme; `redis.Redis.from_url()` (redis-py, used by `infra/ratelimit/limiter.py`) documents identical scheme-based behavior. There is no query-parameter equivalent to PostgreSQL's `sslmode` — the scheme itself is the only switch.
- **The shipped reference deployment** (`docker-compose.prod.yml`) uses stock `postgres:16-alpine`/`redis:7-alpine` images with no TLS certificate configured for either service; its actual, already-accepted security model for these two services is Docker network isolation (`internal` network, no published port — P2.3/BANK-SEC prior work) rather than transport encryption.

This ADR's scope: establish a fail-closed application-side boundary — production must not silently connect in plaintext — without inventing a certificate-management project the current architecture cannot actually back up.

## Options Considered

### Option A — `require_tls` defaults to `ENVIRONMENT == "production"`, independently in each of the three connection-owning config modules; PostgreSQL auto-injects `sslmode=require` when absent, Redis validates the scheme and fails closed

- Advantages: secure-by-default for any future or alternate production deployment (a managed cloud Postgres/Redis, a future topology with real TLS termination) without any operator action; matches this codebase's established "each `infra/` submodule reads `ENVIRONMENT` independently, `infra` submodules never import each other" convention (`infra/secrets/config.py`'s own precedent, followed independently by `infra/db`, `infra/jobs`, `infra/ratelimit`); `DB_REQUIRE_TLS=false`/`REDIS_REQUIRE_TLS=false` remain available as an explicit, application-level override for a deployment that has its own justified reason to opt out (never silently downgrades an operator's own stronger `sslmode`, e.g. `verify-full`).
- Disadvantages: three independent implementations of near-identical logic (mitigated: this is the codebase's own accepted convention for exactly this class of concern, documented in each module's docstring, not an oversight); the one shipped `docker-compose.prod.yml` does not exercise the override, so its stock `postgres:16-alpine`/`redis:7-alpine` containers (TLS off by default) will fail to start against `backend`/`worker` until an operator supplies TLS-capable endpoints — an accepted consequence, not a defect (see Decision and Residual Limitation below).

### Option B — A single shared `infra/_shared/tls.py` helper imported by all three modules

- Advantages: one implementation instead of three.
- Disadvantages: violates the codebase's own established, repeatedly-applied convention that `infra` submodules do not import each other for their own environment-derived configuration (`infra/secrets/config.py`'s documented precedent; BANK-SEC-04/ADR-0020 applied the same "independently maintained, not shared" reasoning to its own near-identical Redis TLS logic split across `infra/jobs` and `infra/ratelimit`). Introducing a new shared-infra-internal module for this one concern, while every other cross-cutting `infra` concern (retry policy, timeouts, non-secret tunables) remains independently duplicated per module, is inconsistent without a demonstrated real cost from the duplication. Rejected.

### Option C — Provision real TLS certificates for `postgres:16-alpine`/`redis:7-alpine` in `docker-compose.prod.yml` so the shipped topology actually encrypts its transport, not merely requires it

- Advantages: transport encryption for the one deployment this repository actually ships, not just a documented boundary.
- Disadvantages: explicitly out of S-05's scope per this phase's own directive ("does not include... setting up certificate infrastructure... redesigning the production deployment topology"); a real certificate-management story (issuance, rotation, trust distribution to every container) is a substantially larger project than a transport-encryption *configuration boundary*. Rejected — documented as a residual limitation instead (see below).

## Recommendation

Option A.

## Decision

**Accepted.**

1. **`infra/db/config.py`** (`DatabaseConfig.require_tls`, defaults to `DB_REQUIRE_TLS` if set, else `ENVIRONMENT == "production"`): when TLS is required, `_apply_tls_requirement()` inspects `DATABASE_URL`/`MIGRATIONS_DATABASE_URL`'s `sslmode` query parameter —
   - absent → injects `sslmode=require` (psycopg's own strongest non-certificate-verifying mode; never silently relies on the driver's `prefer` default),
   - already `require`/`verify-ca`/`verify-full` → left unchanged (an operator's own stricter choice is never weakened),
   - explicitly `disable`/`allow`/`prefer` (a plaintext-permitting downgrade) or any unrecognized value → `DatabaseConfigurationError` at configuration time, before any connection is attempted. The error message never includes the raw URL or embedded credentials.
2. **`infra/jobs/config.py`** and **`infra/ratelimit/config.py`** (`JobsConfig.require_tls` / `RateLimitConfig.require_tls`, each independently defaulting to `REDIS_REQUIRE_TLS` if set, else `ENVIRONMENT == "production"`): when TLS is required, `_validate_redis_tls()` checks `REDIS_URL`'s scheme — `rediss://` passes, `redis://` (or anything else) raises the module's own `*ConfigurationError` at configuration time. Redis has no in-URL parameter to inject, so this validates rather than rewrites, per the verified `ssl=(scheme == "rediss")` behavior above.
3. **`docker-compose.prod.yml`**: `backend` and `worker` services set `ENVIRONMENT: production` and deliberately do **not** set `DB_REQUIRE_TLS`/`REDIS_REQUIRE_TLS` — this repository's one shipped production reference does not provide a plaintext opt-out. This repository's enterprise/financial-services target means the reference configuration must not itself weaken the fail-closed default; a commented note at the same location explains that this reference deployment's stock `postgres:16-alpine`/`redis:7-alpine` containers therefore require a TLS-capable `DATABASE_URL`/`REDIS_URL` (see Residual Limitation).
4. **`.env.example`**: documents both variables, their default, and points at this ADR.

Every real PostgreSQL/Redis connection-construction path in this codebase reaches one of these three config objects before connecting (see "Connection Paths Verified" below) — there is no direct `psycopg`/`redis`/`arq` connection construction elsewhere that bypasses this boundary.

## Connection Paths Verified

| Path | Config source | Verified via |
|---|---|---|
| `infra/db/engine.py::build_engine()` (app runtime) | `get_database_config().url` | reads the source directly; `DatabaseConfig.url` already carries the enforced `sslmode` by construction |
| `infra/db/migrations/env.py::_get_url()` (Alembic) | `get_migrations_database_config().url` | same mechanism, separate config object, same enforcement |
| `infra/jobs/queue.py::_redis_settings()` (ARQ worker/enqueue) | `RedisSettings.from_dsn(config.redis_url)` | `arq.connections.RedisSettings.from_dsn` source read via `inspect.getsource()`: `ssl=conf.scheme == "rediss"` |
| `infra/ratelimit/limiter.py` (rate limiter) | `redis.Redis.from_url(config.redis_url, ...)` | `redis.Redis.from_url` docstring/source: scheme-based SSL, read directly |
| `infra/health/readiness.py` (readiness probe) | reuses `get_database_config()` / `get_jobs_config()` via `get_redis_pool(config)` | no separate connection construction — automatically covered |

## Development/Test Behavior

`ENVIRONMENT` values other than `production` default `require_tls` to `False` — a plaintext `postgresql+psycopg://...`/`redis://...` URL with no `sslmode`/`rediss://` continues to work exactly as before, no certificates required for local development or the test suite. `DB_REQUIRE_TLS`/`REDIS_REQUIRE_TLS` can still force either direction explicitly in any environment.

## Important Distinction: Transport Encryption, Not Certificate Verification

This ADR guarantees the *transport* is encrypted (`sslmode=require` / TLS-negotiated Redis) when required. It does **not** guarantee, and does not claim to guarantee:

- **Server identity / certificate verification** — `sslmode=require` does not validate the server's certificate against a CA or check hostname; only `verify-ca`/`verify-full` (an operator's own explicit, stronger choice, left untouched by this ADR) do. Redis is **not** symmetric with PostgreSQL here, and an earlier revision of this ADR stated otherwise. For the Redis client this repository currently resolves (`redis-py` 5.3.1), `redis.connection.SSLConnection` builds its context with `ssl.create_default_context()` and applies `ssl_cert_reqs="required"`, `ssl_ca_certs=None`, `ssl_check_hostname=False` — so a `rediss://` connection **does** verify the server certificate against the client's default trust store; it is *hostname* checking, not certificate verification, that is off. This repository exposes no application-level `ssl_ca_certs`/`ssl_cert_reqs` configuration surface (`arq`'s `RedisSettings` has those fields; `infra/jobs/config.py` and `infra/ratelimit/config.py` deliberately validate only the scheme), so a privately-signed Redis certificate must be trusted through the client's own trust store rather than through SaaS-OS configuration. `pyproject.toml` declares `redis>=5.0`, a floor rather than an exact pin, so this default is a property of the currently resolved dependency and not a guarantee of the declaration — it is therefore regression-tested (`tests/infra/jobs/test_redis_tls_client_defaults_unit.py`) rather than assumed.
- **Certificate provisioning or rotation** — entirely out of scope; this ADR enforces a *configuration boundary*, not a PKI.
- **Protection against a compromised host inside the trusted network** — network isolation (the current reference deployment's actual control) and transport encryption address different threat models; this ADR does not change or weaken the former.

## Residual Limitation (documented, not fixed here)

The one shipped reference deployment (`docker-compose.prod.yml`) does **not** provide a plaintext production opt-out — `backend`/`worker` set `ENVIRONMENT: production` and leave `DB_REQUIRE_TLS`/`REDIS_REQUIRE_TLS` at their fail-closed default (required). Its `db`/`redis` services, however, are still stock `postgres:16-alpine`/`redis:7-alpine` images with no TLS certificate configured — provisioning one, and wiring trust distribution into every container that connects, is a materially larger project than a configuration boundary and is explicitly out of S-05's scope (Option C above). The practical consequence: as shipped, `docker compose -f docker-compose.prod.yml up` will not produce a healthy `backend`/`worker` against these stock `db`/`redis` containers, because `DATABASE_URL`/`REDIS_URL` (from `.env`, unchanged) carry no TLS, and this repository now refuses that connection rather than silently allowing it. This is the intended architectural boundary for this remediation: *SaaS-OS requires TLS for production PostgreSQL and Redis; certificate provisioning and deployment of the required TLS material are operational infrastructure responsibilities.* A real deployment must point `DATABASE_URL`/`REDIS_URL` at a TLS-capable endpoint (a managed cloud database/cache, or an operator-provisioned certificate on these same containers) before going to production — this repository does not, and per its own current scope should not, do that provisioning itself. `scripts/check-docker-prod.sh`'s automated perimeter check builds and boots this exact compose file end-to-end and will now fail at the backend/worker health-check step against the stock, uncertificated `db`/`redis` images for the same reason; updating that script (or supplying it a TLS-capable database/cache) is a follow-up outside this ADR's scope, noted here for visibility rather than silently left inconsistent.

## Tests

`tests/infra/db/test_tls_requirement_unit.py` (default-by-environment for both `DATABASE_URL` and `MIGRATIONS_DATABASE_URL`; valid `require`/`verify-full` configurations left unchanged; weak/invalid `sslmode` fails closed; explicit `DB_REQUIRE_TLS` override in both directions; invalid override value fails closed; error messages never contain the raw URL/credentials). `tests/infra/jobs/test_jobs_config.py` and `tests/infra/ratelimit/test_ratelimit_unit.py` (equivalent coverage for their own independently-configured `REDIS_URL`: default-by-environment, plaintext fails closed in production, explicit `REDIS_REQUIRE_TLS` override in both directions, invalid override value fails closed). All assert on the resulting `*Config` object's fields (`require_tls`, `url`/`redis_url`) rather than merely re-checking the environment variables that produced them.

## What Would Be Difficult to Change Later

If a future module constructs a PostgreSQL or Redis connection outside `get_database_config()`/`get_migrations_database_config()`/`get_jobs_config()`/`get_ratelimit_config()`, it bypasses this boundary entirely — the same "any path outside the sanctioned chokepoint is invisible to the abstraction" limitation already identified for `infra/secrets` (ADR-0012) and the logging redaction boundary (ADR-0020).

## Related

`docs/SECURITY.md`, `docs/DEPLOYMENT-ARCHITECTURE.md` section 11 (Production Network Perimeter, P2.3 — the pre-existing network-isolation control this ADR's TLS requirement is additive to, not a substitute for); `docs/ADR/0012-secrets-management.md` (chokepoint-bypass risk pattern, `SecretsProvider` — `DATABASE_URL`/`REDIS_URL` are always read through it, never `os.environ` directly); `docs/ADR/0020-logging-audit-redaction-boundary.md` (the prior BANK-SEC ADR this one's structure and "independently maintained, not shared, per-`infra`-submodule" reasoning follows); the BANK-SEC-01 audit (finding S-05) and BANK-SEC-05 (this remediation)'s own directive.
