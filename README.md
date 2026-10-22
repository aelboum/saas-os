# SaaS OS

A reusable, multi-tenant SaaS platform foundation. Dograh (and future
products) are built **on top of** this platform, not as part of it — real
business products live in their own separate repositories and consume
`saas-os` as an external package dependency (`docs/ADR/0015-...`, Accepted).
`products/` is this repository's Product-layer boundary, not a place a real
product is implemented here.

The platform foundation is substantially implemented per
`docs/IMPLEMENTATION-ROADMAP.md`: tenancy and tenant lifecycle, identity/OIDC
authentication and sessions, RBAC and scoped/delegated authorization, API
keys, feature flags, webhooks, notifications, billing/usage/entitlements (a
provider-abstracted interface with a Stripe adapter), audit logging, and the
API/worker/observability infrastructure a consuming product runs on. The AI
Control Plane is also implemented: tool orchestration, human approval gates,
a GitHub development-tool provider, the data-authorization policy gate, and
the self-learning subsystem (evaluation, adaptive/system learning,
experimentation, policy gate, autonomous improvement, continuous improvement
loop — recovered as Phase 9.1–9.9 in the roadmap from source, though that
phase's original acceptance criteria could not be recovered and remain
unverified against any independent specification).

This is a foundation, not a finished or production-hardened product — it
does not claim every possible SaaS capability, and known accepted gaps and
technical debt are tracked in `docs/IMPLEMENTATION-ROADMAP.md` and
`docs/DEPLOYMENT-ARCHITECTURE.md`, not hidden. **See
`docs/IMPLEMENTATION-ROADMAP.md` for exact per-phase status** and **read
`docs/ARCHITECTURE.md` first** for the architecture itself. The rest of
`docs/` covers security, multi-tenancy, data, API, deployment, observability,
and the AI Control Plane in detail. Every accepted architectural decision is
recorded in `docs/ADR/`.

## Layout

```
saas_os/         The one shipped package and import root (docs/ADR/0038-...):
  core/            SaaS Core        -- tenancy, identity, rbac, authority, api_keys, feature_flags,
                                       webhooks, notifications, email, billing, usage, audit_log,
                                       outbox, idempotency, crypto, config
  infra/           Infrastructure   -- db (the single database chokepoint, migrations, backup), jobs,
                                       secrets, observability, ratelimit, health, edge,
                                       local_identity, update
  api/             API ingress      -- the reusable ingress chain, `build_platform_app()`, health and
                                       auth routes, opt-in capability routers (`api/v1/`), the server
                                       and worker entrypoints (docs/ADR/0017-..., docs/ADR/0040-...)
  contracts/       Product Contract -- schema and validator
  control_plane/   AI Control Plane
products/        NOT shipped, NOT where a real product lives (docs/ADR/0015-...) -- kept only
                 as this repo's own internal layer-boundary test fixture; a real product lives
                 in its own separate repository and consumes `saas-os` as a package dependency
examples/        `reference-consumer/` -- ADR-0018 architecture-validation fixture (internal
                 CI harness only, never shipped, never a real product)
                 `consumer-scaffold/` -- ADR-0039 copy-once starting point for a new product
                 (never shipped; see docs/CONSUMER-GUIDE.md)
frontend/        TypeScript + Next.js frontend foundation
tests/           Tests (tests/architecture/ enforces the dependency rule below)
scripts/         Canonical developer validation commands (see below)
docs/            Architecture, ADRs, roadmaps (docs/IMPLEMENTATION-ROADMAP.md, docs/P-ROADMAP.md)
.github/         CI (GitHub Actions) -- runs the same scripts as local dev
```

**Building a product on SaaS OS**: start with `docs/CONSUMER-GUIDE.md` and
`examples/consumer-scaffold/`. The installed package owns exactly one
top-level import name, `saas_os` (`docs/ADR/0038-...`). The Stripe and
S3 SDKs are optional extras: `saas-os[stripe]`, `saas-os[s3-backup]`,
`saas-os[all]` (`docs/ADR/0041-...`).

**Dependency rule** (`docs/ARCHITECTURE.md` section 2, binding):

```
Products         -> SaaS Core -> Infrastructure
AI Control Plane -> SaaS Core -> Infrastructure
```

`saas_os/core/` and `saas_os/infra/` never import from `products/` or `saas_os/control_plane/`.
`saas_os/core/` never imports an AI/LLM/agent framework, even one that isn't
installed. `saas_os/core/`, `products/`, and `saas_os/control_plane/` never import
SQLAlchemy or psycopg directly -- only `saas_os/infra/db` may (docs/MULTI-TENANCY.md
section 3: it's the single database-access chokepoint). These rules, and
the others listed in `pyproject.toml`, are
enforced by import-linter contracts (`pyproject.toml`
`[tool.importlinter]`) and checked by
`tests/architecture/test_layer_boundaries.py` on every test run and in CI.
The frontend has no import-boundary tooling yet -- it's a single placeholder
page with no internal modules to bound; that gets added when a real module
structure exists, not before.

**Import root**: everything is imported from `saas_os` -- `saas_os.core`,
`saas_os.infra`, `saas_os.api`, `saas_os.contracts`, `saas_os.control_plane`.
The former top-level names (`core`, `infra`, `api`, `contracts`,
`control_plane`) no longer exist, and there is no compatibility alias
(`docs/ADR/0038-...`; enforced by `tests/architecture/test_namespace_contract.py`).

## Backend (Python)

Stack fixed by `docs/ADR/0011-backend-language-and-toolchain.md`: Python
3.13+, FastAPI, SQLAlchemy 2.x, Alembic, PostgreSQL, Redis, ARQ. Package
manager is plain `pip` + `setuptools` (no uv/Poetry) per that ADR.

```
python -m venv .venv
.venv/Scripts/activate        # Windows; use `source .venv/bin/activate` on macOS/Linux
pip install -e ".[dev]"

bash scripts/check-backend.sh   # ruff check, ruff format --check, pyright, pytest, lint-imports
```

The HTTP process is `python -m saas_os.api.server` and the job worker is
`python -m saas_os.api.worker` (see "Docker" below). The schema is created by
`saas-os-migrate upgrade`.

## Infra: database (`saas_os/infra/db`)

`saas_os/infra/db` is the platform's single database-access chokepoint
(docs/MULTI-TENANCY.md section 3) -- no other module opens its own
connection. Tenant-owned data is read and written through
`saas_os.infra.db.tenant_session_scope(tenant_id)`, which binds the session to one
tenant for PostgreSQL Row-Level Security (docs/MULTI-TENANCY.md);
`session_scope()` below is the untenanted form for platform-level tables.

```python
from saas_os.infra.db import session_scope
from sqlalchemy import text

with session_scope() as session:
    session.execute(text("SELECT 1"))
```

- **Configuration**: `DATABASE_URL` (the restricted application role) and
  `MIGRATIONS_DATABASE_URL` (the privileged migration role), resolved
  through `saas_os.infra.secrets`' `SecretsProvider` -- a `.env` file in
  development, the process environment otherwise.
- **Engine/session**: `saas_os.infra.db.get_engine()` / `saas_os.infra.db.session_scope()`,
  process-wide cached singletons; `build_engine()`/`build_session_factory()`
  accept explicit overrides for tests.
- **Migrations**: Alembic, initialized at `saas_os/infra/db/migrations/`
  (`alembic.ini` at the repo root, database URL read from
  `saas_os.infra.db.config`, never hardcoded). Tracked in `alembic_version_saas_os`
  (docs/ADR/0016-...) -- independent of a consuming project's own,
  separate migration history. A consuming project applies this history
  through the installed `saas-os` package, never by pointing its own
  Alembic at this directory's filesystem path directly: either the
  importable `saas_os.infra.db.migration_runner.run_core_migrations()`, or the
  `saas-os-migrate upgrade` console script.
- **Tests**: `tests/infra/test_db_*.py`. Config/engine/session tests need
  no real database (session tests use an in-memory SQLite engine to
  exercise commit/rollback control flow). `tests/infra/test_db_integration.py`
  needs real PostgreSQL, is marked `integration`, and is excluded from
  the default `pytest` run:

```
docker compose up -d db
DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \
    pytest -m integration
```

## Frontend (TypeScript / Next.js)

```
cd frontend
npm install
cd ..
bash scripts/check-frontend.sh  # typecheck, eslint, next build
```

A placeholder page plus an i18n foundation (`frontend/i18n/`) -- no
product, dashboard, auth, or billing UI. It is this repository's own
fixture for the single-origin runtime, not a package consumers install
(`docs/ADR/0042-...`, Proposed).

## Canonical validation commands

`scripts/check-backend.sh`, `scripts/check-frontend.sh`,
`scripts/check-security.sh`, `scripts/check-docker.sh`, and
`scripts/check-all.sh` are the single source of truth for what "passing"
means -- run them locally, and `.github/workflows/ci.yml` runs the exact
same scripts, so there is no separate local-vs-CI validation process to
keep in sync. Run individual tools directly (`ruff check .`, `pyright`,
`pytest -k ...`, `npm run lint`, ...) while iterating; run the scripts
before opening a PR.

`check-all.sh` runs `check-backend.sh` + `check-frontend.sh` +
`check-security.sh` -- fast, deterministic, no Docker daemon required.
`check-docker.sh` is deliberately separate (image builds take tens of
seconds and need Docker running) -- run it explicitly, or let CI's
`docker` job run it.

## Continuous Integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull
request, seven jobs in parallel:

- **backend** -- Python 3.13 venv with `pip install -e ".[dev,security]"`
  (the architecture tests exercise `detect-secrets` directly),
  `scripts/check-backend.sh`. Runs with no `.env`: the default test suite
  is hermetic (repository-root `conftest.py`, proven by
  `tests/architecture/test_ci_hermeticity.py`).
- **frontend** -- Node 22, `scripts/check-frontend.sh`
- **security** -- Python venv + Node, `scripts/check-security.sh` (dependency vulnerability scan + secret scan)
- **docker** -- `scripts/check-docker.sh` (image builds + runtime smoke test + compose config validation)
- **packaging** -- `scripts/check-packaging.sh` (a real wheel, its contents,
  and an isolated non-editable install)
- **migrations** -- a disposable `postgres:16-alpine` service container,
  `bash saas_os/infra/db/init/01-create-app-role.sh` (the real role-creation
  script, over TCP via libpq's `PGHOST`/`PGPASSWORD`), then
  `scripts/check-migrations.sh`
- **security-integration** -- disposable PostgreSQL and Redis service
  containers, then `scripts/check-integration.sh` (`pytest -m integration`,
  failing on any skipped test)

It requires no secrets and touches no production infrastructure: no
external secret store, no deployment step, and -- apart from the
`migrations` and `security-integration` jobs' throwaway, CI-only
PostgreSQL and Redis containers -- no service
container. The architecture boundary rule is enforced the same way a local
`pytest`/`lint-imports` run does -- a forbidden import fails CI, not just a
local check someone might skip.

## Docker

Development-oriented only (`docs/ADR/0010-deployment-target.md`: Docker +
Docker Compose + VPS; no Kubernetes, no Vault, no external secrets manager
at this stage). Both images build as non-root (`app`/`node` users) and
their `.dockerignore` files keep `.env`/`.venv`/`.git`/host `node_modules`
out of the build context -- verified empirically, see
`docs/IMPLEMENTATION-ROADMAP.md` Phase 1.4.

```
cp .env.example .env          # fill in local-only values; .env is gitignored
docker compose up --build

bash scripts/check-docker.sh        # build + runtime validation, no host ports used
bash scripts/check-single-origin.sh # the single-origin runtime, end to end
```

### Single origin (ADR-0024)

`docker compose up` serves the whole application -- this repository's
backend and frontend -- on **one** browser origin, `PUBLIC_APP_ORIGIN`
(`http://localhost:8080` by default), through the `edge` service:
`/auth/*`, `/v1/*`, `/healthz` and `/readyz` reach `backend`, everything
else reaches `frontend`. The OIDC callback is derived from that origin, so
`OIDC_REDIRECT_URI` is normally not set at all.

`backend` (:8000) and `frontend` (:3000) stay published as a developer-only
escape hatch for direct, un-proxied access; neither is needed by the
single-origin flow and neither exists in `docker-compose.prod.yml`. A
downstream product gets the same runtime from its installed `saas-os`
dependency with `saas-os-edge-config` -- see
`docs/SINGLE-ORIGIN-RUNTIME.md`.

### Background worker (P2.1)

`docker compose up` runs two application processes from the same image:
`backend` (`python -m saas_os.api.server`, the HTTP API) and `worker`
(`python -m saas_os.api.worker`, the ARQ job worker). The worker is what actually
executes everything `saas_os.infra.jobs.enqueue_job()` puts on Redis -- webhook
delivery (`saas_os.core.webhooks`), usage-event ingestion (`saas_os.core.usage`), and
notification/email dispatch (`saas_os.core.notifications`). Without a running
worker those jobs are enqueued and never run.

- **Command**: `python -m saas_os.api.worker` (long-running, foreground).
  `python -m saas_os.api.worker --check` is the container health probe: exit 0
  only if the running worker's arq health sentinel is present in Redis
  (the worker refreshes it every 15s while its poll loop is alive), 1
  otherwise. No HTTP server is started for the worker.
- **Configuration**: the same variables as `backend` -- `REDIS_URL` and
  `DATABASE_URL` through `saas_os.infra.secrets` (never read from the environment
  directly by the worker), plus the optional non-secret retry tunables
  `JOBS_MAX_TRIES` (default 3) and `JOBS_RETRY_BACKOFF_BASE_SECONDS`
  (default 1.0). The worker runs as the same restricted `saas_os_app`
  database role as the API and refuses to start (exit 1) under a
  superuser/BYPASSRLS role, exactly like `saas_os.api.server` (P1.2 guard).
- **Startup / shutdown**: missing or invalid `REDIS_URL`/`DATABASE_URL`,
  an unreachable Redis (after arq's own bounded connection retries), or
  an unsafe database role all exit non-zero -- there is no fallback to a
  local Redis, a development credential, or an in-memory queue. `SIGTERM`
  /`SIGINT` cancel in-flight jobs (arq re-runs a cancelled job on its next
  pickup -- at-least-once), close the Redis pool, and exit 0. The Compose
  service uses `restart: unless-stopped` so a crashed worker is
  re-supervised.
- **Job execution**: each job runs the handler its Core module registered
  via `saas_os.infra.jobs.register_tenant_job` (handler receives a
  `TenantJobContext` with a validated `uuid.UUID` tenant id) or
  `saas_os.infra.jobs.register_system_job` (no tenant, no payload). A payload that
  does not match the job's declared kind is a permanent contract
  violation: dead-lettered at once, never retried, the handler never runs
  (docs/ADR/0030-foundation-enforcement.md). Any other failure is retried
  with exponential backoff up to
  `JOBS_MAX_TRIES`, then dead-lettered (`arq:dead-letter` Redis list). The
  worker binds the existing `saas_os.infra.observability` correlation context
  per job (`tenant_id`, and the enqueuing request's `request_id` when
  one was captured), and logs `job_started`/`job_succeeded`/
  `job_retry_scheduled`/`job_dead_lettered` with identifiers only --
  never a payload, result, or exception message.
- **Worker failure**: a job that fails is retried, then dead-lettered;
  the worker process itself keeps running. A worker process that dies is
  restarted by Compose; a job it was executing at that moment is re-run
  by arq on the next pickup (duplicate execution is possible -- the
  existing job handlers already document this at-least-once contract).
- **Redis durability (known limitation)**: the queue and the dead-letter
  list are exactly as durable as the Redis instance. The `redis` Compose
  service has no persistence configured, so a Redis restart discards
  queued and dead-lettered jobs. P2.1 makes the job infrastructure
  execute; durable Redis persistence and disaster recovery are handled
  separately (production perimeter/DR remediation), not here.

`scripts/check-docker.sh` starts the worker alongside the backend, waits
for its health probe, proves a real job enqueued from the backend
container is executed by the worker, checks that no secret value reaches
the worker's logs or the image history, and verifies a clean `SIGTERM`
exit (0).

### Development email: Mailpit (ADR-0057)

`docker compose up` also starts `mailpit`, a development-only mail catcher.
With `EMAIL_PROVIDER=mailpit` (the `.env.example` default), notification
email from the worker goes to `mailpit:1025` inside the Compose network and
can be read at **http://127.0.0.1:8025**. The SMTP port is not published to
the host and the web UI is bound to loopback only; Mailpit accepts any
message, delivers nothing onward, and keeps at most 500 messages in memory.
It never receives the SMTP credentials. `EMAIL_PROVIDER=mailpit` is refused
unless `ENVIRONMENT` is `development` or `test`, and `docker-compose.prod.yml`
has no Mailpit service. To send through a real relay instead, set
`EMAIL_PROVIDER=smtp` and the `SMTP_*` variables (`.env.example`).

### Production topology (P2.3)

`docker-compose.yml` above is development-only. Production uses a
separate, standalone `docker-compose.prod.yml` — see
`docs/DEPLOYMENT-ARCHITECTURE.md` §11 for the full topology, network,
TLS, and firewall documentation. Summary:

```
cp .env.example .env          # set PUBLIC_DOMAIN and the other production values
docker compose -f docker-compose.prod.yml up -d --build

bash scripts/check-docker-prod-tls.sh  # full production validation, with disposable TLS for
                                      # PostgreSQL and Redis (docs/ADR/0027-...)
```

`scripts/check-docker-prod.sh` is the older perimeter test of the reference
topology. It runs `docker-compose.prod.yml` against the stock, TLS-less
`db`/`redis` services, and production mode refuses a plaintext database
connection (`docs/ADR/0021-...`), so it stops at its migration step by
design -- a recorded limitation (`docs/ADR/0027-...`, Context), not a
regression. Use the TLS script above to validate a production configuration.

Only the `proxy` service (Caddy, `Caddyfile`) publishes host ports (`80`,
`443`) — PostgreSQL, Redis, the backend, and the frontend publish none;
they are reachable only over the internal Docker networks. The host
firewall must still block `5432`/`6379`/`8000`/`3000` externally and
allow only `22` (restricted), `80`, and `443` — this repository has no
mechanism to configure a host firewall and does not attempt to.

First-tenant provisioning is an operator command, not an HTTP route:
`python -m saas_os.api.tenant_bootstrap` (run inside the `backend` container) —
see `docs/RUNBOOKS.md`, "First-tenant bootstrap".

## Security scanning

Per `docs/IMPLEMENTATION-ROADMAP.md` Phase 1.4:

- **Dependency vulnerabilities**: `pip-audit` (backend, scans the resolved
  Python environment against the OSV database) and `npm audit` at high and
  critical severity (frontend, scans `frontend/package-lock.json`) through
  `scripts/npm_audit_gate.py`, which accepts only the expiring,
  single-advisory exceptions in `scripts/security-exceptions.json`
  (currently one: `docs/SECURITY-EXCEPTION-braces.md`, until 2027-01-11) and
  prints each as not fixed. Run both, and the secret scan, with
  `bash scripts/check-security.sh` (needs `pip install -e ".[security]"`
  first); every check runs even if another fails. CI runs the same command.
- **Secret scanning**: `detect-secrets`, scanning tracked files only
  (`git ls-files`) against `.secrets.baseline`. A known false positive
  (`.env.example`'s placeholder connection string matching a "Basic Auth
  Credentials" pattern) is recorded in the baseline as audited
  (`is_secret: false`) -- it is not a real secret and never was. Any
  *new*, unaudited finding fails the check. To handle a future false
  positive: either add an inline `# pragma: allowlist secret` comment, or
  regenerate and re-audit the baseline with `detect-secrets scan
  $(git ls-files) --baseline .secrets.baseline` followed by
  `detect-secrets audit .secrets.baseline`. If a real credential is ever
  accidentally committed: rotate/revoke it at the provider immediately
  (a git history rewrite does not undo exposure), then remove it from
  history and add a baseline/pragma entry only for the placeholder that
  replaces it.

Failure in either scan is never suppressed to force a green build --
a genuine finding is fixed (upgrade) or explicitly documented, not hidden.

## Secrets

Per `docs/ADR/0012-secrets-management.md`: local development uses `.env`
(gitignored, never committed); `.env.example` documents every variable with
placeholder values only. No secret is ever baked into a Docker image or
committed configuration file. CI requires no secret of any kind. Every
one is read through the `SecretsProvider` interface (`saas_os/infra/secrets`); a future
secrets-manager implementation is added behind that interface.
