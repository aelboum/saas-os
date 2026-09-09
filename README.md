# SaaS OS

A reusable, multi-tenant SaaS platform foundation. Dograh (and future
products) are built **on top of** this platform, not as part of it.

This repository is currently at **Phase 2.1 — infra/db foundation**
(`docs/IMPLEMENTATION-ROADMAP.md`). No business functionality exists yet:
no tenants, users, auth, billing, AI agents, or product code. What exists is
Core's configuration schema, the database connection/session chokepoint
(`infra/db`), and the structural skeleton the accepted architecture
(`docs/ARCHITECTURE.md` and `docs/ADR/`) requires before any business
module is built.

**Read `docs/ARCHITECTURE.md` first.** The rest of `docs/` covers security,
multi-tenancy, data, API, deployment, observability, the AI Control Plane,
and the full phased roadmap. Every accepted architectural decision is
recorded in `docs/ADR/`.

## Layout

```
core/            SaaS Core        -- configuration schema implemented (core/config); no other business module yet
infra/           Infrastructure   -- database connection/session chokepoint implemented (infra/db); nothing else yet
control-plane/   AI Control Plane -- imported as `control_plane` (see note below)
products/        Product-specific code (none yet)
frontend/        TypeScript + Next.js frontend foundation
tests/           Tests (tests/architecture/ enforces the dependency rule below)
scripts/         Canonical developer validation commands (see below)
docs/            Architecture, ADRs, roadmap
.github/         CI (GitHub Actions) -- runs the same scripts as local dev
```

**Dependency rule** (`docs/ARCHITECTURE.md` section 2, binding):

```
Products         -> SaaS Core -> Infrastructure
AI Control Plane -> SaaS Core -> Infrastructure
```

`core/` and `infra/` never import from `products/` or `control-plane/`.
`core/` never imports an AI/LLM/agent framework, even one that isn't
installed. `core/`, `products/`, and `control-plane/` never import
SQLAlchemy or psycopg directly -- only `infra/db` may (docs/MULTI-TENANCY.md
section 3: it's the single database-access chokepoint). All four rules are
enforced by import-linter contracts (`pyproject.toml`
`[tool.importlinter]`) and checked by
`tests/architecture/test_layer_boundaries.py` on every test run and in CI.
The frontend has no import-boundary tooling yet -- it's a single placeholder
page with no internal modules to bound; that gets added when a real module
structure exists, not before.

**Package naming note**: the AI Control Plane directory is `control-plane/`
(matching `docs/ARCHITECTURE.md`), which is not a valid Python identifier.
Its importable package lives at `control-plane/control_plane/` and is
imported as `control_plane` (see `pyproject.toml`'s `package-dir` mapping).

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

No application entrypoint, database schema, or worker exists yet -- those
are later phases.

## Infra: database (`infra/db`)

`infra/db` is the platform's single database-access chokepoint
(docs/MULTI-TENANCY.md section 3) -- no other module opens its own
connection. Tenant-scoping *enforcement* is Phase 3 work (once
`core/tenancy` exists); this phase only establishes the chokepoint's
shape.

```python
from infra.db import session_scope
from sqlalchemy import text

with session_scope() as session:
    session.execute(text("SELECT 1"))
```

- **Configuration**: `DATABASE_URL` from the environment (`.env` /
  `.env.example`), read directly (mirrors `core/config`'s interim
  pattern -- `infra/secrets`, the eventual owner of credential sourcing,
  is Phase 2.3 and doesn't exist yet).
- **Engine/session**: `infra.db.get_engine()` / `infra.db.session_scope()`,
  process-wide cached singletons; `build_engine()`/`build_session_factory()`
  accept explicit overrides for tests.
- **Migrations**: Alembic, initialized at `infra/db/migrations/`
  (`alembic.ini` at the repo root, database URL read from
  `infra.db.config`, never hardcoded). No table is defined anywhere yet,
  so there is nothing to migrate -- `versions/` is empty.
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

Minimal foundation page only -- no product, dashboard, auth, or billing UI.

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
request, five jobs in parallel:

- **backend** -- Python 3.13 venv with `pip install -e ".[dev,security]"`
  (the architecture tests exercise `detect-secrets` directly),
  `scripts/check-backend.sh`. Runs with no `.env`: the default test suite
  is hermetic (repository-root `conftest.py`, proven by
  `tests/architecture/test_ci_hermeticity.py`).
- **frontend** -- Node 22, `scripts/check-frontend.sh`
- **security** -- Python venv + Node, `scripts/check-security.sh` (dependency vulnerability scan + secret scan)
- **docker** -- `scripts/check-docker.sh` (image builds + runtime smoke test + compose config validation)
- **migrations** -- a disposable `postgres:16-alpine` service container,
  `bash infra/db/init/01-create-app-role.sh` (the real role-creation
  script, over TCP via libpq's `PGHOST`/`PGPASSWORD`), then
  `scripts/check-migrations.sh`

It requires no secrets and touches no production infrastructure: no
external secret store, no deployment step, and -- apart from the
`migrations` job's throwaway, CI-only PostgreSQL container -- no service
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

bash scripts/check-docker.sh  # build + runtime validation, no host ports used
```

### Background worker (P2.1)

`docker compose up` runs two application processes from the same image:
`backend` (`python -m api.server`, the HTTP API) and `worker`
(`python -m api.worker`, the ARQ job worker). The worker is what actually
executes everything `infra.jobs.enqueue_job()` puts on Redis -- webhook
delivery (`core.webhooks`), usage-event ingestion (`core.usage`), and
notification/email dispatch (`core.notifications`). Without a running
worker those jobs are enqueued and never run.

- **Command**: `python -m api.worker` (long-running, foreground).
  `python -m api.worker --check` is the container health probe: exit 0
  only if the running worker's arq health sentinel is present in Redis
  (the worker refreshes it every 15s while its poll loop is alive), 1
  otherwise. No HTTP server is started for the worker.
- **Configuration**: the same variables as `backend` -- `REDIS_URL` and
  `DATABASE_URL` through `infra.secrets` (never read from the environment
  directly by the worker), plus the optional non-secret retry tunables
  `JOBS_MAX_TRIES` (default 3) and `JOBS_RETRY_BACKOFF_BASE_SECONDS`
  (default 1.0). The worker runs as the same restricted `saas_os_app`
  database role as the API and refuses to start (exit 1) under a
  superuser/BYPASSRLS role, exactly like `api.server` (P1.2 guard).
- **Startup / shutdown**: missing or invalid `REDIS_URL`/`DATABASE_URL`,
  an unreachable Redis (after arq's own bounded connection retries), or
  an unsafe database role all exit non-zero -- there is no fallback to a
  local Redis, a development credential, or an in-memory queue. `SIGTERM`
  /`SIGINT` cancel in-flight jobs (arq re-runs a cancelled job on its next
  pickup -- at-least-once), close the Redis pool, and exit 0. The Compose
  service uses `restart: unless-stopped` so a crashed worker is
  re-supervised.
- **Job execution**: each job runs the handler its Core module registered
  via `infra.jobs.register_job` -- retry with exponential backoff up to
  `JOBS_MAX_TRIES`, then dead-letter (`arq:dead-letter` Redis list). The
  worker binds the existing `infra.observability` correlation context
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

### Production topology (P2.3)

`docker-compose.yml` above is development-only. Production uses a
separate, standalone `docker-compose.prod.yml` — see
`docs/DEPLOYMENT-ARCHITECTURE.md` §11 for the full topology, network,
TLS, and firewall documentation. Summary:

```
cp .env.example .env          # set PUBLIC_DOMAIN and the other production values
docker compose -f docker-compose.prod.yml up -d --build

bash scripts/check-docker-prod.sh  # perimeter + TLS + regression validation
```

Only the `proxy` service (Caddy, `Caddyfile`) publishes host ports (`80`,
`443`) — PostgreSQL, Redis, the backend, and the frontend publish none;
they are reachable only over the internal Docker networks. The host
firewall must still block `5432`/`6379`/`8000`/`3000` externally and
allow only `22` (restricted), `80`, and `443` — this repository has no
mechanism to configure a host firewall and does not attempt to.

First-tenant provisioning is an operator command, not an HTTP route:
`python -m api.tenant_bootstrap` (run inside the `backend` container) —
see `docs/RUNBOOKS.md`, "First-tenant bootstrap".

## Security scanning

Per `docs/IMPLEMENTATION-ROADMAP.md` Phase 1.4:

- **Dependency vulnerabilities**: `pip-audit` (backend, scans the resolved
  Python environment against the OSV database) and `npm audit
  --audit-level=high` (frontend, scans `frontend/package-lock.json`). Run
  both with `bash scripts/check-security.sh` (needs `pip install -e
  ".[security]"` first). CI runs the same command.
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
committed configuration file. CI requires no secret of any kind. The full
`SecretsProvider` runtime, and any future concrete secrets-manager
implementation, remain provider-agnostic behind that interface (a later
phase) -- nothing in Phase 1.4 assumes a specific provider.
