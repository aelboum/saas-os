# Implementation Roadmap

Status: PROPOSED sequencing (phase order/boundaries) — not yet started, no implementation exists. Technology dependencies referenced within each phase are ACCEPTED per `docs/ADR/` (see `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md`).

This roadmap decomposes the platform into small, independently testable phases. Each phase is designed to be shippable and verifiable on its own, without depending on later phases being complete. Phases within the same numbered group (e.g., 1.x) are ordered; phases across groups may be reordered if a dependency listed doesn't block it, but the group order (0 → 7) reflects the sequencing rationale in `docs/ARCHITECTURE-DISCOVERY.md` §25 and `docs/AI-CONTROL-PLANE.md` §6.

Every phase below follows the same template: Objective, Files/Modules Affected, Dependencies, Tests, Security Requirements, Acceptance Criteria, Rollback Strategy.

---

## Phase 0 — Decisions

### 0.1 Resolve open ADRs — COMPLETE
- **Objective**: obtain explicit human sign-off on every ADR marked Proposed in `docs/ADR/` (0002, 0005–0010), before any code in a phase that depends on that decision begins.
- **Files/Modules Affected**: `docs/ADR/000{2,5,6,7,8,9},0010-*.md` (status field updates only).
- **Dependencies**: none.
- **Tests**: none (documentation-only phase).
- **Security Requirements**: none beyond ensuring the multi-tenancy (0002) and identity (0005) decisions receive explicit security review before acceptance, given their downstream blast radius.
- **Acceptance Criteria**: each listed ADR's status is updated to Accepted (or a superseding ADR is written) with a recorded decision and date.
- **Rollback Strategy**: n/a (reverting a decision means writing a new superseding ADR, per the ADR process itself).
- **Outcome**: complete as of 2026-09-06. All seven ADRs (0002, 0005–0010) are Accepted, with one residual sub-decision left open (observability backend vendor, ADR-0009) that does not block Phase 1. Full record: `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md`.

---

## Phase 1 — Repository Foundations

### 1.1 Directory scaffolding
- **Objective**: create the physical directory structure defined in `docs/ARCHITECTURE.md` §3 (`core/`, `infra/`, `control-plane/`, `products/`, `contracts/`), each with a placeholder README stating its ownership per `docs/ARCHITECTURE.md` §4.
- **Files/Modules Affected**: new top-level directories and their README files only — no functional code.
- **Dependencies**: Phase 0.1 (ADR-0003 accepted).
- **Tests**: a CI check that every top-level module directory contains a README declaring its owner and layer.
- **Security Requirements**: none.
- **Acceptance Criteria**: directory structure matches `docs/ARCHITECTURE.md` §3 exactly; each README correctly states its layer.
- **Rollback Strategy**: delete the directories; no data or running system affected.
- **Outcome**: complete. `core/`, `infra/`, `control-plane/control_plane/`, `products/` exist with docstring-level ownership notes (in `__init__.py`, not a separate README per module — `contracts/` deferred, not required by any phase yet).

### 1.2 Toolchain and package management baseline
- **Objective**: initialize **Python 3.13+** packaging/project config (`pyproject.toml`) for the backend (`core/`, `infra/`, `control-plane/`, `products/`, `contracts/`) and a Node/TypeScript project config for the **Next.js** frontend, per `docs/ADR/0011-backend-language-and-toolchain.md`, with per-layer package boundaries reflecting §3. Wire up **Ruff** (lint/format) and **Pyright** (type checking, switched from the ADR's original mypy default per its own reversibility note) for the backend.
- **Files/Modules Affected**: root/backend `pyproject.toml` (and one manifest per top-level module if adopted), `frontend/package.json`, Ruff/Pyright config.
- **Dependencies**: 1.1.
- **Tests**: `install`/`build` succeeds from a clean checkout, for both the backend and frontend toolchains independently.
- **Security Requirements**: lockfiles committed for both toolchains; no dependency installed without a documented reason.
- **Acceptance Criteria**: a clean clone can install backend and frontend dependencies and run empty `pytest`/Ruff/Pyright and frontend build commands successfully.
- **Rollback Strategy**: revert the commit; no runtime system affected yet.
- **Outcome**: complete. `pyproject.toml` configures Ruff/Pyright/pytest/import-linter; `frontend/package.json` configures TypeScript/ESLint/Next.js. Package managers: plain `pip`+`setuptools` (backend), `npm` (frontend) — no uv/Poetry/pnpm/yarn/Bun, per `docs/ADR/0011-...`.

### 1.3 Dependency-boundary CI enforcement
- **Objective**: wire up the dependency-graph lint rule (`docs/ARCHITECTURE.md` §8) so a Core→Product import, a Product→Product import, or a Control-Plane→internal (non-tool) import fails CI. Backend enforcement uses an **import-linter**-style Python import-boundary tool; frontend enforcement (if/when the Next.js app grows internal boundaries worth checking) uses ESLint import-boundary rules.
- **Files/Modules Affected**: `import-linter` (or equivalent) config, ESLint config, CI pipeline config.
- **Dependencies**: 1.1, 1.2.
- **Tests**: a deliberately-added, temporary violating import (e.g., in a scratch test fixture) is confirmed to fail CI, then removed.
- **Security Requirements**: this check itself is a security control (per ADR-0001) — its removal or weakening should require the same review rigor as a security control change.
- **Acceptance Criteria**: CI red on any disallowed cross-layer import; CI green otherwise.
- **Rollback Strategy**: revert the CI config change; does not affect any deployed system.
- **Outcome**: complete. `pyproject.toml` `[tool.importlinter]` contracts (Core/Infra forbidden from Products/Control-Plane) enforced both by `tests/architecture/test_layer_boundaries.py` (pytest) and directly by `.github/workflows/ci.yml`'s `backend` job. Verified non-vacuous by temporarily introducing a forbidden import locally and confirming failure (see Phase 1.1/1.2 implementation reports). No ESLint import-boundary contract exists yet — the frontend has no internal module boundaries worth checking yet (single placeholder page).
- **Hardening pass (Phase 1.3, "Architecture Enforcement Hardening")**: consolidated Core's AI/LLM-framework independence check (`docs/ARCHITECTURE.md` §2 rule 5) from a hand-rolled AST scanner in the test file into a third import-linter contract, using `include_external_packages = true` so `lint-imports` catches a forbidden third-party import (e.g. `import openai`) even when that package isn't installed — one enforcement mechanism for both internal-boundary and AI-framework rules, not two parallel ones. Now **3 contracts, 3 kept, 0 broken**. All five forbidden edges (`core->products`, `core->control_plane`, `infra->products`, `infra->control_plane`, `core->{anthropic,openai,...}`) individually, manually verified to fail with a correct violation message, then reverted — see the Phase 1.3 implementation report for the exact commands and output.

### 1.4 CI pipeline skeleton
- **Objective**: stand up stages 1–4 of `docs/DEPLOYMENT-ARCHITECTURE.md` §5 (lint+boundary check, test, security scan placeholder, build a Docker image per `docs/ADR/0010-deployment-target.md`) for an empty/near-empty codebase. Stages built here must stay deployment-target-agnostic (no Compose/VPS-specific assumptions), per the `infra/deploy` interface boundary in `docs/DEPLOYMENT-ARCHITECTURE.md` §8.
- **Files/Modules Affected**: CI pipeline config.
- **Dependencies**: 1.2, 1.3.
- **Tests**: pipeline runs end-to-end on a trivial commit.
- **Security Requirements**: dependency and secret scanning stage present even if initially permissive, per `docs/SECURITY.md` §10.
- **Acceptance Criteria**: a PR triggers the full pipeline and reports pass/fail per stage.
- **Outcome**: complete as of the Phase 1.4 hardening pass ("Docker + Security/CI Foundation"). `.github/workflows/ci.yml` now runs four jobs: `backend`, `frontend` (from Phase 1.2), `security` (`scripts/check-security.sh` — pip-audit, npm audit, detect-secrets), and `docker` (`scripts/check-docker.sh` — backend + frontend image builds, a non-root runtime smoke test for each, `docker compose config`). `.dockerignore` (root and `frontend/`) added and empirically verified to exclude `.env`/`.venv`/`.git`/host `node_modules` from build contexts; both images now run as non-root. One dependency vulnerability was found and fixed during this pass (transitive `postcss` via `next`, high severity — resolved with a scoped `overrides` pin to a patched 8.5.x release, not a Next.js major-version bump). No database/cache/production-infrastructure job was added to CI, consistent with this phase's explicit scope limit. Full record: Phase 1.4 implementation report.
- **Rollback Strategy**: revert CI config; no production impact.

---

## Phase 2 — Infrastructure Primitives

### 2.1 `infra/db` connection and query primitives
- **Objective**: build the database connection/pooling layer (**SQLAlchemy 2.x** engine/session management) and the base query interface that will become the tenant-scoping enforcement chokepoint (`docs/MULTI-TENANCY.md` §3) — enforcement logic itself lands in Phase 3 alongside `core/tenancy`, but the chokepoint's shape (no direct DB access from outside this module) is established now. Migration tooling (**Alembic**) is also initialized here.
- **Files/Modules Affected**: `infra/db/*`.
- **Dependencies**: Phase 1; PostgreSQL + row-level tenancy per `docs/ADR/0002-multi-tenancy-isolation-model.md` (Accepted).
- **Tests**: unit tests for connection lifecycle; integration test against a real (local/test) database instance.
- **Security Requirements**: no credentials in code or config committed to the repo; credentials sourced via `infra/secrets` (2.3).
- **Acceptance Criteria**: a query executed through `infra/db` succeeds against a real test database; no other module can obtain a raw connection.
- **Rollback Strategy**: this module has no external consumers yet at this phase; revert is a plain code revert.
- **Outcome**: complete. `infra/db/{config,engine,session}.py` implement `DatabaseConfig`/`get_database_config()` (env-driven, no secret field, mirrors `core/config`'s interim env-read pattern since `infra/secrets` is Phase 2.3 and doesn't exist yet), `get_engine()`/`build_engine()`, and `session_scope()` (the sole sanctioned way to get a session — confirmed via a dedicated test that `infra.db.__all__` exposes no raw-connection escape hatch). Alembic initialized at `infra/db/migrations/` (`alembic.ini` at repo root, URL read from `infra.db.config`, never hardcoded); `target_metadata = None` and `versions/` is empty since no table is defined anywhere yet. Tests: unit tests for config/engine/session (session tests use in-memory SQLite to exercise commit/rollback control flow without needing PostgreSQL) plus a real-PostgreSQL integration suite (`tests/infra/test_db_integration.py`), marked `integration` and excluded from the default `pytest` run/CI (verified against a real, temporarily-started PostgreSQL container, then confirmed to skip promptly — not hang — when unreachable). `infra/db` does not import `core` (Infrastructure depends on nothing above it) — confirmed by direct inspection. A follow-up chokepoint audit found that the *acceptance criterion itself* ("no other module can obtain a raw connection") was not actually enforced — nothing stopped `core`/`products`/`control_plane` from doing `from sqlalchemy import create_engine` directly, confirmed by temporarily injecting exactly that import and observing `lint-imports` report it clean. Fixed with a 4th import-linter contract, "Only infra/db may import SQLAlchemy or psycopg directly" (`source_modules = ["core", "products", "control_plane"]`, `forbidden_modules = ["sqlalchemy", "psycopg", "psycopg2"]`), implementing `docs/MULTI-TENANCY.md` §3 verbatim. Proven non-vacuous both interactively and via a permanent test (`tests/architecture/test_layer_boundaries.py::test_forbidden_database_import_is_actually_caught`) that injects a real forbidden import into `core/__init__.py` at test-runtime, confirms `lint-imports` reports it `BROKEN`, and restores the file byte-exact. Full record: Phase 2.1 implementation report and the follow-up chokepoint-audit report.

### 2.2 `infra/observability` SDK baseline
- **Objective**: implement the shared logging/metrics/tracing SDK using **OpenTelemetry** (`docs/ADR/0009-observability-backend.md`, Accepted standard) and the correlation-ID context propagation (`docs/OBSERVABILITY.md` §2, including the `deployment_id`/`version` dimension), without a production backend wired yet (local/console exporter acceptable — backend vendor is a residual open decision that does not block this phase).
- **Files/Modules Affected**: `infra/observability/*`.
- **Dependencies**: Phase 1.
- **Tests**: unit test confirming `tenant_id`/`user_id`/`request_id`/`deployment_id` propagate through a simulated call chain into emitted log/span records.
- **Security Requirements**: ensure no secret values are ever logged (a scrubbing/allowlist test).
- **Acceptance Criteria**: a sample instrumented function call produces a log line and trace span carrying the full correlation context.
- **Rollback Strategy**: revert; no consumers depend on it yet.
- **Outcome**: complete. `infra/observability/config.py` implements `ObservabilityConfig`/`get_observability_config()` (env-driven, mirrors `infra/db`'s interim env-read pattern since `infra/secrets` is Phase 2.3 and doesn't exist yet; `exporter` restricted to `"console"`/`"none"` — no production backend, per this phase's scope). `context.py` implements `CorrelationContext`/`bind_correlation_context()` on a `contextvars.ContextVar` (`tenant_id`/`user_id`/`request_id`/`agent_id`/`action_id`, `docs/OBSERVABILITY.md` §2) — confirmed async-safe (not a shared global) via a test isolating two concurrent `asyncio` tasks. `otel.py` implements `configure_tracing()`/`get_tracer()` on the official `opentelemetry-api`/`opentelemetry-sdk` (`Resource` carrying `service.name`/`service.version`/`deployment.environment`/`deployment.id`; `ConsoleSpanExporter` or no exporter, never a mandatory network collector). `logging.py` implements `configure_logging()`: one JSON-line handler on stdout, attaching the correlation context plus `deployment_id`/`version`/`trace_id`/`span_id` (OTel's own current-span identifiers, kept a clearly distinct field from `request_id` — confirmed by a test that the two never collide) to every record via a `logging.Filter`. Metrics are explicitly out of scope for this phase — the Objective text mentions them, but the Acceptance Criteria and Tests bullets exercise only logs/traces, and building an unused metrics surface now would be the same premature-scaffolding mistake the Phase 2.1 (SaaS Core runtime) correction identified. Tests: 26 unit tests across `tests/infra/observability/{test_observability_config,test_context,test_otel,test_logging,test_end_to_end}.py`, including the literal acceptance-criteria scenario (a simulated nested call chain producing two spans sharing one trace ID, and log lines carrying the full correlation context) and a non-vacuous secret-leakage test. A `tests/infra/observability/conftest.py` fixture resets OpenTelemetry's private global `TracerProvider` state between tests — required because OTel's global provider is, by the SDK's own design, settable only once per process. Two new import-linter contracts close a boundary gap this phase found: `infra` had no contract preventing it from importing `core` (only the `products`/`control_plane` direction was covered) or an AI/LLM framework (only `core`'s equivalent contract existed). Added "Infrastructure does not depend on Core" and "Infrastructure does not depend on AI or LLM frameworks", both proven non-vacuous via `tests/architecture/test_layer_boundaries.py::test_forbidden_infra_to_core_import_is_actually_caught` (temporarily injects `import core` into `infra/__init__.py`, confirms `lint-imports` reports it `BROKEN`, restores byte-exact) alongside the existing AI/LLM-framework proof pattern. Full record: Phase 2.2 implementation report.

### 2.3 `infra/secrets` — `SecretsProvider` abstraction
- **Objective**: implement the `SecretsProvider` interface (`docs/ADR/0012-secrets-management.md`, Accepted) every module will use, with two concrete implementations: a **development** implementation reading from `.env`, and a **Docker/host production** implementation reading secrets injected into the container's runtime environment at start-up (env vars or Docker Compose `secrets:`-mounted files). Create `.env.example` documenting every variable known at this phase (placeholder values only) and confirm `.env` is gitignored.
- **Files/Modules Affected**: `infra/secrets/*`, `.env.example`, `.gitignore`.
- **Dependencies**: Phase 1.
- **Tests**: unit test that a missing required secret fails fast with a clear error at startup, not at first use; a test confirming the development implementation never runs when a production-environment flag is set (and vice versa); a build-artifact inspection test confirming no secret value appears in a built Docker image layer.
- **Security Requirements**: no secret value ever logged (shared test with 2.2); no secret committed to the repository (CI secret-scan, 1.4, checks `.env` is absent from git history and `.env.example` contains no real-looking values); `.gitignore` covers `.env` from the same commit that introduces it.
- **Acceptance Criteria**: a module can request a named secret through `SecretsProvider` and receive it (or a clear startup failure if absent) under both the development and Docker/host production implementations, with identical calling code.
- **Rollback Strategy**: revert; no consumers depend on it yet.
- **Outcome**: complete. `infra/secrets/provider.py` defines the `SecretsProvider` ABC (`get(name) -> str | None`, `get_required(name) -> str`) plus `SecretNotFoundError`/`SecretsConfigurationError` — both typed, carrying only the secret's *name*, never a value. `infra/secrets/providers.py` implements the two implementations ADR-0012 specifies: `EnvFileSecretsProvider` (development — parses a local `.env` file with a minimal stdlib `KEY=VALUE` parser, no new dependency; an explicitly exported process-environment variable takes precedence over the file, the standard dotenv convention, keeping behavior independent of whatever a given developer machine's own `.env` happens to contain) and `EnvironmentSecretsProvider` (Docker/host production — reads `os.environ` directly, plus the `<NAME>_FILE` convention for a Docker Compose `secrets:`-mounted file). `infra/secrets/config.py`'s `get_secrets_provider()` selects between them by the same `ENVIRONMENT` variable `core/config`/`infra/observability` already read independently (`"development"` → `EnvFileSecretsProvider`; `"test"`/`"production"` → `EnvironmentSecretsProvider`; anything else raises `SecretsConfigurationError`), cached the same way `get_database_config`/`get_observability_config` are. Neither provider stores a *resolved* value on the instance, and both override `__repr__` so an accidental log/exception/repr never reveals one — confirmed by dedicated tests seeding a fake value under an unrelated name and asserting it never appears in `repr()`/`str()`/exception text. `infra/db/config.py` was migrated (this phase's own Security Requirement for 2.1): `DATABASE_URL` is now retrieved via `get_secrets_provider().get(...)` instead of `os.environ` directly, with `DatabaseConfig`/`DatabaseConfigurationError`/`get_database_config`'s public shape and exact error message unchanged, proven non-vacuous by substituting a fake provider and confirming `infra/db` uses *its* answer, not `os.environ`'s (`tests/infra/secrets/test_db_consumer_integration.py`). `infra/observability`'s config was left untouched — none of its fields are secrets. A new import-linter contract, "Only infra/secrets may import its own concrete provider implementations" (`source_modules` covering `core`, `products`, `control_plane`, `infra.db`, `infra.observability`; `forbidden_modules = ["infra.secrets.providers"]`), enforces that consumers depend on the public `SecretsProvider` interface only — with one `ignore_imports` entry (`infra.secrets.config -> infra.secrets.providers`) for the one internal edge the interface's own wiring requires, since import-linter's "forbidden" contract checks reachability, not just a direct edge, and would otherwise flag every legitimate consumer of the public interface. Proven non-vacuous the same way as the platform's other chokepoint contracts: a real forbidden `import infra.secrets.providers` was temporarily written into `infra/db/__init__.py`, `lint-imports` was confirmed to report it `BROKEN`, and the file was restored byte-exact (`tests/architecture/test_layer_boundaries.py::test_forbidden_provider_implementation_import_is_actually_caught`). Tests: 42 across `tests/infra/secrets/` covering the interface contract (including the "a required-but-empty secret is never silently treated as present" rule), both concrete implementations (including the Docker secrets-file-mount convention and quote-stripping), provider selection, cross-cutting secret-value-safety, the `infra/db` consumer-integration proof, and a static Dockerfile/`.dockerignore`/`docker-compose.yml` inspection (not an actual built-image layer extraction, which would need a Docker daemon dependency this phase doesn't otherwise require — separately, empirically confirmed once by hand: `docker history --no-trunc` on the built backend image contains no known secret-shaped value, and the running container has no `.env` file). Zero new dependencies (`pip-audit` clean); no `.env.example`/`.gitignore`/Dockerfile/`docker-compose.yml` changes were needed — Phase 1.4's existing secret-exclusion mechanisms already covered everything this phase requires.

### 2.4 `infra/jobs` queue/worker runner
- **Objective**: implement the generic job execution, retry/backoff, and dead-letter mechanism (`docs/DATA-ARCHITECTURE.md` §5) as a **Redis-backed** queue, per `docs/ADR/0007-background-job-and-workflow-engine.md` (Accepted), with no business-logic jobs registered yet. The interface is deliberately kept narrow (enqueue/execute/retry/dead-letter only) — no multi-step or compensating-workflow semantics — reserving room for a durable workflow engine to be added later (Phase 7+) without a rewrite.
- **Files/Modules Affected**: `infra/jobs/*`.
- **Dependencies**: Phase 1; Redis provisioned as a runtime dependency (Docker Compose service, per `docs/ADR/0010-deployment-target.md`).
- **Tests**: a sample no-op job enqueues, executes, and retries correctly on a simulated failure.
- **Security Requirements**: job payloads containing tenant data are validated as carrying `tenant_id` (schema-level check), per `docs/MULTI-TENANCY.md` §4.
- **Acceptance Criteria**: sample job completes; sample failing job retries per policy then dead-letters.
- **Rollback Strategy**: revert; no production jobs registered yet.
- **Outcome**: complete. `infra/jobs` implements the narrow enqueue/execute/retry/dead-letter interface on **ARQ** (per ADR-0007), with no business-logic job registered. `infra/jobs/config.py`'s `get_jobs_config()` sources `REDIS_URL` through `infra.secrets.get_secrets_provider()` (docs/IMPLEMENTATION-ROADMAP.md Phase 2.3 — a connection URL can embed credentials, so it is never read from `os.environ` directly, the same discipline `infra/db`'s `DATABASE_URL` follows), plus two plain non-secret tunables (`JOBS_MAX_TRIES`, default 3; `JOBS_RETRY_BACKOFF_BASE_SECONDS`, default 1.0). `infra/jobs/payload.py`'s `TenantJobPayload` makes `tenant_id` a required dataclass field — the schema-level check the Security Requirement calls for: a job payload carrying tenant-owned data cannot be constructed without one (docs/MULTI-TENANCY.md §4); a job with no tenant-owned data passes `payload=None` instead. Retry/backoff/dead-letter is decided by `infra/jobs` itself, not delegated to arq's own bookkeeping: `register_job()` pins a registered function's arq-level `max_tries` to `JobsConfig.max_tries` exactly, so arq always hands control back to `infra/jobs`'s own wrapper on the final attempt (rather than silently aborting the job itself); that wrapper re-raises `arq.Retry` with exponential backoff while attempts remain, or — on the final attempt — records a `infra/jobs/dead_letter.py` entry (function name, tenant ID, error text, attempt count; never the payload's own data, so an accidental secret-shaped value in a job's business payload is never persisted into the dead-letter record) and raises `JobDeadLetteredError`. Tests: 28 unit tests across `tests/infra/jobs/` — configuration, the payload schema check, dead-letter recording (against a duck-typed fake Redis pool, so the default suite has no external dependency), the retry/dead-letter decision logic (including that a `arq.Retry`'s backoff grows with each attempt, and that dead-lettering happens only on the true final attempt), and `enqueue_job()` — plus 2 more in `tests/infra/jobs/test_jobs_integration.py` (marked `integration`, excluded from the default run, mirroring `tests/infra/test_db_integration.py`) proves the literal acceptance criteria end-to-end against a real Redis: a sample job enqueues, executes, and completes; a sample always-failing job retries once then dead-letters — run and confirmed passing against a disposable Redis container during this phase's implementation (`docker run --rm -p <port>:6379 redis:7-alpine`, then torn down), and confirmed to skip cleanly (not fail) when Redis is unreachable or requires authentication this session doesn't have. Zero new dependencies — `redis`/`arq` were already declared in `pyproject.toml` from Phase 1.1. Confirmed `infra.jobs` imports cleanly inside the actual built backend Docker image. No new import-linter contract: unlike `infra/db`'s SQLAlchemy/psycopg chokepoint (an explicit Phase 2.1 acceptance criterion) or `infra/secrets`'s provider-implementation boundary (ADR-0012, binding), neither ADR-0007 nor this phase's acceptance criteria establish an equivalent "infra/jobs is the only place Redis/arq may be imported" rule, so none was added.
- **Post-implementation audit correction**: a focused audit found the tenant-payload schema check was enforced by `TenantJobPayload`'s own constructor but not by the queue boundary itself — `enqueue_job()` accepted any object as `payload`, so a raw `dict` never routed through `TenantJobPayload` could silently bypass the Security Requirement. Fixed by adding an explicit `isinstance(payload, TenantJobPayload)` check in `enqueue_job()` (new `InvalidJobPayloadError`, carrying only the function name and the offending type name — never the payload's contents), checked before any Redis connection is opened. Proven non-vacuous: the guard was temporarily removed, four tests failed (one by actually attempting a live Redis connection with the invalid payload), then the guard was restored and all tests passed again. The same audit found `get_redis_pool` — a fully-capable Redis client — was re-exported in `infra.jobs.__all__`, exceeding ADR-0007's narrow enqueue/execute/retry/dead-letter interface; removed from the top-level public surface (still available via `infra.jobs.queue.get_redis_pool` for internal use and tests). 11 more tests added across `tests/infra/jobs/test_enqueue.py` and the new `tests/infra/jobs/test_public_api.py` (39 unit + 2 integration total). Two lower-severity findings from the same audit (a worker crash or a Redis failure exactly during dead-letter recording can let ARQ mark a job permanently failed without an `infra/jobs` dead-letter record) were deliberately left unaddressed — reconciliation/crash-recovery machinery is outside this phase's narrow scope.

### 2.5 `infra/health` liveness/readiness endpoints
- **Objective**: generic health-check aggregation mechanism (`docs/DEPLOYMENT-ARCHITECTURE.md` §7), initially aggregating DB and queue reachability only.
- **Files/Modules Affected**: `infra/health/*`.
- **Dependencies**: 2.1, 2.4.
- **Tests**: health endpoint reports healthy when dependencies are up, unhealthy when a dependency is deliberately taken down in a test environment.
- **Security Requirements**: health endpoint exposes no sensitive internal detail to unauthenticated callers.
- **Acceptance Criteria**: `/health` (or equivalent) returns correct status under both conditions.
- **Rollback Strategy**: revert; no deployment gates depend on it until Phase 8.
- **Outcome**: complete. `infra/health` implements the generic liveness/readiness aggregation mechanism `docs/DEPLOYMENT-ARCHITECTURE.md` §7 calls for — no HTTP endpoint is wired (that is Phase 8.2's ingress-layer concern; the roadmap's own "`/health` (or equivalent)" phrasing already anticipates this). `infra/health/results.py` defines `HealthStatus` (a `StrEnum`), `CheckResult` (name/status/`detail`), and `ReadinessReport` (overall status + per-check results) — `detail` is deliberately restricted to a failing exception's *type name* only, never its message, so the Security Requirement ("no sensitive internal detail exposed") holds structurally. `infra/health/liveness.py`'s `check_liveness()` is a pure, synchronous, zero-I/O function — it cannot fail unless the process itself cannot execute Python, and never imports `infra.db`/`infra.jobs`. `infra/health/readiness.py`'s `check_readiness()` aggregates two checks via `asyncio.gather`: `_check_database()` reuses `infra.db.config.get_database_config()` and `infra.db.engine.build_engine()` (a `SELECT 1` through a short-lived, short-`connect_timeout`-bounded connection — reusing Phase 2.1's own documented finding that an unreachable host with no timeout can hang for the OS's default TCP timeout), and `_check_redis()` reuses `infra.jobs.queue.get_redis_pool()` (a `PING`, relying on `arq.connections.RedisSettings`'s own already-bounded default connect timeout/retry policy rather than adding a second one). Neither check duplicates connection/secret configuration — `DATABASE_URL`/`REDIS_URL` continue to flow through `infra.secrets` exactly as Phase 2.1/2.4 established; `infra/health` reads no secret and builds no connection string itself. Both checks catch every exception internally and return a failed `CheckResult` rather than propagating — one dependency being down never crashes the aggregator or affects the other check's result. Public API (`infra.health.__all__`): `HealthStatus`, `CheckResult`, `ReadinessReport`, `check_liveness`, `check_readiness` — no raw engine, pool, or secrets-provider handle is exposed, matching the narrow-surface discipline established for `infra/secrets` (Phase 2.3) and corrected into `infra/jobs` (Phase 2.4's `get_redis_pool` correction). Tests: 19 unit tests across `tests/infra/health/` (liveness; DB readiness against a real in-memory SQLite engine for the healthy path and a fake failing engine for the unhealthy path, including a non-vacuous proof via a SQLAlchemy event listener that `SELECT 1` is genuinely executed, not hard-coded; Redis readiness against a duck-typed fake pool; all four DB-healthy × Redis-healthy/unhealthy combinations for `check_readiness()`, each proven non-vacuous by substituting `_check_database`/`_check_redis`) plus 5 more in `test_health_integration.py` (marked `integration`, mirroring `tests/infra/test_db_integration.py` and `tests/infra/jobs/test_jobs_integration.py`) — run and confirmed passing against disposable PostgreSQL + Redis containers during this phase's implementation (both healthy-real and genuinely-unreachable-endpoint failure paths), and confirmed to skip cleanly, bounded (not hanging), when either dependency is unreachable. Two security tests per dependency embed a fake, obviously-placeholder password value in the underlying exception and confirm it never surfaces in the check result. Zero new dependencies. No new import-linter contract: `infra/health` importing `sqlalchemy` (for `text("SELECT 1")`) is unrestricted by the existing "Only infra/db may import SQLAlchemy or psycopg directly" contract, whose `source_modules` are `core`/`products`/`control_plane` only — `infra` submodules reaching each other's public APIs (and, minimally, `sqlalchemy.text`) is the already-accepted shape of Infrastructure-internal composition, not a new boundary question this phase raised. `.secrets.baseline` gained one audited entry (`tests/infra/health/test_health_integration.py`, the same placeholder `saas_os:changeme` credential already audited for `tests/infra/test_db_integration.py`, at its own line number) — no existing entry was modified or removed.

---

## Phase 3 — Tenancy and Identity Foundation

### 3.1 `core/tenancy` — tenant entity and lifecycle
- **Objective**: implement the tenant entity, lifecycle states (`docs/MULTI-TENANCY.md` §6), and tenant-scoping enforcement at `infra/db` (completing the chokepoint started in 2.1).
- **Files/Modules Affected**: `core/tenancy/*`, `infra/db/*` (enforcement logic).
- **Dependencies**: 2.1; ADR-0002 accepted.
- **Tests**: unit + integration tests proving a query for tenant A's data cannot return tenant B's data, including an adversarial test that attempts to bypass scoping.
- **Security Requirements**: this phase implements the platform's primary security boundary (`docs/SECURITY.md` §5) — requires a dedicated security review before merge, not just normal code review.
- **Acceptance Criteria**: tenant CRUD works; cross-tenant data leakage test suite passes; RLS policies (if applicable per ADR-0002) are active and tested.
- **Rollback Strategy**: this is foundational — rollback means reverting to no tenancy model at all, which blocks all subsequent phases. Any rollback after this phase ships to production requires a data-migration-aware rollback plan (`docs/DEPLOYMENT-ARCHITECTURE.md` §6), not a simple code revert.

### 3.2 `core/identity` — users, sessions, OIDC integration
- **Objective**: implement user entity (global, per `docs/MULTI-TENANCY.md` §1), ZITADEL OIDC relying-party integration (token/claim validation, external `sub` → platform `user_id` mapping, per `docs/ADR/0005-identity-build-vs-buy.md`), platform session/token issuance, and org-membership linking to `core/tenancy`. `core/identity` does not store credentials — that remains with ZITADEL.
- **Files/Modules Affected**: `core/identity/*`.
- **Dependencies**: 3.1; a running ZITADEL instance (self-hosted, per `docs/ADR/0010-deployment-target.md`'s Docker Compose target, or a ZITADEL Cloud tenant for early development) reachable for OIDC.
- **Tests**: OIDC callback/token-validation tests against a real or sandboxed ZITADEL instance; login/session lifecycle tests; a user-belongs-to-multiple-tenants integration test.
- **Security Requirements**: dedicated security review of OIDC integration correctness (token/claim validation, redirect URI handling, session token handling); no credential or token value ever logged.
- **Acceptance Criteria**: a user can authenticate via ZITADEL's OIDC flow, `core/identity` issues a platform session, and the user can belong to more than one tenant simultaneously.
- **Rollback Strategy**: same caveat as 3.1 — user data existing in production constrains rollback to forward-fixing rather than reverting, once live.

### 3.3 `core/rbac` — roles, permissions, policy evaluation
- **Objective**: implement the single `can(actor, action, resource)` evaluation chokepoint (`docs/SECURITY.md` §3).
- **Files/Modules Affected**: `core/rbac/*`.
- **Dependencies**: 3.1, 3.2.
- **Tests**: policy evaluation unit tests covering allow/deny for every defined role; an integration test confirming the same evaluation path is used for both a sample Core route and a sample Control-Plane tool stub.
- **Security Requirements**: dedicated security review; a deny-by-default test (unknown action/resource combination must deny, never silently allow).
- **Acceptance Criteria**: policy evaluation is deterministic and covers the defined role set; no code path outside this module makes an authorization decision.
- **Rollback Strategy**: revert code; no production traffic depends on it until Phase 8 (first real routes) wires it in as ingress middleware.

### 3.4 `core/audit-log` — append-only audit store
- **Objective**: implement the audit-log store and query interface (`docs/SECURITY.md` §8), ahead of any capability that needs to emit audit events.
- **Files/Modules Affected**: `core/audit-log/*`.
- **Dependencies**: 3.1, 3.2.
- **Tests**: append succeeds; update/delete on an existing entry is rejected at the data-access layer (immutability test).
- **Security Requirements**: this module is itself a security control — verify no code path can mutate or delete an existing entry, including via direct database access (ties to 3.1's enforcement discipline).
- **Acceptance Criteria**: audit entries are queryable by tenant/actor/time; immutability holds under test.
- **Rollback Strategy**: revert code; no dependents yet.

---

## Phase 4 — Remaining Core Capabilities

### 4.1 `core/api-keys`
- **Objective**: API key issuance, scoping, rotation, revocation.
- **Files/Modules Affected**: `core/api-keys/*`.
- **Dependencies**: 3.1, 3.2, 3.3.
- **Tests**: issuance/revocation lifecycle; a revoked key is rejected by the auth chokepoint (integration test once 3.2's auth middleware exists).
- **Security Requirements**: keys are stored hashed, never in plaintext; revocation takes effect immediately (no cache staleness window beyond a documented, tested bound).
- **Acceptance Criteria**: full key lifecycle passes tests; revoked key access attempt is denied and audit-logged (via 3.4).
- **Rollback Strategy**: revert code; no production keys issued yet at this phase.

### 4.2 `core/feature-flags`
- **Objective**: flag definitions, targeting rules, evaluation SDK.
- **Files/Modules Affected**: `core/feature-flags/*`.
- **Dependencies**: 3.1.
- **Tests**: targeting-rule evaluation unit tests; a flag flip is observed by a consuming test client without redeploy.
- **Security Requirements**: flag state changes are audit-logged (via 3.4).
- **Acceptance Criteria**: a flag can be defined, targeted per tenant, and evaluated correctly.
- **Rollback Strategy**: revert code; flags default to a documented safe default on read failure.

### 4.3 `core/webhooks` (outbound)
- **Objective**: subscription management, delivery, retry, signing.
- **Files/Modules Affected**: `core/webhooks/*`.
- **Dependencies**: 2.4 (`infra/jobs`), 3.1.
- **Tests**: delivery + retry-on-failure integration test against a mock endpoint; signature verification test.
- **Security Requirements**: payload signing key management via `infra/secrets` (2.3); no tenant's webhook secret exposed to another tenant.
- **Acceptance Criteria**: a subscribed webhook receives correctly signed events with retry on transient failure.
- **Rollback Strategy**: revert code; disable delivery via feature flag if a bad deploy causes delivery storms.

### 4.4 `core/notifications`
- **Objective**: generic dispatch pipeline (email/SMS/push/in-app), with product-supplied templates deferred to the Product Contract (`docs/ARCHITECTURE.md` §9).
- **Files/Modules Affected**: `core/notifications/*`.
- **Dependencies**: 2.4, 3.1.
- **Tests**: dispatch integration test against a test provider/sandbox for each channel implemented.
- **Security Requirements**: no tenant's notification content or recipient list accessible to another tenant's dispatch path.
- **Acceptance Criteria**: a sample notification dispatches correctly through at least one channel end-to-end in a test environment.
- **Rollback Strategy**: revert code; disable a channel independently via feature flag if a provider integration misbehaves.

---

## Phase 5 — Billing and Usage

### 5.1 `core/billing` — provider abstraction, plans, subscriptions, entitlements
- **Objective**: build the provider-abstraction interface (Plans / Subscriptions / Entitlements / Invoices / Payments as distinct concepts, per `docs/ADR/0008-billing-provider.md`), with **Stripe as the first adapter**; implement the product-agnostic entitlement model (`docs/ARCHITECTURE-DISCOVERY.md` §14). No Core or Product code depends on Stripe-specific types — only the adapter does.
- **Files/Modules Affected**: `core/billing/*`.
- **Dependencies**: 3.1, 3.2, 3.3.
- **Tests**: subscription lifecycle integration test against Stripe's sandbox/test mode, run through the abstraction interface (not the Stripe SDK directly, in test assertions); entitlement lookup unit tests; a substitution test confirming a mock/fake provider adapter satisfies the same interface (proves the abstraction isn't leaky).
- **Security Requirements**: dedicated review of payment-provider credential handling (via `infra/secrets`); webhook-from-provider signature verification (reuses 4.3 patterns where applicable).
- **Acceptance Criteria**: a test subscription can be created, upgraded, and canceled, with entitlements reflecting each state correctly.
- **Rollback Strategy**: billing is revenue-critical — any rollback plan must account for in-flight subscription state at the provider; prefer forward-fix over rollback once live tenant billing exists.

### 5.2 `core/usage` — metering ingestion and aggregation
- **Objective**: usage-event ingestion interface and aggregation logic feeding billing entitlement checks (`docs/DATA-ARCHITECTURE.md` §6).
- **Files/Modules Affected**: `core/usage/*`.
- **Dependencies**: 5.1.
- **Tests**: ingestion-under-load test (confirms async ingestion doesn't block callers); aggregation correctness test against a known event set.
- **Security Requirements**: ingestion path validates `tenant_id` presence and authenticity, preventing usage-event spoofing across tenants.
- **Acceptance Criteria**: emitted usage events are correctly aggregated and reflected in entitlement/quota checks within a documented latency bound.
- **Rollback Strategy**: revert code; aggregation can be recomputed from raw events if a bug is found in aggregation logic (raw events are the source of truth).

---

## Phase 6 — Product Contract (Specification → First Implementation)

### 6.1 Product Contract schema and validator
- **Objective**: implement the schema and validator for the SaaS Product Contract specified in `docs/ARCHITECTURE.md` §9 — this is the first point at which the contract becomes real, not just documented.
- **Files/Modules Affected**: `contracts/*`.
- **Dependencies**: Phases 3–5 complete (the contract references Core modules that must exist to validate against).
- **Tests**: schema validation unit tests (valid contract accepted, contract missing a required field rejected, contract referencing a nonexistent Core module rejected).
- **Security Requirements**: a contract's declared `aiTools` and `environmentVariables` are validated against the actual permission/secret schemas available — a contract cannot declare a tool or secret it isn't authorized to reference.
- **Acceptance Criteria**: a hand-written sample contract (for a hypothetical minimal product) validates successfully; a deliberately malformed sample is rejected with a clear error.
- **Rollback Strategy**: revert code; no product depends on this yet.

---

## Phase 7 — AI Control Plane v0 (Autonomous Development)

**Cross-cutting requirement (`docs/ADR/0013-ai-data-privacy-and-external-model-boundary.md`, Accepted 2026-09-07)**: alongside the Tool Policy mechanism 7.1 builds (`docs/AI-CONTROL-PLANE.md` §2.1, §3), any phase in this group that lets an agent or tool send data to an external AI/LLM provider must also implement the Data Policy / AI data boundary (data classification, minimization, provider-eligibility policy, tenant AI data policy, sensitive-data default-deny — `docs/SECURITY.md` §6.1). No tool in 7.1/7.3 may be registered with unmediated access to an external AI provider ahead of that boundary existing — this is additive to, not separate work from, 7.1's own Security Requirement. Nothing under this requirement is implemented as of this roadmap entry; it is recorded here so the Data Policy gate is planned as part of Phase 7 rather than discovered as a gap once the Tool Policy gate (7.1) is already built.

### 7.1 `control-plane/orchestration` — agent runtime and tool registry mechanism
- **Objective**: build the tool registration/invocation/sandboxing mechanism (`docs/AI-CONTROL-PLANE.md` §3), including the scoped secrets-injection path (`docs/AI-CONTROL-PLANE.md` §3 "Tool Secrets Access", `docs/ADR/0012-...`), with zero tools registered yet.
- **Files/Modules Affected**: `control-plane/orchestration/*`.
- **Dependencies**: 2.3 (`infra/secrets`), 3.2, 3.3, 3.4 (agent identity, authz, and audit must exist first).
- **Tests**: a stub tool registers, is invoked, and its invocation is denied when the invoking agent identity lacks the required RBAC permission; a stub tool declaring a named secret receives that secret's value in its execution context while the invoking agent's returned output/transcript contains no secret value; an attempt to request a secret not declared by the invoking tool is rejected.
- **Security Requirements**: dedicated security review — this is the enforcement point for ADR-0004 and ADR-0012's AI secrets-access consequence; tests confirming no code path allows a tool invocation to bypass RBAC evaluation, and none allows a tool to access a secret it did not declare, are required, not optional.
- **Acceptance Criteria**: a stub tool can be registered, invoked under permission, and rejected without permission; every invocation (allowed or denied) produces an audit-log entry.
- **Rollback Strategy**: revert code; no real tools exist yet, so no production capability is affected.

### 7.2 `control-plane/approvals` — human approval gate workflow
- **Objective**: implement the tier-1 approval workflow (`docs/AI-CONTROL-PLANE.md` §5) as first-class state, not an out-of-band process.
- **Files/Modules Affected**: `control-plane/approvals/*`.
- **Dependencies**: 7.1.
- **Tests**: a staged action requires approval before execution; an approval is itself audit-logged with the approving human's identity.
- **Security Requirements**: an approval cannot be self-granted by the same identity that proposed the action (separation-of-duties test).
- **Acceptance Criteria**: full propose → approve → execute cycle works for a stub action; a rejected proposal never executes.
- **Rollback Strategy**: revert code; no live approvals pending at this phase.

### 7.3 `control-plane/development` — first real tool: development-agent code-change proposal
- **Objective**: build the first real, narrowly scoped tool — an agent that can propose code changes (e.g., open a pull request) against this repository, at tier 1 (propose + human approval via normal PR review, which already satisfies the approval-gate requirement).
- **Files/Modules Affected**: `control-plane/development/*`, one new file under `control-plane/tools/`.
- **Dependencies**: 7.1, 7.2.
- **Tests**: the tool can open a PR in a test/sandbox repository context; it cannot merge or push directly to a protected branch (permission-boundary test).
- **Security Requirements**: agent identity for this tool is scoped to "this repository" only (`docs/AI-CONTROL-PLANE.md` §7); no broader credential is granted.
- **Acceptance Criteria**: agent proposes a change via the normal PR mechanism; normal branch-protection/review rules still apply; every proposal is audit-logged.
- **Rollback Strategy**: disable the tool via the kill-switch mechanism (`docs/AI-CONTROL-PLANE.md` §9) if it misbehaves; proposed-but-unmerged PRs carry no production risk.

---

## Phase 8 — First Real Routes and End-to-End Wiring

### 8.1 Ingress middleware chain
- **Objective**: wire `core/identity` (auth) and `core/rbac` (authz) as the enforced middleware every route passes through (`docs/API-ARCHITECTURE.md` §1–§2), ahead of any real business route being added.
- **Files/Modules Affected**: API ingress layer (new).
- **Dependencies**: 3.2, 3.3.
- **Tests**: an unauthenticated request to a protected route is rejected; an authenticated-but-unauthorized request is rejected; a valid request passes through with correct identity context attached.
- **Security Requirements**: dedicated security review — this is the chokepoint referenced throughout `docs/SECURITY.md`.
- **Acceptance Criteria**: no route can be added that bypasses this middleware (enforced by 1.3's boundary lint, extended to check route registration if feasible).
- **Rollback Strategy**: revert code; no real routes exist to be exposed insecurely yet if this phase is rolled back before 8.2.

### 8.2 First external API route (health/status only)
- **Objective**: expose a minimal, low-risk external route (e.g., authenticated tenant status) at `/v1/...` to validate the full request path end-to-end, including versioning and OpenAPI documentation (`docs/ADR/0006-api-style-and-versioning.md`).
- **Files/Modules Affected**: one route module; an OpenAPI spec fragment for this route.
- **Dependencies**: 8.1.
- **Tests**: end-to-end test hitting the real route through the real middleware chain; OpenAPI spec validated against the actual response shape.
- **Security Requirements**: rate limiting (`docs/API-ARCHITECTURE.md` §6) active on this route from day one.
- **Acceptance Criteria**: route responds correctly under valid auth, rejects correctly under invalid auth, is served under `/v1/`, and is documented in the OpenAPI spec.
- **Rollback Strategy**: standard deployment rollback (`docs/DEPLOYMENT-ARCHITECTURE.md` §6); this route carries no state-mutation risk.

---

## Phase 9+ — Deferred (Not Detailed Here)

The following remain future phases, deliberately not broken down further until the phases above are complete and their learnings can inform sequencing: autonomous customer support agent (tier 0/1), autonomous incident-resolution agent (tier 1, narrow tier-2 promotions only after audit trail is proven per `docs/AI-CONTROL-PLANE.md` §6), autonomous DevOps agent (tier 1 only, last to receive any tier-2 promotion), and Dograh onboarding as the first real Product-layer consumer (`docs/ARCHITECTURE-DISCOVERY.md` §20). Each will receive the same phase template treatment when planned.

---

## Cross-Cutting Rules for Every Phase

- No phase merges without its listed tests passing in CI (Phase 1.4's pipeline).
- No phase touching tenant data (any Phase 3+ ) merges without the cross-tenant isolation test suite established in 3.1 passing against the new code.
- No phase introducing an AI Control Plane tool merges without an audit-logging test (per 7.1) and an explicit autonomy tier declaration (`docs/AI-CONTROL-PLANE.md` §5).
- No phase introduces a new secret-consuming call site outside the `SecretsProvider` interface (`docs/ADR/0012-...`) — any direct environment-variable read for secret material, or any direct call to a specific secrets-management product's SDK from outside `infra/secrets`, is a merge-blocking defect.
- Every phase's rollback strategy must be validated (not just described) before that phase is considered production-ready, per `docs/DEPLOYMENT-ARCHITECTURE.md` §6.
