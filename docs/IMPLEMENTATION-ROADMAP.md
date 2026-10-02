# Implementation Roadmap

Status: PROPOSED sequencing (phase order/boundaries). Technology dependencies referenced within each phase are ACCEPTED per `docs/ADR/` (see `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md`). Implementation status: Phases 0–8 (through 8.2) and Phase 9 (9.1–9.9, self-learning) are complete per each subphase's own `Outcome` entry below. Outcome tracking initially lapsed after Phase 2.5, and Phase 9's own specification was missing from version control entirely; both were retroactively reconciled against the actual codebase, test suite, and (for Phase 9) the specification text quoted verbatim in source docstrings, on 2026-09-17 — see Phase 9's own "RECOVERED FROM SOURCE" note and the Backfilled-capability entries near Phase 2.5 and Phase 8.1. "Phase 9+ — Remaining Deferred Items" (distinct from Phase 9 itself) remains genuinely not started. Phase 5.3 (B2B2C Billing Completion, added by roadmap amendment 2026-10-02) is approved and not started.

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

### Backfilled capability: `infra/db/backup` — PostgreSQL backup, restore, and disaster-recovery primitives
Recorded 2026-09-17. This capability was never given a `2.x` entry in this roadmap — it was tracked instead under a separate, parallel "P-series" hardening numbering (`P1.3`, later extended by `P2.4`) that the code and `docs/BACKUP-RESTORE.md` cite directly but that has no index or canonical definition anywhere in `docs/`. This entry backfills its existence here without renumbering it into `2.x` or inventing the P-series' missing definition.
- **What exists**: `infra/db/backup/{__init__,config,destination,encryption,lock,orchestrator,__main__}.py` (1,967 lines) — manual local backup/restore (P1.3: `create_backup`/restore primitives, deliberately never imported by `infra/db/__init__.py`, reachable only via explicit `from infra.db.backup import ...`) plus a production pipeline (P2.4: `orchestrator.py`, adding encryption, off-site destination upload, and locking around the P1.3 primitives).
- **Security boundary** (per the module's own docstring, citing "P1.3's own Security Boundary"): infrastructure/admin tooling only — "MUST NOT become an application runtime capability... no API route, tenant-facing tool, AI Control Plane tool, Product code, frontend, webhook, or tenant-accessible job may reach it." Enforced by an import-linter `forbidden_modules = ["infra.db.backup"]` contract.
- **Tests**: 8 files under `tests/infra/db/` — `test_backup_{config,destination,encryption,lock,orchestrator,offsite_fail_closed}_unit.py`, `test_backup_unit.py`, and `test_backup_restore_drill_integration.py` (a real disaster-recovery drill).
- **Documentation**: `docs/BACKUP-RESTORE.md` is the existing, detailed operational reference (manual P1.3 usage, full P2.4 production pipeline, encryption key handling, off-site upload, the disaster-recovery drill). This roadmap entry does not duplicate it — see that document for the actual operational procedure.
- **Not a new phase**: this backfill records that the capability exists and is tested; it does not retroactively create a `2.6` and should not be read as one.

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
- **Outcome**: complete (retroactively recorded 2026-09-17; this phase's Outcome tracking had lapsed after Phase 2.5 despite the code shipping). `core/tenancy/{models,lifecycle,service,purge_participants,retention}.py` implement the tenant entity, lifecycle states, and purge/retention flows; 14 test files under `tests/core/tenancy/` and `tests/control_plane/`, including cross-tenant isolation and fencing integration suites.

### 3.2 `core/identity` — users, sessions, OIDC integration
- **Objective**: implement user entity (global, per `docs/MULTI-TENANCY.md` §1), ZITADEL OIDC relying-party integration (token/claim validation, external `sub` → platform `user_id` mapping, per `docs/ADR/0005-identity-build-vs-buy.md`), platform session/token issuance, and org-membership linking to `core/tenancy`. `core/identity` does not store credentials — that remains with ZITADEL.
- **Files/Modules Affected**: `core/identity/*`.
- **Dependencies**: 3.1; a running ZITADEL instance (self-hosted, per `docs/ADR/0010-deployment-target.md`'s Docker Compose target, or a ZITADEL Cloud tenant for early development) reachable for OIDC.
- **Tests**: OIDC callback/token-validation tests against a real or sandboxed ZITADEL instance; login/session lifecycle tests; a user-belongs-to-multiple-tenants integration test.
- **Security Requirements**: dedicated security review of OIDC integration correctness (token/claim validation, redirect URI handling, session token handling); no credential or token value ever logged.
- **Acceptance Criteria**: a user can authenticate via ZITADEL's OIDC flow, `core/identity` issues a platform session, and the user can belong to more than one tenant simultaneously.
- **Rollback Strategy**: same caveat as 3.1 — user data existing in production constrains rollback to forward-fixing rather than reverting, once live.
- **Outcome**: complete (retroactively recorded 2026-09-17). `core/identity/{oidc,sessions,erasure,session_retention}.py` implement OIDC integration, session lifecycle, and identity erasure/retention; `api/auth/routes.py` exposes the authentication routes; 19 test files under `tests/core/identity/` and `tests/api/`.

### 3.3 `core/rbac` — roles, permissions, policy evaluation
- **Objective**: implement the single `can(actor, action, resource)` evaluation chokepoint (`docs/SECURITY.md` §3).
- **Files/Modules Affected**: `core/rbac/*`.
- **Dependencies**: 3.1, 3.2.
- **Tests**: policy evaluation unit tests covering allow/deny for every defined role; an integration test confirming the same evaluation path is used for both a sample Core route and a sample Control-Plane tool stub.
- **Security Requirements**: dedicated security review; a deny-by-default test (unknown action/resource combination must deny, never silently allow).
- **Acceptance Criteria**: policy evaluation is deterministic and covers the defined role set; no code path outside this module makes an authorization decision.
- **Rollback Strategy**: revert code; no production traffic depends on it until Phase 8 (first real routes) wires it in as ingress middleware.
- **Outcome**: complete (retroactively recorded 2026-09-17). `core/rbac/{authorization,scope,principal}.py` implement the `can(actor, action, resource)` chokepoint; `api/dependencies.py`'s `require_permission()` wires it into every protected route (see also 8.1). 15 test files under `tests/core/rbac/`.

### 3.4 `core/audit-log` — append-only audit store
- **Objective**: implement the audit-log store and query interface (`docs/SECURITY.md` §8), ahead of any capability that needs to emit audit events.
- **Files/Modules Affected**: `core/audit-log/*`.
- **Dependencies**: 3.1, 3.2.
- **Tests**: append succeeds; update/delete on an existing entry is rejected at the data-access layer (immutability test).
- **Security Requirements**: this module is itself a security control — verify no code path can mutate or delete an existing entry, including via direct database access (ties to 3.1's enforcement discipline).
- **Acceptance Criteria**: audit entries are queryable by tenant/actor/time; immutability holds under test.
- **Rollback Strategy**: revert code; no dependents yet.
- **Outcome**: complete (retroactively recorded 2026-09-17). `core/audit_log/{service,metadata}.py` implement the append-only store and query interface. 7 test files under `tests/core/audit_log/`.

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
- **Outcome**: complete (retroactively recorded 2026-09-17). `core/api_keys/service.py` implements the key lifecycle; hardened by a recent TOCTOU remediation (see commit history around `81b9516`). 5 test files under `tests/core/api_keys/`.

### 4.2 `core/feature-flags`
- **Objective**: flag definitions, targeting rules, evaluation SDK.
- **Files/Modules Affected**: `core/feature-flags/*`.
- **Dependencies**: 3.1.
- **Tests**: targeting-rule evaluation unit tests; a flag flip is observed by a consuming test client without redeploy.
- **Security Requirements**: flag state changes are audit-logged (via 3.4).
- **Acceptance Criteria**: a flag can be defined, targeted per tenant, and evaluated correctly.
- **Rollback Strategy**: revert code; flags default to a documented safe default on read failure.
- **Outcome**: complete (retroactively recorded 2026-09-17). `core/feature_flags/service.py` implements definitions, targeting, and evaluation. 5 test files under `tests/core/feature_flags/`.

### 4.3 `core/webhooks` (outbound)
- **Objective**: subscription management, delivery, retry, signing.
- **Files/Modules Affected**: `core/webhooks/*`.
- **Dependencies**: 2.4 (`infra/jobs`), 3.1.
- **Tests**: delivery + retry-on-failure integration test against a mock endpoint; signature verification test.
- **Security Requirements**: payload signing key management via `infra/secrets` (2.3); no tenant's webhook secret exposed to another tenant.
- **Acceptance Criteria**: a subscribed webhook receives correctly signed events with retry on transient failure.
- **Rollback Strategy**: revert code; disable delivery via feature flag if a bad deploy causes delivery storms.
- **Outcome**: complete (retroactively recorded 2026-09-17). `core/webhooks/service.py` (~627 lines) implements subscription management, delivery, retry, and signing. 8 test files under `tests/core/webhooks/`.

### 4.4 `core/notifications`
- **Objective**: generic dispatch pipeline (email/SMS/push/in-app), with product-supplied templates deferred to the Product Contract (`docs/ARCHITECTURE.md` §9).
- **Files/Modules Affected**: `core/notifications/*`.
- **Dependencies**: 2.4, 3.1.
- **Tests**: dispatch integration test against a test provider/sandbox for each channel implemented.
- **Security Requirements**: no tenant's notification content or recipient list accessible to another tenant's dispatch path.
- **Acceptance Criteria**: a sample notification dispatches correctly through at least one channel end-to-end in a test environment.
- **Rollback Strategy**: revert code; disable a channel independently via feature flag if a provider integration misbehaves.
- **Outcome**: complete (retroactively recorded 2026-09-17). `core/notifications/service.py` implements the dispatch pipeline. 7 test files under `tests/core/notifications/`.

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
- **Outcome**: complete (retroactively recorded 2026-09-17). `core/billing/{provider,stripe_provider,service}.py` implement the provider-abstraction interface with Stripe as the first adapter, per ADR-0008. 9 test files under `tests/core/billing/`.
- **Audit correction** (2026-10-02, B2B2C billing audit): the acceptance criterion (create, upgrade and cancel a subscription, with entitlements following each state) is met. The objective's "Invoices / Payments as distinct concepts" is not: neither is modelled, and today the provider is the only record of them (ADR-0008 amendment, point 7). Billing work after 5.1 extended this module; see "Phase 5 billing status after 5.2" below.

### 5.2 `core/usage` — metering ingestion and aggregation
- **Objective**: usage-event ingestion interface and aggregation logic feeding billing entitlement checks (`docs/DATA-ARCHITECTURE.md` §6).
- **Files/Modules Affected**: `core/usage/*`.
- **Dependencies**: 5.1.
- **Tests**: ingestion-under-load test (confirms async ingestion doesn't block callers); aggregation correctness test against a known event set.
- **Security Requirements**: ingestion path validates `tenant_id` presence and authenticity, preventing usage-event spoofing across tenants.
- **Acceptance Criteria**: emitted usage events are correctly aggregated and reflected in entitlement/quota checks within a documented latency bound.
- **Rollback Strategy**: revert code; aggregation can be recomputed from raw events if a bug is found in aggregation logic (raw events are the source of truth).
- **Outcome**: complete (retroactively recorded 2026-09-17). `core/usage/service.py` implements ingestion and aggregation. 9 test files under `tests/core/usage/`.
- **Post-implementation audit correction** (2026-10-02, ADR-0037): a re-audit after Reliability & Events found that ingestion accepted non-finite and unbounded quantities (`Infinity` stored in the unconstrained `numeric` column poisons every later sum), `consume_quota_idempotent()` validated no quantity at all (a negative quantity lowered measured usage -- a quota bypass), naive datetimes were interpreted in the database session's timezone, and a single window bound was silently ignored. Every write path now validates the same exact, finite, non-negative, bounded quantity and timezone-aware UTC times; windows are `[since, until)` given together; a malformed recorded event is dead-lettered as permanent. The acceptance criterion's latency bound is documented in ADR-0037. No schema change. Tests: `tests/core/usage/test_usage_metering_integration.py`.

### Phase 5 billing status after 5.2 (B2B2C billing audit, 2026-10-02)

**Authority.** Phase 5 of this roadmap is the only billing roadmap. Two other labels describe billing work and must not be read as roadmap phases:

- **"Architecture research Phase A–J"** (for example "Phase H — Hierarchy-Aware Billing & Usage", cited in `core/billing`, `core/tenancy` and `core/usage` docstrings). These letters come from an external architecture-research plan for universal multi-tenant tenancy. That plan is not in this repository, and its letters are not phases here. Its Phase H work is already implemented and is now frozen legacy; it is not a next or pending billing phase.
- **"Billing Foundation v2 Phase 0–8"** (ADR-0029, and the 2026-10-01 amendment to ADR-0008). These are the internal steps of the commercial-billing design: Phases 0–1 locked the architecture, and Phases 2–3 are implemented. They are work within Phase 5, not top-level roadmap phases.

**Implemented after 5.1, outside the numbered sub-phases:**

- **Legacy hierarchy billing (`inherits_billing`)**, migration `d9da5514672b`. Code docstrings cite it by its research label, which is not a roadmap phase.
  - `Tenant.inherits_billing`, and `resolve_billing_owner()`, which walks to the nearest ancestor that does not inherit and fails closed otherwise.
  - Entitlement reads and the legacy `upgrade_subscription()`/`cancel_subscription()` use the resolved owner's subscription.
  - `aggregate_usage_including_descendants()`.
  - ADR-0029 freezes this as legacy: no new consumers and no changes until Billing Foundation v2 Phase 7 decides how to re-express it.
- **Billing Foundation v2 Phase 2: commercial parties**, migration `6e99825a629c`.
  - Merchant and billing accounts.
  - A payer recorded separately from the service tenant. A sponsored subscription is one tenant paying for another tenant's service; its entitlements stay with the service tenant.
  - Dual authorization through `can()`: `billing.account:charge` on the payer and `billing.subscription:create` on the service tenant.
- **Billing Foundation v2 Phase 3: lifecycle safety**, migration `41e8273a685d`.
  - Provider-confirmed activation, and an allowed-transition lifecycle.
  - At most one live subscription per service tenant and merchant, enforced by the database.
  - Provider idempotency keys, reconciliation and safe cancellation.

**B2B2C capability today** (owner → agency → clients; evidence in `tests/core/billing/test_commercial_parties_integration.py`, `test_billing_hierarchy_integration.py`, `test_lifecycle_integration.py` and `tests/core/usage/test_usage_hierarchy_integration.py`):

| Capability | Status |
|---|---|
| Agency has its own subscription | Implemented |
| Client has its own subscription and pays for it | Implemented |
| Agency pays for a client's subscription (sponsored; entitlements go to the client) | Implemented. Plans can only be the platform merchant's. |
| Siblings with different payers (hybrid) | Implemented by the model. No single test covers the whole scenario. |
| Client shares the agency's own subscription and entitlements | Legacy only (`inherits_billing`, frozen). Each inheriting child is capped separately at the parent's limit; there is no shared pool. |
| Agency sells its own plans to clients (agency as merchant) | Missing (Catalog v2) |
| Payer or payee can see the subscriptions it pays for or sold | Missing. The payer cannot read a sponsored subscription row; the seller projection does not exist. |
| Invoices, payment and provider-event ingestion | Missing (ADR-0008 points 5 and 7) |
| Usage stays with the tenant where it occurred; a move rewrites nothing | Implemented (ADR-0037) |
| Usage roll-up across a subtree | Partial. It is structural and for reporting only; it is not tied to billing relationships and is not used for enforcement. |

**Remaining billing work** (from ADR-0029 and ADR-0008; scoped into 5.3 below except where 5.3 lists it as deferred):

- **Catalog v2:** plan ownership and merchant, visibility, and one shared eligibility predicate. ADR-0022 notes that `list_plans()` is still an unfiltered global listing.
- **Seller and payer read projections.**
- **Provider-event ingestion and asynchronous reconciliation** (Billing Foundation v2 Phase 6).
- **The invoice mirror.**
- **Re-expressing and migrating `inherits_billing`** (Billing Foundation v2 Phase 7).
- **Authority and audit for the legacy billing paths.** `set_tenant_billing_inheritance()` and the legacy `subscribe()`/`upgrade_subscription()`/`cancel_subscription()` are ungated trusted paths, and none of them is assigned to Lifecycle Completion (ADR-0031).
- **Convergence of `BillingActor` with the typed callers** (ADR-0031).
- **Usage policy deferrals:** a provider-neutral billing period, usage retention, and the quota fail-closed rollout (ADR-0029 decision 0.4).

**Roadmap amendment (approved 2026-10-02).** Phase 5.1 is complete (with the correction above), and Phase 5.2 is complete. The next billing sub-phase is **5.3 B2B2C Billing Completion**, below. Its number follows this roadmap's sequential sub-phase convention.

### 5.3 B2B2C Billing Completion — APPROVED, NOT STARTED

- **Objective**: complete the commercial B2B2C model that the platform currently represents only in part. In particular, an agency tenant must be able to act as the merchant of its own catalog to its client tenants. The design authority is ADR-0029; this phase implements it and does not redesign it.
- **Target structure** (example only; SaaS-OS never names "agency" or "client", per ADR-0029 "Explicitly not part of SaaS-OS"):
  ```text
  Platform tenant
      └── Agency A                  (may buy from the platform; may also sell its own plans)
            ├── Client A → Agency A pays
            ├── Client B → Client B pays
            └── Client C → Agency A pays
  ```
- **Concepts kept distinct.** These must never collapse into one "owner" or "payer" field:

  | Concept | Question | Represented by |
  |---|---|---|
  | Subscription ownership | Which tenant owns the subscription record (its RLS owner)? | `Subscription.tenant_id`, the service tenant. ADR-0029 decision 0.1 locks this; changing it requires an ADR amendment. |
  | Billing responsibility | Who is charged? | `BillingAccount.owner_tenant_id`, the payer, recorded as `Subscription.payer_tenant_id`/`billing_account_id` |
  | Merchant / seller | Whose catalog and plan is being sold, and who is paid? | `MerchantAccount.owner_tenant_id`, the payee; the plan's owner and merchant arrive with Catalog v2 |
  | Entitlement recipient | Which tenant receives the service and its limits? | The service tenant. The payer receives nothing by paying (ADR-0029 invariant 7). |
  | Usage ownership | Which tenant owns a usage event? | The tenant where it occurred (`core.usage_events.tenant_id`, ADR-0037). It is never moved or retagged. |
  | Usage aggregation | How may an ancestor or payer total descendant usage? | A derived read-time query over the ledger. It never rewrites history. |

- **Scope:**
  - **A. Catalog ownership.**
    - Plans gain an owner tenant and a merchant (Catalog v2).
    - Existing plans are backfilled to the platform tenant as `public`/`active` (ADR-0029 migration principles).
  - **B. Visibility and eligibility.**
    - Visibility is `public`, `descendants`, `private` or `unlisted`.
    - ADR-0029's single eligibility predicate is shared by listing, checkout and subscription creation.
    - The unfiltered global `list_plans()` listing is replaced or gated (ADR-0022 amendment).
  - **C. Agency selling to clients.**
    - An agency-owned merchant can sell plans to eligible tenants, for example descendants.
    - A client can subscribe to an agency-owned plan.
    - This lifts today's rule that only the platform merchant sells (`MerchantNotEligibleForPlanError`).
  - **D. Service tenant, payer and merchant stay independent.**
    - Both a client-paid and an agency-paid subscription to the same merchant's plan are supported.
    - Creating a subscription keeps the dual authorization of ADR-0029 invariant 6.
  - **E. Billing visibility.** A payer must be able to see the subscriptions it pays for, and a merchant the ones it sold. Today a payer cannot read a sponsored subscription row. This must be met by:
    - a payee-owned projection (`SellerSubscriptionView`) and/or a payer-scoped projection, or by authorized `can()` reads.
    - It must never be met by widening RLS, by `SECURITY DEFINER`, or by arbitrary cross-tenant subscription reads.
  - **F. Entitlement resolution** — define and test which plan applies for each of these cases:
    - self-paid client;
    - agency-paid client;
    - legacy inherited billing;
    - nested agencies;
    - explicit opt-out;
    - canceled payer or parent subscription;
    - tenant movement.

    Binding rules: entitlements follow the service tenant; payment never transfers entitlements; the hierarchy alone never implies payment (ADR-0029).

    The legacy `inherits_billing` mechanism gets no new functionality. Its re-expression as sponsored subscriptions, and the migration path to them, is decided in this phase (the question ADR-0029 left to "Billing Foundation v2 Phase 7"). Until then it remains frozen.
  - **G. Usage.**
    - Usage belongs to the tenant where it occurred.
    - Any roll-up is a derived view or query.
    - A tenant move never rewrites historical usage (ADR-0037).
  - **H. Shared usage pools.**
    - `aggregate_usage_including_descendants()` is a reporting-only structural roll-up. It is **not** a shared billing pool and must not be used as one.
    - If the final model requires pooled allowances, this phase defines them explicitly: who owns the pool, which tenants draw from it, and atomic enforcement under the existing RLS model.
    - Otherwise a pool is recorded as out of scope.
  - **I. Billing lifecycle** — define behaviour for:
    - initial subscription;
    - upgrade and plan change, including plan versions;
    - cancellation by the payer, the merchant or the service tenant;
    - the payer's or parent's subscription disappearing;
    - a child creating its own subscription;
    - tenant movement.

    Every transition must stay within the existing allowed-transition lifecycle (ADR-0029, Billing Foundation v2 Phase 3).
  - **J. Authorization and audit.**
    - Every commercial billing mutation has explicit authorization through `can()` and audit semantics.
    - **Known security gap:** `core.tenancy.set_tenant_billing_inheritance()` has no authorization, no audit and no consent from the parent. A product that exposes it behind a check scoped to the child lets that child take the parent's entitlements.
    - The legacy `subscribe()`/`upgrade_subscription()`/`cancel_subscription()` are ungated trusted paths. Called with a child's id, upgrade and cancel act on the ancestor's subscription.
    - These paths are not declared secure. This phase must gate, audit, replace or retire them.
  - **K. Concurrency** — required scenarios:
    - concurrent subscription creation;
    - concurrent payer changes;
    - concurrent parent and child billing changes;
    - concurrent tenant moves;
    - concurrent entitlement resolution;
    - cancellation during resolution;
    - any inheritance transition the final design retains.
- **Files/Modules Affected**: `core/billing/*`; `core/usage/*` only if H requires it; migrations (additive first, per ADR-0029 migration principles); ADR-0029, ADR-0008 and ADR-0022 status updates.
- **Dependencies**: 5.1, 5.2; ADR-0029 (Accepted).
- **Tests**:
  - an end-to-end B2B2C scenario: platform → agency → clients A, B and C with mixed payers, and the agency selling its own plan;
  - a cross-tenant isolation suite for catalog eligibility and for the payer and seller projections;
  - entitlement-resolution cases F;
  - lifecycle cases I;
  - authorization and audit (J), including negative controls;
  - deterministic concurrency tests (K).
- **Security Requirements**: dedicated security review before merge. RLS is never widened. Knowing a plan id or key never grants eligibility. The payer is never trusted from request input.
- **Acceptance Criteria**: every case in the target structure is representable, enforced and tested, including the agency acting as merchant, and the legacy `inherits_billing` security gap is closed.
- **Rollback Strategy**: additive migrations with backfill. Existing subscriptions are never deleted, and existing `active` rows are not assumed paid (ADR-0029). Prefer forward-fix once live billing exists.
- **Explicitly deferred**:
  - Provider-event ingestion and asynchronous reconciliation (Billing Foundation v2 Phase 6) stay deferred until this phase is complete, unless a later security or reliability review shows they are a prerequisite. The current priority is completing the B2B2C commercial model.
  - The invoice mirror, `BillingActor` convergence and the usage policy deferrals listed above are not in this phase unless pulled in explicitly.

**Sequencing after Phase 5.3** (a recorded decision, not a specification):

```text
5.3 B2B2C Billing Completion
  → B2B2C security and integration audit
  → B2B2C checkpoint
  → SaaS-OS / product auto-update CLI
```

The auto-update CLI is not part of Phase 5. It will be planned separately, and it must preserve the exact-SHA dependency model (ADR-0015 rule 8: consuming projects pin `saas-os` to an exact commit SHA rather than a mutable tag).

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
- **Outcome**: complete (retroactively recorded 2026-09-17), but coverage is comparatively thin. `contracts/{schema,catalog}.py` implement the schema and validator; `contracts/samples/` provides both a valid minimal-product sample and a malformed one, matching the stated Acceptance Criteria. Only one test file exists (`tests/contracts/test_contract_schema.py`), versus the broader multi-file test presence every other Phase 3–8 subphase has. Flagged as a coverage gap, not a functional one — no remediation phase added for it.

---

## Phase 7 — AI Control Plane v0 (Autonomous Development)

**Cross-cutting requirement (`docs/ADR/0013-ai-data-privacy-and-external-model-boundary.md`, Accepted 2026-09-07)**: alongside the Tool Policy mechanism 7.1 builds (`docs/AI-CONTROL-PLANE.md` §2.1, §3), any phase in this group that lets an agent or tool send data to an external AI/LLM provider must also implement the Data Policy / AI data boundary (data classification, minimization, provider-eligibility policy, tenant AI data policy, sensitive-data default-deny — `docs/SECURITY.md` §6.1). No tool in 7.1/7.3 may be registered with unmediated access to an external AI provider ahead of that boundary existing — this is additive to, not separate work from, 7.1's own Security Requirement.
- **Outcome**: complete (retroactively recorded 2026-09-17). `control-plane/control_plane/data_authorization/{models,service}.py` implement the evaluation/authorization/provenance-verification gate (`evaluate_data_authorization`, `authorize_data_access`, `verify_data_authorization_provenance`). Tested in `tests/control_plane/data_authorization/` (unit, integration, provenance integration) and wired into orchestration per `tests/control_plane/orchestration/{test_data_authorization_gate_unit,test_data_authorization_wiring_integration}.py`.

### 7.1 `control-plane/orchestration` — agent runtime and tool registry mechanism
- **Objective**: build the tool registration/invocation/sandboxing mechanism (`docs/AI-CONTROL-PLANE.md` §3), including the scoped secrets-injection path (`docs/AI-CONTROL-PLANE.md` §3 "Tool Secrets Access", `docs/ADR/0012-...`), with zero tools registered yet.
- **Files/Modules Affected**: `control-plane/control_plane/orchestration/*` (corrected 2026-09-17 — the package nests one level deeper than the doc originally stated: `control-plane/` is the repo-root component directory, `control_plane/` beneath it is the actual Python package).
- **Dependencies**: 2.3 (`infra/secrets`), 3.2, 3.3, 3.4 (agent identity, authz, and audit must exist first).
- **Tests**: a stub tool registers, is invoked, and its invocation is denied when the invoking agent identity lacks the required RBAC permission; a stub tool declaring a named secret receives that secret's value in its execution context while the invoking agent's returned output/transcript contains no secret value; an attempt to request a secret not declared by the invoking tool is rejected.
- **Security Requirements**: dedicated security review — this is the enforcement point for ADR-0004 and ADR-0012's AI secrets-access consequence; tests confirming no code path allows a tool invocation to bypass RBAC evaluation, and none allows a tool to access a secret it did not declare, are required, not optional.
- **Acceptance Criteria**: a stub tool can be registered, invoked under permission, and rejected without permission; every invocation (allowed or denied) produces an audit-log entry.
- **Rollback Strategy**: revert code; no real tools exist yet, so no production capability is affected.
- **Outcome**: complete (retroactively recorded 2026-09-17). Note the module lives at `control-plane/control_plane/orchestration/{service,tools}.py` — a directory nested one level deeper than this doc's own `control-plane/orchestration/*` shorthand implies; the code path is correct, the doc's earlier path notation was imprecise. 4 test files under `tests/control_plane/orchestration/`.

### 7.2 `control-plane/approvals` — human approval gate workflow
- **Objective**: implement the tier-1 approval workflow (`docs/AI-CONTROL-PLANE.md` §5) as first-class state, not an out-of-band process.
- **Files/Modules Affected**: `control-plane/control_plane/approvals/*` (path corrected 2026-09-17, see 7.1's note).
- **Dependencies**: 7.1.
- **Tests**: a staged action requires approval before execution; an approval is itself audit-logged with the approving human's identity.
- **Security Requirements**: an approval cannot be self-granted by the same identity that proposed the action (separation-of-duties test).
- **Acceptance Criteria**: full propose → approve → execute cycle works for a stub action; a rejected proposal never executes.
- **Rollback Strategy**: revert code; no live approvals pending at this phase.
- **Outcome**: complete (retroactively recorded 2026-09-17). `control-plane/control_plane/approvals/service.py` implements the propose/approve/execute workflow. 3 test files under `tests/control_plane/approvals/`.

### 7.3 `control-plane/development` — first real tool: development-agent code-change proposal
- **Objective**: build the first real, narrowly scoped tool — an agent that can propose code changes (e.g., open a pull request) against this repository, at tier 1 (propose + human approval via normal PR review, which already satisfies the approval-gate requirement).
- **Files/Modules Affected**: `control-plane/control_plane/development/*`, one new file under `control-plane/control_plane/tools/` (path corrected 2026-09-17, see 7.1's note).
- **Dependencies**: 7.1, 7.2.
- **Tests**: the tool can open a PR in a test/sandbox repository context; it cannot merge or push directly to a protected branch (permission-boundary test).
- **Security Requirements**: agent identity for this tool is scoped to "this repository" only (`docs/AI-CONTROL-PLANE.md` §7); no broader credential is granted.
- **Acceptance Criteria**: agent proposes a change via the normal PR mechanism; normal branch-protection/review rules still apply; every proposal is audit-logged.
- **Rollback Strategy**: disable the tool via the kill-switch mechanism (`docs/AI-CONTROL-PLANE.md` §9) if it misbehaves; proposed-but-unmerged PRs carry no production risk.
- **Outcome**: complete (retroactively recorded 2026-09-17). `control-plane/control_plane/development/github_provider.py` implements the PR-proposal tool. 2 test files under `tests/control_plane/development/`.

---

## Phase 8 — First Real Routes and End-to-End Wiring

### 8.1 Ingress enforcement chain
- **Objective**: wire `core/identity` (auth) and `core/rbac` (authz) as the enforced chokepoint every route passes through (`docs/API-ARCHITECTURE.md` §1–§2), ahead of any real business route being added.
- **Files/Modules Affected**: API ingress layer (new).
- **Dependencies**: 3.2, 3.3.
- **Tests**: an unauthenticated request to a protected route is rejected; an authenticated-but-unauthorized request is rejected; a valid request passes through with correct identity context attached.
- **Security Requirements**: dedicated security review — this is the chokepoint referenced throughout `docs/SECURITY.md`.
- **Acceptance Criteria**: no route can be added that bypasses this middleware (enforced by 1.3's boundary lint, extended to check route registration if feasible).
- **Rollback Strategy**: revert code; no real routes exist to be exposed insecurely yet if this phase is rolled back before 8.2.
- **Outcome**: complete (retroactively recorded 2026-09-17), implemented as a per-route FastAPI dependency chain rather than literal ASGI-level global middleware — `api/dependencies.py` implements `get_current_actor` → `get_tenant_context` → `_enforce_rate_limit_for_route` → `require_permission`, applied to each protected route via `Depends(...)`, not `app.add_middleware(...)`. Every route inspected under 8.2 uses the chain; nothing currently bypasses it, but the enforcement is structural-by-convention (per-route opt-in) rather than structurally impossible to skip (a new route could theoretically omit the dependency). The doc's original phrasing ("enforced middleware") has been corrected above to describe the actual architecture. The rate-limit stage itself is `infra/ratelimit/{__init__,config,errors,limiter}.py` (359 lines; self-documented as this phase's own capability, its module docstring citing this same Phase 8.2 directly) — a Redis-backed fixed-window counter, fail-closed on backend failure (`RateLimitBackendError` is distinct from `RateLimitExceededError` specifically so a Redis outage is never silently treated as "allowed"), tenant/route-agnostic by design (`api/dependencies.py` supplies the scoping key). Backfilled here 2026-09-17 as it was never previously named as its own capability despite `docs/API-ARCHITECTURE.md` §6 and this phase's own Security Requirement bullet already covering it conceptually. Tests: `tests/infra/ratelimit/test_ratelimit_{unit,integration,backend_failure_unit,backend_failure_integration}.py` plus `tests/api/test_ratelimit_dependency_unit.py` and `tests/api/v1/test_ratelimit_failure_integration.py`.

### 8.2 First external API route (health/status only)
- **Objective**: expose a minimal, low-risk external route (e.g., authenticated tenant status) at `/v1/...` to validate the full request path end-to-end, including versioning and OpenAPI documentation (`docs/ADR/0006-api-style-and-versioning.md`).
- **Files/Modules Affected**: one route module; an OpenAPI spec fragment for this route.
- **Dependencies**: 8.1.
- **Tests**: end-to-end test hitting the real route through the real middleware chain; OpenAPI spec validated against the actual response shape.
- **Security Requirements**: rate limiting (`docs/API-ARCHITECTURE.md` §6) active on this route from day one.
- **Acceptance Criteria**: route responds correctly under valid auth, rejects correctly under invalid auth, is served under `/v1/`, and is documented in the OpenAPI spec.
- **Rollback Strategy**: standard deployment rollback (`docs/DEPLOYMENT-ARCHITECTURE.md` §6); this route carries no state-mutation risk.
- **Outcome**: complete (retroactively recorded 2026-09-17). `api/v1/tenant_status.py` implements `GET /v1/tenants/{tenant_id}/status`, read-only, gated by `require_permission` (8.1's chain), returning a typed `TenantStatusResponse` rather than the ORM entity directly. 3 test files including `tests/api/test_tenant_status_integration.py`.

---

## Phase 9 — Self-Learning / Continuous Improvement

**RECOVERED FROM SOURCE — 2026-09-17.** This phase's original specification is not present anywhere in this document's git history (`git log -- docs/IMPLEMENTATION-ROADMAP.md` shows only an initial commit and this session's own sync/recovery commits) and was not found in any other committed file. However, `control-plane/control_plane/self_learning/**/*.py` — a fully implemented, tested subsystem — quotes its own governing specification verbatim throughout its docstrings, roughly 40+ distinct citations of the form "Phase 9.X's own Objective/Scope/Non-Goal/Security Requirement, verbatim." The subphases below were reconstructed by extracting and consolidating those citations. This is a recovery of existing specification text, not new planning — nothing here was invented, and where a template field (e.g. a numeric Acceptance Criteria, a Rollback Strategy) was never quoted anywhere in source, that is stated explicitly as "not recoverable" rather than filled in. Source files: `control-plane/control_plane/self_learning/__init__.py` and each submodule's `__init__.py`/`models.py`/`service.py`/`errors.py`; `control-plane/control_plane/tools/{activate_adaptation,rollback_adaptation}.py`; `docs/ADR/0014-learning-authorization-and-continuous-improvement-boundary.md`; `docs/AI-CONTROL-PLANE.md` §5 (autonomy tiers) and §12 (three learning levels).

Each subphase below carries its recovered specification (Objective/Files-Modules/Dependencies/Tests/Security-or-Non-Goals, as recoverable) followed by a separate **Outcome** bullet describing verified implementation status. These are deliberately not blended: the Outcome bullet states what exists and is tested, and explicitly notes that full re-certification against the recovered criteria has not been independently performed in this documentation pass — only the criteria text itself was recovered, not re-verified line-by-line against every test assertion.

### 9.1 Self-Learning package/schema foundation
- **Objective** (recovered, verbatim): "established package/schema ownership and conceptual documentation only" — `SELF_LEARNING_MARKER`/`SCHEMA_NAME` reserve the package's identity and a future database schema name without creating any table against it.
- **Files/Modules Affected**: `control-plane/control_plane/self_learning/__init__.py`.
- **Dependencies**: not separately recoverable beyond the standing AI Control Plane layering rule ("Layer: AI Control Plane, never SaaS Core... `core` must never acquire a dependency on this package," enforced by the existing Phase 1.3 import-linter contract).
- **Tests**: `tests/control_plane/self_learning/test_self_learning_ownership.py`.
- **Security Requirements**: not separately quoted for 9.1 in isolation — 9.1 has no runtime surface (conceptual/naming only).
- **Non-Goals** (recovered, verbatim, stated as holding "through Phase 9.3" but establishing the 9.1 baseline): "no database migration, no table, no model, no Learning Ledger runtime implementation (still conceptual only)."
- **Acceptance Criteria**: not recoverable verbatim.
- **Outcome**: complete as scoped. `SCHEMA_NAME = "self_learning"` remains a plain string constant, no ORM schema, matching the Non-Goal above.

### 9.2 Learning Authorization (ADR-0014)
- **Objective** (recovered, verbatim): "can this data be retained/reused to shape future behavior, for what purpose, for which tenant, for which model/provider, for how long?" — a third, independent authorization gate distinct from Tool Authorization (ADR-0004) and Data Authorization (ADR-0013). Default is **DENY**.
- **Files/Modules Affected**: `control-plane/control_plane/self_learning/{models,service}.py`.
- **Dependencies**: ADR-0013 (`control_plane.data_authorization` — an already-ALLOW `DataAuthorizationDecision` for the same tenant is a precondition for any ALLOW here).
- **Tests**: `tests/control_plane/self_learning/test_learning_authorization_{unit,integration}.py`.
- **Security Requirements** (recovered, verbatim/near-verbatim): ALLOW reached only after (1) an already-ALLOW `DataAuthorizationDecision` for the same tenant, (2) cross-tenant reuse either not requested or covered by an exactly-matching `CrossTenantLearningPolicy`, and (3) an explicit `TenantLearningPolicy` permitting the request's purpose, model/provider, and retention. `request.evidence` is accepted but never read by any decision branch ("external input is evidence, not trusted policy"). No policy object is persisted. `authorize_learning_use()` records exactly one `core.audit_log` entry per decision (`learning.data_access_approved`/`learning.data_access_denied`). No code path mutates `core.rbac`, `infra.secrets`, or any autonomy-tier policy (ADR-0014 Decision: "Learning Authorization does not grant policy authority").
- **Non-Goals**: same as 9.1 (no migration/table/model).
- **Acceptance Criteria**: not recoverable verbatim as a distinct bullet; the Security Requirements above are the closest recoverable equivalent.
- **Outcome**: complete. `verify_learning_authorization_provenance()` also exists (provenance-verification, same pattern as `control_plane.data_authorization`'s own provenance check).

### 9.3 Evaluation Foundation
- **Objective** (recovered, verbatim): "Baseline -> Benchmark -> Metrics; Candidate -> same Benchmark -> Metrics; Compare -> Pass/Fail, built once here for every learning level (9.4+) to reuse." "Evaluation is evidence."
- **Files/Modules Affected**: `control-plane/control_plane/self_learning/evaluation/{models,service,errors}.py`.
- **Dependencies**: 9.2 (consumes an already-ALLOW `LearningAuthorizationDecision` per subject, never re-derives one).
- **Tests**: `tests/control_plane/self_learning/evaluation/test_evaluation_{unit,integration}.py`.
- **Security Requirements**: no tool invocation, no access to tenant data beyond what the caller already supplied, no RBAC/security/secrets/autonomy-tier authority ("does not grant policy authority," same discipline as 9.2). `run_evaluation()` is the audited entrypoint (`learning.evaluation_run` — recovered, verbatim: "Phase 9.3's own Audit Requirement").
- **Non-Goals** (recovered, verbatim): "no candidate is generated by this package... no autonomous promotion, no deployment."
- **Acceptance Criteria**: not recoverable verbatim; the closest recoverable structural property is the "four-state, never-silently-PASS verdict shape" (`EvaluationOutcome`/`EvaluationInvalidReason`).
- **Outcome**: complete. No database table/migration/model — all dataclasses, immutable (frozen) result/comparison shapes. `verify_evaluation_provenance()` also exists.

### 9.4 L1 Adaptive Learning
- **Objective** (recovered, verbatim, quoting `docs/AI-CONTROL-PLANE.md` §12's L1 row): "versioned, reversible adaptations: prompt/instruction candidates, model selection/routing, tool selection, retrieval/response strategy, permitted personalization, learning from explicit feedback/operator corrections." "Must not: modify source code, database schemas, security policies, authorization, or secrets; deploy infrastructure; bypass approval/policy; access unrestricted tenant data."
- **Files/Modules Affected**: `control-plane/control_plane/self_learning/adaptive/{models,service,errors}.py`; `control-plane/control_plane/tools/{activate_adaptation,rollback_adaptation}.py`.
- **Dependencies**: 9.2, 9.3; Phase 7.2 (`control_plane.approvals` — the tier-1 propose/approve/execute workflow is the only route for activation/rollback).
- **Tests**: `tests/control_plane/self_learning/adaptive/test_adaptive_{unit,integration}.py`.
- **Security Requirements**: `AdaptationSurface` is an explicit, typed allowlist with no member for security policy, RBAC, secrets policy, autonomy-tier policy, tenant-isolation policy, or audit policy — an adaptation targeting any of those is structurally impossible to construct, not merely runtime-rejected.
- **Non-Goals**: L2/L3/experimentation/policy-gate/continuous-loop (9.5–9.9, not built here).
- **Acceptance Criteria**: not recoverable verbatim.
- **Outcome**: complete. `Adaptation` (`self_learning.adaptations`) is the first table ever created in the schema 9.1 reserved — tenant-owned, RLS-protected.

### 9.5 L2 System Learning
- **Objective** (recovered, verbatim): "discover recurring problems (agent/tool failures, support/latency/cost/routing/workflow problems, missing regression tests, recurring policy violations, operational failures) and produce structured, evidence-backed improvement **proposals** — never an arbitrary production modification."
- **Files/Modules Affected**: `control-plane/control_plane/self_learning/system_learning/{models,service,errors}.py`.
- **Dependencies**: 9.2; Phase 3.4 (`core.audit_log`'s existing `list()` query interface — recurring-failure evidence is read through it, never a second observation store).
- **Tests**: `tests/control_plane/self_learning/system_learning/test_system_learning_{unit,integration}.py`.
- **Security Requirements** / **Non-Goals** (recovered, verbatim): "a proposal is data, never auto-applied by this phase." No path deploys, promotes, activates a production change, modifies RBAC/authorization/security/secrets/autonomy-tier policy, alters infrastructure, modifies source code, executes an unrestricted shell/database command, or bypasses Data Authorization, Learning Authorization, Evaluation, or approvals. `ProposedChangeTarget` is a closed, typed vocabulary with no member for any of those — structurally impossible to construct, same discipline as 9.4.
- **Files/Modules Affected note** (recovered, verbatim, explaining no persistence): "Phase 9.5's own Files/Modules Affected names only `control-plane/self-learning/system-learning/*`" — no migration, no table.
- **Acceptance Criteria**: not recoverable verbatim.
- **Outcome**: complete. Every `SystemLearningProposal` is an immutable in-memory dataclass; proposal creation/state changes recorded through `core.audit_log` (`learning.proposal_created`/`learning.proposal_state_changed`).

### 9.6 Experimentation (L1/L2)
- **Objective** (recovered, verbatim): let an authorized adaptation candidate (9.4) or system-learning proposal (9.5) run as "an **isolated experiment, evaluated (Phase 9.3) against a baseline, with zero production-binding effect**."
- **Files/Modules Affected**: `control-plane/control_plane/self_learning/experiments/{models,service,errors}.py`.
- **Dependencies**: 9.2, 9.3, and either 9.4 or 9.5 as the candidate's provenance source.
- **Tests**: `tests/control_plane/self_learning/experiments/test_experiments_{unit,integration}.py`.
- **Security Requirements** (recovered, verbatim, "Tenant-Isolation Requirement"): "experiment records/results are RLS-protected exactly like every other tenant-owned table" — reuses `infra.db.rls.tenant_rls_statements()`. No path deploys, promotes, activates a production change, modifies RBAC/security/secrets/autonomy-tier policy, alters infrastructure/source code, executes an unrestricted shell/database command, or bypasses Data Authorization, Learning Authorization, or Evaluation.
- **Non-Goals** (recovered, verbatim, "Scope, this phase"): "no canary, no autonomous deployment."
- **Acceptance Criteria**: not recoverable verbatim.
- **Outcome**: complete. `Experiment` (`self_learning.experiments`) is tenant-owned, RLS-protected; creation/execution/result-recording/cancellation each recorded through `core.audit_log`.

### 9.7 Autonomy & Policy Gate
- **Objective** (recovered, verbatim): "the boundary every self-learning candidate must pass before any bounded autonomous action (Phase 9.8) is permitted," reusing `docs/AI-CONTROL-PLANE.md` §5's existing autonomy-tier vocabulary (tiers 0–3) rather than inventing a parallel model. Architectural principle (recovered, verbatim): "Tool Authorization -> Data Authorization -> Learning Authorization -> Autonomy/Policy Gate -> Permitted Action." Default is **DENY**.
- **Files/Modules Affected**: `control-plane/control_plane/self_learning/policy_gate/{models,service}.py`.
- **Dependencies**: 9.2 through 9.6, each consumed only as an already-authoritative typed input, never re-derived or re-scored.
- **Tests**: `tests/control_plane/self_learning/policy_gate/test_policy_gate_{unit,integration}.py`.
- **Non-Goals** (recovered, verbatim, "Scope, this phase"): "the gate mechanism itself (policy evaluation + approval-state composition), not any specific promotion decision" — never activates an `Adaptation`, applies a `SystemLearningProposal`, or promotes an `Experiment`. Tier 3 (fully autonomous) is refused unconditionally, not merely omitted from the vocabulary.
- **Security Requirements / Audit Requirement** (recovered, verbatim): `evaluate_and_record_policy_gate_decision()` is the audited entrypoint (`learning.policy_gate_decision` — "this phase's own Audit Requirement").
- **Acceptance Criteria**: not recoverable verbatim.
- **Outcome**: complete. `verify_policy_gate_provenance()` also exists. This is the module `control-plane/control_plane/self_learning/policy_gate/service.py` — the same module recorded in this session's earlier CP-03 canary-authorization remediation (commit `a477f0b`).

### 9.8 L3 Autonomous Improvement (Canary)
- **Objective** (recovered, verbatim): "bounded autonomous improvement through Experiment -> Policy Gate -> Canary -> Monitoring -> Promote OR Rollback." Explicitly "bounded autonomy, not unrestricted self-modification."
- **Files/Modules Affected**: `control-plane/control_plane/self_learning/autonomous_improvement/{models,service,errors}.py`.
- **Dependencies**: 9.4 (`Adaptation`), 9.6 (`Experiment`), 9.7 (`PolicyGateDecision`) — each consumed only as an already-authoritative typed input.
- **Tests**: `tests/control_plane/self_learning/autonomous_improvement/test_autonomous_improvement_{unit,integration}.py`.
- **Non-Goals** (recovered, verbatim): "no tier-3 (fully autonomous, no standing checkpoint) capability — canary + monitoring + promote/rollback is tier 2 at most." `create_canary()` independently refuses any `PolicyGateDecision` not carrying `requested_autonomy_tier == 2`. No path activates, mutates, or promotes a `SystemLearningProposal` (9.5's own binding Non-Goal: "no automatic application of a proposal to production").
- **Security Requirements** (recovered, verbatim, "Scope, this phase"): "a canary is a scoped, monitored, reversible partial rollout, never a direct full-production change" — "scoped" is structurally exactly one tenant (`Adaptation` has no platform-wide/multi-tenant activation mechanism, so this package implements none either).
- **Acceptance Criteria**: not recoverable verbatim.
- **Outcome**: complete. `Canary` (`self_learning.canaries`) is tenant-owned, RLS-protected.

### 9.9 Continuous Improvement Loop
- **Objective** (recovered, verbatim): "an Outcome from 9.8 (or a Level 1/2 adaptation/proposal) becomes a new Observation" — closes the loop by turning an already-terminal outcome into a new observation, seeding the next cycle.
- **Files/Modules Affected**: `control-plane/control_plane/self_learning/continuous_loop/{models,service}.py`.
- **Dependencies**: 9.4, 9.8 (reads already-terminal, already-authorized `Adaptation`/`Canary` rows only).
- **Tests**: `tests/control_plane/self_learning/continuous_loop/test_continuous_loop_{unit,integration}.py`.
- **Non-Goals** (recovered, verbatim, "Scope"): "scheduling/orchestration of the existing pipeline ... not a new learning mechanism." Never proposes, evaluates, gates, activates, or promotes anything itself — zero mutations.
- **Security Requirements** (recovered, verbatim, "Kill switch"): reuses `core.feature_flags.evaluate_flag()`, "not a second disable mechanism" — default-deny, a tenant with no flag override never runs a cycle. No new scheduler is introduced — `infra/jobs` itself is not modified; `trigger_continuous_learning_cycle()`/`CONTINUOUS_LOOP_JOB_FUNCTIONS` is the `infra.jobs`-backed recurring entrypoint.
- **Acceptance Criteria**: not recoverable verbatim.
- **Outcome**: complete. Autonomy tier remains capped at 2 — this package never calls `policy_gate`, `activate_adaptation()`, `start_canary()`, or `promote_canary()`.

**Certification caveat (applies to all of 9.1–9.9)**: this recovery pass extracted and consolidated the specification text already quoted in source; it did not independently re-run or re-derive each subphase's tests against the recovered criteria line-by-line. Code and tests are present and substantial (roughly 5,488 implementation lines against roughly 8,551 test lines across the subsystem, tests exceeding implementation) and the autonomy-tier/gate-ordering model matches `docs/AI-CONTROL-PLANE.md` §5/§12 exactly. This should be read as "implemented and tested; not independently re-certified against the now-recovered acceptance criteria in this pass" — not as a production-readiness claim.

---

## Phase 9+ — Remaining Deferred Items

The following remain future, undefined phases, deliberately not broken down further until the phases above are complete and their learnings can inform sequencing: autonomous customer support agent (tier 0/1), autonomous incident-resolution agent (tier 1, narrow tier-2 promotions only after audit trail is proven per `docs/AI-CONTROL-PLANE.md` §6), and autonomous DevOps agent (tier 1 only, last to receive any tier-2 promotion). Each will receive the same phase template treatment when planned. Each would consume the generic primitives Phase 7 and Phase 9 above already built (`control_plane.orchestration`/`approvals`/`self_learning`); the ticket/incident/deployment-state domain models themselves, if and when built, are Product-layer concerns (see below), not SaaS-OS platform scope.

**Dograh framing corrected 2026-09-17.** This paragraph previously read "Dograh onboarding as the first real Product-layer consumer" as if it were a phase of this repository's own roadmap. Per ADR-0015 (Accepted 2026-09-10, binding), that framing is now factually incorrect: real business-domain projects — Dograh included — "must never be added to this repository, under `products/`, under any other name, or in any other location" (ADR-0015 rule 12); a consuming project lives in its own separate repository and depends on `saas-os` as a versioned package (ADR-0015 rules 2–4, 6). `products/` remains in this repository only as an empty placeholder / import-linter boundary target (ADR-0015's Implementation Note: excluded from the shipped package, kept in `root_packages` for lint purposes only) — it is not, and per ADR-0015 rule 11 is explicitly not, "part of the conceptual SaaS OS consumer architecture." Dograh onboarding is therefore not a next SaaS-OS implementation phase at all; it is out of this repository's scope by binding architectural decision, not merely deferred.

---

## Cross-Cutting Rules for Every Phase

- No phase merges without its listed tests passing in CI (Phase 1.4's pipeline).
- No phase touching tenant data (any Phase 3+ ) merges without the cross-tenant isolation test suite established in 3.1 passing against the new code.
- No phase introducing an AI Control Plane tool merges without an audit-logging test (per 7.1) and an explicit autonomy tier declaration (`docs/AI-CONTROL-PLANE.md` §5).
- No phase introduces a new secret-consuming call site outside the `SecretsProvider` interface (`docs/ADR/0012-...`) — any direct environment-variable read for secret material, or any direct call to a specific secrets-management product's SDK from outside `infra/secrets`, is a merge-blocking defect.
- Every phase's rollback strategy must be validated (not just described) before that phase is considered production-ready, per `docs/DEPLOYMENT-ARCHITECTURE.md` §6.
