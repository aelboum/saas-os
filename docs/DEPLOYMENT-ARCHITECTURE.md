# Deployment Architecture

Status: ACCEPTED. Target platform finalized per `docs/ADR/0010-deployment-target.md`: Docker + Docker Compose + VPS.

## 1. Deployment Unit Strategy

- **Modular monolith, initially.** The platform ships as a small number of deployable units (likely one, possibly split along Core/Control-Plane if operational reasons emerge) rather than many independently deployed microservices, per `docs/ARCHITECTURE-DISCOVERY.md` §16.
- This is deliberately decoupled from the *code* boundary: the four layers (`docs/ARCHITECTURE.md` §1–§2) are enforced as internal module boundaries regardless of how many physical deployables they compile into. Splitting a module into its own service later is a deployment-topology change, not a rewrite, precisely because the code boundary already exists.
- Each Product may be its own deployable unit (especially its frontend) even while Core/Infra/Control-Plane ship as one unit — Product deployability is declared per-product in its contract (`deploymentRequirements`, `docs/ARCHITECTURE.md` §9).

## 2. Environments and Promotion

- Standard promotion path: local/dev → staging → production. No environment skips the pipeline gates defined in §5.
- Each environment is a fully isolated deployment (its own database, its own secrets) — no environment shares tenant data with another, including staging never containing real tenant data unless explicitly and narrowly seeded for testing.

## 3. Configuration Ownership

- `infra/deploy` owns the *mechanism* of supplying configuration to a running deployment (env injection, config service, etc.).
- Each module (Core, Control Plane, each Product) owns the *schema* of configuration it requires and must declare it explicitly rather than reading ambient environment state implicitly — for Products, this is the contract's `environmentVariables` field (`docs/ARCHITECTURE.md` §9).
- Configuration values differ per environment; configuration *schema* (what keys must exist) does not — a missing required key should fail deployment validation before runtime, not surface as a null-pointer failure in production.

## 4. Secrets in Deployment (Accepted)

Per `docs/ADR/0012-secrets-management.md`:

- Secrets are supplied to running deployments via `infra/secrets`'s `SecretsProvider` interface (`docs/SECURITY.md` §4), never baked into build artifacts (no Docker image layer ever contains a real secret value) and never committed to configuration files (a committed `docker-compose.yml` may reference where a secret comes from — an env var name, a `secrets:` file path — but never the value).
- **Initial production implementation**: secrets are injected into the container's runtime environment at start-up on the VPS — as environment variables or as files mounted via Docker Compose's `secrets:` mechanism — sourced from the host (a restricted-permission location outside the repository) or the CI/CD deploy step, never from the image or the repository.
- Local development uses `infra/secrets`'s development implementation (`.env`, gitignored, `.env.example` documents required variables without real values — `docs/SECURITY.md` §4).
- This is deployment-target-specific by necessity (it's the one place the Compose/VPS target is directly visible to secret handling), but is implemented behind the same `SecretsProvider` interface every other environment and every calling module uses — a future Kubernetes or managed-platform target (`docs/ADR/0010-...` §Future Migration) or a future external secrets manager (Vault, cloud KMS) adds a new implementation of this interface without changing calling code.
- Secret rotation must not require a full redeploy where avoidable (design constraint for `infra/secrets` and `infra/deploy` to jointly satisfy, not yet implemented).

## 5. CI/CD Pipeline Stages (Directional)

1. Lint + module-boundary check (`docs/ARCHITECTURE.md` §8) — fails fast on any disallowed cross-layer import.
2. Unit + integration tests, per module.
3. Security scan (dependency + secret scanning, `docs/SECURITY.md` §10).
4. Build artifact (a Docker image, per §8).
5. Deploy to staging (via `infra/deploy`'s deployment-target interface, §8); automated smoke test against health checks (§7).
6. Manual or policy-gated promotion to production (gate criteria to be defined per-phase in the roadmap).
7. Post-deploy health verification; automatic rollback trigger on failure (§6).

## 6. Rollback Boundaries

- **Every deployment must have a defined, tested rollback path before it is considered production-ready** — this is a release-process requirement, not optional tooling.
- Rollback operates at the deployment-unit level: rolling back a build does not, by itself, roll back a database migration (`docs/DATA-ARCHITECTURE.md` §2) — migrations must be designed to be backward-compatible with the previous code version for at least one release cycle (expand/contract pattern), so a code rollback never leaves the database in a state the old code can't handle.
- Rollback of an AI-Control-Plane-initiated infrastructure change (§ Autonomous DevOps, `docs/AI-CONTROL-PLANE.md`) follows the same mechanism as a human-initiated change — the Control Plane does not get a separate, less-tested rollback path.
- Ownership: `infra/deploy` owns the rollback *mechanism*; each module owns ensuring its own migrations/changes are rollback-safe.

## 7. Health Checks

- `infra/health` owns the generic liveness/readiness endpoint mechanism and dependency-health aggregation (DB reachable, queue reachable, etc.).
- Each module (Core, each Product) contributes its own health signal (e.g., "billing provider reachable," declared per-product via the contract's `healthChecks` field) rather than Infra guessing what "healthy" means for a module it doesn't understand.

## 8. Deployment Target (Accepted)

Per `docs/ADR/0010-deployment-target.md`: **Docker containers, orchestrated with Docker Compose, running on a single VPS.** Kubernetes is explicitly not implemented at this stage.

To keep this reversible, `infra/deploy` exposes a **deployment-target interface** — build image, push/publish, deploy, health-check (§7), roll back (§6) — implemented first for Docker Compose + VPS. CI/CD stages 1–4 (§5) are deployment-target-agnostic by construction and must not encode Compose- or VPS-specific assumptions (e.g., a hardcoded single-host filesystem path), so that a future Kubernetes or managed-platform implementation of the same interface can be added without changing those stages or any application code. This interface boundary is a binding design constraint on `infra/deploy`, not an aspiration.

## 9. AI Control Plane and Deployment

Autonomous DevOps capability (`docs/AI-CONTROL-PLANE.md`) interacts with deployment exclusively through declared tools that wrap this pipeline's own gates (§5) and rollback mechanism (§6) — it does not get a shortcut path that skips staging verification or the rollback safety net, regardless of autonomy level.

## 10. What Is Hard to Change Later

Nothing in this document is strictly irreversible if the module-boundary discipline (`docs/ARCHITECTURE.md` §2, §8) holds — a modular monolith with real internal boundaries can be split into services later without a rewrite. The boundary discipline is the load-bearing decision; the specific deploy target is not.

## 11. Production Network Perimeter (P2.3, Accepted)

Closes the readiness-audit blocker: *"PostgreSQL/Redis are published on all interfaces and there is no production TLS/reverse-proxy boundary."* Implemented as a standalone `docker-compose.prod.yml` — the development `docker-compose.yml` is untouched and remains the local workflow (`docker compose up`).

**Topology**:

```
INTERNET
   │
 :80 / :443
   │
 proxy (Caddy) ── edge ── frontend
   │
   └── edge ── backend ── internal ── postgres
                        └─ internal ── redis
worker ── internal ── postgres, redis
```

Two Docker networks: `edge` (proxy, frontend, backend) and `internal` (backend, worker, postgres, redis; `internal: true`, no outbound Internet route). Only `backend` is dual-homed. PostgreSQL, Redis, and the worker never join `edge` and publish no host port — reachability is a structural property of network membership, not a documented intention.

**Required public ports** (host firewall must allow):

```
22/tcp   SSH   — restricted to an operator's known source, not this repository's concern
80/tcp   HTTP  — ACME challenge + redirect to HTTPS
443/tcp  HTTPS — the application
```

**Required firewall-blocked ports** (this repository never publishes them in `docker-compose.prod.yml`; the *host* firewall is still the operator's responsibility — no deployment mechanism in this repository owns it, so no automation is added):

```
5432/tcp  PostgreSQL
6379/tcp  Redis
8000/tcp  backend
3000/tcp  frontend
```

Removing host publication entirely (rather than binding one interface) means neither IPv4 nor IPv6 host exposure exists for PostgreSQL/Redis — there is no address family left to reason about.

**TLS**: Caddy (`Caddyfile`, repo root) terminates HTTPS for `PUBLIC_DOMAIN` (a required, deployment-specific, non-secret env var — never a real domain committed here), with automatic ACME certificate issuance/renewal, `tls1.2`/`tls1.3` only, and an automatic HTTP→HTTPS redirect. Certificate/account state persists in the named volumes `caddy-data`/`caddy-config` — never ephemeral container storage, never committed. **DNS**: the operator must point `PUBLIC_DOMAIN` at the VPS before Caddy can obtain a real certificate; this repository cannot do that for them.

This TLS termination is the external HTTP perimeter only — it says nothing about the PostgreSQL/Redis transport between `backend`/`worker` and `db`/`redis` on the `internal` network. That connection's own transport-encryption posture (an application-side, fail-closed `sslmode`/`rediss://` requirement in `infra/db/config.py`/`infra/jobs/config.py`/`infra/ratelimit/config.py`, required and not disabled by this compose file, additive to the network isolation documented above) is `docs/ADR/0021-database-redis-transport-encryption.md`'s own scope, not this section's — including that ADR's own documented residual limitation that this compose file's stock `db`/`redis` images ship with no TLS certificate, so `backend`/`worker` will not become healthy against them until an operator supplies TLS-capable `DATABASE_URL`/`REDIS_URL` endpoints.

**Three distinct kinds of infrastructure are involved here, and conflating them is how a validation run ends up claiming more than it proved:**

1. **Shipped/reference application Compose infrastructure** — `docker-compose.prod.yml`'s own `db`/`redis` services. These are stock `postgres:16-alpine`/`redis:7-alpine` with **no TLS material**; their security control is the network isolation documented above, not transport encryption. They are the right subject for topology and perimeter validation (`scripts/check-docker-prod.sh`) and they are **not** production TLS services.
2. **Operator-provided production stateful infrastructure** — what a real deployment must supply: TLS-capable `DATABASE_URL`/`REDIS_URL` endpoints (a managed database/cache, or an operator-provisioned certificate on these same containers). Provisioning that material is an operational responsibility this repository deliberately does not take on (`docs/ADR/0021-database-redis-transport-encryption.md`).
3. **Disposable full-production validation infrastructure** — a per-run, TLS-capable PostgreSQL and Redis used only to exercise the application's production TLS boundary end to end (`scripts/check-docker-prod-tls.sh`). It is never shipped, never part of this compose file, and is not a deployment recommendation. See `docs/ADR/0027-production-validation-tls-infrastructure.md`.

**Which of the three a production deployment uses is now decided** (`docs/ADR/0028-production-stateful-service-ownership-and-tls-trust.md`): kind 2. Production PostgreSQL and Redis are operator-managed external TLS endpoints, addressed purely by `DATABASE_URL`/`MIGRATIONS_DATABASE_URL`/`REDIS_URL`; the bundled `db`/`redis` are local/development convenience services, not production dependencies. The Compose wiring is implemented: `db`/`redis` carry `profiles: ["bundled-stateful"]` and no service declares `depends_on` on them, so a production `up` starts neither and `backend`/`worker` reach the operator's endpoints by URL alone. `scripts/check-docker-prod.sh` still starts them explicitly by name to validate the reference perimeter. What remains unwritten is the operator runbook; a deployment that supplies no external endpoints still cannot produce a healthy `backend`/`worker`, which is now a configuration error rather than a missing-TLS one. Certificate issuance, distribution and rotation for those endpoints are operator responsibilities; SaaS-OS neither provisions nor rotates them. PostgreSQL `verify-full` works today with no code change (`sslmode`/`sslrootcert` pass through untouched) while the injected default stays `require`; Redis verifies the certificate chain but performs **no hostname verification** and exposes no CA configuration surface. Backups reach an external database through `infra/db/backup`'s endpoint transport (ADR-0028 D4-B): `create_backup()`/`restore_backup()` run `pg_dump`/`pg_restore` directly against the configured endpoint when no `container=` is given, forwarding that configuration's own TLS settings unchanged. The bundled database keeps the original `docker exec` transport. The operator responsibility this adds is small but real: the PostgreSQL client binaries must be present on whatever host executes backups — they are deliberately not a repository dependency, since the container transport needs none.

**Routing**: `/auth/*` and `/v1/*` (the backend's actual external surface, `api/main.py`) go to `backend:8000`; everything else goes to `frontend:3000`. `/healthz`/`/readyz` are deliberately not proxied externally (no documented need for Internet reachability) and fall through to the frontend's own 404, rather than leaking readiness detail to an external prober.

**CORS**: not configured, deliberately — the proxy serves frontend and backend from one origin (`PUBLIC_DOMAIN`), so no cross-origin request exists for the browser to need CORS headers for. No `Access-Control-Allow-Origin` is ever returned; there is no wildcard-plus-credentials configuration surface to misconfigure because none exists.

**Forwarded-header trust**: `TRUST_PROXY_HEADERS=true` (set only on `backend` in `docker-compose.prod.yml`) makes the pre-login rate limiter (`api/auth/routes.py::_resolve_client_address`) read the client address from `X-Forwarded-For` — and only ever the *last* comma-separated entry, the one hop Caddy itself appended and could not have been forged by the client, since network segmentation guarantees a request can only reach `backend` through `proxy`. `X-Forwarded-Proto`/`X-Forwarded-Host` are not read anywhere in this codebase; cookie `Secure` and redirect generation are driven by static configuration (`AuthHttpConfig`), never per-request scheme headers, so there is nothing there for a forwarded header to spoof.

**Security headers** (set by Caddy): `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`. No CSP is set — the frontend is an unstyled foundation page with no inline-script inventory to build a real policy against yet; a guessed policy would likely break the first real page.

**What this phase does not solve** (unchanged from the readiness audit, remain separate phases): off-site backups, RPO/RTO, Redis durable queue persistence, `detect-secrets` baseline remediation, platform administration/tenant-provisioning UI. Live ACME/DNS certificate issuance requires a real, DNS-resolvable domain and is not exercised by this repository's own automated validation (`scripts/check-docker-prod.sh` uses `PUBLIC_DOMAIN=localhost`, which deterministically exercises Caddy's internal, self-signed CA instead).

## 11a. Production Self-Hosted Identity (ADR-0023 Phase 3)

Extends §11's topology with a self-hosted ZITADEL, structurally isolated from every SaaS-OS service that has no legitimate reason to reach it -- network membership is the enforcement mechanism (§11's own "not merely a documented intention" principle), not credentials.

**Topology**:

```
INTERNET
   │
 :80 / :443
   │
 proxy (Caddy)
   ├── edge ── frontend
   ├── edge ── backend ── internal ── postgres, redis
   ├── identity-edge ── backend ── (never identity-db)
   └── identity-edge ── zitadel ── identity-db ── zitadel-db

worker ── internal ── postgres, redis   (no identity network membership)
zitadel-bootstrap ── identity-edge only (one-shot, never restart-managed)
```

Two additional Docker networks, both `internal: true`: `identity-edge` (proxy, backend, zitadel, zitadel-bootstrap) and `identity-db` (zitadel, zitadel-db only). `backend` is a member of `identity-edge` but deliberately **not** `identity-db` -- it needs ZITADEL's OIDC endpoints (discovery/JWKS/token exchange), never ZITADEL's own database. `worker` and `frontend` are members of neither identity network -- they have no legitimate reason to reach ZITADEL or its database, and cannot (structurally, not by convention).

**ZITADEL itself publishes no host port**, in any environment -- reachable only through Caddy (the browser's OIDC authorization-redirect leg) and directly over `identity-edge` (backend's/`zitadel-bootstrap`'s server-side calls).

**Same-domain identity strategy** (docs/ADR/0023-... §9, corrected in Phase 3; profile-specific since docs/ADR/0025-same-origin-zitadel-login-v2-topology.md §1a): ZITADEL has no supported arbitrary path-prefix deployment model (verified against its own official reverse-proxy documentation), so it is always routed at the root of its own public domain, `IDENTITY_PUBLIC_DOMAIN` (unmodified paths, matching ZITADEL's own documented shape). Which domain that is depends on the identity deployment profile (`IDENTITY_PROFILE`):

- **Fresh profile** (`fresh`): `IDENTITY_PUBLIC_DOMAIN` equals `PUBLIC_DOMAIN`. ZITADEL's documented routes (including `/auth/v1/*`, matched ahead of SaaS-OS `/auth/*`) and ZITADEL Login V2 at `/ui/v2/login` (the `zitadel-login` service) share the product's own Caddy site with SaaS-OS; the OIDC issuer and the passkey/U2F RP ID are `PUBLIC_DOMAIN`.
- **Existing profile** (`existing`, the default): `IDENTITY_PUBLIC_DOMAIN` is a separate, operator-controlled **subdomain** of the same registrable domain as `PUBLIC_DOMAIN` (e.g. `id.` + `PUBLIC_DOMAIN`'s own domain) -- never a third-party or ZITADEL-branded hostname -- fronted by its own Caddy site block. Existing deployments keep this identity-domain topology, their issuer and their RP ID; Login V2 is served there at `/ui/v2/login` when enabled (`ZITADEL_LOGIN_V2_ENABLED`).

No deployment is migrated between profiles: `identity-profile-guard` (`deploy/check-identity-profile.sh`) refuses to start on a profile or domain change. In both profiles the OIDC callback is `PUBLIC_APP_ORIGIN` + `/auth/callback` on the application origin (`docker-compose.prod.yml` sets `PUBLIC_APP_ORIGIN` to `https://${PUBLIC_DOMAIN}`; docs/ADR/0024-single-origin-application-runtime.md); the profile only decides whether ZITADEL shares that origin.

**Backend → ZITADEL, without hairpinning through Caddy**: `backend`/`zitadel-bootstrap` reach `https://<IDENTITY_PUBLIC_DOMAIN>` directly over `identity-edge`, resolved by a Docker network alias on the `zitadel` service itself (`docker-compose.prod.yml`) equal to `IDENTITY_PUBLIC_DOMAIN` -- the same mechanism Phase 1's local `zitadel.localhost` alias already used, just with the production hostname. Because the exact same URL is also what the browser uses (through Caddy), whatever answers on that alias must actually terminate TLS, not merely claim to over a plaintext connection -- ZITADEL terminates its own TLS for this internal-facing listener with a self-signed certificate (`identity-tls-init`, a one-shot service generating it once, idempotent across restarts), matching ZITADEL's own documented "enabled-tls" reverse-proxy pattern. Caddy trusts it via `tls_insecure_skip_verify` in the existing profile (ZITADEL's own documented pattern for exactly this) and verifies it against that same certificate (the `identity-ca` volume) in the fresh profile; `backend`/`zitadel-bootstrap` trust it via the standard `SSL_CERT_FILE` environment variable, which both `httpx`'s and `urllib.request`'s default TLS verification already honor -- verified empirically against the pinned ZITADEL v4.19.0 image, so no `core/identity` or `local-dev` code needed any change for this to work.

**Bootstrap**: reuses Phase 1's exact mechanism (FirstInstance + machine PAT + Management-API list-before-create, `local-dev/bootstrap_zitadel.py`, unmodified) through a thin production entrypoint (`deploy/bootstrap_zitadel_production.py`) that imports and calls that same script's functions directly -- not a second provisioning system. One-shot, never restart-managed; the Management-API-capable PAT never leaves the `zitadel`↔`zitadel-bootstrap` shared volume and is never given to `backend`.

**Database**: `zitadel-db`, a dedicated PostgreSQL container, `identity-db`-only, no host port, own volume/credentials -- structurally separate from the SaaS-OS `db` service (own volume `zitadel-db-data-prod`, distinct from `db-data-prod`). ZITADEL manages its own schema/migrations independently of SaaS-OS's own Alembic history (ADR-0023 S5) -- there is no code path, in either direction, that could couple them.

**Backup**: `infra/db/backup/orchestrator.py`'s existing pipeline, extended additively (`--admin-database-url-var`, reads a variable *name* through `SecretsProvider`, never a raw connection string as a CLI argument) rather than duplicated -- see docs/BACKUP-RESTORE.md's own identity section. A separate systemd timer (`deploy/saas-os-zitadel-backup.{service,timer}`), offset from the main SaaS backup's own schedule.

**Health/readiness**: unchanged mechanism from Phase 1 (`/app/zitadel ready`, verified empirically to also work correctly under this TLS-enabled production configuration). Caddy's own `identity-edge` site block adds an active upstream health check (`health_uri /debug/ready`) against ZITADEL, so a request is failed closed (502/503) rather than proxied to a ZITADEL instance that is alive but not ready (e.g. its own database unreachable) -- verified empirically: stopping `zitadel` makes `https://<IDENTITY_PUBLIC_DOMAIN>/...` return 503 through Caddy, while existing SaaS-OS sessions and `/auth/me` remain entirely unaffected (`core/identity/sessions.py` never calls the provider), and `backend`'s own startup remains independent of ZITADEL's readiness (Phase 2's lazy OIDC discovery, unchanged).

## 12. Hardening Track Identifier Glossary

Recorded 2026-09-17 following a read-only documentation audit. Code, tests, and this document itself cite a dotted `P1.x`/`P2.x` identifier scheme (e.g. `P2.3` in §11's own heading above) that has no canonical index anywhere in `docs/`. This section is that index. It is a documentation-clarity fix only — no identifier is renamed, renumbered, or merged into another numbering system by this entry.

**This dotted track is independent of two other numbering systems in this repository, despite superficial notation overlap:**

- **`docs/IMPLEMENTATION-ROADMAP.md` `Phase N.M`** — the platform's main implementation roadmap. Collision warning: roadmap `Phase 2.3` (`infra/secrets`) and hardening-track `P2.3` (production network perimeter, this document's §11) are **unrelated identifiers that happen to look alike** — they describe different capabilities and must not be conflated.
- **`PRIV-03` `Phase P1`…`P13`+ / the `RA-01`…`RA-12` privacy re-audit series** — a separate privacy/security initiative (tenant purge, lifecycle fencing, retention, support-access restrictions; see `core/tenancy/*`, `core/rbac/service.py`, `control-plane/control_plane/orchestration/service.py` for its in-code citations). Its `P`-prefixed phase numbers use no dot (`P8`, `P13`) versus this track's dotted form (`P1.3`, `P2.4`) — a real but easily-missed distinguishing detail. This glossary does not index `PRIV-03`/RA-series; that remains tracked separately.

**Provenance**: every dotted identifier below already existed at this repository's `Initial commit` (`0f41ea3`, 2026-09-09) with no subsequent `git log -S` introduction found for any of them. This repository's history does not extend further back — provenance predating `0f41ea3` is not recoverable from this repository and is not reconstructed here.

**Consistency**: each identifier below has one stable, internally consistent meaning everywhere it is cited in current code, tests, and documentation.

| Identifier | Meaning | Primary evidence |
|---|---|---|
| `P1.1` | Wiring the Data Authorization gate (ADR-0013) into AI Control Plane tool execution — the orchestration → data-authorization dependency direction and boundary. | `tests/architecture/test_layer_boundaries.py:255,268,281`; `tests/control_plane/orchestration/test_data_authorization_{gate_unit,wiring_integration}` |
| `P1.3` | Manual, local PostgreSQL backup/restore/disaster-recovery primitives (`create_backup`/restore) — infrastructure/admin-only, never imported by application code. | `infra/db/backup/__init__.py:1`; `docs/BACKUP-RESTORE.md`; `tests/architecture/test_layer_boundaries.py:323` |
| `P1.4` | Request-correlation-ID middleware / `infra/observability` wiring at the API layer (`X-Request-ID`). | `api/middleware.py:1,42`; `docs/OBSERVABILITY.md:7` |
| `P1.8` | Infrastructure liveness/readiness HTTP endpoints. | `api/health.py:1` |
| `P2.1` | The production background-worker entrypoint (`api/worker.py`) — the long-running ARQ worker process, plus its observability/correlation additions to `infra/jobs`. | `api/worker.py:1,3,78`; `infra/jobs/{payload,queue}.py`; `README.md:191` |
| `P2.2` | OIDC Authorization Code Flow (browser login). | `core/identity/oidc.py:162` |
| `P2.3` | Production network perimeter: TLS termination, proxy-trust (`X-Forwarded-For`, last-hop only), CORS posture, and no public exposure of PostgreSQL/Redis. Documented in full in §11 above — the only dotted identifier with its own dedicated section here. | `docs/DEPLOYMENT-ARCHITECTURE.md` §11; `api/auth/{config,routes}.py`; `docker-compose.prod.yml` |
| `P2.4` | Two related hardening concerns sharing one identifier — not split or renumbered here: (1) the production backup pipeline (locking, encryption, off-site upload, layered on `P1.3`'s primitives); (2) Redis AOF persistence hardening (durable queue state across restarts). | `infra/db/backup/{config,destination,encryption,lock,orchestrator}.py`; `docs/BACKUP-RESTORE.md`; `docker-compose.prod.yml:59`; `tests/infra/jobs/test_redis_persistence_integration.py` |
