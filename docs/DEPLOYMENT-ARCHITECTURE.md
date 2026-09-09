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

**Routing**: `/auth/*` and `/v1/*` (the backend's actual external surface, `api/main.py`) go to `backend:8000`; everything else goes to `frontend:3000`. `/healthz`/`/readyz` are deliberately not proxied externally (no documented need for Internet reachability) and fall through to the frontend's own 404, rather than leaking readiness detail to an external prober.

**CORS**: not configured, deliberately — the proxy serves frontend and backend from one origin (`PUBLIC_DOMAIN`), so no cross-origin request exists for the browser to need CORS headers for. No `Access-Control-Allow-Origin` is ever returned; there is no wildcard-plus-credentials configuration surface to misconfigure because none exists.

**Forwarded-header trust**: `TRUST_PROXY_HEADERS=true` (set only on `backend` in `docker-compose.prod.yml`) makes the pre-login rate limiter (`api/auth/routes.py::_resolve_client_address`) read the client address from `X-Forwarded-For` — and only ever the *last* comma-separated entry, the one hop Caddy itself appended and could not have been forged by the client, since network segmentation guarantees a request can only reach `backend` through `proxy`. `X-Forwarded-Proto`/`X-Forwarded-Host` are not read anywhere in this codebase; cookie `Secure` and redirect generation are driven by static configuration (`AuthHttpConfig`), never per-request scheme headers, so there is nothing there for a forwarded header to spoof.

**Security headers** (set by Caddy): `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`. No CSP is set — the frontend is an unstyled foundation page with no inline-script inventory to build a real policy against yet; a guessed policy would likely break the first real page.

**What this phase does not solve** (unchanged from the readiness audit, remain separate phases): off-site backups, RPO/RTO, Redis durable queue persistence, `detect-secrets` baseline remediation, platform administration/tenant-provisioning UI. Live ACME/DNS certificate issuance requires a real, DNS-resolvable domain and is not exercised by this repository's own automated validation (`scripts/check-docker-prod.sh` uses `PUBLIC_DOMAIN=localhost`, which deterministically exercises Caddy's internal, self-signed CA instead).
