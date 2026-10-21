# ADR-0012: Secrets management

Status: Accepted
Date: 2026-09-06
Supersedes / Superseded by: —

## Context

`infra/secrets` was specified from the first architecture pass (`docs/SECURITY.md` §4, `docs/ARCHITECTURE.md` §3) as the module owning secret retrieval for every layer, but its concrete backend was left an explicitly open, non-blocking residual decision (`docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` §2). This is the last precondition tracked before Phase 0 is considered fully closed. It must be resolved consistently with: the Docker Compose + VPS deployment target (`docs/ADR/0010-...`), the provider-abstraction pattern already used for billing (`docs/ADR/0008-...`) and identity (`docs/ADR/0005-...`), and the AI Control Plane's tool-mediated-access rule (`docs/ADR/0004-...`).

## Options Considered

### Option A — A provider-agnostic `SecretsProvider` interface in `infra/secrets`, with swappable implementations (dev, Docker/host production, future external managers), Core/Product/Control-Plane depending only on the interface
- Advantages: matches the pattern already accepted for billing (ADR-0008) and, at the protocol level, identity (ADR-0005) — the platform now has one consistent answer to "how do we avoid vendor lock-in for a critical dependency": an internal abstraction with adapters; defers the operational cost of an external secrets manager until it is actually needed, without foreclosing it
- Disadvantages: the abstraction is extra design work up front, and a poorly designed interface could still leak provider-specific assumptions (e.g., if it's shaped exactly like one provider's API)

### Option B — Hardcode a single secrets mechanism now (e.g., plain environment variables everywhere, no interface)
- Advantages: fastest to start
- Disadvantages: every module that reads a secret couples directly to "read from `os.environ`," and a future move to any real secrets manager (even a simple file-based one) becomes a full-codebase find-and-replace under security pressure — exactly the anti-pattern this platform's architecture exists to avoid (`docs/ARCHITECTURE-DISCOVERY.md` §23)

### Option C — Adopt an external secrets manager (HashiCorp Vault, a cloud provider's secret manager) now, as the only mechanism
- Advantages: strongest security posture immediately; no later migration needed
- Disadvantages: explicitly rejected by instruction — operational overhead (Vault) or cloud-provider coupling (cloud secret managers) unjustified before the platform has real production load, and out of step with the deliberately minimal Docker Compose + VPS target (ADR-0010)

## Recommendation

Option A.

## Decision

**Accepted.** `infra/secrets` defines a provider-agnostic `SecretsProvider` interface. **No module outside `infra/secrets` — not Core, not Product, not the AI Control Plane — ever depends on a specific secrets-management product directly.** Every secret is retrieved through this interface, by name, never by reading ambient environment state or a provider SDK directly from calling code.

```
SecretsProvider (interface: get(name) -> value; fails fast if required and absent)
├── Development implementation       — reads from `.env` (local machine only)
├── Docker/host production implementation  — reads secrets injected into the
│                                             container's runtime environment at
│                                             start-up (env vars or files mounted
│                                             via Docker Compose `secrets:`),
│                                             sourced from the VPS host, never
│                                             from the image or the repository
└── Future external secret-manager implementations
    (HashiCorp Vault, cloud secret managers, formalized Docker Secrets,
     other enterprise secret-management systems) — not built now
```

### Development implementation

- `.env` is permitted for local development only.
- `.env.example` **must** exist and document every required variable name (and a description/type where useful) **without containing any real secret value** — placeholder/dummy values only.
- `.env` **must** be listed in `.gitignore` from the first commit that introduces it.
- **No real credential is ever committed to source control, in `.env`, in application config, in a test fixture, or anywhere else.** This is enforced by the CI secret-scanning stage (`docs/SECURITY.md` §10, `docs/DEPLOYMENT-ARCHITECTURE.md` §5 stage 3), not by developer discipline alone.

### Initial production implementation — Docker/host, on the accepted Docker Compose + VPS target (ADR-0010)

- Secrets are **injected into the running container at start-up** — as environment variables or as files mounted via Docker Compose's `secrets:` mechanism, sourced from the VPS host (a restricted-permission location outside the repository) or from CI/CD's deploy step.
- Secrets are **never baked into a Docker image layer** (no `ENV` with a real value, no `COPY` of a secrets file into the image) and **never committed to source control**, including inside any committed `docker-compose.yml` or application config file — a committed compose file may reference *where* to find a secret (an env var name, a `secrets:` file reference) but never the secret value itself.
- This implementation is what `infra/deploy` (`docs/DEPLOYMENT-ARCHITECTURE.md`) wires up at deploy time; it is the same `SecretsProvider` interface as every other implementation, so application code does not change between environments.

### Future implementations (not built now)

HashiCorp Vault, a cloud provider's secret manager, a formalized Docker Secrets integration, or another enterprise secret-management system may be added later as additional `SecretsProvider` implementations. **None of these is installed, deployed, or scaffolded as part of this decision.** This ADR fixes the interface and the two implementations needed now; future implementations are separate, later work triggered by actual need (e.g., an enterprise/compliance-driven tenant, or the platform outgrowing single-VPS operation).

## Rejected Alternatives

- **Hardcoded single mechanism, no interface (Option B)**: rejected — recreates the exact coupling risk the platform's core dependency rule (`docs/ARCHITECTURE.md` §2) and the billing/identity ADRs were designed to prevent, this time for a dependency every module touches.
- **Adopting Vault or a cloud secret manager now (Option C)**: rejected per explicit instruction and for the same reason ADR-0010 rejected Kubernetes now — operational overhead and/or cloud coupling not justified before demonstrated need, and out of step with the deliberately minimal initial deployment target.
- **"Encrypted secrets committed to the repo"** (a pattern some platforms use, e.g. SOPS/git-crypt): considered implicitly and rejected — it does not actually solve the problem, since the decryption key must then live somewhere outside the repo, which is just the Docker/host production implementation above with extra steps. Not adopted as a separate mechanism.

## Security Consequences

- **Reduces blast radius of a source-control leak to zero for secret material** — a leaked repository (public accidentally, a compromised contributor account, a leaked backup) never contains a real credential, only variable names and dummy values.
- **Centralizes the one place secret-handling bugs can occur** (`infra/secrets`) instead of spreading ad hoc `os.environ` reads across the codebase — makes a future security review of "how are secrets handled" a review of one module, not the whole codebase.
- **Residual risk, explicitly accepted for now**: the Docker/host production implementation means a compromised VPS host has access to every secret injected into containers running on it — this is an inherent consequence of the single-VPS, no-external-secrets-manager posture already accepted in `docs/ADR/0010-deployment-target.md`'s risk disclosure, not a new risk introduced here. It is mitigated, not eliminated, by minimal-privilege host access and is the concrete reason a future external secrets manager (Vault, cloud KMS) remains on the roadmap rather than being ruled out.
- **AI Control Plane consequence** (binding, detailed in `docs/SECURITY.md` §6 and `docs/AI-CONTROL-PLANE.md`, restated here because it is a direct consequence of this ADR): an AI agent **never** receives a `SecretsProvider` handle, a bulk export of the secrets store, or the full runtime environment. A secret reaches an agent's tool execution **only** when:
  1. An explicitly declared, RBAC-scoped Control Plane **tool** (`control-plane/tools/*`, per `docs/ADR/0004-...`) is invoked, and
  2. That specific tool's definition names the specific secret(s) it needs, and
  3. `infra/secrets` resolves and injects only that named secret into that tool's execution context — not into the agent's conversational context/memory, and not as a general-purpose lookup the agent can call with an arbitrary name, and
  4. The invocation, the secret *name* (never the secret *value*), the invoking agent identity, and the outcome are recorded in `core/audit-log` (`docs/SECURITY.md` §8).
  A tool that would return a raw secret value into an agent's visible output is permitted only if returning that value is the tool's explicit, reviewed purpose (e.g., a support tool that displays a tenant's own non-platform API key back to that tenant) — never as an incidental side effect of broader access. This satisfies the explicit / scoped / audited / policy-controlled / minimally-privileged requirement for AI secrets access.

## Future Migration / Extension Path

A future `SecretsProvider` implementation (Vault, a cloud secret manager, formalized Docker Secrets) is added as a new adapter behind the existing interface — triggered by an enterprise/compliance tenant requirement (paralleling the hybrid-database escape hatch in `docs/ADR/0002-...`) or by the platform outgrowing single-VPS operation (paralleling the Kubernetes migration path in `docs/ADR/0010-...`). Because Core/Product/Control-Plane code depends only on the `SecretsProvider` interface, this migration touches `infra/secrets` and deployment configuration only — no calling code changes.

## What Would Be Difficult to Change Later

If any module reads a secret by any path other than the `SecretsProvider` interface (a direct `os.environ` read, a hardcoded provider SDK call), that call site becomes invisible to this abstraction and must be found and rewritten under security pressure when the backend eventually changes — the same one-way-door pattern already identified for the billing provider (ADR-0008) and the multi-tenancy enforcement chokepoint (ADR-0002). This is why the interface boundary is a binding constraint from the first line of code that reads a secret, not an aspiration.

## Related

`docs/SECURITY.md` §4, §6, §8; `docs/DEPLOYMENT-ARCHITECTURE.md` §4, §8; `docs/AI-CONTROL-PLANE.md` §2–§3, §6; `docs/ARCHITECTURE.md` §7, §10; ADR-0002, ADR-0004, ADR-0005, ADR-0008, ADR-0010; `docs/PHASE-0.3-SECRETS-DECISION.md`.

## Amendment 2026-10-21: production configuration files

Status: Accepted (repository owner, 2026-10-21).

**Context.** `docker-compose.prod.yml` loaded the production `.env` whole (`env_file: - .env`) into `backend`, `worker`, `frontend` and `proxy`. The same file supplies Compose's `${...}` substitution, so the identity provider's secrets an operator wrote there (`ZITADEL_MASTERKEY`, ZITADEL's database password, the first-instance admin password, `ZITADEL_SESSION_COOKIE_SECRET`) were injected into four containers that never use them. Found during the ZITADEL v4.19.5 upgrade (ledger, `docs/P-ROADMAP.md`).

**Options considered.** (a) Per-service files: the application's settings in a separate file loaded only by the services that read them. (b) Compose `secrets:` with `*_FILE` variables: stronger, but needs file support in every consumer, including ZITADEL's own configuration, and a larger change to the production implementation above. (c) Keep the wholesale load and accept the exposure.

**Decision.** Option (a), within the existing Docker/host production implementation; the `SecretsProvider` interface and every other part of this ADR are unchanged.

- `.env.app` (template `.env.app.example`) holds the application's settings. `docker-compose.prod.yml` loads it into `backend` and `worker` only; the host timers in `deploy/` read it.
- `.env` holds only what Compose substitutes into the file, including every identity-provider value. No service loads it. The ZITADEL backup timer reads `ZITADEL_BACKUP_DATABASE_URL` from it.
- `frontend` and `proxy` load no file; `proxy` receives its three Caddy values explicitly.
- Both files stay outside source control (`.gitignore`: `.env`, `.env.*`).

**Consequences.** An identity secret no longer reaches an application container, so a compromise of `backend`, `worker`, `frontend` or `proxy` no longer discloses ZITADEL's master key or database password through the process environment. The application's own secrets still reach both `backend` and `worker`, which both read them. Existing deployments must create `.env.app` before upgrading; Compose refuses to run without it (`docs/RUNBOOKS.md`, "Production configuration files"). This is a new required deployment step, so the release carrying it is a `0.Y.0` release (ADR-0015). The development topology (`docker-compose.yml`) still loads `.env` whole; it holds placeholders only.

**Evidence.** `tests/architecture/test_production_identity_topology.py` (`test_only_backend_and_worker_load_an_env_file`, `test_application_containers_receive_no_identity_secret`, and two checks on `.env.app.example`); with the previous `docker-compose.prod.yml` the two rendered-configuration tests fail. `scripts/check-docker-prod.sh` fails if a running `backend`, `worker`, `frontend` or `proxy` container receives a `ZITADEL_` variable.
