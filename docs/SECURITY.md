# Security Architecture

Status: ACCEPTED (boundary rules, gates, identity/tenancy providers, and secrets architecture per `docs/ADR/`) — compliance target remains open (§11).

This document defines security boundaries across the four layers defined in `docs/ARCHITECTURE.md`. It is a specification; no security tooling is implemented yet.

## 1. Principles

- **Single enforced chokepoint over ad hoc checks.** Every security-relevant check (authentication, authorization, tenant scoping) is implemented once, in the shared `saas_os/api/dependencies.py` chain and `saas_os/core/rbac` — never reimplemented per-endpoint or per-module. Routes opt into that chain by declaring a route policy, and the platform's startup check refuses an application with any route that has not (`docs/ADR/0030-foundation-enforcement.md`). Database-level tenant isolation is RLS on every tenant-owned table, classified in `saas_os/core/tenancy/isolation.py` and proven schema-wide by the RLS coverage sweep.
- **Least privilege by default**, for humans, service accounts, and AI agents alike.
- **Every privileged action is attributable and audit-logged** — human or AI, there is always an actor ID and a reason.
- **Security-critical code lives in Core/Infra, not Product.** A product cannot weaken the platform's security guarantees; it can only operate within them.

## 2. Authentication Boundary

Per `docs/ADR/0005-identity-build-vs-buy.md` (Accepted): **credential verification is delegated to ZITADEL via OIDC.** The platform does not implement its own login form, password storage, or MFA logic — `saas_os/core/identity` acts as an OIDC relying party.

- `saas_os/core/identity` owns everything on the platform side of that handshake, and is the only module — including Product modules — permitted to implement OIDC integration, session issuance, or token-verification logic. No other module talks to ZITADEL directly or implements a parallel login path.
- Flow: a caller authenticates via ZITADEL's OIDC flow → `saas_os/core/identity` validates the returned token/claims → maps the external `sub` claim to the platform's canonical `user_id` → issues a platform-level session/token used for subsequent requests. Downstream code trusts the resulting identity context (`user_id`, `tenant_id`, `auth_method`); it does not re-verify credentials or talk to ZITADEL itself.
- Session/token verification happens once, at the API/Infra ingress layer (see `docs/API-ARCHITECTURE.md`), producing that verified identity context for all downstream code.
- Machine identities (API keys, service accounts, AI Control Plane agents) are **not** authenticated via ZITADEL's human OIDC login flow — they are authenticated through a distinct mechanism owned by `saas_os/core/identity` (see `docs/AI-CONTROL-PLANE.md` §7), but resolve to the same identity-context shape, so downstream authorization code does not need to special-case "is this a human or a machine."
- **This platform owns application authorization and permissions, not authentication infrastructure.** ZITADEL is a source of authenticated identity only — see §3.
- **A verified email, on the session only** (ADR-0046). Login requests the `email` scope. When the ID token asserts `email_verified` as `true`, the email is stored, normalized, on the session the login issues (`core.sessions.verified_email`). Its only use is the comparison that binds an invitation to the person invited. It is never an identity key; `core.users` stores no email; non-ASCII addresses are never kept, because case folding can make two of them equal; logout clears it, and it is deleted with the session by retention and by identity erasure.
- **API keys at ingress, only where a route opts in** (ADR-0047). A route declared with `require_permission(..., api_key=True)` also accepts a key in the `X-API-Key` header, authenticated by `saas_os.core.api_keys.validate_api_key()` (revocation, expiry, the tenant's lifecycle, an inactive owner or a disabled service account all refuse it, each audited) and answered as the key's owner: its user, or its service account. A key reaches only its own tenant, never alongside a session credential in the same request, and is rate-limited per key. A permission that changes authority (`saas_os.core.rbac.is_authority_changing`: the set a support-access grant may never satisfy) cannot accept a key at all. Keys issued over HTTP carry the `sok_` prefix and expire within 365 days.

## 2.1 Cross-Site Request Forgery

The session cookie is `HttpOnly`, `Secure` and `SameSite=Lax`. `SameSite` separates sites, not origins, so it does not stop a sibling subdomain. A request that authenticates with the cookie and uses an unsafe method (anything but `GET`, `HEAD`, `OPTIONS`) must therefore also carry an `Origin` header equal to the application's own origin (`PUBLIC_APP_ORIGIN`), and `Sec-Fetch-Site: same-origin` when the browser sends that header; otherwise it is refused with `403` before session validation, tenant resolution or authorization. Requests authenticated with `Authorization: Bearer` are exempt. The check is part of the authentication dependencies, so no route can be authenticated without it. Decision and limits: `docs/ADR/0044-same-origin-check-for-cookie-authenticated-mutations.md`.

## 2.2 Identity Provider Version and Advisories

The bundled identity provider is pinned to one ZITADEL release for the server and the Login V2 UI: **v4.19.5** in `docker-compose.yml` and `docker-compose.prod.yml` (2026-10-20), enforced equal by `tests/architecture/test_production_identity_topology.py`. That release includes the v4.19.2 fixes for GHSA-jh92-5mrj-p2w2 (Login V2 session cookie unsigned: account takeover; High), GHSA-x4c7-fpcx-w9q6 (SAML identity-provider confusion; High, only where a SAML provider is configured) and GHSA-w4gv-rcwj-w6r5 (impersonation of administrators; Low, only where impersonation is enabled).

- Login V2 signs its cookies with `ZITADEL_SESSION_COOKIE_SECRET`, which production must supply (`docs/RUNBOOKS.md`, "Login V2 session-cookie secret"); the Compose file refuses to start without it.
- The pin is the repository's. A product's running deployment is patched only once it runs the pinned release; this repository does not observe deployments. Open items are in the deferred issue ledger (`docs/P-ROADMAP.md`).
- `saas_os/core/identity` is unaffected by the version: it verifies OIDC ID tokens through discovery and JWKS and uses no ZITADEL SDK.
- Disposable-stack evidence for v4.19.5, including what is not yet verified: `docs/architecture/ZITADEL-4.19.5-LIVE-VALIDATION.md`.

## 3. Authorization Boundary

- Owned entirely by `saas_os/core/rbac`, wholly independent of ZITADEL (§2) — the IdP authenticates identity, it never determines permissions. Authorization is a single policy-evaluation call (`can(actor, action, resource)`), invoked through the same dependency chain as authentication (`require_permission`, which every non-public, non-authenticated-only route must declare — ADR-0030) — not scattered `if user.role == 'admin'` checks across Product code.
- Authority-changing Core operations (roles, grants, memberships, delegations, denies, service accounts, API keys, support access) require an explicit typed caller (`saas_os.core.authority`: a user, a service account, or a named system purpose) and authorize it through the same `can()` call — never ambient request state, never `None` meaning "system". An approved support-access grant can never satisfy an authority-changing capability, and an inactive user (`User.is_active == False`) is never an authenticated or authorized actor (`docs/ADR/0031-foundation-authority-and-evidence.md`).
- Product code may define its own permission *names* relevant to its domain (e.g., `dograh:call.transcript.read`) but cannot bypass the Core evaluation mechanism to implement a parallel authorization system.
- AI Control Plane actions are authorized through the *same* RBAC evaluation as human actions, scoped to the agent's own identity (see §6) — an agent is a first-class principal in the authorization model, not a bypass of it.

## 3.1 Last Tenant Administrator

A tenant that has an administrator must keep one. An administrator is an active member, an active user, who can assign roles in the tenant (`membership_role:create`) without relying on a delegation that expires — a capability evaluated by `can()`, not a role name.

Every supported change that can take that authority away is judged against each tenant it can reach, in its own transaction, and rolled back with `LastTenantAdministratorError` (naming the tenant) if one of them had an administrator before and has none after: suspending or revoking a membership, removing a role from a member, revoking a permission from a role, creating a deny grant, revoking a delegation — in the tenant itself or in an ancestor whose SUBTREE-scoped grants reach it — and moving a tenant or suspending or closing an ancestor tenant. Per-tenant locks are taken ancestor first, so these changes cannot deadlock on them.

Not covered: user deactivation (Core has no such function), the operator-only purge and erasure paths, and a tenant attached beneath a tenant in the instant that tenant is suspended. Decision, inventory, lock order and limits: `docs/ADR/0043-last-tenant-administrator-invariant.md`.

## 4. Secrets Management

Per `docs/ADR/0012-secrets-management.md` (Accepted): **owned entirely by `saas_os/infra/secrets`, behind a provider-agnostic `SecretsProvider` interface.** No module — Core, Infra consumer, Product, or Control Plane — reads raw environment variables for secret material directly, calls a specific secrets-management product's SDK directly, or has any path to a secret that bypasses this interface.

- **Development**: `SecretsProvider`'s development implementation reads from a local `.env` file. `.env` is gitignored from its first introduction; `.env.example` documents every required variable with placeholder values only, never real secrets. No real credential is ever committed, enforced by CI secret-scanning (§10).
- **Initial production** (Docker Compose + VPS, per `docs/ADR/0010-...`): secrets are injected into the running container at start-up (environment variables or Docker Compose `secrets:`-mounted files), sourced from the VPS host or the deploy step — never baked into a Docker image layer, and never committed to source control (including inside a committed `docker-compose.yml`, which may reference *where* a secret comes from but never its value). Detail in `docs/DEPLOYMENT-ARCHITECTURE.md` §4.
- **Future**: HashiCorp Vault, a cloud secret manager, formalized Docker Secrets, or another enterprise secret-management system may be added later as additional `SecretsProvider` implementations, triggered by actual need (an enterprise/compliance tenant, or outgrowing single-VPS operation) — not installed or scaffolded now.
- Secret access is scoped per module/service identity — Product code cannot request Core's database credentials, and Control Plane tools cannot request raw infrastructure credentials or the full secrets store at all (see §6, which states the binding AI-specific rule this ADR's security consequences require).
- Secret rotation is a platform-level (Infra) capability; modules must tolerate rotation without restart where feasible (design constraint, not yet implemented).

## 5. Tenant Data Isolation

Full detail in `docs/MULTI-TENANCY.md`. Security summary: tenant scoping is enforced at the `saas_os/infra/db` chokepoint (query layer), not left to individual query authors. This is treated as the platform's primary security boundary for customer data, and any code path that queries tenant-scoped data without going through the enforced chokepoint is a security defect. Which specific entry point a call site must use (`tenant_session_scope()` vs. the untenanted `session_scope()`) is a statically enforced architecture invariant, not only a review convention — see `docs/ADR/0022-tenant-session-boundary-enforcement.md`. PostgreSQL Row-Level Security remains the actual runtime, fail-closed guarantee underneath both.

## 5.1 Database/Cache Transport Encryption

Full detail in `docs/ADR/0021-database-redis-transport-encryption.md`. Security summary: `saas_os/infra/db/config.py`, `saas_os/infra/jobs/config.py`, and `saas_os/infra/ratelimit/config.py` each fail closed against a silent plaintext PostgreSQL/Redis connection in `ENVIRONMENT=production` (`DB_REQUIRE_TLS`/`REDIS_REQUIRE_TLS`, overridable, default true in production). The shipped `docker-compose.prod.yml` does not disable this default. This is a transport-encryption boundary only — it does not guarantee certificate/hostname verification, is additive to (not a substitute for) network isolation, and does not itself provision the TLS material a real deployment's PostgreSQL/Redis need (operational responsibility, documented in the ADR).

## 6. AI Agent Permission Boundaries

This is the highest-consequence boundary in the platform, given the stated goal of autonomous DevOps/incident-response/support/development capability.

- **No ambient access, ever.** An AI agent never receives raw database credentials, raw infrastructure/cloud credentials, or an unscoped API key. All agent action against Core or Product happens through explicitly declared **tools** (see `docs/AI-CONTROL-PLANE.md`), each of which wraps exactly one bounded capability (e.g., "restart service X," "read tenant Y's support tickets," "propose a config change") and enforces RBAC/tenant-scoping identically to a human actor performing the same action.
- **No agent ever receives a `SecretsProvider` handle, a bulk export of the secrets store, or the full runtime environment** (`docs/ADR/0012-secrets-management.md`, binding). A secret reaches an agent's tool execution only when: (1) an explicitly declared, RBAC-scoped tool is invoked, (2) that tool's own definition names the specific secret(s) it needs, and (3) `saas_os/infra/secrets` resolves and injects only that named secret into the tool's execution context — never into the agent's conversational context/memory, and never via a general-purpose "look up any secret by name" capability exposed to the agent. Every such access is audit-logged with the secret's *name*, never its value (§8). A tool may return a raw secret value into an agent's visible output only if doing so is that tool's explicit, reviewed purpose — never as an incidental side effect.
- **Every tool has a declared permission tier** (read-only / write-with-approval / write-autonomous), and a tool cannot be invoked by an agent whose identity has not been explicitly granted that tier for that tool.
- **Every agent identity is scoped** — to a tenant (for support/product agents acting on tenant data), to an environment (for DevOps/incident agents), or to a repository (for development agents) — and cannot act outside that scope regardless of what the tool technically permits.
- **Tool definitions live in `saas_os/control_plane/tools/`, not in Core or Product code**, so the full set of capabilities an agent could ever exercise is enumerable by reading one directory — this is what makes "what could the AI possibly do" answerable without auditing the entire codebase.

## 6.1 AI Data Privacy Boundary

Per `docs/ADR/0013-ai-data-privacy-and-external-model-boundary.md` (Accepted): §6 above ("AI Agent Permission Boundaries") governs what an agent may *do* — this section governs what data may be *sent to an external AI/LLM provider* (Claude, OpenAI, DeepSeek, or any other), by an AI Control Plane agent or by a product-level feature calling an external provider directly. This is a distinct, independent boundary — passing §6's tool/RBAC check never implies data is cleared to cross this one. These are binding invariants. When this section was written nothing in it was implemented; their status since governed AI inference (`docs/ADR/0054-governed-ai-inference-subsystem.md`, `docs/ADR/0055-ai-data-governance-and-destination-authorization.md`, merged by pull request #53; both Accepted 2026-10-18 with explicit scope) follows the list.

1. No tenant or user data reaches an external AI/LLM provider except through the approved AI data-authorization boundary — never a direct, unmediated call from Product or Control Plane code.
2. Data sent to an external provider must be the minimum required for the specific task — full customer/tenant records are not sent by default.
3. Data that has not been classified is treated as sensitive and denied by default — the boundary never fails open.
4. AI providers are not equally trusted by default — provider eligibility is policy-driven configuration, not a hardcoded, permanent trust assumption.
5. A tenant's data may only be sent to an external AI provider consistent with that tenant's own AI data policy, once such a policy exists (ADR-0013 §4) — absent an explicit policy, the default is deny, not implicit allow.
6. Sensitive data classes (at minimum: authentication credentials/tokens, secrets/API keys, financial information, government identifiers, health information) are never sent to an external AI provider without an explicit, reviewed policy decision permitting that specific class.
7. Every request that crosses the AI data boundary is attributable and audit-logged (`§8`) — which actor/agent, which data class, which provider, and the policy decision that permitted it.
8. No AI Control Plane tool or product feature may bypass the AI data boundary by embedding an external-provider API call directly, even for a narrow or "temporary" use case.
9. Redaction/anonymization/pseudonymization applied before external transmission must not be silently reversible by the receiving provider through the data sent alongside it.
10. This boundary is additive to, not a substitute for, tenant isolation (§5) and tool-mediated access (§6) — data that is correctly tenant-scoped and correctly obtained via an authorized tool can still be denied here if it is not classified/minimized/policy-approved for external transmission.

**Implementation status (2026-10-18).** For governed AI inference (`saas_os.inference`), the only provider path SaaS OS ships:
- 1 and 8: inside this repository, import contracts forbid AI SDKs outside the inference adapters and forbid products and other Control Plane packages from importing the inference internals; a raw `httpx` call is not forbidden by contract, and a consumer's own code is bound only by documentation and review.
- 2: per-use-case limits on part kinds, part count and bytes; real minimization stays the product's job.
- 3: every content part carries a classification; a missing or invalid one denies before any destination is considered.
- 4 and 5: stored installation destination policy per provider and classification, and a stored tenant AI policy; absent means deny.
- 6: one coarse `sensitive` class, crossing only with the use case's ceiling, the tenant's explicit grant and an installation policy row with a reason (ADR-0055 section 5).
- 7: each crossing has an attempt row with actor, classification, provider, model and the decision, committed before sending; refusals write `denied` tenant audit rows, best effort, except quota and capacity refusals (ADR-0055 section 6).
- 9: not implemented; no redaction exists.
- 10: holds structurally.
Classifications are product declarations; SaaS OS does not verify that a label describes the content. Tool orchestration's own data-authorization check (`saas_os.control_plane.data_authorization`) is unchanged and has no persisted policy store.

## 6.2 Learning Authorization Boundary (Future, `docs/IMPLEMENTATION-ROADMAP.md` Phase 9)

Per `docs/ADR/0014-learning-authorization-and-continuous-improvement-boundary.md` (**Accepted**): the proposed Self-Learning / Continuous Improvement subsystem introduces a third gate, independent of §6 (Tool Authorization) and §6.1 (Data Authorization). Passing §6 (this agent may invoke this tool) and §6.1 (this data may reach an external AI provider for this one call) never implies the same data may be *retained or reused* to shape the platform's future behavior — that is Learning Authorization, evaluated separately:

```
Can the AI access this data?          -- §6, Tool Authorization
        |
Can this data reach an external model, once? -- §6.1, Data Authorization
        |
Can this data be used for learning?   -- this section, Learning Authorization
        |
For what purpose? For which tenant? For which model/provider? For how long?
        |
Default: DENY
```

Binding invariants, once implemented:

1. Learning from Tenant A's data must never become learning data for Tenant B unless an explicit, authorized, reviewed policy permits that specific reuse — accidental cross-tenant learning is a security defect, not an acceptable side effect.
2. Data that has not been explicitly authorized for learning reuse is denied by default, exactly as §6.1 rule 3 requires for unclassified data reaching an external provider at all.
3. The Self-Learning subsystem is AI Control Plane capability (`saas_os/control_plane/self-learning`), never SaaS Core — SaaS Core must remain fully functional with it disabled (`docs/ARCHITECTURE.md` §2).
4. The future Learning Ledger (learning lineage/state) is additive to, never a replacement for, `core/audit-log` (§8) — every learning-related privileged action is still recorded through the existing audit-log interface.
5. This boundary is additive to, not a substitute for, tenant isolation (§5), tool-mediated access (§6), and the AI data boundary (§6.1) — data correctly scoped and authorized under all three can still be denied here if it is not authorized for retention/reuse.

Full phase-by-phase decomposition: `docs/IMPLEMENTATION-ROADMAP.md` Phase 9; conceptual detail: `docs/AI-CONTROL-PLANE.md` §12.

## 7. Human Approval Gates

Every autonomous capability is assigned an explicit autonomy level before it can be built, not after:

| Level | Description | Default for |
|---|---|---|
| 0 — Propose only | Agent produces a recommendation; takes no action | Starting point for any new capability |
| 1 — Propose + human approval | Agent stages an action; a human must approve before execution | DevOps changes, incident remediation beyond safe-listed actions |
| 2 — Auto-execute + audit | Agent executes without prior approval, but every action is logged and reversible/reviewable after the fact | Narrow, pre-vetted, low-blast-radius actions only (e.g., a pre-approved list of "safe" incident remediations) |
| 3 — Fully autonomous | No standing human checkpoint | Not enabled for any capability at this stage of the platform |

Rules:

- A capability starts at Level 0 or 1. Promotion to a higher level requires a recorded decision (an ADR) citing demonstrated reliability, not a default.
- Approval gates are themselves implemented as Control Plane workflow state (`saas_os/control_plane/approvals`), not as a Slack message or out-of-band process — the approval action is itself audit-logged and attributable to a specific human.
- See `docs/AI-CONTROL-PLANE.md` for the sequencing of which capabilities get built at which autonomy level.

## 8. Audit Logging

- `core/audit-log` (`core.audit_log`) is the append-only store for every privileged action *inside a tenant*: permission changes, billing changes, and every AI agent tool invocation (including ones that were proposed but not approved, and ones that were denied by a permission check). Once the future Self-Learning subsystem (§6.2, Phase 9) is built, this includes: learning event creation, dataset access, feedback ingestion, candidate creation, evaluation, approval, rejection, experiment creation, canary deployment, promotion, rollback, and both policy-gate and autonomy-limit denials — reusing this same interface, never a second audit mechanism (`docs/AI-CONTROL-PLANE.md` §12's Learning Ledger is a distinct, additive lineage record, not a substitute for this store).
- **Two stores, by scope.** Every row of `core.audit_log` belongs to one tenant and is under that tenant's row-level security, so an event with no tenant cannot be recorded there. Platform events -- an operator enrolled or suspended, a platform permission granted or revoked, a tenant created, suspended or moved by an operator, a user deactivated, an oversight read -- are recorded in `core.platform_audit_log` (`docs/ADR/0045-installation-scoped-platform-authority.md` section 8), which no tenant-scoped transaction can see and which the runtime role can insert into and read but never update or delete. A platform *change* to a tenant writes to both: the platform row, and a row in that tenant's own trail naming the operator. An oversight read is recorded in the platform audit only.
- **Logins.** An ordinary user's login is not recorded in either store: it has no tenant, and it is not a platform event. A login by a user who is an enrolled platform operator is recorded (`platform.operator.session_issued`), so that a session an operator did not start is visible to anyone who may read the platform audit (`platform.audit:read`); an operator without that permission does not see their own. The row is written for a suspended operator too. The identity provider's own event log is the record of every other login.
- **What is written in the same transaction, and what is not.** A privileged *change* and its audit entry are written in the same database transaction (`saas_os.core.audit_log.record_in_transaction()`, and `record_platform_event_in_transaction()` for platform events): a rolled-back change leaves no record claiming it happened, and a committed one always has its record. The entry's actor is the explicit caller that was authorized (`docs/ADR/0031-foundation-authority-and-evidence.md`). Three kinds of row are deliberately written in a transaction of their own: a *refusal* (`denied`) and a *failure*, recorded after the refused operation rolled back, best effort, never replacing the refusal the caller receives; and the *attempt* row of a platform oversight read, committed before anything is read and fail closed -- if it cannot be written, nothing is read. The data of an oversight read leaves Core only after its completion row is committed.
- Audit events are immutable and queryable by tenant, actor, and time range. Product code emits product-specific audit events through the same Core interface, using the extension pattern described in `docs/ARCHITECTURE.md` §9 (contract) — it does not maintain its own separate audit trail.
- AI agent audit entries always carry: agent identity, the tool invoked, the input, the approval record (if applicable), and the outcome — sufficient to answer "what did the AI do, on whose behalf, and was it approved" without additional investigation.

## 9. Data Classification (Directional)

Not yet formalized into policy, but the architecture anticipates at minimum: **tenant business data** (product-owned, isolated per §5), **platform account data** (Core-owned: identity, billing), **secrets/credentials** (never stored alongside application data), and **audit/observability data** (append-only, longer retention than operational data). A formal classification and retention policy is deferred to a phase where compliance requirements are known (see `docs/ARCHITECTURE-DISCOVERY.md` §17, and the open human decision on compliance target).

## 10. CI/Dependency Security (Infra-owned)

Implemented in Phase 1.4 (`docs/IMPLEMENTATION-ROADMAP.md`), running in CI's `security` job and locally via `scripts/check-security.sh`:

- **Dependency vulnerability scanning**: `pip-audit` (backend, queries the OSV database against the resolved Python environment) and `npm audit --audit-level=high` (frontend, against `frontend/package-lock.json`). A finding is fixed with the smallest compatible upgrade (a scoped `overrides` pin, not a forced major-version bump) or explicitly documented if no safe fix exists yet — never suppressed to force a green build.
- **Secret scanning**: `detect-secrets`, scanning git-tracked files against a committed `.secrets.baseline`. Known false positives (e.g., a placeholder connection string in `.env.example` matching a credential-shaped pattern) are recorded in the baseline as audited, not disabled globally — a genuinely new, unaudited finding still fails the check. Verified non-vacuous: a synthetic fake credential in a disposable, never-committed file was confirmed to be caught before this mechanism was relied upon.

Both scans run against repository/environment content only — no production environment or credential is required. Full detail: `README.md` "Security scanning".

## 11. Platform Authority and Tier 0

Decided in `docs/ADR/0045-installation-scoped-platform-authority.md`. Three kinds of authority exist in a deployment, and they do not convert into one another.

| Authority | Held by | Reaches |
|---|---|---|
| **Tenant** | A member, service account, delegate or approved support engineer, through tenant RBAC (`saas_os.core.rbac.can()`) | One tenant, and its descendants where a role says so |
| **Platform** | A *platform operator*: a user this deployment enrolled, holding explicit platform permissions (`saas_os.core.platform_authority`) | The installation: tenant registry and lifecycle, users and their credentials, feature flags, a commercial overview, the platform audit, and platform authority itself. Never a tenant's business data |
| **Infrastructure (tier 0)** | Whoever possesses a tier-0 credential | Everything, including bypassing SaaS OS |

**Platform authority is installation-scoped.** Grants are rows in this deployment's database, keyed by this deployment's user ids. The same person, or the same identity-provider subject, has no authority in another deployment until that deployment grants it. The reverse also holds: **a copy of the database is a copy of the authority.** Restoring or cloning a production database into another environment carries its operators and grants with it (`docs/RUNBOOKS.md`, "Platform operators").

**What platform authority is not.** Eighteen permissions, each granted individually; holding one implies no other. None allows reading a tenant's business data, and the only tenant-owned rows any of them writes are a feature-flag override, the revocation of one user's API keys, and the evidence row in the tenant's own audit trail. None allows adding a membership, changing a tenant role, approving support access, or issuing an API key. An operator who needs to see a customer's data files a support-access request and the tenant approves it. Service accounts never hold platform authority. There is no permission for purge, identity erasure, migrations, backup, the owner bootstrap or recovery: those are infrastructure operations, run as commands.

**Invariants Core enforces.** A deployment that has a platform owner (an active operator, of an active user, holding `platform.authority:manage`) keeps one: no revocation, suspension or deactivation that would remove the last is accepted. An operator cannot change their own authority, and can grant only a permission they hold. A user who is an enrolled operator cannot be erased until the operator is revoked.

**Tier 0.** These credentials are outside SaaS OS's authorization boundary. Holding any one of them is equivalent to holding every platform and every tenant authority, and SaaS OS does not claim to prevent their misuse:

| Credential | Why it is tier 0 |
|---|---|
| The migrations database role | Owns every table: it can read any tenant's data, change any grant, and alter or delete audit rows, which the runtime role cannot |
| The application role's database credentials and the deployment's secrets | Can run the owner bootstrap and recovery commands, and can write the rows those commands write |
| Host or orchestrator access to the backend | Runs code in the process, where a system purpose is an ordinary value |
| A database backup and the key that decrypts it | A copy of the database is a copy of every grant, session and key in it |
| ZITADEL `IAM_OWNER` (and the `bootstrap` machine user's personal access token) | Can reset any subject's credentials or control signing keys, and so obtain any user's session, a platform owner's included |

The controls around that boundary are compensating, not preventive: operator logins are recorded, so a takeover through the identity provider produces a login the real operator did not make; a change to platform authority over HTTP needs a session at most 15 minutes old (a deployment may lower the limit, not raise it); deactivating a user and revoking sessions take effect on the next request; the recovery command suspends a compromised owner without depending on any other owner; and the identity provider's own event log is the independent evidence for actions taken with `IAM_OWNER` (`docs/RUNBOOKS.md`, "Platform operators", section 9: where it is kept and how). The platform audit table is append-only for the runtime role and is **not tamper-evident**: there is no hash chain and no external copy, and tier 0 can alter it without trace.

**Known limits**, recorded in the roadmap ledger: two rare lock orderings in user deactivation are resolved by PostgreSQL aborting one transaction (nothing is left half-done; the caller repeats). Since 2026-10-14 every operator is someone who can log in: enrollment refuses a user linked to no external identity, an erased user included, and erasure removes the links under the same lock as its operator check.

## 12. Open Decisions

Identity provider (ZITADEL/OIDC), multi-tenancy model, API/deployment posture, and secrets architecture are now Accepted — see `docs/ADR/`. Still open: observability backend vendor (`docs/ADR/0009-...`) and compliance target. This document's boundary rules (§2–§8) hold regardless of which specific tools are chosen to implement the remaining open items. See `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` and `docs/PHASE-0.3-SECRETS-DECISION.md` for the current consolidated status.
