# Security Architecture

Status: ACCEPTED (boundary rules, gates, identity/tenancy providers, and secrets architecture per `docs/ADR/`) — compliance target remains open (§11).

This document defines security boundaries across the four layers defined in `docs/ARCHITECTURE.md`. It is a specification; no security tooling is implemented yet.

## 1. Principles

- **Single enforced chokepoint over ad hoc checks.** Every security-relevant check (authentication, authorization, tenant scoping) happens at one enforced layer that all code paths pass through — never reimplemented per-endpoint or per-module.
- **Least privilege by default**, for humans, service accounts, and AI agents alike.
- **Every privileged action is attributable and audit-logged** — human or AI, there is always an actor ID and a reason.
- **Security-critical code lives in Core/Infra, not Product.** A product cannot weaken the platform's security guarantees; it can only operate within them.

## 2. Authentication Boundary

Per `docs/ADR/0005-identity-build-vs-buy.md` (Accepted): **credential verification is delegated to ZITADEL via OIDC.** The platform does not implement its own login form, password storage, or MFA logic — `core/identity` acts as an OIDC relying party.

- `core/identity` owns everything on the platform side of that handshake, and is the only module — including Product modules — permitted to implement OIDC integration, session issuance, or token-verification logic. No other module talks to ZITADEL directly or implements a parallel login path.
- Flow: a caller authenticates via ZITADEL's OIDC flow → `core/identity` validates the returned token/claims → maps the external `sub` claim to the platform's canonical `user_id` → issues a platform-level session/token used for subsequent requests. Downstream code trusts the resulting identity context (`user_id`, `tenant_id`, `auth_method`); it does not re-verify credentials or talk to ZITADEL itself.
- Session/token verification happens once, at the API/Infra ingress layer (see `docs/API-ARCHITECTURE.md`), producing that verified identity context for all downstream code.
- Machine identities (API keys, service accounts, AI Control Plane agents) are **not** authenticated via ZITADEL's human OIDC login flow — they are authenticated through a distinct mechanism owned by `core/identity` (see `docs/AI-CONTROL-PLANE.md` §7), but resolve to the same identity-context shape, so downstream authorization code does not need to special-case "is this a human or a machine."
- **This platform owns application authorization and permissions, not authentication infrastructure.** ZITADEL is a source of authenticated identity only — see §3.

## 3. Authorization Boundary

- Owned entirely by `core/rbac`, wholly independent of ZITADEL (§2) — the IdP authenticates identity, it never determines permissions. Authorization is a single policy-evaluation call (`can(actor, action, resource)`), invoked at the same enforced ingress chokepoint as authentication — not scattered `if user.role == 'admin'` checks across Product code.
- Product code may define its own permission *names* relevant to its domain (e.g., `dograh:call.transcript.read`) but cannot bypass the Core evaluation mechanism to implement a parallel authorization system.
- AI Control Plane actions are authorized through the *same* RBAC evaluation as human actions, scoped to the agent's own identity (see §6) — an agent is a first-class principal in the authorization model, not a bypass of it.

## 4. Secrets Management

Per `docs/ADR/0012-secrets-management.md` (Accepted): **owned entirely by `infra/secrets`, behind a provider-agnostic `SecretsProvider` interface.** No module — Core, Infra consumer, Product, or Control Plane — reads raw environment variables for secret material directly, calls a specific secrets-management product's SDK directly, or has any path to a secret that bypasses this interface.

- **Development**: `SecretsProvider`'s development implementation reads from a local `.env` file. `.env` is gitignored from its first introduction; `.env.example` documents every required variable with placeholder values only, never real secrets. No real credential is ever committed, enforced by CI secret-scanning (§10).
- **Initial production** (Docker Compose + VPS, per `docs/ADR/0010-...`): secrets are injected into the running container at start-up (environment variables or Docker Compose `secrets:`-mounted files), sourced from the VPS host or the deploy step — never baked into a Docker image layer, and never committed to source control (including inside a committed `docker-compose.yml`, which may reference *where* a secret comes from but never its value). Detail in `docs/DEPLOYMENT-ARCHITECTURE.md` §4.
- **Future**: HashiCorp Vault, a cloud secret manager, formalized Docker Secrets, or another enterprise secret-management system may be added later as additional `SecretsProvider` implementations, triggered by actual need (an enterprise/compliance tenant, or outgrowing single-VPS operation) — not installed or scaffolded now.
- Secret access is scoped per module/service identity — Product code cannot request Core's database credentials, and Control Plane tools cannot request raw infrastructure credentials or the full secrets store at all (see §6, which states the binding AI-specific rule this ADR's security consequences require).
- Secret rotation is a platform-level (Infra) capability; modules must tolerate rotation without restart where feasible (design constraint, not yet implemented).

## 5. Tenant Data Isolation

Full detail in `docs/MULTI-TENANCY.md`. Security summary: tenant scoping is enforced at the `infra/db` chokepoint (query layer), not left to individual query authors. This is treated as the platform's primary security boundary for customer data, and any code path that queries tenant-scoped data without going through the enforced chokepoint is a security defect.

## 6. AI Agent Permission Boundaries

This is the highest-consequence boundary in the platform, given the stated goal of autonomous DevOps/incident-response/support/development capability.

- **No ambient access, ever.** An AI agent never receives raw database credentials, raw infrastructure/cloud credentials, or an unscoped API key. All agent action against Core or Product happens through explicitly declared **tools** (see `docs/AI-CONTROL-PLANE.md`), each of which wraps exactly one bounded capability (e.g., "restart service X," "read tenant Y's support tickets," "propose a config change") and enforces RBAC/tenant-scoping identically to a human actor performing the same action.
- **No agent ever receives a `SecretsProvider` handle, a bulk export of the secrets store, or the full runtime environment** (`docs/ADR/0012-secrets-management.md`, binding). A secret reaches an agent's tool execution only when: (1) an explicitly declared, RBAC-scoped tool is invoked, (2) that tool's own definition names the specific secret(s) it needs, and (3) `infra/secrets` resolves and injects only that named secret into the tool's execution context — never into the agent's conversational context/memory, and never via a general-purpose "look up any secret by name" capability exposed to the agent. Every such access is audit-logged with the secret's *name*, never its value (§8). A tool may return a raw secret value into an agent's visible output only if doing so is that tool's explicit, reviewed purpose — never as an incidental side effect.
- **Every tool has a declared permission tier** (read-only / write-with-approval / write-autonomous), and a tool cannot be invoked by an agent whose identity has not been explicitly granted that tier for that tool.
- **Every agent identity is scoped** — to a tenant (for support/product agents acting on tenant data), to an environment (for DevOps/incident agents), or to a repository (for development agents) — and cannot act outside that scope regardless of what the tool technically permits.
- **Tool definitions live in `control-plane/tools/`, not in Core or Product code**, so the full set of capabilities an agent could ever exercise is enumerable by reading one directory — this is what makes "what could the AI possibly do" answerable without auditing the entire codebase.

## 6.1 AI Data Privacy Boundary

Per `docs/ADR/0013-ai-data-privacy-and-external-model-boundary.md` (Accepted): §6 above ("AI Agent Permission Boundaries") governs what an agent may *do* — this section governs what data may be *sent to an external AI/LLM provider* (Claude, OpenAI, DeepSeek, or any other), by an AI Control Plane agent or by a product-level feature calling an external provider directly. This is a distinct, independent boundary — passing §6's tool/RBAC check never implies data is cleared to cross this one. Nothing in this section is implemented yet; these are binding invariants for when it is:

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
3. The Self-Learning subsystem is AI Control Plane capability (`control-plane/self-learning`), never SaaS Core — SaaS Core must remain fully functional with it disabled (`docs/ARCHITECTURE.md` §2).
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
- Approval gates are themselves implemented as Control Plane workflow state (`control-plane/approvals`), not as a Slack message or out-of-band process — the approval action is itself audit-logged and attributable to a specific human.
- See `docs/AI-CONTROL-PLANE.md` for the sequencing of which capabilities get built at which autonomy level.

## 8. Audit Logging

- `core/audit-log` is the single append-only store for every privileged action platform-wide: human logins, permission changes, billing changes, and every AI agent tool invocation (including ones that were proposed but not approved, and ones that were denied by a permission check). Once the future Self-Learning subsystem (§6.2, Phase 9) is built, this includes: learning event creation, dataset access, feedback ingestion, candidate creation, evaluation, approval, rejection, experiment creation, canary deployment, promotion, rollback, and both policy-gate and autonomy-limit denials — reusing this same interface, never a second audit mechanism (`docs/AI-CONTROL-PLANE.md` §12's Learning Ledger is a distinct, additive lineage record, not a substitute for this store).
- Audit events are immutable and queryable by tenant, actor, and time range. Product code emits product-specific audit events through the same Core interface, using the extension pattern described in `docs/ARCHITECTURE.md` §9 (contract) — it does not maintain its own separate audit trail.
- AI agent audit entries always carry: agent identity, the tool invoked, the input, the approval record (if applicable), and the outcome — sufficient to answer "what did the AI do, on whose behalf, and was it approved" without additional investigation.

## 9. Data Classification (Directional)

Not yet formalized into policy, but the architecture anticipates at minimum: **tenant business data** (product-owned, isolated per §5), **platform account data** (Core-owned: identity, billing), **secrets/credentials** (never stored alongside application data), and **audit/observability data** (append-only, longer retention than operational data). A formal classification and retention policy is deferred to a phase where compliance requirements are known (see `docs/ARCHITECTURE-DISCOVERY.md` §17, and the open human decision on compliance target).

## 10. CI/Dependency Security (Infra-owned)

Implemented in Phase 1.4 (`docs/IMPLEMENTATION-ROADMAP.md`), running in CI's `security` job and locally via `scripts/check-security.sh`:

- **Dependency vulnerability scanning**: `pip-audit` (backend, queries the OSV database against the resolved Python environment) and `npm audit --audit-level=high` (frontend, against `frontend/package-lock.json`). A finding is fixed with the smallest compatible upgrade (a scoped `overrides` pin, not a forced major-version bump) or explicitly documented if no safe fix exists yet — never suppressed to force a green build.
- **Secret scanning**: `detect-secrets`, scanning git-tracked files against a committed `.secrets.baseline`. Known false positives (e.g., a placeholder connection string in `.env.example` matching a credential-shaped pattern) are recorded in the baseline as audited, not disabled globally — a genuinely new, unaudited finding still fails the check. Verified non-vacuous: a synthetic fake credential in a disposable, never-committed file was confirmed to be caught before this mechanism was relied upon.

Both scans run against repository/environment content only — no production environment or credential is required. Full detail: `README.md` "Security scanning".

## 11. Open Decisions

Identity provider (ZITADEL/OIDC), multi-tenancy model, API/deployment posture, and secrets architecture are now Accepted — see `docs/ADR/`. Still open: observability backend vendor (`docs/ADR/0009-...`) and compliance target. This document's boundary rules (§2–§8) hold regardless of which specific tools are chosen to implement the remaining open items. See `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` and `docs/PHASE-0.3-SECRETS-DECISION.md` for the current consolidated status.
