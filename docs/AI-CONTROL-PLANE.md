# AI Control Plane Architecture

Status: Boundary rules and approval-gate framework ACCEPTED. Execution substrate (Redis+ARQ jobs now; workflow engine deferred, per `docs/ADR/0007-...`) ACCEPTED. Secrets access model (per `docs/ADR/0012-...`) ACCEPTED. Agent runtime/model provider PROPOSED pending `docs/ADR/`. Self-Learning / Continuous Improvement (§12): Learning Authorization (`docs/ADR/0014-...`) ACCEPTED; no Self-Learning runtime code, table, or migration exists yet (Phase 9.1 package/schema-ownership scaffold only). No agents are built yet.

## 1. Purpose

The AI Control Plane is the layer that lets AI agents operate the platform (autonomous DevOps, incident resolution, customer support) and build it (autonomous development), without ever becoming a second, unaccountable way to bypass the boundaries defined in `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, and `docs/MULTI-TENANCY.md`.

## 2. The Governing Rule

**The AI Control Plane may interact with SaaS Core and Product modules only through explicitly defined tools/interfaces.** It never:

- Imports or calls Core/Product internal code directly.
- Holds ambient database, infrastructure, or cloud credentials, or any handle to the secrets store itself (see §3, "Tool Secrets Access," and `docs/ADR/0012-secrets-management.md`).
- Receives a broader permission scope than a human performing the equivalent action would receive under RBAC.

Everything an agent can possibly do is enumerable by reading `control-plane/tools/` — this is the property that makes the platform's AI capability auditable rather than an open-ended risk surface.

### 2.1 Tool Authorization vs. Data Authorization (`docs/ADR/0013-ai-data-privacy-and-external-model-boundary.md`, Accepted)

The rule above governs **what an agent can do** — Tool Authorization. It is necessary but not sufficient: a tool can be correctly scoped by RBAC and tenant (§7) and still, once invoked, hand the data it reads to an external AI/LLM provider without restriction. ADR-0013 establishes a second, independent gate — **Data Authorization** — governing **what data may cross the boundary to an external AI/LLM provider**, regardless of which tool or agent produced it.

```
AI Control Plane
     |
     +--> Tool Policy   ("can this agent invoke this tool?")   -- this section, §3-§7
     |
     +--> Data Policy   ("can this data reach an external model?") -- ADR-0013
                |
                v
        AI Data Boundary
                |
                v
        External AI Provider
```

Both gates are described architecture, not implemented code — no AI Gateway, classification engine, or data-policy store exists yet (ADR-0013 §"What Is Deliberately Not Decided Here"). The point recorded now is that a tool passing its RBAC/tenant-scope check (Tool Authorization) never implies the data it touches is cleared for external-provider transmission (Data Authorization) — the two checks are independent, and a future tool implementation must satisfy both, not treat one as a proxy for the other. See `docs/SECURITY.md` "AI Data Privacy Boundary" for the binding invariant list.

## 3. Tool Registry

A **tool** is the atomic unit of AI Control Plane capability. Each tool:

- Wraps exactly one bounded action (e.g., `restart_service`, `read_tenant_support_tickets`, `propose_config_change`, `open_pull_request`) — never a general-purpose "run arbitrary code/query" escape hatch.
- Is implemented using Core's public interfaces or a Product's declared contract (`docs/ARCHITECTURE.md` §9, `aiTools` field) — never by reaching into internals.
- Declares its own required RBAC permission and default autonomy tier (§5).
- Declares its own scope constraints (tenant-scoped, environment-scoped, repo-scoped — see `docs/SECURITY.md` §6).
- Is independently testable and independently revocable — disabling one tool does not require disabling the agent runtime.

`control-plane/orchestration` owns the mechanism for registering, invoking, and sandboxing tool calls; it owns no business logic itself.

### Tool Secrets Access (Accepted, `docs/ADR/0012-secrets-management.md`)

A tool that needs a secret (a third-party API key, a service credential) **declares which named secret(s) it requires as part of its own definition** — it does not receive a `SecretsProvider` handle or any ability to request an arbitrary secret by name at invocation time. When such a tool is invoked:

1. `control-plane/orchestration` resolves the tool's declared secret name(s) against `infra/secrets`.
2. The resolved value is injected **into the tool's execution context only** — never into the invoking agent's conversational context, prompt, or memory, and never returned in the tool's output unless returning that value is the tool's explicit, reviewed purpose (e.g., a support tool that surfaces a tenant's own API key back to that tenant).
3. The invocation is audit-logged with the secret's **name**, never its value, alongside the standard tool-invocation record (agent identity, tool, approval state, outcome — `docs/SECURITY.md` §8).

No tool is ever defined with unscoped access to "the secrets store" as a whole — this would recreate the ambient-access risk §2 exists to prevent, just one layer down.

## 4. Agent Categories

Distinguished by trust level and what they act on — not interchangeable, and not built in the same phase:

| Category | Acts on | Notes |
|---|---|---|
| **Autonomous development** | This platform's own codebase | Lowest blast radius: output is code changes subject to normal review/CI gates, not direct production action. Reasonable first capability to build. |
| **Autonomous customer support** | Tenant-scoped product data + a product's declared `supportKnowledge` (`docs/ARCHITECTURE.md` §9) | Bounded by RBAC to the tenant in question; mostly read-heavy; escalates outside a defined confidence/scope boundary. |
| **Autonomous incident resolution** | Observability data (`docs/OBSERVABILITY.md`) + a pre-approved remediation tool set | Executes only pre-approved "safe" remediation classes autonomously (§5, tier 2); escalates everything else. |
| **Autonomous DevOps** | Infrastructure/deployment (`docs/DEPLOYMENT-ARCHITECTURE.md`) | Highest blast radius; defaults to propose + human approval (§5, tier 1) until a narrow, pre-vetted action set earns tier 2. |

## 5. Autonomy Tiers and Human Approval Gates

Restated from `docs/SECURITY.md` §7 as the binding framework for every tool:

| Tier | Behavior | Approval mechanism |
|---|---|---|
| 0 — Propose only | Agent produces a recommendation; no action taken | None needed (no action to gate) |
| 1 — Propose + approval | Agent stages an action via `control-plane/approvals`; a scoped human role must approve before execution | Approval is itself an audited, attributable action — not an out-of-band chat message |
| 2 — Auto-execute + audit | Agent executes without a prior human checkpoint, strictly limited to a pre-vetted, narrow action list | Every execution is logged to `core/audit-log` and reviewable; the *list* of tier-2-eligible actions is itself a human-approved, versioned artifact |
| 3 — Fully autonomous | No standing checkpoint at all | Not enabled for any capability at this stage |

- A tool is created at tier 0 or 1 by default. Promotion to tier 2 requires an ADR citing demonstrated reliability evidence (not a default or a convenience decision).
- No tool is ever created at tier 3 without a separate, explicit, documented human decision — this document does not pre-authorize it for anything.

## 6. Sequencing (Build Order)

Per `docs/ARCHITECTURE-DISCOVERY.md` §19, capabilities are built in ascending order of blast radius:

1. Autonomous development (tier 0/1, acting on this repo, gated by normal PR review)
2. Autonomous customer support (tier 0/1, RBAC- and tenant-scoped, mostly read-heavy)
3. Autonomous incident resolution (tier 1, narrow tier-2 promotions only after audit trail is proven)
4. Autonomous DevOps (tier 1, the last to receive any tier-2 promotion, given highest blast radius)

No capability in this list is built until `core/audit-log`, `core/rbac`, and the approval-gate mechanism (`control-plane/approvals`) exist and are proven — audit/approval infrastructure is a prerequisite, not a parallel workstream.

## 7. Agent Identity and Scoping

- Every agent has its own identity in `core/identity`, distinct from any human user, authenticated and authorized through the same mechanisms (`docs/SECURITY.md` §2–§3) as any other principal. Per `docs/ADR/0005-identity-build-vs-buy.md`, agent identities are **not** authenticated via ZITADEL's human OIDC login flow — they are issued and verified through a separate machine-identity mechanism inside `core/identity`, but resolve to the same identity-context shape human sessions do, so `core/rbac` and every tool's permission check treat both uniformly.
- Every agent identity carries an explicit scope: a tenant (support/product agents), an environment (DevOps/incident agents), or a repository (development agents). A tool invocation outside an agent's declared scope is rejected at the authorization layer, independent of whether the tool itself would technically permit it.
- **Execution substrate (Accepted, `docs/ADR/0007-background-job-and-workflow-engine.md`)**: multi-step, stateful, or compensating agent workflows (e.g., an incident-response agent needing several tool calls in sequence with rollback-on-failure semantics) must **not** be built on top of the Redis-backed `infra/jobs` queue by hand-rolling state tracking — that queue is reserved for genuinely single-step-retryable tasks. Any Control Plane capability that needs multi-step durability is the trigger to introduce a durable workflow engine (e.g., Temporal) as an additional execution substrate, evaluated when that capability is actually built (`docs/IMPLEMENTATION-ROADMAP.md` Phase 7+) — not before, and not by working around the constraint.

## 8. Model/Provider

Given this platform is being built using Claude Code / the Claude Agent SDK, that is the directional default runtime for the Control Plane's agents. Whether to additionally build a model-provider-agnostic abstraction (vs. committing to a single provider) is an open decision — see `docs/ADR/`. The tool-boundary architecture in this document (§2–§4) is provider-independent either way: tools are the interface an agent runtime calls, regardless of which model sits behind that runtime.

## 9. Kill Switch / Blast Radius Limits

Anticipated as a design requirement, not yet implemented: a platform-operator-level ability to immediately disable a specific tool, a specific agent identity, or the entire Control Plane, independent of the normal deployment pipeline (i.e., not requiring a full redeploy to take effect). This is a prerequisite for any tool being promoted to tier 2 (§5).

## 10. Relationship to the Product Contract

A Product's declared `aiTools` field (`docs/ARCHITECTURE.md` §9) is the *only* way an agent gains any capability to act on that specific product — a product that declares no `aiTools` is, by construction, unreachable by the Control Plane beyond whatever generic Core-level tools apply to every tenant equally (e.g., generic support-ticket read access, if granted). This is what lets the platform onboard new products without the Control Plane's capability surface growing implicitly.

## 11. What Is Hard to Change Later

An agent that is ever given ambient/unscoped access "temporarily, to move faster" establishes a precedent and a code path that is difficult to fully excise later — the tool-mediated-access rule (§2) must hold from the very first agent built, including internal development-support tooling, or it stops being a real boundary anywhere.

## 12. Self-Learning / Continuous Improvement (Future, `docs/IMPLEMENTATION-ROADMAP.md` Phase 9)

Anticipated as a design requirement, not yet implemented — no `control-plane/self-learning` code, table, or migration exists. Recorded here so its architectural placement is decided before it is built, the same discipline §9's kill switch already follows.

**Layer**: Self-Learning is AI Control Plane capability, never SaaS Core (`docs/ARCHITECTURE.md` §1–§2) — it observes and adapts the behavior of AI Control Plane agents/tools and has no meaning independent of that layer. SaaS Core must remain fully functional with the AI Control Plane and Self-Learning both disabled, and must never acquire a dependency on an LLM/agent/learning framework.

**Three learning levels** — describe *what kind of change* a capability may propose, independent of the autonomy tiers in §5 (which describe *how much standing autonomy* it has to apply that change without a human; every Self-Learning capability declares both):

| Level | May do | Must not do |
|---|---|---|
| 1 — Adaptive Learning | Versioned, reversible adaptations: prompt/instruction candidates, model selection/routing, tool selection, retrieval/response strategy, permitted personalization, learning from explicit feedback/operator corrections | Modify source code, database schemas, security policies, authorization, or secrets; deploy infrastructure; bypass approval/policy; access unrestricted tenant data |
| 2 — System Learning | Discover recurring problems (agent/tool failures, support/latency/cost/routing/workflow problems, missing regression tests, recurring policy violations) and produce a structured **improvement proposal** | Apply the proposal to production automatically — output is a proposal, never an arbitrary production modification |
| 3 — Autonomous Improvement | Bounded autonomous improvement: Observation → Hypothesis → Candidate → Automated Evaluation → Benchmark → Regression Tests → Policy Gate → Canary → Monitoring → Promote OR Rollback | Operate without a policy gate (§5's tiers still apply — tier 3, fully autonomous with no standing checkpoint, remains not enabled for anything, including this) |

**Tool Authorization vs. Data Authorization vs. Learning Authorization**: §2.1 above establishes Tool Authorization (this document) and Data Authorization (ADR-0013) as independent gates. Self-Learning introduces a third — **Learning Authorization** (ADR-0014, Accepted) — governing whether data already cleared to reach an external provider for one call may also be *retained or reused* to shape future behavior:

```
AI Control Plane
     |
     +--> Tool Policy       ("can this agent invoke this tool?")            -- §3-§7, ADR-0004
     |
     +--> Data Policy       ("can this data reach an external model, once?") -- ADR-0013
     |
     +--> Learning Policy   ("can this data be retained/reused to learn?")   -- ADR-0014 (Accepted)
                |
                v
        Learning Authorization Boundary
                |
                v
        Self-Learning / Continuous Improvement
```

Passing an earlier gate never implies a later one passes. Default is **DENY**. Learning from Tenant A's data must never become learning data for Tenant B absent an explicit, authorized policy.

**Learning Ledger — not a second `core-audit-log`**: the future lineage record (Observation → Learning Event → Hypothesis → Experiment → Evaluation → Candidate → Approval → Deployment → Outcome → Rollback/Promotion) belongs to `control-plane/self-learning`, under its own schema/table set — never `core.*`. `core/audit-log` (§8 above, `docs/SECURITY.md` §8) remains the platform's one append-only security/audit trail; every learning-related privileged action is *additionally* recorded through `core/audit-log`'s existing interface, the same way `core/api-keys` and `core/feature-flags` already do, never via a parallel audit mechanism.

**Evaluation before promotion**: a candidate is compared against a baseline on the same benchmark before any promotion decision — task success, hallucination/error rate, latency, cost, tool success, user feedback, safety violations, and regression rate are illustrative metrics. An LLM's own claim that a candidate is better is never, by itself, sufficient evidence for promotion.

**Threat model**: prompt injection through learning data; poisoned or malicious feedback; malicious tool output used as a learning input; cross-tenant contamination; reward hacking; evaluation manipulation; self-reinforcing incorrect behavior; autonomous privilege escalation; model/provider data leakage; unauthorized policy modification; unsafe automated deployment; rollback failure; corrupted learning datasets. Binding principle: **external input is evidence, not trusted policy** — a learning event never automatically becomes trusted truth merely because an agent, tool, or model produced it.

Full phase-by-phase decomposition: `docs/IMPLEMENTATION-ROADMAP.md` Phase 9 (9.1 Learning Foundation through 9.9 Continuous Improvement Loop).
