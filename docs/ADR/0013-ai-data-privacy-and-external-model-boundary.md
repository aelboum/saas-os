# ADR-0013: AI data privacy and external-model boundary

Status: Accepted
Date: 2026-09-07
Supersedes / Superseded by: —

## Context

`docs/AI-CONTROL-PLANE.md` and ADR-0004 establish a binding rule for **what an AI agent is allowed to do**: all Control Plane action against Core/Product happens through explicitly declared, individually scoped tools (tool-mediated access only). That rule constrains *actions*. It says nothing about a distinct, equally consequential question: **what data is an AI agent — or any future AI-assisted product feature — allowed to send to an external AI/LLM provider (Claude, OpenAI, DeepSeek, or any other)?**

Without an explicit answer, the default failure mode is a product (or a future Control Plane tool) passing an unrestricted tenant/user record — full customer object, full database row, full support-ticket thread — to an external provider's API because it was the easiest way to get a task done. This is a real risk specifically because the platform's stated ambitions include SaaS products (e.g., MarocAssist, `docs/ARCHITECTURE-DISCOVERY.md`) whose tenant data may contain PII or other sensitive information, and because the platform's own AI Control Plane (`docs/AI-CONTROL-PLANE.md` §4, §7) is designed to eventually read tenant-scoped data on a tenant's behalf.

Tool-mediated access (ADR-0004) answers "what can the AI do." This ADR exists to answer the orthogonal question: "what can the AI see or transmit externally" — **data authorization**, not action authorization. Both are required; neither substitutes for the other. This decision must be recorded now, before any AI-consuming product feature or Control Plane tool is built, for the same reason ADR-0004 was recorded before any agent was built: a boundary adopted after the first ad hoc external-API call already exists is far harder to retrofit than one that is a starting constraint every future AI-touching code path is built against.

## Options Considered

### Option A — No platform-level boundary; each product/feature decides for itself what data to send externally
- Advantages: no upfront design cost; fastest to ship a first AI feature
- Disadvantages: recreates exactly the failure mode ADR-0004 rejected for tool access, one layer down — "what data could ever reach an external AI provider" becomes an audit of every product's own ad hoc code, not an enumerable platform property; a single careless integration in any product leaks tenant data to a third party with no platform-level control point to have prevented it

### Option B — A mandatory platform-level data boundary between any internal data source and any external AI provider, enforcing classification, minimization, and policy before data crosses that boundary
- Advantages: matches the shape already accepted for tool access (ADR-0004) and for infrastructure secrets (ADR-0012) — a single, auditable control point rather than per-feature discipline; lets tenant-specific and provider-specific policy be enforced centrally instead of trusted to every future developer; secure-by-default (unclassified data denied) rather than secure-by-convention
- Disadvantages: real design and implementation cost before the first AI feature can ship; some latency/complexity overhead per AI-provider call; requires a data-classification taxonomy that does not fully exist yet

### Option C — Boundary enforced only inside the AI Control Plane (agents), with no equivalent constraint on product-level AI features (e.g., a product calling an LLM directly for a feature)
- Advantages: narrower scope, less upfront work; matches the Control Plane's existing tool-mediated-access framing
- Disadvantages: leaves exactly the gap this ADR exists to close — a product feature that calls an external AI provider directly (not through the Control Plane) would be entirely unconstrained; the risk this ADR is written to prevent (an unrestricted customer record reaching an external provider) is at least as likely to originate in product code as in Control Plane agent code

## Recommendation

Option B.

## Decision

**Accepted.** SaaS-OS establishes a mandatory **AI Data Privacy / External Model Boundary** as a platform-wide architectural invariant, binding on both AI Control Plane agents and any product-level feature that calls an external AI/LLM provider. This ADR fixes the *principles and control-point shape*; it does **not** implement the boundary, and no code, data-classification table, or policy-storage schema is created by this decision. Implementation is future work, sequenced with the AI Control Plane (`docs/IMPLEMENTATION-ROADMAP.md` Phase 7+, see "Related" below).

### 1. Sensitive data must not flow directly to an external AI provider

No code path — Product, Core, or AI Control Plane — may send tenant/user data to an external AI/LLM provider without first passing through the approved data-authorization boundary. Concretely prohibited patterns:

```
Product          -> OpenAI API           -> full customer record
Product          -> DeepSeek API         -> full tenant database object
AI Control Plane -> arbitrary DB query   -> external model
```

This is the data-plane analogue of ADR-0004's tool-mediated-access rule: just as no agent may act on Core/Product except through a declared tool, no data may reach an external model except through the declared data boundary.

### 2. Data minimization is mandatory, not incidental

Only the minimum data required for the specific AI task may cross the external-model boundary. The eventual implementation must support **policy-driven**: data classification, minimization, redaction, and anonymization/pseudonymization where appropriate, provider eligibility, tenant policy, and use-case policy. None of these mechanisms are implemented by this ADR — it establishes that they are required, not what they look like in code.

### 3. Provider trust is not equivalent across providers

The platform must not assume every AI provider offers identical data retention, training/use policy, data residency, contractual protection, security posture, subprocessor chain, or regulatory standing. Provider eligibility is therefore **policy-driven configuration**, not a hardcoded trust assumption — this ADR does not rank or pre-approve any specific provider as a permanent fact; that determination belongs to the future policy implementation and may differ per tenant or per data class.

### 4. Tenant-scoped AI data policy

A tenant must eventually be able to hold an explicit AI data policy governing what may be done with its data:

```
Tenant
  -> AI Data Policy
       -> Allowed data classes
       -> Allowed providers
       -> Allowed use cases
       -> Retention requirements
       -> Processing restrictions
```

No storage schema, table, or API for this policy is created by this ADR (see "What Is Deliberately Not Decided Here").

### 5. Secure default: unclassified data is denied

```
Unknown or unclassified sensitive data
  -> DENY
```

The boundary must not depend on a developer remembering to redact something manually. Data that has not been classified is treated as sensitive by default and blocked from crossing the boundary until classified and permitted by policy.

### 6. Relationship to tenant isolation (ADR-0002) and tool-mediated access (ADR-0004)

This boundary is additive to, not a replacement for, the platform's existing security invariants: tenant isolation (ADR-0002, `docs/MULTI-TENANCY.md`) must already hold for any data an AI process reads, and tool-mediated access (ADR-0004) must already hold for any action an AI agent takes to obtain that data. The AI data boundary is a *third*, independent gate — data that is correctly tenant-scoped and correctly obtained via an authorized tool can still be denied at this boundary if it is not classified/minimized/policy-approved for external transmission.

### The reference shape (future implementation, not built by this ADR)

```
            Tenant Data
                |
                v
          Data Classification
                |
                v
          Policy Decision
             /        \
          DENY        ALLOW
                        |
                        v
               Data Minimization
                        |
                        v
                Provider Policy
                        |
                        v
                 External AI Provider
```

## Rejected Alternatives

- **No platform-level boundary (Option A)**: rejected — recreates the exact per-feature-discipline failure mode ADR-0004 already rejected for tool access, for a risk (external data exfiltration) at least as consequential.
- **Control-Plane-only boundary (Option C)**: rejected — a product feature calling an external AI provider directly is an equally real, arguably more likely, path for the exact harm this ADR exists to prevent; the boundary must be platform-wide, not scoped to one subsystem.

## What Would Be Difficult to Change Later

Exactly the same one-way-door pattern already identified for ADR-0004: an AI-consuming feature built once "temporarily" without going through the data boundary establishes a precedent, a shipped behavior tenants may come to depend on, and a code path that is difficult to fully excise once tenant data has already been transmitted to an external provider under it. This is why the invariant is recorded now, before the first AI Control Plane tool or product AI feature is built, rather than retrofitted once one exists.

## What Is Deliberately Not Decided Here

Consistent with the instruction that produced this ADR, the following are explicitly **out of scope** and must not be inferred as implemented or as fixed for all time by this decision:

- No AI Gateway, redaction service, or classification engine is built.
- No data-classification taxonomy is finalized — categories such as PII, authentication/session credentials, financial information, government identifiers, health information, private tenant business data, secrets, access tokens, API keys, passwords, and private documents are illustrative of what a future taxonomy must consider, not a fixed, exhaustive, or legally-authoritative classification adopted here.
- No database table or storage schema for tenant AI policy is created.
- No provider is ranked, pre-approved, or permanently trusted/distrusted.
- No AI Control Plane code is built or modified by this ADR.
- No legal/regulatory compliance determination (GDPR, HIPAA, etc.) is made here — that remains the open compliance-target decision already tracked in `docs/SECURITY.md` §11.

## Related

`docs/AI-CONTROL-PLANE.md` (Tool Policy vs. Data Policy); `docs/SECURITY.md` §6 (AI Agent Permission Boundaries), new "AI Data Privacy Boundary" section; `docs/DATA-ARCHITECTURE.md` (tenant data vs. AI-processing-eligible data); `docs/IMPLEMENTATION-ROADMAP.md` Phase 7 (AI Control Plane v0); ADR-0002 (multi-tenancy isolation — a prerequisite gate this boundary is additive to); ADR-0004 (tool-mediated access — the data-authorization analogue of this ADR's action-authorization counterpart); ADR-0012 (secrets management — AI provider credentials flow through the same `SecretsProvider` architecture, not a new mechanism).
