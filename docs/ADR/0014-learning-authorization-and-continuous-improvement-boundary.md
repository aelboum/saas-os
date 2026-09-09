# ADR-0014: Learning Authorization and the Self-Learning data boundary

Status: Accepted
Date: 2026-09-08
Supersedes / Superseded by: —

## Context

ADR-0004 establishes **Tool Authorization** ("can this agent invoke this tool?"). ADR-0013 establishes **Data Authorization** ("can this data reach an external AI/LLM provider for this one call?"). Neither answers a third, distinct question the proposed Self-Learning / Continuous Improvement subsystem (`docs/IMPLEMENTATION-ROADMAP.md` Phase 9) introduces: **can data a tool was authorized to access, and that was authorized to leave the platform for one inference, also be *retained or reused* to shape the platform's future behavior?**

These are genuinely independent questions. A support ticket's contents might legitimately be authorized to reach an external model to answer one customer question (Data Authorization, ADR-0013) without that same content being authorized for retention as a training/adaptation input reused across future requests or across tenants — retention and reuse introduce purpose-limitation, retention-period, and cross-tenant-contamination risks that a single-call transmission does not. Without an explicit answer, the default failure mode is a Self-Learning capability treating "this data was already cleared for one AI call" as sufficient justification to also learn from it indefinitely — silently widening ADR-0013's boundary by reinterpretation rather than by a reviewed decision, the same failure pattern ADR-0013 itself was written to prevent one layer up (an ad hoc external-provider call), and ADR-0004 one layer up from that (ambient tool access).

This decision must be recorded before the first Self-Learning phase (`docs/IMPLEMENTATION-ROADMAP.md` Phase 9.2) is built, for the same reason ADR-0004 and ADR-0013 were each recorded before their respective first capability was built: a boundary adopted after data has already been retained and reused is far harder to retrofit than one that is a starting constraint.

## Options Considered

### Option A — Treat Data Authorization (ADR-0013) as sufficient; no separate Learning Authorization gate
- Advantages: no new gate to design/implement; fewer moving parts before Phase 9 can start
- Disadvantages: conflates "may leave the platform once" with "may be retained and reused indefinitely" — two materially different risk profiles (a single-call disclosure vs. a standing influence on future behavior, potentially across tenants); recreates the exact reasoning-by-adjacent-precedent failure ADR-0013 itself rejected for tool access

### Option B — A third, independent Learning Authorization gate, evaluated in addition to (never instead of) Tool Authorization and Data Authorization, with an explicit default-deny and mandatory purpose/tenant/model/retention-period scoping
- Advantages: matches the shape already accepted for ADR-0004 and ADR-0013 — a single, auditable control point per concern rather than overloading one gate with two different questions; makes cross-tenant learning reuse an explicit, reviewed policy decision rather than an implicit side effect of Data Authorization already having passed; secure-by-default
- Disadvantages: a third gate to design, implement, and reason about before any Self-Learning capability ships; some additional latency/complexity per learning-input decision

### Option C — Fold Learning Authorization into `core/rbac`'s existing `can(actor, action, resource)` chokepoint rather than a separate AI Control Plane concept
- Advantages: reuses an already-built, already-trusted mechanism; no new evaluation path
- Disadvantages: `core/rbac` answers "is this actor permitted to perform this action" — a human-and-machine-uniform authorization model (`docs/SECURITY.md` §3) with no concept of data purpose, retention period, model/provider identity, or cross-tenant data reuse; forcing those concepts into RBAC's resource/action shape would either distort RBAC's own model or require RBAC to grow AI-specific knowledge it should not have, given SaaS Core must remain usable with the AI Control Plane fully disabled (`docs/ARCHITECTURE.md` §2)

## Recommendation

Option B.

## Decision

**Accepted.** Learning Authorization is a third, independent gate, evaluated in addition to (never instead of) Tool Authorization (ADR-0004) and Data Authorization (ADR-0013):

```
Tool Authorization (ADR-0004)   -- can this agent invoke this tool?
        |
Data Authorization (ADR-0013)   -- can this data reach an external AI provider, for this one call?
        |
Learning Authorization (this ADR) -- can this data be retained/reused to shape future behavior,
                                      for what purpose, for which tenant, for which model/provider,
                                      for how long?
        |
      DENY (default) or ALLOW, scoped
```

Passing an earlier gate never implies a later one passes. Cross-tenant learning reuse (Tenant A's data becoming a learning input that influences Tenant B) requires an explicit, separately authorized policy — the default is deny, identical in spirit to ADR-0013 §5's "unclassified data is denied."

### External input is evidence, not trusted policy

Binding on every future Self-Learning capability (`docs/IMPLEMENTATION-ROADMAP.md` Phase 9.2 onward): a learning input — user feedback, operator feedback, tool output, external content, model-generated content, or any other evidence originating outside the platform's own trusted decision-making — is **evidence to be evaluated by Learning Authorization, never a self-executing instruction**. Nothing about the mere existence, volume, or apparent confidence of such input authorizes retention, reuse, or a change in platform behavior on its own. This closes the specific failure mode this ADR exists to prevent: prompt injection carried in learning data, poisoned or malicious feedback, and malicious tool output must be denied the same default-deny treatment stated above as any other unauthorized learning input — an agent, tool, or model producing content is never, by that fact alone, sufficient authorization for that content to shape future behavior. A detailed evidence-classification taxonomy is deliberately not fixed here (see "What Is Deliberately Not Decided Here") — this principle binds regardless of how that taxonomy is eventually built.

### Learning Authorization does not grant policy authority

Passing this gate (or any of the three gates it composes with) governs only whether data may be retained/reused to shape *adaptive platform behavior* within the Self-Learning capability itself (`docs/AI-CONTROL-PLANE.md` §12's L1/L2/L3 levels). It never grants, implies, or substitutes for authority to modify:

- security policy or tenant isolation enforcement,
- RBAC/authorization policy (`core/rbac`'s `can(actor, action, resource)` chokepoint),
- secrets policy or `infra/secrets` access,
- autonomy-tier policy (`docs/AI-CONTROL-PLANE.md` §5's tier 0-3 framework).

Those remain governed exclusively by their own existing, authoritative mechanisms. A learning event, candidate, or proposal that is properly authorized under this ADR carries no standing authority over any of the above — an implementation that let a learning-derived change touch one of these boundaries would itself be an unauthorized policy modification, the exact threat this constraint exists to foreclose, independent of whether the learning data that produced it was otherwise properly authorized.

## What Would Be Difficult to Change Later

The same one-way-door pattern already identified for ADR-0004 and ADR-0013: a Self-Learning capability built once without this gate, that has already retained or reused tenant data to shape platform behavior, is difficult to fully unwind — the influenced behavior may already be deployed, and "which past adaptations were shaped by improperly authorized data" becomes a forensic question rather than one this boundary would have prevented outright. This is why the gate is recorded now, before Phase 9.2 is built, rather than retrofitted once a learning event already exists.

## What Is Deliberately Not Decided Here

Consistent with ADR-0013's own precedent:

- No Learning Ledger schema, storage table, or migration is created by this ADR (`docs/IMPLEMENTATION-ROADMAP.md` Phase 9.1 documents the conceptual shape only).
- No specific retention-period values, purpose taxonomy, or per-model/provider policy defaults are fixed here.
- No AI Control Plane code is built or modified by this ADR.
- No ranking or pre-approval of any model/provider for learning-reuse eligibility is made here.
- No legal/regulatory compliance determination is made here — remains the open compliance-target decision tracked in `docs/SECURITY.md` §11.

## Related

`docs/IMPLEMENTATION-ROADMAP.md` Phase 9 (Self-Learning & Continuous Improvement); `docs/AI-CONTROL-PLANE.md` §12 (Self-Learning, future); `docs/SECURITY.md` §6.1 (AI Data Privacy Boundary) and new §6.2; ADR-0004 (tool-mediated access — this ADR's action-authorization counterpart); ADR-0013 (AI data privacy and external-model boundary — this ADR's single-call-transmission counterpart, which this ADR is additive to, not a replacement for); ADR-0002 (multi-tenancy isolation — a prerequisite gate this boundary is additive to, exactly as ADR-0013 is).
