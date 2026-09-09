# ADR-0004: AI Control Plane — tool-mediated access only

Status: Accepted
Date: 2026-09-06
Supersedes / Superseded by: —

## Context

The platform's stated ambitions include autonomous DevOps, incident resolution, customer support, and development. These are the highest-blast-radius capabilities in the entire system. A boundary rule is needed for how AI agents are permitted to act on Core and Product, before any agent is built.

## Options Considered

### Option A — Agents receive scoped ambient credentials (e.g., a restricted DB role, a limited cloud IAM role) and call existing internal code/APIs directly
- Advantages: less upfront design work; reuses existing internal interfaces
- Disadvantages: "what could the AI possibly do" becomes an audit of arbitrary internal code paths rather than an enumerable list; scope creep is easy (an agent granted DB read "for one feature" tends to accumulate more access over time); does not compose cleanly with per-action RBAC or per-action audit logging

### Option B — All agent action against Core/Product happens exclusively through explicitly declared, individually scoped "tools," each wrapping one bounded capability, authorized identically to a human action under RBAC
- Advantages: the full capability surface is enumerable (read `control-plane/tools/`); every tool independently carries its own permission tier, scope constraint, and audit entry; a tool can be individually disabled without disabling the agent runtime; matches the platform's stated goal of increasing autonomy gradually and safely
- Disadvantages: more upfront design per capability (a tool must be explicitly built and scoped before an agent can do a new thing); cannot "quickly" grant an agent a new ad hoc capability without going through the tool-definition process

## Recommendation

Option B.

## Decision

Accepted. Documented in `docs/AI-CONTROL-PLANE.md` §2–§4 and `docs/SECURITY.md` §6. This is treated as non-negotiable given the platform's autonomous-operations goals — the disadvantage (more upfront design per capability) is accepted as the cost of the capability surface remaining auditable.

## What Would Be Difficult to Change Later

Any agent given ambient/unscoped access "temporarily" establishes both a precedent and a code dependency that is hard to fully remove later, and undermines the enumerability property for every other tool built after it. This rule must hold from the very first agent built (including internal development-support tooling), or it is not a real boundary anywhere in the system.

## Related

`docs/AI-CONTROL-PLANE.md`; `docs/SECURITY.md` §6–§7; ADR-0001.
