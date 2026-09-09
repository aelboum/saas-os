# Phase 0.3 — Secrets Management Decision

Status: COMPLETE. This document is the decision record and documentation-consistency review for the final Phase 0 architectural precondition: secrets management.

Date: 2026-09-06

Numbering note: the language/runtime/toolchain resolution (Python/FastAPI/etc., `docs/ADR/0011-...`) was handled as an addendum inside `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` rather than its own file. This decision — secrets management — is given its own file per explicit instruction, numbered 0.3 to follow that resolution in sequence.

## 1. Approved Decision

**Accepted** (`docs/ADR/0012-secrets-management.md`): the platform defines a provider-agnostic `SecretsProvider` interface in `infra/secrets`. **No module — Core, Product, or the AI Control Plane — ever depends on a specific secrets-management product directly.**

```
SecretsProvider
├── Development implementation           — .env (local only, gitignored, never committed)
├── Docker/host production implementation — runtime injection into the container at
│                                            start-up (Docker Compose secrets: mounts or
│                                            host-supplied env), never baked into images
└── Future external secret-manager implementations
    (HashiCorp Vault, cloud secret managers, formalized Docker Secrets,
     other enterprise systems) — NOT installed, deployed, or scaffolded now
```

### Development rules (binding)

- `.env` permitted for local development only.
- `.env.example` documents every required variable with placeholder values — no real secret, ever.
- `.env` is gitignored from the commit that introduces it.
- No real credential is ever committed, anywhere, enforced by CI secret-scanning (`docs/SECURITY.md` §10).

### Initial production rules (binding)

- Secrets are injected into the running container at start-up on the VPS (environment variables or Docker Compose `secrets:`-mounted files), sourced from the host or the deploy step.
- Never baked into a Docker image layer; never committed to source control, including inside a committed `docker-compose.yml` (which may name *where* a secret comes from, never its value).

### AI Control Plane rule (binding, the specific requirement this task called out)

An AI agent never receives a `SecretsProvider` handle, a bulk export of the secrets store, or the full runtime environment. A secret reaches an agent's tool execution only when: an explicitly declared, RBAC-scoped tool is invoked; that tool's own definition names the specific secret(s) it needs; `infra/secrets` injects only that named secret into the tool's execution context (never into the agent's conversational context/memory); and the invocation is audit-logged with the secret's name, never its value. Full detail in `docs/AI-CONTROL-PLANE.md` §3 "Tool Secrets Access" and `docs/SECURITY.md` §6.

## 2. Rationale

- **Consistency with the platform's existing anti-lock-in pattern**: this is the third time the platform has faced "a critical dependency needs a concrete backend without coupling Core to it" — billing (ADR-0008, provider-abstraction + Stripe adapter) and identity (ADR-0005, OIDC-standard integration rather than a proprietary IdP SDK) both resolved this the same way. Secrets management follows the same shape: one interface, swappable implementations. A platform meant to outlive any single vendor choice should solve this class of problem once, not three different ways.
- **Matches the accepted deployment target**: the Docker/host production implementation is the natural fit for `docs/ADR/0010-deployment-target.md`'s Docker Compose + VPS choice — it requires no new infrastructure component, consistent with that ADR's stated goal of minimal operational surface at this stage.
- **Directly satisfies the explicit instruction not to install Vault now**: the interface exists specifically so that instruction is honorable without foreclosing Vault later — the platform gets the architectural benefit of "secrets are abstracted" today without paying Vault's operational cost today.
- **The AI-specific rule closes the platform's single highest-consequence gap** if left open: an autonomous DevOps/incident-response capability with unscoped secrets access would be the most damaging possible failure mode for this platform's stated ambitions (`docs/ARCHITECTURE-DISCOVERY.md` §23, `docs/AI-CONTROL-PLANE.md` §2). Defining the scoped-access model now, before any agent or tool exists, means it is a starting constraint every future tool is built against, not a retrofit.

## 3. Rejected Alternatives

Recorded in full in `docs/ADR/0012-secrets-management.md`; summarized here:

- **No interface, hardcoded mechanism** (e.g., every module reads `os.environ` directly) — rejected: recreates the exact coupling risk the platform's core dependency rule and the billing/identity ADRs exist to prevent, for a dependency every module touches.
- **Adopt Vault (or a cloud secret manager) now** — rejected per explicit instruction, and for the same reasoning that rejected Kubernetes-now in ADR-0010: operational overhead/cloud coupling not justified before demonstrated need.
- **"Encrypted secrets committed to the repo"** — considered and rejected: the decryption key still has to live somewhere outside the repo, which is just the Docker/host production implementation with an extra step; it does not solve the underlying problem, so it was not adopted as a distinct mechanism.

## 4. Future Migration / Extension Path

A future `SecretsProvider` implementation (Vault, a cloud secret manager, formalized Docker Secrets, another enterprise system) is added as a new adapter behind the existing interface — triggered by an enterprise/compliance tenant requirement or by the platform outgrowing single-VPS operation, paralleling the escape hatches already defined for multi-tenancy (`docs/ADR/0002-...`, dedicated database per tenant) and deployment (`docs/ADR/0010-...`, Kubernetes/managed platform). Because calling code depends only on the interface, this migration touches `infra/secrets` and deployment configuration only.

## 5. Security Consequences

- Reduces the blast radius of a source-control leak to zero for secret material — a leaked repository never contains a real credential.
- Centralizes secret-handling risk to one module (`infra/secrets`) instead of spreading ad hoc environment reads across the codebase.
- **Residual, explicitly accepted risk**: a compromised VPS host has access to every secret injected into containers running on it. This is inherent to the already-accepted single-VPS, no-external-secrets-manager posture (`docs/ADR/0010-...`'s own disadvantages list) — not a new risk introduced here, and the concrete reason a future external secrets manager remains on the roadmap.
- Establishes the binding AI secrets-access model (§1) before any agent exists, closing what would otherwise be the platform's most consequential open permission gap.

## 6. Documentation Updated

- `docs/ADR/0012-secrets-management.md` — new, Accepted.
- `docs/ADR/README.md` — index entry added.
- `docs/ARCHITECTURE.md` — §4 module ownership (`infra/secrets` row), §10 technology-decisions table (new Secrets row; removed from "still open" list), §11 related-documents list.
- `docs/SECURITY.md` — §4 Secrets Management rewritten (dev/prod/future implementations, binding rules); §6 AI Agent Permission Boundaries gains an explicit secrets-scoping clause; §11 open-decisions list updated; status header updated.
- `docs/DEPLOYMENT-ARCHITECTURE.md` — §4 Secrets in Deployment rewritten as Accepted, with the concrete Docker/host injection mechanism and the interface-boundary note tying it to the future Kubernetes/external-secrets-manager migration paths.
- `docs/AI-CONTROL-PLANE.md` — §2 governing rule gains an explicit secrets clause; new "Tool Secrets Access" subsection under §3; status header updated.
- `docs/IMPLEMENTATION-ROADMAP.md` — Phase 2.3 rewritten with the two concrete implementations and expanded tests/acceptance criteria; Phase 7.1 gains secrets-injection scope, tests, and a security requirement; Cross-Cutting Rules gains a merge-blocking rule against secret-consuming call sites outside the interface.
- `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` — secrets-backend item marked resolved in §2 and §6, cross-referenced to this document.

## 7. Consistency Review

Performed against the same categories as the Phase 0.1 review, scoped to this addition.

- **Contradictory technology choices**: none found. The Docker/host production implementation is a direct, non-conflicting application of the already-Accepted Docker Compose + VPS target (`docs/ADR/0010-...`); it introduces no new infrastructure component and no competing mechanism.
- **Undefined ownership**: none found. `infra/secrets` was already the designated owner of secret retrieval (`docs/ARCHITECTURE.md` §4) prior to this decision; this ADR fills in *how*, not *who*.
- **Circular dependencies**: none. `infra/secrets` remains a leaf Infra module — Core, Product, and Control Plane depend on it; it depends on nothing above it. External systems it may eventually integrate (Vault, a cloud provider) are outside the platform's own dependency graph, same as ZITADEL and Stripe.
- **Unclear tenant boundaries**: not applicable to this decision; unaffected.
- **Unclear identity boundaries**: not applicable; unaffected. (Secrets used *by* `core/identity` — e.g., an OIDC client secret — are retrieved through `SecretsProvider` like any other module's secrets; no special path.)
- **Unclear API ownership**: not applicable; unaffected.
- **Unclear deployment ownership**: none found post-update — `docs/DEPLOYMENT-ARCHITECTURE.md` §4 now states the concrete mechanism and its owner (`infra/deploy` wires up the Docker/host implementation) without ambiguity.
- **Unclear AI permissions**: this was the primary risk this task existed to close. Resolved explicitly by the scoped tool-secrets-access model (§1, `docs/AI-CONTROL-PLANE.md` §3, `docs/SECURITY.md` §6) — a secret is reachable by an agent only via a tool that declares it by name, never as ambient or bulk access. Checked against the existing tool-mediated-access rule (`docs/ADR/0004-...`) for conflict: none — this is a refinement of that rule for the specific case of secret material, not a competing rule.
- **Future migration blockers**: one identified and mitigated the same way prior ADRs handle this class of risk — if a future call site reads a secret by any path other than `SecretsProvider` (a direct env read, a hardcoded provider SDK call), that call site becomes invisible to the abstraction and must be found and rewritten under security pressure when the backend eventually changes. Mitigated by the new Cross-Cutting Rule in `docs/IMPLEMENTATION-ROADMAP.md` making this a merge-blocking defect from Phase 1 onward, and by CI secret-scanning (`docs/SECURITY.md` §10) catching committed real secrets as a backstop.

No contradictions were found between ADR-0012 and any of ADR-0001 through ADR-0011.

## 8. Remaining Unresolved Decisions (Unchanged by This Task)

Carried forward from `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` §2, none affected by this decision:

| Decision | Status | Blocks |
|---|---|---|
| Observability backend vendor | Open (`docs/ADR/0009-...`) | Nothing before Phase 2.2 ships a production exporter |
| Compliance target (SOC2/GDPR/etc.) | Open, no urgency | Formal data-classification/retention policy only |
| AI Control Plane model/provider abstraction | Open | Phase 7 (AI Control Plane v0) |
| Python/Node package manager choice | Open, low-stakes, explicitly out of ADR scope | Phase 1.2 directly |

None of these block any part of Phase 1 or Phase 2.

## 9. Is Phase 0 Now Fully Unblocked?

**Yes.** Both gaps tracked as Phase 0 preconditions are resolved:

1. Language/runtime and toolchain (`docs/ADR/0011-...`) — resolved in the prior session, recorded as an addendum in `docs/PHASE-0.1-ARCHITECTURE-REVIEW.md` §6.
2. Secrets management (`docs/ADR/0012-...`) — resolved by this document.

The four items in §8 above are genuinely non-blocking: each is scoped to a specific later phase (2.2, 7, or a policy exercise with no current driver) or is explicitly deferred below ADR-level as an implementation detail for whoever starts Phase 1.2. Nothing in §8 prevents Phase 1.1 (directory scaffolding), 1.2 (toolchain baseline), 1.3 (boundary enforcement), or 1.4 (CI skeleton) from starting.

**Phase 0 is complete. Phase 1 of `docs/IMPLEMENTATION-ROADMAP.md` may begin, pending only the human owner's confirmation that this document and ADR-0012 accurately reflect intent** — the same standing confirmation condition every prior phase-closure document in this set has carried.

## 10. Next Step

Per the governing instructions for this task: **stop here.** No `core/`, `infra/`, `control-plane/`, `products/`, or `frontend/` directory has been created; no dependencies have been installed; no application code has been written. This remains documentation only.
