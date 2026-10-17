# ADR-0055: AI data governance and destination authorization for inference

Status: Proposed (2026-10-16). Stays Proposed until its open questions are resolved and acceptance is decided (ADR-0054 section 12a, Q6). Approved in principle on 2026-10-16: the classification trust model (section 4) and the minimum tenant AI policy in Phase AI-C (section 7). Approved owner decisions on 2026-10-16: the in-process use-case registry for immutable, application-defined use cases (section 4) and per-attempt audit granularity (section 6). None of these makes the ADR Accepted. **Implementation status (2026-10-17): sections 2 to 6 are enforced by the governed inference path, implemented on branch `feat/ai-inference` and merged into `main` by pull request #53 (`0598a9a`); see "Implementation record". Implementation does not make this ADR Accepted (Q6).**
Date: 2026-10-16 (Phase AI-A); reconciled four times with owner decisions on 2026-10-16
Supersedes / Superseded by: — (implements the shape of [ADR-0013](0013-ai-data-privacy-and-external-model-boundary.md) for the inference subsystem; does not change ADR-0013's principles. Would make `docs/SECURITY.md` section 6.1's sentence "Nothing in this section is implemented yet" partly stale once Phase AI-D ships; it is already partly stale, see "Context")

## Context

ADR-0013 (Accepted) fixed the principles: no tenant or user data reaches an external AI provider except through a platform data boundary; minimization; provider trust is policy, not assumption; a tenant AI data policy; unclassified data is denied. `docs/SECURITY.md` section 6.1 turned those into ten binding invariants. ADR-0054 proposes the inference subsystem through which products will send content to providers. This ADR states how that subsystem satisfies ADR-0013, and where it cannot.

### What exists (verified at `7ab9422`)

`saas_os/control_plane/data_authorization` implements a pure, default-deny decision:

- `DataClassification = Literal["none", "tenant_data", "sensitive"]` (`models.py:35`). The three values "deliberately mirror" the tool registry's vocabulary (`orchestration/tools.py:54`) and are stated to be "the smallest coherent choice, not a new taxonomy" (`models.py:4-14`). No value has a written definition.
- `evaluate_data_authorization(request, *, tenant_policy, provider_policy)` (`service.py:78-109`) denies, in order, for: missing or unknown classification; no tenant policy or a policy for another tenant; classification not allowed by the tenant; purpose missing or not allowed; provider not globally eligible; provider not allowed by the tenant. The only `ALLOW` is the last line.
- `authorize_data_access(...)` (`service.py:112-150`) writes one `core.audit_log` row per decision through `audit_log.record` (its own transaction), always with `ActorType.USER`.
- `verify_data_authorization_provenance(decision, *, tenant_id)` (`service.py:153-194`) re-reads that row; it has no expiry, replay or single-use protection (its own docstring).
- `TenantAIDataPolicy` and `ProviderEligibilityPolicy` are dataclasses the caller supplies. **No table stores either.** Retention and processing-restriction fields named in ADR-0013 section 4 are absent.
- The classification is a caller-supplied string. **Nothing derives a classification from data.** `sensitive` gets no special treatment beyond needing to be listed by the tenant policy.
- No production code produces a decision; the orchestration check (`orchestration/service.py:249`) applies only to tools that set `requires_data_authorization=True`, and none does.

`docs/SECURITY.md` section 6.1 says "Nothing in this section is implemented yet". The decision gate exists, so the sentence is stale for invariants 3, 5 and 7 (decision level only); the rest are not implemented. Recorded in the deferred ledger.

### Invariant status today (verified)

| SECURITY.md 6.1 | Today | After Phase AI-D (proposed) |
|---|---|---|
| 1 Only through the boundary | Gate exists, nothing forces its use | Inference is the only provider path SaaS OS ships; import contracts forbid other paths inside SaaS OS; consumers bound by documentation |
| 2 Minimization | Not implemented | Use-case declarations limit parts and sizes; real minimization stays the product's job (section 8) |
| 3 Unclassified denied | Implemented for missing/unknown strings | Per content part; missing or invalid fails closed |
| 4 Provider eligibility is policy | Input shape only | Stored platform policy (Phase AI-C) |
| 5 Tenant policy, absent = deny | Implemented as input | Stored tenant policy (minimal in AI-C, full in AI-E) |
| 6 Sensitive classes need reviewed policy | One coarse `sensitive` bucket | Unchanged taxonomy; `sensitive` additionally requires a destination flagged for it and an explicit tenant opt-in (section 5) |
| 7 Every crossing attributable and audited | Decision audited | Decision audited in the attempt's transaction; attempt ledger row per crossing |
| 8 No bypass by direct calls | Partial (Core, Infra, data_authorization only) | Extended to the rest of the Control Plane and `products/` |
| 9 Redaction not reversible | Not implemented | Not implemented; no redaction is proposed (section 8) |
| 10 Additive gate | Implemented structurally | Unchanged |

## Options Considered

### For trusting a classification

#### Option C1 — Caller-declared per content part, accepted as is
- Disadvantages: a string from product code is not proof; the brief and ADR-0013 section 5 both reject treating it as such.

#### Option C2 — Caller-declared per part, bounded by a registered use case (recommended)
A product registers each *use case* (purpose) once, at startup, in code: its name, the maximum classification it may send, which part kinds it may carry, and size limits. Each request names a use case; each part's classification must be at or below that use case's ceiling, and the use case must be allowed by the tenant's policy.
- Advantages: classification becomes a reviewed, versioned declaration in the product's source instead of a per-call string; the tenant policy grants use cases, not raw classes, matching ADR-0013's "allowed use cases"; a product cannot raise a call's classification ceiling at run time.
- Disadvantages: still a declaration. Product code that labels a customer record `none` under a `none` use case is not detected. Residual risk recorded in section 4.

#### Option C3 — Content inspection (PII detectors, classifiers)
- Disadvantages: probabilistic; false negatives are exactly the failure ADR-0013 is about; adds a model or a heavy dependency; would itself need data authorization if external. Not proposed as a gate. May later be added as an *additional* deny-only check (it can only lower eligibility).

#### Option C4 — Derive classification from SaaS OS-owned sources
Parts built by SaaS OS from rows it owns could carry a classification derived from the table.
- Disadvantages: products build their own prompts from their own data; SaaS OS owns almost none of it. Kept as the rule for any part SaaS OS itself constructs (section 4, rule 4).

### For where tenant policy lives

#### Option T1 — Tenant-owned table under tenant RLS, written through tenant RBAC (recommended)
#### Option T2 — Platform-managed per-tenant policy
- Disadvantages: ADR-0013 section 4 says the tenant holds its AI data policy; ADR-0045 constraint 4 keeps platform operators out of tenant data decisions.

## Recommendation

Option C2 with C4 for SaaS OS-built parts; Option T1.

## Decision

**Pending; partly decided.** Approved in principle on 2026-10-16: section 4's trust model and section 7's sequencing. Approved owner decisions on 2026-10-16: the in-process registry for immutable, application-defined use cases in section 4 (ADR-0054 Q5) and the audit granularity in section 6 (ADR-0054 Q7). Sections 1–3, 5, 8 and 9 are the proposed design. Nothing is implemented.

### 1. Classification vocabulary (provisional, unchanged values)

The three existing values are kept, so the existing gate and tool registry need no migration. This ADR gives them definitions for inference, which they do not have today:

| Value | Meaning for inference | What it does **not** mean |
|---|---|---|
| `none` | The part contains no data obtained from or about a tenant, its users or its customers: fixed instructions written by the product, public reference text | That the part may go to any provider. A `none` part still needs an eligible destination and a tenant policy that allows the use case |
| `tenant_data` | Data belonging to, or derived from, one tenant's records or its users' input, that is not in a sensitive class | That every provider the tenant allowed may receive it regardless of the destination's declared handling |
| `sensitive` | Any part in a sensitive class of SECURITY.md 6.1 invariant 6 (credentials, secrets, financial information, government identifiers, health information) or data the tenant designates sensitive | That it may cross the boundary at all without section 5's additional conditions |

Ordering for ceilings and "effective classification": `none < tenant_data < sensitive`. The effective classification of a request is the highest classification of any part, including system instructions, tool definitions and tool results (all are content parts).

A real taxonomy remains future work (ADR-0013 "not decided"). A value outside the three is invalid and denied.

### 2. Every content part is classified

- Each content part carries exactly one classification. A missing, empty or unknown value fails the whole request before any destination is considered (`UNCLASSIFIED_DATA`), never defaulted.
- There is no request-level default classification. A convenience that applies one value to all parts would reintroduce the "forgot to classify" path ADR-0013 section 5 forbids.
- Parts returned by a provider (completions) inherit the request's effective classification when a product sends them back in a later request; the API marks returned text with that classification so the product does not have to re-declare it lower. The product may still declare it higher.

### 3. Destination eligibility (all must hold, per candidate destination)

1. **Platform availability.** The provider and model are `active` (not `disabled`, not past `retire_after`).
2. **Platform eligibility.** The installation-wide policy lists the provider for the request's effective classification.
3. **Tenant policy.** The tenant's stored policy exists and is enabled; it enables the use case, allows the provider and model for that use case, and allows the effective classification for that destination (section 7).
4. **Capability.** The model declares every capability the request requires.
5. **Health.** The circuit for (provider, model) is not open.
6. **Restrictions.** Any configured residency tag required by the tenant policy is among the destination's declared tags. Declared data-handling attributes (retention, training use) are operator declarations, not verified facts; the policy can require them, and the ADR does not claim more.

The existing `evaluate_data_authorization` covers 2 and 3 (classes, purposes, providers). Phase AI-D extends the request with `model` and `residency` inputs and keeps the evaluator pure and default-deny. 1, 4 and 5 are checked by routing before the evaluator. A destination failing any check is not a candidate; it is never tried "to see".

**A self-hosted or private destination is still a destination.** ADR-0013 speaks of *external* providers. This ADR applies the same gate to every destination, including a vLLM server on the installation's own network: the operator may make such a destination eligible for `sensitive` where an external one is not, but eligibility is always explicit.

### 4. Trust model for declared classifications (approved in principle, 2026-10-16)

**Decision.** SaaS OS accepts product-declared classifications, constrained by registered use cases, tenant authorization and destination policy. **The platform enforces authorization boundaries. It does not prove that a classification accurately describes the semantic contents of a payload, and no SaaS OS document may claim that it does.** No automatic classification or sensitivity inference is part of this decision (Option C3 stays rejected as a gate).

**Requirements** (approved; enforcement is Phase AI-D work, nothing exists now):

1. Every submitted content part has a classification (section 2).
2. A missing, invalid or unsupported classification fails closed: the request is denied before any destination is considered.
3. Every product use case is registered through a controlled mechanism. A request naming an unknown (unregistered) use case is denied.
4. A use case declares its maximum permitted classification (`max_classification`). A part above it is denied (`CLASSIFICATION_EXCEEDS_USE_CASE`).
5. Product code cannot grant itself runtime authority by changing a classification field. A label can only narrow what is sent within limits other parties set, never widen them. The tenant's grant names the use case **and** the classifications it allows for that use case. Raising a registered ceiling in code therefore gains nothing the tenant has not granted.
6. The tenant's policy authorizes the use case (section 7). No policy, or a disabled policy, means deny.
7. Platform policy permits the destination and model for the effective classification (section 3).
8. `none` does not permit arbitrary external transmission (section 1). A `none`-only request still needs a registered use case, a tenant grant and an eligible destination.
9. Unknown use cases are denied (as in 3).
10. Classification labels, use cases and policy decisions are auditable without logging raw payloads: the attempt row and the audit row record the labels, use case, decision and reason (section 6), never content.

**Effective authorization**, for a part with classification `c` in a request for use case `u`, sent to destination `d` (provider and model):

```
c is one of the three values
and u is registered and c <= ceiling(u)
and the tenant policy is enabled, grants u, and allows c for u
and d is allowed by the tenant policy for u
and the platform policy makes d eligible for the request's effective classification
and d is available, capable and healthy (section 3)
and, if the effective classification is sensitive, section 5 holds
```

Every conjunct must hold; the request is denied otherwise.

Any part SaaS OS itself builds from a SaaS OS-owned source is classified by SaaS OS from that source, never by the caller.

**Use-case registration (approved owner decision, Q5, 2026-10-16): an in-process registry for immutable, application-defined use cases.** No persistent use-case registry table is introduced without a demonstrated requirement for independently managed registrations. Nothing is implemented; the registry is built in the phase that needs it, under that phase's own authorization.

*Registration:*
- Use cases are registered explicitly. An unknown use case is denied.
- A use case is an application-owned declaration and changes only through a controlled application release.
- Each use case declares its permitted classification ceiling and its supported capabilities.
- **Registration alone authorizes nothing.**

The model follows the repository's existing convention for declared AI capabilities: the in-process `ToolRegistry`, validated at registration (`saas_os/control_plane/orchestration/tools.py:133-194`, "not a database table").

*Independent authorization.* The registry is not an authorization mechanism. Every inference request must also satisfy all of the following, and missing or invalid authorization information never grants access:

1. trusted caller authentication and authority (`UserCaller` / `ServiceAccountCaller`, `can()`);
2. tenant and entitlement authorization;
3. registration of the requested use case;
4. classification of every part within the use case's ceiling;
5. tenant policy permitting the use case and the classification;
6. platform destination policy permitting the intended provider or endpoint;
7. provider and model eligibility;
8. resource and concurrency admission.

Further rules:
- A supplied `tenant_id` alone never confers authority.
- Every content part is classified; missing or invalid classifications are denied.
- `none` does not authorize arbitrary external transmission.
- Because the tenant's grant names the use case and the classifications it allows, a release that raises a registered ceiling gains nothing the tenant has not granted.

*When the in-process registry would no longer be sufficient* (design guidance, not a commitment). A persisted, audited registry should be reconsidered if a future requirement calls for:
- administrators creating or modifying use cases independently of application releases;
- independently governed registration lifecycles;
- durable registration-change history;
- audited changes to classification ceilings or capabilities;
- central management of use cases across independently deployed applications.

Such a registry would bring a schema and migration, authorization and lifecycle rules, audited mutations, and bootstrap, recovery and tests. None of that is planned or implemented.

**Residual risk.** Product code may still label content incorrectly within the scope it is authorized to submit (below).

**Residual risk (recorded, not solved).** In-process product code is trusted (ADR-0045 section 1, "In-process code is trusted"). It can label content incorrectly within the scope it has been authorized to submit; for example, a customer record marked `none` under a use case and destination the tenant has granted for `none`. SaaS OS cannot detect this. The controls are:
- the ceiling, the tenant's grant and the destination policy are reviewed, versioned and audited;
- a mislabel cannot reach a destination or classification the tenant and platform have not allowed;
- a tenant that wants no exposure does not grant the use case.

The platform never presents a label as independently verified.

### 5. Additional conditions for `sensitive`

`sensitive` crosses only if all hold: the tenant policy lists `sensitive` explicitly for that use case; the destination is flagged `accepts_sensitive` in the platform policy (an operator decision recorded with a reason); and the use case's ceiling is `sensitive`. No default policy, template or bootstrap step ever enables it.

### 6. Decision, audit and transaction

Granularity is an approved owner decision (ADR-0054 Q7, 2026-10-16): **one durable decision record per inference attempt, with correlated destination-level decisions where needed**. ADR-0054 section 7a gives the full event model and design requirements.

- Each destination actually attempted gets its own destination-level decision. A decision for provider A never covers a fallback to provider B, and a destination change is never merged into another attempt's record.
- Pre-send evidence (approved owner decision, ADR-0054 Q10): the attempt-level decision record and destination-level evidence are written **before** any content is sent. If a required authorization or policy decision fails, or a required audit write cannot be completed, nothing is sent.
- Proposed mechanism: the decision is recorded with the typed caller (`UserCaller` or `ServiceAccountCaller`) through `audit_log.record_in_transaction`, in the same PostgreSQL transaction that inserts the attempt's `started` row, committed before sending. That transaction gives durability and atomicity only if this mechanism is chosen and tested in AI-D. Today's `authorize_data_access` writes in its own transaction and only as a user; AI-D would add a caller-typed entry point beside it and keep the existing function for orchestration.
- Audit metadata: decision id, use case, effective classification, provider key, model id, attempt id, outcome, denial reason. Never content, never a credential, never a content hash that could confirm a guess about content.
- Denials before any destination is chosen (unclassified part, unregistered use case, caller not authorized, entitlement denied) produce the attempt-level decision record, with the reason. How capacity rejections are recorded is an AI-D design decision (ADR-0054 section 7a).
- **Volume.** At least one durable decision record per attempt, as invariant 7 requires. A volume estimate per workload is an AI-D design deliverable. Volume is never reduced by dropping required records.

### 7. Tenant AI data policy (sequencing approved in principle 2026-10-16; schema proposed)

**Sequencing (owner decision, 2026-10-16).** Phase AI-C establishes the minimum tenant AI policy required for governed inference. Phase AI-D relies on it, and never assumes that a policy exists or permits a request when it is missing. Phase AI-E extends tenant configuration and adds tenant-owned credentials, if approved. AI-E is not the first phase to establish the policy AI-D needs.

**Minimum policy responsibilities (AI-C):**

- enable or disable each AI use case for the tenant;
- define the eligible providers and models for each enabled use case;
- define which classifications may be sent to which of those destinations;
- record whether the policy (and each use-case grant) is enabled;
- apply default deny when a required policy, grant or entry is absent or disabled.

**Expanded configuration (AI-E):** preferences (for example a preferred model among eligible ones); residency and retention requirements matched against destinations' declared attributes; tenant-owned credentials; any further per-tenant restrictions.

**Proposed shape**, not a final schema: the exact schema and operational contract are designed in the separately authorized AI-C implementation against the repository's database, RLS and authorization conventions. A tenant-owned table set in the `control_plane` schema (working name `ai_tenant_policies` with child rows) under tenant RLS (`tenant_rls_statements`). Changes are written through a tenant RBAC permission (proposed `ai.policy:manage`, registered with `register_permission`) with same-transaction tenant audit (`record_in_transaction`). Platform operators cannot write it (ADR-0045 constraint 4). `platform.ai_policy:manage` governs only installation-wide destination eligibility and does not imply this permission. No row means deny, which is unchanged from today's evaluator.

### 8. Minimization and redaction

- SaaS OS cannot minimize a product's prompt; it does not know the task. Proposed controls: per-use-case limits on part kinds, part count and bytes; refusal of oversized requests; no automatic inclusion of any SaaS OS data in a request.
- No redaction or pseudonymization service is proposed. Invariant 9 therefore stays "not implemented"; a product that redacts does so before calling the API and classifies the result.

### 9. Learning Authorization

Nothing in the inference subsystem retains prompts or completions. Storing or reusing them (prompt caching on the SaaS OS side, evaluation datasets, fine-tuning) is Learning Authorization (ADR-0014) and is out of scope. Provider-side prompt caching is a provider data-handling attribute the platform policy can require or forbid.

## What Would Be Difficult to Change Later

- Making classification optional or request-level after products are written against per-part classification.
- The use-case registry shape, once tenant policies reference use cases by name.
- Any destination made eligible for `sensitive`, once data has been sent there.

## Related

ADR-0002, ADR-0004, ADR-0013, ADR-0014, ADR-0031, ADR-0045, ADR-0054; `docs/SECURITY.md` sections 6 and 6.1; `docs/AI-CONTROL-PLANE.md` section 2.1; `docs/architecture/AI-INFERENCE-CONTRACTS.md` sections 3–5.

## Implementation record (2026-10-17; implemented on branch `feat/ai-inference`; merged by pull request #53)

This ADR stays Proposed (Q6). What exists, by section:

- **Section 2 (classification).** Every content part carries a required
  classification; a missing, unknown or unsupported value denies before
  anything is read (`saas_os/control_plane/inference/resolution.py`,
  `validate_request`). The effective classification is the highest part.
  Returned text is marked with the request's effective classification.
- **Section 3 (eligibility).** Each check is independent and all must hold:
  tenant policy exists and is enabled; the use case is granted for the
  classification; the alias is active; per candidate the provider is active
  and its credential bound to its origin, the model usable, installation
  policy allows the provider for the classification, the tenant granted the
  model for the use case and classification, the ADR-0013 evaluator
  (`evaluate_data_authorization`, unchanged) allows, the tenant's
  preferences are met, and the capabilities and output limit suffice. The
  evaluator was not extended with model and residency inputs, as section 3
  anticipated; those are checked by routing before it, so the evaluator stays
  as reviewed. Health (an open circuit) skips a destination.
- **Section 4 (Q5 registry).** In-process, immutable, application-defined use
  cases (`…inference.use_cases`); registration authorizes nothing.
- **Section 6 (evidence).** One `started` attempt row with its decision is
  committed before any content is sent; if it cannot be written nothing is
  sent. The row holds no content.
- **Section 7 (tenant policy).** The minimum policy (AI-C) and the
  preferences (AI-E) are tenant-owned, written only with `ai.policy:manage`,
  audited, never satisfiable by support access or a platform permission.
  Tenant-owned credentials are not implemented (no owner decision).
