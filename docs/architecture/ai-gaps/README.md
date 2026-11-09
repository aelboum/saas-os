# AI platform gaps 20, 21 and 22: dependency and sequencing

**Status: owner decisions recorded 2026-11-09 (section 5); implementation authorized in seven stages and tracked in `GAP-REGISTER.md`. No gap is closed.** Written 2026-11-09 on `main` at `0f9bf4d` (v0.10.0). A proposal, a decision or a merged stage is not a release: a gap is closed only after implementation, review, verification and release through `docs/RELEASING.md`. Release and LeadStack adoption need the owner's separate approval.

Documents: [Gap 20](GAP-20-WORKSPACE-AI-CONFIGURATION.md), [Gap 21](GAP-21-MONETARY-AI-SPENDING-LIMITS.md), [Gap 22](GAP-22-WORKSPACE-AI-USAGE-VISIBILITY.md), [register and progress](GAP-REGISTER.md).

Scope: text-based AI only. Voice AI (telephony, speech-to-text, text-to-speech, real-time voice agents) is a separate future capability and is not part of these gaps. "Workspace" in the request means "tenant" in SaaS-OS.

## 1. What already exists (audit summary, verified in code at `0f9bf4d`)

The governed AI inference subsystem (ADR-0054, ADR-0055, phases AI-A to AI-F in `docs/AI-INFERENCE-ROADMAP.md`) already provides the base these gaps extend. No second abstraction is needed.

| Area | Exists | Missing |
|---|---|---|
| Provider abstraction | One adapter interface; OpenAI-compatible, Anthropic Messages, Gemini adapters; `StrictEgressClient`; catalogue tables | none for these gaps |
| Tenant enablement | `ai_tenant_policies.enabled`, default off, plan entitlement `ai.inference` default off | tenant-facing read of eligibility; platform per-tenant hold; exposed API |
| Model selection | Tenant allowlist per use case; alias with platform-ordered candidates; tenant data preferences enforced at call time | tenant ranking; grant-time validation; eligibility view |
| Secrets | Name-only references, deployment allowlist, redacted credential object | tenant-owned credentials (separate pending owner decision, not part of these gaps) |
| Token quota | Soft monthly `ai.tokens` per plan, UTC month | hard or concurrency-safe control; any monetary limit |
| Pricing | `ai_model_prices`, immutable versions, `estimated_cost` on each attempt | budget, plan money limits, overrides, staleness, other billable units, cost aggregation |
| Usage records | `ai_inference_attempts` (RLS), provenance, state, cost fields; Core ledger for provider-reported tokens | tenant-facing AI report, cost totals, remaining-limit view, warnings |
| Visibility | `GET /v1/tenants/{id}/usage` (tokens only); platform `read_ai_usage_totals` (no cost, no tenant variant) | AI usage report, permission tier, descendant rule, audit of reads |
| Surfaces | Python service layer; platform CLI | any HTTP route for AI (import boundary forbids it today) |

## 2. Dependency graph

```
            +-----------------------------+
            | D0 owner decisions (below)  |
            +--------------+--------------+
                           |
        +------------------v------------------+
        | 20a eligibility read, ranks,        |
        |     grant-time validation           |
        +--------+-----------------+----------+
                 |                 |
   +-------------v---+     +-------v---------------------+
   | 20b platform    |     | 21a price table extension,  |
   |     tenant hold |     |     staleness               |
   +-------------+---+     +-------+---------------------+
                 |                 |
                 |         +-------v---------------------+
                 |         | 21b budget tables,          |
                 |         |     reserve/settle          |
                 |         +-------+---------------------+
                 |                 |
                 |         +-------v---------------------+      +--------------------+
                 +-------->| 21c thresholds and events   |      | 22a usage read,    |
   (optional: hold on      +-------+---------------------+      |  ai.usage:read,    |
    exhaustion)                    |                            |  audit, index      |
                                   |                            +---------+----------+
                                   +--------------+---------------------+
                                                  |
                                       +----------v-----------+
                                       | 22b rollup (after    |
                                       |  retention decision) |
                                       |  + HTTP router (per  |
                                       |  surface decision)   |
                                       +----------------------+
```

Hard dependencies: 21b needs 21a (staleness and complete price units). 22's budget block needs 21b (before it ships it reports `unconfigured`, so 22a does not wait). 20b is needed by 21 only if automatic suspension at exhaustion is chosen. The HTTP router for all three depends on one shared decision (Gap 20 question 1).

Independent: 20a, 21a and 22a can proceed in parallel after approval because they touch different files, but each ships its own migration (if any), so migrations must be serialized on the Alembic head.

## 3. Implementation order

**Approved order (owner, 2026-11-09):** Stage 0 record decisions; Stage 1 platform AI hold (20b, first, as a safety control); Stage 2 usage read (22a); Stage 3 model eligibility and ranking (20a); Stage 4 pricing extension and staleness (21a); Stage 5 reserve-then-settle (21b); Stage 6 warnings and events (21c); Stage 7 usage reporting and HTTP surface (22b). Each stage is its own branch and pull request; none is merged or released without the owner. The table below is the original recommendation, superseded by this order where they differ.

| Step | Content | Migration | Label | Why this position |
|---|---|---|---|---|
| 1 | Shared decisions and ADR-0054 amendment (docs only) | no | none | settles surface, vocabulary and Q8 before code |
| 2 | **22a** usage read and `ai.usage:read` | index only | additive minor (0.Y.0 if index migration ships) | smallest, read-only, immediately useful, no enforcement risk |
| 3 | **20a** eligibility read, ranks, grant-time validation | yes (column) | 0.Y.0 | settings the other gaps report on |
| 4 | **21a** price extension and staleness | yes (columns) | 0.Y.0 | prerequisite for enforcement, no behaviour change for unbudgeted tenants |
| 5 | **21b** budget reserve/settle behind `AI_INFERENCE_BUDGET_REQUIRED` | yes (tables) | 0.Y.0 | highest-risk change, isolated by a default-off switch |
| 6 | **20b** platform hold | yes (table) | 0.Y.0 | can move earlier if a security or contractual hold is needed first |
| 7 | **21c** thresholds and events | no (uses 21b tables) | additive | needs 21b |
| 8 | **22b** rollups and HTTP router | yes | 0.Y.0 | needs retention and surface decisions |

Steps 4 and 5 may be combined if the owner prefers a single migration; keeping them apart limits the blast radius. Each step is its own pull request, its own release-PR inclusion, and goes through the normal governance (approval, 7/7 checks, review, release). Steps 6 and 2 are the most natural candidates for the first release because they carry the least risk to existing behaviour.

## 4. Cross-cutting requirements (apply to every step)

- Tenant isolation by RLS; every new table classified in `core/tenancy/isolation.py` and `retention.py` and covered by the RLS sweep.
- Same-transaction audit for every change; closed action names; no user id in metadata where `user_subject_ref` applies.
- No credential, prompt or completion in any new table, response, audit row or log; tests with sentinel strings.
- No real provider is configured, no network call is made and no cost is incurred by any test; `FakeAdapter` only.
- AI stays disabled by default for new tenants; no step creates a policy row implicitly; no unlimited usage by default is introduced (the existing `*_REQUIRED` switches are the documented control; see Gap 21 question 8).
- Amendments to ADR-0054 (and cross-references to ADR-0037, ADR-0045, ADR-0060) are dated amendments, not new ADRs, following the #205 and #224 precedent.
- Public API snapshot updated by `scripts/public_api_snapshot.py --write` after review; CHANGELOG `## Unreleased`; CONSUMER-GUIDE section 14.
- No commercial value (plan name, price, quota amount) is written anywhere in code or docs by these steps.

## 5. Decisions

### 5.0 Approved by the owner, 2026-11-09 (also in ADR-0054 section 12e and each proposal's section 18)

| Topic | Decision |
|---|---|
| API surface | Python API first; HTTP router later |
| Spending enforcement | Reserve-then-settle |
| Tenant budget changes | Tenant may lower its own budget; increasing needs a platform operator override; plan limits are hard upper bounds |
| Currency | Mixed-currency plans and budgets rejected in v1; no conversion |
| Price staleness | Maximum price age 24 hours |
| Missing or stale prices | Fail closed for spend-controlled requests |
| Required enforcement switches | Default ON in production whenever AI is enabled |
| Inheritance | Parent/child inheritance out of scope for v1 |
| Support cost visibility | Denied by default; exceptional access needs explicit authorization and audit |
| Tenant cost-data reads | Audited |
| Permissions | Dedicated: `ai.usage:read`, `ai.budget:manage`, a separate platform-only AI hold permission; no inheritance from billing-read |
| Roles | Owner: usage read and budget management (cannot raise the platform-authorized budget); admin: usage read; budget management elsewhere only where explicitly granted; support: nothing automatic. SaaS-OS defines no tenant roles and ships no default AI grant; products bind roles by ADR-0060 migrations (ADR-0060 review note) |
| Retention targets | Attempt metadata 90 days; reservation and settlement records 13 months; usage and cost rollups 24 months; no prompts or generated content in any accounting record |
| Financial meaning | The budget controls **estimated platform spend**, not provider invoices. Estimated platform cost, provider-reported usage and provider invoice amounts stay distinguishable in APIs, docs and any UI. Exact invoice enforcement is never claimed |

**Retention: legal and contractual constraints still to be verified before production.** Not verified by this work: any statutory minimum or maximum for retaining financial or usage records in the jurisdictions where the operator and its tenants are located; whether 13 months of reservation and settlement records satisfies the operator's accounting and tax obligations (which may require longer retention of billing records, held in billing systems rather than here); data-processing agreements and each AI provider's contractual terms on usage records; whether any tenant contract requires shorter retention or deletion on request; interaction with tenant purge (`core/tenancy/retention.py`) and with erasure of users (accounting rows carry no user content, and actor references follow the audit identity rules of P1). Until legal review, these targets are design inputs, not commitments, and no document may state them as guaranteed customer terms. Implementing retention needs a purge or expiry mechanism per table; each stage that introduces a table states which mechanism it uses and that it is not yet scheduled in a deployment.

### 5.1 Original question list (before the decisions above; kept for the record)

Gap-specific questions are in each proposal (section 15). The decisions that gate the plan are:

1. **Surface** (Gap 20 Q1): Python API first with router later (recommended), router now, or Python API only.
2. **Reserve-then-settle** as the resolution of ADR-0054 Q8 (Gap 21 Q1) and the rule that a tenant can only lower, not raise, its own budget (Gap 21 Q3).
3. **Currency and staleness** rules (Gap 21 Q4 and Q5) and the defaults for the `*_REQUIRED` switches (Gap 21 Q8).
4. **Permissions**: `ai.usage:read` and `ai.budget:manage` as new tenant permissions, a distinct platform hold permission, and whether ADR-0060 grant migrations distribute them (Gap 20 Q3, Q5; Gap 22 Q1).
5. **Support access** to AI usage and cost (Gap 22 Q3) and **audit of cost reads** (Gap 22 Q2).
6. **Retention** of attempts, reservations and rollups (Gap 21 Q9, Gap 22 Q5).
7. **Inheritance** from parent tenants: out of v1 (recommended) (Gap 20 Q6).
8. **Commercial inputs** (plan names, prices, quotas) are not requested: the design carries fields only. They are needed before any real budget value is configured, not before implementation.
9. Whether to open GitHub issues for steps as consumer requests (the house pattern is issue then proposal PR). None exist for these gaps today.

## 6. Blockers found

- **Governance:** none for proposals. The numbered gap register ("Gap 20/21/22") is not in this repository (searched `docs/` and the whole tree); `GAP-REGISTER.md` was created here. If the register lives elsewhere (for example a LeadStack-side document), it needs a pointer to this one.
- **Technical:** the HTTP layer may not import `saas_os.inference` (an architecture test), so any router needs an ADR-0054 amendment; entitlements are int/float JSON and cannot hold currency; no entitlement override per tenant exists; tenant-owned credentials are unimplemented (not required by these gaps); retention of attempts is `DEFERRED_POLICY`; whether Core billing exposes a tenant's active plan codes is unverified.
- **External:** no live provider has ever been called through this subsystem in this repository's history of record (`AI-PROVIDER-QUALIFICATION.md`); real usage reporting, pricing and invoice behaviour are unverified.
