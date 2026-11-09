# Gap 22: Tenant AI usage visibility: options and recommendation

**Status: Proposal. This document changes no code, test, public contract, migration or ADR.** Proposal submission is not implementation approval.
Written 2026-11-09 on `main` at `0f9bf4d` (v0.10.0, Alembic head `e2b7c4d9a1f6`).
Facts carry a `file:line` citation read from code; a statement with no citation is an inference. "Workspace" means **tenant** (see Gap 20, vocabulary). Text-based AI only; voice AI is a separate future capability.

## 1. What is requested and what it unblocks

An authenticated tenant-level usage interface and API for tenant administrators: total usage, estimated spending, breakdown by provider, model and (where attribution is reliable) application or feature, input and output tokens, monthly consumption, remaining token quota and monetary budget, and warning or exhaustion status. Access must be tenant-isolated, tiered (ordinary users do not get billing-level data), explicit for parent or agency access, free of credentials, prompts and generated content, auditable, and have defined retention and aggregation.

## 2. Existing-state audit

**Tenant-facing route today.** `GET /v1/tenants/{tenant_id}/usage` (`saas_os/api/v1/usage.py:38,62`): an opt-in router not mounted by `build_platform_app` (`:1-16`), gated by `billing.subscription:read` (`:40`), query `since`/`until` (both or neither; default current UTC month) and repeatable `metric` (max 50). It returns per-metric `used`, `limit`, `remaining`, `over_limit` and `effective_entitlements` from `core/usage/reporting.py` (`service_tenant_usage_report`), for the caller's own tenant. Reads are not audited (`reporting.py:47`, ADR-0031 treats them as non-mutations). AI appears only as the Core metrics `ai.input_tokens` and `ai.output_tokens`, which mirror **only provider-reported** token counts (`control_plane/inference/service.py:145-146, 510-519`). The AI limit `ai.tokens` shows in `effective_entitlements` but has no matching metric, so there is no used/remaining for it. There is no cost, no provider or model breakdown, no estimated usage and no use-case breakdown.

**Descendant reads.** Core supports `include_descendants=True`, which authorizes `(tenant, billing.subscription, read)` for **every** descendant and returns totals with `limit=None` (`reporting.py:193-240`); the HTTP route does not expose it (`usage.py:10-16`). Hierarchy is structural: a parent gains no automatic access to a child (`core/tenancy/models.py:21-24`). Explicit reach exists only through a `SUBTREE`-scoped role (`core/rbac/scope.py`, `authorization.py:80-115`), delegation grants, deny grants and time-bounded support access (`authorization.py:42-52, 815-850`). Billing **reads** remain open to support access (`authorization.py:309-312`).

**Platform-side AI usage totals.** `read_ai_usage_totals` (`control_plane/inference/usage.py:410-455`): grouped by provider, model, state and provenance, window at most 93 days, an audited platform oversight read (`AI_USAGE_READ`, `api/platform_bootstrap.py:118`). It has no API caller and no tenant variant, and it omits `estimated_cost`.

**Where the data is.** `control_plane.ai_inference_attempts` (`attempts.py:498-549`, tenant RLS): `use_case`, `alias`, `provider_key`, `model_id`, state, `error_category`, token fields, `usage_provenance`, `other_usage`, cost fields, timestamps, `actor_*`. Attribution available today: `use_case` (registered by the product in-process), alias, provider, model. There is **no application or feature field** beyond `use_case` (audit result); the proposal does not claim more.

**Aggregation and retention.** No rollups; reads are on-the-fly `SUM`s (`accounting.py:151`, `usage.py:410-455`, `core/usage/service.py:303`). `core.usage_events` and `ai_inference_attempts` are both `RetentionClass.DEFERRED_POLICY` (`core/tenancy/retention.py:141,146`): no retention period has been decided. Whether an index on (`tenant_id`, `started_at`) exists was not verified.

**Audit conventions.** `action` is a free dotted string (`audit_log/service.py:80-81`); same-transaction writers `record_in_transaction` / `record_system_action_in_transaction`; user ids in metadata are discouraged (CONSUMER-GUIDE.md:534,552; issue #222). Successful AI runs are not in the tenant audit log (the attempt row is the record); denials are (`service.py:293-312`).

**Tests that pin today's behaviour:** `tests/api/v1/test_capability_routers_integration.py` (usage router), `tests/core/usage/test_usage_reporting_integration.py`, `test_usage_hierarchy_integration.py`, `tests/architecture/test_platform_authority_contract.py` (AI_USAGE_READ).

## 3. Problem statement

A tenant administrator cannot see, in one place and in either tokens or currency: what AI was used, by which provider and model, for which feature, what it probably cost, and how close the tenant is to its limits. The pieces exist in two places that do not meet: provider-reported tokens in the Core ledger, and complete attempt data (including estimated usage, cost and provenance) in `ai_inference_attempts`, readable only by the platform and without cost.

| # | Gap |
|---|---|
| G22-1 | No tenant-facing read over `ai_inference_attempts` (provider, model, use case, state, provenance) |
| G22-2 | No cost aggregation anywhere (`estimated_cost` is never summed) |
| G22-3 | No remaining-token-quota or remaining-budget view (`ai.tokens` has no metric; budget is Gap 21) |
| G22-4 | No warning or exhaustion status |
| G22-5 | No AI-specific permission: visibility today is the broad `billing.subscription:read` |
| G22-6 | No defined parent or agency rule specific to AI usage |
| G22-7 | No retention or rollup decision |
| G22-8 | Reads are unaudited; for cost data of this sensitivity that needs an explicit decision |

## 4. Options

**Option A (recommended): a tenant-scoped read over the attempts table, behind a new permission, reusing the platform totals logic.**

*Service.* `read_tenant_ai_usage(caller, tenant_id, *, since, until, group_by, include_descendants=False) -> AIUsageReport` in `saas_os.inference`, built on the same grouping code as `read_ai_usage_totals` and run in `tenant_session_scope(tenant_id)` so RLS confines it. `group_by` is a closed set: `provider`, `model`, `use_case`, `day`, `provenance`, `state`. Totals returned per group: attempt counts by state; input, output, cached-input tokens; `estimated_cost` summed **per currency** (never across currencies); and counts of attempts with unknown usage or unknown cost, so a reader sees what the total does not include. Provenance is kept visible: `provider_reported` and `estimated` are reported separately, `unknown` is counted, not hidden. Window at most 93 days per call (same limit as the platform read); monthly consumption is the default window (current UTC month).

*Status block.* `read_tenant_ai_status`-style summary in the same report: token quota used/limit/remaining (from `ai.tokens` and the same projection source as admission, labelled **soft**), budget used/reserved/limit/remaining/state (from Gap 21 when present, else `unconfigured`), the thresholds crossed, and `exhausted` flags. Labels are fixed vocabulary: "estimated spend", "soft token quota". No field is named "invoice", "bill" or "hard limit".

*Access tiers (new tenant permissions, registered like `register_ai_permissions`).*
- `ai.usage:read`: tenant usage with cost and budget. Intended for tenant administrators. Not granted to ordinary members by default; the product binds it to roles.
- Ordinary members who run AI get no usage data unless granted. A caller may always see refusal reasons for their own requests (existing behaviour); that is not usage data.
- Optionally `ai.usage:read_self` (a user's own attempts, tokens only, no cost) is **not** proposed in v1; listed as question 4.

*Parent or agency access.* Not implicit. `include_descendants=True` requires `ai.usage:read` on **each** descendant, evaluated by the existing `can()` path (mirrors `reporting.py:211-220`), so a `SUBTREE`-scoped role grants it and a deny grant on any child excludes that child. Results are returned per child, never silently merged; a child the caller cannot read is omitted and reported only as a count of "not authorized" without id or name (so existence is not leaked). Parent roll-up of cost is allowed only for children in one currency. Support access: see question 3.

*Audit.* Proposed: every tenant read of cost data writes one audit row `ai.usage.read` (same-transaction writer) with metadata limited to window, `group_by`, `include_descendants` and tenant ids read counts; no user id beyond what the audit actor already carries, no aggregates. Cost is a few rows per admin page view; this is cheap relative to other audit volume but is a decision (question 2). Denied reads are audited by the permission dependency as today.

*Retention and aggregation.* v1 reads attempts directly (no schema change except an index if missing). Retention of `ai_inference_attempts` remains `DEFERRED_POLICY`, so the report documents "available while the rows exist" and promises no retention period. A second step may add a monthly rollup table `ai_usage_monthly` (tenant-owned: tenant, month, provider, model, use case, currency, token sums, cost sum, counts) maintained by the settlement transaction, so that history survives a future purge of raw attempts. Rollups hold **no content and no per-request data** and would be the natural retained form once the owner decides retention (question 5).

**Option B: extend the existing `/usage` route and Core metrics** with `ai.cost` and per-model metrics. Rejected as primary: the Core ledger mirrors only provider-reported tokens, has no currency or dimension model, and adding dimensions to a generic ledger duplicates metering. It remains the right place for token totals that products already read.

**Option C: product-built dashboards over exported data.** Rejected: it recreates metering in each product, which the requirement forbids.

## 5. Proposed architecture

```
tenant admin -> (optional HTTP router) -> read_tenant_ai_usage(ai.usage:read)
             -> tenant_session_scope -> ai_inference_attempts (RLS)  [+ ai_budget_periods, Gap 21]
             -> aggregates only: tokens, cost per currency, counts, provenance
```

No write path. No new ledger. The only new persistence in v1 is an index (and, in step 2, the rollup table).

## 6. API and interface design

Python: `read_tenant_ai_usage(...)`, `AIUsageReport`, `AIUsageGroup`, `AIQuotaStatus`, `AIBudgetStatus`.

HTTP (opt-in router, after the Gap 20 surface decision; one policy per route):
- `GET /v1/tenants/{tenant_id}/ai/usage?since=&until=&group_by=provider|model|use_case|day&include_descendants=false` -> `AIUsageReport`
- `GET /v1/tenants/{tenant_id}/ai/limits` -> token quota and budget status, thresholds, exhaustion flags

Response shape (illustrative, not final):
`{ "window": {"since","until","timezone":"UTC"}, "totals": {"attempts":{"succeeded":n,"failed":n,...}, "input_tokens":n, "output_tokens":n, "cached_input_tokens":n, "cost":[{"currency":"XXX","estimated":"0.00000000"}], "usage_unknown_attempts":n, "cost_unknown_attempts":n}, "groups":[...], "limits": {"token_quota":{"limit":n|null,"used":n,"remaining":n|null,"basis":"soft_projection"}, "budget":{"state":"unconfigured|ok|warning|exhausted|pricing_unavailable", ...}} }`.
Monetary values are decimal strings, never floats. Pagination and the 93-day window cap apply. Errors reuse the shared vocabulary; unknown tenant and non-member are indistinguishable.

## 7. Database and migration implications

v1: at most an index on `ai_inference_attempts (tenant_id, started_at)` if absent (to be checked); registering `ai.usage:read` needs no table (tenant permissions are data in the existing RBAC tables; ADR-0060 governs giving it to existing roles). Step 2: `ai_usage_monthly` (RLS, isolation and retention classification, RLS sweep). Index creation on a large table should use `CREATE INDEX CONCURRENTLY` outside the migration transaction; the migration gate (P1.7) must accept it (not verified). Label 0.Y.0 if a migration ships.

## 8. Authorization and security model

- Tenant isolation: all reads run in the tenant session under RLS; the explicit `tenant_id` argument is checked against the authorization context before the session opens. Cross-tenant reads are refused identically to unknown tenants.
- No credentials, prompts, completions or provider request bodies are returned; the report has no free-text field. `decision` JSON, `provider_request_id`, `error_category` details and `other_usage` raw JSON are **not** returned. A test asserts the response schema is a closed set. (Whether `decision` JSON can contain content was not verified; v1 never returns it.)
- `ai.usage:read` is not authority-changing; `api_key` access refused by default; service accounts excluded in v1 (question 4).
- Ordinary users do not receive admin-level billing information because the permission is not default-granted and the report is not reachable through `billing.subscription:read`.
- Descendant reads follow explicit authorization per child (Section 4).
- Audit rows contain no aggregates and no content.

## 9. Backwards compatibility

Purely additive: new function, new permission, optional router. The existing `/usage` route and Core metrics are unchanged. Tenants without the permission see no change. Products already reading `ai.input_tokens` keep working; the docs state that the new report includes `estimated` usage which the Core ledger deliberately does not.

## 10. Acceptance criteria (testable)

1. **Isolation.** Tenant A's admin reading tenant B's usage is refused, identically to a nonexistent tenant; a report for A never contains a B attempt (two-tenant fixture, includes concurrent writes).
2. **Permissions.** A member without `ai.usage:read`, a holder of only `billing.subscription:read`, a service account, an API key and an expired membership are refused; support access behaves as the owner decides (test pins the decision).
3. **Aggregation accuracy.** For a fixture of attempts across providers, models, use cases, states and provenances, sums of tokens and cost equal an independent `Decimal` oracle; `usage_unknown_attempts` and `cost_unknown_attempts` equal the true counts; unknown is never treated as zero.
4. **Date ranges.** Inclusive start and exclusive end; UTC month boundaries; leap day; a window over 93 days is refused; `since` without `until` is refused; default is the current UTC month.
5. **Provider and model breakdowns** equal the sum of the totals; the same model id under two providers stays separate.
6. **Monetary correctness.** Costs are summed per currency and never across currencies; decimal strings round-trip without float error; attempts without a price contribute to `cost_unknown_attempts` only.
7. **Remaining quota and budget.** `remaining` equals limit minus the same figure admission uses; a malformed `ai.tokens` shows an `invalid` state, not unlimited; a tenant with no limit shows `null`, not zero; exhaustion and thresholds match Gap 21 state.
8. **Parent access.** Without a `SUBTREE` role a parent cannot read a child; with it, it reads only children it holds the permission on; a deny grant on one child omits that child; omitted children are counted without identifiers.
9. **Privacy.** A response-schema test and a fixture seeded with sentinel strings in prompts, credentials and outputs prove none appears in any response, audit row or log.
10. **Audit.** Each allowed read writes exactly one `ai.usage.read` row with the specified metadata; a denied read writes an `api.access_denied` row; failure of the audit write fails the read (if the owner decides reads are audited).
11. **Retention behaviour.** The report states its basis ("rows present"); with a rollup (step 2) the monthly totals equal the sum of attempts for the same month and survive deletion of raw attempts in a test that simulates the purge.
12. **Performance.** A fixture with 1,000,000 attempts for one tenant returns a month report within a stated bound using the index (query plan asserted, not wall time alone).
13. **Negative controls.** Removing the RLS session, the permission check, the currency partition or the descendant authorization each fails a named test.

## 11. Automated test strategy

Unit: aggregation and currency partitioning against an oracle, date arithmetic, response-schema closure. Integration on the disposable Postgres with seeded attempts (no provider, no network, no cost). Authorization matrix test over caller types, roles, scopes, support access and deny grants. Architecture: public API snapshot, route policy (if a router is added), import boundary, doc reference check. Property test: random attempt sets, report sums equal oracle for every `group_by`.

## 12. Operational considerations

- Cost data is **estimated spend**, labelled so, and differs from invoices for the reasons listed in Gap 21 section 12. The page must not be used as a bill.
- Queries scan attempts by tenant and window; the 93-day cap and the index bound the cost. Large tenants motivate the rollup step.
- Monitoring of the read path depends on the observability backend (ADR-0009).
- Retention remains undecided until the owner decides; until then the documentation must not promise history length.

## 13. Dependencies

Gap 20 (permission registration pattern, surface decision H1/H2/H3). Gap 21 (budget and threshold status; before it ships the budget block reports `unconfigured`). The ADR-0060 decision on distributing `ai.usage:read` to existing roles. A retention decision for step 2.

## 14. What could not be verified

The index on `(tenant_id, started_at)`; whether `decision` or `other_usage` JSON can carry content (not returned by design); `CREATE INDEX CONCURRENTLY` under the migration gate; production-size performance; whether `core.billing` exposes plan information needed for display.

## 15. Open questions only the owner can answer

1. Is a dedicated `ai.usage:read` permission acceptable, rather than reusing `billing.subscription:read`? (Recommended: dedicated.)
2. Audit every tenant read of AI cost (recommended) or leave reads unaudited as with other billing reads?
3. Support access to AI usage and cost: allowed (as for billing reads), or excluded like `ai.policy:manage`? Recommendation: excluded in v1.
4. Per-user "my own usage" view and service-account access: out of v1?
5. Retention of attempts and monthly rollups: decide now (rollup recommended as the retained form) or leave `DEFERRED_POLICY`?
6. Do you want an "application" attribution dimension? Today only `use_case` is reliable; a new product-supplied field would be self-declared, not platform-verified.
7. Parent roll-up of cost across children: allowed within one currency (recommended), or per-child only?

## 16. Recommendation

Option A in two steps: **22a** `read_tenant_ai_usage`, `ai.usage:read`, audit, index; **22b** monthly rollup once retention is decided, and the HTTP router following the Gap 20 surface decision. Budget fields light up when Gap 21 ships. Vehicle: dated amendment of ADR-0054 (usage reporting) with cross-reference to ADR-0037; no new ADR. Label 0.Y.0 only if a migration ships, otherwise additive minor per the v0.10.0 precedent.

## 17. Definition of done

Implemented as above; criteria 1 to 13 pass with negative controls on the final tree; documentation (AI-INFERENCE-CONTRACTS section 7, CONSUMER-GUIDE, HTTP-CAPABILITY-MATRIX if a router is added, CHANGELOG, public API snapshot) updated; 7/7 checks green; reviewed; released via `docs/RELEASING.md`; owner decisions recorded in section 18. **Gap 22 is not closed until then.**

## 18. Owner decisions

*Not yet recorded. Implementation is a separate approval.*
