# Gap 21: Monetary AI spending limits: options and recommendation

**Status: Proposal. This document changes no code, test, public contract, migration or ADR.** Proposal submission is not implementation approval.
Written 2026-11-09 on `main` at `0f9bf4d` (v0.10.0, Alembic head `e2b7c4d9a1f6`).
Facts carry a `file:line` citation read from code; a statement with no citation is an inference. "Workspace" means **tenant** (see Gap 20, vocabulary). Text-based AI only; voice AI is a separate future capability.

**No prices, plan names or commercial quotas are proposed here.** They are not approved. Every number in this document is an example of a *field*, not a value.

## 1. What is requested and what it unblocks

Real monetary spending controls next to the existing token quota: monthly budgets per tenant, limits per subscription plan, optional overrides, cost from provider and model pricing, enforcement before a request, a defined concurrency policy, warning thresholds, monthly reset, and a safe response when pricing is missing or stale. The system must never claim a financial cap it does not enforce. Gap 22 reports the remaining budget this gap creates.

## 2. Existing-state audit

**A soft monthly token quota exists.** Entitlement key `ai.tokens` from the tenant's plan (`control_plane/inference/accounting.py:49`, read through `core.billing.get_entitlements`, `:46,168`). Input plus output tokens only (`:151-159,186`). Entitlement values are JSON bool or finite non-negative int/float (`core/billing/catalog.py:341-375`); with several active subscriptions numeric keys combine by MAX, bool by OR (`core/billing/service.py:741-785, 813-836`). Malformed `ai.tokens` refuses with `quota_invalid` (`accounting.py:132-148`). A missing limit is allowed unless `AI_INFERENCE_TOKEN_QUOTA_REQUIRED=true`, which refuses with `quota_not_configured` (`:108-118,177-180`). Unreadable entitlement or ledger refuses with `quota_unavailable` (`:174-185`).

**Enforcement is pre-request, projected and soft.** Order (`service.py:~735-770`): `ai.inference` boolean entitlement (`admission.py:286-296`), then `check_soft_token_quota` (`service.py:753-757`), then the Redis concurrency lease. Projected usage = recorded usage this month + `max(1, ceil(input_bytes/4))` + `max_output_tokens`, refused if above the limit (`accounting.py:186-188`). It is a plain `SELECT SUM` over `control_plane.ai_inference_attempts` by `started_at` (`:151-159`). There is **no reservation, no row lock, no advisory lock**; concurrent requests can overshoot, and in-flight or unknown-usage attempts are not counted (module docstring `accounting.py:11-19`). ADR-0054 records hard caps as open question Q8 and forbids documentation from promising a hard ceiling (`docs/ADR/0054-governed-ai-inference-subsystem.md:403-406, 773, 804`). The Redis lease bounds parallelism (default 4 per tenant, 64 per installation, fail closed; `admission.py:243-244, 299-348`), not spend.

**Period.** UTC calendar month, reset on the 1st at 00:00 UTC (`accounting.py:121-129`). No billing-anchor or subscription-period semantics. The Core `ai.*` metrics use the same window (`core/usage/service.py:387-395`).

**A separate Core quota path exists** and AI admission does not use it: `check_quota`, `consume_quota` with `pg_advisory_xact_lock` and `consume_quota_idempotent` (`core/usage/service.py:418, 467, 573, 597`). It needs the final quantity, so it cannot reserve (ADR-0054:403). It treats a malformed limit as unlimited (`:398-415`), the opposite of the AI path.

**Pricing exists as an estimate only.** Table `control_plane.ai_model_prices` (migration `c5d7e9f1a2b4`; `config/models.py:227-246`): `model_ref`, `pricing_version`, `currency` (ISO-4217, CHECK), `input_per_million`, `output_per_million`, `cached_input_per_million` (`Numeric(18,8)`), `effective_from`; unique on (`model_ref`, `pricing_version`); immutable (a change is a new version; `config/service.py:843-923`, permission `platform.ai_provider:manage`); rates are `Decimal`, 0 to 1,000,000, at most 8 decimals (`:826-840`). `price_in_effect` returns the newest row with `effective_from <= settlement time`, with no expiry or staleness (`accounting.py:63-69`). `estimate_cost` does `Decimal` math per million tokens, quantized to 1e-8 `ROUND_HALF_UP`, returns `None` for no price or unknown counts, never zero (`:72-101`). The result is stored on the attempt (`estimated_cost`, `currency`, `pricing_version`; `attempts.py:547-549`) at settlement (`service.py:496-505`), described as "an estimate, never a billed amount".

**Not present:** any monetary budget; plan-level monetary limits (a `Plan` has only `provider_price_id`, no amount or currency; `core/billing/models.py:25,175`); tenant overrides of entitlements (none exist; the only per-tenant difference is a different plan or subscription); pricing for `cache_write_tokens` and `other_usage` (stored at `attempts.py:543-544`, never priced); cost aggregation anywhere (the platform AI usage totals omit `estimated_cost`; `control_plane/inference/usage.py:410-455`); any threshold or alert (only the unrelated circuit-breaker threshold, `service.py:187-202`); a refusal on missing or stale price (admission ignores prices); a currency guard when summing.

**Usage recording.** One `ai_inference_attempts` row per provider attempt, tenant-owned with RLS (`attempts.py:498-549`): tokens in/out/cached/cache-write, `other_usage` JSON, `usage_provenance` (`provider_reported|estimated|unknown`), state, `possibly_accepted`, cost fields. The `started` row commits before any content is sent (`service.py:395-460`). Settlement locks the row with `SELECT ... FOR UPDATE` and is a no-op unless the state is `started`, which is the double-settlement fence (`:474-520`). Output is returned only after settlement commits (`:999-1010`). A failed or interrupted attempt settles with unknown usage and no cost (`:523-535, 886-937`); stale `started` rows become `abandoned`, `possibly_accepted`, usage unknown (`:339-359`). Only `provider_reported` token counts are mirrored to the Core usage ledger (`ai.input_tokens`, `ai.output_tokens`), through an outbox event in the same transaction (`:145-146, 510-519`; `core/usage/service.py:195-262`). Successful runs are not written to the tenant audit log; the attempt row is the record. Quota and capacity refusals write no audit row (`service.py:734-737`).

**Tests that pin today's behaviour:** `tests/control_plane/inference/test_ai_accounting_unit.py` (cost math, quota, month window, invalid prices), `test_ai_inference_integration.py` (priced and unpriced cost, soft quota refusal, required quota), `tests/core/usage/*`, `tests/api/test_entitlement_quota_dependency_unit.py`.

## 3. Problem statement

A token quota is not a spending cap, and today nothing limits money. A tenant on an expensive model exhausts a budget at a fraction of the token count a cheap model would, and there is no limit, warning or visibility in currency terms. The existing quota also over-admits under concurrency by design. The platform must add a monetary control that is honest about what it enforces: **a cap on the platform's own estimated cost, not a cap on the provider's invoice.**

| # | Gap | Evidence |
|---|---|---|
| G21-1 | No monthly monetary budget per tenant | Section 2 |
| G21-2 | No plan-level monetary limit; entitlements are int/float JSON, unsuitable for currency | `catalog.py:341-375` |
| G21-3 | No tenant or operator override | Section 2 |
| G21-4 | Cost covers input, output, cached input only; cache-write and other units unpriced | `attempts.py:543-544` |
| G21-5 | No pre-request cost check and no reservation | `accounting.py:11-19` |
| G21-6 | No concurrency-safe accounting (the soft quota overshoots by design) | same |
| G21-7 | No thresholds or alerts | Section 2 |
| G21-8 | No staleness concept; missing price does not refuse | `accounting.py:63-69` |
| G21-9 | Price used at settlement time, not at admission | `service.py:496-505` |

## 4. Options

**Option A (recommended): reserve-then-settle monetary budget, with the token quota kept as is.**

*Concepts.* The **effective monthly budget** of a tenant is the lesser of the plan budget and the tenant cap, unless a platform operator sets an explicit override (question 3). Two controls coexist and are both checked; either one can refuse:

| Control | Unit | Source | Enforcement |
|---|---|---|---|
| Token quota (unchanged) | tokens | entitlement `ai.tokens` | soft, projected, no reservation |
| Monetary budget (new) | one currency, `Decimal` | new tables | reserve-then-settle under a row lock |

*Tables (control plane, new).*
- `ai_plan_budgets` (platform-managed): `plan_code`, `currency`, `monthly_amount` `Numeric(18,8)`, `warn_thresholds` (ascending list of percentages), `version`, `effective_from`. Immutable versions, as for prices. Keyed by plan code because entitlements cannot hold currency safely. With several active subscriptions the effective plan budget is the maximum **within one currency**; mixed currencies refuse with `budget_currency_conflict` (question 4).
- `ai_tenant_budgets` (tenant-owned, RLS): `tenant_id`, `currency`, `cap_amount` (nullable), `warn_thresholds` (nullable, inherit plan), set by `ai.budget:manage` (new tenant permission, support access excluded). A tenant cap can only **lower** the effective budget; raising above the plan requires an operator override (`platform.ai_budget:manage`), recorded in `ai_budget_overrides` (platform-owned: tenant id, currency, amount, reason code, `expires_at`, set by, audited).
- `ai_budget_periods` (tenant-owned, RLS): `tenant_id`, `period_start` (UTC month), `currency`, `limit_amount` (effective limit frozen at first use in the period, with the versions it came from), `reserved` , `settled`, `last_threshold_notified`. Unique on (`tenant_id`, `period_start`).
- `ai_budget_reservations` (tenant-owned, RLS): `tenant_id`, `request_id`, `attempt_number`, `amount`, `state` (`held|settled|released|expired_unknown`), `price_version`, timestamps; unique on (`tenant_id`, `request_id`, `attempt_number`).

*Admission (new step after the token quota, before the concurrency lease).*
1. Resolve the candidate and its price **in effect now**. If the tenant has an effective budget and the model has no price, no price in the budget's currency, or a price older than `AI_PRICE_MAX_AGE` (new setting; an `effective_from` older than the limit, or a `reviewed_at` on a new price column, see question 5), **refuse** with `budget_pricing_unavailable`. Never admit on missing data (fail closed).
2. Worst-case cost = estimated input tokens x input rate + `max_output_tokens` x output rate (+ cache-write and other-unit worst cases where the price row defines a rate), rounded **up** at 1e-8.
3. In the tenant transaction: `SELECT ... FOR UPDATE` the period row (create it if absent), refuse if `reserved + settled + worst_case > limit_amount`, otherwise add `worst_case` to `reserved` and insert the reservation. The lock serializes concurrent requests for one tenant; two requests can never both fit if only one fits.
4. The attempt row stores the reservation id and `price_version`.

*Settlement.* In the existing settlement transaction (already `FOR UPDATE` on the attempt, idempotent): compute actual cost with the **same price version as the reservation**, move `reserved` down by the reservation and `settled` up by the actual cost, mark the reservation `settled`. Actual may be lower than the reservation; it cannot exceed it for provider-reported usage unless the provider reports more output tokens than `max_output_tokens`, in which case the overage is recorded and the period may exceed the limit by that amount (documented; the cap is on the platform estimate).

*Failure and unknown outcome.* Provider failure with usage known to be zero (request definitely not accepted) releases the reservation. A possibly-accepted or unknown outcome keeps the reservation `held` at worst case until the stale-attempt sweep marks it `expired_unknown`, which **keeps the worst-case amount charged** for the period (conservative, fail closed) and is reported as such; an operator can release it with an audited action (question 6).

*Thresholds.* When `settled + reserved` first crosses each configured percentage in a period, write one `ai.budget.threshold_crossed` outbox event and one audit row, exactly once (guarded by `last_threshold_notified` in the same transaction). SaaS-OS emits the event; delivering email or an inbox item is the product's job (see issue #230, in-app inbox, open). At 100 % the next admission refuses with `monthly_budget_exhausted`.

*Monthly reset.* A new period row per UTC calendar month, the same window as the token quota, so the two controls reset together. Billing-anchored periods are not proposed (question 7). Unused budget does not roll over. Held reservations at month end belong to the month of their `started_at`.

*Different pricing models.* Extend `ai_model_prices` additively with `cache_write_per_million`, `per_request`, and `unit_rates` (JSON of billable unit name to rate, closed set per provider adapter). Provider-specific names stay in adapters and price rows, never in Core logic. Missing rate for a unit the attempt used means the cost is unknown, which refuses at admission and settles as "cost unknown, reservation retained" (never zero).

**Option B: extend the soft token quota with a cost estimate** (no reservation). Rejected as the sole control: it would keep over-admitting under concurrency and could not honestly be called a cap.

**Option C: a separate prepaid balance or credit system.** Rejected for this proposal: it is a billing product feature with its own money-handling, refund and tax questions, and commercial rules are not approved.

**Option D: rely on provider-side spend limits.** Recommended **in addition**, as an operator control, not as a substitute, because provider limits are account-wide, not per tenant.

## 5. Proposed architecture

Budget logic lives beside accounting in `saas_os/control_plane/inference/budget.py`, called from `service.py` at admission and settlement. It reuses the attempt row, the settlement fence, the outbox, the audit mechanism and the price table. No new provider abstraction; no new metering ledger (the Core usage ledger remains for tokens; the budget period tables hold money). Token quota code is untouched.

## 6. API and interface design

Python (additive, exported from `saas_os.inference`):
- `set_tenant_budget_cap(caller, tenant_id, *, currency, amount | None, warn_thresholds | None)`
- `read_tenant_budget(caller, tenant_id) -> BudgetStatus` (effective limit, source plan/cap/override, settled, reserved, remaining, thresholds, state `ok|warning|exhausted|pricing_unavailable|unconfigured`)
- Platform: `set_plan_budget(...)`, `set_budget_override(...)`, `release_expired_reservation(...)`
- New typed refusals under the existing `InferenceQuotaExceededError` family or a sibling `InferenceBudgetExceededError` with closed reason codes: `monthly_budget_exhausted`, `budget_pricing_unavailable`, `budget_currency_conflict`, `budget_unavailable`.
- New setting `AI_INFERENCE_BUDGET_REQUIRED` (default `false` for compatibility, mirroring `AI_INFERENCE_TOKEN_QUOTA_REQUIRED`; question 8): when true, a tenant without an effective budget is refused with `budget_not_configured`.

HTTP: none in this gap. Reading is exposed through Gap 22.

## 7. Database and migration implications

One migration, four new tables plus additive nullable columns on `ai_model_prices` and on `ai_inference_attempts` (`reservation_id`). All new tenant tables use `tenant_rls_statements`, are classified in `core/tenancy/isolation.py` and `retention.py` (budget periods and reservations: financial-retain; this is a retention decision for the owner, question 9), and are covered by the RLS sweep. Money columns are `Numeric(18,8)`; no floats anywhere. Index on (`tenant_id`, `period_start`). Downgrade drops the tables and loses budget history (document). Label **0.Y.0**.

## 8. Authorization and security model

- Budget reads need `ai.policy:read` or `billing.subscription:read` (see Gap 22 for the tiering); caps need `ai.budget:manage`, excluded from support access, refused for service accounts and system callers. Plan budgets and overrides are platform operations with platform audit.
- **Bypass attempts the design closes:** raising the tenant's own limit (cap can only lower); switching alias or model to dodge a price (price resolved per candidate at admission); omitting `max_output_tokens` (the model's catalogue maximum is used for the worst case); sending many parallel requests (row lock plus reservation); writing the attempts table directly (the app role has no such path; tests assert the grants); submitting a different currency (refused); changing the clock (UTC from the database `now()`); replaying a request id (unique reservation key; settlement fence); a stale price row (staleness refusal); service accounts acting for an admin (refused for `ai.budget:manage`).
- No prompt, completion or credential is stored in the new tables.
- Fail closed: any error reading budget, price or period refuses with `budget_unavailable`.

## 9. Backwards compatibility

A tenant with no plan budget, no cap and `AI_INFERENCE_BUDGET_REQUIRED=false` behaves exactly as today (token quota only). Existing attempt rows are untouched. The cost-at-settlement-time rule changes to cost-at-admission for budgeted tenants only; unbudgeted tenants keep the current estimate behaviour. Migration, new env setting and a new permission are listed in the CHANGELOG and CONSUMER-GUIDE.

## 10. Acceptance criteria (testable)

1. **Budget exhaustion.** After settled + reserved reaches the limit, the next request is refused with `monthly_budget_exhausted` before any content is sent and no attempt row is started.
2. **Concurrency.** N parallel requests whose worst cases sum above the limit: the number admitted never exceeds what fits; `settled + reserved` never exceeds the limit at any observed instant (barrier-synchronized test, run repeatedly).
3. **Pricing changes.** A new price version after admission does not change the reserved or settled amount of an in-flight attempt; the next attempt uses the new version; a price that is stale or absent refuses.
4. **Provider pricing models.** Input/output, cached input, cache-write, per-request and per-unit prices each compute the expected `Decimal` cost; an unpriced billed unit yields unknown cost and keeps the reservation.
5. **Missing price.** No price, wrong currency or stale price refuses with `budget_pricing_unavailable`; cost is never recorded as zero.
6. **Monthly reset.** Usage at 23:59:59 UTC on the last day counts to the old month; 00:00:00 starts a new period with a fresh limit; leap and year boundaries covered; held reservations stay with their month.
7. **Overrides.** A tenant cap below the plan lowers the limit; a tenant cap above the plan has no effect; an operator override raises it and expires at `expires_at`.
8. **Plan limits.** Plan change mid-month: the period keeps its frozen limit until the next period unless the owner decides otherwise (question 10); multiple subscriptions combine by the stated rule; mixed currency refuses.
9. **Provider failures.** Definite non-acceptance releases the reservation; a timeout or unknown outcome retains the worst case and appears as `expired_unknown`; double settlement is a no-op.
10. **Bypass.** Each case listed in section 8 has a test that fails if the defence is removed.
11. **Thresholds.** Each configured percentage fires exactly once per period, including under concurrency, and survives a crash between settlement and notification (outbox).
12. **Token quota coexists.** A request within budget but over token quota is refused with the token reason; within token quota but over budget is refused with the budget reason; the token code path is unchanged (existing tests untouched and green).
13. **Honesty.** No docstring, error message, API field or document states a "hard", "guaranteed" or "invoice" cap; a test greps public docstrings and error text for the prohibited words.
14. **Secrets and privacy.** No credential, prompt or completion appears in any new row, audit metadata or log.
15. **Negative controls.** Removing the row lock, the reservation, the price-staleness check, the currency check, or the RLS predicate each fails a named test.

## 11. Automated test strategy

Unit: cost math (property tests against an independent `Decimal` oracle, rounding direction), period boundaries, threshold state machine. Integration on the disposable Postgres with `FakeAdapter` (configurable usage, latency and failure modes; no real provider, no network, no cost): concurrency with real transactions, settlement fence, crash injection between reservation and settlement, outbox idempotency. Migration up/down and RLS sweep. Architecture: public API snapshot, import boundaries, prohibited-claims grep. Existing `test_ai_accounting_unit.py` and `test_ai_inference_integration.py` stay and must pass unchanged.

## 12. Operational considerations

- **Estimates versus invoices (unavoidable differences).** The platform figure is `tokens x listed rate` from the operator's price table. It can differ from the provider invoice because of: rate changes between price-table update and provider change; volume or committed-use discounts; tiered or long-context pricing; cached-token and batch pricing the adapter does not report; tokens the provider bills but does not report (failed or cancelled calls, retries inside the provider); usage reported late or corrected; rounding and minimum charges; currency conversion and tax; provider-side features billed outside tokens. Therefore the control is "estimated platform spend", the UI/API label must say so, and finance must reconcile against invoices outside SaaS-OS.
- Operators must keep prices current; a stale-price refusal is the intended alarm, and it needs alerting (depends on the observability decision, ADR-0009).
- Reservation holds can briefly lock budget for long calls (bounded by the request deadline of 120 s default, `egress_config.py:69-88`). Large `max_output_tokens` reserve more; products should set it tightly.
- Row-lock contention is per tenant and short; not load tested (not verified).
- Runbook entries: releasing an `expired_unknown` reservation, setting an override, price update procedure.

## 13. Dependencies

Gap 20 (selected model per use case; hold table for optional automatic suspension with reason `spending`). Core billing API to resolve a tenant's active plan codes (to be verified; the audit found entitlement access but not a plan-code list). Gap 22 consumes the budget status and the period tables. ADR-0054 amendment resolving Q8 (hard-cap requirements) and ADR-0037 cross-reference.

## 14. What could not be verified

Whether `core.billing` exposes active plan codes per tenant; whether an index on (`tenant_id`, `started_at`) already serves the token-quota SUM (migration `a7f3c91e2d48` not checked for it); lock contention at scale; any provider's real usage reporting and invoicing behaviour (no provider is configured; none is called by this work); `docs/ADR/0037-usage-metering-semantics.md` body.

## 15. Open questions only the owner can answer

1. Approve the reserve-then-settle design (Option A) as the vehicle for ADR-0054 Q8?
2. Are all spending-related field names and warning defaults acceptable, given prices and plans are not approved? (This proposal sets no values.)
3. Tenant admin may only lower the effective budget; raising needs an operator override. Agree?
4. Mixed-currency subscriptions: refuse (recommended), or define a conversion source (adds FX rates and staleness)?
5. Price staleness: global `AI_PRICE_MAX_AGE` setting, or a per-price `reviewed_at`/`valid_until` column?
6. Unknown-outcome reservations: keep worst case charged until an operator releases (recommended) or release after a fixed time?
7. Billing-anchored periods instead of UTC calendar month: out of v1 (recommended)?
8. Default for `AI_INFERENCE_BUDGET_REQUIRED` and `AI_INFERENCE_TOKEN_QUOTA_REQUIRED`: keep `false` for compatibility, or document `true` as the production default?
9. Retention class and period for budget periods and reservations (financial-retain proposed).
10. Plan change mid-month: freeze limit until next period (recommended) or apply immediately?
11. Automatic suspension at exhaustion: refusal only (recommended; reversible at reset) or also set a Gap 20 hold?

## 16. Recommendation

Option A, implemented in three steps: **21a** price-table extension and staleness (no enforcement); **21b** budget tables, reservation, settlement and refusals behind `AI_INFERENCE_BUDGET_REQUIRED`; **21c** thresholds and events. Add Option D as an operator checklist item. Vehicle: dated ADR-0054 amendment resolving Q8. Label 0.Y.0.

## 17. Definition of done

Implemented as above; criteria 1 to 15 pass with negative controls on the final tree; migration tested up and down; public API snapshot, CHANGELOG, CONSUMER-GUIDE, AI-INFERENCE-CONTRACTS section 7 and ADR-0054 amended; the documentation says "estimated platform spend" and lists the invoice differences of section 12; 7/7 checks green; reviewed; released via `docs/RELEASING.md`. **Gap 21 is not closed until then.** No real provider is activated and no provider cost is incurred by any step of this work.

## 18. Owner decisions

*Not yet recorded. Implementation is a separate approval.*
