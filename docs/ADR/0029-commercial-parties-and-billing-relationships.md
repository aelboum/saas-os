# ADR-0029: Commercial parties and billing relationships

Status: Accepted — architecture locked (Billing Foundation v2, Phase 0 + 1); Phase 2 (commercial party model) and Phase 3 (billing lifecycle safety) implemented — see "Implementation status" below; later phases as recorded below. **Amended 2026-10-02** for roadmap Phase 5.3 B2B2C Billing Completion, implemented (Phase 5.3 complete; post-5.3 audit remediation `636f7bf`) — see "Amendment (2026-10-02)" below.
Date: 2026-10-01
Supersedes / Superseded by: — (amends the scope of [ADR-0008](0008-billing-provider.md); refines [ADR-0022](0022-tenant-session-boundary-enforcement.md)'s catalog classification — see the amendment sections appended to both)

## Context

`core/billing` today has exactly one party slot and exactly one seller:

- **One party slot.** `core.billing_subscriptions.tenant_id` (`core/billing/models.py::Subscription`) is simultaneously the payer, the subscription owner, the entitlement owner and the service recipient. Nothing else in the schema names a party.
- **One seller.** The only payee is the deployment-wide provider account: `core/billing/service.py::_default_provider()` builds a `StripeBillingProvider` from the single `STRIPE_API_KEY` secret. `core.billing_plans` (`Plan`) has no owner, so every plan is implicitly sold by the deployment.
- **Provider customer identity is not modeled.** `core/billing/stripe_provider.py::StripeBillingProvider.create_subscription()` creates a new provider customer on every call, tagged with `metadata.tenant_id`, and never persists its id.
- **Hierarchy billing is entitlement sharing, not a payment relationship.** `Tenant.inherits_billing` plus `core/billing/service.py::resolve_billing_owner()` let a child read an ancestor's *entire* entitlement map and redirect upgrade/cancel to the ancestor's subscription. It cannot express who pays whom, and `core/usage/service.py::consume_quota()` counts an inheriting child's usage against the full inherited limit per child (the pool is multiplied, not shared).

As a result SaaS-OS cannot represent ordinary commercial structures that products built on it need: a tenant paying for another tenant's service; a tenant selling its own plans to other tenants (B2B2C, marketplaces, franchises); two independent commercial relationships stacked on top of each other. A product that needs any of these today either cannot build it, or builds a parallel catalog/subscription model outside SaaS-OS (the failure mode found when auditing a consuming product: a product-owned "resale plan" table mirrored into SaaS-OS's global catalog, leaking every tenant's commercial configuration through an unfiltered plan listing and routing every payment to the deployment's own provider account).

The read-only Billing Foundation v2 audits (2026-10-01, against HEAD `78f03b3`) are the evidence base for this ADR.

## Options Considered

### Option A — Tenant is the payer (status quo)

`Tenant → Subscription → provider customer`.

- Advantages: no new concepts; nothing to migrate.
- Disadvantages: payer ≠ service recipient is unrepresentable; payee is always the deployment; provider customers are wrongly keyed by tenant alone, even though a provider customer exists *inside* exactly one merchant account. Cannot support anything beyond direct B2B with one seller.

### Option B — Separate payer (BillingAccount) and payee (MerchantAccount); the subscription carries the relationship

`MerchantAccount (payee) ← BillingAccount (payer, scoped to one merchant) ← Subscription → service tenant`.

- Advantages: every party is named exactly once. Payer comes from the billing account, payee comes from the account's merchant, and the recipient is the subscription's service tenant. Supports direct B2B, sponsored (payer ≠ recipient) and stacked B2B2C relationships with two new entities. Maps exactly onto how payment providers scope customers (per merchant account). The existing subscription RLS column keeps its meaning.
- Disadvantages: two new entities plus a backfill; cross-tenant writes (payer, payee and service tenant are different RLS owners) become multi-step operations.

### Option C — A first-class, multi-party BillingRelationship entity

`Payer → BillingRelationship → Subscription → ServiceRecipient`, with relationship type, status and effective dates.

- Advantages: can represent a standing commercial agreement independent of any subscription.
- Disadvantages: every field it would hold (payer, payee, recipient, status, effective period) is already implied by `Subscription + BillingAccount + MerchantAccount` under Option B. A "relationship type" column tends to become an enum of business models (`agency`, `reseller`, `sponsor`), which is exactly the product leakage this platform must avoid. Standing authority ("tenant X may pay for tenant Y") is an *authorization* fact the existing `core/rbac` delegation model already represents.

## Recommendation

Option B. Option C is not adopted for the foundation; revisit it only if a product needs standing contractual terms that exist independently of any subscription (closer to contract management than to billing primitives).

## Decision

**Accepted (2026-10-01).** SaaS-OS adopts a three-party commercial model. These primitives are introduced by later phases of Billing Foundation v2; none exist yet.

### Parties

| Term | Meaning | Represented by |
|---|---|---|
| **Payee** | the party that sells and receives payment | `MerchantAccount.owner_tenant_id` |
| **Payer** | the party that is charged | `BillingAccount.owner_tenant_id` |
| **Service recipient** | the tenant that receives the service and its entitlements | `Subscription.tenant_id` (the *service tenant*) |

Payer, payee and service recipient are independent. They may coincide (a direct customer subscribing for itself has payer = recipient), but no code may assume they do.

### Primitives (target shape, conceptual — exact columns are fixed by the implementing phase)

```text
MerchantAccount          RLS owner: payee
  id, owner_tenant_id, provider, provider_account_ref, status

BillingAccount           RLS owner: payer
  id, owner_tenant_id, merchant_account_id, provider_customer_ref, status
  UNIQUE (owner_tenant_id, merchant_account_id)

Subscription             RLS owner: service tenant (existing core.billing_subscriptions)
  id, tenant_id (= service tenant), billing_account_id, plan_version_id, price_id, status,
  provider, provider_subscription_ref, period / trial / cancellation fields

Plan                     non-RLS catalog, application-level eligibility (ADR-0022 amendment)
  id, owner_tenant_id, merchant_account_id, key, visibility, status, name, description, metadata
PlanVersion              plan_id, version, entitlements (immutable once subscribed)
Price                    plan_version_id, currency, amount_minor, interval, interval_count, trial_days, status
ProviderPriceRef         price_id, provider, provider_product_id, provider_price_id

Invoice (minimal mirror) RLS owner: payer
  provider_invoice_ref, billing_account_id, subscription_id, service_tenant_id, status,
  currency, amount_due, amount_paid, period_start, period_end, hosted_url
SellerSubscriptionView   RLS owner: payee (non-sensitive projection of what a merchant has sold)
```

A **payee** is derived, never stored on the subscription: `subscription → billing_account → merchant_account → owner_tenant_id`.

### Invariants future implementations must preserve

1. **Merchant identity.** `MerchantAccount.owner_tenant_id` identifies the payee. A merchant is fully identified by its owner tenant plus its provider account. There is **no merchant-type enum**: a "platform merchant" is simply a merchant owned by the platform tenant, and an "external merchant" is a merchant owned by any other tenant (`provider` may be a payment provider, or a value meaning payment is collected outside SaaS-OS).
2. **Billing account uniqueness.** `UNIQUE (owner_tenant_id, merchant_account_id)`. Provider customer identity is `(payer tenant, merchant) → provider customer`, never `tenant → provider customer`. The same payer has a different provider customer at each merchant it pays.
3. **Service tenant.** `Subscription.tenant_id` is the tenant receiving the service. The column is **not renamed**. Its meaning is made explicit, and it is what the subscription's existing RLS policy already keys on.
4. **Merchant compatibility.** `Plan.merchant_account_id = BillingAccount.merchant_account_id` for every subscription. A payer can only subscribe to a merchant's plans through its billing account at that merchant.
5. **One live subscription.** Default: at most one *live* subscription per `(service tenant, merchant)`, unless the plan explicitly supports add-ons/quantities. It must be enforced at the database level (partial unique index), not only in application code.
6. **Dual authorization.** Creating a subscription (and therefore a sponsored one) requires **both** `can(actor, payer tenant, billing.account:charge)` **and** `can(actor, service tenant, billing.subscription:create)`. The payer is never trusted from request input alone.
7. **Entitlements follow the service tenant.** A subscription's entitlements are granted to its service tenant. The payer does **not** receive them merely because it pays.
8. **Platform is a tenant.** Every plan and merchant has a real `owner_tenant_id`. `owner_tenant_id IS NULL` must not be given a special "platform" meaning (Decision 0.2 below).

### RLS ownership

| Entity | RLS owner | Why |
|---|---|---|
| `Subscription` | service tenant | Preserves today's FORCE RLS on `core.billing_subscriptions` unchanged (`tenant_id` policy, `infra/db/rls.py::tenant_rls_statements()`). Preserves the entitlement hot path: `get_entitlements(tenant)` remains a single-tenant read of `WHERE tenant_id = :tenant`. The payer is irrelevant to entitlement evaluation, so a sponsored subscription adds no cross-tenant read to the hot path. |
| `BillingAccount` | payer | Payment methods, provider customer and charges belong to whoever is charged. |
| `Invoice` | payer | Invoices are addressed to the payer. |
| `MerchantAccount` | payee | The merchant's provider account and status belong to the seller. |
| `SellerSubscriptionView` | payee | A payee needs to see what it sold without gaining access to the payer's or recipient's rows. The payee is not necessarily an ancestor of either, so a projection owned by the payee is used. RLS is never widened and no `SECURITY DEFINER` is introduced. |
| `Plan` family | none (catalog) | See the ADR-0022 amendment: owner-scoped, application-level eligibility. |
| `ProviderRef`, `ProviderEvent` | none (global-by-design) | See the ADR-0022 amendment: provider events arrive before the tenant is known. |

Because payer, payee and service tenant are different RLS owners, one commercial operation may write rows under several tenants. These writes are separate `tenant_session_scope()` transactions, made idempotent and reconcilable (Billing Foundation v2 Phases 5–6). They never share a single cross-tenant transaction and never bypass RLS. This mirrors the deliberate scope switching `resolve_billing_owner()` already performs.

### Billing graph versus tenant hierarchy

The tenant hierarchy (`Tenant.parent_id`, `core.tenant_ancestry`) is an **authorization and visibility structure**. The billing graph is **payer → payee** (`BillingAccount → MerchantAccount`) and **service recipient ← subscription**.

The hierarchy may be used as an *input* to:

- authorization (e.g. a `SUBTREE`-scoped role over descendants' billing — `core/rbac/scope.py::RoleScope`);
- catalog visibility (`descendants` visibility);
- catalog eligibility.

It must **never by itself imply** that a parent pays for a child, that a child pays a parent, or that a child inherits a parent's subscription or entitlements. Each of those is an explicit commercial relationship: a subscription with a specific billing account and service tenant. Two tenants may have a billing relationship with no hierarchy relationship at all, and siblings under one parent may have entirely different payers and payees.

Example used only to clarify the generic model: tenant C pays tenant B €149 per month for a plan B owns, and B independently pays the platform tenant P €99 per month for a plan P owns. These are **two independent subscriptions** at two different merchants (B's and P's). SaaS-OS records both. It does not record, compute or settle the €50 difference — margin is an emergent fact of two prices, owned by the product.

### Catalog

- SaaS-OS owns the catalog **schema and runtime engine**. The product or operator owns the catalog **content** (plan names, prices, entitlement bundles).
- Every plan has an owner tenant and a merchant. Visibility is one of `public`, `descendants`, `private`, `unlisted`. No product-shaped visibility or plan-type names are allowed (no `agency_plan`, `reseller_plan`, `client_plan`, `white_label_plan`).
- Plans are **versioned**: a `PlanVersion`'s entitlements are immutable once any subscription references it. Changing a plan creates a new version, and existing subscribers keep their version until migrated.
- Provider price ids are **references** (`ProviderPriceRef`), never the source of truth for pricing. Provider references must not appear in generic catalog DTOs.
- **One eligibility predicate** is shared by catalog listing, checkout and subscription creation:

  ```text
  plan.status = active
  AND can(actor, service_tenant, billing.subscription:create)
  AND (
        visibility = public
     OR (visibility = descendants AND service_tenant is a strict descendant of plan.owner_tenant_id)
     OR (visibility = private     AND can(actor, plan.owner_tenant_id, billing.catalog:read))
     OR (visibility = unlisted    AND an explicit offer of this plan to service_tenant exists)
  )
  ```

  Knowing a plan key or id never grants eligibility.

### Billing authorization

There is **no second authorization system**. Billing operations are permissions evaluated by the existing `core/rbac/authorization.py::can()`, including `SUBTREE` scope, `DelegationGrant` (explicit authority across unrelated tenants) and `DenyGrant`. Target vocabulary, registered generically by SaaS-OS; which roles receive it is a product decision:

```text
billing.catalog:{read,manage}                                   on the plan owner tenant
billing.merchant:{manage}                                       on the payee tenant
billing.account:{read,manage,charge}                            on the payer tenant
billing.subscription:{create,read,change,cancel,reactivate}     on the service tenant
billing.invoice:{read}                                          on the payer tenant (seller projection: payee tenant)
```

SaaS-OS commercial entry points that accept an actor enforce invariant 6 themselves. A payer field must never ship without the `billing.account:charge` check (Billing Foundation v2 Phase 2).

### Provider boundary

- Provider-specific concepts stay inside provider adapters. Core must not acquire provider- or product-specific domain types such as `ConnectAccount`, `StripeConnectAccount`, `AgencyMerchant`, `ResellerMerchant` or `PlatformMerchant`.
- A provider's own merchant/connected-account identifier (e.g. a Stripe Connect account) maps to `MerchantAccount.provider_account_ref`, and the adapter uses it as its per-request account context.
- Application fees, payouts, settlement and marketplace economics are provider and product concerns. If a product needs one, it is passed through the adapter as opaque provider options, never modeled in core.

### Phase 0 decisions (locked)

**0.1 — RLS ownership.** As in the RLS ownership table above. `Subscription.tenant_id` = service tenant, and it is not renamed.

**0.2 — Platform as tenant.** The deployment's own commercial identity is an ordinary `core.tenants` row with a designated operational role in that deployment (it owns the platform `MerchantAccount` and the platform-owned plans). There is no `NULL`-owner special case and no global special-case billing owner. Each SaaS-OS deployment has its own database (ADR-0015), so "platform tenant" is a per-deployment designation. How it is designated and created (operator command, following the `api/tenant_bootstrap.py` pattern) is implemented in Phase 2, not here.

**0.3 — Merchant identity.** `owner tenant + provider + provider_account_ref + status`. No `MerchantType` enum (`platform | external` is redundant with "who owns it" and "which provider"), and no provider- or product-specific merchant subtypes.

**0.4 — Quota fail-closed policy.** The target is that **billed/monetized quota enforcement fails closed**. Today `core/usage/service.py::_numeric_limit()` treats a missing or non-numeric entitlement as "no limit", and `tests/core/usage/test_quota_enforcement_integration.py::test_no_configured_limit_never_denies` asserts that. Semantics:
- **Boolean entitlement absent** → denied (unchanged; already fail-closed).
- **Numeric quota absent** → currently unlimited; becomes fail-closed for billed metrics.
- **What a metric means**, and which metrics are billed, is product-owned.

Because SaaS-OS is 0.x and consumers may depend on the current behavior, the change is staged:

```text
current 0.x behavior (absent numeric limit = unlimited)
  → configurable compatibility mode (explicit opt-in to fail-closed)
  → deprecation warning / migration period while the compatibility mode is the default
  → fail-closed default for billed metrics
```

Not implemented. Phase 3 deliberately excluded this rollout (see "Implementation status" below), and it remains deferred (Phase 5.3 "Deferred"). `core/usage/service.py` is unchanged by this ADR.

**0.5 — Existing active subscriptions.** Rows currently marked `active` were written as soon as a provider returned an object id (`core/billing/service.py::subscribe()`), with no payment confirmation. They are treated as **legacy-unverified until reconciled**:
- never silently assumed paid;
- never automatically deleted;
- never changed by this ADR.

Phase 3 defines the procedure, which must include:
- provider reconciliation where provider references exist;
- an explicit legacy/unverified representation where confirmation cannot be established;
- preservation of all existing rows, with no destructive cleanup by migration;
- a consumer-compatibility analysis before status semantics change, since consumers read `status == "active"`.

No status value is added to the database by this ADR.

### `inherits_billing` (legacy, frozen)

`Tenant.inherits_billing` / `resolve_billing_owner()` is legacy behavior and must not become the commercial billing graph. Its future semantic replacement is: *parent pays for child* = a **sponsored subscription** (billing account owned by the parent, service tenant = the child). It is not *child inherits the parent's entire subscription and entitlement map*.

*Origin and numbering.* This mechanism (migration `d9da5514672b`, commit `0c5d066`) was built from an external architecture-research plan for universal multi-tenant tenancy, whose steps are labelled Phase A–J; code docstrings still cite it as "architecture research Phase H". Those letters, and the "Billing Foundation v2 Phase N" numbers in this ADR, are not roadmap phases. All billing work is sequenced under Phase 5 of `docs/IMPLEMENTATION-ROADMAP.md`; see its "Phase 5 billing status after 5.2" section.

**Superseded (2026-10-02):** the re-expression is now decided — see "Amendment (2026-10-02)", "`inherits_billing`: retired forward". The freeze below applied until that decision:

Until Phase 7 decides the re-expression and migration path:
- existing behavior is frozen and preserved;
- no new consumers;
- no removal;
- no implementation change.

### Migration principles (binding on every implementing phase)

- Migrations are **additive where possible**: nullable column → backfill → constraint.
- Existing subscriptions are **never deleted automatically**, and existing `active` rows are **not assumed paid** (0.5).
- Existing plans are **backfilled** into the ownership model: owner = platform tenant, visibility = `public`, status = `active`, which preserves today's behavior exactly.
- Compatibility shims are expected. For example, the current `subscribe(tenant_id, plan_key)` signature keeps working by resolving the tenant's own billing account at the platform merchant.
- The existing **global uniqueness of plan keys may remain** during the transition, until consumers address plans by `(owner, key)`.
- **Destructive migration requires separate, explicit approval.**
- Tests that currently enforce the pre-v2 model are rewritten in the phase that changes the behavior they pin, not before. These are `test_plans_has_no_tenant_id_column`, `test_plans_has_no_tier_rank_or_price_column`, `test_get_entitlements_does_not_crash_with_two_active_subscriptions`, the Stripe lifecycle test asserting immediate `active`, and `test_no_configured_limit_never_denies`.

## Implementation status

**Phase 2 — commercial party model (implemented, migration `6e99825a629c`).**

- `core.billing_merchant_accounts` (payee, RLS) and `core.billing_accounts` (payer, RLS). The owner column is named `tenant_id`, the repository-wide RLS convention; this ADR's `owner_tenant_id` is that column. `core.billing_accounts (merchant_tenant_id, merchant_account_id)` is a composite FK, so the recorded payee is always the merchant's real owner.
- `core.billing_subscriptions` gains `payer_tenant_id` + `billing_account_id` (composite FK into `core.billing_accounts`, both-or-neither) and `provider`, all nullable. `tenant_id` is unchanged and remains the service tenant. Pre-Phase-2 rows keep NULLs: no payer, account, provider or provider customer is backfilled.
- `core.billing_provider_refs`, the global-by-design index, allowlisted in `tests/architecture/test_tenant_session_boundary.py`.
- The platform tenant is designated by configuration: `PLATFORM_TENANT_ID` (`core/tenancy/config.py`; `core.tenancy.get_platform_tenant_id()`/`require_platform_tenant()`). Unset means `PlatformTenantNotConfiguredError`.
- `core/billing/authorization.py` holds the permission vocabulary and the explicit callers: `BillingActor.user(...)` or `trusted_system(reason)`, never `None` (Phase 2 state; superseded by the `core.authority` callers of ADR-0031's amendment, Phase 5.3 step 1). Only user principals are accepted in Phase 2; service-account billing actors are deferred because audit attribution is tenant-bound.
- `core/billing/commercial.py::create_subscription()` is the dual-authorized entry point. Until Catalog v2, plans are sold only by a merchant owned by the platform tenant, and activation is still unconfirmed (Phase 3).
- The legacy `subscribe()`/`subscribe_idempotent()`/`upgrade_subscription()`/`cancel_subscription()` are unchanged trusted in-process paths. They now record `provider` but no payer.

**Phase 3 — lifecycle safety (implemented, migration `41e8273a685d`; `core/billing/lifecycle.py`).**

- **Lifecycle** (`SubscriptionStatus`):

  | Current | Allowed next states |
  |---|---|
  | `pending` | `active`, `past_due`, `canceled` |
  | `active` | `past_due`, `canceled` |
  | `past_due` | `active`, `canceled` |
  | `canceled` | none (terminal) |

  A same-state transition is a no-op. Nothing returns to `pending`, and nothing resurrects `canceled`. `lifecycle.set_subscription_status()` is the only code that assigns `Subscription.status` (pinned by a static test). There is no public "set status" entry point.
- **Live** means `pending`, `active` or `past_due`. Only `active` grants entitlements. `past_due` grants nothing; a grace policy is a later decision.
- **Verification** (`verified` | `legacy_unverified`) is a separate column. Every pre-Phase-3 row is `legacy_unverified`, including Phase 2 commercial rows, whose `active` was never confirmed. Rows created by the legacy `subscribe()` path are `legacy_unverified` too. No status was rewritten.
  - *Compatibility decision:* a legacy row keeps its pre-Phase-3 effect. A legacy `active` row still grants entitlements, because consumers depend on it. Revoking unverified legacy entitlements is a later, opt-in policy change, not something this phase does silently.
- **Provider-confirmed activation.** `create_subscription()` always writes the row `pending`. It moves only through `get_subscription_status()`, the provider-neutral `ProviderSubscriptionState`: `active` / `pending` / `past_due` / `canceled` / `not_found` / `unknown`, with an outage raised as `BillingProviderError`.
  - `not_found`, `unknown` and an outage never change a row and never activate one. The row stays `pending` and the caller gets that state.
  - The provider object is never deleted automatically.
  - Reconciliation is covered in its own bullet below. No provider events exist yet.
  - The Stripe adapter maps `active`→active, `incomplete`→pending, `past_due`/`unpaid`→past_due, `canceled`/`incomplete_expired`→canceled. It maps `trialing`, `paused` and anything new to `unknown`.
- **One live subscription per (service tenant, merchant).** `Subscription.merchant_account_id` is recorded, and a composite FK guarantees it is the billing account's merchant. The partial unique index `uq_billing_subscriptions_one_live_per_merchant` is on `(tenant_id, merchant_account_id) WHERE merchant_account_id IS NOT NULL AND status IN ('pending','active','past_due')`.
  - Rows without a merchant (legacy, unreconciled) are outside the index until reconciled.
  - The application pre-check only improves the error. A lost race maps to `LiveSubscriptionExistsError`.
  - If two different requests race past the pre-check, the loser's provider subscription is not deleted. Its provider reference remains, pointing at no row, for later reconciliation.
- **Provider idempotency.** The provider idempotency key and the local subscription id are both derived from the durable `core.idempotency` reservation id. That id is one row per (service tenant, operation, client key, request fingerprint). Retries, restarts and abandoned attempts therefore reuse the same provider key and the same local row. Concurrent duplicates get `IdempotencyInProgressError`, and a reused key with a different request gets `IdempotencyKeyReusedError`. Stripe receives the key as its `Idempotency-Key`, suffixed per request. On a retry, a provider subscription that an earlier attempt already recorded durably is reused, and the provider is not asked to create again. "Recorded" means on the local row, or in the provider-reference index registered for this local id. Safety therefore doesn't depend on the provider's own idempotency window. The provider key alone covers only the narrow crash window between the provider call returning and the reference being registered. Adapters must declare `honors_idempotency_keys = True`; the commercial path refuses any that don't (`BillingProviderContractError`).
- **Legacy reconciliation.** `reconcile_legacy_subscription()` is the only way out of `legacy_unverified`.
  - The caller is authorized like creation: `billing.account:charge` on the payer AND `billing.subscription:create` on the service tenant.
  - The caller supplies the authoritative payer billing account. It must agree with any payer the row already records.
  - The provider must positively confirm the row's provider subscription, and its state must be reachable through an allowed transition.
  - The provider reference is then registered, payer/merchant/provider are recorded, and the row becomes `verified`. The step is audited as `billing.subscription_reconciled`.
  - Any failure leaves the row unchanged.
- **Duplicate-live remediation runbook.** Migration `41e8273a685d` refuses to run while any `(tenant_id, merchant_account_id)` group holds more than one live subscription, and changes nothing.
  1. Inspect the reported groups: `SELECT tenant_id, merchant_account_id, count(*) FROM core.billing_subscriptions WHERE merchant_account_id IS NOT NULL AND status IN ('pending','active','past_due') GROUP BY 1, 2 HAVING count(*) > 1`.
  2. Decide per group which subscription is genuine. That is a business decision, never automated.
  3. Cancel the others at the provider and locally.
  4. Re-run the migration.
- **Reconciliation.** `reconcile_subscription_status()` (requires `billing.subscription:read`) is the synchronous reconciliation boundary for a `verified` subscription. In order:
  1. The row is read under the service tenant's RLS scope.
  2. Its provider identity is re-verified through the Phase 2 provider-reference index. The payer's billing account names the merchant, and that merchant's provider account plus the row's provider and provider subscription id must resolve back to exactly this row in this tenant (`ProviderReferenceMismatchError` otherwise). Provider-side metadata is never consulted.
  3. The provider is asked for its authoritative state, which is applied only through an allowed transition.
  - Provider errors raise and change nothing. `not_found`, `unknown` and lifecycle-forbidden transitions change nothing.
  - Re-running with an unchanged provider state is a no-op.
  - `legacy_unverified` rows are refused; they go through legacy reconciliation.
- **Cancellation safety.** `cancel_commercial_subscription()` (requires `billing.subscription:cancel`; `verified` rows only) works as follows:
  - It is idempotent when the row is already `canceled`.
  - It re-verifies the provider reference, then cancels through `cancel_at_provider()`.
  - That helper tolerates a provider that has *already* canceled: if the provider's cancel call fails, the provider's own status must positively report `canceled` to count as done.
  - `not_found` (ambiguous), any other state, or an outage re-raises and leaves the local row unchanged. A local row is never marked canceled on uncertainty.
  - Provider canceled but local write failed? A retry, or `reconcile_subscription_status()`, converges the row to `canceled`.
  - The legacy `cancel_subscription()` uses the same tolerant helper; its authorization is unchanged.
- **Deferred to later phases:**
  - provider-event ingestion and the `ProviderEvent` ledger; *(implemented for subscription status on 2026-10-15 by ADR-0048)*
  - asynchronous reconciliation, including dangling provider references and orphaned provider objects;
  - checkout sessions; *(a payment page for a subscription Core created is ADR-0052, 2026-10-15; Checkout Sessions themselves are not used)*
  - trials (Stripe `trialing` is `unknown`);
  - pause, cancel-at-period-end, reactivation and plan-change semantics (`upgrade_subscription()`/`cancel_subscription()` are the unchanged legacy operations; cancel now goes through the lifecycle);
  - an entitlement policy for `past_due` grace and for unverified legacy rows;
  - the quota fail-closed rollout (Decision 0.4): deliberately not part of this billing-safety phase; a separate phase;
  - Catalog v2.

## Amendment (2026-10-02): Phase 5.3 B2B2C Billing Completion

**Status: Accepted and implemented — Phase 5.3 complete (steps 1–8)** (see the step status sections below and the ADR-0031 amendment's "Implementation status"). This amendment records the decisions approved for roadmap Phase 5.3 (`docs/IMPLEMENTATION-ROADMAP.md`). It completes the model above and does not replace it. Where it supersedes an earlier statement in this ADR, it says so in "Superseded statements" below. How each decision was implemented is recorded in the "Implementation status" sections that follow the decisions.

### Domain concepts (kept distinct, never inferred from one another)

| Concept | Represented by | Rule |
|---|---|---|
| Service tenant | `Subscription.tenant_id` | **Unchanged** (decision 0.1). It remains the subscription's RLS owner. |
| Payer tenant | `Subscription.payer_tenant_id` + `billing_account_id` → `BillingAccount` | Named explicitly by the caller and authorized with `billing.account:charge`. Never inferred from the hierarchy, the merchant or the service tenant. |
| Merchant | `Plan.merchant_account_id` = `Subscription.merchant_account_id` = the billing account's merchant | Fixed by the plan being sold. Never inferred from the payer. |
| Entitlement recipient | The service tenant | The payer and the merchant receive no entitlements (invariant 7). |
| Usage owner | `core.usage_events.tenant_id` | The tenant where usage occurred ([ADR-0037](0037-usage-metering-semantics.md)). Never moved by a payer, merchant or hierarchy change. |

**Sponsored billing** is the canonical "someone else pays" relationship:

```text
service tenant = the tenant receiving the service (e.g. a client)
payer tenant   = the tenant paying for it          (e.g. its agency or parent)
merchant       = the merchant selling the plan
```

It is an ordinary subscription whose payer differs from its service tenant. It is never derived from the hierarchy.

**Authority is not ownership.** A role held through the hierarchy (a `SUBTREE` scope) or by delegation can authorize a caller to act *for* a tenant in that tenant's own capacity. It never makes the caller the payer, the merchant or the billing-account owner. Payer and merchant capacities are decided only by the canonical subscription row's recorded payer and merchant.

### Merchant-owned catalog

Plans stop being deployment-global commercial objects. The target model is:

- **Ownership:** each plan has an owner tenant and a merchant account owned by that tenant.
- **Visibility:** `public` | `descendants` | `private` | `unlisted`, as in "Catalog" above.
- **Lifecycle status:** `active` | `withdrawn`. Withdrawal stops new subscriptions only.
- **Uniqueness:** plan keys are unique per owner, not deployment-wide. A duplicate-key error must not disclose another owner's catalog.
- **Offers:** an `unlisted` plan is eligible only through an explicit offer of that plan to a service tenant. The offer is owned by the plan owner.
- **Legacy plans:** existing plans without an owner are adopted by the platform tenant through an explicit operator action (migration principles above). Until then they stay usable only by the legacy `subscribe()` path. `NULL` never means "platform" (invariant 8).

The exact schema is fixed by the implementing step.

### One eligibility predicate

```text
evaluate_plan_eligibility(caller, service_tenant, plan, session)
```

This is the single decision for:
- listing and visibility (`list_plans()` becomes an eligibility-filtered catalog read, not an unrestricted enumeration);
- checkout and subscription creation;
- the final commit-time re-check inside the transaction that persists the subscription. The plan row and the service tenant's ancestry are locked there, so a concurrent withdrawal or tenant move is serialized against it.

It implements the predicate in "Catalog" above. Knowing a plan id or key never grants eligibility.

**Merchant compatibility** (invariant 4, made concrete):

```text
plan.merchant_account_id == subscription.merchant_account_id == billing_account.merchant_account_id
```

This replaces the interim rule that only the platform tenant's merchant may sell (Phase 2 implementation status).

### Entitlements across merchants

A service tenant may hold live subscriptions at different merchants (at most one per merchant, invariant 5). Its entitlements are the deterministic combination of its `active` subscriptions' plans, key by key:

- **boolean capability:** `OR`;
- **numeric limit:** `MAX`.

Only plans that define a key contribute to it. If any plan gives a key a number, the key takes the `MAX` of the numbers, so a non-numeric value never erases a numeric limit. Plan values are validated to booleans and finite non-negative numbers (post-5.3 audit remediation R4; until then, a mix took the newest subscription's value). The payer and the merchant gain nothing for their own tenants.

There are **no shared usage pools** in Phase 5.3. Each service tenant's quota is measured against its own usage. Derived aggregate reporting across tenants is read-only and never creates a pool.

### Seller and payer projections

A payer cannot read a sponsored subscription row, and a merchant cannot read the rows it sold, because the service tenant owns them. Visibility is provided by projections, never by widening RLS:

| Projection | RLS owner | Authorized reader |
|---|---|---|
| Seller projection (`SellerSubscriptionView` above) | payee (merchant owner) | `billing.merchant:manage` on the payee |
| Payer projection (new) | payer | `billing.account:read` on the payer |

- **Contents:** non-sensitive fields only (subscription id, service tenant, plan, status, verification, timestamps). **No provider references.**
- **Source of truth:** the subscription row. Projections are derived.
- **Mechanism:**
  ```text
  subscription transaction (row change + outbox event, atomically)
    → transactional outbox (ADR-0032/0033)
    → RE-5-idempotent consumer (ADR-0036)
    → version-aware upsert of the seller and payer projections, each under its owner's tenant scope
  ```
- **Ordering:** each subscription change carries a monotonically increasing version. A projection applies an update only if its version is newer, so redelivery and reordering are harmless.
- **Consistency:** projections are eventually consistent, within the outbox latency bound (ADR-0037).

### Lifecycle and cancellation authority

| Action | Authority | Effect |
|---|---|---|
| Service tenant cancels its own subscription | `billing.subscription:cancel` on the service tenant (unchanged) | That subscription only |
| Payer cancels a sponsored subscription it pays for | `billing.account:charge` on the payer, and the subscription's recorded payer is that tenant | That subscription only |
| Merchant cancels a subscription it sold | `billing.merchant:manage` on the payee, and the subscription's merchant is that merchant | That subscription only |
| Merchant withdraws a plan | `billing.catalog:manage` on the plan owner | No new subscriptions. **Existing subscriptions are not canceled.** |

Every cancellation goes through the existing lifecycle (`set_subscription_status()`, the allowed-transition table) and the existing provider-confirmed cancellation safety. No action falls back to, resurrects or redirects to another subscription.

**Changing the payer** means canceling the existing subscription and creating a new one with the new payer. There is no in-place payer mutation.

### Plan immutability (Phase 5.3 compromise)

- The public API provides no operation that edits an existing plan's entitlements, price reference or merchant.
- A material commercial change means creating a new plan. Existing subscriptions keep their plan until they are explicitly changed.
- Full `PlanVersion` / `Price` / `ProviderPriceRef` versioning ("Catalog" above) is **deferred**, not abandoned.

### `inherits_billing`: retired forward

This is the re-expression the earlier section deferred:

- **New writes:** setting `inherits_billing=True` is refused. The inheritance model is not expanded and gains no new semantics.
- **Existing inheriting tenants:** they keep their current read behaviour (`get_entitlements()` through `resolve_billing_owner()`) temporarily, for compatibility.
- **Opt-out:** an explicit operation sets `inherits_billing=False`. It takes a typed caller, is authorized, and is audited in the same transaction.
- **Migration:** an explicit, authorized and audited operation converts an inheriting tenant into a sponsored subscription (service tenant = the child, payer = the sponsoring ancestor, merchant = the plan's merchant), then opts the tenant out. It changes what is billed, so it is never automatic.
- **Legacy mutations:** `upgrade_subscription()` and `cancel_subscription()` called with an inheriting tenant no longer redirect to the ancestor's subscription. They fail closed with `InheritedBillingSubscriptionError`, as `subscribe()` already does.
- **Commercial rows (step 7):** the legacy trusted `upgrade_subscription()` and `cancel_subscription()` act only on genuine legacy rows. A verified commercial subscription is refused with `LegacyBillingPathError`; it changes only through the commercial API.
  - The post-5.3 audit extended the refusal to any row that records a billing account. A Phase 2 sponsored row is `legacy_unverified` but still names its payer and merchant; it is reconciled first, then changed through the commercial API.
  - The legacy `subscribe()` and the legacy plan change also refuse a withdrawn plan (`PlanNotEligibleError`). An adopted legacy plan stays key-addressable and can be withdrawn. This is checked before the provider is called, and again in the writing transaction with the plan row read `FOR SHARE`.

### Support access

An approved support-access grant never authorizes a billing mutation, including:
- subscription create, change, cancel and reactivate;
- billing-account charge and manage;
- catalog and plan mutations;
- merchant mutations;
- payer and commercial-relationship mutations.

Billing reads stay governed by normal billing authorization. The exclusion is by action, not by whole resource (ADR-0031 amendment).

### Implementation structure (Phase 5.3 internal steps)

1. ADR and authority convergence.
2. Catalog v2.
3. Commercial subscription path.
4. Seller and payer projections.
5. Lifecycle and `inherits_billing` retirement.
6. Usage reporting.
7. Security and concurrency testing.
8. Full validation, documentation and checkpoint.

### Deferred (not part of Phase 5.3)

- provider-event ingestion and asynchronous reconciliation, unless implementation or security review proves them a prerequisite; *(scheduled by the owner and implemented for subscription status on 2026-10-15, ADR-0048; reconciliation stays synchronous within the event's request)*
- the invoice mirror;
- checkout sessions and trials; *(the payment step: ADR-0052, 2026-10-15)*
- billing-period modeling;
- usage retention;
- the quota fail-closed rollout (decision 0.4);
- full `PlanVersion` / `Price` / `ProviderPriceRef`;
- shared usage pools;
- service-account billing actors;
- live Stripe Connect validation (adapter behaviour is exercised through the provider abstraction);
- external/manual merchants.

Deferred during implementation (recorded at Phase 5.3 completion; the roadmap's Phase 5.3 deferred ledger is authoritative):

- a `(tenant_id, occurred_at)` index on `core.usage_events` for large reporting windows (performance, LOW);
- auditing refused operations on inherited tenants (LOW);
- retiring the legacy trusted billing API (commercial rows are already fenced from it, step 7);
- a projection rebuild/replay operation (step 4: no backfill);
- outbox durability for the payer-side `billing.subscription_charged_to_account` record (ADR-0031 amendment);
- a product-owned HTTP surface for usage reports (products own routes, ADR-0017).

### Implementation status: step 2, Catalog v2 (migration `d23cbb2ba746`)

- **Schema.** `core.billing_plans` gains `owner_tenant_id` and `merchant_account_id`.
  - They are set together or not at all, and a composite foreign key into `core.billing_merchant_accounts (tenant_id, id)` guarantees the merchant is the owner's.
  - It also gains `visibility`, `status` and `legacy`.
  - Keys are unique per owner, and among legacy plans.
  - New tenant-owned, RLS table `core.billing_plan_offers`, with at most one active offer per plan and service tenant.
- **Legacy plans.** Every pre-existing plan stays `legacy` and unowned: *not yet adopted*, never "platform".
  - The legacy key-addressed paths (`create_plan()`, `get_plan(key)`, `subscribe()`) keep working within the legacy namespace.
  - `adopt_legacy_plan()` is the explicit operator action, accepting only `SystemCaller(BILLING_OPERATIONS)`. It sets the owner and merchant and audits in the owner's tenant.
- **One predicate.** `core/billing/catalog.py::evaluate_plan_eligibility()` implements the predicate in "Catalog", plus an optional merchant-compatibility check.
  - `list_plans(caller, *, service_tenant_id)` filters through it. As that predicate says, listing requires `billing.subscription:create` on the service tenant, so a support grant cannot list the catalog.
  - It reads the merchant, ancestry and offer rows `FOR SHARE` in the caller's transaction.
- **Catalog mutations.** `create_owned_plan`, `set_plan_visibility`, `withdraw_plan` (terminal), `create_plan_offer` and `revoke_plan_offer`.
  - Each requires `billing.catalog:manage` on the owner.
  - Each authorizes and audits in the same transaction (ADR-0031 amendment).
- **Plan immutability.** There is no API that edits a plan's entitlements, key, merchant or provider price.
- **Commercial path:** moved to owned plans and this predicate in step 3 (below).

### Implementation status: step 3, commercial subscription path

No schema change.

- **Signature.** `create_subscription(caller, *, service_tenant_id, payer_tenant_id, billing_account_id, plan_id, idempotency_key, provider=None)` takes a Catalog v2 plan **by id**; the legacy `plan_key` argument is gone.
- **Parties.** They are explicit and checked: service tenant = `Subscription.tenant_id`; payer = the billing account's owner (`billing.account:charge` on the payer); merchant = the plan's merchant, which must be the billing account's merchant.
- **One check, run twice.** `_commercial_context()` runs before the provider call and again in the final transaction that writes the row and its audit entry. It checks:
  - authority;
  - both tenants open (`FOR SHARE`);
  - the service tenant owns its billing;
  - the plan row `FOR SHARE`;
  - the billing account read under the payer's RLS scope `FOR SHARE`, belonging to the payer and active;
  - `evaluate_plan_eligibility(..., merchant_account_id=<the account's merchant>)`.

  A missing plan and an ineligible one raise the same `PlanNotEligibleError`. The interim platform-merchant-only rule is lifted for new subscriptions.
- **Refusal after the provider call.** If anything changed while the provider was working (withdrawal, offer revocation, merchant or billing-account deactivation, revoked authority):
  - the final transaction refuses and writes no local row;
  - the provider subscription and its registered reference remain for reconciliation;
  - `billing.subscription_create_refused` (`outcome=failure`) records the provider object.
- **Provider context.** The adapter receives a provider-neutral `ProviderCommerceContext` (merchant account and its provider account reference, payer and billing account, provider customer).
  - The provider customer is created once per (payer, merchant) through `BillingProvider.ensure_customer()` with a stable key.
  - It is registered in the provider-reference index, persisted on the billing account, and reused.
- **Adapter guard.** The deployment's default Stripe adapter is constructed only for the configured platform tenant's merchant; another merchant needs an adapter that can act in its account (Stripe Connect deferred).
- **Deliberately not a foreign key.** The plan/merchant agreement on a subscription is enforced in the final transaction under the plan's row lock. Verified Phase 2/3 rows record the platform merchant against unadopted legacy plans, which such a key would reject; adding one needs an explicit legacy-plan adoption pass first.
- **Legacy paths unchanged.** `subscribe()`/`subscribe_idempotent()` use legacy plans by key. `reconcile_legacy_subscription()` records only the platform tenant's merchant for a legacy row. Cancellation and reconciliation adapters are unchanged (step 5 owns the cancellation authority).

### Implementation status: step 4, seller and payer projections (migration `732590273bc1`)

- **Source of truth.** `core.billing_subscriptions` remains the source of truth: whether a subscription exists, its status, payer, merchant and entitlements are never decided from a projection.
  - It gains `version` (default 1), incremented in SQL by every change.
- **Read models.**
  - `core.billing_seller_subscriptions`: RLS-owned by the merchant's owner tenant, with a composite foreign key to that tenant's merchant account.
  - `core.billing_payer_subscriptions`: RLS-owned by the payer, with a composite foreign key to that payer's billing account.
  - Both are unique per (owner, subscription), indexed by (owner, status), FORCE RLS, with no provider references, and registered tenant-owned and `FINANCIAL_RETAIN`.
- **Transactional outbox.** `core/billing/projections.py::announce_subscription_change()` appends `billing.subscription_changed` (payload: subscription id and version only) in the same transaction as every canonical change (pinned by a static test). The changes are:
  - creation;
  - provider-confirmed and reconciled status changes;
  - commercial and legacy cancellation;
  - legacy plan change;
  - legacy reconciliation.

  A rolled-back change leaves no event. A legacy subscription without a payer is versioned but not projected.
- **Consumer.**
  - It re-reads the subscription under the event tenant's own RLS scope (a subscription not in that tenant is a malformed, dead-lettered event).
  - It takes every party from the canonical row and its billing account, never from the event.
  - It upserts both projections, each in its owner's own transaction, fenced by `source_version`: newer applied, same or older a no-op.
  - It records its RE-5 consumption (`billing.subscription_changed`), which suppresses a repeated delivery.
  - Duplicate, reordered, retried and concurrent deliveries converge on the newest canonical version.
  - It never calls a provider or writes a canonical row, writes no audit evidence, and skips an owner whose tenant is closed.
- **Eventual consistency.** Projections are eventually consistent. Each view carries the `source_version` and `projected_at` it reflects.
- **Reads.**
  - `list_/get_seller_subscription(s)`: `billing.merchant:manage` on the merchant's owner. A mutation action, so support access cannot read the seller view.
  - `list_/get_payer_subscription(s)`: `billing.account:read` on the payer, following the normal support policy.
  - The service tenant gains no projection access.
- **Not done:**
  - no backfill: an existing commercial subscription is projected when it next changes; a rebuild operation is deferred;
  - the payer-side `billing.subscription_charged_to_account` record remains a post-commit record, and making it outbox-durable is deferred.

### Implementation status: step 5, lifecycle and `inherits_billing` retirement (migration `aa43b942bf93`)

- **No new inheritance.** The trigger `trg_tenants_refuse_new_billing_inheritance` on `core.tenants` refuses every new `inherits_billing = true` (an insert with it, or false → true) for every role. Existing `true` rows are untouched and remain updatable.
  - A `NOT VALID` CHECK was rejected: PostgreSQL would re-check it on every update of an existing `true` row.
  - The ungated `core.tenancy.set_tenant_billing_inheritance()` is removed.
- **Read compatibility.** `get_entitlements()` still resolves an existing inheriting tenant through `resolve_billing_owner()`.
- **Mutations fail closed** with `InheritedBillingSubscriptionError`, before the provider is touched and changing nothing. This covers the legacy `subscribe()`, `upgrade_subscription()` and `cancel_subscription()` (which no longer redirect to an ancestor) and the commercial creation.
- **Opt-out.** `core.billing.opt_out_of_billing_inheritance(caller, tenant_id)` requires `billing.subscription:change` evaluated on the tenant itself. A `SELF`-scoped role at an ancestor does not satisfy it. A `SUBTREE`-scoped role at an ancestor does: that is explicit delegated authority, and it does not make the ancestor the tenant's payer or merchant (corrected by the post-5.3 audit).
  - It locks the tenant row `FOR UPDATE`, sets the flag false and audits `billing.inheritance_opted_out` in one transaction.
  - It is idempotent and calls no provider.
- **Sponsored migration.** `core.billing.migrate_inherited_tenant_to_sponsorship(caller, service_tenant_id=..., payer_tenant_id=..., billing_account_id=..., plan_id=..., idempotency_key=...)` is the commercial creation path plus `billing.subscription:change` on the tenant.
  - The payer, its billing account and the plan are explicit and validated as for any creation, never inferred from the former billing ancestor.
  - The tenant must still inherit and have no live subscription of its own.
  - In the final transaction the tenant row is locked `FOR UPDATE`, the sponsored subscription inserted, the flag set false, and `billing.subscription_created` plus `billing.inheritance_migrated` audited.
  - It is provider-first with the final re-check; an opt-out during the provider call refuses it.
  - A retry with the same idempotency key replays the completed result. Nothing migrates automatically.
- **Cancellation authority.** `cancel_commercial_subscription(..., acting_as=CancellationCapacity.SERVICE_TENANT | PAYER | MERCHANT)` checks each capacity against the canonical row:
  - service tenant: `billing.subscription:cancel` on `Subscription.tenant_id`;
  - payer: `billing.account:charge` on the recorded payer;
  - merchant: `billing.merchant:manage` on the owner of the subscription's merchant account, read from the payer's billing account under the payer's RLS scope.

  Payer and merchant capacities get the same `BillingNotAuthorizedError` for a missing row as for a denial, so they cannot probe for subscriptions. Authority is checked before the provider call and again, against the locked row, in the final transaction. The audit entry names the capacity (`canceled_as`); the cancellation bumps the version and appends one projection event.
- **Withdrawal.** Withdrawing a plan cancels nothing (tested).

### Implementation status: step 6, usage reporting

No schema change.

- **Entitlements across merchants, now enforced.** `core.billing.get_entitlements()` combines every entitlement-granting subscription key by key via `combine_entitlements()`; quota enforcement, `require_entitlement()` and the reports all read it.
  - Boolean values combine with OR.
  - Numeric values combine with MAX, never a sum.
  - Only plans that define a key contribute: a plan omitting a numeric key does not make it unlimited (decided 2026-10-03, consistent with decision 0.4's fail-closed direction).
  - Any other or mixed value: the newest subscription's (superseded by the post-5.3 audit remediation R4: any number now gives the `MAX` of the numbers, otherwise booleans combine with `OR`).
  - Until step 6 it read only the newest active subscription.
- **Reports** (`core/usage/reporting.py`). Read-only; every view is authorized with `can(session=...)` and audits nothing.
  - `service_tenant_usage_report` needs `billing.subscription:read` on the tenant, and shows:
    - its own usage per metric over `[since, until)` (exact `Decimal`);
    - all of its live subscriptions (none chosen);
    - for each metric, the limit enforcement applies and `remaining = limit - used`.
  - With `include_descendants=True` it gives a descendant-inclusive **report**:
    - it needs the same authority on every included tenant;
    - it reports per-tenant usage as well as the sum;
    - it computes no limit, since there are no pools.
  - `payer_subscription_usage` needs `billing.account:read` on the payer, and the canonical row must record that payer.
  - `merchant_subscription_usage` needs `billing.merchant:manage` on the merchant's owner, and the canonical row's merchant must belong to it.
  - Both show the service tenant's usage for that subscription's plan metrics only. For both, a missing subscription, another party's subscription and a denial are the same refusal.
- **Ownership unchanged.** Usage ownership, the Phase 5.2 ledger and its semantics are unchanged; reports never read projections, providers or audit entries.

### Implementation status: step 7, security and concurrency testing

No schema change. `tests/core/billing/test_billing_security_attacks_integration.py` attacks the whole Phase 5.3 surface against PostgreSQL. It covers:

- hierarchy, support and system-purpose substitution;
- concurrent cancellation, creation and migration;
- tenant moves during the provider call;
- projection ordering;
- idempotency-key reuse;
- entitlement agreement across readers;
- indistinguishable refusals;
- direct-SQL RLS and constraint violations;
- audit integrity.

**One defect fixed.** The legacy trusted `upgrade_subscription()` and `cancel_subscription()` still acted on verified commercial rows. They have no authorization, no Catalog v2 eligibility and no merchant check, so they could:

- switch a commercial subscription to any legacy plan;
- cancel one outside the cancellation matrix.

They now refuse a verified row with `LegacyBillingPathError`:

- before the provider is called;
- again on the row locked `FOR UPDATE` in the writing transaction, since a concurrent `reconcile_legacy_subscription()` can verify it.

Legacy rows are unaffected. (The post-5.3 audit, A1, extended the refusal to any row that records a billing account, including Phase 2 `legacy_unverified` rows.)

### Post-5.3 security and integration audit (2026-10-03)

The audit found no CRITICAL or HIGH issue. It ran on checkpoint `688f08b`, and its remediation is recorded here.

**Fixed (MEDIUM):**

- **A1.** The legacy `upgrade_subscription()`/`cancel_subscription()` refuse any row that records a billing account (`LegacyBillingPathError`). See "`inherits_billing`: retired forward" above.
- **A2.** The legacy `subscribe()`/plan change refuse a withdrawn plan. See the same section.
- **A3.** An explicitly supplied Stripe adapter is refused for a non-platform merchant (ADR-0008, "Post-5.3 audit").
- **R4: entitlement value integrity.**
  - `core.billing.catalog.validate_entitlements()` is the write boundary for both plan write paths: `create_owned_plan()` and the legacy `create_plan()`. Plans are immutable through the API, so there are no others.
  - A value must be a `bool` (a capability) or a finite, non-negative `int`/`float` (a numeric limit). Anything else is refused with `InvalidCatalogValueError`, never converted. That includes `"100"`, `null`, lists, mappings, negatives, NaN and infinity.
  - `combine_entitlements()` now takes the `MAX` of the numbers whenever any plan gives a key a number, so a non-numeric value can no longer erase a numeric quota. Otherwise booleans combine with `OR`.
  - A plan persisted before validation that holds only invalid values for a key keeps the newest value for compatibility. It is never a numeric limit.
  - Existing data is not rewritten. Before deploying, run this check against production; it lists the plans holding values validation now refuses:

    ```sql
    SELECT p.id, p.key, v.key AS entitlement, jsonb_typeof(v.value) AS kind
    FROM core.billing_plans p, jsonb_each(p.entitlements::jsonb) v
    WHERE jsonb_typeof(v.value) NOT IN ('boolean', 'number')
       OR (jsonb_typeof(v.value) = 'number' AND (v.value #>> '{}')::numeric < 0);
    ```

**Decided, not changed:**

- **R1: reconciliation is provider-driven synchronization.**
  - `reconcile_subscription_status()` is authorized as a read (`billing.subscription:read`), so an approved support grant satisfies it.
  - It is not a caller-chosen billing mutation: it only moves the canonical row to the state the provider reports, through the allowed lifecycle transitions. It is audited and announced like any other change.
  - The caller chooses no status, plan, payer or merchant, so support access gains no subscription mutation through it.
- **R2: provider rollback after a final local refusal is deferred.**
  - When the final transaction refuses a creation, the provider subscription and its registered reference remain (the documented "remains for reconciliation" contract), recorded in the refusal audit.
  - Such a subscription can keep charging the payer until it is handled. This is **financial-risk debt**: automatic cancellation, orphan sweeps or rollback orchestration need a deliberate future provider-rollback design.
- **R3: payer and merchant usage views keep the step 6 semantics.**
  - They resolve the canonical subscription's payer or merchant, then report the service tenant's usage for the plan's metrics over the requested `[since, until)` window. That usage is tenant-wide.
  - The window is **not** clamped to the subscription's lifetime, and the subscription need not be live. Usage is not attributed to individual subscriptions or billing periods.
  - The views therefore answer "what did this service tenant use", not "what did this subscription consume".
- **R5: the legacy path to adopted plans is deferred.**
  - Adopted legacy plans stay reachable by key through the legacy `subscribe()`/`upgrade_subscription()`.
  - That path does not apply Catalog v2 visibility or merchant rules, and it uses the deployment's default adapter. Only withdrawal is enforced there (A2). This is a known compatibility limitation.
  - Commercial subscriptions always use the Catalog v2 eligibility predicate.
  - Restricting or retiring the legacy path needs its own deliberate migration.
- **R6: database enforcement of the plan's merchant is deferred.**
  - `plan.merchant_account_id == subscription.merchant_account_id` is enforced by the application, both before the provider call and in the final transaction.
  - The plan's own merchant ownership and the subscription/billing-account merchant pair are database-enforced (composite FKs).
  - `core.billing_plans` stays outside RLS (ADR-0022) and is writable by the application role. Plan immutability and withdrawal finality are application rules.
  - A composite FK from subscriptions to plans is not safe today: reconciled legacy subscriptions record the platform merchant while their plans may still be unadopted (no merchant). Stronger enforcement needs data analysis and a dedicated migration design.

### Superseded statements

| Earlier statement | Superseded by |
|---|---|
| "`inherits_billing` (legacy, frozen)": "Until Phase 7 decides the re-expression and migration path… no implementation change" | "`inherits_billing`: retired forward" above. The freeze ends with this decision. |
| Phase 2 implementation status: "Until Catalog v2, plans are sold only by a merchant owned by the platform tenant" | Merchant compatibility above. The interim rule is lifted when Catalog v2 lands. |
| "Catalog": "Plans are versioned" | For Phase 5.3, plan immutability through the API and new plans for changes. Versioning is deferred. |
| "Billing authorization": cancellation implicitly authorized only on the service tenant | The cancellation authority table above adds payer and merchant cancellation. The permission vocabulary is unchanged. |
| "RLS ownership": seller projection only | Adds the payer projection. |
| "Migration principles": "Existing plans are **backfilled** into the ownership model: owner = platform tenant…" | Catalog v2 (step 2): legacy plans stay unowned and become eligible only through explicit operator adoption (`adopt_legacy_plan()`); nothing is backfilled. |
| Step 6 status: mixed entitlement values take the newest subscription's | Post-5.3 audit remediation R4: any number gives the `MAX` of the numbers; plan values are validated. |

## Explicitly not part of SaaS-OS

These belong to products, provider adapters or external systems, and must not become SaaS-OS domain concepts, enums, tables or modules: agency, client, reseller, white-label, resale plan, markup, commission, margin, revenue share, settlement, payout, accounting ledger, tax engine/tax rules, product-specific onboarding, and provider-specific (e.g. Connect) types in the core domain. A product may *use* SaaS-OS primitives to build these (a reseller is a tenant that owns a merchant and plans with `descendants` visibility), but SaaS-OS never names them.

## What Would Be Difficult to Change Later

- **The RLS owner of each entity.** Moving a subscription from service-tenant ownership to payer ownership later would turn the entitlement hot path into a cross-tenant lookup and require re-keying every RLS policy and isolation test.
- **The `(payer, merchant)` key of provider customers.** Once provider customers are created against it, re-keying means re-mapping live provider objects.
- **The permission vocabulary.** Once products grant `billing.*` permissions to their roles, renaming them is a coordinated migration across every consumer.
- **Platform-as-tenant.** Once plans and merchants reference a platform tenant, introducing a `NULL`-owner special case later would split every ownership predicate in two.

## Related

[ADR-0008](0008-billing-provider.md) (amended: subscription ≠ payment, provider-confirmed activation, events, reconciliation, invoice boundary); [ADR-0022](0022-tenant-session-boundary-enforcement.md) (amended: owner-scoped catalog, global-by-design provider tables); [ADR-0002](0002-multi-tenancy-isolation-model.md) (RLS model); [ADR-0015](0015-saas-os-distribution-and-consumer-boundary.md) (per-deployment database); [ADR-0017](0017-saas-os-api-application-boundary.md) (SaaS-OS exposes reusable components, products own routes); `core/billing/*`; `core/usage/service.py`; `core/rbac/{authorization,scope,models}.py`; `core/tenancy/models.py`.
