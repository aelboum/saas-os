# ADR-0029: Commercial parties and billing relationships

Status: Accepted — architecture locked (Billing Foundation v2, Phase 0 + 1); Phase 2 (commercial party model) and Phase 3 (billing lifecycle safety) implemented — see "Implementation status" below; Phases 4+ pending.
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

Implemented in Phase 3. `core/usage/service.py` is unchanged by this ADR.

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
- `core/billing/authorization.py` holds the permission vocabulary and the explicit callers: `BillingActor.user(...)` or `trusted_system(reason)`, never `None`. Only user principals are accepted in Phase 2; service-account billing actors are deferred because audit attribution is tenant-bound.
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
  - provider-event ingestion and the `ProviderEvent` ledger;
  - asynchronous reconciliation, including dangling provider references and orphaned provider objects;
  - checkout sessions;
  - trials (Stripe `trialing` is `unknown`);
  - pause, cancel-at-period-end, reactivation and plan-change semantics (`upgrade_subscription()`/`cancel_subscription()` are the unchanged legacy operations; cancel now goes through the lifecycle);
  - an entitlement policy for `past_due` grace and for unverified legacy rows;
  - the quota fail-closed rollout (Decision 0.4): deliberately not part of this billing-safety phase; a separate phase;
  - Catalog v2.

## Explicitly not part of SaaS-OS

These belong to products, provider adapters or external systems, and must not become SaaS-OS domain concepts, enums, tables or modules: agency, client, reseller, white-label, resale plan, markup, commission, margin, revenue share, settlement, payout, accounting ledger, tax engine/tax rules, product-specific onboarding, and provider-specific (e.g. Connect) types in the core domain. A product may *use* SaaS-OS primitives to build these (a reseller is a tenant that owns a merchant and plans with `descendants` visibility), but SaaS-OS never names them.

## What Would Be Difficult to Change Later

- **The RLS owner of each entity.** Moving a subscription from service-tenant ownership to payer ownership later would turn the entitlement hot path into a cross-tenant lookup and require re-keying every RLS policy and isolation test.
- **The `(payer, merchant)` key of provider customers.** Once provider customers are created against it, re-keying means re-mapping live provider objects.
- **The permission vocabulary.** Once products grant `billing.*` permissions to their roles, renaming them is a coordinated migration across every consumer.
- **Platform-as-tenant.** Once plans and merchants reference a platform tenant, introducing a `NULL`-owner special case later would split every ownership predicate in two.

## Related

[ADR-0008](0008-billing-provider.md) (amended: subscription ≠ payment, provider-confirmed activation, events, reconciliation, invoice boundary); [ADR-0022](0022-tenant-session-boundary-enforcement.md) (amended: owner-scoped catalog, global-by-design provider tables); [ADR-0002](0002-multi-tenancy-isolation-model.md) (RLS model); [ADR-0015](0015-saas-os-distribution-and-consumer-boundary.md) (per-deployment database); [ADR-0017](0017-saas-os-api-application-boundary.md) (SaaS-OS exposes reusable components, products own routes); `core/billing/*`; `core/usage/service.py`; `core/rbac/{authorization,scope,models}.py`; `core/tenancy/models.py`.
