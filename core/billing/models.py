"""Plan and Subscription entities (docs/IMPLEMENTATION-ROADMAP.md Phase
5.1; docs/ADR/0008-billing-provider.md: "Plans / Subscriptions /
Entitlements / Invoices / Payments as distinct concepts").

Two isolation postures, mirroring `core/feature_flags`'s `FeatureFlag`/
`FeatureFlagTenantOverride` split (`core/feature_flags/models.py`):

    core.billing_plans        -- not RLS-scoped. Since Catalog v2
                                  (Phase 5.3 step 2) an owner-scoped
                                  catalog: a plan has an owner tenant and
                                  a merchant, and who may see or buy it is
                                  the application-level eligibility
                                  predicate (`core/billing/catalog.py`),
                                  which RLS cannot express (ADR-0022
                                  amendment).
    core.billing_subscriptions -- tenant-owned, RLS-protected. A
                                  tenant's own subscription state/lifecycle
                                  against a plan (docs/ADR/0008-...'s own
                                  "Subscriptions" row).

`entitlements` is the product-agnostic "plan -> feature/limit" data model
`docs/ARCHITECTURE-DISCOVERY.md` section 14 calls for: a generic
entitlement-key-to-value mapping (e.g. `{"max_users": 10, "api_access":
true}`) that Product code queries via `core/billing/service.py::get_entitlements()`
-- never a Stripe-specific shape. `Plan` carries no "tier rank"/"price"
column: nothing in this phase's Acceptance Criteria needs plan ordering,
and `core/billing/service.py::upgrade_subscription()` is a direction-
agnostic plan change, not a validated "must be higher tier" operation.

`Subscription.provider_subscription_id` and `Plan.provider_price_id` are
the only provider-shaped values this module persists -- both are opaque
identifier strings a billing provider issues, never a secret or payment
credential (docs/ADR/0008-...: "Only the provider-abstraction layer and
its Stripe adapter know about Stripe's specific object model").

**Commercial parties (Billing Foundation v2 Phase 2;
docs/ADR/0029-commercial-parties-and-billing-relationships.md).** Three
further entities name the parties a subscription involves, without
changing what `Subscription.tenant_id` means:

    core.billing_merchant_accounts -- the PAYEE. RLS-owned by the
                                      merchant's owner tenant
                                      (`tenant_id`). No merchant-type
                                      column: a "platform merchant" is
                                      simply one owned by the platform
                                      tenant (`core.tenancy.
                                      get_platform_tenant_id()`).
    core.billing_accounts          -- the PAYER. RLS-owned by the payer
                                      tenant (`tenant_id`), scoped to
                                      exactly one merchant: provider
                                      customer identity is
                                      `(payer, merchant) -> customer`,
                                      never `tenant -> customer`.
    core.billing_provider_refs     -- GLOBAL-BY-DESIGN, not RLS-scoped
                                      (docs/ADR/0022-..., 2026-10-01
                                      amendment): resolves an opaque
                                      provider object reference to the
                                      tenant/local row owning it, before
                                      that tenant is known.

The owner column of the two RLS-owned entities is named `tenant_id`, the
repository-wide convention every RLS policy (`infra/db/rls.py`), the
retention inventory (`core/tenancy/retention.py`) and the purge
machinery key on -- ADR-0029 calls the same column `owner_tenant_id`.

`Subscription.tenant_id` remains the SERVICE TENANT (the tenant
receiving the service and its entitlements) and keeps its RLS policy
unchanged, so `core/billing/service.py::get_entitlements()` is untouched.
The payer is recorded alongside it as `(payer_tenant_id,
billing_account_id)`, a composite foreign key into
`core.billing_accounts (tenant_id, id)` -- the payer tenant is therefore
always the billing account's own owner, enforced by the database, and
readable from the service tenant's row without a cross-tenant read. Both
columns are NULL for every subscription created before Phase 2 and for
every subscription the legacy `subscribe()` path still creates: the
payer of those rows was never recorded, and is not reconstructed
(ADR-0029, Decision 0.5 -- no financial fact is fabricated).

No `Invoice`/`Payment` table exists yet -- docs/ADR/0008-...'s own table
lists them as distinct concepts, but nothing in this phase's Tests/
Acceptance Criteria queries or persists one (`core/billing/__init__.py`'s
own docstring states this Non-Goal explicitly); Stripe itself remains the
system of record for both until a future phase has an actual, tested
need to mirror them locally.

Uses infra.db.orm's shared declarative base and primitives -- this module
never imports sqlalchemy directly (pyproject.toml's "Only infra/db may
import SQLAlchemy or psycopg directly" contract).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from infra.db import (
    JSON,
    Base,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Mapped,
    String,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class Plan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A product-agnostic pricing-tier definition, owned by a tenant and
    sold by that tenant's merchant (Catalog v2, Phase 5.3 step 2;
    docs/ADR/0029-..., "Amendment (2026-10-02)").

    - `owner_tenant_id` + `merchant_account_id`: the plan owner and its
      merchant -- both set or both NULL
      (`ck_billing_plans_owner_merchant_pair`), and the composite foreign
      key `fk_billing_plans_owner_merchant` guarantees the merchant is
      owned by the plan owner. NULL means **not yet adopted**, never
      "platform": an unadopted plan is never eligible in the catalog.
    - `legacy`: the plan lives in the pre-Catalog-v2 key namespace --
      every row that existed before this step, and every plan the legacy
      `core/billing/service.py::create_plan()` still creates. Its `key` is
      unique among legacy plans (`uq_billing_plans_legacy_key`, a partial
      index in the migration) and `get_plan(key)` resolves it, so the
      legacy key-addressed paths keep working. Adoption sets an owner; it
      does not move a plan out of that namespace. A non-legacy plan must
      have an owner (`ck_billing_plans_owned_unless_legacy`).
    - `key` is unique per owner (`uq_billing_plans_owner_key`, a partial
      index over owned plans) -- two owners may both have `starter`.
    - `visibility` (`public` | `descendants` | `private` | `unlisted`) and
      `status` (`active` | `withdrawn`) feed the eligibility predicate
      (`core/billing/catalog.py`). Withdrawal stops new subscriptions only.

    Plans are immutable through the API: nothing edits a plan's
    entitlements, key, merchant or provider price after creation; a
    material change is a new plan (full versioning is deferred).
    """

    __tablename__ = "billing_plans"
    __table_args__ = (
        CheckConstraint(
            "(owner_tenant_id IS NULL) = (merchant_account_id IS NULL)",
            name="ck_billing_plans_owner_merchant_pair",
        ),
        CheckConstraint(
            "legacy OR owner_tenant_id IS NOT NULL",
            name="ck_billing_plans_owned_unless_legacy",
        ),
        CheckConstraint(
            "visibility IN ('public', 'descendants', 'private', 'unlisted')",
            name="ck_billing_plans_visibility",
        ),
        CheckConstraint("status IN ('active', 'withdrawn')", name="ck_billing_plans_status"),
        ForeignKeyConstraint(
            ["owner_tenant_id", "merchant_account_id"],
            ["core.billing_merchant_accounts.tenant_id", "core.billing_merchant_accounts.id"],
            name="fk_billing_plans_owner_merchant",
        ),
        UniqueConstraint("owner_tenant_id", "id", name="uq_billing_plans_owner_id"),
        {"schema": "core"},
    )

    key: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    provider_price_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    entitlements: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    owner_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=True, index=True
    )
    merchant_account_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    visibility: Mapped[str] = mapped_column(
        String(20), nullable=False, default="public", server_default="public"
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active"
    )
    legacy: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )


class PlanOffer(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An explicit offer of one plan to one service tenant -- the only way
    an `unlisted` plan becomes eligible (Catalog v2; ADR-0029 "Catalog").

    RLS-owned by the plan owner (`tenant_id`), who creates and revokes it.
    The composite foreign key `fk_billing_plan_offers_plan_owner` into
    `core.billing_plans (owner_tenant_id, id)` guarantees the offer's owner
    is the plan's owner. At most one `active` offer per
    `(plan_id, service_tenant_id)` (`uq_billing_plan_offers_one_active`, a
    partial index in the migration); `revoked_at` is set exactly when the
    offer is `revoked` (`ck_billing_plan_offers_revoked_at`). An offer
    grants eligibility only: it never grants an authority.
    """

    __tablename__ = "billing_plan_offers"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "plan_id"],
            ["core.billing_plans.owner_tenant_id", "core.billing_plans.id"],
            name="fk_billing_plan_offers_plan_owner",
        ),
        CheckConstraint("status IN ('active', 'revoked')", name="ck_billing_plan_offers_status"),
        CheckConstraint(
            "(status = 'revoked') = (revoked_at IS NOT NULL)",
            name="ck_billing_plan_offers_revoked_at",
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    service_tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Subscription(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One tenant's subscription state against a `Plan`. `status` is a
    plain string (`"active"` / `"canceled"`) rather than a database enum
    -- mirrors `core/notifications`'s `Notification.channel`/`.status`
    convention: new statuses are added by extending
    `core/billing/service.py`, never by a schema migration.

    `tenant_id` is the SERVICE TENANT -- the tenant receiving the service
    and its entitlements (docs/ADR/0029-...: never renamed, never the
    payer). `(payer_tenant_id, billing_account_id)` is the payer
    relationship: both NULL for a subscription whose payer was never
    recorded (pre-Phase-2 rows and the legacy `subscribe()` path), both
    set otherwise (`ck_billing_subscriptions_payer_pair`). `provider` is
    the name of the `BillingProvider` adapter that holds the subscription
    (`BillingProvider.name`), NULL where it was never recorded.

    Billing Foundation v2 Phase 3 (lifecycle safety,
    `core/billing/lifecycle.py`): `status` is the lifecycle
    (`SubscriptionStatus`, transitions validated -- never assigned outside
    `lifecycle.set_subscription_status()`); `verification` says whether the
    commercial relationship is verified (`verified`) or a pre-Phase-3/legacy
    claim (`legacy_unverified`, the server default, so every pre-existing
    row is unverified). `merchant_account_id` records the payee merchant,
    present exactly when a billing account is
    (`ck_billing_subscriptions_merchant_pair`) and guaranteed by
    `fk_billing_subscriptions_billing_account_merchant` to be that billing
    account's own merchant. A `verified` row always has a billing account
    (`ck_billing_subscriptions_verified_is_commercial`).

    The one-live-subscription invariant is the migration-defined partial
    unique index `uq_billing_subscriptions_one_live_per_merchant` on
    `(tenant_id, merchant_account_id) WHERE merchant_account_id IS NOT NULL
    AND status IN ('pending', 'active', 'past_due')` -- declared only in the
    migration (`41e8273a685d`), since a partial-index predicate needs raw
    SQL this module, by the "only infra/db imports SQLAlchemy" contract,
    cannot express.
    """

    __tablename__ = "billing_subscriptions"
    __table_args__ = (
        CheckConstraint(
            "(payer_tenant_id IS NULL) = (billing_account_id IS NULL)",
            name="ck_billing_subscriptions_payer_pair",
        ),
        ForeignKeyConstraint(
            ["payer_tenant_id", "billing_account_id"],
            ["core.billing_accounts.tenant_id", "core.billing_accounts.id"],
            name="fk_billing_subscriptions_billing_account",
        ),
        CheckConstraint(
            "(merchant_account_id IS NULL) = (billing_account_id IS NULL)",
            name="ck_billing_subscriptions_merchant_pair",
        ),
        CheckConstraint(
            "verification <> 'verified' OR billing_account_id IS NOT NULL",
            name="ck_billing_subscriptions_verified_is_commercial",
        ),
        CheckConstraint(
            "verification IN ('verified', 'legacy_unverified')",
            name="ck_billing_subscriptions_verification_values",
        ),
        ForeignKeyConstraint(
            ["payer_tenant_id", "billing_account_id", "merchant_account_id"],
            [
                "core.billing_accounts.tenant_id",
                "core.billing_accounts.id",
                "core.billing_accounts.merchant_account_id",
            ],
            name="fk_billing_subscriptions_billing_account_merchant",
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.billing_plans.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    provider_subscription_id: Mapped[str] = mapped_column(String(255), nullable=False)
    payer_tenant_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    billing_account_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    merchant_account_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    verification: Mapped[str] = mapped_column(
        String(20), nullable=False, default="legacy_unverified"
    )
    # Phase 5.3 step 4: a monotonically increasing version, incremented in
    # SQL (`version = version + 1`) by every change to the row
    # (`core/billing/projections.py::announce_subscription_change()`), so
    # the seller/payer projections can tell a newer canonical state from an
    # older one. The subscription stays the source of truth.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")


class MerchantAccount(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The PAYEE (docs/ADR/0029-...): a tenant's selling identity at one
    provider. `tenant_id` is the owner tenant -- the payee -- and the RLS
    key. `provider` names a `BillingProvider` adapter
    (`BillingProvider.name`); `provider_account_ref` is the provider's own
    opaque merchant/account identifier (for a connected-account model, the
    connected account id -- never a provider SDK object, never a secret).

    `(provider, provider_account_ref)` is unique across the whole
    deployment, not merely per owner: two tenants claiming the same
    provider account would make "who receives this money" ambiguous.
    `status` is a plain string validated by `core/billing/parties.py::
    MerchantAccountStatus`, mirroring `Subscription.status`'s convention.
    `uq_billing_merchant_accounts_tenant_id_id` is the composite-FK target
    `core.billing_accounts` references, so a billing account's recorded
    payee tenant is always its merchant's real owner.
    """

    __tablename__ = "billing_merchant_accounts"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "provider_account_ref",
            name="uq_billing_merchant_accounts_provider_account",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_billing_merchant_accounts_tenant_id_id"),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    provider_account_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)


class BillingAccount(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The PAYER (docs/ADR/0029-...): one tenant's customer relationship
    with one merchant. `tenant_id` is the payer and the RLS key.

    `(merchant_tenant_id, merchant_account_id)` is a composite foreign key
    into `core.billing_merchant_accounts (tenant_id, id)`: the payee is
    recorded on the payer's own row and guaranteed by the database to be
    the merchant's real owner, so answering "whom does this account pay"
    never needs a read under the payee's RLS scope.

    `UNIQUE (tenant_id, merchant_account_id)`: one billing account per
    payer per merchant. `provider_customer_ref` is the provider's opaque
    customer id *at that merchant* -- nullable, never backfilled (it was
    never persisted before Phase 2), populated only once a provider
    integration actually records one.
    """

    __tablename__ = "billing_accounts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "merchant_account_id", name="uq_billing_accounts_tenant_merchant"
        ),
        UniqueConstraint("tenant_id", "id", name="uq_billing_accounts_tenant_id_id"),
        # Phase 3: composite-FK target letting a subscription record its
        # merchant with a database guarantee it is the account's merchant.
        UniqueConstraint(
            "tenant_id",
            "id",
            "merchant_account_id",
            name="uq_billing_accounts_tenant_id_id_merchant",
        ),
        ForeignKeyConstraint(
            ["merchant_tenant_id", "merchant_account_id"],
            [
                "core.billing_merchant_accounts.tenant_id",
                "core.billing_merchant_accounts.id",
            ],
            name="fk_billing_accounts_merchant_account",
        ),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    merchant_tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    merchant_account_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    provider_customer_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)


class ProviderRef(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """GLOBAL-BY-DESIGN provider-reference index (docs/ADR/0022-...,
    2026-10-01 amendment; docs/ADR/0029-...): maps one opaque provider
    object reference -- `(provider, provider_account_ref, object_type,
    provider_object_ref)`, unique -- to the tenant and local row that own
    it. Deliberately NOT RLS-scoped: a provider callback names only
    provider objects, so the owning tenant is unknown until this index is
    consulted (the `core.api_keys` precedent). Holds references only --
    never payment data, never a secret, never a provider SDK object.

    This is the only sanctioned way to resolve a provider object to a
    tenant; provider-side metadata never is (ADR-0008 amendment, point 9).
    Rows reached through it are still read only via
    `tenant_session_scope(tenant_id)` for the resolved tenant
    (`core/billing/provider_refs.py`).
    """

    __tablename__ = "billing_provider_refs"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "provider_account_ref",
            "object_type",
            "provider_object_ref",
            name="uq_billing_provider_refs_provider_object",
        ),
        Index("ix_billing_provider_refs_local_object", "local_object_type", "local_object_id"),
        {"schema": "core"},
    )

    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    provider_account_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    provider_object_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    local_object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    local_object_id: Mapped[uuid.UUID] = mapped_column(nullable=False)


class SellerSubscription(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The seller (payee) read model of one commercial subscription --
    "what was sold through my merchant account" (Phase 5.3 step 4;
    ADR-0029 "Seller and payer projections").

    RLS-owned by the merchant's owner tenant (`tenant_id`); the composite
    foreign key `fk_billing_seller_subscriptions_merchant` guarantees the
    merchant account is that tenant's own. **Derived, never authoritative**:
    nothing decides whether a subscription exists, is active, who pays or
    who sells, or any entitlement from this table -- `core.billing_
    subscriptions` does. It is written only by the projection consumer,
    fenced by `source_version` (the canonical row's `version`): an update
    is applied only if newer. No provider reference, no payer billing
    account."""

    __tablename__ = "billing_seller_subscriptions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "subscription_id", name="uq_billing_seller_subscriptions_subscription"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "merchant_account_id"],
            ["core.billing_merchant_accounts.tenant_id", "core.billing_merchant_accounts.id"],
            name="fk_billing_seller_subscriptions_merchant",
        ),
        CheckConstraint("source_version >= 1", name="ck_billing_seller_subscriptions_version"),
        Index("ix_billing_seller_subscriptions_status", "tenant_id", "status"),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    subscription_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.billing_subscriptions.id"), nullable=False
    )
    merchant_account_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    service_tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False
    )
    payer_tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.billing_plans.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    verification: Mapped[str] = mapped_column(String(20), nullable=False)
    subscription_created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    subscription_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    source_version: Mapped[int] = mapped_column(Integer, nullable=False)
    projected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PayerSubscription(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """The payer read model of one commercial subscription -- "what is
    charged to my billing account" (Phase 5.3 step 4).

    RLS-owned by the payer tenant (`tenant_id`); the composite foreign key
    `fk_billing_payer_subscriptions_account` guarantees the billing account
    is that tenant's own, and `fk_billing_payer_subscriptions_merchant` that
    the recorded merchant tenant really owns the merchant account. Derived,
    never authoritative, written only by the projection consumer and fenced
    by `source_version`, exactly like `SellerSubscription`. Not the billing
    account itself: no provider customer, no provider reference."""

    __tablename__ = "billing_payer_subscriptions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "subscription_id", name="uq_billing_payer_subscriptions_subscription"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "billing_account_id"],
            ["core.billing_accounts.tenant_id", "core.billing_accounts.id"],
            name="fk_billing_payer_subscriptions_account",
        ),
        ForeignKeyConstraint(
            ["merchant_tenant_id", "merchant_account_id"],
            ["core.billing_merchant_accounts.tenant_id", "core.billing_merchant_accounts.id"],
            name="fk_billing_payer_subscriptions_merchant",
        ),
        CheckConstraint("source_version >= 1", name="ck_billing_payer_subscriptions_version"),
        Index("ix_billing_payer_subscriptions_status", "tenant_id", "status"),
        {"schema": "core"},
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    subscription_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.billing_subscriptions.id"), nullable=False
    )
    billing_account_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    merchant_tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    merchant_account_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    service_tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.billing_plans.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    verification: Mapped[str] = mapped_column(String(20), nullable=False)
    subscription_created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    subscription_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    source_version: Mapped[int] = mapped_column(Integer, nullable=False)
    projected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
