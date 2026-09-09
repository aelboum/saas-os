"""Plan and Subscription entities (docs/IMPLEMENTATION-ROADMAP.md Phase
5.1; docs/ADR/0008-billing-provider.md: "Plans / Subscriptions /
Entitlements / Invoices / Payments as distinct concepts").

Two isolation postures, mirroring `core/feature_flags`'s `FeatureFlag`/
`FeatureFlagTenantOverride` split (`core/feature_flags/models.py`):

    core.billing_plans        -- GLOBAL, not RLS-scoped. A plan
                                  definition (its `key`, `provider_price_id`,
                                  and `entitlements` mapping) is a
                                  platform/product pricing-tier
                                  declaration, not tenant-owned data --
                                  the same reasoning `core.feature_flags`
                                  already established.
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

from infra.db import (
    JSON,
    Base,
    ForeignKey,
    Mapped,
    String,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    mapped_column,
)


class Plan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A global, product-agnostic pricing-tier definition."""

    __tablename__ = "billing_plans"
    __table_args__ = ({"schema": "core"},)

    key: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    provider_price_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    entitlements: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class Subscription(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One tenant's subscription state against a `Plan`. `status` is a
    plain string (`"active"` / `"canceled"`) rather than a database enum
    -- mirrors `core/notifications`'s `Notification.channel`/`.status`
    convention: new statuses are added by extending
    `core/billing/service.py`, never by a schema migration.
    """

    __tablename__ = "billing_subscriptions"
    __table_args__ = ({"schema": "core"},)

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("core.tenants.id"), nullable=False, index=True
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("core.billing_plans.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    provider_subscription_id: Mapped[str] = mapped_column(String(255), nullable=False)
