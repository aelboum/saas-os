"""The retirement of `Tenant.inherits_billing` (Phase 5.3 step 5;
docs/ADR/0029-commercial-parties-and-billing-relationships.md, "Amendment
(2026-10-02)", "`inherits_billing`: retired forward").

- **No new inheritance.** Nothing can set `inherits_billing = true`: there is
  no API for it, and the database trigger
  `trg_tenants_refuse_new_billing_inheritance` (migration `aa43b942bf93`)
  refuses every new `true` on insert or update.
- **Existing inheriting tenants keep read compatibility**:
  `core/billing/service.py::get_entitlements()` still resolves them through
  `resolve_billing_owner()`. Every *mutation* fails closed for them
  (`InheritedBillingSubscriptionError`): the legacy `subscribe()`,
  `upgrade_subscription()` and `cancel_subscription()` and the commercial
  `create_subscription()` -- nothing is redirected to an ancestor.
- **Two explicit ways out**, both authorized through `can(session=...)` and
  audited in the same transaction as the change:

      opt_out_of_billing_inheritance(caller, tenant_id)
          billing.subscription:change on the tenant. Sets the flag to false
          and nothing else: the tenant becomes its own billing owner, with
          no subscription until one is created for it. No provider call.

      migrate_inherited_tenant_to_sponsorship(caller, service_tenant_id=...,
                                              payer_tenant_id=..., ...)
          The commercial create path (`create_subscription()`'s own checks:
          billing.account:charge on the payer, billing.subscription:create
          on the tenant, payer-owned active billing account, Catalog v2
          eligibility through that account's merchant) plus
          billing.subscription:change on the tenant. The payer, its billing
          account and the plan are explicit arguments -- never inferred from
          the ancestor that used to supply the billing. The tenant must still
          inherit and have no live subscription of its own; the new
          sponsored subscription and the end of inheritance commit in one
          final transaction.

Nothing migrates automatically, and no inheriting tenant is changed except
the one named.
"""

from __future__ import annotations

import uuid

from core.billing.authorization import (
    BILLING_SUBSCRIPTION,
    authorize_billing,
    record_billing_audit,
    require_billing_caller,
)
from core.billing.commercial import _create_commercial_subscription
from core.billing.provider import BillingProvider
from core.billing.service import SubscribeResult
from core.tenancy import Tenant, TenantNotFoundError
from infra.db import tenant_session_scope

_MIGRATION_OPERATION = "billing.subscription.migrate_inheritance"


def opt_out_of_billing_inheritance(caller: object, tenant_id: uuid.UUID) -> Tenant:
    """Turn `tenant_id`'s retired `inherits_billing` off
    (`billing.subscription:change` on the tenant). Its `core.tenants` row is
    locked `FOR UPDATE`, the flag set to `false`, and
    `billing.inheritance_opted_out` audited in one transaction. A tenant
    that does not inherit is returned unchanged, with no audit entry.
    Authority-reducing -- the tenant gives up its ancestor's entitlements --
    so it is allowed on a closed tenant too. No provider is called."""
    require_billing_caller(caller)
    with tenant_session_scope(tenant_id) as session:
        authorized = authorize_billing(
            caller,
            [(tenant_id, BILLING_SUBSCRIPTION, "change")],
            operation="billing.inheritance.opt_out",
            session=session,
        )
        tenant = session.get(Tenant, tenant_id, with_for_update=True)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)
        if tenant.inherits_billing:
            tenant.inherits_billing = False
            session.flush()
            record_billing_audit(
                session,
                authorized,
                tenant_id=tenant_id,
                action="billing.inheritance_opted_out",
                resource_type="tenant",
                resource_id=str(tenant_id),
                metadata={"previous_inherits_billing": True, "inherits_billing": False},
            )
        session.refresh(tenant)
        session.expunge(tenant)
    return tenant


def migrate_inherited_tenant_to_sponsorship(
    caller: object,
    *,
    service_tenant_id: uuid.UUID,
    payer_tenant_id: uuid.UUID,
    billing_account_id: uuid.UUID,
    plan_id: uuid.UUID,
    idempotency_key: str,
    provider: BillingProvider | None = None,
) -> tuple[bool, SubscribeResult]:
    """Move an inheriting tenant onto an explicit sponsored subscription
    (module docstring): a commercial subscription for `service_tenant_id`
    to the Catalog v2 plan `plan_id`, paid through `payer_tenant_id`'s
    billing account `billing_account_id`, with the tenant's inheritance
    ended in the same final transaction (`billing.subscription_created` and
    `billing.inheritance_migrated` audited there). Provider-first, exactly
    like `create_subscription()`: if anything changed while the provider
    worked -- including the tenant opting out or gaining a subscription of
    its own -- nothing local is written and the refusal is audited.
    Idempotent on `idempotency_key`."""
    return _create_commercial_subscription(
        caller,
        service_tenant_id=service_tenant_id,
        payer_tenant_id=payer_tenant_id,
        billing_account_id=billing_account_id,
        plan_id=plan_id,
        idempotency_key=idempotency_key,
        provider=provider,
        operation=_MIGRATION_OPERATION,
        migrating_inheritance=True,
    )
