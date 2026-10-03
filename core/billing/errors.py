"""Typed errors for `core/billing` (docs/IMPLEMENTATION-ROADMAP.md Phase
5.1). Every error here carries only identifying metadata -- never a
payment credential, a raw provider API key, or a webhook payload's
contents.
"""

from __future__ import annotations

import uuid

from core.outbox.errors import PermanentEventError


class InvalidPlanKeyError(ValueError):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class DuplicatePlanKeyError(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Billing plan {key!r} already exists.")


class PlanNotFoundError(LookupError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Billing plan {key!r} not found.")


class SubscriptionNotFoundError(LookupError):
    """Raised when a subscription id does not resolve within the given
    tenant -- deliberately the same error whether the subscription truly
    doesn't exist or belongs to a different tenant, so this lookup itself
    never confirms or denies another tenant's data (docs/SECURITY.md
    section 5), mirroring `core/webhooks`'s `WebhookSubscriptionNotFoundError`."""

    def __init__(self, tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        super().__init__(f"Subscription {subscription_id} not found in tenant {tenant_id}.")


class BillingProviderError(RuntimeError):
    """Raised when the underlying billing provider (Stripe, or the fake
    test adapter) rejects an operation. Carries only the provider's error
    *type name* and a short reason -- never the raw provider exception,
    which could echo request parameters or account-identifying detail."""

    def __init__(self, operation: str, reason: str) -> None:
        self.operation = operation
        super().__init__(f"Billing provider operation {operation!r} failed: {reason}")


class InvalidWebhookSignatureError(ValueError):
    """Raised when a provider webhook payload's signature does not verify
    -- never includes the payload or the webhook secret in its message."""

    def __init__(self) -> None:
        super().__init__("Webhook signature verification failed.")


class InvalidBillingHierarchyError(RuntimeError):
    """Raised by `resolve_billing_owner()` (architecture research Phase H
    -- "Hierarchy-Aware Billing & Usage") when a tenant's
    `inherits_billing=True` configuration cannot be resolved to a real
    billing owner -- e.g. a root tenant (no parent) with no ancestor to
    inherit from, or every ancestor up to the root also has
    `inherits_billing=True` (nobody in the chain actually owns billing).
    Fail-closed by design (this phase's own approved requirement: "if
    configuration is invalid, fail closed rather than guessing") -- never
    silently falls back to treating the tenant as its own owner, which
    would silently reactivate billing for a tenant that explicitly opted
    out of owning it itself."""

    def __init__(self, tenant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        super().__init__(
            f"Tenant {tenant_id} has inherits_billing=True but no ancestor resolves to a "
            "valid billing owner."
        )


class InheritedBillingSubscriptionError(RuntimeError):
    """Raised when a legacy billing mutation -- `subscribe()`/
    `subscribe_idempotent()`, and since Phase 5.3 step 5 also
    `upgrade_subscription()`/`cancel_subscription()`, which no longer
    redirect to the ancestor -- or a commercial creation is attempted for a
    tenant with the retired `Tenant.inherits_billing=True`. The operation
    fails closed and changes nothing. Such a tenant does
    not own its own billing -- `get_entitlements()` would keep reading
    the resolved owner's plan regardless of any `Subscription` row
    created here, and creating one anyway would be exactly the
    "multiple billing owners" ambiguity the whole hierarchy design
    forbids. Fails closed rather than silently redirecting the mutation
    to the resolved owner (a mutation on a tenant other than the one
    literally supplied, with no explicit authorization for it in this
    phase) or silently creating the child's own orphaned subscription. A
    caller that wants to subscribe the resolved owner calls
    `resolve_billing_owner(tenant_id)` itself first, then
    `subscribe(owner_id, ...)`."""

    def __init__(self, tenant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        super().__init__(
            f"Tenant {tenant_id} inherits billing (retired) and cannot be billed directly; "
            "opt it out or migrate it to a sponsored subscription first."
        )


class EntitlementDeniedError(RuntimeError):
    """Raised by `require_entitlement()` (P1.9) when the tenant's active
    plan does not grant a given boolean capability key. Carries only the
    entitlement key -- never the tenant's full entitlements dict, plan
    name, or any other subscription detail (mirrors
    `SubscriptionNotFoundError`'s own minimal-disclosure convention)."""

    def __init__(self, tenant_id: uuid.UUID, key: str) -> None:
        self.tenant_id = tenant_id
        self.key = key
        super().__init__(f"Tenant {tenant_id} is not entitled to {key!r}.")


# --- Commercial parties (Billing Foundation v2 Phase 2; ADR-0029) ----------


class BillingActorRequiredError(TypeError):
    """Raised when a commercial billing entry point that enforces
    authorization (`core/billing/authorization.py`) is called without an
    explicit caller. A missing caller is never treated as "authorized" and
    never silently downgraded to a system caller: callers pass a
    `core.authority.UserCaller` (evaluated by `core.rbac.can()`) or
    `SystemCaller(SystemAuthority.BILLING_OPERATIONS)` (Phase 5.3; the
    deprecated `BillingActor`/`trusted_system()` map onto those)."""

    def __init__(self) -> None:
        super().__init__(
            "This billing operation requires an explicit caller: a UserCaller, or "
            "SystemCaller(SystemAuthority.BILLING_OPERATIONS) for a genuine in-process "
            "system path."
        )


class BillingNotAuthorizedError(PermissionError):
    """Raised when `core.rbac.can()` denies a billing permission
    (`core/billing/authorization.py`). Deliberately the same error -- and
    the same message shape -- whichever of a multi-check operation's
    checks failed (e.g. payer `billing.account:charge` vs. service tenant
    `billing.subscription:create`), so a denial never reveals which side
    of a commercial relationship the actor lacks authority over."""

    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(f"Not authorized to perform billing operation {operation!r}.")


class InvalidBillingPartyError(ValueError):
    """Raised for a malformed commercial-party input (an empty provider
    name/reference, an unknown status value, an inconsistent party
    combination). Carries no provider credential."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class MerchantAccountNotFoundError(LookupError):
    """Same error whether the merchant account does not exist or belongs
    to a different owner tenant -- mirrors `SubscriptionNotFoundError`'s
    non-disclosure convention."""

    def __init__(self, tenant_id: uuid.UUID, merchant_account_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.merchant_account_id = merchant_account_id
        super().__init__(
            f"Merchant account {merchant_account_id} not found for tenant {tenant_id}."
        )


class DuplicateMerchantAccountError(ValueError):
    """Raised when `(provider, provider_account_ref)` is already claimed by
    a merchant account -- deployment-wide, whichever tenant owns it. The
    message never names the existing owner."""

    def __init__(self, provider: str) -> None:
        self.provider = provider
        super().__init__(
            f"A merchant account for this {provider!r} provider account already exists."
        )


class BillingAccountNotFoundError(LookupError):
    """Same error whether the billing account does not exist or belongs to
    a different payer tenant."""

    def __init__(self, tenant_id: uuid.UUID, billing_account_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.billing_account_id = billing_account_id
        super().__init__(f"Billing account {billing_account_id} not found for tenant {tenant_id}.")


class CommercialPartyNotActiveError(ValueError):
    """Raised when a merchant account or billing account that an operation
    would charge through is not in the `active` status."""

    def __init__(self, kind: str, party_id: uuid.UUID, status: str) -> None:
        self.kind = kind
        self.party_id = party_id
        self.status = status
        super().__init__(f"{kind} {party_id} is not active (status {status!r}).")


class MerchantNotEligibleForPlanError(ValueError):
    """Raised when a billing account's merchant cannot sell the requested
    plan. Until Catalog v2 gives plans an owner and a merchant
    (docs/ADR/0029-..., invariant 4), every plan is sold by the platform
    tenant's merchant only, so a billing account at any other merchant is
    rejected rather than guessed at."""

    def __init__(self, merchant_account_id: uuid.UUID, plan_key: str) -> None:
        self.merchant_account_id = merchant_account_id
        self.plan_key = plan_key
        super().__init__(
            f"Merchant account {merchant_account_id} does not sell billing plan {plan_key!r}."
        )


class BillingProviderMismatchError(ValueError):
    """Raised when the `BillingProvider` adapter supplied for an operation
    is not the provider the merchant account is held at -- e.g. a fake
    adapter used against a `"stripe"` merchant, which would record a
    provider reference the real provider never issued."""

    def __init__(self, expected: str, actual: str | None) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Billing provider adapter {actual!r} does not match the merchant's provider "
            f"{expected!r}."
        )


class ProviderRefConflictError(ValueError):
    """Raised when a provider object reference is already mapped -- to any
    tenant or local row. Never names the existing mapping's tenant."""

    def __init__(self, provider: str, object_type: str) -> None:
        self.provider = provider
        self.object_type = object_type
        super().__init__(
            f"This {provider!r} {object_type!r} reference is already mapped to a local object."
        )


class ProviderRefNotFoundError(LookupError):
    """Raised when a provider object reference has no mapping."""

    def __init__(self, provider: str, object_type: str) -> None:
        self.provider = provider
        self.object_type = object_type
        super().__init__(f"No local object is mapped to this {provider!r} {object_type!r}.")


# --- Lifecycle safety (Billing Foundation v2 Phase 3) -----------------------


class InvalidSubscriptionTransitionError(ValueError):
    """Raised when a subscription status change is not an allowed
    lifecycle transition (`core/billing/lifecycle.py::ALLOWED_TRANSITIONS`)."""

    def __init__(self, current: str, target: str) -> None:
        self.current = current
        self.target = target
        super().__init__(f"Subscription status cannot move from {current!r} to {target!r}.")


class LiveSubscriptionExistsError(ValueError):
    """Raised when a service tenant already has a live (`pending`, `active`
    or `past_due`) subscription at the same merchant -- the database's
    `uq_billing_subscriptions_one_live_per_merchant` partial unique index is
    the authoritative check; this error is its stable domain mapping."""

    def __init__(self, service_tenant_id: uuid.UUID, merchant_account_id: uuid.UUID) -> None:
        self.service_tenant_id = service_tenant_id
        self.merchant_account_id = merchant_account_id
        super().__init__(
            f"Tenant {service_tenant_id} already has a live subscription at merchant "
            f"{merchant_account_id}."
        )


class LegacyReconciliationError(ValueError):
    """Raised when a legacy-unverified subscription cannot be reconciled:
    it is not legacy-unverified, the supplied mapping contradicts what the
    row already records, or the provider cannot positively confirm the
    subscription. The row is left unchanged."""

    def __init__(self, subscription_id: uuid.UUID, reason: str) -> None:
        self.subscription_id = subscription_id
        self.reason = reason
        super().__init__(f"Subscription {subscription_id} cannot be reconciled: {reason}")


class ProviderReferenceMismatchError(ValueError):
    """Raised when a verified subscription's provider reference does not
    resolve, through the global provider-reference index, back to exactly
    that subscription in its own tenant. Fails closed: no provider answer is
    applied to a row whose provider identity cannot be confirmed."""

    def __init__(self, subscription_id: uuid.UUID) -> None:
        self.subscription_id = subscription_id
        super().__init__(
            f"Subscription {subscription_id}'s provider reference does not resolve to it."
        )


class BillingProviderContractError(ValueError):
    """Raised when a `BillingProvider` adapter used for a commercial
    subscription does not declare `honors_idempotency_keys = True` -- the
    explicit contract provider idempotency rests on (Billing Foundation v2
    Phase 3)."""

    def __init__(self, provider: str | None) -> None:
        self.provider = provider
        super().__init__(
            f"Billing provider adapter {provider!r} does not declare that it honors "
            "idempotency keys and cannot be used for commercial subscriptions."
        )


# --- Catalog v2 (Phase 5.3 step 2) -------------------------------------------------


class InvalidCatalogValueError(ValueError):
    """A catalog input -- plan key or name, entitlements, visibility --
    is not valid. Raised before anything is read or written."""


class DuplicateOwnedPlanKeyError(ValueError):
    """The owner already has a plan with this key. Plan keys are unique
    per owner, so this never reveals anything about another owner's
    catalog."""

    def __init__(self, owner_tenant_id: uuid.UUID, key: str) -> None:
        self.owner_tenant_id = owner_tenant_id
        self.key = key
        super().__init__(f"Tenant {owner_tenant_id} already has a billing plan {key!r}.")


class CatalogPlanNotFoundError(LookupError):
    """The plan does not exist among `owner_tenant_id`'s plans -- the same
    error whether it does not exist at all or belongs to another owner."""

    def __init__(self, owner_tenant_id: uuid.UUID, plan_id: uuid.UUID) -> None:
        self.owner_tenant_id = owner_tenant_id
        self.plan_id = plan_id
        super().__init__(f"Billing plan {plan_id} not found for tenant {owner_tenant_id}.")


class PlanWithdrawnError(ValueError):
    """The plan is withdrawn: it can be neither offered nor newly
    subscribed to. Existing subscriptions are unaffected."""

    def __init__(self, plan_id: uuid.UUID) -> None:
        self.plan_id = plan_id
        super().__init__(f"Billing plan {plan_id} is withdrawn.")


class PlanOfferNotFoundError(LookupError):
    """The offer does not exist among `owner_tenant_id`'s offers."""

    def __init__(self, owner_tenant_id: uuid.UUID, offer_id: uuid.UUID) -> None:
        self.owner_tenant_id = owner_tenant_id
        self.offer_id = offer_id
        super().__init__(f"Plan offer {offer_id} not found for tenant {owner_tenant_id}.")


class LegacyPlanAdoptionError(ValueError):
    """A legacy plan cannot be adopted: it does not exist, is not a legacy
    plan, or already has an owner. Nothing is changed."""

    def __init__(self, plan_id: uuid.UUID, reason: str) -> None:
        self.plan_id = plan_id
        self.reason = reason
        super().__init__(f"Billing plan {plan_id} cannot be adopted: {reason}")


class PlanNotEligibleError(PermissionError):
    """The plan may not be subscribed to for this service tenant by this
    caller, through this billing account (Phase 5.3 step 3): the single
    Catalog v2 eligibility predicate refused it, or the plan does not
    exist. Deliberately the same error -- and the same message -- for every
    reason, so a refusal never reveals whether a plan exists, who owns it,
    or which rule failed. `reason` is for the caller's own diagnostics."""

    def __init__(self, service_tenant_id: uuid.UUID, plan_id: uuid.UUID, reason: str) -> None:
        self.service_tenant_id = service_tenant_id
        self.plan_id = plan_id
        self.reason = reason
        super().__init__(f"Billing plan {plan_id} is not available to tenant {service_tenant_id}.")


# --- Seller/payer projections (Phase 5.3 step 4) ------------------------------------


class MalformedProjectionEventError(PermanentEventError, ValueError):
    """A `billing.subscription_changed` outbox event that cannot be
    projected: malformed payload, or a subscription that does not exist in
    the event's own tenant. Permanent -- dead-lettered, never retried, and
    never projected into any tenant. The message names the problem, never
    the payload."""


class ProjectionNotReadyError(RuntimeError):
    """The canonical subscription is older than the event announcing it --
    the change is not visible yet. Transient: the event is retried."""


class SubscriptionProjectionNotFoundError(LookupError):
    """No projection row for this subscription in the reading tenant's
    view -- the same error whether it does not exist, belongs to another
    tenant, or has not been projected yet."""

    def __init__(self, tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        super().__init__(f"No projected subscription {subscription_id} for tenant {tenant_id}.")


# --- Lifecycle and inherits_billing retirement (Phase 5.3 step 5) ---------------------


class BillingInheritanceMigrationError(ValueError):
    """A sponsored migration of an inheriting tenant was refused: the
    tenant does not (or no longer does) inherit billing, or it already has
    a live subscription the migration could duplicate. Nothing changed."""

    def __init__(self, tenant_id: uuid.UUID, reason: str) -> None:
        self.tenant_id = tenant_id
        self.reason = reason
        super().__init__(f"Tenant {tenant_id} cannot be migrated to sponsorship: {reason}")


class LegacyBillingPathError(PermissionError):
    """A legacy trusted billing mutation (`upgrade_subscription()`,
    `cancel_subscription()`) was attempted on a verified commercial
    subscription (Phase 5.3 step 7). Those paths perform no authorization,
    no Catalog v2 eligibility and no merchant-compatibility check, so a
    commercial subscription is changed only through the commercial API
    (`cancel_commercial_subscription()`, ...). Nothing was changed and no
    provider was called."""

    def __init__(self, subscription_id: uuid.UUID) -> None:
        self.subscription_id = subscription_id
        super().__init__(
            f"Subscription {subscription_id} is a commercial subscription; "
            "use the commercial billing API."
        )
