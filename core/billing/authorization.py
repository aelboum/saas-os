"""Billing authorization: the generic billing permission vocabulary and the
explicit caller types every commercial billing entry point takes
(Billing Foundation v2 Phase 2;
docs/ADR/0029-commercial-parties-and-billing-relationships.md, "Billing
authorization").

**No second authorization system.** Every check here is one call to
`core.rbac.can()` -- the same chokepoint every other Core module uses
(`core/api_keys/service.py`, `core/identity/service.py`) -- so `SUBTREE`
role scope, `DelegationGrant`s and `DenyGrant`s apply to billing exactly
as they do everywhere else. This module only names *which* permission
on *which* tenant each billing operation needs.

**Vocabulary** (`resource`, `action`), registered generically into the
global `core.permissions` catalog; which roles receive them is a
consumer's decision:

    billing.catalog       read, manage                          on the plan owner tenant
    billing.merchant      manage                                on the payee tenant
    billing.account       read, manage, charge                  on the payer tenant
    billing.subscription  create, read, change, cancel,
                          reactivate                            on the service tenant
    billing.invoice       read                                  on the payer tenant

**Explicit callers -- the trust boundary.** A commercial entry point takes
a `BillingCaller`, never an optional actor id:

- `BillingActor.user(user_id)` -- a `core.identity` user, authorized by
  `can()` for every required check. Denial raises
  `BillingNotAuthorizedError`, the same error whichever check failed.
- `trusted_system(reason)` -- an explicit, named marker for a genuine
  in-process system path (an operator command, a migration-time
  backfill, a test fixture) that has no human or machine principal to
  evaluate. It skips `can()` and is audited as `ActorType.SYSTEM` with
  its `reason` recorded. It must be constructed deliberately at the call
  site; it is never produced by omitting an actor.

`None` is rejected (`BillingActorRequiredError`): a missing actor is never
treated as an authorized human, and never silently becomes a system
caller. This is deliberately different from the pre-Phase-2 functions
(`core/billing/service.py::subscribe()` and friends), whose optional
`actor_user_id` remains audit attribution only -- those are documented
there as the legacy trusted path.

Service-account principals are not yet accepted as billing actors: a
service account's audit attribution is bound to its own tenant
(`core/audit_log/models.py::fk_audit_log_tenant_service_account`), and
attributing a cross-tenant commercial operation to one needs a design
decision this phase does not make.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from core.audit_log import ActorType
from core.billing.errors import BillingActorRequiredError, BillingNotAuthorizedError
from core.rbac import can, register_permission

BILLING_CATALOG = "billing.catalog"
BILLING_MERCHANT = "billing.merchant"
BILLING_ACCOUNT = "billing.account"
BILLING_SUBSCRIPTION = "billing.subscription"
BILLING_INVOICE = "billing.invoice"

BILLING_PERMISSIONS: tuple[tuple[str, str], ...] = (
    (BILLING_CATALOG, "read"),
    (BILLING_CATALOG, "manage"),
    (BILLING_MERCHANT, "manage"),
    (BILLING_ACCOUNT, "read"),
    (BILLING_ACCOUNT, "manage"),
    (BILLING_ACCOUNT, "charge"),
    (BILLING_SUBSCRIPTION, "create"),
    (BILLING_SUBSCRIPTION, "read"),
    (BILLING_SUBSCRIPTION, "change"),
    (BILLING_SUBSCRIPTION, "cancel"),
    (BILLING_SUBSCRIPTION, "reactivate"),
    (BILLING_INVOICE, "read"),
)


@dataclass(frozen=True)
class BillingActor:
    """A principal whose billing authority is evaluated by `core.rbac.can()`."""

    user_id: uuid.UUID

    @classmethod
    def user(cls, user_id: uuid.UUID) -> BillingActor:
        return cls(user_id=user_id)


@dataclass(frozen=True)
class TrustedSystemCaller:
    """An explicit in-process system caller -- see the module docstring.
    Construct only via `trusted_system()`."""

    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("trusted_system() requires a non-empty reason.")


def trusted_system(reason: str) -> TrustedSystemCaller:
    """Mark a call as a genuine trusted in-process system path. `reason` is
    recorded in the audit entry; it names *why* no principal is evaluated
    (e.g. `"operator: platform merchant setup"`)."""
    return TrustedSystemCaller(reason=reason)


BillingCaller = BillingActor | TrustedSystemCaller


def register_billing_permissions() -> None:
    """Register the full billing vocabulary into the global permission
    catalog. Idempotent (`core.rbac.register_permission()`); a consumer
    calls it once so its roles can be granted billing permissions before
    any billing operation has run."""
    for resource, action in BILLING_PERMISSIONS:
        register_permission(resource, action)


def require_billing_caller(caller: object) -> BillingCaller:
    """Reject anything that is not an explicit `BillingCaller` -- in
    particular `None` (`BillingActorRequiredError`)."""
    if not isinstance(caller, (BillingActor, TrustedSystemCaller)):
        raise BillingActorRequiredError()
    return caller


def authorize_billing(
    caller: object,
    checks: Iterable[tuple[uuid.UUID, str, str]],
    *,
    operation: str,
) -> BillingCaller:
    """Require `caller` to hold every `(tenant_id, resource, action)` in
    `checks`, via `core.rbac.can()`. Every check must pass; the first
    denial raises `BillingNotAuthorizedError(operation)` -- identical for
    every check, so the error never says which party the actor lacks
    authority over. A `TrustedSystemCaller` skips `can()` by design (module
    docstring). Returns the validated caller."""
    validated = require_billing_caller(caller)
    if isinstance(validated, TrustedSystemCaller):
        return validated
    for tenant_id, resource, action in checks:
        register_permission(resource, action)
        if not can(
            actor_id=validated.user_id, tenant_id=tenant_id, action=action, resource=resource
        ):
            raise BillingNotAuthorizedError(operation)
    return validated


def audit_actor(caller: BillingCaller) -> tuple[ActorType, uuid.UUID | None, dict[str, object]]:
    """`(actor_type, actor_user_id, extra audit metadata)` for `caller`."""
    if isinstance(caller, TrustedSystemCaller):
        return ActorType.SYSTEM, None, {"trusted_system_reason": caller.reason}
    return ActorType.USER, caller.user_id, {}
