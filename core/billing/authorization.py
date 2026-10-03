"""Billing authorization: the generic billing permission vocabulary and the
caller model every commercial billing entry point takes
(Billing Foundation v2 Phase 2; converged on `core.authority` by Phase 5.3
step 1 -- docs/ADR/0029-commercial-parties-and-billing-relationships.md,
"Billing authorization", and docs/ADR/0031-foundation-authority-and-
evidence.md, "Amendment (2026-10-02)").

**No second authorization system.** Every check here is one call to
`core.rbac.can(session=...)` -- the same chokepoint every other Core module
uses -- evaluated *inside the protected mutation's own transaction*, so
`SUBTREE` role scope, `DelegationGrant`s and `DenyGrant`s apply to billing
exactly as they do everywhere else, and the rows the decision relied on
stay locked until the mutation commits. This module only names *which*
permission on *which* tenant each billing operation needs.

**Vocabulary** (`resource`, `action`), registered generically into the
global `core.permissions` catalog; which roles receive them is a
consumer's decision:

    billing.catalog       read, manage                          on the plan owner tenant
    billing.merchant      manage                                on the payee tenant
    billing.account       read, manage, charge                  on the payer tenant
    billing.subscription  create, read, change, cancel,
                          reactivate                            on the service tenant
    billing.invoice       read                                  on the payer tenant

Every mutation action is listed in
`core.rbac.authorization.BILLING_MUTATION_ACTIONS`, which a support-access
grant can never satisfy; the read actions stay ordinarily authorized.

**Callers -- the trust boundary.** A billing entry point takes an explicit
`core.authority` caller, never an optional actor id:

- `UserCaller(user_id)` -- a `core.identity` user, authorized by `can()`
  for every required check. Denial raises `BillingNotAuthorizedError`, the
  same error whichever check failed.
- `SystemCaller(SystemAuthority.BILLING_OPERATIONS)` -- a genuine
  in-process system path (an operator command, a migration-time backfill,
  a test fixture) with no principal to evaluate. It skips `can()` and is
  audited as `ActorType.SYSTEM` with its purpose. A `SystemCaller` for any
  other purpose is refused.

`ServiceAccountCaller` is not accepted yet: a service account's audit
attribution is bound to its own tenant, and attributing a cross-tenant
commercial operation to one needs a decision Phase 5.3 defers.

**Deprecated compatibility layer.** `BillingActor.user(user_id)` and
`trusted_system(reason)` predate the convergence. They are accepted and
mapped onto the types above -- `BillingActor` to `UserCaller`,
`trusted_system(reason)` to `SystemCaller(BILLING_OPERATIONS)` -- so they
can never carry more authority than the typed caller they map to. A
`trusted_system()` reason is only recorded as an audit note; it is never
an authority. Both will be removed once their callers move.

`None`, or anything else, is rejected (`BillingActorRequiredError`) before
any database access: a missing caller is never an authorized human and
never silently becomes a system caller. The pre-Phase-2 functions
(`core/billing/service.py::subscribe()` and friends) are the separate,
documented legacy trusted path and take no caller.
"""

from __future__ import annotations

import uuid
import warnings
from collections.abc import Iterable
from dataclasses import dataclass

from core.audit_log import ActorType, AuditOutcome, record_in_transaction
from core.authority import Caller, SystemAuthority, SystemCaller, UserCaller
from core.billing.errors import BillingActorRequiredError, BillingNotAuthorizedError
from core.rbac import can, register_permission
from infra.db import Session

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

#: The one `SystemAuthority` purpose billing entry points accept.
BILLING_SYSTEM_AUTHORITY = SystemAuthority.BILLING_OPERATIONS


@dataclass(frozen=True)
class BillingActor:
    """**Deprecated** (Phase 5.3): use `core.authority.UserCaller`. Maps to
    `UserCaller(user_id)` and carries nothing more."""

    user_id: uuid.UUID

    @classmethod
    def user(cls, user_id: uuid.UUID) -> BillingActor:
        return cls(user_id=user_id)


@dataclass(frozen=True)
class TrustedSystemCaller:
    """**Deprecated** (Phase 5.3): use
    `SystemCaller(SystemAuthority.BILLING_OPERATIONS)`. Construct only via
    `trusted_system()`. Its `reason` is an audit note, never an authority."""

    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("trusted_system() requires a non-empty reason.")


def trusted_system(reason: str) -> TrustedSystemCaller:
    """**Deprecated** (Phase 5.3): use
    `SystemCaller(SystemAuthority.BILLING_OPERATIONS)`. Accepted only as
    that typed authority; `reason` is recorded in the audit entry and
    grants nothing."""
    warnings.warn(
        "trusted_system(reason) is deprecated; use "
        "SystemCaller(SystemAuthority.BILLING_OPERATIONS).",
        DeprecationWarning,
        stacklevel=2,
    )
    return TrustedSystemCaller(reason=reason)


BillingCaller = UserCaller | SystemCaller | BillingActor | TrustedSystemCaller


@dataclass(frozen=True)
class AuthorizedBillingCaller:
    """A billing caller normalized onto `core.authority`: `caller` is what
    `can()` evaluates and what the audit entry names; `audit_note` carries
    only a deprecated `trusted_system()` reason, as metadata."""

    caller: Caller
    audit_note: dict[str, object]


def register_billing_permissions() -> None:
    """Register the full billing vocabulary into the global permission
    catalog. Idempotent (`core.rbac.register_permission()`); a consumer
    calls it once so its roles can be granted billing permissions before
    any billing operation has run."""
    for resource, action in BILLING_PERMISSIONS:
        register_permission(resource, action)


def require_billing_caller(caller: object) -> AuthorizedBillingCaller:
    """Normalize `caller` onto `core.authority`, or raise
    `BillingActorRequiredError` -- in particular for `None`, a bare id or a
    `ServiceAccountCaller`. Performs no database access, so it is the
    first thing every billing entry point does."""
    if type(caller) is UserCaller:
        return AuthorizedBillingCaller(caller=caller, audit_note={})
    if type(caller) is SystemCaller:
        return AuthorizedBillingCaller(caller=caller, audit_note={})
    if type(caller) is BillingActor:
        return AuthorizedBillingCaller(caller=UserCaller(caller.user_id), audit_note={})
    if type(caller) is TrustedSystemCaller:
        return AuthorizedBillingCaller(
            caller=SystemCaller(BILLING_SYSTEM_AUTHORITY),
            audit_note={"trusted_system_reason": caller.reason},
        )
    raise BillingActorRequiredError()


def authorize_billing(
    caller: object,
    checks: Iterable[tuple[uuid.UUID, str, str]],
    *,
    operation: str,
    session: Session,
) -> AuthorizedBillingCaller:
    """Require `caller` to hold every `(tenant_id, resource, action)` in
    `checks`, through `core.rbac.can(session=session)` -- evaluated in
    `session`, which must be the protected mutation's own transaction
    (ADR-0031 section 3a). Every check must pass; the first denial raises
    `BillingNotAuthorizedError(operation)` -- identical for every check, so
    the error never says which party the actor lacks authority over.

    A `SystemCaller` skips `can()` only for `SystemAuthority.
    BILLING_OPERATIONS`; any other purpose is denied. Returns the
    normalized caller."""
    authorized = require_billing_caller(caller)
    core_caller = authorized.caller
    if isinstance(core_caller, SystemCaller):
        if core_caller.authority is not BILLING_SYSTEM_AUTHORITY:
            raise BillingNotAuthorizedError(operation)
        return authorized
    assert isinstance(core_caller, UserCaller)
    for tenant_id, resource, action in checks:
        register_permission(resource, action, session=session)
        if not can(
            actor_id=core_caller.user_id,
            tenant_id=tenant_id,
            action=action,
            resource=resource,
            session=session,
        ):
            raise BillingNotAuthorizedError(operation)
    return authorized


def record_billing_audit(
    session: Session,
    authorized: AuthorizedBillingCaller,
    *,
    tenant_id: uuid.UUID,
    action: str,
    resource_type: str,
    resource_id: str,
    metadata: dict[str, object],
) -> None:
    """Append the billing mutation's audit entry inside `session` -- the
    mutation's own transaction (`core.audit_log.record_in_transaction()`),
    so the change and its evidence commit or roll back together. `session`
    must be scoped to `tenant_id` (the audit log's RLS refuses any other)."""
    record_in_transaction(
        session,
        caller=authorized.caller,
        tenant_id=tenant_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=AuditOutcome.SUCCESS,
        metadata={**metadata, **authorized.audit_note},
    )


def audit_actor(
    authorized: AuthorizedBillingCaller,
) -> tuple[ActorType, uuid.UUID | None, dict[str, object]]:
    """`(actor_type, actor_user_id, extra metadata)` for a secondary audit
    entry written outside the mutation's transaction (the payer-side record
    of a sponsored subscription -- a separate tenant, which ADR-0029 keeps
    out of the service tenant's transaction; making it durable through the
    outbox is deferred, since the projection consumer deliberately writes
    no audit evidence)."""
    core_caller = authorized.caller
    if isinstance(core_caller, SystemCaller):
        return (
            ActorType.SYSTEM,
            None,
            {"system_authority": core_caller.authority.value, **authorized.audit_note},
        )
    assert isinstance(core_caller, UserCaller)
    return ActorType.USER, core_caller.user_id, dict(authorized.audit_note)
