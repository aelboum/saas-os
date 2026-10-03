"""Catalog v2: owner- and merchant-scoped plans, their visibility, offers
for unlisted plans, and the single eligibility predicate (Phase 5.3 step 2;
docs/ADR/0029-commercial-parties-and-billing-relationships.md, "Catalog"
and "Amendment (2026-10-02)"; docs/ADR/0022-..., catalog status update).

**Parties.** A plan has an **owner** tenant and a **merchant** (a
`MerchantAccount` the owner owns; enforced by the composite foreign key
`fk_billing_plans_owner_merchant`). The **service tenant** is whoever would
receive the service; the **payer** is chosen at subscription time and is
not a catalog concept. None of these is inferred from the tenant hierarchy
-- the hierarchy is only an *input* to `descendants` visibility.

**One eligibility predicate.** `evaluate_plan_eligibility()` decides, for
one caller, service tenant and plan, whether that plan may be offered to
and bought for that tenant. `list_plans()` uses it to filter, and the
commercial subscription path re-evaluates it in its final transaction
(Phase 5.3 step 3). ADR-0029's predicate:

    plan is adopted (has an owner) and active, its merchant is active
    AND can(caller, service_tenant, billing.subscription:create)
    AND (   visibility = public
         OR (visibility = descendants AND service_tenant is a strict
             descendant of the plan owner)
         OR (visibility = private     AND can(caller, owner, billing.catalog:read))
         OR (visibility = unlisted    AND an active offer of the plan to
             service_tenant exists))

plus, when the caller names a billing account's merchant, merchant
compatibility (`plan.merchant_account_id` must be that merchant). Knowing
a plan id never grants eligibility. Listing therefore requires the same
`billing.subscription:create` authority as buying: the catalog is "what
this tenant may be subscribed to", and a support-access grant -- which can
never satisfy a billing mutation (ADR-0031 amendment) -- cannot list it.

**Storage and isolation.** `core.billing_plans` stays outside RLS (ADR-0022
amendment): visibility depends on hierarchy position, actor permissions and
offers, which a single-tenant RLS policy cannot express. Every read and
write here runs inside a `tenant_session_scope()` transaction; the offer
and merchant rows (both RLS-protected, owned by the plan owner) are read in
that same transaction under `bind_tenant_scope()`, so a decision and the
rows it relied on are one snapshot -- the concurrency guarantee the
step 3 commit-time re-check relies on (rows are read `FOR SHARE`).

**Mutations** (`billing.catalog:manage` on the owner, authorized with
`can(session=...)` and audited with `record_in_transaction()` in the same
transaction, ADR-0031 amendment): `create_owned_plan`,
`set_plan_visibility`, `withdraw_plan`, `create_plan_offer`,
`revoke_plan_offer`. `adopt_legacy_plan` is an operator action and accepts
only `SystemCaller(SystemAuthority.BILLING_OPERATIONS)`.

**Plans are immutable through this API.** Nothing here edits a plan's
entitlements, key, merchant or provider price; a material change is a new
plan, and existing subscriptions keep theirs. Full `PlanVersion`/`Price`
versioning is deferred. Withdrawal stops new subscriptions only and is
terminal; it never touches an existing subscription.

**Legacy plans.** Plans created before Catalog v2, or by the legacy
`core/billing/service.py::create_plan()`, have no owner: they are *not yet
adopted* (never "platform"), keep working on the legacy key-addressed paths
(`get_plan(key)`, `subscribe()`), and are never eligible here until adopted.
"""

from __future__ import annotations

import enum
import math
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from core.authority import SystemCaller
from core.billing.authorization import (
    BILLING_CATALOG,
    BILLING_SUBSCRIPTION,
    BILLING_SYSTEM_AUTHORITY,
    authorize_billing,
    record_billing_audit,
    require_billing_caller,
)
from core.billing.errors import (
    BillingNotAuthorizedError,
    CatalogPlanNotFoundError,
    CommercialPartyNotActiveError,
    DuplicateOwnedPlanKeyError,
    InvalidCatalogValueError,
    LegacyPlanAdoptionError,
    MerchantAccountNotFoundError,
    PlanOfferNotFoundError,
    PlanWithdrawnError,
)
from core.billing.models import MerchantAccount, Plan, PlanOffer
from core.billing.parties import MerchantAccountStatus
from core.tenancy import lock_ancestor_ids, lock_open_tenant
from infra.db import IntegrityError, Session, bind_tenant_scope, select, tenant_session_scope

_MAX_KEY_LENGTH = 100
_MAX_NAME_LENGTH = 200
_MAX_PRICE_REF_LENGTH = 255
_OWNER_KEY_INDEX = "uq_billing_plans_owner_key"


class PlanVisibility(enum.StrEnum):
    """Who may discover and buy a plan (ADR-0029 "Catalog")."""

    PUBLIC = "public"
    DESCENDANTS = "descendants"
    PRIVATE = "private"
    UNLISTED = "unlisted"


class PlanStatus(enum.StrEnum):
    """`active` plans may be newly subscribed to; `withdrawn` plans may
    not. Withdrawal is terminal and never touches existing subscriptions."""

    ACTIVE = "active"
    WITHDRAWN = "withdrawn"


class PlanOfferStatus(enum.StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class EligibilityReason(enum.StrEnum):
    """Why a plan is or is not eligible. For the caller's own use; a
    consumer showing a denial to an end user should not distinguish
    them."""

    ELIGIBLE = "eligible"
    NOT_AUTHORIZED = "not_authorized"
    NOT_ADOPTED = "not_adopted"
    WITHDRAWN = "withdrawn"
    MERCHANT_MISMATCH = "merchant_mismatch"
    MERCHANT_INACTIVE = "merchant_inactive"
    NOT_A_DESCENDANT = "not_a_descendant"
    PRIVATE = "private"
    NO_OFFER = "no_offer"


@dataclass(frozen=True)
class PlanEligibility:
    eligible: bool
    reason: EligibilityReason


_ELIGIBLE = PlanEligibility(True, EligibilityReason.ELIGIBLE)


def _ineligible(reason: EligibilityReason) -> PlanEligibility:
    return PlanEligibility(False, reason)


# --- The eligibility predicate ---------------------------------------------------------


def evaluate_plan_eligibility(
    caller: object,
    service_tenant_id: uuid.UUID,
    plan: Plan,
    *,
    session: Session,
    merchant_account_id: uuid.UUID | None = None,
) -> PlanEligibility:
    """The single catalog eligibility decision (module docstring), made in
    `session` -- the caller's transaction, scoped to `service_tenant_id`.

    `merchant_account_id`, when given, is the merchant of the billing
    account that would pay; the plan must be sold by that merchant
    (ADR-0029 invariant 4). Raises `BillingActorRequiredError` for a
    missing caller and `TenantClosedError` for a closed service tenant;
    every other outcome is a `PlanEligibility`.

    The service tenant's `core.tenants` row is read `FOR SHARE` and its
    ancestry `FOR SHARE`, and the offer and merchant rows `FOR SHARE`, so a
    concurrent move, offer revocation or merchant change is serialized
    against the transaction that relies on this decision."""
    require_billing_caller(caller)
    lock_open_tenant(session, service_tenant_id)
    owner = plan.owner_tenant_id
    if owner is None or plan.merchant_account_id is None:
        return _ineligible(EligibilityReason.NOT_ADOPTED)
    if plan.status != PlanStatus.ACTIVE.value:
        return _ineligible(EligibilityReason.WITHDRAWN)
    if merchant_account_id is not None and merchant_account_id != plan.merchant_account_id:
        return _ineligible(EligibilityReason.MERCHANT_MISMATCH)
    if not _holds(caller, service_tenant_id, BILLING_SUBSCRIPTION, "create", session=session):
        return _ineligible(EligibilityReason.NOT_AUTHORIZED)

    with bind_tenant_scope(session, owner):
        merchant = session.execute(
            select(MerchantAccount)
            .where(
                MerchantAccount.tenant_id == owner,
                MerchantAccount.id == plan.merchant_account_id,
            )
            .with_for_update(read=True)
        ).scalar_one_or_none()
    if merchant is None or merchant.status != MerchantAccountStatus.ACTIVE.value:
        return _ineligible(EligibilityReason.MERCHANT_INACTIVE)

    visibility = PlanVisibility(plan.visibility)
    if visibility is PlanVisibility.PUBLIC:
        return _ELIGIBLE
    if visibility is PlanVisibility.DESCENDANTS:
        ancestors = lock_ancestor_ids(session, service_tenant_id)
        if owner != service_tenant_id and owner in ancestors:
            return _ELIGIBLE
        return _ineligible(EligibilityReason.NOT_A_DESCENDANT)
    if visibility is PlanVisibility.PRIVATE:
        if _holds(caller, owner, BILLING_CATALOG, "read", session=session):
            return _ELIGIBLE
        return _ineligible(EligibilityReason.PRIVATE)
    with bind_tenant_scope(session, owner):
        offer = session.execute(
            select(PlanOffer.id)
            .where(
                PlanOffer.tenant_id == owner,
                PlanOffer.plan_id == plan.id,
                PlanOffer.service_tenant_id == service_tenant_id,
                PlanOffer.status == PlanOfferStatus.ACTIVE.value,
            )
            .with_for_update(read=True)
        ).first()
    return _ELIGIBLE if offer is not None else _ineligible(EligibilityReason.NO_OFFER)


def _holds(
    caller: object, tenant_id: uuid.UUID, resource: str, action: str, *, session: Session
) -> bool:
    try:
        authorize_billing(
            caller,
            [(tenant_id, resource, action)],
            operation="billing.catalog.eligibility",
            session=session,
        )
    except BillingNotAuthorizedError:
        return False
    return True


def list_plans(caller: object, *, service_tenant_id: uuid.UUID) -> list[Plan]:
    """The plans `caller` may subscribe `service_tenant_id` to: every
    adopted, active plan for which `evaluate_plan_eligibility()` holds --
    including an `unlisted` plan only when it has been offered to this
    tenant. Not a deployment-wide enumeration: a plan is returned only
    because the predicate admitted it. Unaffected by the tenant's own
    entitlements."""
    require_billing_caller(caller)
    with tenant_session_scope(service_tenant_id) as session:
        candidates = (
            session.execute(
                select(Plan)
                .where(
                    Plan.owner_tenant_id.is_not(None),
                    Plan.status == PlanStatus.ACTIVE.value,
                )
                .order_by(Plan.owner_tenant_id, Plan.key)
            )
            .scalars()
            .all()
        )
        eligible = [
            plan
            for plan in candidates
            if evaluate_plan_eligibility(caller, service_tenant_id, plan, session=session).eligible
        ]
        for plan in eligible:
            session.expunge(plan)
    return eligible


# --- Catalog mutations ------------------------------------------------------------------


def _validate_key(key: object) -> str:
    if not isinstance(key, str) or not key.strip() or len(key) > _MAX_KEY_LENGTH:
        raise InvalidCatalogValueError(
            f"plan key must be a non-empty string of at most {_MAX_KEY_LENGTH} characters."
        )
    return key


def _validate_name(name: object) -> str:
    if not isinstance(name, str) or not name.strip() or len(name) > _MAX_NAME_LENGTH:
        raise InvalidCatalogValueError(
            f"plan name must be a non-empty string of at most {_MAX_NAME_LENGTH} characters."
        )
    return name


def _validate_visibility(visibility: object) -> PlanVisibility:
    try:
        return PlanVisibility(visibility)
    except ValueError:
        raise InvalidCatalogValueError(f"unknown plan visibility {visibility!r}.") from None


def _require_owned_merchant(
    session: Session, owner_tenant_id: uuid.UUID, merchant_account_id: uuid.UUID
) -> MerchantAccount:
    merchant = session.get(MerchantAccount, merchant_account_id)
    if merchant is None or merchant.tenant_id != owner_tenant_id:
        raise MerchantAccountNotFoundError(owner_tenant_id, merchant_account_id)
    if merchant.status == MerchantAccountStatus.DISABLED.value:
        raise CommercialPartyNotActiveError("Merchant account", merchant.id, merchant.status)
    return merchant


def _lock_owned_plan(session: Session, owner_tenant_id: uuid.UUID, plan_id: uuid.UUID) -> Plan:
    plan = session.execute(
        select(Plan)
        .where(Plan.id == plan_id, Plan.owner_tenant_id == owner_tenant_id)
        .with_for_update()
    ).scalar_one_or_none()
    if plan is None:
        raise CatalogPlanNotFoundError(owner_tenant_id, plan_id)
    return plan


def _owner_key_conflict(exc: IntegrityError) -> bool:
    diag = getattr(getattr(exc, "orig", None), "diag", None)
    return getattr(diag, "constraint_name", None) == _OWNER_KEY_INDEX


def _plan_metadata(plan: Plan) -> dict[str, object]:
    return {
        "plan_key": plan.key,
        "merchant_account_id": str(plan.merchant_account_id),
        "visibility": plan.visibility,
        "status": plan.status,
    }


def validate_entitlements(entitlements: object) -> dict[str, object]:
    """The single write-boundary check for a plan's entitlements (post-5.3
    audit remediation R4), shared by `create_owned_plan()` and the legacy
    `core.billing.service.create_plan()`. Plans are immutable through the
    API, so these are every write path.

    An entitlement is either a capability -- a literal `bool`, combined
    across subscriptions with `OR` -- or a numeric limit -- a finite,
    non-negative `int` or `float` (never a `bool`), combined with `MAX`.
    Anything else is refused, never converted: a string such as `"100"`,
    `None`, a list or a mapping would otherwise read as "no configured
    limit" and could let one plan erase another plan's numeric quota.
    Raises `InvalidCatalogValueError` naming the key (not the value)
    before anything is read or written; returns a plain copy."""
    if entitlements is None:
        return {}
    if not isinstance(entitlements, dict):
        raise InvalidCatalogValueError("entitlements must be a mapping.")
    validated: dict[str, object] = {}
    for key, value in entitlements.items():
        if not isinstance(key, str) or not key.strip():
            raise InvalidCatalogValueError("entitlement keys must be non-empty strings.")
        if isinstance(value, bool):
            validated[key] = value
            continue
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise InvalidCatalogValueError(
                f"entitlement {key!r} must be a boolean or a finite non-negative number."
            )
        validated[key] = value
    return validated


def create_owned_plan(
    caller: object,
    owner_tenant_id: uuid.UUID,
    *,
    merchant_account_id: uuid.UUID,
    key: str,
    name: str,
    entitlements: dict[str, object] | None = None,
    provider_price_id: str | None = None,
    visibility: PlanVisibility = PlanVisibility.PUBLIC,
) -> Plan:
    """Create a plan owned by `owner_tenant_id`, sold by its merchant
    `merchant_account_id` (`billing.catalog:manage` on the owner). The key
    must be unique among the owner's plans (`DuplicateOwnedPlanKeyError`).
    The plan is `active` and immutable from here on."""
    key = _validate_key(key)
    name = _validate_name(name)
    visibility = _validate_visibility(visibility)
    entitlements = validate_entitlements(entitlements)
    if provider_price_id is not None and (
        not isinstance(provider_price_id, str)
        or not provider_price_id.strip()
        or len(provider_price_id) > _MAX_PRICE_REF_LENGTH
    ):
        raise InvalidCatalogValueError("provider_price_id must be a short non-empty string.")
    require_billing_caller(caller)

    try:
        with tenant_session_scope(owner_tenant_id) as session:
            authorized = authorize_billing(
                caller,
                [(owner_tenant_id, BILLING_CATALOG, "manage")],
                operation="billing.plan.create",
                session=session,
            )
            lock_open_tenant(session, owner_tenant_id)
            _require_owned_merchant(session, owner_tenant_id, merchant_account_id)
            plan = Plan(
                key=key,
                name=name,
                entitlements=entitlements,
                provider_price_id=provider_price_id,
                owner_tenant_id=owner_tenant_id,
                merchant_account_id=merchant_account_id,
                visibility=visibility.value,
                status=PlanStatus.ACTIVE.value,
                legacy=False,
            )
            session.add(plan)
            session.flush()
            record_billing_audit(
                session,
                authorized,
                tenant_id=owner_tenant_id,
                action="billing.plan_created",
                resource_type="billing_plan",
                resource_id=str(plan.id),
                metadata=_plan_metadata(plan),
            )
            session.refresh(plan)
            session.expunge(plan)
    except IntegrityError as exc:
        if _owner_key_conflict(exc):
            raise DuplicateOwnedPlanKeyError(owner_tenant_id, key) from None
        raise
    return plan


def set_plan_visibility(
    caller: object,
    owner_tenant_id: uuid.UUID,
    plan_id: uuid.UUID,
    visibility: PlanVisibility,
) -> Plan:
    """Change who may discover and buy one of the owner's plans
    (`billing.catalog:manage` on the owner). Existing subscriptions are
    unaffected. Setting the current value is a no-op (no audit entry)."""
    visibility = _validate_visibility(visibility)
    require_billing_caller(caller)
    with tenant_session_scope(owner_tenant_id) as session:
        authorized = authorize_billing(
            caller,
            [(owner_tenant_id, BILLING_CATALOG, "manage")],
            operation="billing.plan.set_visibility",
            session=session,
        )
        plan = _lock_owned_plan(session, owner_tenant_id, plan_id)
        previous = plan.visibility
        if previous != visibility.value:
            plan.visibility = visibility.value
            session.flush()
            record_billing_audit(
                session,
                authorized,
                tenant_id=owner_tenant_id,
                action="billing.plan_visibility_changed",
                resource_type="billing_plan",
                resource_id=str(plan.id),
                metadata={"previous_visibility": previous, **_plan_metadata(plan)},
            )
            session.refresh(plan)
        session.expunge(plan)
    return plan


def withdraw_plan(caller: object, owner_tenant_id: uuid.UUID, plan_id: uuid.UUID) -> Plan:
    """Withdraw one of the owner's plans (`billing.catalog:manage` on the
    owner): it can no longer be newly subscribed to or offered. Terminal,
    idempotent, and **never** touches an existing subscription."""
    require_billing_caller(caller)
    with tenant_session_scope(owner_tenant_id) as session:
        authorized = authorize_billing(
            caller,
            [(owner_tenant_id, BILLING_CATALOG, "manage")],
            operation="billing.plan.withdraw",
            session=session,
        )
        plan = _lock_owned_plan(session, owner_tenant_id, plan_id)
        if plan.status != PlanStatus.WITHDRAWN.value:
            plan.status = PlanStatus.WITHDRAWN.value
            session.flush()
            record_billing_audit(
                session,
                authorized,
                tenant_id=owner_tenant_id,
                action="billing.plan_withdrawn",
                resource_type="billing_plan",
                resource_id=str(plan.id),
                metadata=_plan_metadata(plan),
            )
            session.refresh(plan)
        session.expunge(plan)
    return plan


def create_plan_offer(
    caller: object,
    owner_tenant_id: uuid.UUID,
    plan_id: uuid.UUID,
    *,
    service_tenant_id: uuid.UUID,
) -> PlanOffer:
    """Offer one of the owner's active plans to `service_tenant_id`
    (`billing.catalog:manage` on the owner) -- what makes an `unlisted`
    plan eligible for that tenant, and only that tenant. Idempotent: an
    existing active offer is returned unchanged."""
    require_billing_caller(caller)

    def _existing(session: Session) -> PlanOffer | None:
        return session.execute(
            select(PlanOffer).where(
                PlanOffer.tenant_id == owner_tenant_id,
                PlanOffer.plan_id == plan_id,
                PlanOffer.service_tenant_id == service_tenant_id,
                PlanOffer.status == PlanOfferStatus.ACTIVE.value,
            )
        ).scalar_one_or_none()

    try:
        with tenant_session_scope(owner_tenant_id) as session:
            authorized = authorize_billing(
                caller,
                [(owner_tenant_id, BILLING_CATALOG, "manage")],
                operation="billing.plan_offer.create",
                session=session,
            )
            lock_open_tenant(session, owner_tenant_id)
            lock_open_tenant(session, service_tenant_id)
            plan = session.execute(
                select(Plan)
                .where(Plan.id == plan_id, Plan.owner_tenant_id == owner_tenant_id)
                .with_for_update(read=True)
            ).scalar_one_or_none()
            if plan is None:
                raise CatalogPlanNotFoundError(owner_tenant_id, plan_id)
            if plan.status != PlanStatus.ACTIVE.value:
                raise PlanWithdrawnError(plan_id)
            existing = _existing(session)
            if existing is not None:
                session.expunge(existing)
                return existing
            offer = PlanOffer(
                tenant_id=owner_tenant_id,
                plan_id=plan_id,
                service_tenant_id=service_tenant_id,
                status=PlanOfferStatus.ACTIVE.value,
            )
            session.add(offer)
            session.flush()
            record_billing_audit(
                session,
                authorized,
                tenant_id=owner_tenant_id,
                action="billing.plan_offer_created",
                resource_type="billing_plan_offer",
                resource_id=str(offer.id),
                metadata={
                    "plan_id": str(plan_id),
                    "plan_key": plan.key,
                    "service_tenant_id": str(service_tenant_id),
                },
            )
            session.refresh(offer)
            session.expunge(offer)
    except IntegrityError:
        # A concurrent identical offer won the one-active-offer index; this
        # transaction (and its audit entry) rolled back.
        with tenant_session_scope(owner_tenant_id) as session:
            existing = _existing(session)
            if existing is None:
                raise
            session.expunge(existing)
            return existing
    return offer


def revoke_plan_offer(caller: object, owner_tenant_id: uuid.UUID, offer_id: uuid.UUID) -> PlanOffer:
    """Revoke one of the owner's offers (`billing.catalog:manage` on the
    owner). Idempotent; authority-reducing, so allowed on a closed owner."""
    require_billing_caller(caller)
    with tenant_session_scope(owner_tenant_id) as session:
        authorized = authorize_billing(
            caller,
            [(owner_tenant_id, BILLING_CATALOG, "manage")],
            operation="billing.plan_offer.revoke",
            session=session,
        )
        offer = session.execute(
            select(PlanOffer)
            .where(PlanOffer.id == offer_id, PlanOffer.tenant_id == owner_tenant_id)
            .with_for_update()
        ).scalar_one_or_none()
        if offer is None:
            raise PlanOfferNotFoundError(owner_tenant_id, offer_id)
        if offer.status != PlanOfferStatus.REVOKED.value:
            offer.status = PlanOfferStatus.REVOKED.value
            offer.revoked_at = datetime.now(UTC)
            session.flush()
            record_billing_audit(
                session,
                authorized,
                tenant_id=owner_tenant_id,
                action="billing.plan_offer_revoked",
                resource_type="billing_plan_offer",
                resource_id=str(offer.id),
                metadata={
                    "plan_id": str(offer.plan_id),
                    "service_tenant_id": str(offer.service_tenant_id),
                },
            )
            session.refresh(offer)
        session.expunge(offer)
    return offer


def adopt_legacy_plan(
    caller: object,
    plan_id: uuid.UUID,
    *,
    owner_tenant_id: uuid.UUID,
    merchant_account_id: uuid.UUID,
    visibility: PlanVisibility = PlanVisibility.PUBLIC,
) -> Plan:
    """The explicit operator action that gives a legacy (unowned) plan its
    owner and merchant -- the only way one becomes eligible in the catalog.
    Nothing is guessed: the operator names the owner and one of the
    owner's merchant accounts.

    Accepts only `SystemCaller(SystemAuthority.BILLING_OPERATIONS)`: a
    tenant user must never be able to claim a deployment-wide legacy plan
    that other tenants' subscriptions may reference. The plan keeps its
    key and stays in the legacy key namespace, so legacy key-addressed
    callers keep resolving it; its key must not collide with one of the
    owner's own plans (`DuplicateOwnedPlanKeyError`). Audited in the
    owner's tenant, in the adopting transaction."""
    visibility = _validate_visibility(visibility)
    authorized_caller = require_billing_caller(caller)
    operation = "billing.plan.adopt_legacy"
    core_caller = authorized_caller.caller
    if not (
        isinstance(core_caller, SystemCaller) and core_caller.authority is BILLING_SYSTEM_AUTHORITY
    ):
        raise BillingNotAuthorizedError(operation)
    try:
        with tenant_session_scope(owner_tenant_id) as session:
            authorized = authorize_billing(caller, [], operation=operation, session=session)
            lock_open_tenant(session, owner_tenant_id)
            _require_owned_merchant(session, owner_tenant_id, merchant_account_id)
            plan = session.execute(
                select(Plan).where(Plan.id == plan_id).with_for_update()
            ).scalar_one_or_none()
            if plan is None:
                raise LegacyPlanAdoptionError(plan_id, "it does not exist")
            if not plan.legacy or plan.owner_tenant_id is not None:
                raise LegacyPlanAdoptionError(plan_id, "it is not an unadopted legacy plan")
            adopted_key = plan.key
            plan.owner_tenant_id = owner_tenant_id
            plan.merchant_account_id = merchant_account_id
            plan.visibility = visibility.value
            session.flush()
            record_billing_audit(
                session,
                authorized,
                tenant_id=owner_tenant_id,
                action="billing.plan_adopted",
                resource_type="billing_plan",
                resource_id=str(plan.id),
                metadata=_plan_metadata(plan),
            )
            session.refresh(plan)
            session.expunge(plan)
    except IntegrityError as exc:
        if _owner_key_conflict(exc):
            raise DuplicateOwnedPlanKeyError(owner_tenant_id, adopted_key) from None
        raise
    return plan
