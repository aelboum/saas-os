"""Commercial parties: `MerchantAccount` (the payee) and `BillingAccount`
(the payer) -- Billing Foundation v2 Phase 2;
docs/ADR/0029-commercial-parties-and-billing-relationships.md.

**Ownership and RLS.** A merchant account is owned by, and RLS-scoped to,
its payee tenant; a billing account by, and to, its payer tenant. Every
read/write here goes through `infra.db.tenant_session_scope()` for the
owning tenant -- never the untenanted `session_scope()`. The one
cross-tenant read is bounded and explicit: creating a billing account
reads the merchant account under the *merchant's* tenant scope, given
the caller-supplied `(merchant_tenant_id, merchant_account_id)` pair, and
the composite foreign key `fk_billing_accounts_merchant_account`
guarantees at the database level that the recorded payee tenant really
owns that merchant.

**No merchant type.** A merchant is `owner tenant + provider +
provider_account_ref + status`. "Platform merchant" is not a kind of
merchant -- it is any merchant owned by the platform tenant
(`core.tenancy.get_platform_tenant_id()`). Provider-specific merchant
concepts (connected accounts and the like) stay inside the provider
adapter; `provider_account_ref` is only their opaque identifier.

**Authorization.** Mutations take an explicit `BillingCaller`
(`core/billing/authorization.py`) and require:

    create_merchant_account / set_merchant_account_status
        billing.merchant:manage   on the merchant's owner (payee) tenant
    get_or_create_billing_account
        billing.account:manage    on the payer tenant

Plain getters/listers take no caller and perform no authorization, the
same in-process convention as `core/billing/service.py::get_subscription()`:
a consumer exposing them authorizes first (`billing.merchant:manage`,
`billing.account:read`). RLS still confines every read to the named
owner tenant.

**`inherits_billing` is never consulted here.** Payer and payee are
always the tenants explicitly named; nothing is inferred from the tenant
hierarchy (ADR-0029, "`inherits_billing` (legacy, frozen)").
"""

from __future__ import annotations

import enum
import uuid

from core.audit_log import AuditOutcome
from core.audit_log import record as record_audit_event
from core.billing.authorization import (
    BILLING_ACCOUNT,
    BILLING_MERCHANT,
    audit_actor,
    authorize_billing,
)
from core.billing.errors import (
    BillingAccountNotFoundError,
    CommercialPartyNotActiveError,
    DuplicateMerchantAccountError,
    InvalidBillingPartyError,
    MerchantAccountNotFoundError,
)
from core.billing.models import BillingAccount, MerchantAccount
from core.tenancy import require_open_tenant
from infra.db import IntegrityError, select, tenant_session_scope

_MAX_PROVIDER_LENGTH = 50
_MAX_REF_LENGTH = 255


class MerchantAccountStatus(enum.StrEnum):
    """`onboarding` -- created, not yet able to receive payment;
    `active` -- may be charged through; `restricted` -- temporarily unable
    to receive payment (e.g. a provider-side hold); `disabled` -- retired.
    Only `active` merchants may be charged through."""

    ONBOARDING = "onboarding"
    ACTIVE = "active"
    RESTRICTED = "restricted"
    DISABLED = "disabled"


class BillingAccountStatus(enum.StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


def _validate_text(value: object, *, field: str, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidBillingPartyError(f"{field} must be a non-empty string.")
    if len(value) > max_length:
        raise InvalidBillingPartyError(f"{field} exceeds {max_length} characters.")
    return value


def _validate_merchant_status(status: object) -> MerchantAccountStatus:
    try:
        return MerchantAccountStatus(status)
    except ValueError:
        raise InvalidBillingPartyError(f"Unknown merchant account status {status!r}.") from None


# --- MerchantAccount (payee) -----------------------------------------------


def create_merchant_account(
    caller: object,
    owner_tenant_id: uuid.UUID,
    *,
    provider: str,
    provider_account_ref: str,
    status: MerchantAccountStatus = MerchantAccountStatus.ONBOARDING,
) -> MerchantAccount:
    """Create `owner_tenant_id`'s merchant account at `provider`.
    `(provider, provider_account_ref)` is unique deployment-wide
    (`DuplicateMerchantAccountError`, never naming the existing owner)."""
    provider = _validate_text(provider, field="provider", max_length=_MAX_PROVIDER_LENGTH)
    provider_account_ref = _validate_text(
        provider_account_ref, field="provider_account_ref", max_length=_MAX_REF_LENGTH
    )
    status = _validate_merchant_status(status)
    validated = authorize_billing(
        caller,
        [(owner_tenant_id, BILLING_MERCHANT, "manage")],
        operation="billing.merchant_account.create",
    )
    require_open_tenant(owner_tenant_id)

    try:
        with tenant_session_scope(owner_tenant_id) as session:
            merchant = MerchantAccount(
                tenant_id=owner_tenant_id,
                provider=provider,
                provider_account_ref=provider_account_ref,
                status=status.value,
            )
            session.add(merchant)
            session.flush()
            session.refresh(merchant)
            session.expunge(merchant)
    except IntegrityError as exc:
        raise DuplicateMerchantAccountError(provider) from exc

    actor_type, actor_user_id, extra = audit_actor(validated)
    record_audit_event(
        tenant_id=owner_tenant_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action="billing.merchant_account_created",
        resource_type="billing_merchant_account",
        resource_id=str(merchant.id),
        outcome=AuditOutcome.SUCCESS,
        metadata={"provider": provider, "status": status.value, **extra},
    )
    return merchant


def set_merchant_account_status(
    caller: object,
    owner_tenant_id: uuid.UUID,
    merchant_account_id: uuid.UUID,
    status: MerchantAccountStatus,
) -> MerchantAccount:
    """Change a merchant account's status. Moving to `active` is
    authority-expanding and requires an open owner tenant; any other
    transition only reduces what the merchant can do and is permitted on
    a closed tenant too, so a closed tenant can still be wound down."""
    status = _validate_merchant_status(status)
    validated = authorize_billing(
        caller,
        [(owner_tenant_id, BILLING_MERCHANT, "manage")],
        operation="billing.merchant_account.set_status",
    )
    if status is MerchantAccountStatus.ACTIVE:
        require_open_tenant(owner_tenant_id)

    with tenant_session_scope(owner_tenant_id) as session:
        merchant = session.get(MerchantAccount, merchant_account_id)
        if merchant is None or merchant.tenant_id != owner_tenant_id:
            raise MerchantAccountNotFoundError(owner_tenant_id, merchant_account_id)
        old_status = merchant.status
        merchant.status = status.value
        session.flush()
        session.refresh(merchant)
        session.expunge(merchant)

    actor_type, actor_user_id, extra = audit_actor(validated)
    record_audit_event(
        tenant_id=owner_tenant_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action="billing.merchant_account_status_changed",
        resource_type="billing_merchant_account",
        resource_id=str(merchant_account_id),
        outcome=AuditOutcome.SUCCESS,
        metadata={"old_status": old_status, "new_status": status.value, **extra},
    )
    return merchant


def get_merchant_account(
    owner_tenant_id: uuid.UUID, merchant_account_id: uuid.UUID
) -> MerchantAccount:
    with tenant_session_scope(owner_tenant_id) as session:
        merchant = session.get(MerchantAccount, merchant_account_id)
        if merchant is None or merchant.tenant_id != owner_tenant_id:
            raise MerchantAccountNotFoundError(owner_tenant_id, merchant_account_id)
        session.expunge(merchant)
        return merchant


def list_merchant_accounts(owner_tenant_id: uuid.UUID) -> list[MerchantAccount]:
    with tenant_session_scope(owner_tenant_id) as session:
        merchants = (
            session.execute(
                select(MerchantAccount).where(MerchantAccount.tenant_id == owner_tenant_id)
            )
            .scalars()
            .all()
        )
        for merchant in merchants:
            session.expunge(merchant)
        return list(merchants)


def require_active_merchant_account(merchant: MerchantAccount) -> MerchantAccount:
    if merchant.status != MerchantAccountStatus.ACTIVE.value:
        raise CommercialPartyNotActiveError("Merchant account", merchant.id, merchant.status)
    return merchant


# --- BillingAccount (payer) ------------------------------------------------


def get_or_create_billing_account(
    caller: object,
    payer_tenant_id: uuid.UUID,
    *,
    merchant_tenant_id: uuid.UUID,
    merchant_account_id: uuid.UUID,
) -> tuple[BillingAccount, bool]:
    """Return `payer_tenant_id`'s billing account at the given merchant,
    creating it if none exists -- one account per (payer, merchant),
    enforced by `uq_billing_accounts_tenant_merchant`. Returns
    `(account, created)`. The merchant must exist under
    `merchant_tenant_id` and be `active`. `provider_customer_ref` is left
    NULL: no provider customer is created or invented here."""
    validated = authorize_billing(
        caller,
        [(payer_tenant_id, BILLING_ACCOUNT, "manage")],
        operation="billing.account.create",
    )
    require_open_tenant(payer_tenant_id)
    merchant = require_active_merchant_account(
        get_merchant_account(merchant_tenant_id, merchant_account_id)
    )

    existing = _find_billing_account(payer_tenant_id, merchant.id)
    if existing is not None:
        return existing, False

    try:
        with tenant_session_scope(payer_tenant_id) as session:
            account = BillingAccount(
                tenant_id=payer_tenant_id,
                merchant_tenant_id=merchant.tenant_id,
                merchant_account_id=merchant.id,
                provider_customer_ref=None,
                status=BillingAccountStatus.ACTIVE.value,
            )
            session.add(account)
            session.flush()
            session.refresh(account)
            session.expunge(account)
    except IntegrityError:
        # Lost a race to a concurrent creation for the same (payer,
        # merchant) -- the other caller's row is canonical.
        existing = _find_billing_account(payer_tenant_id, merchant.id)
        if existing is None:
            raise
        return existing, False

    actor_type, actor_user_id, extra = audit_actor(validated)
    record_audit_event(
        tenant_id=payer_tenant_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action="billing.account_created",
        resource_type="billing_account",
        resource_id=str(account.id),
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "merchant_account_id": str(merchant.id),
            "merchant_tenant_id": str(merchant.tenant_id),
            **extra,
        },
    )
    return account, True


def _find_billing_account(
    payer_tenant_id: uuid.UUID, merchant_account_id: uuid.UUID
) -> BillingAccount | None:
    with tenant_session_scope(payer_tenant_id) as session:
        account = session.execute(
            select(BillingAccount).where(
                BillingAccount.tenant_id == payer_tenant_id,
                BillingAccount.merchant_account_id == merchant_account_id,
            )
        ).scalar_one_or_none()
        if account is not None:
            session.expunge(account)
        return account


def get_billing_account(
    payer_tenant_id: uuid.UUID, billing_account_id: uuid.UUID
) -> BillingAccount:
    with tenant_session_scope(payer_tenant_id) as session:
        account = session.get(BillingAccount, billing_account_id)
        if account is None or account.tenant_id != payer_tenant_id:
            raise BillingAccountNotFoundError(payer_tenant_id, billing_account_id)
        session.expunge(account)
        return account


def list_billing_accounts(payer_tenant_id: uuid.UUID) -> list[BillingAccount]:
    with tenant_session_scope(payer_tenant_id) as session:
        accounts = (
            session.execute(
                select(BillingAccount).where(BillingAccount.tenant_id == payer_tenant_id)
            )
            .scalars()
            .all()
        )
        for account in accounts:
            session.expunge(account)
        return list(accounts)


def require_active_billing_account(account: BillingAccount) -> BillingAccount:
    if account.status != BillingAccountStatus.ACTIVE.value:
        raise CommercialPartyNotActiveError("Billing account", account.id, account.status)
    return account
