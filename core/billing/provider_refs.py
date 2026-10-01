"""The global-by-design provider-reference index (Billing Foundation v2
Phase 2; docs/ADR/0022-tenant-session-boundary-enforcement.md, 2026-10-01
amendment; docs/ADR/0029-commercial-parties-and-billing-relationships.md).

`core.billing_provider_refs` maps an opaque provider object reference --
`(provider, provider_account_ref, object_type, provider_object_ref)` -- to
the tenant and local row that own it. It is deliberately NOT RLS-scoped:
a provider callback or reconciliation pass names only provider objects,
so the owning tenant cannot be known until this index is consulted, and
an untenanted query against an RLS-protected FORCE-enabled table returns
zero rows. That makes this module's two functions the only billing code
allowed to use the untenanted `infra.db.session_scope()` against this
table; both are allowlisted in
`tests/architecture/test_tenant_session_boundary.py` with that
justification.

**Bounded by construction.** The index holds references only (never
payment data, never a secret, never a provider SDK object), and resolving
a reference yields only `(tenant_id, local_object_type, local_object_id)`.
The local row itself is then read under `tenant_session_scope(tenant_id)`
for the resolved tenant (`core/billing/commercial.py::
get_subscription_by_provider_ref()`), so RLS still governs every tenant-
owned read. Provider-side metadata (e.g. a `tenant_id` an adapter writes
onto a provider customer) is never used to resolve a tenant
(docs/ADR/0008-... amendment, point 9).

**Uniqueness is the conflict detector.** A provider reference maps to
exactly one local object; registering the identical mapping again is a
no-op, registering it to a different tenant or local row raises
`ProviderRefConflictError` -- a provider reference can never be silently
re-pointed at another tenant.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass

from core.billing.errors import (
    InvalidBillingPartyError,
    ProviderRefConflictError,
    ProviderRefNotFoundError,
)
from core.billing.models import ProviderRef
from infra.db import IntegrityError, select, session_scope

_MAX_SHORT = 50
_MAX_REF = 255


class ProviderObjectType(enum.StrEnum):
    """Provider-neutral kinds of provider object this index maps."""

    SUBSCRIPTION = "subscription"
    CUSTOMER = "customer"


class LocalObjectType(enum.StrEnum):
    """Local row kinds a provider object may map to."""

    BILLING_SUBSCRIPTION = "billing_subscription"
    BILLING_ACCOUNT = "billing_account"


@dataclass(frozen=True)
class ProviderRefResolution:
    tenant_id: uuid.UUID
    local_object_type: LocalObjectType
    local_object_id: uuid.UUID


def _validate(value: object, field: str, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidBillingPartyError(f"{field} must be a non-empty string.")
    if len(value) > max_length:
        raise InvalidBillingPartyError(f"{field} exceeds {max_length} characters.")
    return value


def _lookup(
    provider: str,
    provider_account_ref: str,
    object_type: ProviderObjectType,
    provider_object_ref: str,
) -> ProviderRef | None:
    with session_scope() as session:
        ref = session.execute(
            select(ProviderRef).where(
                ProviderRef.provider == provider,
                ProviderRef.provider_account_ref == provider_account_ref,
                ProviderRef.object_type == object_type.value,
                ProviderRef.provider_object_ref == provider_object_ref,
            )
        ).scalar_one_or_none()
        if ref is not None:
            session.expunge(ref)
        return ref


def register_provider_ref(
    *,
    provider: str,
    provider_account_ref: str,
    object_type: ProviderObjectType,
    provider_object_ref: str,
    tenant_id: uuid.UUID,
    local_object_type: LocalObjectType,
    local_object_id: uuid.UUID,
) -> ProviderRefResolution:
    """Record that a provider object belongs to `(tenant_id,
    local_object_type, local_object_id)`. Idempotent for the identical
    mapping; any different mapping of the same provider reference raises
    `ProviderRefConflictError`."""
    provider = _validate(provider, "provider", _MAX_SHORT)
    provider_account_ref = _validate(provider_account_ref, "provider_account_ref", _MAX_REF)
    provider_object_ref = _validate(provider_object_ref, "provider_object_ref", _MAX_REF)
    object_type = ProviderObjectType(object_type)
    local_object_type = LocalObjectType(local_object_type)
    wanted = ProviderRefResolution(tenant_id, local_object_type, local_object_id)

    try:
        with session_scope() as session:
            session.add(
                ProviderRef(
                    provider=provider,
                    provider_account_ref=provider_account_ref,
                    object_type=object_type.value,
                    provider_object_ref=provider_object_ref,
                    tenant_id=tenant_id,
                    local_object_type=local_object_type.value,
                    local_object_id=local_object_id,
                )
            )
            session.flush()
    except IntegrityError:
        existing = _lookup(provider, provider_account_ref, object_type, provider_object_ref)
        if existing is not None and _resolution(existing) == wanted:
            return wanted
        raise ProviderRefConflictError(provider, object_type.value) from None
    return wanted


def resolve_provider_ref(
    *,
    provider: str,
    provider_account_ref: str,
    object_type: ProviderObjectType,
    provider_object_ref: str,
) -> ProviderRefResolution:
    """Deterministic lookup: the one local object a provider reference is
    mapped to, or `ProviderRefNotFoundError`."""
    ref = _lookup(
        provider, provider_account_ref, ProviderObjectType(object_type), provider_object_ref
    )
    if ref is None:
        raise ProviderRefNotFoundError(provider, ProviderObjectType(object_type).value)
    return _resolution(ref)


def _resolution(ref: ProviderRef) -> ProviderRefResolution:
    return ProviderRefResolution(
        tenant_id=ref.tenant_id,
        local_object_type=LocalObjectType(ref.local_object_type),
        local_object_id=ref.local_object_id,
    )
