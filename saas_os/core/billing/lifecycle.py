"""The subscription lifecycle state machine (Billing Foundation v2 Phase 3
-- lifecycle safety; docs/ADR/0029-commercial-parties-and-billing-
relationships.md, "Implementation status"; docs/ADR/0008-billing-
provider.md, 2026-10-01 amendment points 1-2).

Two independent dimensions describe a `core.billing_subscriptions` row:

**`status` -- the lifecycle** (`SubscriptionStatus`):

    pending   -- the local record and the provider-side object exist, but
                 the provider has not positively confirmed an active
                 subscription (e.g. payment not yet completed). Grants no
                 entitlements.
    active    -- the provider confirmed an active subscription (or, for a
                 legacy row, the pre-Phase-3 claim of one -- see below).
                 The only entitlement-granting status.
    past_due  -- the provider confirmed a payment problem on an otherwise
                 live subscription. Grants no entitlements (fail closed);
                 a grace-period policy is a later phase's decision.
    canceled  -- terminal.

Allowed transitions (`ALLOWED_TRANSITIONS`; a same-state "transition" is
an idempotent no-op):

    pending  -> active | past_due | canceled
    active   -> past_due | canceled
    past_due -> active | canceled
    canceled -> (none; terminal)

Nothing ever moves a subscription *back* to `pending`, and nothing
resurrects a `canceled` one -- reactivation is a later phase's feature,
not a transition here. `set_subscription_status()` is the only code that
assigns `Subscription.status` (pinned by a static test); every caller is a
`saas_os/core/billing` service function, never a consumer -- there is no public
"set status" entry point.

**`verification` -- whether the commercial relationship is verified**
(`VerificationState`):

    verified           -- created by the Phase-3 commercial path, or
                          reconciled: payer, merchant and provider were
                          recorded from authoritative input and the
                          lifecycle status comes from the provider.
    legacy_unverified  -- every row that existed before Phase 3 (including
                          Phase 2 commercial rows, whose `active` was never
                          provider-confirmed) and every row the legacy
                          `subscribe()` path still writes. Its payer/
                          merchant/provider relationship is unverified and
                          its `status` is a legacy claim, not a provider
                          confirmation (ADR-0029, Decision 0.5). Such a row
                          leaves this state only through
                          `saas_os/core/billing/commercial.py::
                          reconcile_legacy_subscription()`.

**Live** (`LIVE_STATUSES`) = `pending`, `active` or `past_due` -- a
subscription that exists at the provider and is not terminal. The
database allows at most one live subscription per `(service tenant,
merchant)` (`uq_billing_subscriptions_one_live_per_merchant`, a partial
unique index); rows with no recorded merchant (legacy rows awaiting
reconciliation) are outside that invariant until reconciled.

**Provider status mapping.** Adapters translate their native state into a
provider-neutral `ProviderSubscriptionState` (`saas_os/core/billing/provider.py`);
`target_status_for()` maps it onto this lifecycle. `not_found` and
`unknown` never map to a status -- an unconfirmable state changes nothing
and is never treated as active (fail closed).
"""

from __future__ import annotations

import enum

from saas_os.core.billing.errors import InvalidSubscriptionTransitionError
from saas_os.core.billing.models import Subscription
from saas_os.core.billing.provider import ProviderSubscriptionState


class SubscriptionStatus(enum.StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"


class VerificationState(enum.StrEnum):
    VERIFIED = "verified"
    LEGACY_UNVERIFIED = "legacy_unverified"


ALLOWED_TRANSITIONS: dict[SubscriptionStatus, frozenset[SubscriptionStatus]] = {
    SubscriptionStatus.PENDING: frozenset(
        {SubscriptionStatus.ACTIVE, SubscriptionStatus.PAST_DUE, SubscriptionStatus.CANCELED}
    ),
    SubscriptionStatus.ACTIVE: frozenset(
        {SubscriptionStatus.PAST_DUE, SubscriptionStatus.CANCELED}
    ),
    SubscriptionStatus.PAST_DUE: frozenset(
        {SubscriptionStatus.ACTIVE, SubscriptionStatus.CANCELED}
    ),
    SubscriptionStatus.CANCELED: frozenset(),
}

LIVE_STATUSES: frozenset[SubscriptionStatus] = frozenset(
    {SubscriptionStatus.PENDING, SubscriptionStatus.ACTIVE, SubscriptionStatus.PAST_DUE}
)

ENTITLEMENT_GRANTING_STATUSES: frozenset[SubscriptionStatus] = frozenset(
    {SubscriptionStatus.ACTIVE}
)

_PROVIDER_TARGETS: dict[ProviderSubscriptionState, SubscriptionStatus] = {
    ProviderSubscriptionState.ACTIVE: SubscriptionStatus.ACTIVE,
    ProviderSubscriptionState.PENDING: SubscriptionStatus.PENDING,
    ProviderSubscriptionState.PAST_DUE: SubscriptionStatus.PAST_DUE,
    ProviderSubscriptionState.CANCELED: SubscriptionStatus.CANCELED,
}


def parse_status(value: str) -> SubscriptionStatus:
    try:
        return SubscriptionStatus(value)
    except ValueError:
        raise InvalidSubscriptionTransitionError(value, value) from None


def is_transition_allowed(current: SubscriptionStatus, target: SubscriptionStatus) -> bool:
    return current == target or target in ALLOWED_TRANSITIONS[current]


def validate_transition(current: str, target: SubscriptionStatus) -> SubscriptionStatus:
    """Return `target` if `current -> target` is allowed (a same-state
    transition is an allowed no-op); raise
    `InvalidSubscriptionTransitionError` otherwise, including for an
    unrecognized stored `current` value."""
    current_status = parse_status(current)
    if not is_transition_allowed(current_status, target):
        raise InvalidSubscriptionTransitionError(current, target.value)
    return target


def set_subscription_status(subscription: Subscription, target: SubscriptionStatus) -> bool:
    """The single place `Subscription.status` is assigned. Validates the
    transition first; returns whether the stored status changed."""
    validate_transition(subscription.status, target)
    if subscription.status == target.value:
        return False
    subscription.status = target.value
    return True


def target_status_for(state: ProviderSubscriptionState) -> SubscriptionStatus | None:
    """The lifecycle status a confirmed provider state maps to, or `None`
    for `not_found`/`unknown` -- states that must never change (and in
    particular never activate) a local subscription."""
    return _PROVIDER_TARGETS.get(state)
