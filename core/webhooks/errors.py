"""Typed errors for `core/webhooks` (docs/IMPLEMENTATION-ROADMAP.md
Phase 4.3). Every error here carries only identifying metadata -- never
the signing secret, never a delivery payload's contents.
"""

from __future__ import annotations

import uuid


class WebhookConfigurationError(ValueError):
    """P1.10: raised when a `core/webhooks` environment variable
    (currently only `WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS`) holds an
    invalid value. Never carries a secret -- the tolerance window is a
    plain non-secret tunable."""


class InvalidWebhookUrlError(ValueError):
    """Raised when a subscription's `url` is not a well-formed `http(s)`
    URL -- rejects `file://`/`javascript:`/scheme-less values outright,
    the minimum sane input validation for a destination this module will
    later make outbound HTTP requests to."""

    def __init__(self, url: str) -> None:
        super().__init__(f"Invalid webhook URL: {url!r} (must be http:// or https://).")


class WebhookSubscriptionNotFoundError(LookupError):
    """Raised when a subscription id does not resolve within the given
    tenant -- deliberately the same error whether the subscription truly
    doesn't exist or belongs to a different tenant, so this lookup itself
    never confirms or denies another tenant's data (docs/SECURITY.md
    section 5), mirroring `core/api_keys`'s `ApiKeyNotFoundError`."""

    def __init__(self, tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        super().__init__(f"Webhook subscription {subscription_id} not found in tenant {tenant_id}.")


class WebhookDeliveryError(RuntimeError):
    """Raised by the delivery job handler when an attempt fails (network
    error or a non-2xx response) -- caught by `infra.jobs`' own retry/
    dead-letter wrapper (`core/webhooks/service.py::register_job`'s
    caller), never by this module. Carries the subscription id and a
    short reason only -- never the signing secret, the response body, or
    the event payload, any of which could carry sensitive data."""

    def __init__(self, subscription_id: uuid.UUID, reason: str) -> None:
        self.subscription_id = subscription_id
        super().__init__(f"Webhook delivery to subscription {subscription_id} failed: {reason}")


class WebhookTimestampInvalidError(ValueError):
    """P1.10: raised when a delivery's timestamp is missing, malformed,
    or falls outside the configured freshness tolerance (too old --
    a possible replay of a captured old delivery -- or too far in the
    future). One fixed, generic message regardless of which of those
    three reasons applies (mirrors `api/errors.py`'s own
    non-enumeration convention) -- never includes the received
    timestamp value or the configured tolerance, neither of which an
    unauthenticated-at-this-point caller needs to calibrate a forged
    one against."""

    def __init__(self) -> None:
        super().__init__("Webhook timestamp is invalid or outside the allowed tolerance window.")


class WebhookSignatureInvalidError(ValueError):
    """P1.10: raised when a delivery's signature does not verify against
    the expected HMAC (computed over the timestamp+payload envelope,
    `core/webhooks/service.py::compute_signed_envelope()`). Never
    includes the expected or received signature value, the signing
    secret, or any other comparison detail."""

    def __init__(self) -> None:
        super().__init__("Webhook signature verification failed.")


class WebhookReplayDetectedError(RuntimeError):
    """P1.10: raised when `(tenant_id, subscription_id, event_id)` has
    already been recorded as accepted -- a genuine malicious replay, or
    an accidental duplicate delivery attempt, of an event already
    processed. Carries only identifying metadata (ids), never the
    payload or signature -- mirrors `WebhookSubscriptionNotFoundError`'s
    own minimal-disclosure convention."""

    def __init__(
        self, tenant_id: uuid.UUID, subscription_id: uuid.UUID, event_id: uuid.UUID
    ) -> None:
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.event_id = event_id
        super().__init__(
            f"Webhook event {event_id} for subscription {subscription_id} in tenant "
            f"{tenant_id} has already been recorded (replay detected)."
        )
