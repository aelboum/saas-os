"""`core/webhooks` -- outbound webhook subscription management, signing,
and delivery (docs/IMPLEMENTATION-ROADMAP.md Phase 4.3; docs/ARCHITECTURE.md
section 4: "Outbound webhook subscriptions, delivery, retry").

Owns:
- the tenant-owned `WebhookSubscription` entity (`core.webhook_subscriptions`,
  RLS-protected) -- a destination URL and its HMAC signing secret;
- `subscribe`/`get_subscription`/`list_subscriptions`/`unsubscribe`;
- `compute_signature()`, the low-level HMAC primitive, and
  `compute_signed_envelope()` (P1.10), the actual timestamp-bound signing
  scheme a subscriber's own receiver replicates to verify a delivery;
- `verify_webhook_signature()`/`record_webhook_delivery()`/
  `verify_and_record_webhook_delivery()` (P1.10) -- the inbound
  verification/replay-protection boundary a future receiver would call
  (no HTTP route calls it yet, mirroring
  `core.billing.stripe_provider.verify_stripe_webhook_signature()`'s own
  precedent), plus `purge_expired_replay_records()` for retention;
- the tenant-owned `WebhookReplayRecord` entity (`core.webhook_replay_records`,
  RLS-protected, P1.10) -- the atomic replay-detection ledger;
- `trigger_event()`, the entrypoint that enqueues delivery to every one
  of a tenant's subscriptions;
- `WEBHOOK_JOB_FUNCTIONS`, the registered `infra.jobs` handler a worker
  process registers to actually perform deliveries.

Does NOT own: retry/backoff/dead-letter execution bookkeeping
(`infra/jobs`, reused here, never reimplemented -- docs/DATA-ARCHITECTURE.md
section 5), an inbound webhook HTTP receiver (this module is
outbound-only, per the roadmap's own "(outbound)" qualifier -- P1.10
provides the verification/replay primitives a future receiver would use,
never the receiver itself), event-type filtering per subscription, or
any HTTP/API surface (Phase 8).
"""

from core.webhooks.errors import (
    InvalidWebhookUrlError,
    WebhookConfigurationError,
    WebhookDeliveryError,
    WebhookReplayDetectedError,
    WebhookSignatureInvalidError,
    WebhookSubscriptionNotFoundError,
    WebhookTimestampInvalidError,
)
from core.webhooks.models import WebhookReplayRecord, WebhookSubscription
from core.webhooks.service import (
    WEBHOOK_JOB_FUNCTIONS,
    compute_signature,
    compute_signed_envelope,
    get_subscription,
    list_subscriptions,
    purge_expired_replay_records,
    record_webhook_delivery,
    subscribe,
    trigger_event,
    unsubscribe,
    verify_and_record_webhook_delivery,
    verify_webhook_signature,
)

__all__ = [
    "WebhookSubscription",
    "WebhookReplayRecord",
    "subscribe",
    "get_subscription",
    "list_subscriptions",
    "unsubscribe",
    "compute_signature",
    "compute_signed_envelope",
    "verify_webhook_signature",
    "record_webhook_delivery",
    "verify_and_record_webhook_delivery",
    "purge_expired_replay_records",
    "trigger_event",
    "WEBHOOK_JOB_FUNCTIONS",
    "InvalidWebhookUrlError",
    "WebhookSubscriptionNotFoundError",
    "WebhookDeliveryError",
    "WebhookConfigurationError",
    "WebhookTimestampInvalidError",
    "WebhookSignatureInvalidError",
    "WebhookReplayDetectedError",
]
