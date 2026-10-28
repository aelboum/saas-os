"""Redaction of webhook destination errors stored before pull request #110
(ledger row 900).

Until then `InvalidWebhookUrlError` and its delivery-time subclasses
`WebhookDestinationRejectedError` and `WebhookDestinationUnresolvedError`
carried the full destination URL in their message (`Invalid webhook URL:
'<url>' (must be http:// or https://).`), so a failed delivery stored the URL,
with any credential or token in its user info, path or query, in the outbox
event's `last_error` and in the Redis dead-letter list. The fix stopped new
copies; this removes the ones already stored.

Only that exact message shape is matched (`<type>: Invalid webhook URL: `),
which no current message has. Each match keeps its error type and gets a
fixed text; nothing else about an event or an entry changes (status,
attempts, schedule, tenant, function name). Running it again finds nothing.
`saas-os-operator redact-webhook-errors` runs it, counting only unless
`--apply` is given.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from saas_os.core.outbox import rewrite_stored_errors
from saas_os.infra.jobs.config import JobsConfig, get_jobs_config
from saas_os.infra.jobs.dead_letter import rewrite_dead_letter_errors

logger = logging.getLogger(__name__)

_LEGACY_TYPES = (
    "WebhookDestinationRejectedError",
    "WebhookDestinationUnresolvedError",
    "InvalidWebhookUrlError",
)

REDACTED_MESSAGE = (
    "Invalid webhook URL (redacted: the stored message contained the destination URL)."
)

LEGACY_REPLACEMENTS: dict[str, str] = {
    f"{name}: Invalid webhook URL: ": f"{name}: {REDACTED_MESSAGE}" for name in _LEGACY_TYPES
}


@dataclass(frozen=True)
class StoredWebhookErrorRedaction:
    applied: bool
    outbox_events: int
    dead_letter_entries: int


async def redact_stored_webhook_url_errors(
    *, apply: bool, config: JobsConfig | None = None
) -> StoredWebhookErrorRedaction:
    """Count, and with `apply=True` rewrite, every stored webhook error that
    still carries a destination URL: outbox `last_error` values in every
    tenant, then the Redis dead-letter list. Returns the counts, never a
    stored text."""
    from saas_os.infra.jobs.queue import get_redis_pool

    outbox_events = rewrite_stored_errors(LEGACY_REPLACEMENTS, apply=apply)
    cfg = config or get_jobs_config()
    pool = await get_redis_pool(cfg)
    try:
        dead_letter_entries = await rewrite_dead_letter_errors(
            pool, cfg, LEGACY_REPLACEMENTS, apply=apply
        )
    finally:
        await pool.aclose()
    result = StoredWebhookErrorRedaction(
        applied=apply, outbox_events=outbox_events, dead_letter_entries=dead_letter_entries
    )
    logger.info(
        "webhook_stored_errors_redaction",
        extra={
            "redaction_applied": apply,
            "outbox_events_matched": outbox_events,
            "dead_letter_entries_matched": dead_letter_entries,
        },
    )
    return result
