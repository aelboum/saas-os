"""Typed errors for `saas_os/core/notifications` (docs/IMPLEMENTATION-ROADMAP.md
Phase 4.4). Every error here carries only identifying metadata -- never
a notification's own subject/body content, which could carry sensitive
tenant data.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from saas_os.core.outbox.errors import (
    AmbiguousOutcomeError,
    ConfirmedNotSentError,
    PermanentEventError,
    RetryAfterEventError,
)


class InvalidNotificationChannelError(ValueError):
    def __init__(self, channel: str) -> None:
        self.channel = channel
        super().__init__(f"Unsupported notification channel: {channel!r}.")


class NotificationNotFoundError(LookupError):
    """Raised when a notification id does not resolve within the given
    tenant -- deliberately the same error whether the notification truly
    doesn't exist or belongs to a different tenant, so this lookup itself
    never confirms or denies another tenant's data (docs/SECURITY.md
    section 5), mirroring `saas_os/core/webhooks`'s `WebhookSubscriptionNotFoundError`."""

    def __init__(self, tenant_id: uuid.UUID, notification_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.notification_id = notification_id
        super().__init__(f"Notification {notification_id} not found in tenant {tenant_id}.")


class NotificationDispatchError(RuntimeError):
    """Raised by the dispatch job handler when a channel provider fails
    to deliver -- caught by `saas_os.infra.jobs`' own retry/dead-letter wrapper,
    never by this module. Identifies the failed attempt by
    `recipient_user_id` (no `Notification` row necessarily exists yet --
    dispatch may have failed before or during the insert) -- never the
    subject/body content."""

    def __init__(self, recipient_user_id: uuid.UUID, reason: str) -> None:
        self.recipient_user_id = recipient_user_id
        super().__init__(f"Notification dispatch to recipient {recipient_user_id} failed: {reason}")


class NotificationPermanentDispatchError(NotificationDispatchError, PermanentEventError):
    """A dispatch failure that retrying the same event cannot fix -- the
    email provider permanently refused the message
    (`saas_os.core.email.errors.EmailProviderError.permanent`, ADR-0057). The
    outbox dispatcher dead-letters the event at once instead of spending its
    remaining attempts (`saas_os.core.outbox.errors.PermanentEventError`); every
    other dispatch failure stays transient and keeps the existing retry
    policy."""


class NotificationDeferredDispatchError(NotificationDispatchError, RetryAfterEventError):
    """A transient dispatch failure for which the email provider asked to be
    retried later (`saas_os.core.email.errors.EmailProviderError.retry_after_seconds`:
    a rate limit's `Retry-After`, or a quota). The outbox dispatcher delays
    the next attempt accordingly, within its bound, and still counts the
    attempt (`saas_os.core.outbox.errors.RetryAfterEventError`)."""

    def __init__(
        self, recipient_user_id: uuid.UUID, reason: str, retry_after_seconds: float
    ) -> None:
        NotificationDispatchError.__init__(self, recipient_user_id, reason)
        self.retry_after_seconds = retry_after_seconds


class NotificationAmbiguousDispatchError(NotificationDispatchError, AmbiguousOutcomeError):
    """The email provider may already have accepted the message, and its
    outcome is unknown (`saas_os.core.email.errors.EmailOutcomeUnknownError`,
    owner decision of 2026-11-01). The outbox dispatcher dead-letters the
    event at once -- an SMTP send has no de-duplication -- unless the provider
    declared an idempotency window (`retry_within`: Resend, with a key), in
    which case the event is retried within it under the same key
    (`saas_os.core.outbox.errors.AmbiguousOutcomeError`)."""

    def __init__(
        self,
        recipient_user_id: uuid.UUID,
        reason: str,
        *,
        phase: str,
        retry_within: timedelta | None = None,
    ) -> None:
        AmbiguousOutcomeError.__init__(self, reason, phase=phase, retry_within=retry_within)
        NotificationDispatchError.__init__(self, recipient_user_id, reason)


class NotificationNotSentDispatchError(NotificationDispatchError, ConfirmedNotSentError):
    """The e-mail was provably not handed to the provider: its transport
    failed before sending (`saas_os.core.email.errors.EmailNotSentError`), or
    the send never started (missing configuration, an invalid address).
    Transient: the outbox retries it with the ordinary backoff, and states
    explicitly that a retry cannot deliver it twice (owner decision D of
    2026-11-01, `ConfirmedNotSentError`)."""
