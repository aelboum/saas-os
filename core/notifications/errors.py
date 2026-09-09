"""Typed errors for `core/notifications` (docs/IMPLEMENTATION-ROADMAP.md
Phase 4.4). Every error here carries only identifying metadata -- never
a notification's own subject/body content, which could carry sensitive
tenant data.
"""

from __future__ import annotations

import uuid


class InvalidNotificationChannelError(ValueError):
    def __init__(self, channel: str) -> None:
        self.channel = channel
        super().__init__(f"Unsupported notification channel: {channel!r}.")


class NotificationNotFoundError(LookupError):
    """Raised when a notification id does not resolve within the given
    tenant -- deliberately the same error whether the notification truly
    doesn't exist or belongs to a different tenant, so this lookup itself
    never confirms or denies another tenant's data (docs/SECURITY.md
    section 5), mirroring `core/webhooks`'s `WebhookSubscriptionNotFoundError`."""

    def __init__(self, tenant_id: uuid.UUID, notification_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.notification_id = notification_id
        super().__init__(f"Notification {notification_id} not found in tenant {tenant_id}.")


class NotificationDispatchError(RuntimeError):
    """Raised by the dispatch job handler when a channel provider fails
    to deliver -- caught by `infra.jobs`' own retry/dead-letter wrapper,
    never by this module. Identifies the failed attempt by
    `recipient_user_id` (no `Notification` row necessarily exists yet --
    dispatch may have failed before or during the insert) -- never the
    subject/body content."""

    def __init__(self, recipient_user_id: uuid.UUID, reason: str) -> None:
        self.recipient_user_id = recipient_user_id
        super().__init__(f"Notification dispatch to recipient {recipient_user_id} failed: {reason}")
