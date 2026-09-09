"""Generic notification dispatch pipeline (docs/IMPLEMENTATION-ROADMAP.md
Phase 4.4).

`dispatch_notification()` enqueues delivery through `infra.jobs`
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.4) exactly the way
`core/webhooks/service.py::trigger_event()` enqueues webhook delivery --
the same "genuinely single-step-retryable" job shape
(`docs/ADR/0007-background-job-and-workflow-engine.md`), reused here
rather than reinvented. `core/notifications` owns the job *handler*
(`_dispatch_notification_job`, registered via `infra.jobs.register_job`
and exported as `NOTIFICATION_JOB_FUNCTIONS` for a worker process to
register); `infra/jobs` owns the generic retry-count/dead-letter
execution metadata (docs/DATA-ARCHITECTURE.md section 5).

Two channels are implemented: `"in_app"` -- a `Notification` row
persisted in `core.notifications` (docs/IMPLEMENTATION-ROADMAP.md Phase
4.4's own Acceptance Criteria: "a sample notification dispatches
correctly through at least one channel end-to-end"), and, since P1.12,
`"email"`, via `core.email.send_email()`. Both still write the same
`Notification` row recording the dispatch attempt's outcome -- `"email"`
needs no schema change and no second persistence path
(`core/notifications/models.py`'s own docstring already anticipated this:
"adding a future channel means adding a new dispatch branch ... plus
that channel's own provider adapter, never a schema migration"). `"sms"`/
`"push"`, the roadmap's other illustrative examples, remain unbuilt.

**P1.12's `"email"` channel**: `dispatch_notification()` gains one new,
optional parameter, `recipient_email` -- required (and validated) only
when `channel="email"`; entirely absent from the enqueued payload for
every other channel, so `"in_app"`'s existing payload shape (and every
test asserting it) is unchanged. The email address itself is never
persisted to `core.notifications` or any other table -- it flows through
the `infra.jobs`/Redis job payload only, transiently, exactly the way
`subject`/`body` free text already does for every channel; this avoids
adding a new place email-address PII lives at rest (this checkpoint's
own "treat recipient addresses as potentially sensitive" requirement).
The actual `From:` address comes from `core.email.config.EmailConfig.default_sender`
(`EMAIL_DEFAULT_SENDER`) -- a deployment-wide setting, not a per-call
parameter, since a transactional sender identity is normally fixed per
platform, not chosen by each caller.

**Known, pre-existing, symmetric limitation carried by both channels
(not new to `"email"`)**: this job has no idempotency of its own (P1.11's
`core.idempotency` is not applied here -- discovery found no business
operation in this repository that currently calls `dispatch_notification()`
with a genuine client-retry-driven duplicate-send risk; P1.11 remains
the correct mechanism to wrap around a *future* real caller if one
arises, not something to bolt onto this job speculatively, this
checkpoint's own "do not blindly apply idempotency everywhere"). If the
side effect (an in-app row insert, or a real outbound email) succeeds but
the job is retried anyway (e.g. the final commit's outcome was
ambiguous), a duplicate is possible -- exactly as already true for
`"in_app"` today, unchanged by this phase.

Dispatch is deliberately **not** audit-logged: a notification dispatch is
a routine, potentially high-volume business event, not a privileged/
security-sensitive action -- the same reasoning that already keeps
`core/webhooks`' routine deliveries (as opposed to subscription lifecycle
changes) out of `core.audit_log` (docs/IMPLEMENTATION-ROADMAP.md Phase
3.4 section 2's standing "no automatic logging of every request"
prohibition). `core/notifications` has no subscription-like lifecycle
event to audit in the first place -- dispatch *is* the only operation
this module performs. P1.12's own operational visibility
(`email_send_started`/`_succeeded`/`_failed`) is a structured *log*, not
an audit event, for the same reason -- see `_dispatch_notification_job`'s
own inline logging.
"""

from __future__ import annotations

import logging
import uuid

from arq.worker import Function

from core.notifications.errors import (
    InvalidNotificationChannelError,
    NotificationDispatchError,
    NotificationNotFoundError,
)
from core.notifications.models import Notification
from infra.db import select, tenant_session_scope
from infra.jobs import TenantJobPayload, enqueue_job, register_job

logger = logging.getLogger(__name__)

_SUPPORTED_CHANNELS = frozenset({"in_app", "email"})
_MAX_SUBJECT_LENGTH = 255


def _validate_channel(channel: str) -> None:
    if channel not in _SUPPORTED_CHANNELS:
        raise InvalidNotificationChannelError(channel)


def _validate_recipient_email(channel: str, recipient_email: str | None) -> None:
    """`recipient_email` is required exactly when `channel="email"` --
    validated eagerly, before enqueueing, mirroring `_validate_channel()`/
    `_validate_subject()`'s own "fail before any job exists" discipline.
    Actual address-shape/injection validation is `core.email.service.
    validate_email_address()`'s job, called again here so a malformed
    address is rejected synchronously at `dispatch_notification()` call
    time, not only later, asynchronously, inside the job handler."""
    if channel != "email":
        return
    if not recipient_email:
        raise ValueError("recipient_email is required when channel='email'.")
    from core.email import validate_email_address
    from core.email.errors import InvalidEmailAddressError

    try:
        validate_email_address(recipient_email)
    except InvalidEmailAddressError as exc:
        raise ValueError(str(exc)) from exc


def _validate_subject(subject: str | None) -> None:
    if subject is not None and len(subject) > _MAX_SUBJECT_LENGTH:
        raise ValueError(f"subject exceeds {_MAX_SUBJECT_LENGTH} characters.")


# --- Dispatch ----------------------------------------------------------


async def dispatch_notification(
    tenant_id: uuid.UUID,
    recipient_user_id: uuid.UUID,
    channel: str,
    body: str,
    *,
    subject: str | None = None,
    recipient_email: str | None = None,
    queue_name: str | None = None,
) -> str:
    """Enqueue dispatch of one notification to `recipient_user_id` within
    `tenant_id`. Returns the arq job ID -- dispatch itself happens
    asynchronously via `infra.jobs`; this function does not block on I/O.

    `(tenant_id, recipient_user_id)` must be a real `TenantMembership` --
    enforced structurally by the composite foreign key in
    `core/notifications/models.py`, not merely by this function
    remembering to check; a pair that is not a genuine membership
    surfaces at dispatch time as `NotificationDispatchError` (raised by
    the job handler, after the composite FK rejects the insert with an
    `IntegrityError`).

    `recipient_email` (P1.12) is required, and validated, only when
    `channel="email"` -- see `_validate_recipient_email()`'s own
    docstring for why, and the module docstring for why it is never
    persisted to `core.notifications` itself.

    `queue_name` is a thin passthrough to `infra.jobs.enqueue_job()`'s own
    parameter of the same name, for test isolation (mirrors
    `core/webhooks/service.py::trigger_event`'s identical parameter).
    """
    _validate_channel(channel)
    _validate_subject(subject)
    _validate_recipient_email(channel, recipient_email)

    data: dict[str, object] = {
        "recipient_user_id": str(recipient_user_id),
        "channel": channel,
        "subject": subject,
        "body": body,
    }
    if channel == "email":
        data["recipient_email"] = recipient_email

    return await enqueue_job(
        _dispatch_notification_job.__name__,
        TenantJobPayload(tenant_id=str(tenant_id), data=data),
        queue_name=queue_name,
    )


def _send_email_channel(
    recipient_user_id: uuid.UUID, subject: str | None, body: str, recipient_email: str
) -> None:
    """The `"email"` channel's own delivery step (P1.12) -- called from
    `_dispatch_notification_job()` before the `Notification` row is
    persisted (module docstring: never claim a status this job cannot
    yet back up). Raises `NotificationDispatchError` on any failure --
    configuration, validation, or provider -- so `infra.jobs`' own
    retry/dead-letter wrapper handles it exactly like every other
    dispatch failure, never a second retry mechanism.
    """
    from core.email import EmailMessage, get_email_config, send_email
    from core.email.errors import (
        EmailConfigurationError,
        EmailProviderError,
        InvalidEmailAddressError,
    )

    logger.info(
        "email_send_started",
        extra={"notification_channel": "email"},
    )
    try:
        config = get_email_config()
        if not config.default_sender:
            raise EmailConfigurationError("EMAIL_DEFAULT_SENDER is not set.")
        message = EmailMessage(
            sender=config.default_sender,
            to=(recipient_email,),
            subject=subject or "",
            text_body=body,
        )
        send_email(message)
    except (EmailConfigurationError, EmailProviderError, InvalidEmailAddressError) as exc:
        # Never the recipient address, the body, or a secret -- only the
        # failure's own type name (this checkpoint's own logging
        # requirement: no email body, no full recipient list).
        logger.warning("email_send_failed", extra={"failure_category": type(exc).__name__})
        raise NotificationDispatchError(recipient_user_id, type(exc).__name__) from exc
    else:
        logger.info("email_send_succeeded", extra={"notification_channel": "email"})


async def _dispatch_notification_job(payload: TenantJobPayload | None) -> None:
    """The registered job handler. `"in_app"` inserts a `Notification`
    row directly; `"email"` (P1.12) sends through `core.email` first,
    then records the same kind of `Notification` row -- both channels
    end in the identical persisted-outcome shape (module docstring).
    Raises `NotificationDispatchError` on failure so `infra.jobs`' own
    wrapper (`register_job`) retries with backoff, then dead-letters on
    exhaustion -- this function never implements retry/backoff itself.
    """
    if payload is None:
        raise ValueError("_dispatch_notification_job requires a TenantJobPayload, got None.")

    tenant_id = uuid.UUID(payload.tenant_id)
    recipient_user_id = uuid.UUID(payload.data["recipient_user_id"])
    channel = payload.data["channel"]
    subject = payload.data["subject"]
    body = payload.data["body"]

    if channel == "email":
        recipient_email = payload.data["recipient_email"]
        _send_email_channel(recipient_user_id, subject, body, recipient_email)
    elif channel != "in_app":
        # Defense in depth: dispatch_notification() already validated the
        # channel before enqueueing; a job somehow enqueued with an
        # unsupported channel is a caller error, not a transient failure
        # worth retrying indefinitely -- still dead-letters eventually via
        # infra.jobs' own retry-then-dead-letter policy.
        raise NotificationDispatchError(recipient_user_id, f"unsupported channel {channel!r}")

    try:
        with tenant_session_scope(tenant_id) as session:
            notification = Notification(
                tenant_id=tenant_id,
                recipient_user_id=recipient_user_id,
                channel=channel,
                subject=subject,
                body=body,
                status="sent",
            )
            session.add(notification)
            session.flush()
    except Exception as exc:
        raise NotificationDispatchError(recipient_user_id, type(exc).__name__) from exc


NOTIFICATION_JOB_FUNCTIONS: list[Function] = [register_job(_dispatch_notification_job)]


# --- Reads ---------------------------------------------------------------


def get_notification(tenant_id: uuid.UUID, notification_id: uuid.UUID) -> Notification:
    with tenant_session_scope(tenant_id) as session:
        notification = session.get(Notification, notification_id)
        if notification is None or notification.tenant_id != tenant_id:
            raise NotificationNotFoundError(tenant_id, notification_id)
        session.expunge(notification)
        return notification


def list_notifications(tenant_id: uuid.UUID, recipient_user_id: uuid.UUID) -> list[Notification]:
    with tenant_session_scope(tenant_id) as session:
        notifications = (
            session.execute(
                select(Notification).where(
                    Notification.tenant_id == tenant_id,
                    Notification.recipient_user_id == recipient_user_id,
                )
            )
            .scalars()
            .all()
        )
        for notification in notifications:
            session.expunge(notification)
        return list(notifications)
