"""Generic notification dispatch pipeline (docs/IMPLEMENTATION-ROADMAP.md
Phase 4.4).

`dispatch_notification()` records a `saas_os.core.outbox` event in the caller's own
transaction (RE-1, transactional outbox); delivery then runs through
`saas_os.infra.jobs` (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4) once the dispatcher
(RE-2) publishes it, exactly the way `saas_os/core/webhooks/service.py::
trigger_event()` records webhook delivery --
the same "genuinely single-step-retryable" job shape
(`docs/ADR/0007-background-job-and-workflow-engine.md`), reused here
rather than reinvented. `saas_os/core/notifications` owns the job *handler*
(`_dispatch_notification_job`, registered via `saas_os.infra.jobs.register_tenant_job`
and exported as `NOTIFICATION_JOB_FUNCTIONS` for a worker process to
register); `saas_os/infra/jobs` owns the generic retry-count/dead-letter
execution metadata (docs/DATA-ARCHITECTURE.md section 5).

Two channels are implemented: `"in_app"` -- a `Notification` row
persisted in `saas_os.core.notifications` (docs/IMPLEMENTATION-ROADMAP.md Phase
4.4's own Acceptance Criteria: "a sample notification dispatches
correctly through at least one channel end-to-end"), and, since P1.12,
`"email"`, via `saas_os.core.email.send_email()`. Both still write the same
`Notification` row recording the dispatch attempt's outcome -- `"email"`
needs no schema change and no second persistence path
(`saas_os/core/notifications/models.py`'s own docstring already anticipated this:
"adding a future channel means adding a new dispatch branch ... plus
that channel's own provider adapter, never a schema migration"). `"sms"`/
`"push"`, the roadmap's other illustrative examples, remain unbuilt.

**P1.12's `"email"` channel**: `dispatch_notification()` gains one new,
optional parameter, `recipient_email` -- required (and validated) only
when `channel="email"`; entirely absent from the event payload for
every other channel, so `"in_app"`'s existing payload shape (and every
test asserting it) is unchanged. The email address itself is never
persisted in plaintext: not to `saas_os.core.notifications`, and in the durable
`saas_os.core.outbox` event (RE-1) only as a `saas_os.core.crypto` envelope bound to the
tenant, decrypted by the job handler at send time -- so no new place holds
email-address PII at rest in the clear (this checkpoint's own "treat
recipient addresses as potentially sensitive" requirement). A user's
undispatched notification events are deleted on user erasure
(`purge_user_notification_events_in_tenant()`).
The actual `From:` address comes from `saas_os.core.email.config.get_email_default_sender()`
(`EMAIL_DEFAULT_SENDER`) -- a deployment-wide setting, not a per-call
parameter, since a transactional sender identity is normally fixed per
platform, not chosen by each caller. Since ADR-0057 the provider is the
deployment's configured one (`EMAIL_PROVIDER`), the send runs off the event
loop (`asyncio.to_thread`), each outbox event carries a stable `Message-ID`,
and a provider failure marked permanent dead-letters the event at once
(`NotificationPermanentDispatchError`); every other failure keeps the
existing retry policy.

**Known, pre-existing, symmetric limitation carried by both channels
(not new to `"email"`)**: this job has no idempotency of its own (P1.11's
`saas_os.core.idempotency` is not applied here -- discovery found no business
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
`saas_os/core/webhooks`' routine deliveries (as opposed to subscription lifecycle
changes) out of `saas_os.core.audit_log` (docs/IMPLEMENTATION-ROADMAP.md Phase
3.4 section 2's standing "no automatic logging of every request"
prohibition). `saas_os/core/notifications` has no subscription-like lifecycle
event to audit in the first place -- dispatch *is* the only operation
this module performs. P1.12's own operational visibility
(`email_send_started`/`_succeeded`/`_failed`) is a structured *log*, not
an audit event, for the same reason -- see `_dispatch_notification_job`'s
own inline logging.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from arq.worker import Function

from saas_os.core.notifications.errors import (
    InvalidNotificationChannelError,
    NotificationDeferredDispatchError,
    NotificationDispatchError,
    NotificationNotFoundError,
    NotificationPermanentDispatchError,
)
from saas_os.core.notifications.models import Notification
from saas_os.core.outbox import (
    append_event,
    claim_event_consumption,
    delete_aggregate_events,
    event_consumption_recorded,
)
from saas_os.core.tenancy import (
    TenantClosedError,
    TenantNotFoundError,
    lock_open_tenant,
    require_open_tenant,
    require_purging_tenant,
)
from saas_os.infra.db import Session, select, tenant_session_scope
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload, register_tenant_job

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
    Actual address-shape/injection validation is `saas_os.core.email.service.
    validate_email_address()`'s job, called again here so a malformed
    address is rejected synchronously at `dispatch_notification()` call
    time, not only later, asynchronously, inside the job handler."""
    if channel != "email":
        return
    if not recipient_email:
        raise ValueError("recipient_email is required when channel='email'.")
    from saas_os.core.email import validate_email_address
    from saas_os.core.email.errors import InvalidEmailAddressError

    try:
        validate_email_address(recipient_email)
    except InvalidEmailAddressError as exc:
        raise ValueError(str(exc)) from exc


def _validate_subject(subject: str | None) -> None:
    if subject is not None and len(subject) > _MAX_SUBJECT_LENGTH:
        raise ValueError(f"subject exceeds {_MAX_SUBJECT_LENGTH} characters.")


# --- Dispatch ----------------------------------------------------------


# RE-1 (transactional outbox): the outbox event type a notification is
# recorded under; its payload is the data `_dispatch_notification_job()`
# consumes.
NOTIFICATION_DISPATCH_EVENT_TYPE = "notification.dispatch"

# The recipient address is stored in the outbox only as a `saas_os.core.crypto`
# envelope (the F-02 pattern `saas_os/core/webhooks` uses for signing secrets),
# bound to the owning tenant: the outbox is durable, and this module's
# invariant is that the address never rests anywhere in plaintext.
_ENVELOPE_PREFIX = "efv1:"  # pragma: allowlist secret


def _recipient_email_associated_data(tenant_id: uuid.UUID) -> bytes:
    return f"notification_recipient_email:{tenant_id}".encode("ascii")


def _encrypt_recipient_email(tenant_id: uuid.UUID, recipient_email: str) -> str:
    from saas_os.core.crypto import EncryptionService

    return EncryptionService().encrypt_str(
        recipient_email, associated_data=_recipient_email_associated_data(tenant_id)
    )


def _decrypt_recipient_email(tenant_id: uuid.UUID, stored_value: str) -> str:
    """The plaintext address for a job payload. A value without the
    envelope prefix is a plaintext address from a job queued before RE-1,
    passed through unchanged."""
    if not stored_value.startswith(_ENVELOPE_PREFIX):
        return stored_value
    from saas_os.core.crypto import EncryptionService

    return EncryptionService().decrypt_str(
        stored_value, associated_data=_recipient_email_associated_data(tenant_id)
    )


def dispatch_notification(
    session: Session,
    tenant_id: uuid.UUID,
    recipient_user_id: uuid.UUID,
    channel: str,
    body: str,
    *,
    subject: str | None = None,
    recipient_email: str | None = None,
) -> uuid.UUID:
    """Record dispatch of one notification to `recipient_user_id` within
    `tenant_id`, in the caller's own transaction (RE-1, transactional
    outbox): a `saas_os.core.outbox` event appended on `session` -- the caller's
    `tenant_session_scope(tenant_id)` session -- so it commits or rolls back
    with the caller's mutation. Nothing is committed here and no queue is
    contacted. Returns the outbox event id. Dispatch itself stays
    asynchronous: the dispatcher (RE-2) publishes the event to
    `_dispatch_notification_job`.

    `(tenant_id, recipient_user_id)` must be a real `TenantMembership` --
    enforced structurally by the composite foreign key in
    `saas_os/core/notifications/models.py`, not merely by this function
    remembering to check; a pair that is not a genuine membership
    surfaces at dispatch time as `NotificationDispatchError` (raised by
    the job handler, after the composite FK rejects the insert with an
    `IntegrityError`).

    `recipient_email` (P1.12) is required, and validated, only when
    `channel="email"` -- see `_validate_recipient_email()`'s own
    docstring. It is recorded only as an encrypted envelope bound to the
    tenant (never plaintext at rest) and never persisted to
    `saas_os.core.notifications` itself; the email channel therefore requires the
    field-encryption key (`saas_os.core.crypto`). The tenant lifecycle is checked
    in the same transaction (`lock_open_tenant()`): a closed tenant raises
    `TenantClosedError`, as before.
    """
    _validate_channel(channel)
    _validate_subject(subject)
    _validate_recipient_email(channel, recipient_email)
    lock_open_tenant(session, tenant_id)

    data: dict[str, object] = {
        "recipient_user_id": str(recipient_user_id),
        "channel": channel,
        "subject": subject,
        "body": body,
    }
    if channel == "email":
        assert recipient_email is not None  # _validate_recipient_email()
        data["recipient_email"] = _encrypt_recipient_email(tenant_id, recipient_email)

    return append_event(
        session,
        tenant_id=tenant_id,
        event_type=NOTIFICATION_DISPATCH_EVENT_TYPE,
        aggregate_type="user",
        aggregate_id=str(recipient_user_id),
        payload=data,
    )


def _notification_message_id(event_id: uuid.UUID | None, sender: str) -> str | None:
    """ADR-0057: a `Message-ID` that is the same on every attempt of one
    outbox event, so a receiver that deduplicates on it can drop a resend
    after an ambiguous failure. `None` for a directly queued job with no
    event identity -- the provider then generates one. Never exactly-once."""
    if event_id is None:
        return None
    return f"<notification.{event_id}@{sender.rsplit('@', 1)[-1]}>"


def _send_email_channel(
    recipient_user_id: uuid.UUID,
    subject: str | None,
    body: str,
    recipient_email: str,
    event_id: uuid.UUID | None = None,
) -> None:
    """The `"email"` channel's own delivery step (P1.12) -- called from
    `_dispatch_notification_job()` before the `Notification` row is
    persisted (module docstring: never claim a status this job cannot
    yet back up). Raises `NotificationDispatchError` on any failure --
    configuration, validation, or provider -- so the outbox dispatcher /
    `saas_os.infra.jobs` retry and dead-letter it exactly like every other
    dispatch failure, never a second retry mechanism. A failure the
    provider marks permanent (ADR-0057) raises
    `NotificationPermanentDispatchError` instead, which the outbox
    dispatcher dead-letters at once.

    The provider is the deployment's configured one (`EMAIL_PROVIDER`,
    ADR-0057); the sender is `EMAIL_DEFAULT_SENDER`, independent of any
    provider's transport settings.
    """
    from saas_os.core.email import (
        EmailMessage,
        get_email_default_sender,
        get_email_provider_name,
        send_email,
    )
    from saas_os.core.email.errors import (
        EmailConfigurationError,
        EmailProviderError,
        InvalidEmailAddressError,
    )

    logger.info(
        "email_send_started",
        extra={"notification_channel": "email"},
    )
    started = time.monotonic()
    provider_name: str | None = None
    try:
        provider_name = get_email_provider_name() or "smtp"
        sender = get_email_default_sender()
        if not sender:
            raise EmailConfigurationError("EMAIL_DEFAULT_SENDER is not set.")
        message = EmailMessage(
            sender=sender,
            to=(recipient_email,),
            subject=subject or "",
            text_body=body,
            message_id=_notification_message_id(event_id, sender),
        )
        send_email(message)
    except (EmailConfigurationError, EmailProviderError, InvalidEmailAddressError) as exc:
        # Never the recipient address, the subject, the body, a secret or
        # the server's reply text -- only the failure's type name, its
        # permanence and numeric reply code (P1.12/ADR-0057 logging rule).
        permanent = isinstance(exc, EmailProviderError) and exc.permanent
        logger.warning(
            "email_send_failed",
            extra={
                "failure_category": type(exc).__name__,
                "email_provider": provider_name,
                "permanent": permanent,
                "smtp_reply_code": getattr(exc, "reply_code", None),
                "duration_ms": round((time.monotonic() - started) * 1000),
            },
        )
        if permanent:
            raise NotificationPermanentDispatchError(recipient_user_id, type(exc).__name__) from exc
        hint = getattr(exc, "retry_after_seconds", None)
        if hint is not None:
            raise NotificationDeferredDispatchError(
                recipient_user_id, type(exc).__name__, hint
            ) from exc
        raise NotificationDispatchError(recipient_user_id, type(exc).__name__) from exc
    else:
        logger.info(
            "email_send_succeeded",
            extra={
                "notification_channel": "email",
                "email_provider": provider_name,
                "duration_ms": round((time.monotonic() - started) * 1000),
            },
        )


async def _dispatch_notification_job(context: TenantJobContext, payload: TenantJobPayload) -> None:
    """The registered job handler. `"in_app"` inserts a `Notification`
    row directly; `"email"` (P1.12) sends through `saas_os.core.email` first,
    then records the same kind of `Notification` row -- both channels
    end in the identical persisted-outcome shape (module docstring).
    At most one notification row per outbox event; an e-mail is not re-sent
    once its completion is recorded (RE-5 -- see the inline comments for
    the one window where it can be). Raises `NotificationDispatchError` on
    failure so the event is retried -- this function never implements
    retry/backoff itself. A tenant job
    (`register_tenant_job`, Foundation Enforcement FE-5): the worker has
    already validated the payload and parsed `context.tenant_id`.
    """
    tenant_id = context.tenant_id
    recipient_user_id = uuid.UUID(payload.data["recipient_user_id"])
    channel = payload.data["channel"]
    subject = payload.data["subject"]
    body = payload.data["body"]

    # PRIV-03 P7 (privacy re-audit RA-03): the execution-time lifecycle
    # fence. `dispatch_notification()`'s `lock_open_tenant()` only
    # proves the tenant was open when the event was *recorded*; between that
    # and this point lie queue latency, retries and worker downtime, and
    # the tenant may have committed DELETED/PURGING/PURGED in the meantime.
    # A closed tenant's notification is intentionally dropped here --
    # before any e-mail is sent and before any tenant-scoped database work
    # -- and dropping is a normal return, never an exception: `saas_os.infra.jobs`'
    # wrapper would otherwise retry and dead-letter a job that must simply
    # not run (the shape `control_plane...continuous_loop`'s `TENANT_CLOSED`
    # outcome established). The row write below repeats the check *inside*
    # its own transaction with `lock_open_tenant()` (`core.tenants` FOR
    # SHARE, serialized against the FOR UPDATE lifecycle transitions), so a
    # closure cannot commit between the check and the write. An e-mail
    # already handed to the provider cannot be recalled: if the tenant
    # closes between the send and the row write, the row is dropped and
    # the job still ends without a retry (a retry would re-send).
    try:
        require_open_tenant(tenant_id)
    except TenantClosedError:
        logger.info("notification_dropped_tenant_closed", extra={"notification_channel": channel})
        return
    except TenantNotFoundError:
        # Not "closed" -- a tenant that does not exist is a genuine
        # failure, not a lifecycle outcome: fall through so the write
        # below fails exactly as it always has (`NotificationDispatchError`,
        # retried then dead-lettered by `saas_os.infra.jobs`).
        pass

    if channel == "email":
        # RE-5: an e-mail cannot join a database transaction, so a repeated
        # execution of an event whose completion is already recorded is
        # stopped *before* sending. (A worker that dies between the send and
        # the record below can still send twice -- the inherent at-least-once
        # limit for an external side effect; `saas_os/core/outbox/consumption.py`.)
        if context.event_id is not None:
            try:
                with tenant_session_scope(tenant_id) as session:
                    already_sent = event_consumption_recorded(
                        session,
                        tenant_id=tenant_id,
                        consumer=NOTIFICATION_DISPATCH_EVENT_TYPE,
                        event_id=context.event_id,
                    )
            except Exception as exc:
                # Fail closed: an unreadable record is never "already sent".
                raise NotificationDispatchError(recipient_user_id, type(exc).__name__) from exc
            if already_sent:
                logger.info(
                    "notification_duplicate_suppressed", extra={"notification_channel": channel}
                )
                return
        try:
            recipient_email = _decrypt_recipient_email(tenant_id, payload.data["recipient_email"])
        except Exception as exc:
            # Only the failure's type name -- never the envelope or address.
            raise NotificationDispatchError(recipient_user_id, type(exc).__name__) from exc
        # ADR-0057: `smtplib` is blocking; run it off the event loop so one
        # slow relay cannot stall the worker's other jobs (the same choice
        # ADR-0035 made for webhook DNS resolution).
        await asyncio.to_thread(
            _send_email_channel,
            recipient_user_id,
            subject,
            body,
            recipient_email,
            context.event_id,
        )
    elif channel != "in_app":
        # Defense in depth: dispatch_notification() already validated the
        # channel before enqueueing; a job somehow enqueued with an
        # unsupported channel is a caller error, not a transient failure
        # worth retrying indefinitely -- still dead-letters eventually via
        # saas_os.infra.jobs' own retry-then-dead-letter policy.
        raise NotificationDispatchError(recipient_user_id, f"unsupported channel {channel!r}")

    try:
        with tenant_session_scope(tenant_id) as session:
            lock_open_tenant(session, tenant_id)
            # RE-5: the consumption claim commits with the notification row,
            # so a repeated execution of the same outbox event records one
            # notification (and, for e-mail, a later repeat is stopped by the
            # check above). No event identity: a directly queued job, as before.
            if context.event_id is not None and not claim_event_consumption(
                session,
                tenant_id=tenant_id,
                consumer=NOTIFICATION_DISPATCH_EVENT_TYPE,
                event_id=context.event_id,
            ):
                logger.info(
                    "notification_duplicate_suppressed", extra={"notification_channel": channel}
                )
                return
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
    except TenantClosedError:
        logger.info("notification_dropped_tenant_closed", extra={"notification_channel": channel})
        return
    except Exception as exc:
        raise NotificationDispatchError(recipient_user_id, type(exc).__name__) from exc


NOTIFICATION_JOB_FUNCTIONS: list[Function] = [register_tenant_job(_dispatch_notification_job)]

# RE-2 (durable outbox dispatcher): the consumer of each outbox event type
# this module produces. The dispatcher runs it in-process, inside its own
# outbox job, with the event's payload -- the same handler, payload and
# fences as the registered job above.
OUTBOX_EVENT_HANDLERS: dict[
    str, Callable[[TenantJobContext, TenantJobPayload], Awaitable[None]]
] = {NOTIFICATION_DISPATCH_EVENT_TYPE: _dispatch_notification_job}


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


# --- PRIV-03 Phase P3: tenant purge ------------------------------------------


def purge_tenant_notifications(tenant_id: uuid.UUID) -> int:
    """Delete every `core.notifications` row `tenant_id` owns -- one
    module-owned step of `saas_os.core.tenancy.purge_tenant()`, only callable in
    the purge phase (`TenantNotPurgingError` otherwise). Runs under
    `tenant_session_scope()`/RLS like every other write here, so it can
    only ever see this tenant's rows. Idempotent (returns 0 on repeat).
    Must run before memberships are removed: `(tenant_id,
    recipient_user_id)` is a composite FK onto `core.tenant_memberships`.
    """
    require_purging_tenant(tenant_id)
    deleted = 0
    with tenant_session_scope(tenant_id) as session:
        rows = (
            session.execute(
                select(Notification)
                .where(Notification.tenant_id == tenant_id)
                .order_by(Notification.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for row in rows:
            session.delete(row)
            deleted += 1
    return deleted


def purge_user_notifications_in_tenant(tenant_id: uuid.UUID, user_id: uuid.UUID) -> int:
    """RA-12-3 -- delete every `core.notifications` row addressed to
    `user_id` *within `tenant_id`* -- one module-owned step of
    `saas_os.core.identity.erasure.erase_user_identity()`, mirroring
    `purge_tenant_notifications()`'s own shape, scoped to one recipient's
    own notifications rather than every notification the tenant owns.
    Runs under `tenant_session_scope()`/RLS like every other write here,
    so it can only ever see this tenant's rows. Idempotent (returns 0 on
    repeat). Must run before the user's own `core.tenant_memberships` row
    in this tenant is removed: `(tenant_id, recipient_user_id)` is a
    composite FK onto it.
    """
    deleted = 0
    with tenant_session_scope(tenant_id) as session:
        rows = (
            session.execute(
                select(Notification)
                .where(
                    Notification.tenant_id == tenant_id,
                    Notification.recipient_user_id == user_id,
                )
                .order_by(Notification.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for row in rows:
            session.delete(row)
            deleted += 1
    return deleted


def purge_user_notification_events_in_tenant(tenant_id: uuid.UUID, user_id: uuid.UUID) -> int:
    """User erasure (`saas_os/core/identity/erasure.py`): delete `user_id`'s
    not-yet-dispatched notification events in `tenant_id`'s outbox (RE-1) --
    they carry the user's notification content and (encrypted) address and
    must not outlive the erasure. Returns how many were deleted."""
    with tenant_session_scope(tenant_id) as session:
        return delete_aggregate_events(
            session,
            tenant_id=tenant_id,
            event_type=NOTIFICATION_DISPATCH_EVENT_TYPE,
            aggregate_type="user",
            aggregate_id=str(user_id),
        )
