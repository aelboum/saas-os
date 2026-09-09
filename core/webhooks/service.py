"""Outbound webhook subscription management, signing, and delivery
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.3).

`subscribe`/`get_subscription`/`list_subscriptions`/`unsubscribe` are
tenant-scoped CRUD over `core.webhook_subscriptions`, using
`infra.db.tenant_session_scope()` exactly like every other tenant-owned
Core entity -- the RLS policy `core/webhooks/models.py`'s own migration
applies is this module's enforcement mechanism, not application-level
filtering alone.

Delivery reuses `infra.jobs` (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4)
for retry/backoff/dead-letter -- exactly the "genuinely single-step-
retryable" task shape `docs/ADR/0007-background-job-and-workflow-engine.md`
names webhook delivery as. `core/webhooks` owns the job *handler*
(`_deliver_webhook`, registered via `infra.jobs.register_job` and
exported as `WEBHOOK_JOB_FUNCTIONS` for a worker process to register);
`infra/jobs` owns the generic retry-count/dead-letter execution metadata
(docs/DATA-ARCHITECTURE.md section 5) -- this module does not duplicate
that bookkeeping with its own delivery-attempt table.

The job payload passed through `infra.jobs.enqueue_job()` carries only a
`subscription_id` and the event's own (non-secret) data -- never the
signing secret. The handler re-reads the subscription (secret included)
from the database at execution time, inside its own `tenant_session_scope`,
so the secret is never serialized into the Redis queue or any job-queue
log (docs/SECURITY.md: secrets must not enter logs or generated
artifacts).

Subscription creation and removal are audit-logged via `core.audit_log`
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.3's own Security Requirement
context, mirroring `core/api_keys`' create/revoke precedent) -- routine
successful deliveries are not (mirrors `core/audit_log`'s own Phase 3.4
prohibition on "automatic logging of every request"; a dead-lettered
delivery is `infra/jobs`' own operational record, not a security event).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx
from arq.worker import Function

from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
from core.webhooks.config import get_webhook_security_config
from core.webhooks.errors import (
    InvalidWebhookUrlError,
    WebhookDeliveryError,
    WebhookReplayDetectedError,
    WebhookSignatureInvalidError,
    WebhookSubscriptionNotFoundError,
    WebhookTimestampInvalidError,
)
from core.webhooks.models import WebhookReplayRecord, WebhookSubscription
from infra.db import IntegrityError, select, tenant_session_scope
from infra.jobs import TenantJobPayload, enqueue_job, register_job

_SECRET_BYTES = 32  # 256 bits, matches core/identity/sessions.py and core/api_keys/service.py.
_MAX_URL_LENGTH = 2048
_DELIVERY_TIMEOUT_SECONDS = 10.0
_SIGNATURE_HEADER = "X-Webhook-Signature"
_TIMESTAMP_HEADER = "X-Webhook-Timestamp"
_ENVELOPE_SEPARATOR = b"."


def _validate_url(url: str) -> None:
    if not url or len(url) > _MAX_URL_LENGTH:
        raise InvalidWebhookUrlError(url)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise InvalidWebhookUrlError(url)


def compute_signature(secret: str, payload_bytes: bytes) -> str:
    """`sha256=<hex hmac>` over exactly `payload_bytes` -- the low-level
    HMAC primitive every signed value in this module is built from. A
    pure function (no I/O), so it is independently testable without a
    database or network call. Unchanged since Phase 4.3: P1.10 does not
    modify this function's behavior, only what its caller passes as
    `payload_bytes` for an actual delivery (`compute_signed_envelope()`
    below) -- existing direct callers/tests of `compute_signature()`
    itself are unaffected.
    """
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def compute_signed_envelope(secret: str, payload_bytes: bytes, timestamp: int) -> str:
    """P1.10: the actual value sent in `X-Webhook-Signature` for a real
    delivery -- HMAC over `f"{timestamp}.".encode() + payload_bytes`,
    never over the payload alone. This is the "smallest backwards-
    compatible signed-envelope extension" this checkpoint's own
    objective calls for: `compute_signature()` itself (the HMAC
    primitive) is untouched, only the bytes fed into it now bind the
    signature to a specific point in time. Without this, a captured
    valid `(payload, signature)` pair for the old payload-only scheme
    would remain valid forever -- replaying it later would verify
    successfully, since a stale HMAC alone carries no expiry. Binding
    the timestamp into the signed bytes (not just sending it as a
    parallel, unsigned header) is what makes `verify_webhook_signature()`
    able to trust the timestamp it validates -- an attacker who alters
    the timestamp header without the secret cannot produce a matching
    signature, so a freshness check on an unsigned timestamp would be
    trivially bypassable by resending an old payload with a fresh,
    forged timestamp header.

    Mirrors Stripe's own signed-payload convention (already referenced
    in this codebase: `core/billing/stripe_provider.py::
    verify_stripe_webhook_signature()` delegates to the Stripe SDK's
    identical `timestamp.payload` scheme) -- a well-precedented design,
    not a bespoke one.
    """
    signed_bytes = str(timestamp).encode("ascii") + _ENVELOPE_SEPARATOR + payload_bytes
    return compute_signature(secret, signed_bytes)


def verify_webhook_signature(
    secret: str,
    payload_bytes: bytes,
    timestamp: int,
    signature_header: str,
    *,
    tolerance_seconds: int | None = None,
    now: datetime | None = None,
) -> None:
    """P1.10: the verification counterpart to `compute_signed_envelope()`
    -- what a future inbound receiver would call (mirrors
    `core.billing.stripe_provider.verify_stripe_webhook_signature()`'s
    own precedent: "no HTTP route receives this yet ... this function is
    what a future route would call"). Raises `WebhookTimestampInvalidError`
    if `timestamp` is outside the configured tolerance window (UTC,
    symmetric: rejects both too-old -- a possible replay -- and too-far-
    in-the-future), or `WebhookSignatureInvalidError` if the signature
    does not match. Order matters: timestamp is checked first, so a
    stale request is rejected without ever running the (slightly more
    expensive, and less informative to reject first) signature
    comparison -- matching this checkpoint's own required ordering
    (parse envelope -> validate timestamp -> validate signature).

    The comparison itself uses `hmac.compare_digest()` -- constant-time,
    never a plain `==`, so response timing cannot leak how many leading
    bytes of a guessed signature were correct.

    `tolerance_seconds` defaults to `core.webhooks.config.get_webhook_security_config()`'s
    configured (or safe-default) value -- never disabled by missing
    configuration. `now` is an injection point for tests only; real
    callers never pass it (defaults to the real current UTC time).
    """
    tolerance = (
        tolerance_seconds
        if tolerance_seconds is not None
        else get_webhook_security_config().tolerance_seconds
    )
    current_time = now if now is not None else datetime.now(UTC)

    try:
        delivery_time = datetime.fromtimestamp(timestamp, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise WebhookTimestampInvalidError() from exc

    age_seconds = (current_time - delivery_time).total_seconds()
    if age_seconds > tolerance or age_seconds < -tolerance:
        raise WebhookTimestampInvalidError()

    expected_signature = compute_signed_envelope(secret, payload_bytes, timestamp)
    if not hmac.compare_digest(expected_signature, signature_header):
        raise WebhookSignatureInvalidError()


# --- Replay detection (P1.10: atomic, database-authoritative) --------------


def record_webhook_delivery(
    tenant_id: uuid.UUID, subscription_id: uuid.UUID, event_id: uuid.UUID
) -> None:
    """Atomically record that `(tenant_id, subscription_id, event_id)`
    has been accepted, raising `WebhookReplayDetectedError` if it already
    was. Must be called only *after* `verify_webhook_signature()` has
    already succeeded for this exact request (never record a replay-
    ledger entry for a request whose signature was never verified --
    that would let an attacker poison the ledger with fabricated
    `event_id`s and cause legitimate future deliveries using those ids
    to be wrongly rejected as replays).

    The atomicity is the database's own unique-constraint enforcement
    (`core/webhooks/models.py::WebhookReplayRecord`'s own docstring) --
    a plain `INSERT` inside `tenant_session_scope()`'s transaction,
    which either succeeds (first, legitimate acceptance) or raises
    `IntegrityError` (a concurrent or later duplicate), mapped here to
    `WebhookReplayDetectedError` exactly the way
    `core/billing/service.py::create_plan()` already maps its own
    unique-key `IntegrityError` to `DuplicatePlanKeyError`. No
    `SELECT`-then-`INSERT` race window exists: two simultaneous
    transactions attempting the same triple both attempt the `INSERT`;
    PostgreSQL's own index guarantees only one can ever commit.
    """
    try:
        with tenant_session_scope(tenant_id) as session:
            session.add(
                WebhookReplayRecord(
                    tenant_id=tenant_id, subscription_id=subscription_id, event_id=event_id
                )
            )
            session.flush()
    except IntegrityError as exc:
        raise WebhookReplayDetectedError(tenant_id, subscription_id, event_id) from exc


def verify_and_record_webhook_delivery(
    tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    event_id: uuid.UUID,
    payload_bytes: bytes,
    timestamp: int,
    signature_header: str,
    secret: str,
    *,
    tolerance_seconds: int | None = None,
    now: datetime | None = None,
) -> None:
    """P1.10: the complete inbound verification boundary -- Parse
    envelope (caller's job) -> validate timestamp -> validate signature
    -> atomically detect/reject replay, this checkpoint's own required
    order. Tenant/endpoint authorization is `tenant_id`/`subscription_id`
    themselves here: both must already be the authenticated, established
    identifiers a real caller resolved (never values read from an
    unverified request body) -- exactly like every other tenant-owned
    write in this codebase trusts only `tenant_session_scope`'s own
    tenant, never a caller-supplied claim.

    No HTTP route calls this yet -- this repository's webhook system is
    outbound-only (`core/webhooks/__init__.py`'s own docstring); this is
    the reusable primitive a future inbound receiver (ours or a Product's)
    would call, mirroring `core.billing.stripe_provider.
    verify_stripe_webhook_signature()`'s identical "no route yet, this is
    what one would call" precedent.
    """
    verify_webhook_signature(
        secret,
        payload_bytes,
        timestamp,
        signature_header,
        tolerance_seconds=tolerance_seconds,
        now=now,
    )
    record_webhook_delivery(tenant_id, subscription_id, event_id)


def purge_expired_replay_records(tenant_id: uuid.UUID, older_than: datetime) -> int:
    """Retention: delete `tenant_id`'s replay records created before
    `older_than`. Safe to call at any time -- a replay record older than
    the configured tolerance window has already lost all protective
    value (any delivery attempt old enough to reuse it would already be
    rejected by `verify_webhook_signature()`'s own timestamp check before
    `record_webhook_delivery()` is ever reached), so deleting it changes
    no security property, only storage growth (this checkpoint's own
    "the database must not grow forever" requirement).

    Tenant-scoped (not a global cross-tenant purge) so this runs through
    the ordinary restricted application role and `tenant_session_scope()`
    -- exactly like every other tenant-owned write/delete in this
    codebase -- rather than needing a superuser/cross-tenant bypass.
    P1.10 does not wire this into a recurring job (this checkpoint's own
    "do not introduce a background cleanup framework ... unless strictly
    required" -- correctness never depends on cleanup running); a future
    phase may register it with `infra.jobs` if unbounded growth becomes
    an actual operational concern.
    """
    deleted = 0
    with tenant_session_scope(tenant_id) as session:
        stale_records = (
            session.execute(
                select(WebhookReplayRecord).where(
                    WebhookReplayRecord.tenant_id == tenant_id,
                    WebhookReplayRecord.created_at < older_than,
                )
            )
            .scalars()
            .all()
        )
        for record in stale_records:
            session.delete(record)
            deleted += 1
    return deleted


# --- Subscription management ------------------------------------------------


def subscribe(
    tenant_id: uuid.UUID, url: str, *, actor_user_id: uuid.UUID | None = None
) -> tuple[WebhookSubscription, str]:
    """Create a subscription for `tenant_id`. Returns the persisted
    record and the raw signing secret -- unlike a bearer credential
    (`core/api_keys`), this secret is also stored (see
    `core/webhooks/models.py`'s docstring for why), so it remains
    retrievable for later re-display if the caller's own UI needs to show
    it again; it is simply never *returned* by `get_subscription`/
    `list_subscriptions` below.
    """
    _validate_url(url)
    raw_secret = secrets.token_urlsafe(_SECRET_BYTES)

    with tenant_session_scope(tenant_id) as session:
        subscription = WebhookSubscription(tenant_id=tenant_id, url=url, signing_secret=raw_secret)
        session.add(subscription)
        session.flush()
        session.refresh(subscription)
        session.expunge(subscription)

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action="webhook.subscription_created",
        resource_type="webhook_subscription",
        resource_id=str(subscription.id),
        outcome=AuditOutcome.SUCCESS,
    )
    return subscription, raw_secret


def get_subscription(tenant_id: uuid.UUID, subscription_id: uuid.UUID) -> WebhookSubscription:
    with tenant_session_scope(tenant_id) as session:
        subscription = session.get(WebhookSubscription, subscription_id)
        if subscription is None or subscription.tenant_id != tenant_id:
            raise WebhookSubscriptionNotFoundError(tenant_id, subscription_id)
        session.expunge(subscription)
        return subscription


def list_subscriptions(tenant_id: uuid.UUID) -> list[WebhookSubscription]:
    with tenant_session_scope(tenant_id) as session:
        subscriptions = (
            session.execute(
                select(WebhookSubscription).where(WebhookSubscription.tenant_id == tenant_id)
            )
            .scalars()
            .all()
        )
        for subscription in subscriptions:
            session.expunge(subscription)
        return list(subscriptions)


def unsubscribe(
    tenant_id: uuid.UUID, subscription_id: uuid.UUID, *, actor_user_id: uuid.UUID | None = None
) -> None:
    """Idempotent: removing an already-removed subscription is a no-op,
    not an error (mirrors `core/rbac/service.py::remove_role` and
    `core/api_keys/service.py::revoke_api_key`'s precedent) -- writes no
    audit entry when there was nothing to remove."""
    with tenant_session_scope(tenant_id) as session:
        subscription = session.get(WebhookSubscription, subscription_id)
        if subscription is None or subscription.tenant_id != tenant_id:
            return
        session.delete(subscription)

    record_audit_event(
        tenant_id=tenant_id,
        actor_type=ActorType.USER if actor_user_id is not None else ActorType.SYSTEM,
        actor_user_id=actor_user_id,
        action="webhook.subscription_deleted",
        resource_type="webhook_subscription",
        resource_id=str(subscription_id),
        outcome=AuditOutcome.SUCCESS,
    )


# --- Delivery ----------------------------------------------------------------


async def _deliver_webhook(payload: TenantJobPayload | None) -> None:
    """The registered job handler: re-reads the subscription (secret
    included) from the database at execution time -- the secret is never
    carried in the job payload itself (module docstring) -- signs the
    event body, and POSTs it. Raises `WebhookDeliveryError` on a network
    error or a non-2xx response so `infra.jobs`' own wrapper
    (`register_job`) retries with backoff, then dead-letters on
    exhaustion -- this function never implements retry/backoff itself.

    P1.10: `event_id` is generated once, in `trigger_event()`, and stays
    fixed across every retry `infra.jobs` performs for this delivery --
    a receiver's replay ledger needs a stable identity across legitimate
    retries. `timestamp`, in contrast, is computed fresh on *every*
    attempt (here, at actual send time), never reused from an earlier
    attempt or fixed at enqueue time: a retry can happen well after
    `infra.jobs`' own backoff delay, and a stale timestamp from the
    original enqueue would make an otherwise-legitimate retry fail a
    receiver's freshness check for no security reason. A fresh timestamp
    each attempt is what lets legitimate internal retries keep working
    without weakening replay protection (this checkpoint's own required
    distinction between "legitimate internal delivery retry" and
    "replayed externally received webhook").
    """
    if payload is None:
        # trigger_event() always enqueues a TenantJobPayload; a job
        # invoked with none was not enqueued through this module's own
        # entrypoint. Not a delivery failure to retry -- a caller error.
        raise ValueError("_deliver_webhook requires a TenantJobPayload, got None.")
    tenant_id = uuid.UUID(payload.tenant_id)
    subscription_id = uuid.UUID(payload.data["subscription_id"])
    event_id = uuid.UUID(payload.data["event_id"])

    with tenant_session_scope(tenant_id) as session:
        subscription = session.get(WebhookSubscription, subscription_id)
        if subscription is None:
            # The subscription was removed after this delivery was
            # enqueued -- nothing to deliver to, and not a transient
            # failure worth retrying.
            return
        url = subscription.url
        secret = subscription.signing_secret

    body = _encode_event(event_id, payload.data["event_type"], payload.data["event_data"])
    timestamp = int(datetime.now(UTC).timestamp())
    signature = compute_signed_envelope(secret, body, timestamp)

    try:
        async with httpx.AsyncClient(timeout=_DELIVERY_TIMEOUT_SECONDS) as client:
            response = await client.post(
                url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    _SIGNATURE_HEADER: signature,
                    _TIMESTAMP_HEADER: str(timestamp),
                },
            )
    except httpx.HTTPError as exc:
        raise WebhookDeliveryError(subscription_id, type(exc).__name__) from exc

    if response.status_code >= 300:
        raise WebhookDeliveryError(subscription_id, f"HTTP {response.status_code}")


def _encode_event(event_id: uuid.UUID, event_type: str, event_data: dict[str, object]) -> bytes:
    return json.dumps(
        {"event_id": str(event_id), "event_type": event_type, "data": event_data}
    ).encode("utf-8")


WEBHOOK_JOB_FUNCTIONS: list[Function] = [register_job(_deliver_webhook)]


async def trigger_event(
    tenant_id: uuid.UUID,
    event_type: str,
    event_data: dict[str, object],
    *,
    queue_name: str | None = None,
) -> list[str]:
    """Enqueue delivery of `event_type` to every one of `tenant_id`'s
    current subscriptions. Returns the arq job IDs (one per subscription)
    -- delivery itself happens asynchronously via `infra.jobs`; this
    function does not block on network I/O. Return shape unchanged by
    P1.10 -- still `list[str]`, no existing caller needs to change.

    P1.10: one `event_id` (a fresh UUID) is generated *once* here and
    shared by every subscription's delivery of this occurrence -- it is
    genuinely the same event, just fanned out to multiple destinations.
    Each subscription still gets its own independent signature (its own
    `signing_secret`), but the shared `event_id` is what a receiver's
    replay ledger keys on, and what lets `infra.jobs`' own retry of one
    subscription's delivery remain recognizable as "the same event" on
    every attempt (`_deliver_webhook()`'s own docstring).

    `queue_name` is a thin passthrough to `infra.jobs.enqueue_job()`'s own
    parameter of the same name (default `None` uses arq's standard queue,
    unchanged production behavior) -- it exists so a test's isolated
    `Worker` (bound to a non-default queue) has a matching producer side,
    the same reason `enqueue_job()` itself exposes it.
    """
    subscriptions = list_subscriptions(tenant_id)
    event_id = uuid.uuid4()
    job_ids: list[str] = []
    for subscription in subscriptions:
        job_id = await enqueue_job(
            _deliver_webhook.__name__,
            TenantJobPayload(
                tenant_id=str(tenant_id),
                data={
                    "subscription_id": str(subscription.id),
                    "event_id": str(event_id),
                    "event_type": event_type,
                    "event_data": event_data,
                },
            ),
            queue_name=queue_name,
        )
        job_ids.append(job_id)
    return job_ids
