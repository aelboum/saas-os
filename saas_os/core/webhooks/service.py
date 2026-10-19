"""Outbound webhook subscription management, signing, and delivery
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.3).

`subscribe`/`get_subscription`/`list_subscriptions`/`unsubscribe` are
tenant-scoped CRUD over `core.webhook_subscriptions`, using
`saas_os.infra.db.tenant_session_scope()` exactly like every other tenant-owned
Core entity -- the RLS policy `saas_os/core/webhooks/models.py`'s own migration
applies is this module's enforcement mechanism, not application-level
filtering alone.

Delivery reuses `saas_os.infra.jobs` (docs/IMPLEMENTATION-ROADMAP.md Phase 2.4)
for retry/backoff/dead-letter -- exactly the "genuinely single-step-
retryable" task shape `docs/ADR/0007-background-job-and-workflow-engine.md`
names webhook delivery as. `saas_os/core/webhooks` owns the job *handler*
(`_deliver_webhook`, registered via `saas_os.infra.jobs.register_tenant_job` and
exported as `WEBHOOK_JOB_FUNCTIONS` for a worker process to register);
`saas_os/infra/jobs` owns the generic retry-count/dead-letter execution metadata
(docs/DATA-ARCHITECTURE.md section 5) -- this module does not duplicate
that bookkeeping with its own delivery-attempt table.

`trigger_event()` records each delivery as a `saas_os.core.outbox` event in the
caller's own transaction (RE-1, transactional outbox); a dispatcher (RE-2)
publishes it to `_deliver_webhook`. The event payload -- and the job payload
built from it -- carries only a `subscription_id` and the event's own
(non-secret) data -- never the signing secret. The handler re-reads the
subscription (secret included) from the database at execution time, inside
its own `tenant_session_scope`, so the secret is never serialized into the
outbox, the Redis queue or any job-queue log (docs/SECURITY.md: secrets must
not enter logs or generated artifacts).

Subscription creation and removal are audit-logged via `saas_os.core.audit_log`
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.3's own Security Requirement
context, mirroring `saas_os/core/api_keys`' create/revoke precedent) -- routine
successful deliveries are not (mirrors `saas_os/core/audit_log`'s own Phase 3.4
prohibition on "automatic logging of every request"; a dead-lettered
delivery is `saas_os/infra/jobs`' own operational record, not a security event).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import uuid
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx
from arq.worker import Function

from saas_os.core.audit_log import record_in_transaction
from saas_os.core.authority import Caller, SystemAuthority, require_caller
from saas_os.core.crypto import EncryptionService
from saas_os.core.outbox import append_event, event_consumption_recorded, record_event_consumption
from saas_os.core.rbac.service import authorize_caller
from saas_os.core.tenancy import (
    TenantClosedError,
    TenantNotFoundError,
    lock_open_tenant,
    require_open_tenant,
    require_purging_tenant,
    tenant_job_session,
)
from saas_os.core.webhooks.config import get_webhook_security_config
from saas_os.core.webhooks.errors import (
    InvalidWebhookUrlError,
    MalformedWebhookEventError,
    WebhookDeliveryError,
    WebhookDestinationRejectedError,
    WebhookDestinationUnresolvedError,
    WebhookPermanentDeliveryError,
    WebhookReplayDetectedError,
    WebhookSignatureInvalidError,
    WebhookSubscriptionNotFoundError,
    WebhookTimestampInvalidError,
)
from saas_os.core.webhooks.models import WebhookReplayRecord, WebhookSubscription
from saas_os.infra.db import IntegrityError, Session, select, tenant_session_scope
from saas_os.infra.egress.addresses import (
    NAT64_WELL_KNOWN_PREFIX,
    embedded_ipv4_addresses,
    format_address_for_url,
    is_non_public_address,
    pin_url_to_address,
)
from saas_os.infra.egress.deadline import Deadline
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload, register_tenant_job

_PROVISIONING = frozenset({SystemAuthority.PROVISIONING})
_SECRET_BYTES = (
    32  # 256 bits, matches saas_os/core/identity/sessions.py and saas_os/core/api_keys/service.py.
)
_MAX_URL_LENGTH = 2048
_DELIVERY_TIMEOUT_SECONDS = 10.0
_SIGNATURE_HEADER = "X-Webhook-Signature"
_TIMESTAMP_HEADER = "X-Webhook-Timestamp"

logger = logging.getLogger(__name__)
_ENVELOPE_SEPARATOR = b"."

# --- F-02: signing-secret encryption at rest --------------------------------
#
# `signing_secret` is stored as a `saas_os.core.crypto.EncryptionService` ciphertext
# envelope, never the raw HMAC secret directly (`saas_os/core/webhooks/models.py`'s
# own docstring). This is a second, defense-in-depth layer on top of RLS
# (the table's primary confidentiality boundary, unchanged): a privileged
# connection that structurally bypasses RLS no longer reads a usable secret
# directly off the row.
#
# `associated_data` binds each ciphertext to the owning tenant (the exact
# `f"tenant:{tenant_id}"` pattern `tests/core/crypto/test_service_unit.py`
# already demonstrates for this purpose) -- moving a row's ciphertext "to" a
# different tenant_id column value would fail AEAD authentication, not
# silently decrypt under the wrong binding.
# A public format tag, not a secret (saas_os/core/crypto/envelope.py).
_SIGNING_SECRET_ENVELOPE_PREFIX = "efv1:"  # pragma: allowlist secret


def _signing_secret_associated_data(tenant_id: uuid.UUID) -> bytes:
    return f"webhook_signing_secret:{tenant_id}".encode("ascii")


def _encrypt_signing_secret(tenant_id: uuid.UUID, raw_secret: str) -> str:
    """Encrypt a newly generated raw secret for persistence. Every
    subscription created from this point on stores only the ciphertext
    envelope -- the raw value is never written to the database. Fails
    closed (raises) if no key is configured -- `subscribe()` never falls
    back to storing plaintext when encryption is unavailable."""
    service = EncryptionService()
    return service.encrypt_str(
        raw_secret, associated_data=_signing_secret_associated_data(tenant_id)
    )


def _decrypt_signing_secret(tenant_id: uuid.UUID, stored_value: str) -> str:
    """The inverse of `_encrypt_signing_secret()`, with one compatibility
    exception: a value that does not carry this module's own envelope
    prefix was written before F-02 existed (a raw secret, stored directly)
    and is returned as-is -- never re-encrypted implicitly on a read path,
    and never treated as an error. This is what makes the widening
    migration (`saas_os/infra/db/migrations/versions/76a55dfb1782_...py`) safe with
    no data rewrite: an old row keeps working exactly as it always did.

    For a genuine envelope, decryption failure (wrong/rotated-away key,
    tampered ciphertext, wrong tenant binding) raises
    `DecryptionAuthenticationError`/`MalformedCiphertextError` rather than
    returning anything -- the same fail-closed guarantee
    `EncryptionService` already makes, not weakened here: a caller that
    cannot decrypt a genuine envelope gets no secret at all, never a
    default or partial one.
    """
    if not stored_value.startswith(_SIGNING_SECRET_ENVELOPE_PREFIX):
        return stored_value
    service = EncryptionService()
    return service.decrypt_str(
        stored_value, associated_data=_signing_secret_associated_data(tenant_id)
    )


def _validate_url(url: str) -> None:
    if not url or len(url) > _MAX_URL_LENGTH:
        raise InvalidWebhookUrlError(url)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise InvalidWebhookUrlError(url)
    hostname = parsed.hostname
    if not hostname:
        raise InvalidWebhookUrlError(url)
    _reject_if_literal_non_public_address(hostname, url)


# --- SSRF hardening (Phase J-R1: J-API-01) ----------------------------------
#
# The security question is never "does this hostname/IP string look bad" --
# it is "is the address this will actually connect to publicly routable".
# `_is_non_public_address()` is the one place that question is answered, by
# reasoning about a real `ipaddress.IPv4Address`/`IPv6Address` object, so a
# literal address (checked here, in `_validate_url()`, at subscription time --
# zero network I/O needed since no resolution is required) and a resolved
# address (checked in `_validate_destination()` below, at delivery time) are
# judged by the exact same rule. No hostname/IP string blacklist exists
# anywhere in this module.

AddressResolver = Callable[[str], list[str]]


# AI-B (ADR-0054 section 8b): the address predicate, the embedded-IPv4
# extraction and the pinning helper live in `saas_os.infra.egress.addresses`,
# shared with the AI egress client. These names are kept as module-level
# aliases so this module's behaviour, its call sites and the tests that
# import or patch them are unchanged. Webhook policy (http/https, any port on
# a public address, ADR-0035) stays defined here, not there.
_NAT64_WELL_KNOWN_PREFIX = NAT64_WELL_KNOWN_PREFIX
_embedded_ipv4_addresses = embedded_ipv4_addresses
_is_non_public_address = is_non_public_address


def _reject_if_literal_non_public_address(hostname: str, url: str) -> None:
    """If `hostname` is itself a literal IP address (not a name requiring
    DNS), reject it immediately when it is not publicly routable --
    `127.0.0.1`, `169.254.169.254`, `10.x.x.x`, `::1`, `fe80::...`, `0.0.0.0`,
    etc. This is deliberately network-free: parsing a literal address string
    is not a resolution, so `_validate_url()` stays a pure function callable
    from a unit test with no database or network. A real hostname (not a
    literal IP) is untouched here -- it cannot be judged without resolving
    it, which happens separately, immediately before an actual delivery
    attempt (`_validate_destination()` below), never here.
    """
    try:
        literal_address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if _is_non_public_address(literal_address):
        raise InvalidWebhookUrlError(url)


def _default_resolve_hostname(hostname: str) -> list[str]:
    """Real DNS resolution -- the default `AddressResolver`. Every address
    `hostname` currently maps to (IPv4 and IPv6 both), via the platform
    resolver. An unresolvable hostname raises `InvalidWebhookUrlError`
    rather than being treated as "no addresses, so allow" -- a delivery
    destination this module cannot resolve is not a valid one.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError as exc:
        # RE-4: transient -- DNS may answer on a later attempt (which
        # re-validates whatever it returns).
        raise WebhookDestinationUnresolvedError(hostname) from exc
    return sorted({str(info[4][0]) for info in infos})


def _validate_destination(
    url: str, *, resolver: AddressResolver | None = None
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """The first of `_validate_destination_addresses()` -- the address a
    delivery connects to first."""
    return _validate_destination_addresses(url, resolver=resolver)[0]


def _validate_destination_addresses(
    url: str, *, resolver: AddressResolver | None = None
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """The actual delivery-time SSRF gate: resolve `url`'s host and reject
    unless every resolved address is publicly routable -- covers a literal
    IP (resolves to itself) and a real hostname identically, and is what
    protects against DNS rebinding: a hostname that was safe when the
    subscription was created can be repointed at a private/internal
    address later, so this function re-validates fresh, immediately before
    every actual outbound attempt `_deliver_webhook()` makes (including
    retries) -- never only once at subscription time.

    Returns the validated addresses `_deliver_webhook()` may connect to
    (Phase J-R1B), in lexicographic order (`sorted()`) -- a plain,
    deterministic order, not a load-balancing policy. Connecting to any
    address other than these (by letting the HTTP client resolve the
    hostname again, independently) would reopen exactly the TOCTOU window
    this function exists to close, since a second resolution could
    legitimately return something else (a rebind, or ordinary DNS
    round-robin landing on a different answer). The delivery tries the
    first and, only when connecting to it failed before anything was sent,
    the next (owner decision of 2026-10-19, ADR-0035 amendment).

    `resolver` is an injection point for tests only (defaults to real DNS
    via `_default_resolve_hostname`), so a rebinding scenario -- "resolved
    to a public address at subscribe time, a private one at delivery time"
    -- can be proven deterministically without depending on real external
    DNS or a live attacker-controlled zone.
    """
    hostname = urlparse(url).hostname
    if not hostname:
        raise WebhookDestinationRejectedError(url)
    resolve = resolver or _default_resolve_hostname
    resolved_addresses = resolve(hostname)
    if not resolved_addresses:
        raise WebhookDestinationUnresolvedError(url)
    validated: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw_address in resolved_addresses:
        # An IPv6 scope id (e.g. "fe80::1%eth0") is not part of the address
        # itself for ipaddress's purposes.
        address = ipaddress.ip_address(raw_address.split("%", 1)[0])
        if _is_non_public_address(address):
            # RE-4: a security-policy rejection -- permanent, never retried.
            raise WebhookDestinationRejectedError(url)
        if address not in validated:
            validated.append(address)
    return sorted(validated, key=str)


_format_address_for_url = format_address_for_url


def _pin_url_to_validated_address(
    url: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> tuple[str, str, str]:
    """Phase J-R1B: rewrite `url`'s authority to `address` -- the exact,
    already-validated IP `_validate_destination()` selected -- and return
    `(pinned_url, sni_hostname, host_header)` for the caller to hand to
    httpx. Delegates to `saas_os.infra.egress.pin_url_to_address`, whose
    docstring records the httpcore evidence: connecting to the literal
    address leaves no second resolution, and the `sni_hostname` extension
    keeps TLS certificate verification on the original hostname.
    """
    try:
        return pin_url_to_address(url, address)
    except ValueError as exc:  # pragma: no cover -- callers already validated this
        raise InvalidWebhookUrlError(url) from exc


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
    in this codebase: `saas_os/core/billing/stripe_provider.py::
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
    `saas_os.core.billing.stripe_provider.verify_stripe_webhook_signature()`'s
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

    `tolerance_seconds` defaults to `saas_os.core.webhooks.config.get_webhook_security_config()`'s
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
    (`saas_os/core/webhooks/models.py::WebhookReplayRecord`'s own docstring) --
    a plain `INSERT` inside `tenant_session_scope()`'s transaction,
    which either succeeds (first, legitimate acceptance) or raises
    `IntegrityError` (a concurrent or later duplicate), mapped here to
    `WebhookReplayDetectedError` exactly the way
    `saas_os/core/billing/service.py::create_plan()` already maps its own
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
    outbound-only (`saas_os/core/webhooks/__init__.py`'s own docstring); this is
    the reusable primitive a future inbound receiver (ours or a Product's)
    would call, mirroring `saas_os.core.billing.stripe_provider.
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
    phase may register it with `saas_os.infra.jobs` if unbounded growth becomes
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


def subscribe(tenant_id: uuid.UUID, url: str, *, caller: Caller) -> tuple[WebhookSubscription, str]:
    """Create a subscription for `tenant_id`. Returns the persisted
    record and the raw signing secret -- unlike a bearer credential
    (`saas_os/core/api_keys`), this secret is also needed again later (see
    `saas_os/core/webhooks/models.py`'s docstring for why), so it is returned once
    here for a caller's own UI to display; it is simply never *returned*
    by `get_subscription`/`list_subscriptions` below, and (F-02) never
    even *stored* in plaintext -- `subscription.signing_secret` after this
    call, and every value `get_subscription`/`list_subscriptions` hand
    back, is the encrypted envelope, not `raw_secret`.

    `_validate_url()` rejects a literal non-public IP address here
    immediately (Phase J-R1: J-API-01), but deliberately does not resolve
    a real hostname at subscription time: a name that resolves safely now
    can be repointed at a private/internal address later (DNS rebinding),
    so a one-time check here would create false confidence rather than
    real protection. The actual, repeated enforcement point is
    `_validate_destination()`, called fresh inside `_deliver_webhook()`
    immediately before every real outbound attempt -- the only place this
    module makes a real network connection.

    Authority (RE-4, ADR-0031's model): a subscription is a channel that
    sends tenant data to an arbitrary destination, so `caller` must hold
    `(webhook_subscription, create)` at `tenant_id` -- evaluated by `can()`
    inside this insert's own transaction -- or be a provisioning
    `SystemCaller`. Audited as `webhook.subscription_created` in that same
    transaction; never the secret, never the URL.
    """
    require_caller("subscribe", caller)
    _validate_url(url)
    require_open_tenant(tenant_id)
    raw_secret = secrets.token_urlsafe(_SECRET_BYTES)
    encrypted_secret = _encrypt_signing_secret(tenant_id, raw_secret)

    with tenant_session_scope(tenant_id) as session:
        authorize_caller(
            caller,
            session=session,
            operation="subscribe",
            tenant_id=tenant_id,
            resource="webhook_subscription",
            action="create",
            system_authorities=_PROVISIONING,
        )
        lock_open_tenant(session, tenant_id)
        subscription = WebhookSubscription(
            tenant_id=tenant_id, url=url, signing_secret=encrypted_secret
        )
        session.add(subscription)
        session.flush()
        record_in_transaction(
            session,
            caller=caller,
            tenant_id=tenant_id,
            action="webhook.subscription_created",
            resource_type="webhook_subscription",
            resource_id=str(subscription.id),
        )
        session.refresh(subscription)
        session.expunge(subscription)
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


def unsubscribe(tenant_id: uuid.UUID, subscription_id: uuid.UUID, *, caller: Caller) -> None:
    """Remove a subscription. Idempotent: removing an already-removed
    subscription is a no-op, not an error (mirrors `saas_os/core/rbac/service.py::
    remove_role` and `saas_os/core/api_keys/service.py::revoke_api_key`'s precedent)
    -- writes no audit entry when there was nothing to remove.

    Authority (RE-4): `caller` must hold `(webhook_subscription, delete)` at
    `tenant_id` -- checked first, inside the deletion's own transaction, so
    an unauthorized caller learns nothing about which subscriptions exist --
    or be a provisioning `SystemCaller`. The lookup runs under `tenant_id`'s
    RLS scope, so another tenant's subscription is never found (and never
    deleted). Audited as `webhook.subscription_deleted` in the same
    transaction as the delete."""
    require_caller("unsubscribe", caller)
    with tenant_session_scope(tenant_id) as session:
        authorize_caller(
            caller,
            session=session,
            operation="unsubscribe",
            tenant_id=tenant_id,
            resource="webhook_subscription",
            action="delete",
            system_authorities=_PROVISIONING,
        )
        subscription = session.get(WebhookSubscription, subscription_id)
        if subscription is None or subscription.tenant_id != tenant_id:
            return
        session.delete(subscription)
        session.flush()
        record_in_transaction(
            session,
            caller=caller,
            tenant_id=tenant_id,
            action="webhook.subscription_deleted",
            resource_type="webhook_subscription",
            resource_id=str(subscription_id),
        )


# --- Delivery ----------------------------------------------------------------


async def _deliver_webhook(context: TenantJobContext, payload: TenantJobPayload) -> None:
    """The registered job handler: re-reads the subscription (secret
    included) from the database at execution time -- the secret is never
    carried in the job payload itself (module docstring) -- signs the
    event body, and POSTs it. Run by the durable outbox dispatcher (RE-2),
    which owns retries; this function never implements retry/backoff
    itself. It classifies its failures (RE-4): a transient one
    (`WebhookDeliveryError`, `WebhookDestinationUnresolvedError`) is retried
    with the outbox's bounded backoff; a permanent one -- a malformed event
    (`MalformedWebhookEventError`), a destination policy rejection
    (`WebhookDestinationRejectedError`) or a status resending cannot change
    (`WebhookPermanentDeliveryError`) -- is a `saas_os.core.outbox.PermanentEventError`
    and dead-letters the event at once.

    P1.10: `event_id` is generated once, in `trigger_event()`, and stays
    fixed across every retry `saas_os.infra.jobs` performs for this delivery --
    a receiver's replay ledger needs a stable identity across legitimate
    retries. `timestamp`, in contrast, is computed fresh on *every*
    attempt (here, at actual send time), never reused from an earlier
    attempt or fixed at enqueue time: a retry can happen well after
    `saas_os.infra.jobs`' own backoff delay, and a stale timestamp from the
    original enqueue would make an otherwise-legitimate retry fail a
    receiver's freshness check for no security reason. A fresh timestamp
    each attempt is what lets legitimate internal retries keep working
    without weakening replay protection (this checkpoint's own required
    distinction between "legitimate internal delivery retry" and
    "replayed externally received webhook").
    """
    # A tenant job (`register_tenant_job`, Foundation Enforcement FE-5): a
    # missing or malformed payload never reaches this handler -- the worker
    # dead-letters it as a contract violation without retrying.
    tenant_id = context.tenant_id
    subscription_id, event_id, event_type, event_data = _parse_delivery(payload.data)

    # PRIV-03 P7 (privacy re-audit RA-03) / F-09 (platform readiness
    # audit): the execution-time lifecycle fence. `trigger_event()`'s
    # `require_open_tenant()` only proves the tenant was open when the job
    # was *queued*; between that and this point lie queue latency, retries
    # and worker downtime, and the tenant may have committed
    # DELETED/PURGING/PURGED in the meantime. `tenant_job_session()`
    # (`saas_os.core.tenancy`, F-09's shared primitive -- the exact two-phase
    # pre-check + in-transaction `lock_open_tenant()` re-check this
    # handler implemented ad hoc before F-09 existed) closes that window:
    # a closed tenant's delivery is dropped here -- before the
    # subscription/secret is read, before the request is built, before any
    # network I/O -- and dropping is a normal return, never an exception:
    # `saas_os.infra.jobs`' wrapper would otherwise retry and dead-letter a job
    # that must simply not run (the same shape `control_plane...
    # continuous_loop`'s `TENANT_CLOSED` outcome uses). What this fence
    # cannot do is recall a request already on the wire: once the secret
    # has been read under the lock, the outbound POST proceeds even if the
    # tenant closes during the network call.
    try:
        with tenant_job_session(tenant_id) as session:
            # RE-5: an HTTP delivery cannot join a database transaction, so a
            # repeated execution of an event this consumer already delivered
            # (completion recorded below) stops here, before any request. The
            # identity is the outbox event -- one per (occurrence,
            # subscription) -- never the shared webhook `event_id`, so one
            # subscription's delivery never suppresses another's.
            if context.event_id is not None and event_consumption_recorded(
                session,
                tenant_id=tenant_id,
                consumer=WEBHOOK_DELIVERY_EVENT_TYPE,
                event_id=context.event_id,
            ):
                logger.info(
                    "webhook_delivery_duplicate_suppressed",
                    extra={"webhook_subscription_id": str(subscription_id)},
                )
                return
            subscription = session.get(WebhookSubscription, subscription_id)
            if subscription is None:
                # The subscription was removed after this delivery was
                # enqueued -- nothing to deliver to, and not a transient
                # failure worth retrying.
                return
            url = subscription.url
            # F-02: decrypted only here, immediately before it is needed
            # to sign this one delivery attempt -- never earlier, never
            # cached across attempts/retries, and `subscription` itself
            # (still carrying only the encrypted column value) is never
            # otherwise inspected for its secret.
            secret = _decrypt_signing_secret(tenant_id, subscription.signing_secret)
    except TenantClosedError:
        logger.info(
            "webhook_delivery_dropped_tenant_closed",
            extra={"webhook_subscription_id": str(subscription_id)},
        )
        return
    except TenantNotFoundError:
        return  # no tenant, no subscription -- the pre-existing silent outcome

    # Phase J-R1 (J-API-01) / Phase J-R1B: re-validated fresh on every single
    # delivery attempt, including retries -- never only once at subscription
    # time. `_pin_url_to_validated_address()` then rewrites the request's
    # authority to exactly this validated address, so httpx/httpcore never
    # gets a hostname of its own to resolve -- there is no second DNS
    # lookup between this security decision and the actual TCP connection
    # (see that function's own docstring for the installed-httpcore
    # evidence). The original hostname is preserved for TLS SNI/certificate
    # verification and the HTTP `Host` header, never for the TCP connection
    # itself.
    #
    # ADR-0035 amendment (2026-10-19): the whole attempt -- resolution, every
    # address tried, the request and the response status -- shares one
    # total deadline of `_DELIVERY_TIMEOUT_SECONDS`, and resolution runs in
    # a worker thread, not on the event loop that also runs other tenants'
    # jobs. An expired deadline is a transient failure, retried by the
    # outbox like any other (`WebhookDeliveryError`). The resolver thread
    # itself cannot be interrupted and finishes in the background.
    body = _encode_event(event_id, event_type, event_data)
    status_code = await _send_signed(subscription_id, url, secret, body)

    if status_code >= 300:
        # RE-4: a status that resending the same event cannot change ends the
        # delivery now; any other failure (408, 429, 5xx, 401/403/404, ...)
        # is retried within the outbox's bounded budget. A redirect is never
        # followed -- its target was never validated -- so it is permanent.
        if 300 <= status_code < 400 or status_code in _PERMANENT_STATUSES:
            raise WebhookPermanentDeliveryError(subscription_id, f"HTTP {status_code}")
        raise WebhookDeliveryError(subscription_id, f"HTTP {status_code}")

    # RE-5: the receiver accepted it -- record the completion, so a repeated
    # execution of this event does not deliver it again. If the worker dies
    # before this commits, or this write fails (raised: the event is
    # retried), the receiver can get the event twice: at-least-once, which
    # its replay check on the stable `event_id` absorbs.
    if context.event_id is not None:
        record_event_consumption(
            tenant_id, consumer=WEBHOOK_DELIVERY_EVENT_TYPE, event_id=context.event_id
        )


# Validated addresses one delivery attempt connects to at most, as for AI
# egress (`StrictEgressPolicy.max_addresses_tried`).
_MAX_ADDRESSES_TRIED = 2


async def _send_signed(subscription_id: uuid.UUID, url: str, secret: str, body: bytes) -> int:
    """Resolve and validate `url`'s destination, sign `body` and POST it,
    all within one `_DELIVERY_TIMEOUT_SECONDS` deadline; return the
    response status. The signature's timestamp is taken after resolution,
    immediately before sending."""
    deadline = Deadline.after(_DELIVERY_TIMEOUT_SECONDS)
    try:
        async with asyncio.timeout(deadline.remaining()):
            addresses = await asyncio.to_thread(_validate_destination_addresses, url)
            timestamp = int(datetime.now(UTC).timestamp())
            headers = {
                "Content-Type": "application/json",
                _SIGNATURE_HEADER: compute_signed_envelope(secret, body, timestamp),
                _TIMESTAMP_HEADER: str(timestamp),
            }
            return await _post_to_validated_addresses(
                subscription_id, url, addresses, body, headers, deadline
            )
    except TimeoutError as exc:
        raise WebhookDeliveryError(subscription_id, "deadline_expired") from exc


async def _post_to_validated_addresses(
    subscription_id: uuid.UUID,
    url: str,
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    body: bytes,
    headers: Mapping[str, str],
    deadline: Deadline,
) -> int:
    """POST `body` to the first of `addresses` that accepts a connection and
    return the response status. The next address is tried only when
    connecting failed (`httpx.ConnectError`, `httpx.ConnectTimeout`), so no
    byte of the request was sent; any other failure ends the attempt."""
    last_error = "deadline_expired"
    for address in addresses[:_MAX_ADDRESSES_TRIED]:
        if deadline.expired:
            break
        pinned_url, sni_hostname, host_header = _pin_url_to_validated_address(url, address)
        try:
            return await _post_once(
                pinned_url, sni_hostname, host_header, body, headers, deadline.remaining()
            )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last_error = type(exc).__name__
        except httpx.HTTPError as exc:
            raise WebhookDeliveryError(subscription_id, type(exc).__name__) from exc
    raise WebhookDeliveryError(subscription_id, last_error)


async def _post_once(
    pinned_url: str,
    sni_hostname: str,
    host_header: str,
    body: bytes,
    headers: Mapping[str, str],
    remaining_seconds: float,
) -> int:
    """One POST to one pinned address; every httpx timeout is capped by the
    time left on the delivery's deadline."""
    # follow_redirects=False is httpx's own default (unchanged here --
    # made explicit as a security-relevant property, not a behavior
    # change): a redirect response is returned to this function as a
    # plain >=300 response, below, never transparently followed to a
    # second, unvalidated destination.
    #
    # CP-06-WH-01 (Phase J audit): streamed via `client.stream()`, not
    # `client.post()` -- this function only ever inspects
    # `response.status_code`, below, never the response body, so the
    # body is never read at all. `client.post()` implicitly buffers
    # the full response body into memory before returning; the
    # destination is an attacker-influenced URL (a tenant's own
    # chosen webhook endpoint, explicitly in this module's threat
    # model), so a malicious/compromised destination returning an
    # arbitrarily large body could otherwise exhaust the arq worker
    # process's memory -- shared across every tenant's background
    # jobs, and amplified by `saas_os.infra.jobs`' own retry-with-backoff.
    # Exiting this `async with` block closes the connection without
    # draining an unread body; no size cap is needed because nothing
    # here ever reads a byte of it.
    #
    # `trust_env=False` (ADR-0035 amendment of 2026-10-18, ADR-0054 Q2):
    # no proxy, `.netrc` or certificate setting comes from the
    # environment. A proxy would receive the request instead of the
    # validated, pinned address, and could reach addresses the
    # destination check refuses.
    async with (
        httpx.AsyncClient(
            timeout=max(remaining_seconds, 0.001), follow_redirects=False, trust_env=False
        ) as client,
        client.stream(
            "POST",
            pinned_url,
            content=body,
            headers={"Host": host_header, **headers},
            extensions={"sni_hostname": sni_hostname},
        ) as response,
    ):
        return response.status_code


# RE-4: responses that mean "this event will never be accepted": malformed
# (400), gone for good (410), too large (413), unprocessable (422). Auth and
# not-found errors stay retryable -- a receiver's misconfiguration can be
# fixed while the event is still within its retry budget.
_PERMANENT_STATUSES = frozenset({400, 410, 413, 422})


def _parse_delivery(
    data: Mapping[str, object],
) -> tuple[uuid.UUID, uuid.UUID, str, dict[str, object]]:
    """The delivery event's fields, validated (RE-4). A malformed event is
    permanent (`MalformedWebhookEventError`) -- it can never be delivered --
    and the error names the problem, never the payload."""
    try:
        subscription_id = uuid.UUID(str(data["subscription_id"]))
        event_id = uuid.UUID(str(data["event_id"]))
    except (KeyError, ValueError) as exc:
        raise MalformedWebhookEventError("missing or invalid subscription_id/event_id") from exc
    event_type = data.get("event_type")
    event_data = data.get("event_data")
    if not isinstance(event_type, str) or not event_type:
        raise MalformedWebhookEventError("missing or invalid event_type")
    if not isinstance(event_data, dict):
        raise MalformedWebhookEventError("event_data is not an object")
    return subscription_id, event_id, event_type, event_data


def _encode_event(event_id: uuid.UUID, event_type: str, event_data: dict[str, object]) -> bytes:
    return json.dumps(
        {"event_id": str(event_id), "event_type": event_type, "data": event_data}
    ).encode("utf-8")


WEBHOOK_JOB_FUNCTIONS: list[Function] = [register_tenant_job(_deliver_webhook)]


# RE-1 (transactional outbox): the outbox event type a webhook delivery is
# recorded under. One event per (occurrence, subscription); its payload is
# exactly the data `_deliver_webhook()` consumes, so the dispatcher (RE-2)
# maps one outbox row to one delivery.
WEBHOOK_DELIVERY_EVENT_TYPE = "webhook.delivery"


def trigger_event(
    session: Session,
    tenant_id: uuid.UUID,
    event_type: str,
    event_data: dict[str, object],
) -> list[uuid.UUID]:
    """Record delivery of `event_type` to every one of `tenant_id`'s current
    subscriptions, in the caller's own transaction (RE-1, transactional
    outbox): one `saas_os.core.outbox` event per subscription, appended with
    `saas_os.core.outbox.append_event()` on `session` -- which must be the caller's
    `tenant_session_scope(tenant_id)` session, the same transaction as the
    mutation that caused the event. Nothing is committed here and no queue
    is contacted: the events become durable exactly when the caller
    commits, and vanish if it rolls back. Returns the outbox event ids (one
    per subscription, in subscription-id order; empty with no
    subscriptions). Publishing them is the dispatcher's job (RE-2).

    The subscription set is read in that same transaction, and the tenant
    lifecycle is checked there too (`lock_open_tenant()`, `core.tenants`
    `FOR SHARE`), so a closure cannot commit between the check and the
    events: a closed tenant raises `TenantClosedError`, as before.

    P1.10: one webhook `event_id` (a fresh UUID) is generated *once* here
    and shared by every subscription's delivery of this occurrence -- it is
    genuinely the same event, just fanned out to multiple destinations.
    Each subscription still gets its own independent signature (its own
    `signing_secret`), but the shared `event_id` is what a receiver's
    replay ledger keys on, and it is stored in each outbox event, so every
    retry of a delivery remains recognizable as "the same event".

    `event_data` must be JSON (it is stored durably and delivered as JSON).
    The signing secret never enters the event: `_deliver_webhook()` re-reads
    it at delivery time."""
    lock_open_tenant(session, tenant_id)
    subscription_ids = (
        session.execute(
            select(WebhookSubscription.id)
            .where(WebhookSubscription.tenant_id == tenant_id)
            .order_by(WebhookSubscription.id)
        )
        .scalars()
        .all()
    )
    event_id = uuid.uuid4()
    return [
        append_event(
            session,
            tenant_id=tenant_id,
            event_type=WEBHOOK_DELIVERY_EVENT_TYPE,
            aggregate_type="webhook_subscription",
            aggregate_id=str(subscription_id),
            payload={
                "subscription_id": str(subscription_id),
                "event_id": str(event_id),
                "event_type": event_type,
                "event_data": event_data,
            },
        )
        for subscription_id in subscription_ids
    ]


# RE-2 (durable outbox dispatcher): the consumer of each outbox event type
# this module produces. The dispatcher runs it in-process, inside its own
# outbox job, with the event's payload -- the same handler, payload and
# fences as the registered job above.
OUTBOX_EVENT_HANDLERS: dict[
    str, Callable[[TenantJobContext, TenantJobPayload], Awaitable[None]]
] = {WEBHOOK_DELIVERY_EVENT_TYPE: _deliver_webhook}


# --- PRIV-03 Phase P3: tenant purge ------------------------------------------


def purge_tenant_webhooks(tenant_id: uuid.UUID) -> int:
    """Delete every replay-ledger row and then every subscription
    `tenant_id` owns -- one module-owned step of
    `saas_os.core.tenancy.purge_tenant()`, only callable in the purge phase
    (`TenantNotPurgingError` otherwise). Deleting a subscription destroys
    its `signing_secret` outright, so no webhook credential survives the
    purge. Replay records go first (`subscription_id` FK). Runs under
    `tenant_session_scope()`/RLS; idempotent. Returns the total rows
    removed across both tables.
    """
    require_purging_tenant(tenant_id)
    deleted = 0
    with tenant_session_scope(tenant_id) as session:
        replay_rows = (
            session.execute(
                select(WebhookReplayRecord)
                .where(WebhookReplayRecord.tenant_id == tenant_id)
                .order_by(WebhookReplayRecord.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for row in replay_rows:
            session.delete(row)
            deleted += 1
        session.flush()
        subscriptions = (
            session.execute(
                select(WebhookSubscription)
                .where(WebhookSubscription.tenant_id == tenant_id)
                .order_by(WebhookSubscription.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for subscription in subscriptions:
            session.delete(subscription)
            deleted += 1
    return deleted
