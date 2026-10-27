"""`ResendEmailProvider` -- the `EmailProvider` for Resend's HTTP API
(ADR-0058, added the way ADR-0057 section 8 prescribes). The only file in
`saas_os/core/email` that knows Resend's request and response shapes, the
same boundary `smtp_provider.py` draws around SMTP.

**Transport**: one `POST https://api.resend.com/emails` per send, through
`saas_os.infra.egress.StrictEgressClient` (the existing `httpx` dependency;
no vendor SDK). That client verifies the certificate against certifi's
bundle, refuses non-public destinations, follows no redirect, reads no
proxy or trust-store setting from the environment and bounds the response
size. The endpoint is a constant: no setting can point the API key at
another host.

**Sync interface**: `EmailProvider.send()` is synchronous (the notification
job calls it through `asyncio.to_thread`, ADR-0057 section 5). The egress
client is async, so each send runs it with `asyncio.run()`; if the calling
thread already runs an event loop, the coroutine runs on a short-lived
helper thread instead, and the caller blocks exactly as it would on the
SMTP adapter.

**Secret**: `RESEND_API_KEY` is read once, at construction, through
`saas_os.infra.secrets.get_secrets_provider()`, kept only in this instance's
private attribute, sent only in the `Authorization` header, and never
logged or included in an exception. The raised `EmailProviderError` is not
chained to the egress or `httpx` exception: `httpx` attaches the request
(its headers and body) to its exceptions, so the chain would carry the key
and the message to whatever inspects the error.

**Timeout**: `EMAIL_TIMEOUT_SECONDS` is the total deadline for one send
(DNS, connect, TLS, request and response) and caps the connect and read
timeouts. `getaddrinfo` cannot be interrupted, so the adapter resolves on a
daemon thread it never waits for (`_resolve`); with the loop's own executor,
closing the per-send event loop would wait for a stalled lookup. At most
`_MAX_PENDING_LOOKUPS` lookups run at once; past that a send fails as
unresolved (transient) instead of starting another thread. The resolved
addresses are still validated and pinned by the egress client.

**Failures** raise `EmailProviderError` exactly once; there is no retry
loop here (retries belong to the outbox dispatcher and `saas_os.infra.jobs`).
`reply_code` is the HTTP status. `reason` is Resend's error `name` when it
is one of the documented names, otherwise a fixed word; Resend's `message`
text is never copied. Only `400` and `422` (the request itself is invalid,
so the same message cannot succeed) are `permanent`. Authentication,
unverified-domain and quota refusals (`401`, `403`), rate limits (`429`),
idempotency conflicts (`409`), server errors, network failures, timeouts and
an unreadable `2xx` stay transient: an operator can fix the first group,
and the rest may succeed later or are ambiguous.

**Duplicates**: when the caller supplies `EmailMessage.message_id` (the
notification job derives it from the outbox event id), the request carries
an `Idempotency-Key` derived from it, so a retry within Resend's documented
24-hour window is not sent again, and the message carries the same
`Message-ID` header. Without a `message_id` nothing identifies a retry, so
no key is sent. Either way delivery is at-least-once, never exactly-once:
after 24 hours, or for a retry whose body differs, a resend is a new email.

**Result**: `EmailSendResult.provider_message_id` is Resend's email id, the
identifier its dashboard and API use. Acceptance by the API is not delivery
to an inbox.

**Not supported**: `EmailMessage.metadata` is not forwarded (Resend tags
accept a narrower character set); no attachments, CC/BCC, templates,
scheduling, batch sending or delivery webhooks.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from saas_os.core.email.config import ResendConfig, get_resend_config
from saas_os.core.email.errors import EmailConfigurationError, EmailProviderError
from saas_os.core.email.provider import EmailMessage, EmailSendResult
from saas_os.infra.egress import (
    Deadline,
    EgressError,
    EgressResolutionError,
    EgressResponse,
    StrictEgressClient,
    StrictEgressPolicy,
    get_egress_proxy,
)
from saas_os.infra.secrets import get_secrets_provider

RESEND_API_URL = "https://api.resend.com/emails"

# Resend's documented limit on `to` (https://resend.com/docs/api-reference/emails/send-email).
_MAX_RECIPIENTS = 50
# A success body is `{"id": "<uuid>"}`; an error body is a few hundred bytes.
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_PROVIDER_ID_LENGTH = 256

# Statuses that mean this exact request is invalid, so resending it cannot
# succeed (ADR-0057 section 5's definition of permanent).
_PERMANENT_STATUSES = frozenset({400, 422})

# Resend's documented error names (https://resend.com/docs/api-reference/errors).
# Only these are copied into `EmailProviderError.reason`; anything else
# becomes `http_error`, so a response can never inject text into it.
_KNOWN_ERROR_NAMES = frozenset(
    {
        "application_error",
        "concurrent_idempotent_requests",
        "daily_quota_exceeded",
        "email_above_quota",
        "invalid_attachment",
        "invalid_idempotency_key",
        "invalid_idempotent_request",
        "invalid_parameter",
        "invalid_permission",
        "method_not_allowed",
        "missing_api_key",
        "missing_required_field",
        "missing_required_parameter",
        "monthly_quota_exceeded",
        "not_found",
        "rate_limit_exceeded",
        "resource_locked",
        "restricted_api_key",
        "service_unavailable",
        "suspended_api_key",
        "validation_error",
    }
)


# Lookups that may outlive the send that started them (a stalled resolver).
# Above the worker's default concurrency (arq's 10 jobs), so a healthy
# resolver never hits it; it only caps threads stuck in `getaddrinfo`.
_MAX_PENDING_LOOKUPS = 16
_pending_lookups = threading.BoundedSemaphore(_MAX_PENDING_LOOKUPS)


def _deliver(answer: asyncio.Future[list[str] | None], found: list[str] | None) -> None:
    if not answer.done():  # the send may have given up already
        answer.set_result(found)


async def _resolve(hostname: str, port: int) -> list[str]:
    """`saas_os.infra.egress.default_resolver`'s answer (every address, in
    resolver order, without duplicates), from a daemon thread that nothing
    joins, so the send's deadline holds when DNS stalls (module docstring)."""
    slots = _pending_lookups
    if not slots.acquire(blocking=False):
        raise EgressResolutionError()
    loop = asyncio.get_running_loop()
    answer: asyncio.Future[list[str] | None] = loop.create_future()

    def lookup() -> None:
        found: list[str] | None
        try:
            infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            found = [str(info[4][0]) for info in infos]
        except OSError:
            found = None
        finally:
            slots.release()
        # The loop is closed if the send has already returned.
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(_deliver, answer, found)

    threading.Thread(target=lookup, name="resend-resolve", daemon=True).start()
    found = await answer
    if found is None:
        raise EgressResolutionError()
    return list(dict.fromkeys(found))


def _idempotency_key(message_id: str) -> str:
    """A fixed-length key (Resend allows 1-256 characters) that is the same
    for every attempt of one message and reveals nothing about it."""
    return "saas-os-email-" + hashlib.sha256(message_id.encode("utf-8")).hexdigest()


def _is_printable_ascii(value: str) -> bool:
    return all(0x21 <= ord(ch) <= 0x7E for ch in value)


def _json_object(body: bytes) -> dict[str, object] | None:
    try:
        parsed = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _error_reason(body: bytes) -> str:
    parsed = _json_object(body)
    name = parsed.get("name") if parsed is not None else None
    return name if isinstance(name, str) and name in _KNOWN_ERROR_NAMES else "http_error"


def _provider_id(body: bytes) -> str | None:
    parsed = _json_object(body)
    value = parsed.get("id") if parsed is not None else None
    if (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_PROVIDER_ID_LENGTH
        and _is_printable_ascii(value)
    ):
        return value
    return None


class ResendEmailProvider:
    """A real `EmailProvider` backed by Resend's HTTP API. Construction
    resolves configuration and the API key and builds the egress client; it
    makes no network call. `client` is a seam for tests."""

    name = "resend"

    def __init__(
        self,
        *,
        config: ResendConfig | None = None,
        client: StrictEgressClient | None = None,
    ) -> None:
        self._config = config or get_resend_config()
        api_key = get_secrets_provider().get("RESEND_API_KEY")
        if not api_key:
            raise EmailConfigurationError(
                "RESEND_API_KEY is not set. Provide it through the secrets provider "
                "(see docs/ADR/0058-resend-email-provider.md)."
            )
        if not _is_printable_ascii(api_key):
            raise EmailConfigurationError(
                "RESEND_API_KEY contains whitespace or a non-printable character."
            )
        self._api_key = api_key
        if client is None:
            timeout = float(self._config.timeout_seconds)
            try:
                # ADR-0059: through the egress proxy when one is configured;
                # TLS is still verified on api.resend.com.
                proxy = get_egress_proxy()
                policy = StrictEgressPolicy(
                    connect_timeout_seconds=timeout,
                    read_timeout_seconds=timeout,
                    max_response_bytes=_MAX_RESPONSE_BYTES,
                )
                if proxy is not None:
                    client = StrictEgressClient(policy, resolver=_resolve, proxy=proxy)
                else:
                    client = StrictEgressClient(policy, resolver=_resolve)
            except EgressError as exc:
                raise EmailConfigurationError(
                    f"The Resend provider cannot start: {exc.reason}."
                ) from None
        self._client = client

    def __repr__(self) -> str:
        return f"ResendEmailProvider(timeout_seconds={self._config.timeout_seconds})"

    def _request(self, message: EmailMessage) -> tuple[dict[str, str], bytes]:
        payload: dict[str, object] = {
            "from": message.sender,
            "to": list(message.to),
            "subject": message.subject,
            "text": message.text_body,
        }
        if message.html_body is not None:
            payload["html"] = message.html_body
        if message.reply_to is not None:
            payload["reply_to"] = message.reply_to
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "saas-os",
        }
        if message.message_id is not None:
            payload["headers"] = {"Message-ID": message.message_id}
            headers["Idempotency-Key"] = _idempotency_key(message.message_id)
        return headers, json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def _post(self, headers: dict[str, str], content: bytes) -> EgressResponse:
        async def call() -> EgressResponse:
            return await self._client.post(
                RESEND_API_URL,
                headers=headers,
                content=content,
                deadline=Deadline.after(self._config.timeout_seconds),
            )

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(call())
        # Called from a thread that runs an event loop: asyncio.run() is not
        # allowed there, so run the request on its own thread and wait.
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="resend-send") as pool:
            return pool.submit(asyncio.run, call()).result()

    def _submit(self, message: EmailMessage) -> EgressResponse | str:
        """The response, or the egress failure's reason. Returning the reason
        rather than raising inside the handler leaves the `EmailProviderError`
        unchained, and keeps the request headers out of `send()`'s frame."""
        headers, content = self._request(message)
        try:
            return self._post(headers, content)
        except EgressError as exc:
            return exc.reason

    def send(self, message: EmailMessage) -> EmailSendResult:
        if len(message.to) > _MAX_RECIPIENTS:
            raise EmailProviderError("send", "too_many_recipients", permanent=True)
        response = self._submit(message)
        if isinstance(response, str):
            # Transient, including a timeout after the request may have been
            # sent: the Idempotency-Key (when there is one) covers the retry.
            raise EmailProviderError("send", response)

        status = response.status_code
        if 200 <= status < 300:
            provider_id = _provider_id(response.body)
            if provider_id is None:
                # Probably accepted, but unconfirmed: transient (ADR-0057
                # section 5 keeps every ambiguous outcome transient).
                raise EmailProviderError("send", "malformed_response", reply_code=status)
            return EmailSendResult(accepted=True, provider_message_id=provider_id)
        raise EmailProviderError(
            "send",
            _error_reason(response.body),
            permanent=status in _PERMANENT_STATUSES,
            reply_code=status,
        )
