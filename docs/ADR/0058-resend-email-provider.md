# ADR-0058: Resend email provider

Status: Accepted (2026-10-25). Proposed 2026-10-24; the repository owner accepted it on 2026-10-25 after reviewing the implementation and its validation, with the residual limitations below unchanged. Implemented on branch `feat/resend-email-provider` and merged into `main` by pull request #102 (`89224c0`). Not tested against the live Resend API. **Amended 2026-10-25, before merge, after an independent review:** the implementation now makes two stated guarantees hold that did not fully hold before — the total deadline when DNS stalls (section 1) and an exception that carries no request (section 6); the decision is otherwise unchanged.
Date: 2026-10-24
Supersedes / Superseded by: — (adds a provider by the procedure in ADR-0057 section 8; ADR-0057 is unchanged)
Related: ADR-0012 (secrets), ADR-0020 (logging redaction), ADR-0032/0033/0036 (outbox, dispatcher, consumer idempotency), ADR-0041 (optional dependencies), ADR-0054 sections 8a/8b (strict egress), ADR-0057 (deployment-level email provider selection).

## Context

- ADR-0057 made the deployment's email provider a choice from a fixed, built-in map (`EMAIL_PROVIDER`: `smtp`, `mailpit`). Its section 8 says how a provider is added: a module under `saas_os/core/email` that implements `EmailProvider` and raises only `EmailProviderError`; any vendor SDK behind an optional extra, or an HTTP adapter on the existing `httpx` dependency and `saas_os.infra.egress`; credentials only through `SecretsProvider`; the name in `EMAIL_PROVIDER_NAMES` and the factory in `selection._PROVIDER_FACTORIES`; tests like the SMTP adapter's.
- The owner asked on 2026-10-24 for Resend, a transactional-email HTTP API, as a reusable provider; products keep their own keys, sender identities and content. Resend also offers SMTP, which the `smtp` provider can already use; the HTTP API adds an idempotency key and a provider email id.
- `EmailProvider.send()` is synchronous. The notification job calls it with `asyncio.to_thread` (ADR-0057 section 5). `saas_os.infra.egress.StrictEgressClient` is asynchronous.

## Options considered

1. **HTTP adapter on `StrictEgressClient` (chosen).** No new dependency. Pinned, public-only HTTPS, no redirects, no environment proxies, a bounded response and one total deadline, which the AI provider adapters already use.
2. **The official `resend` Python SDK behind an optional extra.** A new dependency for one POST, and its transport (its own `requests` session, redirects, proxies, error texts in exceptions) would sit outside the egress rules.
3. **Document Resend's SMTP endpoint with the `smtp` provider only.** Works today, with no code. There is no idempotency key, so a retry after an ambiguous failure is always a second email. It remains available.

## Decision

### 1. Selection and configuration

- `EMAIL_PROVIDER=resend` selects `ResendEmailProvider` (`saas_os/core/email/resend_provider.py`). It is a third entry in the fixed map, not a registry. Nothing else about selection changes: unset still means SMTP, an unknown name is still an error, and a failing Resend configuration never falls back to another provider.
- `RESEND_API_KEY` is read once, at construction, through `SecretsProvider`. A missing or empty key, or one containing anything other than printable ASCII (whitespace, control or non-ASCII characters, which could break the header), is an `EmailConfigurationError` that never contains the value. The key is sent only in the `Authorization: Bearer` header.
- The sender is `EMAIL_DEFAULT_SENDER` (ADR-0057 section 2). Resend accepts it only from a domain verified in the product's Resend account.
- `EMAIL_TIMEOUT_SECONDS` (default 10) is the total deadline of one send (DNS, connect, TLS, request and response) and caps the connect and read timeouts. `getaddrinfo` cannot be interrupted, and with the event loop's default executor `asyncio.run()` waits for a stalled lookup when it closes its loop (up to 300 seconds in CPython), so the adapter resolves `api.resend.com` on a daemon thread it never waits for: `send()` returns at the deadline and the lookup finishes in the background. At most 16 such lookups run at once per process; beyond that a send fails at once as `unresolved` (transient) rather than starting another thread. The egress client still validates every resolved address (all public, or the destination is refused) and pins the connection to it, with TLS, SNI and `Host` on the name.
- The endpoint `https://api.resend.com/emails` is a constant. No setting can redirect the API key to another host.
- Resend is allowed in every environment. Unlike Mailpit it is a real provider, so a development deployment that selects it sends real mail.
- With `EMAIL_PROVIDER=resend` the worker's startup check (`validate_email_configuration()`) builds the provider (it reads the key and builds the egress client, which refuses an `httpx`/`httpcore` version outside the tested range; no network call) and requires `EMAIL_DEFAULT_SENDER`.
- **Calling convention.** `send()` stays synchronous, as `EmailProvider` requires. It runs the asynchronous egress client with `asyncio.run()`; when the calling thread already runs an event loop, the request runs on a short-lived helper thread and the caller blocks until it finishes, as it would on the SMTP adapter. The notification job calls it through `asyncio.to_thread` (ADR-0057 section 5).

### 2. Request

One `POST` per send with JSON `from`, `to` (at most 50, Resend's limit; more is a permanent error before any request), `subject`, `text`, and `html`/`reply_to` when set. `EmailMessage.metadata` is not forwarded. No attachments, CC/BCC, templates, scheduling, batches or tags.

### 3. Failures

`EmailProviderError` is raised once; the adapter never retries (the outbox dispatcher and `saas_os.infra.jobs` own retries). `reply_code` is the HTTP status. `reason` is Resend's error `name` only when it is one of the names documented at https://resend.com/docs/api-reference/errors, otherwise `http_error`; Resend's `message` text is never copied.

| Outcome | Permanent | Why |
| --- | --- | --- |
| `400`, `422` | yes | The request itself is invalid; the same message cannot succeed |
| more than 50 recipients | yes | Refused before sending |
| `401`, `403` (key, permission, unverified domain) | no | An operator can fix it; ADR-0057 keeps authentication transient |
| `404`, `405` | no | Not a property of the message |
| `409` (idempotency conflict, concurrent request) | no | May succeed later |
| `429` (rate limit, daily or monthly quota) | no | `Retry-After` is not read; the dispatcher's schedule applies |
| `5xx`, network failure, TLS failure, timeout | no | May succeed later, or is ambiguous |
| `2xx` without a readable `id` | no | Probably accepted but unconfirmed: ambiguous outcomes stay transient (ADR-0057 section 5) |
| redirect, oversized response, non-public address | no | Refused by the egress client |

The notification job dead-letters a permanent failure after one attempt (`NotificationPermanentDispatchError`) and retries the rest, as it does for SMTP. Its `email_send_failed` log field `smtp_reply_code` carries the HTTP status for this provider; the field name is unchanged.

### 4. Duplicates

- When `EmailMessage.message_id` is set (the notification job derives it from the outbox event id), the request carries `Idempotency-Key: saas-os-email-<sha256 of the Message-ID>` and the custom header `Message-ID`. Every attempt of one event therefore sends the same key, and Resend's documented idempotency (keys expire after 24 hours) prevents a duplicate email for a retry within that window. The key is a hash: it does not contain the `Message-ID`, the event id or the domain.
- Without a `message_id` there is nothing to identify a retry, so no key is sent.
- **At-least-once, never exactly-once.** A retry after 24 hours, or one whose body differs (Resend then answers `409 invalid_idempotent_request` until the key expires), can send a second email. The notification job's `Message-ID` ends in the sender's domain (ADR-0057), so a retry after `EMAIL_DEFAULT_SENDER` moves to another domain carries a different key and is submitted as a new request, not deduplicated against the earlier one; a new sender in the same domain keeps the key and gets the `409`. Whether Resend keeps a caller-supplied `Message-ID` header on the delivered message has not been verified.

### 5. Result

`provider_message_id` is Resend's email id. It means Resend accepted the request, not that a mailbox received the message. Delivery events (Resend webhooks) are not consumed.

### 6. Logging and secrets

The adapter and `saas_os.infra.egress` write no log line. The `httpx` library itself logs one `INFO` line per request on the `httpx` logger, `HTTP Request: POST https://<pinned address>/emails "HTTP/1.1 <status> <reason>"`: the method, the URL with the resolved IP address in place of the host name, and the status; never headers or bodies. The notification job's existing events add no field. The key, recipients, subject, body, idempotency key and Resend's error text never appear in an exception or a log line. `httpx` attaches the request (headers and body) to its exceptions, so the adapter raises its `EmailProviderError` outside the `except` block, with no `__cause__` or `__context__`, and builds the request headers in a helper frame rather than in `send()`'s own; the egress client's internal chaining is unchanged (deferred ledger). Tests search for canary values at `DEBUG` level, which includes that `httpx` line.

### 7. Egress

The worker needs outbound HTTPS to `api.resend.com:443`. The strict egress client ignores `HTTP_PROXY`/`HTTPS_PROXY` and refuses a name that resolves to a non-public address, so a deployment cannot reach Resend through an environment-configured HTTP proxy or a private relay address. This extends G9 (ADR-0057 section 7): the reference production topology has no Internet route from the worker.

## What Would Be Difficult to Change Later

- `EMAIL_PROVIDER=resend` and `RESEND_API_KEY` become part of deployments' configuration.
- The idempotency-key derivation: changing it makes in-flight retries within 24 hours send again.
- Treating `400`/`422` as permanent dead-letters those messages without retry.

## Validation

Unit: `tests/core/email/test_resend_provider_unit.py` (through the real `StrictEgressClient` with a scripted resolver and `httpx.MockTransport`: request construction, mapping, classification, redaction including the whole `__cause__`/`__context__` chain, timeouts including a stalled `getaddrinfo` measured on the public `send()` and the cap on pending lookups, idempotency key and its derivation), `tests/core/email/test_email_provider_selection_unit.py` (selection, no SMTP fallback, startup validation, no network call), `tests/core/notifications/test_email_channel_unit.py` (the notification channel through the real adapter), `tests/architecture/test_ci_hermeticity.py` (`RESEND_API_KEY` scrubbed from the default suite's environment). No test contacts Resend. A live send against Resend has not been run.

## Residual limitations

- Not verified against the live Resend API; the request and error shapes follow its published documentation of 2026-10-24.
- No environment proxy support (section 7); G9 applies.
- `429` does not honor `Retry-After`. A daily or monthly quota refusal (`429`) therefore uses up the outbox's attempts (about 3 hours at the defaults) and dead-letters the notification, which then needs a manual replay.
- Resend documents a `400 validation_error` for an `Authorization` header that is not a valid key; a `400` is permanent here, so such a send is dead-lettered after one attempt instead of being retried as an authentication failure (ADR-0057). Unlikely: the key is checked for printable ASCII and sending endpoints answer `401` for an unknown key.
- Not documented by Resend: whether a request that failed (`429`, `5xx`) consumes its idempotency key or replays the failure for 24 hours.
- Duplicates are possible as described in section 4.
