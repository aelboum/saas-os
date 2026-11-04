# External side effects: classifying outcomes and handling ambiguous ones

**Status: decided design, implemented by pull request #197 (`feat/ambiguous-outcomes`); this document merges after or with #189 and #197. Updated 2026-11-02.** First written 2026-11-01 on `main` `6fd2dfd` as a proposal that changed no code. Owner decision of 2026-11-01 on finding F5: an external request that may already have been sent but has no confirmed outcome is **ambiguous**, and an ambiguous outcome is not retried automatically unless the operation has a safe idempotency mechanism or a reconciliation strategy. The outbox consumer timeout is handled that way in pull request #189; this design covers the outcomes a consumer or transport reports itself. The owner has since decided every question of the first version's section 7, plus decision D on bare timeouts and, on 2026-11-02, its limit (section 7). Sections 2 and 3 keep the first version's analysis and are labeled where it is historical.

**Merge order:** #197 is stacked on #189 (`fix/r1-security-hardening`), and this document describes #197's behaviour, so #194 should merge after, or together with, #189 and #197.

## 1. Four outcomes

| Outcome | Meaning | Evidence that establishes it | Default handling |
|---|---|---|---|
| **Not sent** | No byte of the request reached the destination | The transport failed before writing: resolution, connection, TLS handshake, proxy refusal or proxy tunnel not established, local validation | Retry with backoff (safe) |
| **Succeeded** | The destination confirmed the effect | A response the protocol defines as acceptance (HTTP `2xx` with the expected body; SMTP `250` after the message data) | Record completion |
| **Failed, safe to retry** | The destination answered, refusing for now, and the effect did not happen | A response the protocol defines as refusal before effect (HTTP `408`, `429`, `503`; SMTP `4xx`). Exception: for Resend every `5xx`, `503` included, is ambiguous (section 4); its `429` stays a refusal | Retry with backoff, honouring `Retry-After` |
| **Ambiguous** | The request may have been sent and its outcome is unknown | The transport failed after it started writing: write timeout, read timeout, connection closed or reset before a complete response, deadline expiring after the exchange started, an unreadable `2xx`; a consumer that ran out of time | Not retried automatically, unless a safe retry policy is declared (section 3) |

A refusal that can never succeed (HTTP `400`, `410`, `413`, `422`; SMTP `5xx`) stays **failed, permanent**, dead-lettered at once as today (`PermanentEventError`, ADR-0035). It is a fifth case, unchanged.

**A generic `TimeoutError` proves nothing.** It may come before connecting (not sent) or after writing (ambiguous). Only the transport that saw the phase can classify it. Code that cannot tell must treat the outcome as ambiguous, never as "not sent" and never as "succeeded" (decision D, section 3.1).

## 2. What the transports reported before the change (historical, `main` `6fd2dfd`)

*Historical analysis from the first version; the "Gap" column is what #197 closes (the last column).*

| Transport | Evidence available | Gap (on `6fd2dfd`) | In #197 |
|---|---|---|---|
| `StrictEgressClient` (`saas_os/infra/egress/client.py`) | Every `EgressError` carries `phase` and `request_may_have_been_sent`: `False` for connect timeouts and the pre-exchange deadline, `True` for write timeouts and failures after the exchange started | Sufficient. Used by Resend and the AI adapters | Unchanged |
| AI adapters (`saas_os/control_plane/inference/adapters/errors.py`) | Map `request_may_have_been_sent` to `possibly_accepted`; the attempt ledger keeps an attempt `started`/`unknown` and never returns output before its evidence commits | Sufficient; inference is synchronous and not retried by Core | Unchanged |
| Webhook delivery (`saas_os/core/webhooks/service.py`) | Distinguished connection failures (the next address is tried: not sent) from every other `httpx.HTTPError` | Read and write timeouts, protocol errors and the delivery deadline after sending all became `WebhookDeliveryError`, retried as transient | `WebhookAmbiguousDeliveryError` (at least once) versus `WebhookNotSentError` |
| SMTP (`saas_os/core/email/smtp_provider.py`, `_classify`) | Reply codes for refusals | A disconnect after the message data was sent and before `250` had no reply code and fell through to a transient `EmailProviderError` | Phase tracked on the live connection; `EmailOutcomeUnknownError` (phase `data`) versus `EmailNotSentError` |
| Resend (`saas_os/core/email/resend_provider.py`) | `EgressError.request_may_have_been_sent` | Every failure other than a permanent refusal (`400`, `422`) retried as transient, including one whose request may have been sent | `EmailOutcomeUnknownError` with the 23-hour window (also for any `5xx`) versus `EmailNotSentError` |
| Stripe adapter (`saas_os/core/billing/`) | Mandatory provider idempotency keys (ADR-0008 amendment) and provider-confirmed state (ADR-0029, ADR-0048) | Sufficient: an ambiguous call is retried with the same key or reconciled from the provider's state | Unchanged |

## 3. Handling ambiguous outcomes, per consumer (decided)

| Consumer | Idempotency or reconciliation | Decided handling of an ambiguous outcome | Duplicate risk |
|---|---|---|---|
| **Webhooks** | The `event_id` is stable across attempts and inside the signed body; ADR-0035's receiver-side replay ledger (`verify_and_record_webhook_delivery`) is keyed on it | **W1:** retried within the normal attempt budget as an explicit **at-least-once** contract on `event_id` (`WebhookAmbiguousDeliveryError`, `at_least_once=True`); dead-lettered when the attempts run out. **Receivers must de-duplicate on `event_id`** | A receiver that ignores `event_id` acts twice; the contract now requires it to de-duplicate |
| **Resend** | `Idempotency-Key` derived from the notification's stable identity; Resend keeps a key for 24 hours (ADR-0058) | Retried, with an **identical payload** and the **same idempotency key**, only while the retry is due within **23 hours** of the event's creation (the outbox row's `created_at`); dead-lettered after that, and at once when the request carried no key | Within the window: none, if Resend honours the key for a request it accepted; whether a failed request consumes the key is undocumented (deferred-issue ledger) |
| **SMTP** | None: the `Message-ID` is stable, but receiving servers do not reliably de-duplicate | **Dead-lettered** (a disconnect or timeout after the relay invited the message data and before its final reply); replay by an operator | A replay can deliver the message twice |
| **Stripe billing** | Provider idempotency keys and reconciliation from the provider's state | Unchanged: retry with the same key; reconcile. **No ambiguous-outcome retry policy is enabled** | None beyond what the provider de-duplicates |
| **AI inference** | Attempt ledger, settlement as `unknown` | Unchanged: no automatic retry by Core; the caller sees an error and decides. **No ambiguous-outcome retry policy is enabled** | The provider may bill an attempt twice if the caller retries |
| **Outbox consumer timeout** (all consumers) | None at that level | Dead-lettered, never reclaimed (`ConsumerTimedOut:`, pull request #189) | None automatically |
| **Product consumers** | Whatever the product provides | Decision D and its 2026-11-02 limit (section 3.1) | Only through an operator's replay of a dead-lettered event |

*Historical (first version):* the product-consumer row read "report the outcome typed (section 4); an unclassified failure stays transient, as today, until the product adopts it". Decision D replaced that for bare timeouts; the 2026-11-02 decision keeps it for every other exception.

### 3.1 Product consumers: bare timeouts (decision D) and other exceptions

- A **bare timeout** escaping a product's outbox consumer unclassified is dead-lettered at once as an ambiguous outcome with no retry policy (`last_error` `OutcomeUnknown: <type name> (unclassified); ...`). A bare timeout is a `TimeoutError` (which includes `asyncio.TimeoutError`, `socket.timeout`, `concurrent.futures.TimeoutError` and their subclasses), an `httpx.TimeoutException` (not a `TimeoutError` subclass), or an exception group holding one (`_is_unclassified_timeout` in `saas_os/api/outbox_dispatcher.py`). Only the exception's type name is stored. This is a behaviour change for product consumers: such an event used to be retried with backoff.
- An error that is a **`ConfirmedNotSentError`** (raised, or mixed into the consumer's own class, on evidence that nothing was sent) keeps the **ordinary retry** (backoff, attempt counted, dead-lettered when the attempts run out), even when it is also a `TimeoutError`.
- **Every other exception keeps the ordinary retry.** Owner decision of 2026-11-02: do not dead-letter every unclassified exception. #197 implements this and records it in its consumer guide (`docs/CONSUMER-GUIDE.md`).
- An **exception group** holding `AmbiguousOutcomeError`s is ambiguous and takes the most conservative policy of its members: `at_least_once` only if every member declares it, `retry_within` (the shortest) only if every member declares one, otherwise none (dead-lettered); a bare timeout in the same group means no policy. `ConfirmedNotSentError` members change nothing (`_ambiguous_outcome` in `saas_os/api/outbox_dispatcher.py`).
- `AmbiguousOutcomeError`, `PermanentEventError` and `RetryAfterEventError` raised explicitly are handled first, by their own meaning.

### 3.2 Common rules

In every case: an ambiguous outcome is never recorded as success; the event stays in its tenant's outbox under RLS; `last_error` names the category and phase, never a URL, recipient or payload; recovery is the audited operator replay (`platform.outbox:replay`, `saas-os-operator replay-outbox-events`), after the operator checks the destination (provider dashboard, receiver logs, Resend by `Message-ID`). A replay resets the attempts, so the replayed run itself always runs once.

## 4. How a consumer reports the outcome (decided: T1)

Before the change a consumer raised `PermanentEventError` (dead-letter now), `RetryAfterEventError` (retry later) or any other exception (retry with backoff). The owner chose **Option T1, a typed exception**, over T2 (a reason convention on `PermanentEventError`, *historical alternative, not implemented*). #197 adds two classes to `saas_os.core.outbox` (additive public API, snapshot updated):

```python
AmbiguousOutcomeError(reason, *, phase, retry_within=None, at_least_once=False)
ConfirmedNotSentError
```

- **`AmbiguousOutcomeError`**: the request may have been sent and the outcome is unknown. `reason` and `phase` are short categories stored in `last_error`. With neither policy the dispatcher dead-letters the event at once with `last_error` `OutcomeUnknown: <reason> (<phase>); ...`. A consumer whose destination is safe to retry declares at most one policy (both at once is a `ValueError`):
  - `retry_within` (a positive `timedelta`): the destination de-duplicates the same idempotency key with an identical payload for that long. The event is retried with the normal backoff only while the retry is due before `created_at + retry_within` (`created_at` is a lower bound of the first send, so the window is never longer than declared). The deadline is stored in `last_error` as a trailing `[idempotent-retry-until <time>]` tag (whole seconds, UTC; no migration), carried over by every later failure of the event; a retry still pending when the window closes is dead-lettered instead of running. The tag is trusted only in exactly that form, at the end of `last_error` (`_RETRY_DEADLINE_TAG` in `saas_os/core/outbox/dispatch.py`); the marker is neutralised in any other stored text, and a malformed deadline reads as already passed (fail closed: the retry is dead-lettered for an operator).
  - `at_least_once=True`: the receiver de-duplicates on a stable id. The event is retried within the normal attempt budget and dead-lettered when the attempts run out.
- **`ConfirmedNotSentError`**: explicit evidence that the request was not sent; exempts the error from the bare-timeout rule (section 3.1). A class cannot be both a `ConfirmedNotSentError` and an `AmbiguousOutcomeError` (`TypeError` at class definition).

Inside SaaS OS, each transport maps its evidence to these types:

- **Resend:** `EgressError.request_may_have_been_sent`, an unreadable `2xx`, or any HTTP `5xx`, raises `EmailOutcomeUnknownError` with `retry_within` = `RESEND_IDEMPOTENT_RETRY_WINDOW` (23 hours) when the request carried an `Idempotency-Key`, `None` otherwise; a failure before sending raises `EmailNotSentError`. A `5xx` is treated as a possibly completed send because Resend may have processed a request it then failed to answer: with a key it is retried only with the same key and an identical payload within the 23-hour window from `created_at`, and that deadline then bounds every later retry of the event; without a key it is dead-lettered. A `503` is therefore not "failed, safe to retry" for Resend; a `429` is unchanged (a refusal, retried after its `Retry-After`). Owner confirmation of 2026-11-02: keep this conservative rule. The notification job sets `EmailMessage.idempotency_key` to `notification.{event_id}`, so the key derives from the outbox event id alone and no longer changes with the sender's domain; the key sent is a SHA-256 of that identity, and the request body is serialised deterministically, so a retry is byte-identical. `409 invalid_idempotent_request` (the key was already used with a different body) is **permanent** (`idempotency_payload_mismatch`), so a changed body is never resent under another key.
- **SMTP:** the phase is tracked on the live `smtplib` connection. After the relay answered `354` to DATA and before its final reply, a lost or timed-out connection raises `EmailOutcomeUnknownError` with phase `data` and no window (dead-lettered); before that, with no reply code, `EmailNotSentError`; a failure after the final `250` no longer fails the send.
- The notification job maps these to `NotificationAmbiguousDispatchError` (an `AmbiguousOutcomeError`) and `NotificationNotSentDispatchError` (a `ConfirmedNotSentError`). A notification e-mail that was sent but whose notification row could not then be recorded is ambiguous (`OutcomeUnknown: record_after_send_<type> (record)`, no retry), because a retry would send it again. An invalid recipient address is permanent (`NotificationPermanentDispatchError`): the address is part of the event, so no retry can make it valid; an invalid `EMAIL_DEFAULT_SENDER` is configuration and keeps the retry.
- **Webhooks:** write and read timeouts, a connection lost or a protocol error after connecting, and the delivery deadline once an address was being tried raise `WebhookAmbiguousDeliveryError` (`at_least_once=True`); no connection accepted, no pooled connection, the egress proxy unavailable before the tunnel, the deadline before any address was tried, or an unresolvable destination raise `WebhookNotSentError` / `WebhookDestinationUnresolvedError` (`ConfirmedNotSentError`).

### 4.1 Outside the outbox dispatcher

- **Directly queued jobs:** `AmbiguousOutcomeError` derives from `NonRetriableJobError` (`saas_os/infra/jobs/errors.py`), so a job that raises one outside the outbox (an SMTP connection lost after the data, an unkeyed Resend send) is dead-lettered at once instead of being retried up to `JOBS_MAX_TRIES` times, unless it declares `at_least_once=True`. An idempotency window is not honoured there, because nothing records when the job's first attempt ran.
- **Lease:** `OUTBOX_LEASE_SECONDS` must be at least 360 (the outbox job's 300 seconds plus 60 in the queue); the worker refuses to start with a shorter lease (`OutboxConfigurationError`), so another dispatcher cannot reclaim an event whose first consumer is still sending. The default, 900, is unchanged.

## 5. Tenant isolation, audit and evidence

- Nothing leaves the tenant: the dispatcher records the outcome on the tenant's own outbox row under `tenant_session_scope`, as before.
- The dead-lettered row is the durable evidence; the dispatcher logs identifiers and categories only, never the error text (`outbox_event_outcome_unknown`, `outbox_event_retry_window_closed`).
- A replay writes a platform audit row and a tenant audit row (existing).
- No new table, column or migration: `dead_lettered` and `last_error` already exist; the retry deadline lives in `last_error`.

## 6. Tests the implementation needs

Per transport, with real sockets where the phase matters: connection refused and connect timeout are retried (not sent); a server that reads the request and closes without answering, and one that answers after the read timeout, are ambiguous; a `2xx` is success; `429` and `503` are retried with `Retry-After` (for Resend only `429`: its `5xx` is ambiguous). Per consumer: the ambiguous outcome is dead-lettered, no later polling runs it, a replay brings it back once, and no URL, recipient, secret or payload reaches `last_error`, logs or audit rows. Resend: an ambiguous outcome within the window is retried with the same `Idempotency-Key`; after it, dead-lettered. Product consumers: a bare timeout is dead-lettered; a `ConfirmedNotSentError` and any other exception are retried. Negative control: classifying a post-write read timeout as "not sent" fails the tests. The tests #197 actually contains, and their results, are in that pull request.

## 7. Decisions

All decided; recorded here as decided. *The first version listed questions 1 to 4 as open.*

| # | Question | Decision |
|---|---|---|
| 1 | Typed exception (T1) or reason convention (T2) | **T1**: `AmbiguousOutcomeError(reason, *, phase, retry_within=None, at_least_once=False)`, plus `ConfirmedNotSentError`, in `saas_os.core.outbox` (additive) |
| 2 | Webhooks: W1 or W2 | **W1**: ambiguous deliveries are retried as at-least-once on `event_id`; receivers must de-duplicate. The consumer-guide gap of the first version (no receiver de-duplication requirement in `docs/CONSUMER-GUIDE.md`) is resolved by #197, which adds "Webhook receivers: de-duplicate on `event_id` (mandatory)" |
| 3 | SMTP | **Dead-letter** ambiguous sends; operator replay |
| 4 | Resend window | **23 hours** from the event's creation, identical payload, stable idempotency key; dead-lettered after it. A `5xx` is ambiguous under the same rule (owner confirmation, 2026-11-02) |
| D | Bare timeouts escaping a product consumer (2026-11-01) | Dead-lettered as `OutcomeUnknown` (TimeoutError family, `httpx` timeouts, exception groups holding one); `ConfirmedNotSentError` retries normally |
| D, limit | Every unclassified exception (owner, 2026-11-02) | **No**: other exceptions keep the normal retry |
| - | Stripe and AI | No ambiguous-outcome retry enabled; unchanged |

Nothing in this design needs a migration.
