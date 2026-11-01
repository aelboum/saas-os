# External side effects: classifying outcomes and handling ambiguous ones

**Status: design proposal, 2026-11-01. Changes no code, no migration, no public contract.** Prepared on `main` `6fd2dfd`. Owner decision of 2026-11-01 on finding F5: an external request that may already have been sent but has no confirmed outcome is **ambiguous**, and an ambiguous outcome is not retried automatically unless the operation has a safe idempotency mechanism or a reconciliation strategy. The outbox consumer timeout is already handled that way in pull request #189; this proposal covers the outcomes a consumer or transport reports itself. Items that need a public-contract change are listed for approval in section 7.

## 1. Four outcomes

| Outcome | Meaning | Evidence that establishes it | Default handling |
|---|---|---|---|
| **Not sent** | No byte of the request reached the destination | The transport failed before writing: resolution, connection, TLS handshake, proxy refusal or proxy tunnel not established, local validation | Retry with backoff (safe) |
| **Succeeded** | The destination confirmed the effect | A response the protocol defines as acceptance (HTTP `2xx` with the expected body; SMTP `250` after the message data) | Record completion |
| **Failed, safe to retry** | The destination answered, refusing for now, and the effect did not happen | A response the protocol defines as refusal before effect (HTTP `408`, `429`, `503`; SMTP `4xx`) | Retry with backoff, honouring `Retry-After` |
| **Ambiguous** | The request may have been sent and its outcome is unknown | The transport failed after it started writing: write timeout, read timeout, connection closed or reset before a complete response, deadline expiring after the exchange started, an unreadable `2xx`; a consumer that ran out of time | Not retried automatically (section 3) |

A refusal that can never succeed (HTTP `400`, `410`, `413`, `422`; SMTP `5xx`) stays **failed, permanent**, dead-lettered at once as today (`PermanentEventError`, ADR-0035). It is a fifth case, unchanged.

**A generic `TimeoutError` proves nothing.** It may come before connecting (not sent) or after writing (ambiguous). Only the transport that saw the phase can classify it. Code that cannot tell must treat the outcome as ambiguous, never as "not sent" and never as "succeeded".

## 2. What the transports report today (`main` `6fd2dfd`)

| Transport | Evidence available | Gap |
|---|---|---|
| `StrictEgressClient` (`saas_os/infra/egress/client.py`) | Every `EgressError` carries `phase` and `request_may_have_been_sent`: `False` for connect timeouts and the pre-exchange deadline, `True` for write timeouts and failures after the exchange started | Sufficient. Used by Resend and the AI adapters |
| AI adapters (`saas_os/control_plane/inference/adapters/errors.py`) | Map `request_may_have_been_sent` to `possibly_accepted`; the attempt ledger keeps an attempt `started`/`unknown` and never returns output before its evidence commits | Sufficient; inference is synchronous and not retried by Core |
| Webhook delivery (`saas_os/core/webhooks/service.py`) | Distinguishes connection failures (the next address is tried: not sent) from every other `httpx.HTTPError` | Read and write timeouts, protocol errors and the delivery deadline after sending all become `WebhookDeliveryError`, retried as transient |
| SMTP (`saas_os/core/email/smtp_provider.py`, `_classify`) | Reply codes for refusals | A disconnect after the message data was sent and before `250` has no reply code and falls through to a transient `EmailProviderError` |
| Stripe adapter (`saas_os/core/billing/`) | Mandatory provider idempotency keys (ADR-0008 amendment) and provider-confirmed state (ADR-0029, ADR-0048) | Sufficient: an ambiguous call is retried with the same key or reconciled from the provider's state |

## 3. Handling ambiguous outcomes, per consumer

| Consumer | Idempotency or reconciliation | Proposed handling of an ambiguous outcome | Duplicate risk if retried |
|---|---|---|---|
| **Webhooks** | The `event_id` is stable across attempts and inside the signed body; ADR-0035's receiver-side replay ledger (`verify_and_record_webhook_delivery`) is keyed on it. Correctness depends on the receiver; `docs/CONSUMER-GUIDE.md` does not yet tell receivers to de-duplicate on it | **Option W1:** keep retrying, as an explicit at-least-once contract on `event_id`, documented for receivers. **Option W2:** dead-letter ambiguous deliveries for operator replay | W1: a receiver that ignores `event_id` acts twice. W2: none automatically; a receiver whose request timed out after it acted waits for an operator |
| **Resend** | `Idempotency-Key` derived from the stable `Message-ID`; Resend de-duplicates for 24 hours (ADR-0058) | Retry while the event is within 23 hours of its creation (the outbox row's `created_at`); dead-letter as ambiguous after that | Within the window: none, if Resend honours the key for a request it accepted. Resend does not document whether a failed request consumes the key (deferred-issue ledger) |
| **SMTP** | None: the `Message-ID` is stable, but receiving servers do not reliably de-duplicate | Dead-letter as ambiguous (a disconnect after the data was sent and before `250`); replay by an operator | A retry can deliver the message twice |
| **Stripe billing** | Provider idempotency keys and reconciliation from the provider's state | Unchanged: retry with the same key; reconcile | None beyond what the provider de-duplicates |
| **AI inference** | Attempt ledger, settlement as `unknown` | Unchanged: no automatic retry by Core; the caller sees an error and decides | The provider may bill an attempt twice if the caller retries |
| **Outbox consumer timeout** (all consumers) | None at that level | Dead-lettered, never reclaimed (pull request #189) | None automatically |
| **Product consumers** | Whatever the product provides | Same contract: report the outcome typed (section 4); an unclassified failure stays transient, as today, until the product adopts it | As today |

In every case: an ambiguous outcome is never recorded as success; the event stays in its tenant's outbox under RLS; `last_error` names the category and phase, never a URL, recipient or payload; recovery is the audited operator replay (`platform.outbox:replay`), after the operator checks the destination (provider dashboard, receiver logs, Resend by `Message-ID`).

## 4. How a consumer would report the outcome (public contract: needs approval)

Today a consumer raises `PermanentEventError` (dead-letter now), `RetryAfterEventError` (retry later) or any other exception (retry with backoff). Two ways to add "ambiguous":

- **Option T1 (recommended): a typed exception** `AmbiguousOutcomeError(reason, *, phase)` in `saas_os.core.outbox`, which the dispatcher dead-letters at once with `last_error` `OutcomeUnknown: <reason> (<phase>)`, like the timeout of #189. Additive public API (snapshot change); consumers that do not raise it behave as today.
- **Option T2: a reason convention** on `PermanentEventError` (`"outcome_unknown: ..."`). No public API change, but the category is a string and cannot be told apart by type.

Inside SaaS OS, each transport maps its evidence to the type: `EgressError.request_may_have_been_sent` for Resend; a phase-aware mapping of `httpx` errors for webhooks (read, write, protocol and post-send deadline errors versus connection errors); SMTP failures after the data phase.

## 5. Tenant isolation, audit and evidence

- Nothing leaves the tenant: the dispatcher records the outcome on the tenant's own outbox row under `tenant_session_scope`, as today.
- The dead-lettered row is the durable evidence; the dispatcher logs the event id and type only.
- A replay writes a platform audit row and a tenant audit row (existing).
- No new table, column or migration: `dead_lettered` and `last_error` already exist.

## 6. Tests the implementation needs

Per transport, with real sockets where the phase matters: connection refused and connect timeout are retried (not sent); a server that reads the request and closes without answering, and one that answers after the read timeout, are ambiguous; a `2xx` is success; `429` and `503` are retried with `Retry-After`. Per consumer: the ambiguous outcome is dead-lettered, no later polling runs it, a replay brings it back once, and no URL, recipient, secret or payload reaches `last_error`, logs or audit rows. Resend: an ambiguous outcome within the window is retried with the same `Idempotency-Key`; after it, dead-lettered. Negative control: classifying a post-write read timeout as "not sent" fails the tests.

## 7. Decisions for the owner

1. **Typed exception (T1) or reason convention (T2).** T1 changes the public outbox contract additively.
2. **Webhooks: W1 (documented at-least-once on `event_id`) or W2 (dead-letter ambiguous deliveries).** W1 keeps today's behaviour and makes the receiver contract explicit; W2 stops automatic duplicates at the cost of operator work for every receiver timeout.
3. **SMTP: dead-letter ambiguous sends** (recommended; no idempotency exists), a behaviour change products will notice.
4. **Resend: the 23-hour retry window**, which depends on Resend's undocumented handling of a failed request's key.

Nothing in this proposal needs a migration. Implementation follows these decisions, in its own pull request.
