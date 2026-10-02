# ADR-0036: Outbox consumer idempotency (Foundation Reliability & Events, RE-5)

Status: Accepted and implemented
Date: 2026-10-02
Supersedes / Superseded by: — (completes [ADR-0032](0032-transactional-outbox.md), [ADR-0033](0033-durable-outbox-dispatcher.md) and [ADR-0035](0035-durable-webhooks-and-subscription-authority.md))

## Context

Outbox delivery is at-least-once (RE-2). A consumer runs again when its worker finished the work but died before the dispatcher recorded the outcome, and two executions can overlap when a lease expires while the first is still running. Before RE-5, a repeat counted usage twice, wrote a second notification row, re-sent an e-mail and re-POSTed a webhook.

## Decision

**Guarantee.** For a registered consumer and an outbox event's stable identity, a consumer durably recognizes an execution it already completed and suppresses the duplicate. Delivery stays at-least-once. Nothing here is exactly-once, and no atomicity is claimed between PostgreSQL and an external side effect.

**Identity: `(tenant_id, consumer, event_id)`.**
- **`event_id`** is the outbox event id. It is generated once when the event is recorded and is the same on every attempt; the dispatcher passes it to the consumer as `TenantJobContext.event_id`. It is never derived from time, worker or attempt. A webhook occurrence is one outbox event per subscription, so subscriptions never share an identity. The webhook payload's shared `event_id` is deliberately not the key.
- **`consumer`** names the consuming operation (its event type), so two consumers of one event never suppress each other.
- **`tenant_id`** scopes the identity.

**Record.** `core.outbox_consumptions`:
- The primary key is the identity. The row has only the identity and `consumed_at`: no payload, result or secret.
- The table is tenant-owned and RLS-protected (canonical policy, ENABLE + FORCE, registered `TENANT_OWNED`), so tenants can neither read nor create each other's records.
- There is no foreign key to the outbox event, so a record does not depend on the event row's lifetime.

**Claim and completion** (`core.outbox.claim_event_consumption(session, ...)`).
- **Claim:** the consumer inserts the identity in its own transaction, under a savepoint.
  - The uncommitted row *is* the claim. A concurrent claimant of the same identity blocks on PostgreSQL's unique index; there is no polling and no sleep. When the first commits, the second sees it and skips; when the first rolls back, the second proceeds.
  - A rollback or worker death discards the claim, so the event stays eligible.
- **Completion:** the caller's commit, atomic with everything else that transaction wrote.
- **Failure:** any database error raises and the event is retried. A failure is never read as "already consumed", and an integrity error other than an existing record is re-raised.

**Two consumer patterns.**
- **Database work** (a usage row, an in-app notification row): the claim and the work commit together. The work happens at most once per identity, including under concurrent or repeated execution.
- **External effect** (e-mail, HTTP): the consumer checks `event_consumption_recorded()` before acting and records completion afterwards (`record_event_consumption()` for webhooks; the notification row transaction for e-mail).
  - This suppresses every repeat once completion is recorded.
  - If the worker dies after the effect but before the record commits, or two executions overlap before either records it, the effect repeats. That is inherent to at-least-once delivery, and the receiver deduplicates on the stable event id.

**Consumers.**

| Consumer | Needs it | Where suppression happens | Same-transaction completion | External effect |
|---|---|---|---|---|
| `usage.ingestion` | yes: usage must not double-count | claim in the usage-row transaction | yes | none |
| `notification.dispatch` (in-app) | yes | claim in the notification-row transaction | yes | none |
| `notification.dispatch` (e-mail) | yes | pre-check before sending; claim with the row | the row: yes. The e-mail: no | an e-mail can repeat only if the worker dies between sending and committing |
| `webhook.delivery` | yes, to avoid re-POSTing a delivered event | pre-check before the request; record after 2xx | no | a POST can repeat in that same window; the receiver's replay check on the stable event id absorbs it |

There are no other `OUTBOX_EVENT_HANDLERS`.

**Distinctions kept.**
- `core.idempotency` is client-request idempotency: caller-supplied keys, request fingerprints, stored results, TTL expiry, and a persisted `in_progress` state. Its expiry and `in_progress` reservation (which would block an event after a crash until it expired) do not fit consumer idempotency, and sharing its table would mix request keys with consumer identities. It is unchanged.
- The webhook replay ledger (`verify_and_record_webhook_delivery`) is a receiver-side check of inbound signed events. It is unchanged, and it is not the SaaS-OS delivery-side record.

**Legacy jobs.** A job enqueued directly rather than dispatched from the outbox (one queued before RE-1) has no event identity (`event_id is None`) and runs as before, without deduplication. Every event recorded through the outbox always carries its identity: the dispatcher supplies it from the row, and no caller can omit it.

**Security.** The primitive is internal to consumer execution under the event's tenant scope. Identities are server-generated outbox ids. Suppression happens only after the consumer's tenant and lifecycle checks, and no external surface can create a record.

**Retention.** Records are kept until the tenant is purged; the "outbox" purge step removes them with the tenant's outbox events. Deleting a record while its event could still execute would allow a second execution, so there is no TTL cleanup. Records carry no personal data, so user erasure has nothing to remove.

## Consequences

- One migration (`e5b19c7d3a60`) and one new tenant-owned table.
- `TenantJobContext` gains an optional `event_id`, set by the outbox dispatcher.
- A repeated outbox execution now costs one indexed insert (database consumers) or one indexed read plus one insert (external consumers).

## Explicitly not part of this decision (deferred)

- **Cleanup of records whose event is terminal.** That would be safe, because a published or dead-lettered event never runs again, but it isn't needed yet.
- **Operator replay** of dead-lettered events. When added, it must decide deliberately whether a replay re-runs the consumer (new identity) or respects the existing record.

## Related

`core/outbox/consumption.py`; `core/outbox/models.py`; `infra/jobs/context.py`; `api/outbox_dispatcher.py`; `core/usage/service.py`; `core/notifications/service.py`; `core/webhooks/service.py`; `tests/core/outbox/test_outbox_consumption_integration.py`; `tests/api/test_outbox_consumer_idempotency_integration.py`.
