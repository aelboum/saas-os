# Outbox: provider retry hints and replay of dead-lettered events — decision brief

**Status: awaiting the owner's decision.** Prepared 2026-10-30 against `main` `b682b29`. It covers two open items that share one mechanism, the durable outbox (`saas_os/core/outbox/dispatch.py`):

- the ledger row "Resend `429` responses' `Retry-After` is not read" (LOW), whose own follow-up says it "needs the outbox to accept [a provider-supplied delay]: a separate decision";
- the production-readiness gap "no test replays dead-lettered jobs" (gate 6). There is nothing to test: no replay exists.

Nothing in this brief is implemented.

## 1. Current behaviour (verified by reading the code)

- **Retry.** A consumer failure is transient unless the consumer raises `PermanentEventError` (`core/outbox/errors.py`), which dead-letters at once. A transient failure is retried after `retry_delay()`: 30 s doubling to a 3600 s cap, with jitter, for at most `OUTBOX_MAX_ATTEMPTS` = 10 claims. Each claim counts as an attempt before the consumer runs.
- **Provider hints are ignored.** The Resend adapter classifies `429` as transient and does not read `Retry-After`. A daily or monthly quota refusal outlasts the whole schedule (about 3 hours), so every notification sent during it is dead-lettered.
- **Dead-lettered outbox events stay in PostgreSQL** (`core.outbox_events`, `status = 'dead_lettered'`, payload and `last_error` kept). No function, operator command or route moves one back to `pending`.
- **Dead-lettered Redis jobs cannot be replayed by design.** The `arq:dead-letter` list keeps function name, tenant id, attempt count and error, never the payload (privacy, PRIV-03; `keep_result=0`). That is not in scope.
- **The guide promised a replay.** `docs/CONSUMER-GUIDE.md` said "raise the quota, then replay the dead-lettered events". There was no way to do that. This brief's pull request corrects that sentence. It does not add a replay.

## 2. Why this needs a decision

- A retry hint changes the outbox's public consumer contract. `PermanentEventError` is exported, and a product's consumers would use the hint too, so its semantics bind products.
- A replay re-sends webhooks and email to destinations outside SaaS OS, across tenants if done in bulk. The existing rules (ADR-0045, ADR-0050) put such operator actions under a platform permission with platform and tenant audit. No permission or audit vocabulary covers it today.

## 3. Options

### Q1. Provider retry hints

**1A. A typed hint, bounded (recommended).**
- A consumer may raise `RetryAfterEventError(seconds, reason)`, a new exported exception. `fail_event()` schedules the next attempt at `max(retry_delay(), hint)`, capped by a new `OUTBOX_RETRY_HINT_MAX_SECONDS` (proposed default 86 400). The attempt is still counted.
- The Resend adapter raises it for `429` with `Retry-After`, and for the quota names with the cap.
- For: a quota refusal waits instead of burning its attempts. The bound keeps total time finite. Attempts stay counted, so a crash loop is still bounded.
- Against: a new public exception and a new setting; a daily quota still takes about one attempt per day.

**1B. A hint that does not count the attempt.**
- For: a long quota refusal never dead-letters.
- Against: an event can wait forever unless a second bound (maximum age) is added. It is more state, and it departs from "an attempt is counted when it is claimed".

**1C. Keep the current behaviour.** Document it, and rely on replay (Q2) after a quota refusal.

### Q2. Replay of dead-lettered outbox events

**2A. An operator command under platform authority (recommended).**
- `saas-os-operator replay-outbox-events --operator <user-id> --tenant <id> (--event-id <id>... | --dead-lettered-since <time>) [--apply]`.
- Without `--apply` it only counts. With it, each named event moves `dead_lettered` to `pending`: attempts reset to 0, `next_attempt_at` set to now, `last_error` kept, `claim_token` cleared.
- Requires a new platform permission (proposed `platform.outbox:replay`), checked as other platform operations are. Each run writes one platform audit row and one tenant audit row per tenant touched, in the transaction of the change (ADR-0045 section 9c, ADR-0031 dual evidence).
- One tenant per run; a closed tenant is refused.
- For: bounded, audited, tenant-scoped; reuses the operator CLI, platform authority and audit patterns.
- Against: new permission vocabulary; an operator can re-send a payload a tenant no longer wants (the audit row records it).

**2B. A tenant-scoped API route** for a tenant administrator to replay their own events.
- For: self-service.
- Against: new route contract and RBAC permission; the replay of a webhook to a since-changed destination needs its own rules. Larger.

**2C. No replay.** Dead-lettered events are final; the product re-creates what it needs. Correct the guide and close the readiness gap as "by design".

## 4. Recommendation

1A and 2A, built together: 2A gives the operator the step the guide used to describe, and 1A means the quota case rarely needs it. Proposed acceptance:

- for 1A, a hint delays within the bound and still counts the attempt; a hint above the bound is capped; the Resend adapter maps `429` with `Retry-After` and the quota names;
- for 2A, a dry run changes nothing; `--apply` resets only the named dead-lettered events of that tenant; a missing permission is refused with a `denied` platform row; cross-tenant and closed-tenant cases are refused;
- an end-to-end test dead-letters an event, replays it and sees it published once;
- negative controls for the permission check and the tenant predicate.

## 5. Decision needed

For Q1, choose 1A, 1B or 1C; for Q2, choose 2A, 2B or 2C. With 2A, also confirm the permission name and that it is not granted to any default role.

## 6. Not affected

The Redis job dead-letter list, webhook SSRF and egress rules, and the email providers' other error classes.
