# Outbox: retry branches after a started marker (design for approval)

**Status: design proposal for the owner's approval, 2026-11-04. Nothing in it is implemented or decided: no code, migration or test changes, and no setting changes.** Prepared on `main` `99e0f24`. It covers one open item recorded in `docs/architecture/OUTBOX-STARTED-MARKER.md` section 6: after a started marker, a `ConfirmedNotSentError` and an `at_least_once` ambiguous outcome are dead-lettered `OutcomeUnknown:` because the retry branches of #195 section 4a.9 were not implemented. Until they are, no consumer can be wired to `TenantJobContext.external_effect()`: every transient webhook or e-mail failure after a marker would be dead-lettered.

Labels used below: **[existing]** is a rule the owner has decided or the code implements today, with its source; **[proposal]** is new and awaits a decision (section 11).

Sources:

- #195, `docs/architecture/DURABLE-STARTED-STATE-RECOVERY-DESIGN.md` sections 3.1 (safe retry after a crash is an explicit consumer opt-in) and 4a.9 (runtime statements and the exception rule after the marker).
- `docs/architecture/OUTBOX-STARTED-MARKER.md` (D4 as merged: columns, `OUTBOX_EXTERNAL_EFFECT_MARKERS` off by default, `external_effect()`, the reclaim rule, the exception rule; section 6 as rewritten in #207).
- `docs/architecture/EXTERNAL-OUTCOME-CLASSIFICATION-DESIGN.md` (#197: the four outcomes, `ConfirmedNotSentError`, `AmbiguousOutcomeError` with `at_least_once` or `retry_within`, W1 for webhooks).
- `docs/architecture/OUTBOX-RETRY-AND-REPLAY-DECISION-BRIEF.md` (`RetryAfterEventError`, operator replay), ADR-0033 (at-least-once outbox), ADR-0035 (webhooks), ADR-0036 (consumer idempotency), ADR-0045 (platform authority; replay), ADR-0058 (Resend).
- Code: `saas_os/core/outbox/dispatch.py` (`fail_event`, `record_ambiguous_outcome`, `release_claim`, `mark_external_effect_started`, `claim_due_events`, `begin_event_execution`, `_marked_by`, `_clear_marker`, `_instant`) and `saas_os/api/outbox_dispatcher.py` (`_run_outbox_event`, `_ExternalEffectStarter`, `_record_consumer_failure`, `_record_consumer_timeout`, `_ambiguous_outcome`, `_is_unclassified_timeout`).

## 1. Summary

| Question | Answer in this proposal |
|---|---|
| What changes | Two branches that #195 4a.9 already specifies and D4 left out: (1) an attested `ConfirmedNotSentError` after a marker retries and clears the marker; (2) an `at_least_once` outcome the consumer itself raised after a marker retries within the attempt budget and clears the marker |
| What does not change | Reclaim after a crash (`CrashAfterStart:`), `retry_within` after a marker, `RetryAfterEventError` alone, a bare timeout, #189's deadline, every other exception, `PermanentEventError`: all stay dead-lettered. No consumer crash-retry opt-in is created or turned on |
| Schema | None. No migration, no new column, no grant or policy change |
| Default | Unchanged: markers stay off and no consumer uses `external_effect()`. Merging the change alone alters no behaviour on any installation |
| Not decided here | Which consumer is wired first, the handling of a definitive refusal received after sending, and every item of section 11 |

## 2. Current behaviour (existing)

"Unmarked" means the attempt's claim has no started marker: markers off, an exception before `external_effect()`, or the block never entered. "Marked" means `external_started_claim = claim_token` on the locked row.

| Outcome of the execution | Unmarked | Marked | Code |
|---|---|---|---|
| Consumer returns | `complete_event()`: published, both marker columns cleared | Same | `complete_event` |
| `ConfirmedNotSentError` (also when it is a `TimeoutError`) | `fail_event()`: retry with backoff, attempt counted; dead-lettered when attempts run out | **Dead-lettered** `OutcomeUnknown: <error>`, claim cleared, marker kept | `_record_consumer_failure` (last branch), then the marked branch of `fail_event` |
| `AmbiguousOutcomeError`, no retry policy | Dead-lettered `OutcomeUnknown:` | Same, marker kept | `record_ambiguous_outcome` |
| `AmbiguousOutcomeError(at_least_once=True)` | Retry after `retry_delay()` while attempts remain, marker cleared; dead-lettered when attempts run out | **Dead-lettered** `OutcomeUnknown: ... not retried automatically`, marker kept | `record_ambiguous_outcome` (the `_marked_by` guard comes first) |
| `AmbiguousOutcomeError(retry_within=...)` | Retry while attempts remain and the retry is due before `created_at + retry_within`; deadline tag in `last_error` | **Dead-lettered**, same text | `record_ambiguous_outcome` |
| `PermanentEventError` | Dead-lettered with the error | Dead-lettered with the error, marker kept | `fail_event(terminal=True)` |
| `RetryAfterEventError` alone | `fail_event(retry_after=...)`: retry at `max(backoff, hint)`, bounded by `OUTBOX_RETRY_HINT_MAX_SECONDS` | **Dead-lettered** `OutcomeUnknown: <error>` | `fail_event` |
| Bare timeout (`TimeoutError`, `httpx.TimeoutException`, or a group holding one) inside the consumer deadline | Ambiguous with no policy: dead-lettered `OutcomeUnknown: <type> (unclassified)` | Same, marker kept | `_is_unclassified_timeout`, `_ambiguous_outcome` |
| Consumer deadline expires (#189), whatever the consumer raised | `fail_event(terminal=True)` with `ConsumerTimedOut:`; the deadline decides, not the exception type | Same, marker kept | `_run_outbox_event` (`deadline.expired()`), `_record_consumer_timeout` |
| Any other exception (`RuntimeError`, a database error, a plain `5xx` `WebhookDeliveryError`) | Retry with backoff | **Dead-lettered** `OutcomeUnknown: <error>` | `fail_event` |
| Exception group | Ambiguous members decide (most conservative policy); other leaves are ordinary | Dead-lettered | `_ambiguous_outcome` |
| `ExternalEffectNotStartedError` (marker refused: claim superseded, lease expired, or already marked) | No outcome recorded by this execution, even if the consumer swallowed the error | n/a (this execution wrote no marker) | `_run_outbox_event`, `_ExternalEffectStarter.refused` |
| Second `external_effect()` entry | `ExternalEffectAlreadyStartedError` before the block; the outcome is recorded as usual | Dead-lettered if it propagates | `_ExternalEffectStarter.__call__` |
| Hand-off to the queue fails | `release_claim()`: attempt refunded, marker cleared | Same | `release_claim` |
| Lease lost (worker crash or no outcome recorded), reclaim | Retried (`LeaseExpired:`); dead-lettered at the attempt limit | **Dead-lettered** `CrashAfterStart: outcome unknown; not retried automatically`, marker kept; takes precedence over the attempt limit | `claim_due_events` |
| Operator replay | n/a | Clears both columns with the status change | `replay-outbox-events` |

The attempt is counted at claim (`claim_due_events`: `attempts += 1`), not at outcome. The clock is the database's: every time the module compares or writes is `now()` evaluated by the server (`_now`, `_instant`); the application host's clock is never compared with a database-written time.

## 3. Rules that bind this design (existing)

| Rule | Source | Consequence here |
|---|---|---|
| An ambiguous outcome is not retried automatically unless the operation has a safe idempotency mechanism or a reconciliation strategy | Owner decision of 2026-11-01 (finding F5), #197 section 1 | A retry after a marker needs positive evidence ("not sent") or a destination contract ("de-duplicates on `event_id`"); absence of evidence is never a reason to retry |
| Safe retry after a crash is an explicit, approved, per-consumer opt-in, never a default; five conditions; no consumer is enabled, Resend included | Owner decision of 2026-11-02, #195 3.1 | This design adds no crash-retry path. Reclaim stays `CrashAfterStart:` for every consumer, webhooks included (4a.9) |
| An `at_least_once` outcome the consumer itself recorded after its marker is not a crash retry and needs no opt-in | #195 3.1 | Branch B (section 5) follows this text, with no registry |
| `ConfirmedNotSentError` is "the only error that may retry through `fail_event()`" after a marker | #195 4a.9 | Branch A (section 4); D-4 explains how this wording is met |
| The check belongs in `fail_event()` itself, against the locked row, so no caller can retry a marked attempt by mistake | #195 4a.9 | No public path retries a marked attempt on a caller's say-so (D-4) |
| `retry_within` after a marker is honoured only for a consumer holding an approved opt-in; none exists | #195 4a.9 | Unchanged: dead-lettered `OutcomeUnknown:` |
| Conservative default; markers off by default; no consumer opt-in turned on | Owner, D4 | Nothing is enabled by this change |
| Every write names the claim (`claim_token = :claim AND status = 'pending'`) under a row lock; database clock | `dispatch.py` module docstring | New writes use `_now()` and `_locked_claimed_row()` like the existing ones |
| Tenant isolation: every read and write runs under the event's own tenant scope; never cross-tenant, never an RLS bypass | `dispatch.py` module docstring, ADR-0033 | New code runs in `tenant_session_scope(tenant_id)` only |
| Durable event processing uses the established idempotency mechanisms; consumers dedupe on the stable event id | ADR-0036, ADR-0033 | No alternative idempotency path; duplicates are bounded by the destination's contract (section 5) |
| `last_error` carries categories and identifiers only, never a URL, recipient, secret or payload | `AmbiguousOutcomeError` and `ConfirmedNotSentError` docstrings, `describe_error` | New `last_error` texts follow the same rule |

## 4. Branch A: `ConfirmedNotSentError` after a marker

### 4.1 What proves "not sent", and who attests

The marker proves only that the consumer was about to send. It says nothing about whether the request left the process. Evidence that it did not exists only in the transport code that saw the phase: no connection established (refused, unresolved, connect or pool timeout), the egress proxy refused or was unavailable before the tunnel opened, or the delivery deadline expired before any address was tried (`WebhookNotSentError`, `NotificationNotSentDispatchError`; `StrictEgressClient` carries `request_may_have_been_sent`).

**[existing]** The attestation is the exception class: the consumer raises `ConfirmedNotSentError` "only on evidence, from the code that saw the phase" (its docstring). The dispatcher cannot verify it and does not try to; neither the marker nor the dispatcher ever infers "not sent".

**[proposal]** The attestation is credited only when all of these hold; otherwise the attempt stays `OutcomeUnknown:` as today:

1. The exception that reaches the dispatcher is itself a `ConfirmedNotSentError`, or an exception group in which **every leaf** is one. A group that also holds a bare timeout, an `AmbiguousOutcomeError` member or any other exception is not an attestation (today `_ambiguous_outcome` already ignores `ConfirmedNotSentError` members when others exist; the proposal makes the rule explicit for the retry).
2. The consumer deadline did not expire. #189's precedence is kept: `deadline.expired()` is decided first, so a consumer that ran out of time is dead-lettered `ConsumerTimedOut:` whatever it raised (D-3).
3. Optionally, per D-1: the exception propagated out of the `external_effect()` block. An attestation raised after the block exited normally (for example by a later step, after the request was sent and answered) says nothing about that request, and crediting it could duplicate an effect.

### 4.2 Transition and transaction

A new function in `saas_os/core/outbox/dispatch.py`, named here `record_confirmed_not_sent()` (D-4), not exported, called only by `_record_consumer_failure`. In one `tenant_session_scope(tenant_id)` transaction, through `_locked_claimed_row()` (row lock; `status = 'pending'`; `claim_token = :claim`):

```text
marked and attested, attempts left:
    last_error      = describe_error(error), an existing deadline tag kept
    claim_token     = NULL
    external_started_at = NULL, external_started_claim = NULL   (together)
    next_attempt_at = now() + max(retry_delay(attempts), retry hint if any)
marked and attested, attempts exhausted:
    dead-lettered with the error, marker kept (a dead letter keeps it)
```

Both columns clear in the same statement that releases the claim, so no state exists in which the claim is released and the marker still names it, or the reverse. The pair check `ck_outbox_events_external_started_pair` holds throughout. If the transaction does not commit, nothing changed and the row is still marked.

- **Attempt accounting.** The attempt stays counted (no refund). Reasons: a consumer that always marks and always attests "not sent" is dead-lettered after `OUTBOX_MAX_ATTEMPTS`; it matches the unmarked `ConfirmedNotSentError` path, which counts it; `release_claim()` is for an event that never ran. D-2 offers the alternative.
- **Hints.** A class that is both `ConfirmedNotSentError` and `RetryAfterEventError` keeps both meanings (#195 4a.9; `ConfirmedNotSentError` docstring): delay `max(backoff, hint)`, bounded by `retry_hint_max_seconds`. `RetryAfterEventError` alone stays `OutcomeUnknown:` (section 7).
- **`PermanentEventError`**, alone or combined, stays terminal and keeps the marker.
- **Deadline tag.** An existing `[idempotent-retry-until ...]` tag (an event that earlier carried a `retry_within` outcome) is preserved, and `begin_event_execution()` still dead-letters a retry that would start after it, using the database's clock (`_instant`). Branch A adds no deadline of its own: "not sent" needs none, and the attempt budget bounds it.

## 5. Branch B: `at_least_once` after a marker

**[existing]** #195 3.1 and 4a.9: an `AmbiguousOutcomeError(at_least_once=True)` that the consumer raised after its marker "is honoured as #197 implements it, with no opt-in: retried after `retry_delay()` while attempts remain, dead-lettered when they run out". It is not honoured at reclaim.

**What the marker proves.** That the request may have been sent and its outcome is unknown. The declaration `at_least_once` states that this is acceptable for this destination, whose contract is at-least-once on a stable identity it de-duplicates on. The retry may therefore deliver a second time; the destination's contract, not the marker, makes that safe.

**[proposal] Transition.** In `record_ambiguous_outcome()`, the `_marked_by` guard stops applying to an error that declares `at_least_once`. For it after a marker: record the existing `OutcomeUnknown: ... retried: at-least-once delivery on a stable event id` text and, in the same locked transaction, release the claim, clear both marker columns and set `next_attempt_at = now() + retry_delay(attempts)` while attempts remain; otherwise dead-letter with the marker kept. This is the code path that already exists for the unmarked case; the change is that a marked attempt reaches it. `retry_within` and "no policy" after a marker stay dead-lettered.

**Who may declare it.** **[existing]** Only the transport code that observed the phase raises the error. Today exactly one class does: `WebhookAmbiguousDeliveryError` (webhooks, W1). Resend declares `retry_within`; SMTP declares nothing. **Obligations of a consumer that declares it (existing: W1, `docs/CONSUMER-GUIDE.md`):** a stable identity on every attempt (the outbox `event_id`); a destination contract that it de-duplicates on that identity; the duplicate possibility documented to receivers; never declared for an operation without such a contract.

**Bound.** The attempt budget (`OUTBOX_MAX_ATTEMPTS`, default 10, backoff 30 s doubling to 3600 s with jitter). `at_least_once` carries no `retry_within`, so no deadline of its own applies; an existing deadline tag on the event is still enforced by `begin_event_execution()`. D-5 lists an optional age bound.

### 5.1 What is and is not an opt-in

| Mechanism | Retries what | Opt-in in the sense of #195 3.1? |
|---|---|---|
| A consumer's transport raises `AmbiguousOutcomeError(at_least_once=True)` after its marker | An outcome the consumer recorded itself, on a destination that de-duplicates | **No.** #195 3.1 names it as the case that "is not a crash retry and needs no opt-in" |
| A consumer raises `ConfirmedNotSentError` | An attempt with positive evidence of "not sent" | **No.** It is evidence, not a policy; the unmarked path already retries it |
| A registration that makes reclaim retry an attempt whose crash left a marker (`CrashAfterStart:`), or honours `retry_within` after a marker | An attempt with no recorded outcome, or one whose safety rests on a provider's idempotency window | **Yes.** This is the crash-retry opt-in, forbidden by default. **Not created or enabled by this design**; each needs its five conditions and its own approval |

Options for governing the `at_least_once` declaration (D-6):

| Option | Mechanism | For | Against |
|---|---|---|---|
| **A. The raised exception is the declaration (as #195 3.1)** | No registry, no flag. Runtime unchanged apart from reaching the existing branch | Matches the decided text; no second mechanism that could be mistaken for the crash opt-in; no product registration in Core | A new class could declare it without a visible gate |
| **B. An allow-list of event types in code** | After a marker, `at_least_once` is honoured only for listed event types | A visible gate per consumer | A second per-consumer mechanism beside the crash opt-in (confusion risk); departs from #195 3.1 ("with no opt-in"); Core would need a registration seam for products |
| **C. A plus an architecture test that pins the classes passing `at_least_once=True`** | Runtime as A; a test (AST scan of `saas_os/`) fails when an unlisted class declares it | The gate is a review gate, not a runtime flag, so it cannot be mistaken for the opt-in; no Core registry | Governs `saas_os/` only; a product's own class is governed by its own review |

## 6. Per-consumer declaration without the crash opt-in

- Declaration of branch A: the exception class, by evidence. Declaration of branch B: the exception class, by the destination's contract. Neither is stored, neither is a flag on the consumer's registration, neither is read at reclaim.
- The crash-retry opt-in of #195 3.1 and 4a.9 (a per-consumer registration, "recorded separately from `retry_within`") is not implemented, not exposed and not needed by this design. If it is ever built, it is its own change with its own evidence for conditions 1 to 5 and its own approval.
- Consequence for reclaim: a crash after a marker is `CrashAfterStart:` for every consumer, including one that would have retried the same failure had it raised a typed error. This asymmetry is intended: an exception is evidence, a crash is silence.

## 7. What stays `OutcomeUnknown:` (unchanged)

| Case | Why |
|---|---|
| Crash after a marker (reclaim) | No recorded outcome; the #195 3.1 opt-in is required and none exists |
| `AmbiguousOutcomeError(retry_within=...)` after a marker | Honoured only for a consumer holding the opt-in; none exists. Resend therefore dead-letters after a marker |
| `AmbiguousOutcomeError` with no policy; SMTP ambiguous | By design (F5) |
| `RetryAfterEventError` alone after a marker (for example a `429` with `Retry-After`) | A definitive refusal received after sending; #195 4a.9 leaves it to a later decision (D-7) |
| Any plain exception after a marker, including a `WebhookDeliveryError` for HTTP `5xx` | The exception proves nothing about the request |
| A bare timeout, and #189's consumer deadline | A timeout alone never proves "not sent" |
| A group that mixes an attestation with anything else | The leaf that is not an attestation decides |

## 8. State machine (after the proposal)

States of `core.outbox_events` as in the `dispatch.py` docstring: pending/unclaimed, pending/claimed (unmarked, or marked by the claim), published, dead_lettered. Every write below is conditional on `status = 'pending' AND claim_token = :claim` under the row lock, in the event's tenant scope; a write that matches no row changes nothing.

| From | Event | Condition | To | Marker | Changed here |
|---|---|---|---|---|---|
| claimed, unmarked | `external_effect()` entered | markers on, lease live, not marked by this claim | claimed, marked by the claim, lease renewed | set | no |
| claimed, marked | consumer returns | claim current | published | cleared | no |
| claimed, marked | attested `ConfirmedNotSentError`, attempts left | claim current, section 4.1 | pending/unclaimed, backoff | **cleared** | **new** |
| claimed, marked | attested, attempts exhausted | claim current | dead_lettered | kept | **new** (explicit; the same end state as today, with the attested error in `last_error`) |
| claimed, marked | `at_least_once` outcome, attempts left | claim current | pending/unclaimed, backoff | **cleared** | **new** |
| claimed, marked | `at_least_once`, attempts exhausted | claim current | dead_lettered | kept | no |
| claimed, marked | `retry_within`, no policy, `RetryAfterEventError` alone, bare timeout, other exception, deadline | claim current | dead_lettered `OutcomeUnknown:` or `ConsumerTimedOut:` | kept | no |
| claimed, marked | `PermanentEventError` | claim current | dead_lettered | kept | no |
| claimed, marked | lease expires with no outcome recorded | `claim_due_events` finds `external_started_claim = claim_token` | dead_lettered `CrashAfterStart:` | kept | no |
| claimed, marked | stale worker writes an outcome | the row carries another claim, or is not pending | unchanged (returns None or False) | unchanged | no |
| pending/unclaimed | next claim | `claim_due_events` | claimed by a new token; an older claim's marker never makes the new attempt ambiguous | next marker write uses `IS DISTINCT FROM` | no |
| dead_lettered | operator replay | `platform.outbox:replay` | pending, attempts 0 | cleared | no |

### 8.1 Crash windows (existing behaviour kept)

| Crash point | Result |
|---|---|
| Before the marker commits | Unmarked: reclaim retries (`LeaseExpired:`) |
| After the marker commits, before the request | `CrashAfterStart:` (conservative: nothing was sent, but that cannot be known) |
| After the consumer raised an attestation, before `record_confirmed_not_sent()` commits | The row is still marked: `CrashAfterStart:` at reclaim. The attestation was never recorded, so the safe reading is the ambiguous one: no retry, no duplicate |
| After `record_confirmed_not_sent()` commits | pending, marker cleared: the next claim runs normally; a crash after this point is unmarked |
| After `record_ambiguous_outcome()` (`at_least_once`) commits | Same: pending, marker cleared |
| Worker killed while the lease is live | The event waits for lease expiry (the marker write renews it to `now() + lease`), then as above |

### 8.2 Stale-worker and concurrency conditions

- **Superseded claim.** The lease expired and a dispatcher reclaimed the row (`CrashAfterStart:` if this claim had marked it; a new claim otherwise). The old worker's `record_confirmed_not_sent()` or `record_ambiguous_outcome()` finds `claim_token != :claim` or `status != 'pending'` and changes nothing. An old worker can neither clear a newer claim's marker nor retry a dead-lettered event.
- **Outcome write versus reclaim.** `claim_due_events` uses `FOR UPDATE SKIP LOCKED`; an outcome write holds the row lock, so the reclaim skips the row until the write commits, then sees the new state.
- **Two outcomes for one claim.** The first to commit wins; the second finds the claim cleared and returns None. `_write_outcome()` already retries a failed write a bounded number of times and treats a repeat as a no-op.
- **An outcome write that keeps failing.** The lease expires and the row is reclaimed as `CrashAfterStart:` (marked). This fails closed.
- **Tenant closure.** `begin_event_execution()` releases the claim of a closed tenant before the consumer runs, so a marked attempt cannot exist for it.

## 9. Failure and recovery cases

| Case | Result | Operator action |
|---|---|---|
| A consumer attests wrongly (raises `ConfirmedNotSentError` after sending) | The retry may duplicate the effect: the residual risk of attestation | Fix the consumer; D-1(b) narrows it; review of every `ConfirmedNotSentError` raise site is part of the follow-up |
| Attested errors repeat until attempts run out | Dead-lettered with the error, marker kept; `last_error` names the category | Check the destination, replay |
| `at_least_once` retries and the receiver does not de-duplicate | A duplicate delivery; the contract (W1) puts the obligation on the receiver | Receiver fix |
| Markers turned off after being on | Only marker writes stop; stored markers are still read, and the new branches apply to events already marked | As `OUTBOX-STARTED-MARKER.md` section 4 |
| Rollback to code without these branches | Marked attempts dead-letter `OutcomeUnknown:` again (the D4 behaviour) | None; conservative |
| An outcome write fails after its retries | `CrashAfterStart:` at reclaim | Check the destination, replay |

## 10. Security, privacy, compatibility

**Security.** Tenant isolation and RLS are untouched: the new function runs only under `tenant_session_scope(tenant_id)` and reads or writes only the locked row of that event. No cross-tenant read, no RLS bypass, no new privilege, no new grant, no runtime `DELETE`; `_DELETION_ENABLED` is untouched. Authorization is the claim: only the holder of the live claim token changes the row. A buggy consumer can at worst mis-attest within its own tenant's event and its own destination, bounded by the attempt budget. The security-relevant change is that a retry after a marker becomes possible, which is why attestation is narrow (4.1) and every other path stays dead-lettered. Outbox state changes are not platform or tenant audit rows today; dead letters and replay keep their existing evidence. A retried attempt overwrites `last_error`; the previous attempt's category survives only in the structured log events `outbox_event_failed` and `outbox_event_outcome_unknown` (event id, error type, phase; never the payload). D-8 notes this.

**Privacy.** `last_error` and logs carry categories and identifiers only; the new text uses `describe_error()` like the existing paths. No payload, URL, recipient or secret is stored by the new branches.

**Migration and compatibility.** No migration is expected: no column, constraint, index, grant or policy changes; the pair check and the marker-write predicate already cover the states used. Public API: a non-exported function in `saas_os/core/outbox/dispatch.py` (D-4) needs no `public_api_snapshot.txt` change. `TenantJobContext` changes only if D-1(b) is chosen (an additive internal hook, default-off behaviour unchanged). The behaviour change is confined to marked attempts, which exist only when `OUTBOX_EXTERNAL_EFFECT_MARKERS` is on and a consumer uses `external_effect()`; neither is true in any shipped configuration.

## 11. Decisions needed from the owner

Each lists options, trade-offs and a recommendation. Nothing is decided here.

| ID | Decision | Options and trade-offs | Recommendation |
|---|---|---|---|
| D-1 | How narrow the "not sent" attestation is | (a) The exception class alone, with the leaf rule for groups (matches #195 4a.9; a consumer that raises a `ConfirmedNotSentError` after a completed send duplicates). (b) (a) plus the exception must propagate out of the `external_effect()` block; costs an additive hook in `TenantJobContext` and the dispatcher's starter, and removes the "raised after the block" error class | (b), as the conservative default: the marker brackets the send, so an attestation should come from that bracket |
| D-2 | Attempt accounting after an attested retry | (a) Counted, no refund (consistent, bounded). (b) Refunded like `release_claim()`: a transient connect failure never exhausts attempts, but a loop of mark-then-fail-to-connect is unbounded unless a second bound is added | (a) |
| D-3 | Consumer deadline versus attestation | (a) Keep #189: if the deadline expired, dead-letter `ConsumerTimedOut:` whatever was raised (a "deadline expired before any request started" attestation is not credited). (b) Credit an attestation raised at the deadline | (a) |
| D-4 | Shape of the retry entry point | (a) A new non-exported `record_confirmed_not_sent()` beside `record_ambiguous_outcome()`; `fail_event()` keeps refusing every marked attempt, so "no caller can retry a marked attempt" holds for the public function. (b) A keyword on exported `fail_event()`: any caller could assert it, against the intent of #195 4a.9. #195's text says "through `fail_event()`"; (a) honours its rule with a different function | (a); an engineering choice that departs from the letter of #195, so it is listed |
| D-5 | Bound for `at_least_once` | (a) The attempt budget only (as #195 and #197). (b) Also an age bound from `created_at` (for example the 24-hour hint ceiling), dead-lettering a retry that would start later; one more rule, no schema | (a); (b) only if the owner wants a time bound on duplicates |
| D-6 | Governance of the `at_least_once` declaration | Options A, B, C of section 5.1 | C |
| D-7 | A definitive refusal received after sending (`429`, `503` and similar) | (a) Stays `OutcomeUnknown:` (today). (b) A typed "refused before effect" attestation, credited like branch A; needs the provider's evidence (Resend treats every `5xx` as ambiguous, ADR-0058). (c) Each consumer declares it as `at_least_once` where its contract allows (webhooks under W1) | Decide with the first consumer's follow-up (section 12), not here; (a) until then |
| D-8 | Evidence that an ambiguous attempt was retried | (a) Structured log events only (today). (b) Keep the previous category in `last_error` across retries (a rule change in `_record_error`); no schema | (a) |
| D-9 | A dead letter after attested exhaustion keeps the marker | (a) Keep (every dead letter keeps it; replay clears). (b) Clear, since "not sent" was attested | (a) |
| D-10 | Approve implementing branches A and B | Yes, as one code-only pull request with markers staying off / split A and B / not now | Yes, one pull request, with the tests of section 13 |

**To add to the deferred-issue ledger on approval** (`docs/P-ROADMAP.md` is not edited by this change):

| Field | Entry |
|---|---|
| Issue | After a started marker, `ConfirmedNotSentError` and `at_least_once` outcomes dead-letter `OutcomeUnknown:` (#195 4a.9 retry branches not implemented) |
| Severity | LOW (fail-closed: no duplicate, no leak) |
| Component | `saas_os/core/outbox/dispatch.py`, `saas_os/api/outbox_dispatcher.py` |
| Scope | Unrelated to current steps; follows D4 |
| Status | Deferred |
| Evidence | `OUTBOX-STARTED-MARKER.md` section 6; the table of section 2 |
| Risk | Blocks wiring any consumer to `external_effect()`; none otherwise |
| Required phase | The implementation pull request of D-10 |
| Blocks progression | Blocks consumer wiring only |

## 12. First consumer to wire: a separate follow-up with its own decision

Not part of this design's implementation. Facts only:

| Consumer | After the branches of this design | Still dead-lettered after a marker |
|---|---|---|
| **Webhooks** (`saas_os/core/webhooks`) | `WebhookNotSentError` (connect failure, proxy, pre-address deadline) retries; `WebhookAmbiguousDeliveryError` (`at_least_once`, W1) retries within attempts | A received retryable status (HTTP `408`, `429`, `5xx` raise a plain `WebhookDeliveryError`): D-7. A crash at reclaim |
| **E-mail** (`saas_os/core/notifications`, Resend, SMTP) | `NotificationNotSentDispatchError` retries | Resend ambiguous (`retry_within`) after a marker: needs the opt-in of #195 3.1, none approved. SMTP ambiguous: by design. A provider refusal with `Retry-After`: D-7 |

Observation: webhooks is the only consumer with a declared `at_least_once` contract, so it is the only one for which these branches suffice without a new opt-in, once D-7 is settled for its `5xx` refusals. The follow-up needs its own decision, evidence and pull request, and enabling `OUTBOX_EXTERNAL_EFFECT_MARKERS` is a separate operator action (deployment order in `OUTBOX-STARTED-MARKER.md` section 3).

## 13. Test plan for the implementation pull request

**Unit (no database).** The leaf rule for groups (all confirmed; confirmed plus a bare timeout; plus an `AmbiguousOutcomeError`; plus a `RuntimeError`); `retry_after` with a class that is both confirmed and `RetryAfterEventError`; a combined `PermanentEventError` stays terminal; the deadline precedence (D-3); with D-1(b), an attestation raised after the block exits normally is not credited; the exact `last_error` texts (no URL, no payload).

**PostgreSQL 16 integration**, through the real dispatcher and `tenant_session_scope`, markers on:

- attested `ConfirmedNotSentError` after a marker: status pending, `claim_token` NULL, both marker columns NULL, `attempts` unchanged, `next_attempt_at` equal to the database's `now()` plus backoff (compared with the database clock, not the host's), `last_error` set; the next claim writes a new marker and the event completes once;
- attested on the last attempt: dead-lettered, marker kept;
- `at_least_once` after a marker: retried and cleared; on the last attempt dead-lettered with the marker kept; `retry_within` after a marker still dead-letters (Resend path); no policy still dead-letters;
- every row of the section 7 table still dead-letters with the marker kept;
- `fail_event()` still dead-letters a marked attempt whatever it is given;
- RLS: through the application role under tenant A, the new function cannot change tenant B's event; a job of another tenant cannot clear the marker;
- an existing deadline tag survives a retry, and a retry after the tag is dead-lettered by `begin_event_execution()`;
- the migration gate is unchanged (no revision; the expected head does not move).

**Concurrency.** A stale worker's outcome versus a reclaim, in both orders, with a barrier at the `_claim_hook` seam: exactly one wins and the loser changes nothing; two dispatchers claiming around an outcome write; two outcomes for one claim; rows left over by a test are removed so later downgrade tests are not blocked.

**Real-process crash tests** (the harness of `tests/core/outbox/test_outbox_started_marker_crash_integration.py`): a worker killed (a) after the attestation is raised and before the outcome commits: `CrashAfterStart:`, no retry; (b) after the outcome commits: the retry runs once; (c) during the `at_least_once` retry's own request: `CrashAfterStart:` for the new claim; (d) with the stale worker resuming after reclaim: no effect.

**Negative controls** (each must fail the intended tests, then be restored byte-identically): remove the claim predicate from the new write; accept a mixed group as an attestation; honour `retry_within` after a marker; make `fail_event()` retry a marked attempt; skip the marker clear; ignore the deadline precedence.

## 14. Evidence required before enabling anything

The implementation pull request enables nothing. Before any installation turns `OUTBOX_EXTERNAL_EFFECT_MARKERS` on:

- this design approved, and its tests green on the exact final head with PostgreSQL 16 and Redis 7 (counts, commands and negative controls in the pull request);
- the consumer follow-up of section 12 approved, with the raise sites of `ConfirmedNotSentError` and `at_least_once` reviewed against the transport's real evidence, and its own crash-before, crash-during and crash-after tests;
- the deployment order of `OUTBOX-STARTED-MARKER.md` section 3 followed (no older dispatcher or worker can claim events);
- an operator runbook line for `OutcomeUnknown:` and `CrashAfterStart:` dead letters (check the destination, then replay).

Green CI is not production readiness; a crash-retry opt-in (#195 3.1) still needs its own evidence and approval.
