# HTTP webhook destinations: compatibility and migration assessment

**Status: decided 2026-10-27 (option 3, a boolean `WEBHOOK_ALLOW_HTTP`, two releases); release 1 published in v0.6.0 (pull request #131; tag `v0.6.0`, 2026-10-31); release 2 implemented in pull request #133, for the next minor release (section 7).** See section 6. The intended direction is HTTPS on port 443 by default, with plain HTTP only by explicit opt-in (ADR-0059 decision 5). This page records what that would change, and for whom, before anything does.

## 1. Current behaviour (`main` at `18ea05c`)

- **Subscription:** `_validate_url()` in `saas_os/core/webhooks/service.py` accepts `http` and `https` URLs. ADR-0035 says "`http://` is still accepted, unchanged".
- **Ports:** `WEBHOOK_ALLOWED_PORTS` is optional and unset by default, so any port is allowed. When set, it is checked at subscription and again before every delivery, where the default port is 443 for `https` and 80 for `http` (`_require_allowed_port()`). A delivery to a port the setting no longer allows is a permanent rejection, dead-lettered rather than retried.
- **Delivery:** the signed body goes to the destination as given. Over `http://`, the payload, the signature header and the URL's path and query (often a credential) cross the network unencrypted, and anyone on the path can read or alter them. The HMAC signature lets a receiver detect alteration, but it does not keep the content confidential.
- **Reference topology with ADR-0059:** the egress proxy allows port 443 only.
  - An `http://` destination is tunnelled as `CONNECT <ip>:80`, which the proxy refuses. The webhook client then raises `WebhookDestinationRejectedError` (permanent).
  - This is not a regression in that topology, because before ADR-0059 the worker could not reach any destination there.
  - Products that run their own worker, or don't configure the proxy, are unaffected.

## 2. Who a default change would affect

| Deployment | Effect of "HTTPS on 443 by default" |
|---|---|
| Reference production topology (ADR-0059) | None. Port 443 is already the proxy's only allowed port. |
| A product with its own egress and no `WEBHOOK_ALLOWED_PORTS` | Existing `http://` subscriptions and those on other ports would stop being delivered. New ones would be refused at subscription. |
| A product with `WEBHOOK_ALLOWED_PORTS` that includes 80 | Unchanged, if the opt-in keeps honouring an explicit list. |
| Tests and local development (`http://localhost`, mock receivers) | Already refused: non-public addresses never pass the destination check. Local receivers on public names would need the opt-in. |

The number of existing `http://` subscriptions or non-443 ports per deployment is **unknown**. SaaS OS has no deployment data. Each product has to count them:

```sql
SELECT scheme, port, count(*) FROM (
  SELECT split_part(url, ':', 1) AS scheme,
         coalesce(substring(url FROM '^[a-z]+://[^/:]+:([0-9]+)'), 'default') AS port
  FROM core.webhook_subscriptions
) s GROUP BY 1, 2;
```

This is a read-only query, run by the product's operator with the migrations role, because the table is tenant-scoped.

## 3. Options

1. **Keep today's default; document HTTPS as recommended.** No compatibility impact, and plaintext webhooks stay possible everywhere.
2. **Refuse new `http://` subscriptions by default and keep delivering existing ones.** No delivery stops, and new plaintext subscriptions need the opt-in. Existing ones keep leaking until they are replaced. That needs a per-subscription grandfathering rule, because a subscription would otherwise be refused at its next delivery-time check.
3. **Refuse `http://` at subscription and at delivery by default, with an explicit opt-in (`WEBHOOK_ALLOW_HTTP=true`, or `WEBHOOK_ALLOWED_PORTS` naming 80).** This is consistent with the reference topology and closes the plaintext path. Existing `http://` subscriptions stop and are dead-lettered (permanent) unless the deployment opts in.

## 4. Recommended migration path (for option 3)

1. **Release N (warning only).** Add the opt-in setting with today's default (HTTP allowed). Log a warning at worker start when any `http://` subscription exists; the warning carries the count only, never the URL. Document the setting and the query above in `docs/CONSUMER-GUIDE.md` and the changelog.
2. **Release N+1 (default flips).** HTTPS only, with port 443 unless `WEBHOOK_ALLOWED_PORTS` says otherwise. HTTP needs the explicit opt-in. Changelog and upgrade notes state that existing `http://` subscriptions stop at the upgrade unless the opt-in is set.
3. **Tests for each step:**
   - the default refuses `http://` at subscription, and at delivery as a permanent rejection;
   - the opt-in restores today's behaviour exactly;
   - an explicit `WEBHOOK_ALLOWED_PORTS` still wins;
   - the warning carries no URL.
4. **Products** either move their receivers to HTTPS or set the opt-in deliberately. The opt-in also means adding port 80 to the proxy's `egress_ports` (ADR-0059 decision 5).

## 5. Decisions needed before any default changes

- Option 1, 2 or 3; option 3 is recommended.
- The opt-in's form: a boolean, `WEBHOOK_ALLOWED_PORTS` alone, or both.
- Whether the change waits for the next minor release with the warning step first (recommended), or lands at once.

## 6. Decision and behaviour per release (owner, 2026-10-27)

Option 3, with the opt-in a boolean `WEBHOOK_ALLOW_HTTP`. It follows the repository's boolean convention (`1`/`true`/`yes`/`on`, `0`/`false`/`no`/`off`), and anything else is a configuration error. `WEBHOOK_ALLOWED_PORTS` is not an opt-in: naming 80 there does not override `false`. The reference topology's proxy stays at port 443 only, so the setting cannot widen the network.

| | Release 1 (pull request #131, v0.6.0) | Release 2 (pull request #133; section 7) |
|---|---|---|
| `WEBHOOK_ALLOW_HTTP` unset | `http://` allowed. Subscribing, and the first delivery per subscription in each worker process, log `webhook_http_destination_deprecated` with the phase, tenant or subscription id and the setting's name, never the URL. | `http://` refused |
| `false` | Refused | Refused |
| `true` | Allowed, no warning | Allowed, no warning |
| New `http://` subscription, when refused | `InvalidWebhookUrlError` at `subscribe()`; nothing is stored | Same |
| Existing `http://` subscription, when refused | At its next delivery, `WebhookDestinationRejectedError` (permanent), before any resolution; dead-lettered, not retried. The subscription row is kept, and the operator replaces or removes it. | Same |
| Reference topology (ADR-0059) | Refused by the proxy (port 443 only), even with `true` | Same |

**Evidence (release 1):**
- **Unit tests:** `tests/core/webhooks/test_webhook_allow_http_unit.py` covers:
  - the default, parsing and invalid values;
  - the warning, which names no URL, host, path or query, and is logged once per subscription at delivery;
  - `true` is silent and `false` refuses at subscription;
  - an existing subscription is refused before resolution, as a permanent error, when the setting is `false`, and still delivered (with a warning) when unset;
  - the port list is not an opt-in;
  - release 2's flip alone refuses an unset setting and keeps honouring `true`.
- **Negative controls:** removing the delivery check, or the refusal, fails the tests meant to catch it.
- **End to end:** `scripts/check-egress-e2e.sh` shows that `http://` with `WEBHOOK_ALLOW_HTTP=true` is still refused by the proxy (`WebhookDestinationRejectedError`).
- **Topology:** `tests/architecture/test_production_identity_topology.py` asserts that the reference worker does not set the variable.

**Changelog:** the release pull request that ships release 1 must say that `http://` destinations warn now and will be refused in the next release, and must point to this page and the inventory query.

**Malformed values fail closed.** A value outside the boolean words raises `WebhookConfigurationError`, which names the variable and the value (both non-secret).
- **At worker start:** the worker refuses to start (`worker_startup_failed`, before any database access), so a typo cannot fail every delivery later, `https://` included.
- **At subscription:** the request fails, and nothing is stored.
- **Test:** `tests/api/test_worker_unit.py::test_main_fails_closed_on_an_invalid_webhook_allow_http` fails without the startup check.

**Concurrency.** The check and the deduplication run before the first `await` in the delivery, so deliveries running concurrently in one worker log a single warning. This is shown by `test_concurrent_deliveries_of_one_subscription_warn_once`, which fails without the deduplication. The warned set holds subscription ids only, and is bounded by the number of `http://` subscriptions.

**Application versus network.** `WEBHOOK_ALLOW_HTTP` decides what the application accepts. Whether a destination is reachable is decided separately by the network. In the reference topology, the egress proxy allows port 443 only, so `true` makes `http://` acceptable to the application but never reachable there.

**Residual:** the warning is per worker process. A deployment with many workers, or frequent restarts, logs it more than once per subscription.

## 7. Release 2: sequencing and rollback

Release 2 is a single change, `HTTP_ALLOWED_WHEN_UNSET = False` in `saas_os/core/webhooks/config.py`. Nothing else changes: the setting, its parsing, the refusal points and the warning code are release 1's. It has no schema change and no migration.

**Sequencing.**
1. A release containing release 1 is published, and its changelog announces the warning and the coming refusal (section 6). Release 2 is not merged before then, so that deployments get at least one release of warnings first. **Done:** v0.6.0 (2026-10-31) contains release 1. Its changelog lists `WEBHOOK_ALLOW_HTTP` (unset warns, `false` refuses, `true` allows) and names #133 as release 2 of retiring `http://` destinations, but does not say in so many words that the next release refuses an unset setting, nor point to this page's inventory query, as section 6 asks. The changelog of the release containing release 2 therefore has to carry the full notice (step 3).
2. Each deployment, while on release 1:
   - looks for `webhook_http_destination_deprecated` in its worker and API logs, and runs the read-only inventory query (section 2);
   - then either moves those subscriptions to `https://`, or sets `WEBHOOK_ALLOW_HTTP=true` deliberately. Setting `false` while still on release 1 tries release 2's behaviour in advance.
3. Release 2 is merged and published, and its changelog states that an unset `WEBHOOK_ALLOW_HTTP` now refuses `http://`, what happens to existing subscriptions, the inventory query (section 2) and the rollback below. It is a minor release (ADR-0015, version numbers before 1.0): a default that refuses what the previous release accepted is a breaking change for a deployment that relies on it, announced and with a documented migration, not a patch.
4. Consumers adopt it only by moving their exact-SHA pin, as with any release.

**What release 2 does to existing `http://` subscriptions** (unset setting):
- Each event for one is refused at delivery, before resolution, as `WebhookDestinationRejectedError`, which is permanent: the event is dead-lettered at once, not retried. Its stored `last_error` is `WebhookDestinationRejectedError: Webhook destination rejected: plain http:// is not allowed (replace the subscription with an https:// one, or set WEBHOOK_ALLOW_HTTP=true).`, never the URL.
- The subscription row is kept, and the operator replaces or removes it.
- New `http://` subscriptions are refused with `InvalidWebhookUrlError`, message `Invalid webhook URL (plain http:// is not allowed: use https://, or set WEBHOOK_ALLOW_HTTP=true).` (a scheme in any letter case, `HTTP://` included).
- `https://` subscriptions are not affected.

**Rollback.**
- **Preferred: set `WEBHOOK_ALLOW_HTTP=true`.** It restores delivery to `http://` without changing code, and it takes effect when the API and the workers restart.
- **Alternatively, revert the change or pin the previous release.** That restores release 1 (allowed, with warnings).
- **Neither replays events by itself.** Events dead-lettered while `http://` was refused stay dead-lettered; the next events are delivered normally. Since v0.6.0 a platform operator holding `platform.outbox:replay` can return them to `pending` with `saas-os-operator replay-outbox-events` (`docs/RUNBOOKS.md`, operator commands). Replay them **by event id, never by time** (procedure below).

**Replaying the refused deliveries safely.** `--dead-lettered-since` selects every dead-lettered event of the tenant whose row last changed at or after that time: every event type (other webhook deliveries, email and billing events, a product's own consumers) and every cause (a receiver's `410`, a malformed event, an exhausted retry budget), not only the deliveries release 2 refused. Replaying those would run events that were dead-lettered for a reason, for example a webhook to a receiver that answered `410 Gone`. Its preview is a count, not a list. So:

1. Set `WEBHOOK_ALLOW_HTTP=true` and restart the API and the workers. A replayed event is delivered to the subscription as stored, so replaying first only dead-letters it again.
2. List exactly the deliveries release 2 refused, read-only, with the migrations role (the table is tenant-scoped). They are the only rows with this `last_error`:

   <!-- release-2-refused-deliveries -->
   ```sql
   SELECT id
     FROM core.outbox_events
    WHERE tenant_id = '<tenant id>'
      AND event_type = 'webhook.delivery'
      AND status = 'dead_lettered'
      AND last_error = 'WebhookDestinationRejectedError: Webhook destination rejected: plain http:// is not allowed (replace the subscription with an https:// one, or set WEBHOOK_ALLOW_HTTP=true).'
    ORDER BY id;
   ```
3. Count with those ids: `saas-os-operator replay-outbox-events --tenant <id> --operator <user id> --event-id <id> [--event-id <id> ...] --reason "<ticket>: http:// refused by release 2, <n> events"`, without `--apply`. The count must equal the query's row count. An id of another tenant, or an event that is not dead-lettered, is never counted or replayed.
4. Run the same command with `--apply`. At most 1000 ids per run; split a longer list. Each applied run writes one platform audit row and one tenant audit row with the count and the reason, not the ids, so keep the query's output with the ticket.

**No undo.** An applied replay makes the events due at once, and there is no command that dead-letters them again. Check the count before `--apply`; if a wrong set was applied, stop the workers at once (`pending` events are not delivered while no worker runs) and decide before restarting them. A replayed webhook delivery is sent at most once more per event: the delivery records its completion on the outbox event's id and skips one already recorded (RE-5), and a delivery release 2 refused was never sent.
- **A deployment that cannot afford lost events** to an `http://` destination sets `true` (or moves the destination to `https://`) before upgrading, not after.

**Network.** In the reference topology (ADR-0059), the egress proxy allows port 443 only, so `http://` was never reachable there in either release, whatever the setting. Release 2 changes what the application accepts, not what the network allows.

**Evidence (release 2):**
- **`tests/core/webhooks/test_webhook_allow_http_unit.py`** covers:
  - an unset setting refuses at subscription, with no warning;
  - an existing subscription is refused at delivery, permanently and before resolution;
  - `true` is still honoured;
  - the release 1 tests set `HTTP_ALLOWED_WHEN_UNSET = True`, so the rollback stays tested;
  - both refusals name the setting and the fix, never any part of the URL, and are not chained to another error;
  - `HTTP://` in any letter case is refused like `http://`;
  - `https://` is delivered as before.
- **`test_webhook_delivery_durability_integration.py::test_release_two_dead_letters_an_existing_http_subscription_until_opted_in`:** a subscription stored under `true`, delivered with the setting unset: dead-lettered after one attempt, nothing sent, the stored `last_error` exact and without the host, port or path, also in the log; after `true`, the next event is delivered and the refused one stays dead-lettered.
- **Negative controls (2026-10-31 audit):** without the message, the message test fails; a case-sensitive scheme check fails the letter-case tests (3).
- **`test_webhooks_integration.py`:** `subscribe()` stores an `http://` subscription only with `true`.
- **Modules whose receivers are local plain-HTTP servers** opt in explicitly with `WEBHOOK_ALLOW_HTTP=true` in a module fixture: the delivery, durability and outbox idempotency integration tests, and the deadline unit test.

**Draft changelog notice for the release containing release 2** (the release pull request writes the entry; ADR-0015):

> **Plain `http://` webhook destinations are refused by default** (#133, ADR-0035 amendment of 2026-10-27). With `WEBHOOK_ALLOW_HTTP` unset, `subscribe()` refuses an `http://` URL (`InvalidWebhookUrlError`), and each delivery to an existing `http://` subscription is dead-lettered at once (`WebhookDestinationRejectedError`, permanent, nothing sent); `https://` is not affected. Before upgrading, find such subscriptions with the `webhook_http_destination_deprecated` log line of v0.6.0 or the inventory query in `docs/architecture/WEBHOOK-HTTP-DESTINATIONS-ASSESSMENT.md`, section 2, then move them to `https://` or set `WEBHOOK_ALLOW_HTTP=true` deliberately. Rollback: set `true` and restart the API and workers; then replay the deliveries dead-lettered in between by event id (the query in section 7 of the assessment), never with `--dead-lettered-since`, which also selects the tenant's unrelated dead-lettered events. No migration.
