# HTTP webhook destinations: compatibility and migration assessment

**Status: decided 2026-10-27 (option 3, a boolean `WEBHOOK_ALLOW_HTTP`, two releases); release 1 shipped in `main` (pull request #131); release 2 implemented in this change, which is held until a published release contains release 1 (section 7).** See section 6. The intended direction is HTTPS on port 443 by default, with plain HTTP only by explicit opt-in (ADR-0059 decision 5). This page records what that would change, and for whom, before anything does.

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

| | Release 1 (pull request #131) | Release 2 (this change; held, section 7) |
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
1. A release containing release 1 is published, and its changelog announces the warning and the coming refusal (section 6). Release 2 is not merged before then, so that deployments get at least one release of warnings first.
2. Each deployment, while on release 1:
   - looks for `webhook_http_destination_deprecated` in its worker and API logs, and runs the read-only inventory query (section 2);
   - then either moves those subscriptions to `https://`, or sets `WEBHOOK_ALLOW_HTTP=true` deliberately. Setting `false` while still on release 1 tries release 2's behaviour in advance.
3. Release 2 is merged and published, and its changelog states that an unset `WEBHOOK_ALLOW_HTTP` now refuses `http://`.
4. Consumers adopt it only by moving their exact-SHA pin, as with any release.

**What release 2 does to existing `http://` subscriptions** (unset setting):
- Each event for one is refused at delivery, before resolution, as `WebhookDestinationRejectedError`, which is permanent: the event is dead-lettered at once, not retried.
- The subscription row is kept, and the operator replaces or removes it.
- New `http://` subscriptions are refused with `InvalidWebhookUrlError`.

**Rollback.**
- **Preferred: set `WEBHOOK_ALLOW_HTTP=true`.** It restores delivery to `http://` without changing code, and it takes effect when the API and the workers restart.
- **Alternatively, revert the change or pin the previous release.** That restores release 1 (allowed, with warnings).
- **Neither replays events.** Events dead-lettered while `http://` was refused stay dead-lettered; SaaS-OS has no dead-letter replay. The next events are delivered normally.
- **A deployment that cannot afford lost events** to an `http://` destination sets `true` (or moves the destination to `https://`) before upgrading, not after.

**Network.** In the reference topology (ADR-0059), the egress proxy allows port 443 only, so `http://` was never reachable there in either release, whatever the setting. Release 2 changes what the application accepts, not what the network allows.

**Evidence (release 2):**
- **`tests/core/webhooks/test_webhook_allow_http_unit.py`** covers:
  - an unset setting refuses at subscription, with no warning;
  - an existing subscription is refused at delivery, permanently and before resolution;
  - `true` is still honoured;
  - the release 1 tests set `HTTP_ALLOWED_WHEN_UNSET = True`, so the rollback stays tested.
- **`test_webhooks_integration.py`:** `subscribe()` stores an `http://` subscription only with `true`.
- **Modules whose receivers are local plain-HTTP servers** opt in explicitly with `WEBHOOK_ALLOW_HTTP=true` in a module fixture: the delivery, durability and outbox idempotency integration tests, and the deadline unit test.

