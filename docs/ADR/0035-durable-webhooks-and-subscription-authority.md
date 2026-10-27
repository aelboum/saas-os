# ADR-0035: Durable webhooks, subscription authority and SSRF hardening (Foundation Reliability & Events, RE-4)

Status: Accepted and implemented
Date: 2026-10-02
Supersedes / Superseded by: — (builds on [ADR-0031](0031-foundation-authority-and-evidence.md), [ADR-0032](0032-transactional-outbox.md), [ADR-0033](0033-durable-outbox-dispatcher.md); audit findings RE-F2, RE-F7, RE-F8)

## Context

After RE-1/RE-2, every webhook delivery was already a durable `webhook.delivery` outbox row with durable attempts, bounded retries and a durable dead-letter state. Three gaps remained:

- **Failure classification (RE-F2).** Every delivery failure was retried identically: a `410 Gone`, a redirect, an event with a broken payload and a destination resolving to an internal address all spent the full retry budget.
- **Subscription authority (RE-F7).**
  - `subscribe()`/`unsubscribe()` took an optional `actor_user_id`, where `None` meant "system".
  - They authorized nothing.
  - They wrote their audit entry after commit, in a separate transaction.
  - A subscription is a standing channel that sends tenant data to an arbitrary destination.
- **SSRF (RE-F8).** Destination validation rejected `is_private`/loopback/link-local/unspecified/reserved/multicast addresses, but carrier-grade NAT `100.64.0.0/10` is none of those. That let a delivery reach, for example, the `100.100.100.200` cloud-metadata address.

## Decision

**Failure classification.**
- A consumer raises `core.outbox.PermanentEventError` when retrying cannot succeed. The dispatcher (`_run_outbox_event`) dead-letters such an event at once; any other exception is retried within the bounded budget.
- Webhook delivery classifies its failures:

| Failure | Class | Outcome |
|---|---|---|
| Network error, timeout | `WebhookDeliveryError` | retried |
| DNS failure / no addresses | `WebhookDestinationUnresolvedError` | retried (re-validated each attempt) |
| HTTP 408, 429, 5xx, 401, 403, 404 and any other non-2xx not listed below | `WebhookDeliveryError` | retried |
| HTTP 3xx (redirects are never followed) and 400, 410, 413, 422 | `WebhookPermanentDeliveryError` | dead-lettered |
| Destination resolves to / names a non-public address | `WebhookDestinationRejectedError` | dead-lettered, nothing sent |
| Malformed delivery event | `MalformedWebhookEventError` | dead-lettered |
| Unknown event type | (dispatcher) | dead-lettered (RE-2) |

- 401/403/404 stay retryable: a receiver's misconfiguration can be fixed while the event is within its retry budget.
- The new error classes subclass the pre-RE-4 ones (`InvalidWebhookUrlError`, `WebhookDeliveryError`), so existing callers' `except` clauses still match.
- Signing, timeouts, the unread response body (CP-06-WH-01) and pinning the connection to the validated address are unchanged.

**Subscription authority.** `subscribe(tenant_id, url, *, caller)` and `unsubscribe(tenant_id, subscription_id, *, caller)` follow ADR-0031:
- **Caller:** a typed `caller`, required and keyword-only.
- **Authorization:** `can()` for `(webhook_subscription, create|delete)`, evaluated inside the mutation's own tenant transaction, so explicit deny and tenant scoping apply. A provisioning `SystemCaller` is the only system authority accepted.
- **Audit:** written in the same transaction (`record_in_transaction`).
- **Lookup:** `unsubscribe` checks authority before the lookup, so an unauthorized caller learns nothing about which subscriptions exist, and the lookup is RLS-scoped to the caller's tenant.
- **Support access:** `webhook_subscription` joins `AUTHORITY_RESOURCES`, so support access can never create or remove a subscription.

These are the only mutating subscription operations; there is no update, enable/disable or secret rotation, and none was added.

**SSRF policy.**
- A destination address must be globally routable unicast. `_is_non_public_address()` now refuses everything `ipaddress` reports as not `is_global`, which covers:
  - carrier-grade NAT `100.64.0.0/10`;
  - documentation, benchmarking and IETF ranges;
  - `0.0.0.0/8` and `240.0.0.0/4`, plus the IPv6 counterparts.
- The previous checks are kept, plus explicit multicast and IPv6 site-local (`fec0::/10`) checks, because some Python versions report those as global.
- An IPv4 address embedded in an IPv6 one (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) must pass too. NAT64 and 6to4 are refused outright on the Python in use, since it reports both prefixes as non-global. *(Correction, 2026-10-27: the outcome holds, the reason is exact for 6to4 only. On Python 3.13.14 `ipaddress` reports `64:ff9b::/96` as global but reserved, and the policy refuses reserved addresses, so a NAT64 address is refused even when its embedded IPv4 is public; `tests/core/webhooks/test_webhook_ssrf_policy_unit.py` pins both prefixes.)*
- The policy is applied to every resolved address immediately before each attempt, so DNS rebinding is caught. It is also applied to a literal address at subscription time.

## Consequences

- **Breaking change for consumers.** `subscribe`/`unsubscribe` require `caller=`; `actor_user_id` is gone. Tenant administrators need the `webhook_subscription:create|delete` capabilities.
- A permanently refused or malformed delivery stops after one attempt rather than ten.
- Previously accepted destinations in `100.64.0.0/10` (and the other newly refused ranges) are refused, both at subscription time (literal addresses) and at delivery time (resolved addresses).

## Review conclusions (no change)

- **Replay.** The only "replay" mechanism is the receiver-side replay ledger (`verify_and_record_webhook_delivery`). It is durable, unique per `(tenant, subscription, event_id)` and RLS-scoped, so it was left unchanged. No operation re-delivers a dead-lettered webhook; operator replay stays deferred, as in ADR-0033.
- **Durability.** Delivery state, attempts, retry schedule and terminal state already live in the outbox row (RE-1/RE-2); RE-4 adds no table.

## Explicitly not part of this decision (deferred)

- **Operator replay** of dead-lettered deliveries: needs a typed, authorized, audited action.
- **`Retry-After`** on 429/503: still ignored; retries follow the outbox backoff.
- **HTTPS-only destinations:** `http://` is still accepted, unchanged.

> **Amended 2026-10-27** (owner decision 4): plain `http://` destinations are retired over two releases with `WEBHOOK_ALLOW_HTTP`. Release 1 warns by default (no URL logged); `false` refuses at subscription (`InvalidWebhookUrlError`) and at delivery (`WebhookDestinationRejectedError`, permanent); `true` allows. Release 2 refuses unless `true` (implemented after release 1 was published; sequencing and rollback in section 7 of the assessment). The behaviour per release, and what happens to existing subscriptions, is in `docs/architecture/WEBHOOK-HTTP-DESTINATIONS-ASSESSMENT.md`, section 6.
- **Consumer idempotency** (RE-5) and **rate-limit dimensions** (RE-F9).

## Amendment (2026-10-18): no environment trust for webhook delivery (ADR-0054 Q2)

**Decision (owner, 2026-10-18, accepting the recommendation of `docs/RELEASE-READINESS.md` section 4 item 4).** The webhook delivery client is built with `trust_env=False`, as AI egress already is (ADR-0054 section 8b).

> **Amended 2026-10-27 by [ADR-0059](0059-controlled-worker-egress.md)** (owner decision): delivery may use an explicit, configured proxy (never one from the environment; `trust_env=False` stays), reached with HTTP `CONNECT` to the validated IP literal, with no direct fallback.

**Why.** With httpx's default `trust_env=True`, `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` in the worker's environment would send each delivery to the proxy instead of the address `_validate_destination` checked and pinned, and the proxy could reach addresses the destination policy refuses. `.netrc` credentials and `SSL_CERT_FILE`/`SSL_CERT_DIR` would also be read from the environment.

**Consequences.**
- **Breaking for deployments that route webhook deliveries through an outbound proxy:** deliveries now connect directly to the validated destination, so the network must allow that. Nothing else in the delivery contract changes: `http` and any port on a globally routable address stay accepted, the 10-second per-phase timeout and the unread body are unchanged.
- A custom trust store for receivers' certificates no longer comes from `SSL_CERT_FILE` or `SSL_CERT_DIR`; httpx's default trust store (certifi) is used.
- The GitHub, OIDC and ZITADEL bootstrap clients are not covered by this amendment and keep httpx's default (`docs/P-ROADMAP.md` ledger).

**Tests.** `tests/core/webhooks/test_webhooks_delivery_integration.py` (`test_delivery_never_enables_follow_redirects` also asserts `trust_env=False`); the transport-level tests of the same file build the client with the same arguments.

## Amendment (2026-10-19): one deadline, resolution off the event loop, address fallback, optional port allowlist (ADR-0054 Q2)

**Decision (owner, 2026-10-19).** The four webhook egress gaps found by the Phase AI-A audit are closed; the first three use the same rules as AI egress (ADR-0054 section 8a). It answers the part of ADR-0054 Q2 that asked whether the DNS and address-fallback improvements also apply to webhooks: they do.

- **One total deadline per delivery attempt.** Resolution, every address tried, the request and the response status share one deadline of `_DELIVERY_TIMEOUT_SECONDS` (10 s, unchanged). Before, 10 s applied to each phase separately. Each client's timeouts are capped by the time remaining. An expired deadline is `WebhookDeliveryError("deadline_expired")`, transient, and retried by the outbox like any other.
- **Resolution off the event loop.** `getaddrinfo` runs in a worker thread (`asyncio.to_thread`), so one slow resolver no longer stalls the other jobs on the worker's loop. The thread itself cannot be interrupted; the deadline returns control on time and the thread finishes in the background, as for AI egress.
- **Address fallback.** `_validate_destination_addresses` returns every resolved address, sorted, and still refuses the destination if any one is not public. The delivery connects to the first; only when that connection fails before anything was sent (`httpx.ConnectError`, `httpx.ConnectTimeout`) does it try the next, at most two in all. Any other failure ends the attempt, so a request is never sent twice within one attempt.

- **An optional port allowlist** (owner decision of the same day, option c). `WEBHOOK_ALLOWED_PORTS`, a comma-separated list of ports, limits the ports a webhook URL may use; a URL that names no port counts as 443 for `https` and 80 for `http`. Unset, any port is allowed, so no deployment and no existing subscription changes by default. It is checked when a subscription is created (`InvalidWebhookUrlError`) and before every delivery, ahead of any resolution (`WebhookDestinationRejectedError`, permanent: dead-lettered, not retried), so narrowing the list also stops deliveries to subscriptions created before. An empty or invalid value is `WebhookConfigurationError`, never "allow everything".

**Unchanged.** `http` stays accepted, and with `WEBHOOK_ALLOWED_PORTS` unset any port on a globally routable address stays accepted. The address check, pinning, `trust_env=False`, no redirects, the unread response body, the signature and the retry classification are as before. `_validate_destination` still returns the first validated address.

**Tests.** `tests/core/webhooks/test_webhook_delivery_deadline_unit.py`: fallback on a refused connection and on a connect timeout, none after a read timeout, protocol error or write error, at most two addresses, one non-public answer still refuses, `http` with a custom port still delivered, client timeouts capped by the deadline, slow resolution and a hanging receiver both cut off at the total, the event loop keeps running during resolution, and the patched seam takes effect; `tests/core/webhooks/test_webhook_allowed_ports_unit.py`: the variable's parsing and refusals, subscription URLs with explicit and default ports, and a delivery to a port no longer allowed refused before resolution. Negative controls (each restored): removing the fallback, the total deadline or the worker thread, falling back after any error, and trying every address each fail tests. The integration tests that bypass the destination policy for a local receiver now patch `_validate_destination_addresses`.

## Related

`core/webhooks/service.py`; `core/webhooks/errors.py`; `core/outbox/errors.py`; `api/outbox_dispatcher.py`; `core/rbac/authorization.py`; `tests/core/webhooks/test_webhook_ssrf_policy_unit.py`; `tests/core/webhooks/test_webhook_delivery_durability_integration.py`; `tests/core/webhooks/test_webhook_subscription_authority_integration.py`.
