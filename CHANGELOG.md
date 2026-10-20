# Changelog

SaaS OS releases (ADR-0015, "Release labels" and "One pull request per release"). Each entry names the exact commit; the newest names its release pull request until the next release writes in the SHA. Consumers pin that SHA, never the tag (`docs/CONSUMER-GUIDE.md` section 3). Upgrade steps are in `docs/CONSUMER-GUIDE.md` section 14.

## v0.1.2 (2026-10-20)

The merge commit of pull request #71, the release pull request (ADR-0015, "One pull request per release"). The next release writes its full SHA here. Until then, check that the tag `v0.1.2` resolves to that merge commit before pinning it.

It contains everything since v0.1.1 (`c7d8987`): pull requests #66 to #70 and this release. A fix release: no migration, no changed public signature, one new optional setting.

- **Webhook delivery: one deadline per attempt** (#70, ADR-0035 amendment of 2026-10-19). Resolution, every address tried, the request and the response status share one 10-second deadline. Before, 10 seconds applied to each phase. An expired deadline is `WebhookDeliveryError("deadline_expired")`, retried by the outbox like any other transient failure.
- **Webhook delivery: DNS off the event loop** (#70). Resolution runs in a worker thread, so a slow resolver no longer stalls the other jobs on the worker.
- **Webhook delivery: address fallback** (#70). When connecting to the first validated address fails before anything was sent, the second is tried; at most two per attempt. Every resolved address must still be public.
- **Webhook delivery: optional port allowlist** (#70). `WEBHOOK_ALLOWED_PORTS`, a comma-separated list. Unset, any port stays allowed, so nothing changes by default. Set, it is checked when a subscription is created and before every delivery.
- **Tests and documentation** (#66 to #69): payment-page audit failure tests, the ADR-0015 amendment "One pull request per release", the example pins moved to v0.1.1, and status lines in `docs/AI-CONTROL-PLANE.md` and `docs/RELEASE-READINESS.md`.

The example pins stay at v0.1.1 (`c7d8987`), the previous release, as ADR-0015 requires. Migration head: `f6a2c8e4b1d9`, unchanged. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From v0.1.1 to v0.1.2".

## v0.1.1 (2026-10-19)

Commit `c7d898782877b945a54d49c87d280c6ad515586f`, `main` after pull request #65 (the release pull request; its SHA is recorded by the pin-move pull request, ADR-0015 "Release labels", order). Check that the tag `v0.1.1` resolves to that SHA before moving a pin.

It contains everything since v0.1.0 (`dab6357`): pull requests #62 to #64 and this release. A fix release: no migration, no changed public signature, no new deployment step.

- **AI inference: an exhausted OpenAI-compatible account is no longer a rate limit** (#64). A 429 whose `error.code` is `insufficient_quota` is the new error category `provider_quota_exhausted`: not retried on the same destination, may fall back, and the caller gets `InferenceProviderUnavailableError("provider_quota_exhausted")`. Only `error.code` is compared. Alerts or reports that count `rate_limited` attempts no longer include these.
- **AI inference: trust entries are re-checked before every attempt** (#64). A trust entry revoked, expired or added while a request runs refuses its next attempt with `destination_changed`.
- **Tests** (#63): service-level tests for the deadline between retries, `Retry-After` beyond the deadline and destination changes.
- **Release labels** (#62): this file, the ADR-0015 amendment and `docs/CONSUMER-GUIDE.md` sections 14 and 15; the example pins moved to v0.1.0.

Migration head: `f6a2c8e4b1d9`, unchanged. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From v0.1.0 to v0.1.1".

## v0.1.0 (2026-10-19)

Commit `dab6357e4eefc19ab7308cf553e38f658ddd08d0`, `main` after pull request #61. The first tagged release. Main CI run 39251055117 passed on this commit.

It contains everything up to and including pull request #61. Since `4197d2f` (pull request #43, the previous pin of the example consumers):

- **Audit digests** (#52, ADR-0053): the worker writes one `audit_digest` line per settled window of the audit tables to its log, for an append-only external store; `python -m saas_os.ops.audit_digest verify`. Migration `d3e9a1c47b20`.
- **Payment-page audit** (#51, ADR-0052 amendment): `billing.payment_page_issued`, `billing.payment_page_issued_for_account` and `billing.payment_page_refused`.
- **Governed AI inference v1** (#53 to #58, ADR-0054 to ADR-0056; #55 and #57 moved the reference consumer's pin): `saas_os.inference.run_inference` with OpenAI-compatible, Anthropic and Gemini adapters, Redis admission, a soft token quota, cost estimates, the attempt ledger, the `saas-os-operator ai-*` commands and the platform-configuration database role. Migrations `a7f3c91e2d48`, `e4b8c2d6f1a3`, `b8e2d4f6a1c3`, `c5d7e9f1a2b4` and `f6a2c8e4b1d9`. The Redis readiness probe is bounded at 2 s (#58). Qualified against OpenAI `gpt-4o-mini` only; deployment qualification (Gate C) is the product's (`docs/RELEASE-READINESS.md`).
- **Documentation and tests** (#44 to #50, #59 to #61): live multi-factor and Stripe plan-change evidence, ADR status updates, the D1 to D14 local rehearsal records.

Migration head: `f6a2c8e4b1d9`. All six migrations are additive. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From `4197d2f` to v0.1.0".
