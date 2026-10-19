# Changelog

SaaS OS releases (ADR-0015, "Release labels"). Each entry names the exact commit; consumers pin that SHA, never the tag (`docs/CONSUMER-GUIDE.md` section 3). Upgrade steps are in `docs/CONSUMER-GUIDE.md` section 14.

## v0.1.0 (2026-10-19)

Commit `dab6357e4eefc19ab7308cf553e38f658ddd08d0`, `main` after pull request #61. The first tagged release. Main CI run 39251055117 passed on this commit.

It contains everything up to and including pull request #61. Since `4197d2f` (pull request #43, the previous pin of the example consumers):

- **Audit digests** (#52, ADR-0053): the worker writes one `audit_digest` line per settled window of the audit tables to its log, for an append-only external store; `python -m saas_os.ops.audit_digest verify`. Migration `d3e9a1c47b20`.
- **Payment-page audit** (#51, ADR-0052 amendment): `billing.payment_page_issued`, `billing.payment_page_issued_for_account` and `billing.payment_page_refused`.
- **Governed AI inference v1** (#53 to #58, ADR-0054 to ADR-0056; #55 and #57 moved the reference consumer's pin): `saas_os.inference.run_inference` with OpenAI-compatible, Anthropic and Gemini adapters, Redis admission, a soft token quota, cost estimates, the attempt ledger, the `saas-os-operator ai-*` commands and the platform-configuration database role. Migrations `a7f3c91e2d48`, `e4b8c2d6f1a3`, `b8e2d4f6a1c3`, `c5d7e9f1a2b4` and `f6a2c8e4b1d9`. The Redis readiness probe is bounded at 2 s (#58). Qualified against OpenAI `gpt-4o-mini` only; deployment qualification (Gate C) is the product's (`docs/RELEASE-READINESS.md`).
- **Documentation and tests** (#44 to #50, #59 to #61): live multi-factor and Stripe plan-change evidence, ADR status updates, the D1 to D14 local rehearsal records.

Migration head: `f6a2c8e4b1d9`. All six migrations are additive. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From `4197d2f` to v0.1.0".
