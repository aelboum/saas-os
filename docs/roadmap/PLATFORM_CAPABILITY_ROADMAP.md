# Platform capability roadmap

**Status: proposal, 2026-11-01. Nothing here is authorized.** Each stage needs the owner's approval before work starts (`CLAUDE.md` sections 3 and 9); items marked *decision-gated* also need the decision named. Derived from `docs/architecture/UNIVERSAL_PLATFORM_ASSESSMENT.md` (audited at `main` `6fd2dfd`, v0.6.0 `d980e73`); capability ids (`C01`...) and finding ids (`F1`...) refer to `docs/architecture/CAPABILITY_MATRIX.md` and the assessment's section 6. Earlier phases and the deferred-issue ledger stay in `docs/P-ROADMAP.md` and `docs/IMPLEMENTATION-ROADMAP.md`; this document adds the next capability plan and does not replace them.

**Principles.** Security and correctness first; every capability opt-in; no product adopts a module it does not use; no stage forces a consumer to move its pin (consumers move by an owner-approved pin change, ADR-0015); a stage ships as one release so a consumer can adopt it as a unit.

**Release classes** follow current practice (`CHANGELOG.md`): before 1.0, a patch (`0.6.x`) changes no public signature; a minor (`0.x.0`) may add surface and, with an upgrade note in `docs/CONSUMER-GUIDE.md` section 14, change it. The versioning and support-window policy was undecided at the audit (C27); it is now ADR 0062 in pull request #188, accepted by the owner on 2026-11-02, with the decisions of 2026-11-01 recorded there; classes below may change with it.

## Overview

| Stage | Theme | Items | Release | Gate |
|---|---|---|---|---|
| R0 | Decisions and documentation | Threat-model note (F6), owner decisions, versioning policy (C27) | none (documents) | Owner decisions |
| R1 | Security and correctness fixes | F1+F4, F2, F5 (C17), C23, F7 step 1, C24 | Patch (0.6.x) | Authorization |
| R2 | Authority and audit seams | C02 (ADR-0061), C01 (ADR-0060), C03 deprecation | Minor (0.7.0) | ADR-0060, ADR-0061 accepted (done: owner, 2026-11-02) |
| R3 | Reliability and generic platform | C16, C18, C04, C05, C20, F7 step 2 | Minor (0.8.0) | Authorization; egress ADR amendment |
| R4 | Optional integration capabilities | C08+C09, C06, C07 | Minor (0.9.0) | ADR-0058 amendment; inbound-verification ADR |
| R5 | Decision-gated | C21, C10, C14, C25, C03 refusal | Minor each | Named decision per item |

Dependency order: R0 before everything; R1 independent of R2-R4; C02 before C01; C01 before C03; C04 before C05; C05 before any product-side C14; C06 before C07.

## R0: decisions and documentation (no code)

**R0.1 RLS threat-model note (F6).**
1. Justification: products and reviewers must know what RLS protects against; the guide implies more than holds.
2. Scope: a section in `docs/MULTI-TENANCY.md` and a rule in `docs/CONSUMER-GUIDE.md` section 7: RLS protects against a missing or wrong predicate, not against in-process code that executes SQL; `.op()` with raw strings, raw connections and `set_config` are forbidden in products; reviewers check for them.
3. Acceptance: both documents state it; `tests/architecture/test_doc_references.py` passes.
4. API impact: none. 5. Database impact: none. 6. Security impact: documents an existing property.
7. Tests: the documentation reference test.
8. Documentation: the two files above.
9. Dependencies: none. 10. Release: none. 11. Consumer impact: review guidance only.

**R0.2 Owner decisions:** assessment section 10, items 1-6.

**R0.3 Versioning and support-window policy (C27):** a decision on what a patch and a minor may change and how long security fixes are back-ported. *Update 2026-11-02:* ADR 0062 (pull request #188; accepted by the owner on 2026-11-02), a separate ADR that amends ADR-0015 once merged, with the owner's decisions of 2026-11-01 (maintenance branches; the 90-day window starts at the GitHub Release's `published_at`; a support statement in each changelog entry, validated by `scripts/release.py` in open pull request #193).

## R1: security and correctness fixes (patch)

**R1.1 One TLS and stack policy for webhook delivery (F1, F4).**
1. Justification: the proxied delivery path reads `SSL_CERT_FILE`, contrary to ADR-0035's amendment; it also skips the HTTP-stack check the strict client makes.
2. Scope: build the proxied context from certifi with `trust_env=False`; call `require_supported_http_stack()` at delivery start. No other change.
3. Acceptance: with `SSL_CERT_FILE` pointing to an unrelated CA, a proxied delivery to a test endpoint trusted through certifi still verifies, and one trusted only by the unrelated CA is refused; reverting the context makes the test fail (negative control).
4. API: none. 5. Database: none. 6. Security: closes F1 and F4.
7. Tests: unit test with a local TLS server and a fake proxy (existing `tests/core/webhooks/` fixtures).
8. Documentation: ledger rows closed; ADR-0035 amendment note.
9. Dependencies: none. 10. Release: patch. 11. Consumer impact: none, unless a deployment relied on `SSL_CERT_FILE` for webhook trust (record in the upgrade note).

**R1.2 Signature verifier refuses non-ASCII input (F2).** Scope: compare bytes; refuse a non-ASCII header with `WebhookSignatureInvalidError`. Acceptance: a test with a non-ASCII header. No API or database change; patch.

**R1.3 Timed-out jobs are dead-lettered (F5, C17).**
1. Justification: silent loss of non-outbox work.
2. Scope: the job wrapper enforces its own deadline below arq's `job_timeout` and treats expiry as a failure (retry, then dead-letter), or handles cancellation explicitly; scheduled jobs dead-letter as today.
3. Acceptance: a real worker running a job that sleeps past the timeout records a dead-letter entry; without the change the test fails.
4. API: none (configuration may gain one bounded setting). 5. Database: none. 6. Security: none; reliability.
7. Tests: in the style of `tests/api/test_worker_runtime_integration.py`, real Redis.
8. Documentation: `docs/CONSUMER-GUIDE.md` section 10.
9. Dependencies: none. 10. Release: patch. 11. Consumer impact: none.

**R1.4 One error-description policy for persisted and logged error text (C23).**
1. Justification: `last_error`, Redis dead letters and arq's failure line carry exception messages; earlier audits found host names and caller input in them.
2. Scope: one function that renders an exception as its type, plus its message only for allow-listed exception types whose messages SaaS OS constructs; used by the outbox, the job wrapper and the dead-letter list; arq's own failure line filtered like `JobArgumentsFilter`.
3. Acceptance: per sink, a database error carrying a value in `DETAIL` and a provider error reach it as the type and allow-listed text only.
4. API: none. 5. Database: none (existing rows untouched; a redaction command in the pattern of `redact-webhook-errors` if needed). 6. Security: closes the persisted-error-text part of the ledger rows after 902; traceback locals (row 901) remain a product concern.
7. Tests: unit and live-worker. 8. Documentation: `docs/CONSUMER-GUIDE.md` section 10.
9. Dependencies: none. 10. Release: patch. 11. Consumer impact: operators lose some diagnostic text (documented).

**R1.5 Legacy plaintext webhook secrets, step 1 (F7, C26).** Scope: an operator command that re-encrypts plaintext secrets in place, dry run first, audited; a warning log when one is read. Step 2 (refusal) is in R3. No API change; patch.

**R1.6 Optional-capability boundary tests (C24).** Scope: tests that `import saas_os` and each `saas_os.core` package load only standard-library, mandatory-dependency and package modules, and that the API and the worker start with every optional capability unconfigured. Test-only; patch.

## R2: authority and audit seams (minor)

**R2.1 System actor attribution (C02, ADR-0061).**
1. Justification: non-member actions are unattributed or borrow authority; every product has them.
2. Scope: `SystemActor`, `record_system_action_in_transaction()`, the actor on `SystemCaller` (attribution only), a derived executing actor in job contexts, a propagated initiating actor (`initiated_by`, or `"unavailable"`) and separate correlation ids (request, arq job, outbox event), per ADR-0061 as amended 2026-11-02; a deprecation warning for successful `system` rows written through `record()`.
3. Acceptance: a system action is audited in the caller's transaction and rolls back with it; every public Core mutation refuses a `SystemActor` in place of a `Caller`; validation refuses unknown kinds and bad names; the executing actor is never recorded as the initiator and a job id never as either actor; audit digest verification unchanged.
4. API: additive. 5. Database: none (Option B). 6. Security: attribution without new authority; negative control: accepting a `SystemActor` as a caller makes the refusal test fail.
7. Tests: unit and integration (rollback, isolation, digest). 8. Documentation: consumer guide sections 8 and 10; ADR-0061 status.
9. Dependencies: ADR-0061 accepted. 10. Release: minor. 11. Consumer impact: optional adoption; deprecation warning only.

**R2.2 Permission grant migrations (C01, ADR-0060).**
1. Justification: issue #88; every product's second release.
2. Scope: per ADR-0060's recommendation: declaration type, `PERMISSION_UPGRADE` purpose, apply function, tenant-owned ledger, operator command.
3. Acceptance (issue #88 and ADR-0060): a new permission reaches a named role in two tenants, audited, and a re-run changes nothing; a tenant's later revocation survives a re-run; an unregistered permission and an authority-resource permission are refused before any tenant changes, and a purging tenant is skipped, with no partial writes in any tenant; an unknown role is never created and is recorded in that tenant's ledger as `role_missing`, permanently, so that migration is never applied to that tenant again (corrected 2026-11-02 to pull request #198); a user caller still cannot grant a permission it does not hold; concurrent runs on one tenant apply once; the public-surface snapshot includes the new entry points.
4. API: additive (public snapshot change). 5. Database: one migration: a tenant-owned table under the canonical RLS policy, in the isolation registry and the retention classification; downgrade drops it (only the ledger is lost; grants stay). *Update 2026-11-02:* as implemented in pull request #198, the downgrade refuses while the ledger holds any row, so retained evidence is never dropped by a schema rollback; a second migration adds the legal-hold table (ADR-0060 "Decision" item 7).
6. Security: replaces the ambient-authority workaround; RLS sweep; negative controls (remove the purpose check, remove the ledger check) must fail.
7. Tests: integration on PostgreSQL 16, race tests in the style of `tests/core/rbac/test_authorization_transaction_race_integration.py`, migration upgrade and downgrade tests.
8. Documentation: consumer guide section 8 (the supported path), upgrade note, ADR-0060 status, issue #88.
9. Dependencies: R2.1. 10. Release: minor. 11. Consumer impact: products using `PROVISIONING` on existing tenants should move to it.

**R2.3 Deprecate `PROVISIONING` on tenants that are not `PENDING` (C03, first step).** A deprecation warning and an audit metadata flag when `PROVISIONING` acts on an `ACTIVE` or `SUSPENDED` tenant; the refusal is in R5. Minor; no consumer break.

## R3: reliability and generic platform (minor)

**R3.1 Retry policy for plain jobs and webhooks (C16).** Scope: jitter and a cap for job retries (shared with the outbox's `retry_delay`), a typed retry-later error for jobs, `Retry-After` read on webhook `429` and `503` and passed as the outbox hint. Acceptance: deterministic tests with a seeded random source; a webhook `429` with `Retry-After: 120` is not retried sooner than 120 seconds. No database change. Minor (job configuration gains bounded settings). Consumer impact: none required.

**R3.2 Public schedules (C18).** Scope: export from `saas_os.infra.jobs` a scheduling function that accepts arq's calendar fields for system jobs, keeping one attempt per tick and uniqueness across workers; keep `system_cron` for one release. Acceptance: a daily schedule registered through `saas_os.api.worker.main(extra_cron_jobs=...)` runs once across two workers; public snapshot updated. Minor. Consumer impact: optional; host timers keep working.

**R3.3 One egress stack (C04).** Scope: webhook delivery uses `StrictEgressClient`, extended with the webhook policy (`http` opt-in, port configuration, no body read), instead of its own client; behaviour unchanged. Acceptance: every webhook SSRF, port, proxy and redirect test passes on the shared client; `scripts/check-egress-e2e.sh` passes. Needs an ADR-0059 amendment. Minor (internal); no API change.

**R3.4 Egress read methods (C05).** Scope: `get`, `head`, `delete` on `StrictEgressClient`; no request body for `GET` and `HEAD`; bounded response body; redirects still refused; a retry rule per method. Acceptance: existing destination, pinning, TLS, size and proxy tests parametrized over methods; a redirect is refused for every method; enabling redirect following makes that test fail. API additive; no database change. Minor. Consumer impact: enables provider reads (inbound message fetch, domain status).

**R3.5 Named SQL expression constructors (C20).** Scope: a small, reviewed set (cast to an exported type, `coalesce`, `lower`, `to_tsvector`, `websearch_to_tsquery`, `ts_rank`, the `@@` match), each a named function in the `now()`/`sum_()` pattern. Acceptance: `tests/infra/test_db_public_surface_unit.py` updated; the J-INFRA-05 negative control shows none can express `set_config`; a full-text query on a product table under RLS returns one tenant's rows. Minor. Consumer impact: optional.

**R3.6 Refuse legacy plaintext webhook secrets (F7, step 2),** one release after R1.5. Minor.

## R4: optional integration capabilities (minor)

**R4.1 Email headers and structured addresses (C08, C09).**
1. Justification: bulk-sender compliance and reply threading for any product that sends mail; fixes F3.
2. Scope: allow-listed headers (`List-Unsubscribe`, `List-Unsubscribe-Post`, `In-Reply-To`, `References`) with per-header validators; a structured address with an optional display name, encoded with the standard library; a tightened address grammar; both providers send them.
3. Acceptance: header-injection inputs (CR, LF, NUL, encoded-word abuse, overlong values) refused; the RFC 8058 pair accepted only with an `https` URI; non-ASCII display names encoded correctly; `x,y@b.c` refused.
4. API: additive fields on `EmailMessage`. 5. Database: none. 6. Security: a closed allow-list, never free-form headers.
7. Tests: unit for both providers through mock transports. 8. Documentation: ADR-0058 amendment; consumer guide "Email through Resend".
9. Dependencies: none. 10. Release: minor. 11. Consumer impact: optional.

**R4.2 Provider-neutral inbound webhook verification (C06).**
1. Justification: every product receives webhooks; today each writes its own verifier.
2. Scope: a verifier with scheme adapters (Standard Webhooks first; SaaS OS's own scheme; Stripe stays on ADR-0048's path), a replay ledger keyed by source and event id, a scheduled retention job, a body cap and a per-source rate limit as a reusable dependency for product routes; no product route shipped.
3. Acceptance: tampered body, wrong secret, stale and future timestamps, replayed event id, non-ASCII headers and oversized bodies refused; concurrent duplicates recorded once; the scheme's published test vectors pass.
4. API: additive. 5. Database: one migration (ledger). 6. Security: constant-time comparison on bytes; secrets through the secrets provider; only the source and outcome logged.
7. Tests: unit and integration. 8. Documentation: a new ADR; a consumer guide section on receiving webhooks.
9. Dependencies: R2.1 (attribution of processing). 10. Release: minor. 11. Consumer impact: optional.

**R4.3 Outbound webhook signing v2 (C07).** Event-id header, versioned signature prefix, two active secrets during rotation, sharing R4.2's scheme code. One migration (second secret); minor; receivers keep verifying v1 through a deprecation window.

## R5: decision-gated

| Item | Gate | Note |
|---|---|---|
| C21 Embeddings in governed inference | Owner authorizes AI-G for embeddings; ADR-0054 amendment | New adapter method; classification and destination checks identical to chat; attempt ledger kind; vector storage stays product (C22) |
| C10 Attachments | A second consumer or an owner decision | Size, type and scanning policy; egress body limits |
| C14 Email domain adapter capability | A second product or provider | Optional protocol in the ADR-0052 pattern, on top of R3.4 |
| C25 Metrics exporter and alerting | ADR-0009 backend decision | Interface in Core, exporter optional |
| C03 Refuse `PROVISIONING` on tenants that are not `PENDING` | ADR-0060 Q4 | Breaking for consumers still using it; one release after R2.3 |

## Product-owned (not on this roadmap)

Campaigns, audiences and suppression lists; unsubscribe preference pages; conversation threading and mailboxes; inbound email parsing and storage; customer sending-domain workflows; CRM, ERP and project-management domains; search ranking and indexes in product tables; vector stores and retrieval; product automation rules; frontends (ADR-0042).

## Consumer migration summary

| Stage | What a consumer must do | What it may do |
|---|---|---|
| R1 | Nothing (read R1.1's note if it relied on `SSL_CERT_FILE` for webhook trust) | Run the R1.5 re-encryption command |
| R2 | Nothing | Adopt system actors; move permission upgrades to ADR-0060; stop using `PROVISIONING` on existing tenants before the R5 refusal |
| R3 | Nothing | Use read methods, public schedules and named SQL constructors |
| R4 | Nothing | Use email headers, display names and the inbound verifier |
| R5 (C03) | Stop using `PROVISIONING` outside tenant creation | — |
