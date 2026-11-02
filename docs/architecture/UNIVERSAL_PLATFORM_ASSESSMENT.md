# Universal platform assessment

**Status: assessment, 2026-11-01. Decides nothing; changes no code.** An independent review of whether SaaS OS is becoming a reusable, secure and extensible platform for different categories of SaaS products, prompted by the thirteen gaps its first consumer reported. The decisions it asks for are in section 10; nothing in the roadmap that follows from it is authorized until the owner decides.

Companion documents: `docs/architecture/PLATFORM_BOUNDARIES.md` (the inclusion rule and the three layers), `docs/architecture/CAPABILITY_MATRIX.md` (every capability, rated), `docs/roadmap/PLATFORM_CAPABILITY_ROADMAP.md` (sequencing), ADR-0060 and ADR-0061 (proposed with this assessment; accepted by the owner on 2026-11-02).

## 0. Scope and method

- **Audited tree:** `main` `6fd2dfdacc0ccff738965b14c6836d309dbf0973`.
- **Released baseline:** v0.6.0, `d980e73b0313ed63f2a59fd4a991a89f75791c0e` (signed tag, published 2026-10-31). Between the two: one feature (webhook destinations refuse `http://` unless `WEBHOOK_ALLOW_HTTP=true`, pull request #133) and documentation. No email, jobs, RBAC, audit, database or inference module changed, so every finding below applies to v0.6.0 as well, except where marked.
- **Reference consumer:** LeadStack (`aelboum/crm-app`), pinned to `d980e73`; its gap list is `docs/project/saas-os-gaps.md` in that repository (read only; neither the product nor its pin was changed).
- **Method:** source first. Each gap and finding was checked in the code, not only in documentation or earlier reports; claims from parallel read-only reviews were spot-checked by hand (the anti-amplification exemption, the `PROVISIONING` reach, the outbox retry formula, the webhook TLS context, `hmac.compare_digest` behaviour, the email address validator, arq's timeout handling, the `.op()` construction). Two checks were executed, without a database or network: the address validator against crafted inputs, and SQL compilation of a column operator. Nothing was run against PostgreSQL, Redis or a provider. **Inference** is marked where a conclusion was not observed.

## 1. Baseline (Phase A)

### 1.1 Package

- **Mandatory dependencies** (`pyproject.toml`): FastAPI, SQLAlchemy, Alembic, psycopg, redis, arq, OpenTelemetry API and SDK, PyJWT, cryptography, httpx (`<0.29`), httpcore (`<1.1`), certifi, uvicorn. No provider SDK is mandatory.
- **Extras** (ADR-0041): `stripe`, `s3-backup`, `all`; `dev` and `security` for this repository. Resend, ZITADEL and the three AI providers need no SDK: they use the shared HTTP stack.
- **Console scripts:** `saas-os-migrate`, `saas-os-local-identity`, `saas-os-edge-config`, `saas-os-update`, `saas-os-operator`.
- **Import root:** `saas_os` only (ADR-0038). Top-level packages: `api`, `contracts`, `control_plane`, `core`, `inference`, `infra`, `ops`.
- **Public surface:** every package's `__all__`, pinned with signatures by `tests/architecture/test_public_api_snapshot.py`. There is no per-symbol stability tier: anything exported is public.
- **Module boundaries:** 21 import-linter contracts (`pyproject.toml`, `[tool.importlinter]`), including: Core and Infra never import products or the control plane; Infra never imports Core; only `saas_os.infra.db` imports SQLAlchemy and psycopg; no AI SDK anywhere; `saas_os.ops` imported by nothing; products reach inference only through `saas_os.inference`.

### 1.2 Architecture as built

| Area | As built | ADRs |
|---|---|---|
| Identity | OIDC relying party; self-hosted ZITADEL invisible to products; sessions, invitations, MFA for operators | 0005, 0023, 0025, 0046, 0049 |
| Authorization | `can()`; three caller types (`UserCaller`, `ServiceAccountCaller`, `SystemCaller` with four purposes); RBAC with delegation, deny, support access; anti-amplification; last-administrator invariant | 0030, 0031, 0043 |
| Platform authority | Separate operator principal, closed permission vocabulary, platform audit, operator CLI | 0045, 0049, 0050 |
| Tenancy | Shared schema, forced RLS on every tenant-owned table (swept by test), tenant session scopes, statically checked untenanted call sites | 0002, 0022 |
| Database | Two independent Alembic histories (SaaS OS first, then the product); application role without `BYPASSRLS`; no `SECURITY DEFINER` | 0016, 0056 |
| Jobs | Redis and arq; typed tenant and system jobs; Redis dead-letter list; interval schedules | 0007, 0030, 0039 |
| Outbox | Transactional outbox in PostgreSQL, `SKIP LOCKED` claims with leases, backoff with jitter, retry hints, durable dead letters, operator replay, consumer idempotency | 0032, 0033, 0036 |
| Audit | Tenant and platform audit tables, same-transaction and fail-closed for authority changes, append-only grants, hourly SHA-256 digests to an external log | 0031, 0051, 0053 |
| Egress | `StrictEgressClient` (HTTPS, port allow-list, one resolution, every address public, connection pinned to the validated IP, no redirects, bounded body); webhook delivery has its own, similar path; optional policy-enforcing proxy | 0035, 0059 |
| Email | `EmailProvider` protocol; SMTP, Mailpit (development), Resend over the strict client; one provider per deployment | 0057, 0058 |
| Webhooks | Outbound, HMAC-signed, AEAD-encrypted secrets, SSRF policy, outbox-driven | 0035 |
| Billing | Provider-neutral parties and subscriptions, Stripe adapter as an extra, inbound Stripe events | 0008, 0029, 0048, 0052 |
| AI | Governed, non-streaming inference with classification, destination authorization, quota, evidence | 0054, 0055 |
| Observability | Structured JSON logs with key-based redaction, OpenTelemetry (console exporter only), health and readiness | 0009, 0020 |

### 1.3 Readiness as recorded

`docs/PRODUCTION-READINESS.md` (reviewed 2026-10-30) rates SaaS OS **not production-ready**: one gate verified (tenant isolation), fourteen partially verified, live provider and deployment evidence blocked. This assessment does not change that rating and does not treat a green CI run as evidence of production readiness.

## 2. Verdict

SaaS OS is on the right track to be a universal platform, and its first consumer has not pulled product logic into it: no CRM, campaign or contact concept exists in `saas_os/`, and the email module states its non-goals in code. The strongest parts are the parts every product needs most: tenant isolation (forced RLS, swept), typed authority, same-transaction audit, the outbox, and egress control. Provider independence is good: no SDK is mandatory, and each provider sits behind a protocol.

The weaknesses are not missing features. They are:

1. **Seams that each product would otherwise reinvent are missing**: a sanctioned permission upgrade, attribution of non-member actions, a safe read through egress, a provider-neutral inbound webhook verifier, public calendar schedules. Each missing seam pushes products toward a workaround that weakens a platform invariant (the first consumer's use of `PROVISIONING` on existing tenants is the clearest case).
2. **Ambient system authority.** `PROVISIONING` is in-process tenant-administrator authority over every open tenant. It is a known, deferred item (ADR-0045); a consumer now depends on it beyond its purpose. It should be narrowed after ADR-0060 provides the legitimate path.
3. **Duplicated security-critical code.** Webhook delivery and the strict egress client implement the same SSRF and TLS policy twice, and the copies have drifted (findings F1, F4).
4. **The RLS threat model is undocumented.** RLS protects against a missing predicate; it does not protect against in-process code that can execute SQL, and the import fence that removed `func` and `text` can be stepped around (F6). That is acceptable for a library whose products are trusted code, but it must be stated, not implied.
5. **Release and support policy is undecided** (ledger rows 870-872, 947), so a consumer cannot know which upgrades carry breaking changes or how long a security fix is back-ported. *Update 2026-11-02:* the policy is ADR 0062 in pull request #188 (proposed, then accepted by the owner on 2026-11-02), with the owner's decisions of 2026-11-01 recorded there (maintenance branches; the previous minor's 90-day window starts at the GitHub Release's `published_at`; a support statement in every changelog entry, checked by `scripts/release.py` in open pull request #193).

## 3. The thirteen consumer gaps (Phase B)

Each entry: verified state, partial implementations, layer, demand beyond this consumer, security and operations, dependencies, whether the product is the better place, recommendation. Rows refer to `docs/architecture/CAPABILITY_MATRIX.md`.

### Gap 1: custom email headers (C08)

- **Verified absent.** `EmailMessage` (`saas_os/core/email/provider.py`) has sender, recipients, subject, bodies, reply-to, metadata and message id; no header field. Resend sends only `Message-ID`; SMTP sets From, To, Subject, Message-ID, Reply-To. `metadata` reaches neither provider. Unsubscribe management is a stated non-goal of the module.
- **Partial:** header-injection validation exists for addresses, subject and message id (CR, LF, NUL refused).
- **Layer:** Optional (email). Carrying the RFC 8058 pair is transport; deciding unsubscribe semantics is product.
- **Demand:** any product that sends mail a recipient can opt out of (digests, notifications, marketing) and any product that sends replies. Gmail and Yahoo require one-click unsubscribe for bulk senders.
- **Security:** free-form headers would reopen header injection and let products override `From` or `Message-ID`. A closed allow-list with a validator per header does not.
- **Recommendation: implement** a closed allow-list (`List-Unsubscribe` as a list of `<https:...>`/`<mailto:...>` URIs, `List-Unsubscribe-Post` with the single RFC 8058 value, `In-Reply-To` and `References` as message-id lists), refuse anything else, amend ADR-0058 section 2. Minor release.

### Gap 2: egress `GET` and `DELETE` (C05)

- **Verified absent.** `StrictEgressClient` has only `post()`; the method is hard-coded. No ADR limits the application to `POST` (ADR-0059's "`CONNECT` only" is the proxy's method).
- **Layer:** Core. Reading from a provider is generic; doing it safely is exactly what egress control is for.
- **Demand:** any provider integration that reads state (domain status, inbound messages, files, exchange rates for an ERP, calendar data for project management).
- **Security:** the strict client already enforces the destination policy, pinning, TLS and a response cap. Risks of the extension: redirects (keep refusing them; ADR-0059 decision 6 requires re-validation of every hop if ever allowed), unbounded bodies (reuse the cap), retry semantics (`GET`/`HEAD` may be re-sent after a read timeout; `DELETE` is idempotent but not safe; `POST` needs an idempotency key), credentials in query strings (the origin-only log filter covers them).
- **Dependencies:** best after C04 (one egress stack).
- **Recommendation: implement.** Minor release.

### Gap 3: Resend Domains API (C14)

- **Verified absent;** the only endpoint is `/emails`. `docs/CONSUMER-GUIDE.md` makes domain verification the deployment's job in Resend's dashboard.
- **Layer:** product (possibly an optional adapter capability later).
- **Demand:** customer-owned sending domains are common in CRM, helpdesk and marketing products, rarer in ERP or project management. The domain, DNS-record and verification models differ per provider.
- **Consumer-side better:** yes. Once gap 2 is closed, the product calls the provider's API through `StrictEgressClient`, with the same guarantees, and keeps the workspace-to-domain mapping it owns anyway.
- **Recommendation: defer;** revisit as an optional `EmailDomainProvider` capability (the ADR-0052 `PaymentPageProvider` pattern) when a second product or provider needs it.

### Gap 4: display names (C09)

- **Verified absent.** `validate_email_address()` matches `^[^\s@]+@[^\s@]+\.[^\s@]+$`, so `Team <a@b.c>` is refused.
- **Finding F3 (LOW):** the same pattern accepts a comma in the local part. `x,y@b.c` passes, and the SMTP provider builds `To` by joining recipients with `", "`, which a parser reads as two recipients, `x` and `y@b.c` (executed against the validator and the standard library parser, 2026-11-01). A second domain cannot be smuggled (the pattern allows one `@`); a bare local part goes to the relay's own domain.
- **Recommendation: implement** a structured address (display name plus address) encoded with the standard library's header registry, and tighten the address grammar at the same time. Minor release.

### Gap 5: `In-Reply-To` and `References` (C08)

Verified absent; delivered with gap 1 as two allow-listed headers holding validated message-id lists. Conversation matching stays in the product.

### Gap 6: attachments, tags, scheduling, batch send (C10-C13)

- **Verified absent by decision:** ADR-0058 section 2 excludes attachments, CC/BCC, templates, scheduling, batches and tags.
- **Attachments: defer.** Reusable, but they bring size limits, content-type policy, egress body limits and possibly malware scanning; design when a second product needs them.
- **Tags: defer.** Provider metadata; a validated pass-through later if needed.
- **Scheduling: reject.** The outbox and jobs schedule work already; provider-side scheduling would move delivery state outside SaaS OS's at-least-once accounting.
- **Batch send: reject.** It breaks per-message idempotency (ADR-0036) and per-message failure classification.

### Gap 7: inbound email and webhook verification (C06, C15)

- **Verified:** no inbound email; ADR-0058 says Resend webhooks are not consumed; no Svix code. A generic verifier exists (`verify_webhook_signature()`, `verify_and_record_webhook_delivery()` in `saas_os/core/webhooks/service.py`) but speaks only SaaS OS's own outbound scheme, its replay ledger references outbound subscriptions, its retention job is not scheduled, and no route uses it. Stripe has its own verification and ledger (ADR-0048).
- **Finding F2 (LOW):** `verify_webhook_signature()` passes the received header to `hmac.compare_digest`, which raises `TypeError` for a non-ASCII string; a product route calling it answers with an unhandled error instead of a signature refusal (behaviour checked against the standard library).
- **Layer:** the verifier and replay ledger are optional platform capability; the inbound email pipeline is product.
- **Demand:** every product with a third-party integration receives webhooks (payments, email, telephony, version control, calendars).
- **Recommendation: implement** a provider-neutral verification primitive with scheme adapters (Standard Webhooks, which is Svix's format, first), a replay ledger keyed by source and event id independent of outbound subscriptions, a scheduled retention job, body caps and rate limits; **reject** the inbound email pipeline in SaaS OS. Minor release, one migration.

### Gap 8: retry jitter and provider `Retry-After` (C16, C17)

- **Partly present, contrary to the report.** Since v0.6.0 the outbox adds up to 10 % jitter to capped exponential backoff and honours a consumer's retry hint (`RetryAfterEventError`, capped by `OUTBOX_RETRY_HINT_MAX_SECONDS`), and the Resend adapter reads `Retry-After` into it (`saas_os/core/outbox/dispatch.py`, `saas_os/core/email/resend_provider.py`; `docs/architecture/OUTBOX-RETRY-AND-REPLAY-DECISION-BRIEF.md`).
- **Absent:** plain arq jobs retry `base * 2**(try-1)` with no jitter, cap or hint (`saas_os/infra/jobs/queue.py`); webhook delivery treats `408`, `429` and `5xx` alike and never reads `Retry-After`.
- **Finding F5 (LOW):** a plain job that exceeds arq's `job_timeout` (300 s default) is finished by arq with no retry and no entry in SaaS OS's dead-letter list (arq 0.28 `Worker.run_job`: `TimeoutError` falls to the generic failure branch; SaaS OS's wrapper sees a cancellation, not an exception). Outbox work recovers through its lease; plain jobs are lost. From the code, not tested.
- **The consumer's own queues** (`next_attempt_at` columns) are a sound product pattern; nothing requires moving them into SaaS OS. Sending its mail through the outbox-backed notification path would give it jitter and hints today, if its message model fits (it does not yet; gaps 1 and 4).
- **Recommendation: implement** the remainder in Core (jitter, cap and a typed retry-later error for jobs; `Retry-After` for webhooks; dead-letter on timeout). Patch or minor release.

### Gap 9: job payloads and cron (C18, C19)

- **Partly present.** `system_cron()` exists (system jobs only, intervals dividing 60 seconds, one attempt per tick, unique across workers) and is used for the outbox and audit digests, but it is not in `saas_os.infra.jobs.__all__`; the consumer guide tells products to import it from `saas_os.infra.jobs.queue`. Daily tasks (session cleanup, billing-event retention) run from host systemd timers that enqueue a system job. System jobs take no payload by design (ADR-0030).
- **Recommendation: implement** a public scheduling primitive that accepts arq's calendar fields (minute, hour, weekday, day), so products do not need a host timer for daily work; **defer** system-job payloads (a payload on an untenanted job invites tenant data into it; parameters belong in configuration, and tenant work belongs in a tenant job). The consumer's due-row batches with `SKIP LOCKED` are a sound pattern (the outbox uses it).

### Gap 10: permission upgrades for existing tenants (C01, C03)

Verified absent; issue #88. See section 7 and ADR-0060.

### Gap 11: system audit caller (C02)

Partial: `actor_type = 'system'` exists, but no purpose or structure describes a worker, a webhook processor, inbound processing or a public link, and `record()` accepts purpose-less system rows outside the mutation's transaction. See section 8 and ADR-0061.

### Gap 12: SQL function constructors and casts (C20)

- **Absent by design, for a security reason the report does not mention.** `func` and `text` were removed from `saas_os.infra.db` because `func.set_config(...)` or `text("SELECT set_config(...)")` inside a tenant session rewrites `app.tenant_id` and reads another tenant's rows, and with `is_local=false` poisons the pooled connection (CP-07 J-INFRA-05, PRIV-03 RA-01; `saas_os/infra/db/orm.py`). Only `now()` and `sum_()` exist. `docs/CONSUMER-GUIDE.md` section 7 forbids products to import `sqlalchemy` outside migrations.
- **The consumer's workaround** (a stored generated column and a product-schema operator for full-text search) is sound: it adds no capability to execute arbitrary functions.
- **Demand:** casts, `coalesce`, `lower` and full-text search occur in ERP reporting, project-management search and CRM alike.
- **Recommendation: implement narrowly:** named, single-purpose constructors in the `now()`/`sum_()` pattern, each unable to name another function, each covered by the J-INFRA-05 negative control; never a generic `func` or a `cast` to an arbitrary type name. Minor release.
- **Related finding F6** (section 6).

### Gap 13: embeddings (C21, C22)

- **Verified absent.** The inference facade is chat-style and non-streaming; adapters have one method, `complete()`; `docs/AI-INFERENCE-ROADMAP.md` (AI-G) lists embeddings as "only on a concrete consumer requirement" with its own adapter conformance and threat review; `docs/RELEASE-READINESS.md` puts it out of scope for v1.
- **Layer:** if built, inside governed inference (Optional, AI): sending tenant content to an embedding endpoint is the same data egress ADR-0013 and ADR-0055 govern, and a product calling a provider directly would bypass those gates. The vector store, chunking and retrieval are product.
- **Recommendation: defer to an owner decision** (it needs AI-G authorization and an ADR-0054 amendment); a consumer requirement now exists.

## 4. Target architecture (Phase C)

The three layers, the inclusion rule and the boundary examples are in `docs/architecture/PLATFORM_BOUNDARIES.md`. Assessment of Layer 1 against the mission's list:

| Responsibility | Adequate? | Critical gaps |
|---|---|---|
| Identity and access management | Yes, for OIDC | None for this round |
| Authentication and authorization | Mostly | Ambient `PROVISIONING` (C03); no permission upgrade path (C01) |
| Multi-tenancy and RLS | Yes, with a documented limit | Threat model unstated (F6) |
| Database lifecycle and migrations | Yes | None |
| Background jobs | Partly | No jitter or cap for plain jobs, timeout loss (F5), no public calendar schedules |
| Retry and idempotency guarantees | Yes for the outbox | Plain jobs (C16, C17) |
| Audit logging | Mostly | System attribution (C02); `record()` used for successful system actions |
| Security controls | Yes | Error-text redaction in persisted sinks (C23) |
| Egress restrictions | Yes, duplicated | Two stacks (C04); no safe read (C05) |
| Observability interfaces | Partly | No metrics exporter or alerting; backend undecided (ADR-0009) |
| Billing foundation | Yes | Out of scope here |
| Configuration and secrets interfaces | Yes | By design not pluggable (ADR-0012) |

Layer 2 modules: email and webhooks stay and are extended (C08, C09, C06, C07); inbound provider events generalize from Stripe-only to a primitive (C06); AI inference stays, with embeddings pending a decision. No existing module needs to become optional in packaging: none forces a dependency or infrastructure on a product that does not use it, except Redis, which Core needs for jobs and rate limiting (a product without background work still runs Redis; acceptable, recorded).

## 5. Consumer validation (Phase I)

### 5.1 The first consumer (CRM and email marketing)

| Requirement | Reusable? | Where it belongs | Workaround today | Assessment of the workaround |
|---|---|---|---|---|
| Unsubscribe headers, threading headers | Yes | SaaS OS email (C08) | Campaign sending blocked; threading by routing address | Sound; blocks a feature, not a risk |
| Egress reads | Yes | SaaS OS egress (C05) | Inbound email blocked | Sound |
| Sending-domain management | Partly | Product, through C05 | Blocked | Sound to wait for C05 |
| Display names | Yes | SaaS OS email (C09) | Bare addresses | Sound |
| Attachments, batch, scheduling | Attachments partly | Product or later | Text only, one send per message | Sound |
| Inbound mail and Svix verification | Verification yes; pipeline no | C06 in SaaS OS; pipeline in product | Product verifies Svix signatures itself | **Acceptable but carries risk:** each product's own signature code is a place for timing-unsafe comparison, missing timestamp tolerance or missing replay protection. Review it until C06 exists |
| Retry jitter and `Retry-After` | Yes | SaaS OS (C16) for jobs; product for its own queues | Product columns with jitter and hints | Sound |
| Payload-less system jobs, no cron | Scheduling yes | SaaS OS (C18) | `SKIP LOCKED` due-row batches; deployment scheduler | Sound |
| Permission upgrades | Yes | SaaS OS (C01) | `SystemCaller(PROVISIONING)` on existing tenants | **Unsound as a long-term pattern:** uses ambient authority beyond its documented purpose; must move to ADR-0060's path when it exists and not be copied by other products |
| System audit | Yes | SaaS OS (C02) | Actions recorded only in product rows | Acceptable short term; evidence lives outside the audit trail and its digests |
| SQL functions | Narrowly | SaaS OS (C20) | Generated column and product-schema operator | Sound |
| Embeddings | Undecided | Governed inference, if decided | Feature not built | Sound: building it outside governed inference would bypass the AI data gates |

Nothing the consumer needs requires SaaS OS to learn CRM vocabulary.

### 5.2 Hypothetical ERP

Needs: hierarchical organizations (tenant hierarchy exists), fine-grained permissions and approval chains (RBAC exists; approvals are product workflow), audit of automated postings (C02), scheduled period-end jobs (C18), reporting queries with casts and aggregates (C20), file imports and exports (attachments and object storage: not in SaaS OS; product), integration with banks and tax services (C05 reads, C06 inbound), permission upgrades with every release (C01). It does not need email headers or embeddings. **Conclusion:** the same Layer 1 gaps block it; none of the CRM-specific requests would be forced on it.

### 5.3 Hypothetical project management

Needs: per-tenant search (C20, product indexes), notifications with unsubscribe (C08), threaded email replies into tasks (C08 plus the product's inbound handling through C05 and C06), calendar and version-control integrations (C05, C06), recurring jobs (C18), attribution of automation rules (C02). **Conclusion:** consistent with the boundary: it reuses the same seams and keeps its domain in its own repository.

### 5.4 Independence

No capability recommended for implementation requires any consumer to adopt it: each is additive and opt-in (a new function, an allow-listed field, a primitive a product calls). The two that change existing behaviour are both security tightenings with a deprecation step: narrowing `PROVISIONING` (C03) and refusing purpose-less successful system rows through `record()` (ADR-0061 rule 5).

## 6. Security and reliability (Phase D)

### 6.1 Against the standards (summary)

| Standard area | Status | Evidence or gap |
|---|---|---|
| ASVS V4 access control; API1 BOLA, API5 BFLA | Strong | `can()` on every authority change, route policies verified at startup, RLS forced and swept; gap: ambient `PROVISIONING` (C03) |
| ASVS V2/V3 authentication and sessions | Adequate | OIDC RP, verified email for invitations, MFA for operators, same-origin check; live browser login unverified (ledger 1037) |
| ASVS V5 validation; Top 10 A03 injection | Mostly | Parameterized SQL, RLS, email header checks; gaps F3, F6 |
| API7 / A10 SSRF | Strong, duplicated | Pinned connections, all-address checks, IPv4-in-IPv6, proxy defence in depth; gaps F1, F4 |
| ASVS V7 logging; A09 logging failures | Mostly | Same-transaction audit, digests, key redaction; gaps: system attribution (C02), persisted error text (C23), message-string and traceback text uncovered by design (ADR-0020) |
| ASVS V6/V8 data protection; A02 cryptographic failures | Good | AES-GCM field encryption, transport TLS enforced in production; PostgreSQL `sslmode=require` without verification by default (ADR-0021, 0028); legacy plaintext webhook secrets (F7) |
| API4 resource consumption | Partial | Rate limits, quotas (AI soft), body caps; no per-subscription webhook rate or concurrency limit (ADR-0035 RE-F9 deferred) |
| API8 / A05 misconfiguration | Good | Fail-closed configuration, startup checks, production refusals |
| API10 unsafe consumption of APIs | Good | Provider responses capped, errors not echoed, provider types kept in adapters |
| A06/A08 supply chain and integrity | Good | Pinned base images and Actions, image scan and SBOM, signed tags, exact constraints in CI; no consumer-facing constraints or support window (C27) |
| Webhook security, replay protection | Outbound good; inbound narrow | HMAC with timestamp tolerance; no rotation (C07); no provider-neutral inbound verifier (C06); F2 |
| Worker isolation, retry storms, dead-letter safety | Good for outbox; weaker for plain jobs | Leases, jitter, caps, replay; F5; plain dead letters keep no payload by design |

### 6.2 New findings from this assessment

| ID | Finding | Severity | Evidence | Disposition |
|---|---|---|---|---|
| F1 | Webhook delivery through the egress proxy builds its TLS context with `httpx.create_ssl_context()` and its default `trust_env=True`, so `SSL_CERT_FILE`/`SSL_CERT_DIR` replace the trust store for proxied deliveries, contrary to the ADR-0035 amendment (`trust_env=False`) that the direct path follows | LOW | `saas_os/core/webhooks/service.py` (proxied branch); httpx 0.28.1 `create_ssl_context` source. The reference `docker-compose.prod.yml` sets `SSL_CERT_FILE` on `backend`, not `worker`, so the reference topology is unaffected; a deployment that sets it on the worker (for a privately signed Redis, ADR-0028 D3) either fails every delivery (bundle without public roots, fails closed) or lets that private CA vouch for any webhook host | Ledger row; fix as a patch (C04) |
| F2 | `verify_webhook_signature()` raises `TypeError` for a non-ASCII signature header instead of refusing it | LOW | `hmac.compare_digest` contract; the function is exported from `saas_os.core.webhooks` | Ledger row; patch |
| F3 | The email address pattern accepts a comma in the local part, and the SMTP provider's `To` header then names two recipients | LOW | Executed against the validator and the standard library parser | Ledger row; fixed with C09 |
| F4 | Webhook delivery relies on httpcore's `sni_hostname` extension but never calls `require_supported_http_stack()`, which only the strict egress client calls | LOW | `saas_os/infra/egress/client.py`; dependency bounds in `pyproject.toml` make drift unlikely | Ledger row; with C04 |
| F5 | A plain job that exceeds arq's `job_timeout` is neither retried nor dead-lettered by SaaS OS | LOW | arq 0.28 `Worker.run_job`; `saas_os/infra/jobs/queue.py` catches `Exception`, not cancellation. From the code, not tested | Ledger row; patch (C17) |
| F6 | The J-INFRA-05 fence (no `func`, no `text`) is a guardrail, not a boundary: any mapped column's `.op("<raw SQL>")` embeds arbitrary SQL, including `set_config('app.tenant_id', ...)`, without importing SQLAlchemy. RLS keyed on a session setting the application role may change cannot stop in-process code | INFO | SQL compilation only (no database): `Role.name.op(...)` with a raw operator string containing `(SELECT set_config(...))` compiles to that SQL. In-process product code is trusted by design | Ledger row; document the threat model in `docs/MULTI-TENANCY.md` and the consumer guide (roadmap R0); optionally a scaffold static check for `.op(` with a string argument |
| F7 | Webhook secrets stored before encryption (no `efv1:` prefix) are accepted as plaintext indefinitely | LOW | `saas_os/core/webhooks/service.py` secret decoding | Ledger row; operator re-encryption command, then refusal (C26) |

### 6.3 Earlier findings this assessment re-checked

- **Exception chains:** webhook delivery raises its errors outside the `httpx` handler so the request is not chained (ledger row 917, resolved); confirmed in the code.
- **Traceback locals:** a failed delivery's frame locals hold the signing secret, URL and body; SaaS OS records no locals, but a product's error tracker that captures them would (ledger row 901, `docs/CONSUMER-GUIDE.md` section 10). Still open by nature; C23 does not remove it.
- **Database error details and persisted error text:** lifecycle logs carry exception types only, but `last_error`, the Redis dead-letter entry and arq's own failure line carry `type: message` and, for arq, the full chain (ledger rows after 902). Connection errors put host, port, user and database, never the password, into those sinks. C23 proposes one error-description policy for all of them.
- **Webhook security:** URL redaction at delivery and subscription (row 902) holds; `http://` refused by default on `main` (row 921, release 2 merged, not yet in a release).

### 6.4 Architectural weaknesses

1. Ambient `PROVISIONING` authority (C03).
2. Two egress stacks (C04).
3. No provider-neutral inbound verification (C06); every product writes its own.
4. Undocumented RLS threat model (F6).
5. Plain jobs are weaker than the outbox (no jitter, timeout loss, no payload in dead letters, Redis not durable by guarantee); products should be steered to the outbox for anything that must happen.
6. Persisted error text policy is per call site (C23).
7. Release and support policy undecided at the audit (C27); since decided as ADR 0062 in pull request #188 (owner decisions of 2026-11-01; accepted 2026-11-02).

## 7. Permission upgrade architecture (Phase F)

Recommendation: ADR-0060 Option C. In short:

- A product declares append-only **permission grant migrations** (stable id, role name, permissions to add, reason).
- SaaS OS applies them per tenant through one Core function under a new, narrow `SystemAuthority.PERMISSION_UPGRADE` that only adds a registered, non-authority permission to an existing role in an open tenant. It never creates or assigns roles, adds memberships, or touches deny grants or delegations; a deny grant still wins.
- A tenant-owned ledger (`core.permission_grant_applications`, canonical RLS; `SECURITY_RETAIN`, survives purge next to the `PURGED` tombstone, runtime role SELECT and INSERT only, kept two years after `PURGED`, an active legal hold suspends expiry, deleted only by a controlled manual procedure with the migrations role (eligibility report first, active holds excluded, explicit operator action, auditable platform record; never automatic); ADR-0060 "Decision" item 7. Implemented in pull request #198 (open, not merged; head `3bb7e5e`): the eligibility calculation, the legal-hold table, the read-only report under `platform.security_retention:report`, holds under `platform.security_retention_hold:manage`, and the manual deletion `python -m saas_os.ops.permission_grant_ledger_expiry`, which connects only as the migrations role and has no platform permission of its own; it has not been run on real data) records each application, so a re-run never re-grants what a tenant administrator revoked; existing grants are reported, not duplicated.
- Per-tenant transactions under the existing advisory lock; a summary of applied, already present, already applied and refused tenants; safe to resume.
- Same-transaction audit per grant as `role_permission.grant` (the ordinary grant row plus `system_authority=permission_upgrade`, `migration_id`, `namespace`, `operator_user_id`, `run_id`). *Corrected 2026-11-02:* the implementation in pull request #198 does not attribute through ADR-0061's `SystemActor`; the operator is the `operator_user_id` metadata key. Aligning it with ADR-0061's `initiated_by` is a possible future change, not done.
- Invoked by the product's deployment after its migrations or by `saas-os-operator apply-permission-grants` (dry run by default; `--apply` writes).
- Rollback: additive; revocation is a later, separate migration kind limited to grants the ledger attributes to this mechanism.
- Then deprecate and refuse `PROVISIONING` on tenants that are not `PENDING` (ADR-0045 deferred item).

Rejected: documenting `PROVISIONING` (blesses ambient authority) and implicit upgrades (privilege escalation by inference).

## 8. System actor and audit architecture (Phase G)

Recommendation: ADR-0061 Option B. In short:

- **Attribution is separated from authority.** A `SystemActor(kind, name)` names the executing actor, what acted (`kind` from a closed list: worker job, scheduled job, webhook processor, provider-event processor, inbound processor, public link, maintenance, billing process; `name` chosen by the product). As amended on 2026-11-02 (attribution decision (C) of the 2026-11-01 owner review, which is not ADR-0061's Option C), the row also records the initiating actor separately (`initiated_by`: the original user, service account or system actor, or exactly `"unavailable"`; never the executor, never an invented user id, never a token) and correlation separately (request id, arq job id, outbox event id; never actor identity).
- `SystemActor` is not a `Caller`: no Core mutation accepts it, so it cannot become an authorization bypass. Where Core authority is needed, an existing, unchanged `SystemCaller` purpose is used and the actor is attached to it for attribution.
- A new same-transaction, fail-closed audit function writes `actor_type = 'system'` with the actor in validated metadata; tenant id from the verified context only; the correlation ids tie request, event, job and audit row together without standing in for an actor.
- Job contexts carry the derived executing actor and, for tenant jobs, the propagated initiating actor, so handlers attribute consistently; the job id is correlation, not the initiator.
- No migration and no digest-format change (metadata is already digested); columns (Option C) only if querying by actor becomes necessary.
- `PROVISIONING` and every other purpose stay as they are; nothing here widens them.

## 9. Proposed ADRs

| ADR | Title | Status | Needed for |
|---|---|---|---|
| ADR-0060 | Permission grant migrations for existing tenants | Proposed (this assessment); accepted by the owner 2026-11-02 | C01, C03 |
| ADR-0061 | System actor attribution in the audit trail | Proposed (this assessment); accepted by the owner 2026-11-02 | C02 |
| (next free number) | Provider-neutral inbound webhook verification | To draft when the roadmap reaches it | C06, C07 |
| (amendment) | ADR-0058 section 2: allow-listed headers and structured addresses | To draft | C08, C09 |
| (amendment) | ADR-0059 or a new ADR: egress read methods and one egress stack | To draft | C04, C05 |
| (amendment) | ADR-0054: embeddings | Only if the owner authorizes AI-G for embeddings | C21 |

## 10. Decisions requested from the owner

*Update 2026-11-02:* items 2, 3, 4 and 6 have since been decided by the owner (2026-11-01; ADR-0060 and ADR-0061, section "Owner decisions recorded"; ADR 0062 in pull request #188). The list below is kept as it was requested.

1. Accept the inclusion rule and the three layers (`docs/architecture/PLATFORM_BOUNDARIES.md` section 1 and 2).
2. ADR-0060: Option C or B, and its questions Q2-Q4.
3. ADR-0061: Option B or C, and its questions Q2-Q3.
4. Whether to narrow `PROVISIONING` after ADR-0060 ships, and on what schedule.
5. Whether embeddings enter governed inference now (AI-G authorization), or wait.
6. The versioning and support-window policy (ledger rows 870-872, 947), which every roadmap item's release classification depends on.
7. Authorization of roadmap stage R1 (security and correctness patches, `docs/roadmap/PLATFORM_CAPABILITY_ROADMAP.md`).

## 11. Limitations of this assessment

- Read-only: nothing was run against PostgreSQL, Redis, a provider or a live deployment. F3 and F6 were executed in isolation; F1, F2, F4, F5 and F7 come from the code and library sources.
- Parallel reviewers read most modules; their claims used here were spot-checked, not every line re-read.
- The consumer's own code was read only for its gap list and pin; its workarounds were not audited line by line (section 5.1 names the one to review).
- Severity ratings follow the ledger's scale and are the assessor's judgement; none is CRITICAL or HIGH.
- The ERP and project-management consumers are hypothetical.
