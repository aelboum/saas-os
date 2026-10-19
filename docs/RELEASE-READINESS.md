# Release readiness: AI inference and the 2026-10-18 candidate

Status: **prepared, not released.** This page records the evidence for one release candidate of SaaS OS and what still needs a decision. It does not replace the deferred-issue ledger in `docs/P-ROADMAP.md`, which stays authoritative for every finding; rows here point to it.

Nothing on this page is a release, a deployment or a support commitment. SaaS OS is a library that products pin by exact commit; deploying it is the product's act (ADR-0015).

## 1. Candidate

| Item | Value |
|---|---|
| Base | `main` at `0598a9a` (merge of pull request #53, AI inference) |
| Candidate | `b30e3691b6438102761eae4e4e6d1e54e1fef4f9`, the SaaS OS commit the reference consumer pins. Branch head `2dd8566` adds only the pin move; the commit adding the gate results changes only this page |
| Changes since `0598a9a` | post-merge audit findings D1, D2, D4 (`32f95cc`); typed error for invalid AI egress configuration (`3a1d9f0`); ledger corrections and this page (`b30e369`); the reference consumer's pin move (`2dd8566`); gate records (`d90ab8b`, `c7be66b`); the ADR reconciliation and findings F-A to F-D (section 3.1a), committed after `c7be66b` |
| Candidate and later commits | `b30e369` is the commit the reference consumer pins and the one installed from `git+https` (section 2.1). The F-A code change and the F-A to F-C tests come after it: they reach products with the merge of pull request #54, and the reference consumer's pin does not include them until it is moved again (section 5) |
| Published | branch `fix/ai-audit-findings` pushed and pull request #54 opened on 2026-10-18, with the owner's authorization. Not merged, tagged, released or deployed; merging and any release need a separate owner authorization |

## 2. Gates

Run 2026-10-18 on Windows, Python 3.13, on branch head `2dd8566` (tree `0dde3a2`): the candidate `b30e369` plus the reference consumer's pin move. Services were disposable PostgreSQL 16 and Redis 7 containers, or the scripts' own isolated Compose projects. The commits that add this table and the remote results below change only documentation; the local results are for `2dd8566`.

| Gate | Command | Result |
|---|---|---|
| Lint, format, types, import boundaries | `ruff check .`, `ruff format --check .`, `pyright`, `lint-imports` | pass; 883 files formatted; 0 errors; 21 contracts kept |
| Default suite | `pytest` | 4360 passed, 0 failed, 89 skipped (88 need Caddy and openssl, 1 POSIX file permissions) |
| Integration suite | `scripts/check-integration.sh` | 2857 passed, 0 skipped, exit 0 (45 min) |
| Migrations | `scripts/check-migrations.sh` | graph 7, gate 7, reference consumer end to end 1; exit 0 |
| Packaging | `scripts/check-packaging.sh` | 7 passed; exit 0 |
| Docker, development topology | `scripts/check-docker.sh` | exit 0: backend and worker healthy, readiness 503 without PostgreSQL, a real job executed, clean shutdown |
| Production validation over TLS | `scripts/check-docker-prod-tls.sh` | exit 0: migrations over TLS with `sslmode=require` injected, the production stack (backend, worker, frontend, Caddy, ZITADEL 4.19.0), an untrusted chain refused, edge TLS, cookie isolation, a backup of the validation database, restart idempotency |
| Production perimeter, plain | `scripts/check-docker-prod.sh` | fails at the migration step (`server does not support SSL`), as intended and dispositioned in the ledger (ADR-0021, ADR-0027); the TLS run above is the production validation |
| Security | `scripts/check-security.sh` | exit 0: pip-audit no known vulnerabilities, npm audit only the accepted `braces` exception, detect-secrets clean; `.secrets.baseline` unchanged |
| Candidate install and reference consumer | install of `saas-os[dev]` from `git+file` at `b30e3691…` in a new environment outside the repository, then the consumer's migrations, app and integration tests | `direct_url.json` commit `b30e3691b6438102761eae4e4e6d1e54e1fef4f9`; `pip check` clean; `certifi>=2024.7.4` declared; both migration histories at head; `/healthz` 200, `/readyz` 200; 30 consumer integration tests passed (inference, route security, scenarios) |
| Consumer update classification | `saas-os-update check` on a Git copy of the consumer | `REVIEW_REQUIRED` (exit 20) |

### 2.1 After publication (2026-10-18)

| Gate | Result |
|---|---|
| CI on pull request #54, head `d90ab8b` (run 39104663645) | all seven jobs pass: backend checks (ruff, format, pyright, import-linter; `pytest` 4361 passed, 88 skipped), security checks, security integration gate (migrate to head, 2857 passed, zero skips enforced), migration gate, packaging gate, Docker build and runtime validation, frontend checks |
| Pinned `git+https` install, manifest only | a new Python 3.13 environment, `pip install` of `examples/reference-consumer` from `d90ab8b` alone: pip resolved the manifest's requirement to `saas-os @ git+https://github.com/aelboum/saas-os@b30e3691b6438102761eae4e4e6d1e54e1fef4f9`; `direct_url.json` `https://github.com/aelboum/saas-os`, commit `b30e3691b6438102761eae4e4e6d1e54e1fef4f9`; `pip check` clean |
| Pinned `git+https` install and reference consumer gates | `saas-os[dev]` from `git+https` at `b30e3691…` in a new environment, the consumer and its tests from `d90ab8b` outside the repository, disposable PostgreSQL 16 and Redis 7: `pip check` clean, both migration histories at head, `/healthz` 200, `/readyz` 200, 30 consumer integration tests passed (inference, route security, scenarios), `saas_os` and `reference_consumer.inference` imported from the new environment |

CI results for later documentation-only heads of the pull request are on the pull request itself.

### 2.2 After the ADR reconciliation and F-A to F-C (2026-10-18)

Run locally on the working tree that was then committed as the F-A to F-C commit plus the documentation commit (code identical; the documentation commit changes only Markdown). Windows, Python 3.13, disposable PostgreSQL 16 and Redis 7.

| Gate | Result |
|---|---|
| `ruff check .`, `ruff format --check .`, `pyright`, `lint-imports` | pass; 883 files formatted; 0 errors; 21 contracts kept |
| `pytest` | 4360 passed, 0 failed, 89 skipped (88 need Caddy and openssl, 1 POSIX file permissions); the new tests are integration tests |
| Focused: `pytest -m integration tests/control_plane/inference/test_ai_inference_integration.py` | 46 passed |
| `scripts/check-integration.sh` | 2872 passed, 0 skipped, exit 0 (2857 before; 16 tests added, 1 renamed) |
| Negative controls | entitlement row not written: 4 entitlement tests fail; installation policy ignored: 8 `sensitive` and installation-policy tests fail; both restored |
| `scripts/check-migrations.sh` | graph 7, gate 7, reference consumer end to end 1; exit 0 (no migration changed) |
| `scripts/check-packaging.sh` | 7 passed; exit 0 |
| `scripts/check-security.sh` | exit 0: pip-audit no known vulnerabilities, npm audit only the accepted `braces` exception, detect-secrets clean; `.secrets.baseline` unchanged |
| Docker gates | not rerun locally (no Docker, deployment or configuration file changed); CI's Docker job runs on the pull request head |

No real provider was called; all inference tests use fake providers.

## 3. Findings and dispositions

### 3.1 AI inference findings

| ID | Finding | Severity | Status | Evidence / record |
|---|---|---|---|---|
| D1 | Present-day "not merged" statements after the merge | LOW | FIXED (`32f95cc`) | Search: no AI statement claims the work is unmerged |
| D2 | `certifi` imported directly but not declared | LOW | FIXED (`32f95cc`) | Wheel metadata `Requires-Dist: certifi>=2024.7.4`; isolated install loads the TLS context from it |
| D3 | The reference consumer's pin predates `saas_os.inference` | LOW | FIXED (`2dd8566`; pin moved to `b30e369`, see section 5) | `saas-os-update check`: REVIEW_REQUIRED, reviewed here |
| D4 | AI deployment settings undocumented | LOW | FIXED (`32f95cc`, corrected in `3a1d9f0`) | `docs/CONSUMER-GUIDE.md` 12a, "Deployment settings" |
| D5 | An invalid `AI_EGRESS_*` setting escaped the facade as `EgressConfigurationError` | LOW | FIXED (`3a1d9f0`) | `tests/control_plane/inference/test_ai_deadline_config_unit.py`; negative control |
| L1 | A refused inference by a non-member is recorded in the requested tenant's audit log | LOW | OPEN, decision (section 4, item 6) | `docs/P-ROADMAP.md` ledger; same convention as `api.access_denied` |
| L2 | A malformed `ai.tokens` is no limit unless `AI_INFERENCE_TOKEN_QUOTA_REQUIRED=true` | LOW | OPEN, decision (section 4, item 5) | Ledger; documented in the consumer guide |

### 3.1a Post-merge decision review (2026-10-18)

| ID | Finding | Severity | Status | Evidence / record |
|---|---|---|---|---|
| F-A | An entitlement refusal wrote no tenant audit row, although ADR-0055 section 6 requires one | LOW | FIXED (owner decision: option B) | `service.run_inference` records `not_entitled` and `entitlement_unavailable` refusals; five integration tests; negative control caught. Quota and capacity refusals still write no audit row, documented |
| F-B | Denial rows are best effort after the refusal; undocumented | LOW | DOCUMENTED AND TESTED; behaviour unchanged | ADR-0054 7a, ADR-0055 6, consumer guide 12a; an unrecorded refusal still refuses and logs `ai_inference_denial_unrecorded` with the exception type only |
| F-C | ADR-0055 section 5 described an `accepts_sensitive` flag; the code uses a (provider, `sensitive`) destination-policy row with a reason; no targeted test | LOW | FIXED (documentation and tests) | ADR-0055 section 5 "As built"; five `sensitive` tests and a parametrized refusal test (6 cases); negative control caught |
| F-D | The R3 condition (validated timeout values before AI-D) was not met | INFO | RECORDED; R3 revised by the owner | ADR-0054 sections 8a and 12.1: provisional, deployment-configurable defaults; each deployment validates; Q3 open for changes of the defaults |

### 3.2 Open MEDIUM rows in the ledger

| Ledger row | Status | Release impact |
|---|---|---|
| Self-learning 9.1–9.9 not re-certified against its recovered specification | Deferred | None for AI inference; the self-learning subsystem keeps its recorded limits |
| Redis has no persistence in the development Compose file | Deferred | Development only; production Redis is operator-managed (ADR-0028) |
| No external append-only copy of the audit tables | Implemented (ADR-0053); deployment step open | Each deployment must ship the digest logs to a store the database administrators cannot change |
| Webhook, GitHub, OIDC and ZITADEL clients use httpx's default `trust_env` | Webhook delivery resolved 2026-10-18 (`trust_env=False`, ADR-0035 amendment); the other clients open | Environment proxies change their egress path; AI egress is not affected (`trust_env=False`, tested) |

The 2026-10-16 rows on distributed concurrency limiting, the AI SDK import contract and the ADR-0013 data-authorization store were corrected on 2026-10-18: the first two are resolved, the third addressed for governed inference, each with its evidence in the ledger.

Every LOW and INFO row of the ledger carries its own status and rationale; none is CRITICAL or HIGH.

### 3.3 Accepted residual risks (ADR-0056, decided by the owner for the AI release)

- The operator command holds both database credentials; it is a trusted administrative boundary.
- The application role can write `core.platform_operators` and `core.platform_grants` (ADR-0045 §9a).
- The startup check protects exactly the six AI configuration tables; future protected tables need explicit grants and governance.

## 4. Decisions required from the owner

Items 1 to 6 were decided by the owner on 2026-10-18 (items 3 to 6 by accepting the recommendations of this page, section 8.2); items 7 and 8 are not decided here, and none blocks the engineering work above. Each blocks only what it names.

| # | Question | Recommendation | Alternatives and impact | Blocks |
|---|---|---|---|---|
| 1 | Accept ADR-0054 and ADR-0055 (Q6)? | **Decided 2026-10-18: both Accepted with explicit scope and conditions** (ADR-0054 section 12c, ADR-0055 section 10), after the reconciliation of 2026-10-18 (ADR-0054 section 12b). Q3 stays open for changes of the defaults; Q1, Q2 and Q8 stay open | Keep Proposed: no technical effect, but consumers build on Proposed contracts | Calling the AI subsystem's design final |
| 2 | Final timeout and concurrency values (Q3) | **Decided 2026-10-18 (R3 revised):** provisional, deployment-configurable defaults; each production deployment validates its settings before enabling real-provider traffic; Q3 stays open for any change of the defaults | Fix new defaults now: needs provider measurements that do not exist in this repository | A claim of validated defaults |
| 3 | Hard token caps (Q8) | **Decided 2026-10-18: deferred, residual risk accepted for v1** (section 8.2). Quotas stay soft and are documented as soft | A reservation design: atomic reservation before the call, settlement, reconciliation; substantial work and new failure modes | Any statement of a spending cap |
| 4 | Webhook and other non-AI egress `trust_env` (Q2, ledger) | **Decided 2026-10-18: `trust_env=False` on the webhook client** (ADR-0035 amendment, implemented); the GitHub, OIDC and ZITADEL clients and webhook scheme and port behaviour unchanged and still open | Keep: deployments relying on proxies keep working, at the cost of a proxy-dependent egress path. Changing it breaks deployments that route webhooks through a proxy | A uniform egress policy |
| 5 | `AI_INFERENCE_TOKEN_QUOTA_REQUIRED` default (L2) | **Decided 2026-10-18: default kept off**; production deployments set `true` (consumer guide; `docs/AI-PROVIDER-QUALIFICATION.md` D9) | Default on: a tenant without a valid `ai.tokens` is refused; changes behaviour for every existing plan without the entitlement. Financial exposure with it off: a tenant with no or a malformed limit is unlimited | A fail-closed default |
| 6 | Where refusals by non-members are recorded (L1) | **Decided 2026-10-18: current convention kept**, platform-wide | Platform log or no row: changes audit semantics across Core, not only AI | Changing audit attribution |
| 7 | Tenant-owned credentials, provider-report reconciliation authority, attempt-ledger retention class | Defer; none is needed for installation-managed providers | Each needs its own authority or policy decision (ADR-0054 section 8d) | Those features only |
| 8 | A database identity for platform authority; governance of future protected tables | Separate platform-wide ADR | Implementing now changes the trust model of every platform operation | Those boundaries only |

## 5. Reference consumer

`saas-os-update check` against a Git copy of the reference consumer at `4197d2f` classifies the move to the candidate as `REVIEW_REQUIRED` (exit 20): 39 commits touching migrations, authorization, security controls, the provider boundary and public APIs, including pull requests #44 to #53. The tool has no override for that class; this page and the pull request are the review. The consumer scaffold keeps `4197d2f`: it does not use AI inference, and moving it needs its own validation.

The reconciliation commits after `c7be66b` change `saas_os/control_plane/inference/service.py` (F-A) and its tests. The reference consumer still pins `b30e369`, which does not contain them; its code does not depend on them (it catches no inference error; the change adds an audit row to an entitlement refusal and leaves the error raised unchanged). Moving the pin to a commit that contains F-A is a follow-up, separate from the acceptance of ADR-0054 and ADR-0055 (Q6): a manifest cannot name its own commit, so it needs a further commit and the same pinned-install proof (section 2.1). Until then the reference consumer does not validate the entitlement-audit change of `7db23b7`; the consumer is compatible with the accepted contract (it uses only `saas_os.inference`, catches no inference error, and its 30 integration tests pass against `b30e369`), so the follow-up does not block acceptance. **Done 2026-10-18 after the merge:** the pin moved to `8e31cc0` (`main` after pull request #54, containing `7db23b7`), with the pinned `git+https` install and consumer validation repeated (`docs/P-ROADMAP.md`, "Reference consumer pin moved to `8e31cc0`").

## 6. Deferred capabilities

| Capability | Status | Why it does not block | Acceptance criteria to enable |
|---|---|---|---|
| Streaming | Disabled: `stream_inference` refuses every request | Non-streaming inference is complete and governed | The six release criteria of `docs/architecture/AI-INFERENCE-CONTRACTS.md` section 6.6 |
| Hard token caps | Not implemented; quotas are soft and documented as soft | Soft quotas, entitlements and per-tenant concurrency bound use | ADR-0054 Q8 design, implemented and tested under concurrency and failure |
| Tenant-owned credentials | Not implemented | Installation-managed credentials, allowlisted (`AI_PROVIDER_CREDENTIALS`) | Owner decision on authority and storage (ADR-0054 section 8d) |
| Bedrock, Vertex AI, embeddings, reranking | Not implemented | OpenAI-compatible, Anthropic and Gemini adapters exist | A new adapter with conformance and egress tests |
| Provider-report reconciliation | Not implemented; usage is provider-reported or estimated, with provenance | Provenance distinguishes reported, estimated and unknown | A decision on who may record usage against a tenant |
| Attempt-ledger retention | Classified `DEFERRED_POLICY` | Rows are kept | A retention policy decision |

## 7. Operating the release

The procedures are in the documents below. Section 2 says which were executed for this candidate; a procedure that was not executed here is not claimed as validated.

- Install, configuration and pinning: `docs/CONSUMER-GUIDE.md` (sections 4, 5, 6 and 12a), `docs/AUTO-UPDATE-CLI.md`.
- Database roles and migrations, upgrade and downgrade: `docs/CONSUMER-GUIDE.md` 5–6, `docs/RUNBOOKS.md` ("AI configuration role").
- Backup and restore: `docs/BACKUP-RESTORE.md`.
- Observability: `docs/OBSERVABILITY.md`.
- Production topology and external PostgreSQL and Redis: `docs/DEPLOYMENT-ARCHITECTURE.md`, `docs/RUNBOOKS.md` (ADR-0028).
- Operator commands and platform operators: `docs/RUNBOOKS.md`.

No SLA, RPO, RTO or certification is stated or implied.

## 8. AI inference v1: product-readiness review (2026-10-18)

Base: `main` at `1da3e626b211fdb00747778cfc89d38d71182e1a` (pull requests #54 and #55 merged; main CI run 39141280012, seven jobs passing). The changes below are on the local branch `feat/ai-product-ready`, **not pushed or merged**; nothing here is a release, and no real provider was called. The procedures for provider and deployment qualification are in `docs/AI-PROVIDER-QUALIFICATION.md`.

### 8.1 V1 scope

The first product release of AI inference is governed, non-streaming, text-only inference through `saas_os.inference.run_inference`, with installation-managed credentials: exactly the scope accepted in ADR-0054 section 12c and ADR-0055 section 10. Nothing outside that scope is added for v1.

| Capability | Status | Evidence or reason |
|---|---|---|
| Non-streaming inference through the public facade | REQUIRED_FOR_PRODUCT_READY | `tests/control_plane/inference/test_ai_inference_integration.py`; `tests/test_reference_consumer_inference_integration.py`; facade contract in `tests/architecture/test_ai_inference_boundaries.py` |
| Provider, model and alias configuration (installation-managed, platform-audited) | REQUIRED_FOR_PRODUCT_READY | `test_ai_configuration_integration.py`, `test_ai_configuration_unit.py` |
| Credential provisioning and retrieval (`AI_PROVIDER_CREDENTIALS`, `SecretsProvider`) | REQUIRED_FOR_PRODUCT_READY | `test_ai_credentials_unit.py`; credential tests in the integration file; F-G and F-J fixed |
| Tenant authorization, classification and destination policy | REQUIRED_FOR_PRODUCT_READY | Authority, policy and `sensitive` tests; F-E fixed |
| Safe outbound network access (strict egress) | REQUIRED_FOR_PRODUCT_READY | `tests/infra/egress/` (address classes, pinning, rebinding, redirects, proxies ignored, encodings, byte caps, real TLS on loopback) |
| Request and response limits | REQUIRED_FOR_PRODUCT_READY | Use-case `max_input_bytes` and `max_parts`; required `max_output_tokens`, bounded by the model and sent to the provider; `AI_EGRESS_MAX_RESPONSE_BYTES` |
| Timeouts, bounded retries, fallback, circuit breaking | Mechanism REQUIRED_FOR_PRODUCT_READY; values REQUIRED_FOR_PRODUCTION_READY | Retry and fallback tests; provisional values (R3 revised); circuit per (provider, model) since 2026-10-18 |
| Concurrency (cluster-wide leases) | REQUIRED_FOR_PRODUCT_READY | `tests/infra/ratelimit/test_concurrency_leases_integration.py` |
| Soft token quota | REQUIRED_FOR_PRODUCT_READY, documented as soft | `test_ai_accounting_unit.py`; quota integration tests; F-I fixed |
| Hard token caps (Q8) | DEFERRED_WITH_ACCEPTED_RISK (owner, 2026-10-18) | Not designed |
| Token usage capture and cost estimates | REQUIRED_FOR_PRODUCT_READY, with provenance; not billing-grade | Usage tests; F-F and F-H fixed; the settlement-failure and partial-report gaps are open (ledger) |
| Provider-report reconciliation | DEFERRED_WITH_ACCEPTED_RISK (owner decision open, section 4 item 7) | Not implemented |
| Audit events and denial handling | REQUIRED_FOR_PRODUCT_READY | Denial tests, including best-effort writes; quota and capacity refusals write no row (documented) |
| Error redaction and log safety | REQUIRED_FOR_PRODUCT_READY | `test_status_codes_are_normalized`, `test_errors_do_not_carry_urls_or_headers`, `test_credentials_and_content_never_leak`; F-G fixed |
| Observability | Structured log events REQUIRED_FOR_PRODUCT_READY; metrics NOT_IN_SCOPE (ADR-0054 section 12c, condition 6) | `docs/AI-PROVIDER-QUALIFICATION.md` section 4 |
| Database migrations and recovery | REQUIRED_FOR_PRODUCT_READY | `scripts/check-migrations.sh`; no migration changed in this review |
| Reference-consumer installation and integration | REQUIRED_FOR_PRODUCT_READY | Pinned install of `8e31cc0` (section 5); the working-tree consumer test in CI |
| Real-provider conformance | REQUIRED_FOR_PRODUCTION_READY | Harness ready, not run (8.4) |
| Deployment configuration validation | REQUIRED_FOR_PRODUCTION_READY, the product's act | `docs/AI-PROVIDER-QUALIFICATION.md` section 3 |
| Streaming, tool calls, tenant-owned credentials, Bedrock, Vertex AI, embeddings | NOT_IN_SCOPE for v1 | Section 6 |
| Public tool-registration interface (Q1) | NOT_IN_SCOPE for v1 | Not part of inference |

### 8.2 Open items: dispositions

| Item | Exact question and source | Current behaviour | Risk if unresolved | Recommendation | Done in this review | State |
|---|---|---|---|---|---|---|
| Q1 | "Should the existing tool-registration integration eventually receive a public consumer interface?" (ADR-0054 section 12a) | Products import `saas_os.control_plane.orchestration.tools`, an intact, supported integration (owner decision, 2026-10-16) | None for inference: tools are outside the inference interface | Keep open; decide when a second product needs tools | Nothing | Deferred under the owner's existing decision; not product-blocking |
| Q2 | Webhook scheme, port and `trust_env` (ADR-0054 section 12a; section 4 item 4) | The webhook (`saas_os/core/webhooks/service.py`), GitHub (`saas_os/control_plane/development/github_provider.py`), OIDC (`saas_os/core/identity/oidc.py`) and ZITADEL bootstrap (`saas_os/infra/local_identity/zitadel_bootstrap.py`) clients use httpx's default `trust_env=True`; AI egress uses `trust_env=False`, tested (`test_client_ignores_environment_proxies…`) | Environment proxies change the egress path of non-AI clients | Set `trust_env=False` on the webhook client (section 4 item 4). This breaks deployments that route webhooks through a proxy and needs an ADR-0035 amendment | **Owner accepted the recommendation 2026-10-18:** webhook delivery built with `trust_env=False` (ADR-0035 amendment), tested, negative control caught. Breaking for deployments that proxied webhook deliveries | Resolved for webhooks; the GitHub, OIDC and ZITADEL clients and webhook scheme and port stay open (not part of AI inference) |
| Q3 | Final timeout values and changes of the defaults (ADR-0054 section 12a; R3 revised) | Provisional defaults, refused when invalid (`egress_config.py`, `admission.py`), documented in `docs/CONSUMER-GUIDE.md` 12a; the stale "validated before AI-D" docstring corrected | A deployment running unvalidated values | Keep the defaults; each deployment qualifies its values (`docs/AI-PROVIDER-QUALIFICATION.md`, D6 and D7) | Validation method documented | Resolved for v1 by R3 revised; the values are deployment evidence (Gate C) |
| Q8 | "What design, if any, enables reliable hard token caps" (ADR-0054 section 12a; section 4 item 3) | Soft monthly quota. Per-request hard bounds: `max_output_tokens` is required, at most the model's configured maximum, and sent to the provider; input is bounded by the use case (at most 8 MiB). Overshoot of the monthly quota is bounded by concurrency times the per-request bound; attempts with unknown usage are not counted | A tenant can exceed its monthly quota by that bound | V1 can ship without hard caps if no product document promises a spending cap; set `AI_INFERENCE_TOKEN_QUOTA_REQUIRED=true` and conservative concurrency | Nothing (a reservation design is a material decision) | **Deferred, residual risk accepted by the owner 2026-10-18** |
| L1 | Where refusals by non-members are recorded (section 4 item 6; ledger) | A non-member's refusal writes a `denied` row in the requested tenant's log; an unknown or closed tenant gets no row; since this review the refusal is identical in all three cases (F-E) | Audit noise in a tenant's log, bounded by the product's limits | Keep the platform-wide convention | F-E fixed and tested; the audit-write-failure path stays tested (`test_an_unrecorded_authority_refusal_still_refuses`) | Disclosure resolved; **convention kept by the owner 2026-10-18** |
| L2 | `AI_INFERENCE_TOKEN_QUOTA_REQUIRED` default (section 4 item 5; ledger) | Default off: a tenant without a valid `ai.tokens` is unlimited; on: refused; unreadable data always refuses; a typo in the setting now refuses (F-I) | Uncontrolled spend for a plan without a valid limit while off | Keep the default for compatibility; production deployments turn it on (D9) | F-I fixed | **Default kept off by the owner 2026-10-18**; production deployments turn it on (D9) |

### 8.3 Security and accounting checklist

Confirmed controls, each with its proving tests (fake providers only):

- Tenant identity comes from the trusted caller only. Non-members, other tenants' service accounts and support access are refused before anything is sent, and the refusal does not reveal whether a tenant exists (F-E).
- Authority, validation, policy, entitlement, quota and admission all precede the attempt row, which commits before any byte is sent; nothing is sent on any refusal.
- Strict egress: HTTPS; the port from the provider row only; every resolved address validated and pinned; embedded IPv4 checked; no redirects; no proxies; identity encoding; a byte cap; a shared deadline.
- Credentials: allow-listed names, never stored, returned, audited or logged; consumer errors are not chained to provider-side exceptions (F-G); a secrets-backend failure is typed (F-J).
- Usage: provider-reported versus estimated provenance; settlement once only (`FOR UPDATE`, `started` rows only); the outbox mirror in the same transaction; a live attempt is not abandoned by a short request (F-F); Gemini thinking tokens counted (F-H).
- Audit: denial rows for authority, policy and entitlement refusals, best effort; none for quota and capacity refusals; no prompt, completion or credential in any row.
- Import boundaries: `saas_os.api` cannot reach the control plane, and nothing in SaaS OS imports the facade.

Defects fixed in this review: F-E to F-J (`docs/P-ROADMAP.md` ledger), each with a regression test. Negative controls for F-E, F-F and F-G fail as intended; the original code was restored and compared byte for byte.

Residual risks: the soft quota (Q8, L2; accepted by the owner 2026-10-18); usage lost when settlement fails after a provider success; partial usage reports; Anthropic cache counts; trust revocation during a request; best-effort denial rows; unaudited quota and capacity refusals. None is CRITICAL or HIGH, and none blocks product-ready.

### 8.4 Provider conformance

- Deterministic conformance for all three adapters (`test_provider_adapters_unit.py`, `test_gemini_adapter_unit.py`) runs in CI.
- Real-provider conformance, **first run 2026-10-18, incomplete**: OpenAI, `https://api.openai.com`, `openai_chat_completions`, model `gpt-4o-mini`, a non-production key supplied by the owner. Invalid credential: `provider_auth`, not possibly accepted (pass). Unknown model: `invalid_request`, no key in any rendering (pass). Deadline of 50 ms: `timeout`, possibly accepted (pass). Success and output bound: **failed**, HTTP 429 `insufficient_quota` (`credit_balance_exhausted`): the account has no credit, so nothing was generated or billed. Response limit: passed, but inconclusive (the 429 error body alone exceeded 64 bytes); the case now requires a successful response in the same run. Total: 5 requests to the chat endpoint, plus one model listing and one request reading only the error code. Rerun the same day (19:40 UTC) after the owner added credit: **6 passed, 0 failed, 0 skipped.** Success: `finish_reason` `stop`, provider-reported usage 14 input and 1 output tokens, a provider request id returned. Output bound (`max_output_tokens=1`): `finish_reason` `length`, 1 output token. Invalid credential: `provider_auth`. Unknown model: `invalid_request`, the key in no rendering. Response limit of 64 bytes, after a successful response: `response_too_large`. Deadline of 50 ms: `timeout`, possibly accepted. Six requests, sanitized report only. **OpenAI `gpt-4o-mini` through `openai_chat_completions` is qualified to this conformance level**; other models, the Anthropic and Gemini adapters, load, latency and rate-limit behaviour are not. Known limitation, from the provider documentation and not tested here: OpenAI reasoning models refuse `max_tokens` (the adapter sends it), so configure only non-reasoning chat models for this adapter. The harness is `tests/control_plane/inference/test_ai_provider_live_integration.py` (opt-in; here its 6 tests skip), with the procedure in `docs/AI-PROVIDER-QUALIFICATION.md` section 2. The provider needing the least extra scope is the one the first product uses: all three adapters share the harness.

### 8.5 Readiness gates

| Gate | Criterion | Result | Evidence |
|---|---|---|---|
| A | Required CI green on the exact candidate commit | PASS | Pull request #56, head `d1ea9d0`: CI run 39161738126, seven jobs passing (the first run, 39160076833 on `0f07281`, failed in the security integration gate on a test fake that did not accept `trust_env`; fixed in `d1ea9d0`). Merged as `f168752` |
| A | Packaging, migrations, import boundaries, reference consumer | PASS | CI run 39161738126; 8.6; reference consumer pinned to `f168752` with the pinned `git+https` proof repeated (`docs/P-ROADMAP.md`, "Reference consumer pin moved to `f168752`") |
| A | No unexplained failures or security findings | PASS | F-E to F-J fixed; everything else recorded with a severity |
| B | V1 scope explicit | PASS | 8.1 |
| B | Product-blocking decisions resolved | PASS | Q2 (webhooks), Q8, L1 and L2 decided by the owner on 2026-10-18 (section 4); Q1 deferred under the owner's 2026-10-16 decision |
| B | Security and tenant-isolation controls tested | PASS | 8.3 |
| B | Usage accounting and quota meet the product contract | PASS for a soft quota with estimates; not billing-grade | 8.3; ledger |
| B | At least one provider qualified to the promised level | PASS | OpenAI `gpt-4o-mini`, live conformance 6/6 on 2026-10-18 (8.4); v1 promises exactly this provider and model level |
| B | Limitations documented; configuration and failures deterministic | PASS | `docs/CONSUMER-GUIDE.md` 12a; contracts section 4; F-I, F-J |
| C | Real provider and deployment qualification | BLOCKED (provider part done) | Live provider conformance passed (8.4); deployment qualification needs a product deployment (`docs/AI-PROVIDER-QUALIFICATION.md` section 3) |
| C | Deployment-specific defaults validated | BLOCKED | Per deployment (D6, D7) |
| C | Monitoring, alerts, secrets, runbooks, recovery, cost controls proven | BLOCKED | Per deployment (D3 to D14) |
| C | Remaining risks accepted by the decision-maker | BLOCKED | Owner (8.2) |
| C | Release and deployment approvals | BLOCKED | Owner |

**Product-ready is achieved** (2026-10-18): Gate A passes on `f168752` and Gate B since the live OpenAI run of 2026-10-18, for the v1 scope of 8.1 and the provider and model qualified in 8.4. Production-ready is not claimed: Gate C needs a product deployment qualified with `docs/AI-PROVIDER-QUALIFICATION.md` section 3.

### 8.6 Local gates on the candidate (2026-10-18)

Run on Windows, Python 3.13, on commit `35ec43a` of `feat/ai-product-ready` (the code of this review; this table is added by the following documentation-only commit). Disposable PostgreSQL 16 and Redis 7 containers, removed afterwards. Gates were run one at a time; an earlier attempt was stopped by the host for low memory and has no result.

| Gate | Command | Result |
|---|---|---|
| Lint, format, types, import boundaries | `ruff check .`, `ruff format --check .`, `pyright`, `lint-imports` | pass; 885 files formatted; 0 errors; 21 contracts kept |
| Default suite | `pytest` | 4383 passed, 0 failed, 89 skipped (88 need Caddy and openssl, 1 POSIX file permissions) |
| Integration suite | `scripts/check-integration.sh` | 2878 passed, 0 skipped, exit 0 (51 min); 2872 before, 6 tests added |
| Negative controls | F-E, F-F, F-G reverted one at a time | the three new tests fail; code restored and compared byte for byte |
| Migrations | `scripts/check-migrations.sh` | graph 7, gate 7, reference consumer end to end 1; exit 0 (no migration changed) |
| Packaging | `scripts/check-packaging.sh` | 7 passed; exit 0 |
| Security | `scripts/check-security.sh` | exit 0: pip-audit no known vulnerabilities, npm audit only the accepted `braces` exception, detect-secrets clean; `.secrets.baseline` unchanged |
| Live provider conformance | `pytest -m integration tests/control_plane/inference/test_ai_provider_live_integration.py` | not run: 6 skipped, no non-production key configured (8.4) |
| Docker gates | `scripts/check-docker.sh`, `check-docker-prod-tls.sh` | not rerun locally (no Docker, deployment or configuration file changed); CI runs the Docker job once the branch is published |

The reference consumer keeps its pin `8e31cc0`: a manifest cannot name the commit it is part of, and the candidate is unpublished. The working-tree consumer test above (migrations gate) runs this review's code; the pinned-SHA proof is repeated after a merge, as in section 5.

## 9. Local production-readiness rehearsal of D1 to D14 (2026-10-18)

**A local rehearsal, not a deployment qualification.** Gate C stays **NOT YET QUALIFIED**: every item below still has to be qualified in the intended deployment environment (`docs/AI-PROVIDER-QUALIFICATION.md` section 3).

**Environment.**
- A new Python 3.13 environment outside the repository, with `saas-os[dev]` installed from `git+https://github.com/aelboum/saas-os@f168752d7e4e0fbc5481c8e0e1cc7b0986431ba5`. `direct_url.json` records that commit, `pip check` is clean, and the reference consumer's manifest resolved the same requirement.
- The reference consumer and the test support copied outside the repository, with no `saas_os` source.
- Run-owned PostgreSQL 16 and Redis 7 containers on fixed local ports, removed afterwards.
- The real OpenAI provider (`gpt-4o-mini`, `openai_chat_completions`) with the owner's non-production key, read into the process environment only.
- Main at `1b979f3`, CI run 39167404217 green; it differs from `f168752` only in documentation.

**Driver.** A rehearsal script and a pytest module kept outside the repository. They run the default runtime: real Redis admission, the real plan entitlement, the real `StrictEgressClient` and the real adapter wrapped in a counter, so "nothing sent" is measured, not assumed. Their output is a sanitized JSON-lines report: no key, prompt or output. Result: 13 passed, 12 real requests (each at most 200 output tokens), and the key in no log line and no database row the rehearsal could read.

| Item | What was rehearsed | Local result | Remaining deployment verification |
|---|---|---|---|
| D1 Migrations and roles | Both role init scripts, `saas-os-migrate upgrade` (head `f6a2c8e4b1d9`), consumer migrations, the consumer under uvicorn: `/healthz` 200, `/readyz` 200; PostgreSQL stopped: `/readyz` 503, `/healthz` 200, recovered to 200 | **FAIL, fixed** (finding F-K below): with Redis stopped, `/readyz` gave no answer within 10 s. With the fix (working-tree wheel over the pinned install, not the pinned SHA): Redis stopped gives 503 and recovers to 200. Repeated 2026-10-19 from the pinned `git+https` install of `ab17e7f` (the fix merged): PostgreSQL stopped and Redis stopped each give `/readyz` 503 with `/healthz` 200, and both recover to 200 | Run against the deployment's managed PostgreSQL and Redis and its probe timeouts |
| D2 Provider configuration | Provider, model, destination policy and alias through the configuration operations (Python, not the `saas-os-operator` CLI); platform audit rows `platform.ai_provider.configure`, `platform.ai_policy.configure` | PASS_LOCAL | Configure with `saas-os-operator` and real operator enrolment (test helpers were used here) |
| D3 Credentials | A governed call through the reference consumer succeeds (provider-reported usage 24 input and 13 output tokens, provider request id, 2.3 s); a name removed from `AI_PROVIDER_CREDENTIALS` gives `credential_unavailable`, 0 requests sent, no attempt row, log event `ai_provider_credential_unavailable` | PASS_LOCAL | Secret injection through the deployment's secret store |
| D4 Credential rotation | Invalid value under the same name: `provider_auth`, one attempt, no fallback to the second candidate; the real value again works; a new name (`set_provider_credential_ref`) refuses with `no_eligible_destination` and sends nothing until `confirm_provider_binding`, then works | PASS_LOCAL | Rotate a real key at the provider and revoke the old one |
| D5 Egress | `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` set to a dead proxy: the request still succeeds directly (`trust_env=False`); a provider at `https://127.0.0.1/v1` is refused at configuration (`AIConfigurationError`), nothing sent | PASS_LOCAL | The production network path and firewall (only the provider host allowed) |
| D6 Timeouts and response size | Three requests at `max_output_tokens=64`: 1.16 s, 1.17 s, 1.58 s; a 50 ms deadline: `InferenceTimeoutError("deadline")` before anything was sent | PASS_LOCAL for the mechanism | Measure the deployment's real use cases and largest outputs, then set `AI_EGRESS_*`; three samples choose no value |
| D7 Concurrency | `AI_INFERENCE_TENANT_CONCURRENCY=1`, three concurrent requests: one result, two `InferenceCapacityExhaustedError`, one request sent, log event `ai_inference_capacity_exhausted` | PASS_LOCAL | Choose limits from the account's provider rate limits and worker capacity |
| D8 Redis | Redis stopped: `InferenceInternalError("admission_unavailable")`, 0 sent, 0 attempt rows; restarted: success | PASS_LOCAL | Managed Redis failover |
| D9 Token quota | `AI_INFERENCE_TOKEN_QUOTA_REQUIRED=true`: a plan without `ai.tokens` is refused (`quota_not_configured`); with `ai.tokens=120`, a request within the limit passes and the next, projecting past it, is refused (`monthly_token_quota`); one request sent | PASS_LOCAL | Real plan entitlements; the quota stays soft (Q8 accepted) |
| D10 Cost visibility | Price version set with `set_model_price`; the settled attempt has `estimated_cost` 0.00000345 USD with its pricing version; `read_ai_usage_totals` with `platform.ai_usage:read` returns the tenant's totals | PASS_LOCAL | The deployment's real prices; estimates are not billed amounts |
| D11 Monitoring | Log events emitted and free of the key: `ai_inference_attempt`, `ai_provider_credential_unavailable`, `ai_inference_capacity_exhausted` | PASS_LOCAL for the events only | Shipping, alert rules and their delivery: not testable locally |
| D12 Database limits | Disposable server: `max_connections=100`, `statement_timeout=0`, `idle_in_transaction_session_timeout=0` (PostgreSQL defaults) | NOT_TESTED | Size the pool for the concurrency limits and set statement and idle-in-transaction timeouts on the production server |
| D13 Backup and recovery | `python -m saas_os.infra.db.backup create` (exit 0), then `restore --target-database saas_os_restore_check` (exit 0) on the same disposable server; row counts identical (attempts 12, providers 14, audit 199, platform audit 177, outbox 22) | PASS_LOCAL (plaintext, same server) | Encrypted (`age`) backups, off-host storage and a restore drill on separate infrastructure (`docs/BACKUP-RESTORE.md`) |
| D14 Rollback | Disabling switches: the plan without `ai.inference` and a withdrawn destination policy both refuse with nothing sent | PASS_LOCAL for the switches; NOT_TESTED for a rollback to an earlier pin | Exercise a rollback of the deployed product |

Counts: PASS_LOCAL 12 (D2 to D11, D13, D14; D6, D11, D13 and D14 with the limits stated), FAIL then fixed 1 (D1), NOT_TESTED 1 (D12).

**Finding F-K (LOW, fixed on the rehearsal branch).** The Redis readiness probe had no bound of its own. arq's connect retries took 11.1 s against an unreachable Redis (measured), so `/readyz` timed out instead of answering 503. It is now bounded at 2 s around connecting and `PING` (`saas_os/infra/health/readiness.py`), matching the database probe's 2 s connect timeout. Tests: `test_a_hanging_redis_is_unhealthy_within_the_bound`, and `test_redis_check_is_unhealthy_against_an_unreachable_redis` now also asserts the time. The negative control (bound removed) fails. Remeasured: 2.0 s.

## 10. Local rehearsal of D1 to D14 on the published pin `ab17e7f` (2026-10-19)

**A local rehearsal, not a deployment qualification.** Gate C stays **NOT YET QUALIFIED**. Section 9 is unchanged; this section repeats it on the pin that contains the F-K fix, and adds three items section 9 left untested: D2 through the operator CLI, D12 and the D14 rollback to an earlier pin.

**Environment.**
- Main at `2a5d9fa` (pull request #59; main CI run 39211710993, seven jobs passing). The reference consumer pins `ab17e7ff3078a9e89c96db1482b3139efbf1547a`.
- A new Python 3.13 environment outside the repository, with `saas-os[dev]` installed from `git+https://github.com/aelboum/saas-os@ab17e7ff3078a9e89c96db1482b3139efbf1547a`. `direct_url.json` records that commit and `pip check` is clean. No `saas_os` source was copied, and no working-tree wheel was used.
- Run-owned PostgreSQL 16 and Redis 7 containers, removed afterwards (none left).
- The real OpenAI provider (`gpt-4o-mini`) with the owner's non-production key, read into the process environment only.

**Driver.** The section 9 script and pytest module, kept outside the repository, extended with D2 through the CLI, D12 and the D14 rollback. Main run: 14 passed, 16 real requests (at most 64 output tokens each). The rollback run made 1 more request, and the two passing CLI runs made 1 each, for 19 real requests in total. Two earlier CLI runs failed on defects in the rehearsal test itself, before any request was sent: the key was removed from the command's environment, and the operator lacked `platform.ai_config:read`. A scan of every log, report and script the rehearsal wrote (7,700 files) found the key in none, and the D3 case found it in no log line or database row.

| Item | Acceptance criterion (section 3) | What was rehearsed | Local result | Remaining deployment verification |
|---|---|---|---|---|
| D1 Migrations and roles | `saas-os-migrate upgrade` with the migration role; the platform-configuration role exists; the application starts and `/readyz` is 200 | Both role init scripts; the installed `saas-os-migrate upgrade`, exit 0, head `f6a2c8e4b1d9`; consumer migrations exit 0; the consumer under uvicorn: `/healthz` 200 and `/readyz` 200. PostgreSQL stopped: `/readyz` 503, `/healthz` 200, back to 200. Redis stopped: `/readyz` 503, `/healthz` 200, back to 200 | PASS_LOCAL | Managed PostgreSQL and Redis, and the deployment's probe timeouts |
| D2 Provider configuration | `ai-provider-create`, `ai-model-create`, `ai-alias-set` and `ai-destination-policy`, each with `--reason`; prices through `set_model_price`; platform audit rows written | The installed `saas-os-operator`, with the platform-configuration URL only in that command's environment: all five commands exit 0. A governed call through the provider configured this way succeeds. `ai-show` exits 1 without `platform.ai_config:read`, and 0 with it: it lists the provider and contains no key value. A missing `--reason` exits 2. Platform audit actions: `platform.ai_provider.configure` (3), `platform.ai_policy.configure` (2), `platform.ai_config.read`. The Python configuration path also passed (section 9) | PASS_LOCAL | Real operator enrolment (a test helper enrolled the operator here) and running the commands inside the deployment's backend container |
| D3 Credentials | Name listed in `AI_PROVIDER_CREDENTIALS` and injected as a secret; a request succeeds; removing the name gives `credential_unavailable` with nothing sent | A consumer call succeeds: 24 input and 10 output tokens reported by the provider, a provider request id, 2.4 s. With the name removed: `credential_unavailable`, 0 sent, no attempt row, log event `ai_provider_credential_unavailable` | PASS_LOCAL | Injection through the deployment's secret store |
| D4 Credential rotation | Same-name rotation, or a new name bound and confirmed; a revoked key gives `provider_auth`, never a silent fallback | An invalid value under the same name: `provider_auth`, one attempt, no fallback to the second candidate. The real value works again. A new name refuses (`no_eligible_destination`) with 0 sent until `confirm_provider_binding`, then works | PASS_LOCAL | Rotate a real key at the provider and revoke the old one |
| D5 Egress | Direct HTTPS to the provider host, proxy variables ignored; a non-allowed host refused | With `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` pointing at a dead proxy, the request still succeeds. `https://127.0.0.1/v1` is refused at configuration (`AIConfigurationError`), nothing sent | PASS_LOCAL | The production network path and firewall |
| D6 Timeouts and response size | Measure time to a complete response and the largest response; set `AI_EGRESS_*` above them | Three requests at `max_output_tokens=64`: 1.39 s, 1.09 s and 1.31 s. A 50 ms deadline: `InferenceTimeoutError("deadline")`, not possibly accepted | PASS_LOCAL for the mechanism | Measure the deployment's real use cases and largest outputs, then choose the values |
| D7 Concurrency | Concurrent requests above the tenant limit give `InferenceCapacityExhaustedError` and the log event | Tenant limit 1, three concurrent requests: one result, two `InferenceCapacityExhaustedError`, one request sent, log event `ai_inference_capacity_exhausted` | PASS_LOCAL | Limits from the account's provider rate limits and worker capacity |
| D8 Redis | Redis stopped: `admission_unavailable` with nothing sent; restarted: requests succeed | Redis stopped: `InferenceInternalError("admission_unavailable")`, 0 sent, 0 attempt rows. Restarted: success | PASS_LOCAL | Managed Redis failover |
| D9 Token quota | Quota required; a tenant over its limit refused; a tenant without a limit refused (`quota_not_configured`) | Without `ai.tokens`: `quota_not_configured`. With `ai.tokens=120`: a request within the limit passes, and the next one, projecting past it, is refused (`monthly_token_quota`). One request sent | PASS_LOCAL | Real plan entitlements; the quota stays soft (Q8 accepted) |
| D10 Cost visibility | Settled attempts carry `estimated_cost`, currency and pricing version; totals readable with `platform.ai_usage:read` | `estimated_cost` 0.00000405 USD with pricing version `rehearsal-2026-10`; `read_ai_usage_totals` returns the tenant's totals | PASS_LOCAL | The deployment's real prices; estimates are not billed amounts |
| D11 Monitoring | Log events routed to the deployment's log system, with alerts on them | Emitted and free of the key: `ai_inference_attempt`, `ai_provider_credential_unavailable`, `ai_inference_capacity_exhausted`. All ten events in section 4 exist in the pinned source | PASS_LOCAL for the events only | Log shipping, alert rules and their delivery |
| D12 Database limits | Pool sized for the concurrency limits; statement and idle-in-transaction timeouts kept as the deployment sets them | The application role set to `statement_timeout = 5s` and `idle_in_transaction_session_timeout = 10s`; `DB_POOL_SIZE=4`, `DB_POOL_MAX_OVERFLOW=0`, `DB_POOL_TIMEOUT_SECONDS=10`; tenant and global concurrency 4. The whole main run (14 cases) ran under these settings. Four concurrent requests all succeeded and all four attempts settled as `succeeded` | PASS_LOCAL (role-level settings on a disposable server) | The production server's own timeouts, and the pool size for the deployment's number of workers and instances |
| D13 Backup and recovery | The attempt ledger, AI configuration and outbox are in the main backup; crash-left `started` attempts swept | `python -m saas_os.infra.db.backup create` exit 0, then `restore --target-database saas_os_restore_check` exit 0. Row counts identical: attempts 16, providers 15, audit 214, platform audit 188, outbox 30. The crash sweep is covered by the integration suite (`test_a_stale_started_attempt_is_marked_abandoned`), not by this rehearsal | PASS_LOCAL (plaintext, same server) | Encrypted (`age`) backups, off-host storage and a restore drill on separate infrastructure |
| D14 Rollback | A rollback to an earlier pin keeps the AI tables; disabling inference refuses before anything is sent | Switches: a plan without `ai.inference` and a withdrawn destination policy both refuse with 0 sent. Rollback: `f168752` installed into a second environment against the same database. Its `saas-os-migrate upgrade` exits 0 and the head is unchanged; the consumer gives `/readyz` 200; a governed call succeeds; the 11 AI tables and the 17 attempts remain. Probe: the pre-AI pin `4197d2f`'s `saas-os-migrate upgrade` exits 1 with Alembic's `Can't locate revision` error for the head `f6a2c8e4b1d9`, and changes nothing (finding F-L) | PASS_LOCAL for the switches and for a rollback within the same migration head; NOT_TESTED for running a pre-AI application against the AI-head database | Exercise the deployed product's rollback |

Counts: PASS_LOCAL 14 (D6, D11, D12, D13 and D14 with the limits stated); FAIL 0; BLOCKED 0. Within D14, running a pre-AI application against the AI-head database is not tested.

**Finding F-L (LOW, documentation, resolved).** The D14 criterion said only that a rollback keeps the AI tables. It did not say that a pin whose migration history lacks the database's head cannot run its own migration step. `docs/AI-PROVIDER-QUALIFICATION.md` D14 now says so: skip that step; downgrading is a separate decision. No code changed.

**Statuses, kept separate.** Repository-ready (Gate A): PASS, main CI run 39211710993 on `2a5d9fa`. Product-ready (Gate B): PASS (section 8). Local rehearsal: passed with the limitations above. Deployment qualification (Gate C): **NOT YET QUALIFIED**.

## 11. Local rehearsal of D1 to D14 on `main` at `6cab719` (2026-10-19)

**A local rehearsal, not a deployment qualification.** Gate C stays **NOT YET QUALIFIED**. Section 11 repeats section 10 with the same driver, installed from the current `main` (`6cab719`, pull request #60). The `saas_os` code at `6cab719` is identical to `ab17e7f`: the only differences are documentation and the reference consumer's pin comment. This run therefore ties the section 10 evidence to the exact `main` commit; it does not test anything section 10 did not.

**Environment.** A new Python 3.13 environment outside the repository with `saas-os[dev]` from `git+https://github.com/aelboum/saas-os@6cab719b711d458d22b2318656125c31fe80aed2`; `direct_url.json` records that commit, `pip check` is clean, and no `saas_os` source was copied. Run-owned PostgreSQL 16 and Redis 7 containers, removed afterwards (none left). The real OpenAI provider (`gpt-4o-mini`) with the owner's non-production key, read into the process environment only. Two earlier attempts did not reach the tests and left no evidence: one was stopped by the host for low memory during the package install, and one found Docker not running.

**Driver.** Main run: 15 passed (the section 10 cases, with D2 through the operator CLI in the same run), 17 real requests (at most 64 output tokens each). The rollback run: 2 passed, 1 more request. 18 real requests in total. A scan of every file the run and its driver wrote (40,347 files, including the three environments) found the key in none.

| Item | Local evidence on `6cab719` | Local result | Remaining deployment verification |
|---|---|---|---|
| D1 Migrations and roles | `saas-os-migrate upgrade` exit 0, head `f6a2c8e4b1d9`; consumer migrations exit 0; `/healthz` 200, `/readyz` 200. PostgreSQL stopped: `/readyz` 503, `/healthz` 200, back to 200. Redis stopped: `/readyz` 503, `/healthz` 200, back to 200 | PASS_LOCAL | Managed PostgreSQL and Redis, and the deployment's probe timeouts |
| D2 Provider configuration | `saas-os-operator`: `ai-provider-create`, `ai-model-create`, `ai-destination-policy` (twice) and `ai-alias-set` exit 0; a governed call through that configuration succeeds; `ai-show` exits 1 without `platform.ai_config:read` and 0 with it, lists the provider and contains no key value; a missing `--reason` exits 2. Platform audit actions written: `platform.ai_provider.configure` (3), `platform.ai_policy.configure` (2), `platform.ai_config.read` | PASS_LOCAL | Real operator enrolment and the commands run inside the deployment's backend container |
| D3 Credentials | Success: 24 input and 8 output tokens reported by the provider, a provider request id, 1.56 s; the key in no rendering or log line. Name removed from `AI_PROVIDER_CREDENTIALS`: `credential_unavailable`, 0 sent, log event `ai_provider_credential_unavailable` | PASS_LOCAL | Injection through the deployment's secret store |
| D4 Credential rotation | Invalid value under the same name: one attempt, `provider_auth`, no fallback. A new name: `no_eligible_destination` with 0 sent until confirmed, then succeeds | PASS_LOCAL | Rotate a real key at the provider and revoke the old one |
| D5 Egress | Dead proxy in `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY`: the request still succeeds. `https://127.0.0.1/v1` refused at configuration (`AIConfigurationError`), 0 sent | PASS_LOCAL | The production network path and firewall |
| D6 Timeouts and response size | Three requests at `max_output_tokens=64`: 1.52 s, 1.19 s, 1.20 s. A 50 ms deadline: `InferenceTimeoutError("deadline")`, not possibly accepted | PASS_LOCAL for the mechanism | Measure the deployment's real use cases, then choose `AI_EGRESS_*` |
| D7 Concurrency | Tenant limit 1, three concurrent requests: one `InferenceResult`, two `InferenceCapacityExhaustedError`, one sent, log event `ai_inference_capacity_exhausted` | PASS_LOCAL | Limits from the account's rate limits and worker capacity |
| D8 Redis | Redis stopped: `admission_unavailable`, 0 sent, 0 attempt rows. Restarted: success | PASS_LOCAL | Managed Redis failover |
| D9 Token quota | No `ai.tokens`: `quota_not_configured`. Over the limit: `monthly_token_quota`. One sent | PASS_LOCAL | Real plan entitlements (soft quota) |
| D10 Cost visibility | `estimated_cost` 0.00000345 USD, pricing version `rehearsal-2026-10`; usage totals read back | PASS_LOCAL | Real prices; estimates are not billed amounts |
| D11 Monitoring | `ai_inference_attempt`, `ai_provider_credential_unavailable` and `ai_inference_capacity_exhausted` emitted without the key; all ten events of `docs/AI-PROVIDER-QUALIFICATION.md` section 4 exist in the `6cab719` source | PASS_LOCAL for the events only | Log shipping, alert rules and their delivery |
| D12 Database limits | Application role `statement_timeout = 5s`, `idle_in_transaction_session_timeout = 10s`; pool 4, overflow 0, pool timeout 10 s; concurrency 4. The whole main run ran under these settings; four concurrent requests all settled `succeeded`. The server-wide settings stayed at 0 (only the role was set) | PASS_LOCAL (role-level settings on a disposable server) | The production server's timeouts and the pool size per worker and instance |
| D13 Backup and recovery | `python -m saas_os.infra.db.backup create` exit 0 and `restore --target-database saas_os_restore_check` exit 0; counts identical: attempts 17, providers 16, audit 229, platform audit 204, outbox 32. The crash sweep is covered by `test_a_stale_started_attempt_is_marked_abandoned`, not by this run | PASS_LOCAL (plaintext, same server) | Encrypted backups, off-host storage and a restore drill on separate infrastructure |
| D14 Rollback | Both switches (no `ai.inference`; withdrawn destination policy) refuse with 0 sent. Rollback to `f168752` on the same database: migrate exit 0, head unchanged, `/readyz` 200, a governed call succeeds, 11 AI tables before and after, 18 attempts kept. Pre-AI `4197d2f`: migrate exit 1, `Can't locate revision` for the head, nothing changed, 11 AI tables remain (F-L, documented) | PASS_LOCAL for the switches and a same-head rollback; NOT_TESTED for a pre-AI application against the AI-head database | Exercise the deployed product's rollback |

Counts: PASS_LOCAL 14 (D6, D11, D12, D13 and D14 with the limits stated); FAIL 0; BLOCKED 0. No new finding; no code changed.

**Statuses, kept separate.** Repository-ready (Gate A): PASS, main CI run 39230708516 on `6cab719`. Product-ready (Gate B): PASS (section 8). Local rehearsal on `main`: passed with the limitations above. Deployment qualification (Gate C): **NOT YET QUALIFIED** until D1 to D14 are verified in the product's intended non-production deployment.
