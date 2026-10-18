# Release readiness: AI inference and the 2026-10-18 candidate

Status: **prepared, not released.** This page records the evidence for one release candidate of SaaS OS and what still needs a decision. It does not replace the deferred-issue ledger in `docs/P-ROADMAP.md`, which stays authoritative for every finding; rows here point to it.

Nothing on this page is a release, a deployment or a support commitment. SaaS OS is a library that products pin by exact commit; deploying it is the product's act (ADR-0015).

## 1. Candidate

| Item | Value |
|---|---|
| Base | `main` at `0598a9a` (merge of pull request #53, AI inference) |
| Candidate | `b30e3691b6438102761eae4e4e6d1e54e1fef4f9`, the SaaS OS commit the reference consumer pins. Branch head `2dd8566` adds only the pin move; the commit adding the gate results changes only this page |
| Changes since `0598a9a` | post-merge audit findings D1, D2, D4 (`32f95cc`); typed error for invalid AI egress configuration (`3a1d9f0`); ledger corrections and this page (`b30e369`); the reference consumer's pin move (`2dd8566`) |
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

### 3.2 Open MEDIUM rows in the ledger

| Ledger row | Status | Release impact |
|---|---|---|
| Self-learning 9.1–9.9 not re-certified against its recovered specification | Deferred | None for AI inference; the self-learning subsystem keeps its recorded limits |
| Redis has no persistence in the development Compose file | Deferred | Development only; production Redis is operator-managed (ADR-0028) |
| No external append-only copy of the audit tables | Implemented (ADR-0053); deployment step open | Each deployment must ship the digest logs to a store the database administrators cannot change |
| Webhook, GitHub, OIDC and ZITADEL clients use httpx's default `trust_env` | Open; separate decision (ADR-0054 Q2) | Environment proxies change their egress path; AI egress is not affected (`trust_env=False`, tested) |

The 2026-10-16 rows on distributed concurrency limiting, the AI SDK import contract and the ADR-0013 data-authorization store were corrected on 2026-10-18: the first two are resolved, the third addressed for governed inference, each with its evidence in the ledger.

Every LOW and INFO row of the ledger carries its own status and rationale; none is CRITICAL or HIGH.

### 3.3 Accepted residual risks (ADR-0056, decided by the owner for the AI release)

- The operator command holds both database credentials; it is a trusted administrative boundary.
- The application role can write `core.platform_operators` and `core.platform_grants` (ADR-0045 §9a).
- The startup check protects exactly the six AI configuration tables; future protected tables need explicit grants and governance.

## 4. Decisions required from the owner

None of these is decided here, and none blocks the engineering work above. Each blocks only what it names.

| # | Question | Recommendation | Alternatives and impact | Blocks |
|---|---|---|---|---|
| 1 | Accept ADR-0054 and ADR-0055 (Q6)? | Accept once Q3 and Q8 have explicit dispositions (below); the implementation matches both, and every remaining open item is labelled | Keep Proposed: no technical effect, but consumers build on Proposed contracts | Calling the AI subsystem's design final |
| 2 | Final timeout and concurrency values (Q3) | Keep the provisional defaults as defaults; require each production deployment to set and validate its own values against its providers and workloads | Fix new defaults now: needs provider measurements that do not exist in this repository | A claim of validated defaults |
| 3 | Hard token caps (Q8) | Defer. State that quotas are soft (done) | A reservation design: atomic reservation before the call, settlement, reconciliation; substantial work and new failure modes | Any statement of a spending cap |
| 4 | Webhook and other non-AI egress `trust_env` (Q2, ledger) | Set `trust_env=False` on the webhook client, matching AI egress | Keep: deployments relying on proxies keep working, at the cost of a proxy-dependent egress path. Changing it breaks deployments that route webhooks through a proxy | A uniform egress policy |
| 5 | `AI_INFERENCE_TOKEN_QUOTA_REQUIRED` default (L2) | Keep the default off for compatibility, and recommend `true` for production in the consumer guide (done) | Default on: a tenant without a valid `ai.tokens` is refused; changes behaviour for every existing plan without the entitlement. Financial exposure with it off: a tenant with no or a malformed limit is unlimited | A fail-closed default |
| 6 | Where refusals by non-members are recorded (L1) | Keep the current convention, platform-wide | Platform log or no row: changes audit semantics across Core, not only AI | Changing audit attribution |
| 7 | Tenant-owned credentials, provider-report reconciliation authority, attempt-ledger retention class | Defer; none is needed for installation-managed providers | Each needs its own authority or policy decision (ADR-0054 section 8d) | Those features only |
| 8 | A database identity for platform authority; governance of future protected tables | Separate platform-wide ADR | Implementing now changes the trust model of every platform operation | Those boundaries only |

## 5. Reference consumer

`saas-os-update check` against a Git copy of the reference consumer at `4197d2f` classifies the move to the candidate as `REVIEW_REQUIRED` (exit 20): 39 commits touching migrations, authorization, security controls, the provider boundary and public APIs, including pull requests #44 to #53. The tool has no override for that class; this page and the pull request are the review. The consumer scaffold keeps `4197d2f`: it does not use AI inference, and moving it needs its own validation.

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
