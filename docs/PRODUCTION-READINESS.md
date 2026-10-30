# Production readiness ledger

One status per readiness gate, with the evidence behind it. It answers "what has actually been shown to work, and how", not "what is designed". It complements two existing records and does not replace them:

- the **deferred-issue ledger** in `docs/P-ROADMAP.md`, which holds every open finding (cited below as "ledger row" with its line number at `f33977b`; numbers shift as rows are added);
- `docs/RELEASE-READINESS.md`, which holds the AI release gates and the D1-D14 rehearsals.

SaaS OS is a library that products pin by commit SHA and deploy. A gate below concerns what this repository ships and tests; deploying, operating and monitoring a product is the product's job, and evidence that needs a live deployment is marked **blocked**.

**Statuses.** *Verified*: an automated test or a required CI check exercises the property, and the tests are named. *Partially verified*: some of it is exercised, the rest is named as a gap. *Untested*: nothing exercises it. *Blocked*: it needs an action outside this repository (a deployment, a provider, an owner decision). Documentation alone never makes a gate verified, and a green CI run does not make SaaS OS production-ready.

**Required checks.** The `main` ruleset (25485150) requires seven CI checks on the exact head before a merge: `backend checks`, `frontend checks`, `security checks`, `docker build + runtime validation`, `packaging gate (wheel contents + isolated install)`, `migration gate (P1.7)` and `security integration gate (PRIV-03 RA-11-F1)`. Integration tests (`-m integration`) run only in the last one, through `scripts/check-integration.sh`, which fails if no test ran or any test was skipped.

**Last reviewed:** 2026-10-30, at `main` `f33977b` (previous review 2026-10-27 at `be5cc23`). Re-review a gate whenever a change touches its evidence.

## Summary

| # | Gate | Status |
|---|---|---|
| 1 | Architecture and public package interfaces | Partially verified |
| 2 | Authentication and authorization | Partially verified |
| 3 | Tenant isolation and database security | Verified (limitations below) |
| 4 | API and outbound-network security | Partially verified |
| 5 | Data protection and secret management | Partially verified |
| 6 | Background-job reliability and recovery | Partially verified |
| 7 | Payment and email integrations | Partially verified; live providers blocked |
| 8 | Dependency and supply-chain security | Partially verified |
| 9 | Unit, integration, migration, packaging and runtime testing | Partially verified |
| 10 | Observability, health checks and alerting | Partially verified; alerting untested |
| 11 | Backup restoration and disaster recovery | Partially verified; off-host recovery blocked |
| 12 | Deployment, rollback, configuration validation, environment separation | Partially verified; deployment blocked |
| 13 | Operational runbooks and incident response | Partially verified |
| 14 | Consumer-package compatibility and upgrade procedures | Partially verified |
| 15 | Documentation and known limitations | Partially verified |

**Overall: not production-ready.** No gate is failing, but most are only partially verified, and what remains depends on actions outside the repository: a published release, a live deployment, live provider checks, and owner decisions. On 2026-10-30 the deferred-issue ledger had no open CRITICAL row; two HIGH rows (1032, 1033, ZITADEL advisories) fixed in the repository and open only for a deployment that has not upgraded; and five open MEDIUM rows, none of which this repository can close alone: 892 (SMTP relay reachable on `internal`, per deployment), 893 (worker egress, implemented and checked in CI, not run live), 921 (plain `http://` webhooks: release 2 waits for a published release containing release 1), 924 (the external audit store, a deployment step) and 1037 (ZITADEL Login V2 sign-in in a browser, a real domain, replicas). Phase 9 S3 (863) was resolved for the production-effect transitions on 2026-10-30.

## 1. Architecture and public package interfaces — partially verified

- Layer and import contracts: `lint-imports` (contracts in `pyproject.toml`, `[tool.importlinter]`) runs in `backend checks` through `scripts/check-backend.sh`; `tests/architecture/test_layer_boundaries.py`, `tests/architecture/test_namespace_contract.py`.
- Package layout: `tests/test_wheel_contents.py` (top-level import names, isolated non-editable install) in the packaging gate.
- Public surfaces pinned module by module, not as a whole: `tests/infra/test_db_public_surface_unit.py`, `tests/infra/jobs/test_public_api.py`, `tests/architecture/test_platform_authority_contract.py`, `tests/architecture/test_ai_inference_boundaries.py`.
- The whole public surface: every `saas_os` package with `__all__`, with each exported function's signature and each class's bases, fields and public method signatures, is pinned in `tests/architecture/public_api_snapshot.txt` (built from the source with `ast`, no imports) by `test_public_api_snapshot.py` since 2026-10-30; a changed signature fails until the snapshot is rewritten deliberately (`docs/RELEASING.md`).
- Gaps: products import the internal `control_plane.orchestration.tools` (ledger row 987); the `api/` split and the classification of `tenant_status.py` are undecided (873, 874); (the ledger row on `docs/API-ARCHITECTURE.md` and capability routes, 890, was fixed on 2026-10-11 and closed on 2026-10-30).

## 2. Authentication and authorization — partially verified

- OIDC and sessions: `tests/core/identity/test_oidc.py`, `test_oidc_flow_unit.py`, `test_sessions_unit.py`; outbound routing and trust of discovery, JWKS, token exchange and the ZITADEL bootstrap on real local sockets, `test_oidc_outbound_unit.py` and `tests/infra/local_identity/test_bootstrap_outbound_unit.py` (pull request #136: no proxy or CA from the environment, no redirects, explicit `OIDC_CA_BUNDLE`/`OIDC_PROXY_URL`); the same for `GitHubPullRequestProvider`, `tests/control_plane/development/test_github_provider_outbound_unit.py` (pull request #137); `tests/api/auth/test_auth_flow_integration.py`, `test_proxy_trust_integration.py`; CSRF `tests/api/test_csrf_unit.py`.
- API keys: `tests/core/api_keys/` (isolation, revocation, a revoked key is not rotated), `tests/api/v1/test_api_key_request_auth_integration.py`, `tests/api/test_credential_failure_limit_integration.py`.
- RBAC and platform authority, including negative controls and forced races: `tests/core/rbac/test_authorization_integration.py`, `test_deny_authorization_integration.py`, `test_authorization_transaction_race_integration.py`; `tests/core/platform_authority/test_platform_authority_negative_controls_integration.py`, `test_user_deactivation_race_integration.py`.
- Invitation acceptance: `tests/core/identity/test_invitation_integration.py`, run in full by the integration gate since pull request #119 (eleven of its tests had been deselected since 2026-09-19).
- Audit evidence for the self-learning transitions that change a tenant's AI behaviour (adaptation activation and rollback, canary start and rollback) is written in the change's own transaction, and a canary starts or rolls back in one transaction (ADR-0031 amendment of 2026-10-30, Phase 9 S3 option A): injected-failure tests and negative controls in `tests/control_plane/self_learning/autonomous_improvement/test_autonomous_improvement_integration.py`. The rest of the control plane still audits after commit (LOW ledger row after "Phase 9 S3").
- Identity errors carry no issuer, subject or email, in their message or chain, and none reaches the API middleware's log line or span: `tests/core/identity/test_identity_error_messages_unit.py`, the caller-input tests in `test_identity_integration.py` and `test_invitation_integration.py` (audit of 2026-10-28, ledger row after 902).
- Gaps: the caller-input audit of 2026-10-28 did not test live provider error texts, `OperationalError` texts or products' own routes, and PostgreSQL's `DETAIL` still carries values for tables without row security (audited the same day: no realistic path brings a secret or personal value to a sink; a `state` collision or a `NULL` insert on `core.login_transactions` would, neither is reachable; ledger rows after 902); database connection errors put the host, port, user and database name, never the password, into the log line, the span, `last_error` and dead-letter entries (operator-only sinks, kept as diagnostics; ledger rows after 902); webhook errors stored before pull request #110 with the destination URL can be redacted with `saas-os-operator redact-webhook-errors --apply` (ledger row 902); a live worker run, on Windows and on Linux with `ENVIRONMENT=production`, and webhook failures through the real egress proxy, found no password, token or key in its log, the dead-letter list or `last_error`, but arq's own line for a dead-lettered job carries the formatted traceback, with every chained exception's message and each frame's source line, where the dead-letter entry keeps the top error only (ledger rows after 902); no live identity provider test in CI (`test_live_zitadel_integration.py` is excluded by design; the compose `OIDC_CA_BUNDLE` wiring is checked by `scripts/check-docker-prod.sh`, which stops at its migration step without TLS by design, ledger row 943); since 2026-10-30 CI's Docker job runs ZITADEL v4.19.5 behind Caddy in `scripts/check-docker-prod-tls.sh` and follows `/auth/login` to the provider's authorize endpoint and the Login V2 page (ledger row 1040), but signing in through a browser, a real domain and replicas are not verified (1037, MEDIUM); invitation acceptance reads the verified email from the ID token only (1029); design residuals (969, 971, 977, 978).

## 3. Tenant isolation and database security — verified

- Schema sweep against the isolation registry, as the restricted application role: `tests/infra/db/test_rls_coverage_sweep_integration.py` (`test_every_tenant_owned_table_has_forced_rls_and_exactly_the_canonical_policy`, `test_no_security_definer_function_exists_in_saas_os_schemas`).
- `tests/infra/db/test_rls.py`, `test_role_guard_integration.py`, `test_tenant_session_scope_validation.py`; the `*_isolation_integration.py` modules (for example `tests/core/tenancy/test_tenant_isolation_integration.py`, `tests/core/rbac/test_rbac_isolation_integration.py`); `tests/architecture/test_tenant_session_boundary.py`.
- Run on real PostgreSQL 16 in the integration gate, with the application and platform-configuration roles created by `saas_os/infra/db/init/`.
- Limitations: concurrent deny grants in unrelated tenants can deadlock, and PostgreSQL aborts one (fails closed; ledger row 932); the external append-only audit copy is a deployment step (924, gate 5).

## 4. API and outbound-network security — partially verified

- Webhook SSRF and egress: `tests/core/webhooks/test_webhook_ssrf_policy_unit.py`, `test_webhook_allowed_ports_unit.py`, `test_webhook_shared_egress_unit.py`; webhook errors never carry the URL, at delivery (`test_webhook_ssrf_policy_unit.py`) and at subscription, including the API middleware's log line and span (`test_webhook_subscribe_url_error_unit.py`, ledger row 902); `tests/infra/egress/test_strict_egress_unit.py`, `test_strict_egress_socket_unit.py`.
- Rate limiting: `tests/infra/ratelimit/test_ratelimit_atomicity_integration.py`, `test_ratelimit_backend_failure_integration.py`, `tests/api/v1/test_ratelimit_failure_integration.py`.
- Edge: `tests/architecture/test_single_origin_edge.py` against a real Caddy in `backend checks`; CORS `tests/api/test_cors_unit.py`.
- Single-origin runtime (ADR-0024): `scripts/check-single-origin.sh` runs in the required Docker check since 2026-10-30, on the development Compose file: `/readyz`, `/v1/*` and `/auth/me` reach the backend through the edge, browser paths reach the frontend, no internal service is routed, and `/auth/login` redirects to the provider with PKCE S256 and a callback on the public origin.
- Gaps: worker egress (ADR-0059) is implemented and checked end to end on isolated test networks in CI (`scripts/check-egress-e2e.sh`: delivery through the resolver and proxy, refusal of mixed, private, metadata and IPv6 ULA answers by the application and of non-public targets by the proxy, fail-closed resolver and proxy outages with no direct connection), but not against real public hosts, not with recursion and DNSSEC from the root, and not in a live deployment; SMTP still needs a relay on `internal` (ledger rows 892, 893). A proxy refusal misclassified on Linux as transient (fail-closed throughout) was fixed in pull request #132, with a regression test. Plain `http://` webhook destinations: release 1 of `WEBHOOK_ALLOW_HTTP` is merged (#131), and release 2, which refuses them by default, is held as draft #133 until a published release contains release 1. The setting decides what the application accepts, not what the network reaches: the reference proxy refuses `http://` even with `true`, and a product with its own egress gets whatever its network allows (ledger row 925); AI egress limits are provisional (984); payment-page refusals have no rate limit of their own (881); (917, the `httpx` request line, was resolved on 2026-10-27 by #122.)

## 5. Data protection and secret management — partially verified

- Secret scan: `scripts/check-security.sh` in `security checks`; `tests/architecture/test_secrets_gate.py`, `test_security_script_reporting.py` (UTF-8 mode on Windows since pull request #114).
- No credential reaches a value's representation or a built image, per `tests/infra/secrets/test_secret_value_safety.py` and `test_no_secrets_in_docker_artifacts.py`; log redaction `tests/infra/observability/test_logging_redaction_unit.py`, `test_redaction_unit.py`.
- Transport encryption at configuration level (ADR-0021): `tests/infra/db/test_tls_requirement_unit.py`, `tests/infra/jobs/test_redis_tls_client_defaults_unit.py`.
- Retention, purge and erasure: `tests/core/tenancy/test_retention_classification.py`, `test_tenant_purge_integration.py`, `test_purge_participants_integration.py`, `tests/core/identity/test_erasure_integration.py`; backup encryption `tests/infra/db/test_backup_encryption_unit.py`.
- The production ZITADEL master key is read from a file mounted into `zitadel` only, never passed as an argument (2026-10-29; `docs/RUNBOOKS.md`, identity section 5a; checked by `test_production_identity_topology.py` and `scripts/check-docker-prod-tls.sh`); the local `docker-compose.yml` passes its development key through the environment, not the command line (2026-10-30, `test_the_local_master_key_is_never_an_argument`).
- Encryption in transit end to end: `scripts/check-docker-prod-tls.sh` runs in CI's `docker build + runtime validation` job since 2026-10-30 (`tests/architecture/test_image_scan_gate.py`). It boots the unmodified production topology against TLS PostgreSQL and Redis with a throwaway PKI, asserts `ssl=true` from the application's own connection and verified Redis TLS, and refuses an untrusted chain (negative control).
- Gaps: PostgreSQL keeps `sslmode=require`, encryption without certificate verification (ADR-0021); a managed provider's endpoint has not been exercised; the external audit store is not deployed (924, blocked); Core cannot detect a missing purge participant (1046, 1047); AI tables keep the `DEFERRED_POLICY` retention class (1025); redaction does not cover values interpolated into a log message string (recorded by `test_message_string_interpolation_is_an_explicitly_uncovered_path`); a failed webhook delivery's traceback frame locals hold the signing secret, the URL and the body, which SaaS OS never records but a product's error tracker that captures locals would (ledger row 901; `docs/CONSUMER-GUIDE.md` section 10). Webhook URL paths and queries are kept out of `httpx`'s request line, and the OIDC callback's `code` and `state` out of uvicorn's access line, by filters attached to those loggers (pull requests #122 and #126, `tests/infra/observability/test_log_filters_unit.py`); arq's job-start line still logs a truncated payload repr (no URL or secret).

## 6. Background-job reliability and recovery — partially verified

- Real worker process: `tests/api/test_worker_runtime_integration.py` (retry then dead-letter, clean SIGTERM, refusal to start without Redis).
- Outbox: `tests/api/test_outbox_dispatcher_integration.py` (a worker that dies after the consumer ran lets the event run again; an event with no consumer is dead-lettered), `tests/api/test_outbox_consumer_idempotency_integration.py` (concurrent executions count once; an email is not resent once completed).
- `tests/infra/jobs/test_dead_letter.py`, `test_queue_retry.py`, `test_redis_persistence_integration.py`; `tests/core/test_job_lifecycle_fencing_integration.py`.
- Redis keeps an append-only file on a named volume in both Compose files (development since 2026-10-30, ledger row 876; `tests/architecture/test_redis_durability_topology.py`).
- Gaps: there is no replay for dead-lettered outbox events, and Redis job dead-letters keep no payload by design (ledger row 897); Resend `Retry-After` is not read (896). Both need an owner decision: `docs/architecture/OUTBOX-RETRY-AND-REPLAY-DECISION-BRIEF.md`. The guide's earlier advice to replay the dead-lettered events was corrected on 2026-10-30.

## 7. Payment and email integrations — partially verified; live providers blocked

- Stripe webhook authenticity, replay and duplicates: `tests/core/billing/test_billing_unit.py` (tampered payload, wrong secret), `test_stripe_event_parsing_unit.py`, `tests/api/v1/test_billing_events_router_integration.py` (`test_a_stale_delivery_is_refused`), `tests/core/billing/test_provider_events_integration.py` (duplicate and concurrent deliveries recorded once), `test_billing_security_attacks_integration.py`, `test_billing_projections_integration.py`.
- Email with mock transports and fakes only: `tests/core/email/test_resend_provider_unit.py`, `test_smtp_provider_unit.py`, `test_email_provider_selection_unit.py`, `tests/core/notifications/test_email_channel_integration.py`.
- Blocked: Stripe test mode (`tests/core/billing/test_billing_stripe_integration.py`) and live Resend are outside CI, which holds no provider credential (ADR-0012). Resend has been checked live once, partly (ledger rows 894, 899); Stripe subscriptions created before ADR-0052 may lack `save_default_payment_method` (944, an operator check).
- The Stripe adapter's SDK is checked at startup: with `STRIPE_API_KEY` set and no `saas-os[stripe]`, the API and the worker refuse to start (ADR-0041, 2026-10-30; `tests/architecture/test_optional_sdk_imports.py`, ledger row 946).
- Gaps: the production worker reaches the internet only through the egress proxy (ADR-0059) and SMTP only through a relay on `internal`; neither has run in a live deployment (892, 893, MEDIUM).

## 8. Dependency and supply-chain security — partially verified

- `security checks`: `pip-audit` over the resolved environment, `scripts/npm_audit_gate.py` (high and critical, exceptions in `scripts/security-exceptions.json`, currently none), detect-secrets. The gate's own logic is tested: `tests/architecture/test_npm_audit_gate.py`, `test_security_script_reporting.py`, `test_ci_hermeticity.py`.
- `frontend/package-lock.json` is committed; `detect-secrets` and `ruff` are pinned exactly.
- Base images are pinned by tag and multi-architecture digest, with an update procedure (`docs/SECURITY.md`, "Base image digests"; `tests/architecture/test_base_image_digests.py`); Actions are pinned by commit SHA (`tests/architecture/test_ci_workflow_pins.py`, `test_release_script.py`).
- Image scan and SBOM: `scripts/check-image-scan.sh` (Trivy, pinned by digest) in CI's Docker job fails on a fixable HIGH or CRITICAL finding in either image and keeps a CycloneDX SBOM per image as the `sbom` artifact (`tests/architecture/test_image_scan_gate.py`, ledger row 948). Its first run found 15 fixable HIGH findings, all in libraries vendored by `pip` and the `npm` CLI; both are removed from the runtime images.
- Gaps: no Python lock or constraints file, only lower bounds in `pyproject.toml` (ledger row 947, owner decision); the release workflow's approval reviewer and tag signing are not in place (1031); a finding without a fixed version is not failed on.

## 9. Unit, integration, migration, packaging and runtime testing — partially verified

- The seven required checks, each a script: `check-backend.sh`, `check-frontend.sh`, `check-security.sh`, `check-docker.sh`, `check-packaging.sh`, `check-migrations.sh`, `check-integration.sh`.
- Intermittent checks found and fixed on 2026-10-27: the worker dead-letter test (pull request #115) and the Docker readiness check (pull request #117).
- The production topology over TLS (`check-docker-prod-tls.sh`) and the image scan run inside the required Docker check since 2026-10-30.
- Gaps: by design, live Stripe, ZITADEL, GitHub and AI-provider tests are not in CI; `check-docker-prod.sh` (the perimeter run of the stock file) stays manual because it stops at its migration step without TLS (ledger row 943); narrow pytest selections can shadow `control_plane` (ledger row 887).

## 10. Observability, health checks and alerting — partially verified; alerting untested

- Health: `tests/api/test_health_unit.py`, `tests/infra/health/test_health_integration.py`, `test_readiness_aggregate.py`, `test_readiness_db.py`, `test_readiness_redis.py`; `check-docker.sh` asserts `/healthz` and `/readyz`, including `503` with no connection detail when PostgreSQL is down.
- Logging and tracing: `tests/infra/observability/test_end_to_end.py`, `test_otel.py`, `tests/api/test_middleware_correlation_bound_unit.py`.
- Untested: the repository has no metrics exporter and no alerting; the observability backend is undecided (ledger row 875, ADR-0009); the audit digest's missing-record alert and scheduled verification are a deployment step (924). `tests/core/audit_digest/test_audit_digest_integration.py` covers the offline verification only.

## 11. Backup restoration and disaster recovery — partially verified; off-host recovery blocked

- `tests/infra/db/test_backup_restore_drill_integration.py`: `test_full_disaster_recovery_drill` (back up, drop, restore, then RLS, isolation and roles re-checked), the extended pipeline with `age` encryption and an off-site copy run twice from clean environments, and the checksum, corrupt-archive and existing-target refusals.
- `tests/infra/db/test_zitadel_backup_restore_drill_integration.py`, `test_backup_offsite_fail_closed_unit.py`, `tests/infra/jobs/test_redis_persistence_integration.py`.
- Blocked: no restore on separate infrastructure or real off-host storage (`docs/RELEASE-READINESS.md`, D13); the systemd timers in `deploy/` have never run as units; the external audit store (924).

## 12. Deployment, rollback, configuration validation, environment separation — partially verified; deployment blocked

- Migrations and their order: the migration gate (`tests/infra/db/test_migration_gate_integration.py`, `tests/test_reference_consumer_integration.py`, the `tests/infra/db/test_*_migration_rollback.py` files).
- Fail-closed configuration: `tests/infra/secrets/test_config_selection.py` (an unset `ENVIRONMENT` refuses), `tests/core/test_config.py`, `tests/api/auth/test_auth_config_unit.py`, `tests/infra/jobs/test_jobs_config.py`.
- Production topology checked statically: `tests/architecture/test_production_identity_topology.py`, `test_email_provider_topology.py`, `test_single_origin_edge.py`.
- Production topology run in CI: `scripts/check-docker-prod-tls.sh` (Docker job, since 2026-10-30), including a restart without volume loss.
- Blocked: no product deployment, or rollback of one, has been exercised (D14 is local only); worker egress and SMTP in a live deployment (892, 893).

## 13. Operational runbooks and incident response — partially verified

- Exercised: the operator CLI (`tests/core/platform_authority/test_operator_cli_integration.py`, `tests/ops/test_operator_cli_unit.py`), platform bootstrap and break-glass recovery (`tests/api/test_platform_bootstrap_integration.py`, `tests/core/platform_authority/test_last_owner_recovery_concurrency_integration.py`), first-tenant bootstrap (`tests/api/test_tenant_bootstrap_integration.py`), audit digest verification.
- Rehearsed on disposable infrastructure: cloning a database into another environment (`docs/RUNBOOKS.md`, "Platform operators", section 7; 2026-10-28, on one PostgreSQL cluster, ledger row after 902).
- Rehearsed on disposable infrastructure: the disaster-recovery restore of production, re-applying the revocations made after the backup from the newer platform audit (same section; 2026-10-29, restored into a new database, ledger row after the clone rehearsal).
- Rehearsed on disposable infrastructure: the external PostgreSQL and Redis checklist's TLS behaviour (`docs/RUNBOOKS.md`, "Production external PostgreSQL and Redis"; 2026-10-29, TLS-only containers with a test CA, ledger row after the disaster-recovery rehearsal). A managed provider's endpoint has not been exercised. A full Redis was rehearsed too: the outbox dispatcher could not give a claim back while Redis refused writes, fixed (ledger row after the TLS rehearsal). The sweep that followed for NUL characters in stored strings found no second instance; the Core write functions a product calls directly now refuse a control character with their own error rather than a raw database error (ledger row after the full-Redis row).
- Rehearsed on disposable infrastructure: the self-hosted identity runbook's ZITADEL upgrade from v4.19.0 to v4.19.5 with both rollback paths, backup and restore, master-key recovery and Login V2 cookie-secret rotation (`docs/RUNBOOKS.md`, "Self-hosted identity operations"; 2026-10-29, ledger row after the NUL sweep); restart on 2026-10-20 (`docs/architecture/ZITADEL-4.19.5-LIVE-VALIDATION.md`). Two runbook statements were wrong and are corrected: a wrong master key leaves ZITADEL healthy but unable to decrypt, and Login V2 still verifies with its private-key fallback. Found: the production master key was passed on the command line and visible in the host's process list (MEDIUM); fixed the same day by reading it from a file. The same day, the move of an existing deployment to the master-key file and the bootstrap-token revocation and re-issue were rehearsed on the real `docker-compose.prod.yml` (ledger row after the master-key row). Not rehearsed: the compromise decisions (the security owner's), Caddy, a browser, replicas, a real domain.

## 14. Consumer-package compatibility and upgrade procedures — partially verified

- `tests/test_wheel_contents.py` (isolated install, every migration revision in the wheel, provider extras), `tests/test_consumer_pins_unit.py` (exact 40-character SHA pins), the reference-consumer integration and scenario tests, `tests/test_consumer_scaffold_integration.py`.
- Upgrade notes: `docs/CONSUMER-GUIDE.md` section 14 and `CHANGELOG.md`.
- Gaps: CI tests the examples against the working tree, not against the commit they pin, and that pin lacks `register_purge_participant()`, which their code calls (ledger row 1048; ADR-0015 moves the example pins in the release pull request, so this closes with the first release after v0.5.0); the scaffold worker reports a job-registration failure as `worker_startup_failed` since 2026-10-30 (926); versioning and support-window policy undecided (870, 871, 872, 947).

## 15. Documentation and known limitations — partially verified

- `docs/ADR/README.md` indexes ADRs 0001-0059; the deferred-issue ledger records findings with their evidence and is updated by each fix.
- Gaps: nothing checks the documents for staleness. The review of 2026-10-30 found and corrected the guide's replay advice (897) and ADR-0058's matching sentence (marker), and closed the ledger row on `docs/API-ARCHITECTURE.md` (890), fixed on 2026-10-11 but never closed. The ZITADEL version of the TLS validation in `docs/RELEASE-READINESS.md`, ADR-0035's NAT64 reason and the capability matrix's subscribe-time SSRF statement were corrected on 2026-10-27 (pull request #123).
